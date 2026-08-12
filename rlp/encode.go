// Package rlp implements Recursive Length Prefix encoding, the canonical
// serialization used for transactions, blocks and trie nodes.
//
// The item set is deliberately small: an item is either a byte string or a list
// of items. Go values map onto it as follows.
//
//	[]byte, string        byte string
//	uint, uintN           byte string, big-endian with no leading zeros
//	*big.Int              byte string, big-endian with no leading zeros
//	bool                  byte string, 0x01 or empty
//	[N]byte               byte string of exactly N bytes
//	[]T, struct           list
//	pointer               the pointed-to value; nil encodes as an empty item
//	rlp.RawValue          spliced in verbatim, already encoded
package rlp

import (
	"errors"
	"fmt"
	"io"
	"math/big"
	"reflect"
	"sort"
	"sync"
)

// RawValue is pre-encoded RLP that is written through untouched.
type RawValue []byte

// Encoder lets a type control its own encoding.
type Encoder interface {
	EncodeRLP(io.Writer) error
}

var (
	ErrNegativeBigInt = errors.New("rlp: cannot encode negative big.Int")
	ErrUnsupported    = errors.New("rlp: unsupported type")
)

var (
	encoderInterface = reflect.TypeOf((*Encoder)(nil)).Elem()
	bigIntType       = reflect.TypeOf(big.Int{})
	rawValueType     = reflect.TypeOf(RawValue{})
)

// EmptyString is the encoding of a zero-length byte string.
const EmptyString = 0x80

// EmptyList is the encoding of a zero-length list.
const EmptyList = 0xC0

// Encode serializes v as RLP.
func Encode(v any) ([]byte, error) {
	buf := newBuffer()
	defer buf.release()
	if err := encodeValue(buf, reflect.ValueOf(v)); err != nil {
		return nil, err
	}
	out := make([]byte, len(buf.b))
	copy(out, buf.b)
	return out, nil
}

// EncodeTo writes the RLP encoding of v to w.
func EncodeTo(w io.Writer, v any) error {
	b, err := Encode(v)
	if err != nil {
		return err
	}
	_, err = w.Write(b)
	return err
}

// MustEncode is Encode for values known to be encodable; it panics on error.
func MustEncode(v any) []byte {
	b, err := Encode(v)
	if err != nil {
		panic(err)
	}
	return b
}

type buffer struct{ b []byte }

var bufferPool = sync.Pool{New: func() any { return &buffer{b: make([]byte, 0, 256)} }}

func newBuffer() *buffer {
	buf := bufferPool.Get().(*buffer)
	buf.b = buf.b[:0]
	return buf
}

func (b *buffer) release() { bufferPool.Put(b) }

func (b *buffer) Write(p []byte) (int, error) {
	b.b = append(b.b, p...)
	return len(p), nil
}

// EncodeBytes writes a byte string with its length prefix.
func EncodeBytes(b []byte) []byte {
	buf := newBuffer()
	defer buf.release()
	writeBytes(buf, b)
	out := make([]byte, len(buf.b))
	copy(out, buf.b)
	return out
}

// EncodeList concatenates already-encoded items into a list.
func EncodeList(items ...[]byte) []byte {
	total := 0
	for _, it := range items {
		total += len(it)
	}
	buf := newBuffer()
	defer buf.release()
	writeListHeader(buf, total)
	for _, it := range items {
		buf.Write(it)
	}
	out := make([]byte, len(buf.b))
	copy(out, buf.b)
	return out
}

func writeBytes(buf *buffer, b []byte) {
	// A single byte below 0x80 is its own encoding.
	if len(b) == 1 && b[0] < 0x80 {
		buf.b = append(buf.b, b[0])
		return
	}
	writeHeader(buf, len(b), 0x80)
	buf.b = append(buf.b, b...)
}

func writeListHeader(buf *buffer, payloadLen int) { writeHeader(buf, payloadLen, 0xC0) }

// writeHeader emits the short or long form prefix for a payload of the given
// length, based at offset (0x80 for strings, 0xC0 for lists).
func writeHeader(buf *buffer, length int, offset byte) {
	if length < 56 {
		buf.b = append(buf.b, offset+byte(length))
		return
	}
	lenBytes := putUint(uint64(length))
	buf.b = append(buf.b, offset+55+byte(len(lenBytes)))
	buf.b = append(buf.b, lenBytes...)
}

// putUint renders an integer big-endian with no leading zero bytes.
func putUint(v uint64) []byte {
	if v == 0 {
		return nil
	}
	var tmp [8]byte
	i := 8
	for v > 0 {
		i--
		tmp[i] = byte(v)
		v >>= 8
	}
	return tmp[i:]
}

func encodeValue(buf *buffer, v reflect.Value) error {
	if !v.IsValid() {
		// A nil interface encodes as an empty string.
		buf.b = append(buf.b, EmptyString)
		return nil
	}

	typ := v.Type()

	if typ == rawValueType {
		raw := v.Bytes()
		if len(raw) == 0 {
			buf.b = append(buf.b, EmptyString)
			return nil
		}
		buf.b = append(buf.b, raw...)
		return nil
	}

	// Custom encoders take precedence, on the value or on its address.
	if typ.Implements(encoderInterface) {
		if typ.Kind() == reflect.Ptr && v.IsNil() {
			buf.b = append(buf.b, EmptyString)
			return nil
		}
		return v.Interface().(Encoder).EncodeRLP(buf)
	}
	if v.CanAddr() && reflect.PtrTo(typ).Implements(encoderInterface) {
		return v.Addr().Interface().(Encoder).EncodeRLP(buf)
	}

	switch typ.Kind() {
	case reflect.Ptr:
		if v.IsNil() {
			// A nil pointer to a struct is an empty list; otherwise an empty string.
			if typ.Elem().Kind() == reflect.Struct && typ.Elem() != bigIntType {
				buf.b = append(buf.b, EmptyList)
			} else {
				buf.b = append(buf.b, EmptyString)
			}
			return nil
		}
		return encodeValue(buf, v.Elem())

	case reflect.Interface:
		if v.IsNil() {
			buf.b = append(buf.b, EmptyString)
			return nil
		}
		return encodeValue(buf, v.Elem())

	case reflect.Struct:
		if typ == bigIntType {
			i := v.Addr().Interface().(*big.Int)
			if i.Sign() < 0 {
				return ErrNegativeBigInt
			}
			writeBytes(buf, i.Bytes())
			return nil
		}
		return encodeStruct(buf, v)

	case reflect.String:
		writeBytes(buf, []byte(v.String()))
		return nil

	case reflect.Bool:
		if v.Bool() {
			buf.b = append(buf.b, 0x01)
		} else {
			buf.b = append(buf.b, EmptyString)
		}
		return nil

	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		writeBytes(buf, putUint(v.Uint()))
		return nil

	case reflect.Slice:
		if typ.Elem().Kind() == reflect.Uint8 {
			writeBytes(buf, v.Bytes())
			return nil
		}
		return encodeSequence(buf, v)

	case reflect.Array:
		if typ.Elem().Kind() == reflect.Uint8 {
			// Arrays are fixed width; copy through a slice to read them.
			tmp := make([]byte, v.Len())
			reflect.Copy(reflect.ValueOf(tmp), v)
			writeBytes(buf, tmp)
			return nil
		}
		return encodeSequence(buf, v)

	default:
		return fmt.Errorf("%w: %s", ErrUnsupported, typ)
	}
}

func encodeSequence(buf *buffer, v reflect.Value) error {
	inner := newBuffer()
	defer inner.release()
	for i := 0; i < v.Len(); i++ {
		if err := encodeValue(inner, v.Index(i)); err != nil {
			return err
		}
	}
	writeListHeader(buf, len(inner.b))
	buf.b = append(buf.b, inner.b...)
	return nil
}

func encodeStruct(buf *buffer, v reflect.Value) error {
	fields, err := structFields(v.Type())
	if err != nil {
		return err
	}
	inner := newBuffer()
	defer inner.release()

	// Trailing optional fields are omitted when they hold zero values, which is
	// how forward-compatible extensions to a struct stay backward-compatible.
	last := len(fields) - 1
	for last >= 0 && fields[last].optional && v.Field(fields[last].index).IsZero() {
		last--
	}
	for i := 0; i <= last; i++ {
		if err := encodeValue(inner, v.Field(fields[i].index)); err != nil {
			return fmt.Errorf("field %s: %w", fields[i].name, err)
		}
	}
	writeListHeader(buf, len(inner.b))
	buf.b = append(buf.b, inner.b...)
	return nil
}

type fieldInfo struct {
	index    int
	name     string
	optional bool
	nilOK    bool
}

var fieldCache sync.Map // reflect.Type -> []fieldInfo

// structFields returns the exported fields of typ in declaration order,
// honoring `rlp:"-"`, `rlp:"optional"` and `rlp:"nil"` tags.
func structFields(typ reflect.Type) ([]fieldInfo, error) {
	if cached, ok := fieldCache.Load(typ); ok {
		return cached.([]fieldInfo), nil
	}
	var fields []fieldInfo
	seenOptional := false
	for i := 0; i < typ.NumField(); i++ {
		f := typ.Field(i)
		if f.PkgPath != "" {
			continue // unexported
		}
		tag := f.Tag.Get("rlp")
		if tag == "-" {
			continue
		}
		info := fieldInfo{index: i, name: f.Name}
		for _, opt := range splitTag(tag) {
			switch opt {
			case "", "nil":
				info.nilOK = opt == "nil"
			case "optional":
				info.optional = true
			default:
				return nil, fmt.Errorf("rlp: unknown tag %q on %s.%s", opt, typ, f.Name)
			}
		}
		if info.optional {
			seenOptional = true
		} else if seenOptional {
			return nil, fmt.Errorf("rlp: %s.%s is required but follows an optional field", typ, f.Name)
		}
		fields = append(fields, info)
	}
	sort.SliceStable(fields, func(i, j int) bool { return fields[i].index < fields[j].index })
	fieldCache.Store(typ, fields)
	return fields, nil
}

func splitTag(tag string) []string {
	if tag == "" {
		return nil
	}
	var out []string
	start := 0
	for i := 0; i <= len(tag); i++ {
		if i == len(tag) || tag[i] == ',' {
			out = append(out, tag[start:i])
			start = i + 1
		}
	}
	return out
}
