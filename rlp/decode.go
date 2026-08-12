package rlp

import (
	"errors"
	"fmt"
	"io"
	"math/big"
	"reflect"
)

var (
	ErrUnexpectedEOF   = errors.New("rlp: input truncated")
	ErrExpectedString  = errors.New("rlp: expected a byte string, got a list")
	ErrExpectedList    = errors.New("rlp: expected a list, got a byte string")
	ErrCanonInt        = errors.New("rlp: non-canonical integer (leading zero bytes)")
	ErrCanonSize       = errors.New("rlp: non-canonical size prefix")
	ErrOversizedLength = errors.New("rlp: size prefix exceeds the addressable range")
	ErrTrailingData    = errors.New("rlp: trailing bytes after the top-level item")
	ErrTooManyFields   = errors.New("rlp: list has more elements than the target struct")
	ErrTooFewFields    = errors.New("rlp: list has fewer elements than the target struct")
	ErrValueTooLarge   = errors.New("rlp: value does not fit the target type")
)

// Decoder lets a type control its own decoding.
type Decoder interface {
	DecodeRLP(*Stream) error
}

var decoderInterface = reflect.TypeOf((*Decoder)(nil)).Elem()

// Kind distinguishes the two RLP item shapes.
type Kind int

const (
	Byte Kind = iota // a single byte below 0x80, a degenerate string
	String
	List
)

func (k Kind) String() string {
	switch k {
	case Byte:
		return "byte"
	case String:
		return "string"
	default:
		return "list"
	}
}

// Decode parses RLP into the value pointed to by out, which must be a non-nil
// pointer. It rejects trailing bytes: the input must be exactly one item.
func Decode(data []byte, out any) error {
	s := NewStream(data)
	if err := s.Decode(out); err != nil {
		return err
	}
	if s.Remaining() > 0 {
		return ErrTrailingData
	}
	return nil
}

// Stream is a cursor over an RLP payload.
type Stream struct {
	data []byte
	pos  int
}

func NewStream(data []byte) *Stream { return &Stream{data: data} }

func (s *Stream) Remaining() int { return len(s.data) - s.pos }

func (s *Stream) Empty() bool { return s.Remaining() == 0 }

// Reset points the stream at new data.
func (s *Stream) Reset(data []byte) {
	s.data = data
	s.pos = 0
}

// Kind reports the shape of the next item without consuming it.
func (s *Stream) Kind() (Kind, uint64, error) {
	if s.Empty() {
		return 0, 0, ErrUnexpectedEOF
	}
	b := s.data[s.pos]
	switch {
	case b < 0x80:
		return Byte, 1, nil
	case b < 0xB8:
		return String, uint64(b - 0x80), nil
	case b < 0xC0:
		size, err := s.peekLength(int(b - 0xB7))
		return String, size, err
	case b < 0xF8:
		return List, uint64(b - 0xC0), nil
	default:
		size, err := s.peekLength(int(b - 0xF7))
		return List, size, err
	}
}

// peekLength reads the long-form length that follows the prefix byte.
func (s *Stream) peekLength(lenOfLen int) (uint64, error) {
	if lenOfLen > 8 {
		return 0, ErrOversizedLength
	}
	if s.Remaining() < 1+lenOfLen {
		return 0, ErrUnexpectedEOF
	}
	raw := s.data[s.pos+1 : s.pos+1+lenOfLen]
	if raw[0] == 0 {
		return 0, ErrCanonSize
	}
	var size uint64
	for _, c := range raw {
		size = size<<8 | uint64(c)
	}
	// The long form is only canonical for payloads that do not fit the short form.
	if size < 56 {
		return 0, ErrCanonSize
	}
	if size > uint64(maxInt) {
		return 0, ErrOversizedLength
	}
	return size, nil
}

const maxInt = int(^uint(0) >> 1)

// headerSize is the number of prefix bytes for an item of the given kind and size.
func headerSize(kind Kind, size uint64) int {
	switch kind {
	case Byte:
		return 0
	case String:
		if size < 56 {
			return 1
		}
	case List:
		if size < 56 {
			return 1
		}
	}
	return 1 + byteLen(size)
}

func byteLen(v uint64) int {
	n := 0
	for v > 0 {
		n++
		v >>= 8
	}
	return n
}

// Bytes consumes the next item, which must be a byte string, and returns its
// payload. The returned slice aliases the input.
func (s *Stream) Bytes() ([]byte, error) {
	kind, size, err := s.Kind()
	if err != nil {
		return nil, err
	}
	if kind == List {
		return nil, ErrExpectedString
	}
	if kind == Byte {
		b := s.data[s.pos : s.pos+1]
		s.pos++
		return b, nil
	}
	hdr := headerSize(kind, size)
	if uint64(s.Remaining()) < uint64(hdr)+size {
		return nil, ErrUnexpectedEOF
	}
	start := s.pos + hdr
	end := start + int(size)
	// A single byte below 0x80 must use its own one-byte encoding.
	if size == 1 && s.data[start] < 0x80 {
		return nil, ErrCanonSize
	}
	s.pos = end
	return s.data[start:end], nil
}

// Raw consumes the next item and returns it including its header.
func (s *Stream) Raw() ([]byte, error) {
	kind, size, err := s.Kind()
	if err != nil {
		return nil, err
	}
	total := headerSize(kind, size) + int(size)
	if kind == Byte {
		total = 1
	}
	if s.Remaining() < total {
		return nil, ErrUnexpectedEOF
	}
	out := s.data[s.pos : s.pos+total]
	s.pos += total
	return out, nil
}

// List enters the next item, which must be a list, and returns a stream over
// its elements.
func (s *Stream) List() (*Stream, error) {
	kind, size, err := s.Kind()
	if err != nil {
		return nil, err
	}
	if kind != List {
		return nil, ErrExpectedList
	}
	hdr := headerSize(kind, size)
	if uint64(s.Remaining()) < uint64(hdr)+size {
		return nil, ErrUnexpectedEOF
	}
	start := s.pos + hdr
	end := start + int(size)
	s.pos = end
	return &Stream{data: s.data[start:end]}, nil
}

// Uint consumes a byte string and interprets it as an unsigned integer.
func (s *Stream) Uint() (uint64, error) {
	b, err := s.Bytes()
	if err != nil {
		return 0, err
	}
	if len(b) > 8 {
		return 0, ErrValueTooLarge
	}
	if len(b) > 0 && b[0] == 0 {
		return 0, ErrCanonInt
	}
	var v uint64
	for _, c := range b {
		v = v<<8 | uint64(c)
	}
	return v, nil
}

// BigInt consumes a byte string and interprets it as a non-negative integer.
func (s *Stream) BigInt() (*big.Int, error) {
	b, err := s.Bytes()
	if err != nil {
		return nil, err
	}
	if len(b) > 0 && b[0] == 0 {
		return nil, ErrCanonInt
	}
	return new(big.Int).SetBytes(b), nil
}

// Decode reads the next item into out, which must be a non-nil pointer.
func (s *Stream) Decode(out any) error {
	if out == nil {
		return errors.New("rlp: Decode into nil")
	}
	v := reflect.ValueOf(out)
	if v.Kind() != reflect.Ptr || v.IsNil() {
		return fmt.Errorf("rlp: Decode requires a non-nil pointer, got %T", out)
	}
	return s.decodeValue(v.Elem())
}

func (s *Stream) decodeValue(v reflect.Value) error {
	typ := v.Type()

	if typ == rawValueType {
		raw, err := s.Raw()
		if err != nil {
			return err
		}
		v.SetBytes(append([]byte(nil), raw...))
		return nil
	}

	if v.CanAddr() && reflect.PtrTo(typ).Implements(decoderInterface) {
		return v.Addr().Interface().(Decoder).DecodeRLP(s)
	}

	switch typ.Kind() {
	case reflect.Ptr:
		if typ.Elem() == bigIntType {
			i, err := s.BigInt()
			if err != nil {
				return err
			}
			v.Set(reflect.ValueOf(i))
			return nil
		}
		elem := reflect.New(typ.Elem())
		if err := s.decodeValue(elem.Elem()); err != nil {
			return err
		}
		v.Set(elem)
		return nil

	case reflect.Struct:
		if typ == bigIntType {
			i, err := s.BigInt()
			if err != nil {
				return err
			}
			v.Set(reflect.ValueOf(*i))
			return nil
		}
		return s.decodeStruct(v)

	case reflect.String:
		b, err := s.Bytes()
		if err != nil {
			return err
		}
		v.SetString(string(b))
		return nil

	case reflect.Bool:
		u, err := s.Uint()
		if err != nil {
			return err
		}
		if u > 1 {
			return fmt.Errorf("rlp: %d is not a boolean", u)
		}
		v.SetBool(u == 1)
		return nil

	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		u, err := s.Uint()
		if err != nil {
			return err
		}
		if v.OverflowUint(u) {
			return fmt.Errorf("%w: %d overflows %s", ErrValueTooLarge, u, typ)
		}
		v.SetUint(u)
		return nil

	case reflect.Slice:
		if typ.Elem().Kind() == reflect.Uint8 {
			b, err := s.Bytes()
			if err != nil {
				return err
			}
			v.SetBytes(append([]byte(nil), b...))
			return nil
		}
		inner, err := s.List()
		if err != nil {
			return err
		}
		out := reflect.MakeSlice(typ, 0, 4)
		for !inner.Empty() {
			elem := reflect.New(typ.Elem())
			if err := inner.decodeValue(elem.Elem()); err != nil {
				return err
			}
			out = reflect.Append(out, elem.Elem())
		}
		v.Set(out)
		return nil

	case reflect.Array:
		if typ.Elem().Kind() == reflect.Uint8 {
			b, err := s.Bytes()
			if err != nil {
				return err
			}
			if len(b) != v.Len() {
				return fmt.Errorf("%w: %s wants %d bytes, got %d", ErrValueTooLarge, typ, v.Len(), len(b))
			}
			reflect.Copy(v, reflect.ValueOf(b))
			return nil
		}
		inner, err := s.List()
		if err != nil {
			return err
		}
		for i := 0; i < v.Len(); i++ {
			if inner.Empty() {
				return ErrTooFewFields
			}
			if err := inner.decodeValue(v.Index(i)); err != nil {
				return err
			}
		}
		if !inner.Empty() {
			return ErrTooManyFields
		}
		return nil

	case reflect.Interface:
		// Without a concrete target the best we can do is hand back raw bytes.
		raw, err := s.Raw()
		if err != nil {
			return err
		}
		v.Set(reflect.ValueOf(RawValue(append([]byte(nil), raw...))))
		return nil

	default:
		return fmt.Errorf("%w: %s", ErrUnsupported, typ)
	}
}

func (s *Stream) decodeStruct(v reflect.Value) error {
	fields, err := structFields(v.Type())
	if err != nil {
		return err
	}
	inner, err := s.List()
	if err != nil {
		return err
	}
	for _, f := range fields {
		if inner.Empty() {
			if f.optional {
				// Absent optional fields keep their zero value.
				continue
			}
			return fmt.Errorf("%w: missing %s.%s", ErrTooFewFields, v.Type(), f.name)
		}
		if err := inner.decodeValue(v.Field(f.index)); err != nil {
			return fmt.Errorf("field %s: %w", f.name, err)
		}
	}
	if !inner.Empty() {
		return fmt.Errorf("%w: decoding %s", ErrTooManyFields, v.Type())
	}
	return nil
}

// DecodeFrom reads one complete RLP item from r and decodes it into out.
func DecodeFrom(r io.Reader, out any) error {
	data, err := io.ReadAll(r)
	if err != nil {
		return err
	}
	return Decode(data, out)
}

// Split returns the elements of a top-level list as raw encoded items.
func Split(data []byte) ([][]byte, error) {
	s := NewStream(data)
	inner, err := s.List()
	if err != nil {
		return nil, err
	}
	var out [][]byte
	for !inner.Empty() {
		item, err := inner.Raw()
		if err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, nil
}
