package rlp

import (
	"bytes"
	"encoding/hex"
	"math/big"
	"strings"
	"testing"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// Vectors from the Ethereum yellow paper and the reference RLP test suite.
func TestEncodeKnownVectors(t *testing.T) {
	cases := []struct {
		name string
		in   any
		want string
	}{
		{"empty string", "", "80"},
		{"single char", "d", "64"},
		{"zero byte", []byte{0x00}, "00"},
		{"byte 0x7f", []byte{0x7f}, "7f"},
		{"byte 0x80", []byte{0x80}, "8180"},
		{"dog", "dog", "83646f67"},
		{"55 chars", strings.Repeat("a", 55), "b7" + hex.EncodeToString(bytes.Repeat([]byte("a"), 55))},
		{"56 chars", strings.Repeat("a", 56), "b838" + hex.EncodeToString(bytes.Repeat([]byte("a"), 56))},
		{"empty list", []string{}, "c0"},
		{"cat dog", []string{"cat", "dog"}, "c88363617483646f67"},
		{"zero", uint64(0), "80"},
		{"fifteen", uint64(15), "0f"},
		{"1024", uint64(1024), "820400"},
		{"big zero", big.NewInt(0), "80"},
		{"big 1024", big.NewInt(1024), "820400"},
		{"true", true, "01"},
		{"false", false, "80"},
	}
	for _, c := range cases {
		got, err := Encode(c.in)
		if err != nil {
			t.Errorf("%s: %v", c.name, err)
			continue
		}
		if hex.EncodeToString(got) != c.want {
			t.Errorf("%s: got %x, want %s", c.name, got, c.want)
		}
	}
}

func TestEncodeNestedLists(t *testing.T) {
	// The "set theoretic representation of three": [ [], [[]], [ [], [[]] ] ]
	type empty []any
	got, err := Encode([]any{
		[]any{},
		[]any{[]any{}},
		[]any{[]any{}, []any{[]any{}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(got) != "c7c0c1c0c3c0c1c0" {
		t.Fatalf("got %x, want c7c0c1c0c3c0c1c0", got)
	}
	_ = empty(nil)
}

func TestEncodeLongPayload(t *testing.T) {
	data := bytes.Repeat([]byte{0x61}, 1024)
	got, err := Encode(data)
	if err != nil {
		t.Fatal(err)
	}
	// 1024 needs a two-byte length: 0xb9 0x04 0x00
	if got[0] != 0xb9 || got[1] != 0x04 || got[2] != 0x00 {
		t.Fatalf("bad long-form header: %x", got[:3])
	}
	if len(got) != 3+1024 {
		t.Fatalf("length = %d, want %d", len(got), 3+1024)
	}
}

type person struct {
	Name string
	Age  uint64
}

type withOptional struct {
	A uint64
	B uint64
	C uint64 `rlp:"optional"`
}

type skipped struct {
	A uint64
	B string `rlp:"-"`
	C uint64
}

func TestStructRoundTrip(t *testing.T) {
	in := person{Name: "satoshi", Age: 42}
	enc, err := Encode(in)
	if err != nil {
		t.Fatal(err)
	}
	var out person
	if err := Decode(enc, &out); err != nil {
		t.Fatal(err)
	}
	if out != in {
		t.Fatalf("round-trip changed the value: %+v", out)
	}
}

func TestOptionalTrailingFields(t *testing.T) {
	// A zero trailing optional field is omitted from the encoding.
	short, err := Encode(withOptional{A: 1, B: 2})
	if err != nil {
		t.Fatal(err)
	}
	long, err := Encode(withOptional{A: 1, B: 2, C: 3})
	if err != nil {
		t.Fatal(err)
	}
	if len(short) >= len(long) {
		t.Fatalf("omitted field did not shorten the encoding: %x vs %x", short, long)
	}

	var out withOptional
	if err := Decode(short, &out); err != nil {
		t.Fatal(err)
	}
	if out.A != 1 || out.B != 2 || out.C != 0 {
		t.Fatalf("absent optional field should decode to zero, got %+v", out)
	}
	out = withOptional{}
	if err := Decode(long, &out); err != nil {
		t.Fatal(err)
	}
	if out.C != 3 {
		t.Fatalf("present optional field lost: %+v", out)
	}
}

func TestSkippedField(t *testing.T) {
	enc, err := Encode(skipped{A: 1, B: "ignored", C: 2})
	if err != nil {
		t.Fatal(err)
	}
	var out skipped
	if err := Decode(enc, &out); err != nil {
		t.Fatal(err)
	}
	if out.A != 1 || out.C != 2 || out.B != "" {
		t.Fatalf("`rlp:\"-\"` field was not skipped: %+v", out)
	}
}

func TestRequiredAfterOptionalIsRejected(t *testing.T) {
	type bad struct {
		A uint64 `rlp:"optional"`
		B uint64
	}
	if _, err := Encode(bad{}); err == nil {
		t.Fatal("a required field after an optional one must be rejected")
	}
}

func TestDecodeIntoFixedArray(t *testing.T) {
	var arr [4]byte
	enc, _ := Encode([]byte{1, 2, 3, 4})
	if err := Decode(enc, &arr); err != nil {
		t.Fatal(err)
	}
	if arr != [4]byte{1, 2, 3, 4} {
		t.Fatalf("array = %v", arr)
	}
	wrong, _ := Encode([]byte{1, 2, 3})
	if err := Decode(wrong, &arr); err == nil {
		t.Fatal("wrong-length payload must be rejected for a fixed array")
	}
}

func TestDecodeSliceOfStructs(t *testing.T) {
	in := []person{{"a", 1}, {"b", 2}, {"c", 3}}
	enc, err := Encode(in)
	if err != nil {
		t.Fatal(err)
	}
	var out []person
	if err := Decode(enc, &out); err != nil {
		t.Fatal(err)
	}
	if len(out) != 3 || out[2].Name != "c" || out[2].Age != 3 {
		t.Fatalf("decoded %+v", out)
	}
}

func TestDecodeBigInt(t *testing.T) {
	in := new(big.Int).Lsh(big.NewInt(1), 200)
	enc, err := Encode(in)
	if err != nil {
		t.Fatal(err)
	}
	var out *big.Int
	if err := Decode(enc, &out); err != nil {
		t.Fatal(err)
	}
	if out.Cmp(in) != 0 {
		t.Fatalf("got %s, want %s", out, in)
	}
}

func TestNegativeBigIntRejected(t *testing.T) {
	if _, err := Encode(big.NewInt(-1)); err != ErrNegativeBigInt {
		t.Fatalf("got %v, want ErrNegativeBigInt", err)
	}
}

func TestCanonicalityChecks(t *testing.T) {
	cases := map[string]string{
		"leading zero in integer":  "820001", // 0x0001 must encode as 0x01
		"long form for short data": "b800",   // length 0 must use the short form
		"single byte in string":    "8105",   // 0x05 must encode as itself
		"size prefix leading zero": "b90040", // length bytes must not start with 0
	}
	for name, h := range cases {
		var out []byte
		var num uint64
		data := mustHex(t, h)
		errBytes := Decode(data, &out)
		errNum := Decode(data, &num)
		if errBytes == nil && errNum == nil {
			t.Errorf("%s: %s decoded without error", name, h)
		}
	}
}

func TestTruncatedInputRejected(t *testing.T) {
	enc, _ := Encode(person{"truncate me", 7})
	for i := 1; i < len(enc); i++ {
		var out person
		if err := Decode(enc[:i], &out); err == nil {
			t.Fatalf("truncation at %d decoded successfully", i)
		}
	}
}

func TestTrailingDataRejected(t *testing.T) {
	enc, _ := Encode("hello")
	var out string
	if err := Decode(append(enc, 0x01), &out); err != ErrTrailingData {
		t.Fatalf("got %v, want ErrTrailingData", err)
	}
}

func TestListLengthMismatch(t *testing.T) {
	// A three-element list cannot decode into a two-field struct.
	enc, _ := Encode([]uint64{1, 2, 3})
	var out person
	if err := Decode(enc, &out); err == nil {
		t.Fatal("extra list elements must be rejected")
	}
	enc, _ = Encode([]uint64{1})
	if err := Decode(enc, &out); err == nil {
		t.Fatal("missing list elements must be rejected")
	}
}

func TestUintOverflow(t *testing.T) {
	enc, _ := Encode(uint64(300))
	var small uint8
	if err := Decode(enc, &small); err == nil {
		t.Fatal("300 must not decode into a uint8")
	}
}

func TestRawValuePassThrough(t *testing.T) {
	inner, _ := Encode([]string{"a", "b"})
	enc, err := Encode([]any{RawValue(inner), "c"})
	if err != nil {
		t.Fatal(err)
	}
	items, err := Split(enc)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 2 || !bytes.Equal(items[0], inner) {
		t.Fatalf("raw value was not spliced verbatim: %x", enc)
	}
}

func TestEncodeListHelper(t *testing.T) {
	a := EncodeBytes([]byte("cat"))
	b := EncodeBytes([]byte("dog"))
	if hex.EncodeToString(EncodeList(a, b)) != "c88363617483646f67" {
		t.Fatalf("EncodeList = %x", EncodeList(a, b))
	}
}

func TestStreamKindAndNesting(t *testing.T) {
	enc, _ := Encode([]any{"a", []string{"b", "c"}})
	s := NewStream(enc)
	kind, _, err := s.Kind()
	if err != nil || kind != List {
		t.Fatalf("Kind = %v, %v", kind, err)
	}
	inner, err := s.List()
	if err != nil {
		t.Fatal(err)
	}
	first, err := inner.Bytes()
	if err != nil || string(first) != "a" {
		t.Fatalf("first element = %q, %v", first, err)
	}
	nested, err := inner.List()
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for !nested.Empty() {
		b, err := nested.Bytes()
		if err != nil {
			t.Fatal(err)
		}
		got = append(got, string(b))
	}
	if len(got) != 2 || got[0] != "b" || got[1] != "c" {
		t.Fatalf("nested list = %v", got)
	}
	if !inner.Empty() {
		t.Fatal("outer list should be exhausted")
	}
}

func TestPointerHandling(t *testing.T) {
	type holder struct {
		P *big.Int
	}
	enc, err := Encode(holder{P: big.NewInt(7)})
	if err != nil {
		t.Fatal(err)
	}
	var out holder
	if err := Decode(enc, &out); err != nil {
		t.Fatal(err)
	}
	if out.P.Int64() != 7 {
		t.Fatalf("pointer field = %v", out.P)
	}
}

func BenchmarkEncodeStruct(b *testing.B) {
	p := person{Name: "benchmark", Age: 99}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		Encode(p)
	}
}
