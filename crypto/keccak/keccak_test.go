package keccak

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func hexOf(b [32]byte) string { return hex.EncodeToString(b[:]) }

func TestKnownVectors(t *testing.T) {
	cases := []struct{ in, want string }{
		{"", "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"},
		{"abc", "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45"},
		{"hello world", "47173285a8d7341e5e972fc677286384f802f8ef42a5ec5f03bbfa254cb01fad"},
		{"The quick brown fox jumps over the lazy dog", "4d741b6f1eb29cb2a9b9911c82f56fa8d73b04959d3d9d222895df6c0b28aa15"},
	}
	for _, c := range cases {
		if got := hexOf(Sum256([]byte(c.in))); got != c.want {
			t.Errorf("Sum256(%q) = %s, want %s", c.in, got, c.want)
		}
	}
}

func TestStreamingMatchesOneShot(t *testing.T) {
	data := bytes.Repeat([]byte{0xa3}, 400) // spans multiple 136-byte blocks
	want := Sum256(data)

	d := New()
	d.Write(data[:7])
	d.Write(data[7:140])
	d.Write(data[140:272]) // exactly on a rate boundary
	d.Write(data[272:])
	var got [32]byte
	copy(got[:], d.Sum(nil))

	if got != want {
		t.Fatalf("streaming %x != one-shot %x", got, want)
	}
}

func TestSumDoesNotMutateState(t *testing.T) {
	d := New()
	d.Write([]byte("abc"))
	first := hex.EncodeToString(d.Sum(nil))
	second := hex.EncodeToString(d.Sum(nil))
	if first != second {
		t.Fatalf("Sum is not idempotent: %s vs %s", first, second)
	}
	d.Write([]byte("def"))
	if hex.EncodeToString(d.Sum(nil)) != hexOf(Sum256([]byte("abcdef"))) {
		t.Fatal("writing after Sum produced the wrong digest")
	}
}

func TestVariadicConcatenation(t *testing.T) {
	if Sum256([]byte("foo"), []byte("bar")) != Sum256([]byte("foobar")) {
		t.Fatal("variadic parts must hash as their concatenation")
	}
}

func TestReset(t *testing.T) {
	d := New()
	d.Write([]byte("noise"))
	d.Reset()
	if hex.EncodeToString(d.Sum(nil)) != hexOf(Sum256(nil)) {
		t.Fatal("Reset did not restore the initial state")
	}
}

func BenchmarkSum256_1KB(b *testing.B) {
	data := bytes.Repeat([]byte{0x5a}, 1024)
	b.SetBytes(int64(len(data)))
	for i := 0; i < b.N; i++ {
		Sum256(data)
	}
}
