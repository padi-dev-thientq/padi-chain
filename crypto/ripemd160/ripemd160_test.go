package ripemd160

import (
	"encoding/hex"
	"strings"
	"testing"
)

// Vectors from the RIPEMD-160 specification.
func TestKnownVectors(t *testing.T) {
	cases := []struct{ in, want string }{
		{"", "9c1185a5c5e9fc54612808977ee8f548b2258d31"},
		{"a", "0bdc9d2d256b3ee9daae347be6f4dc835a467ffe"},
		{"abc", "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc"},
		{"message digest", "5d0689ef49d2fae572b881b123a85ffa21595f36"},
		{"abcdefghijklmnopqrstuvwxyz", "f71c27109c692c1b56bbdceb5b9d2865b3708dbc"},
		{"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", "12a053384a9c0c88e405a06c27dcf49ada62eb2b"},
		{"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", "b0e20b6e3116640286ed3a87a5713079b21f5189"},
		{strings.Repeat("1234567890", 8), "9b752e45573d4b39f4dbd3323cab82bf63326bfb"},
		{strings.Repeat("a", 1000000), "52783243c1697bdbe16d37f97f68f08325dc1528"},
	}
	for _, c := range cases {
		sum := Sum160([]byte(c.in))
		got := hex.EncodeToString(sum[:])
		if got != c.want {
			label := c.in
			if len(label) > 20 {
				label = label[:20] + "..."
			}
			t.Errorf("Sum160(%q) = %s, want %s", label, got, c.want)
		}
	}
}

func TestStreamingMatchesOneShot(t *testing.T) {
	data := []byte(strings.Repeat("padi-chain", 500))
	want := Sum160(data)

	d := New()
	d.Write(data[:7])
	d.Write(data[7:64]) // exactly on a block boundary
	d.Write(data[64:200])
	d.Write(data[200:])
	var got [Size]byte
	copy(got[:], d.Sum(nil))

	if got != want {
		t.Fatalf("streaming %x != one-shot %x", got, want)
	}
}

func TestSumIsRepeatable(t *testing.T) {
	d := New()
	d.Write([]byte("abc"))
	first := hex.EncodeToString(d.Sum(nil))
	if second := hex.EncodeToString(d.Sum(nil)); first != second {
		t.Fatalf("Sum is not idempotent: %s vs %s", first, second)
	}
	// The digest must still be usable after Sum.
	d.Write([]byte("def"))
	want := Sum160([]byte("abcdef"))
	if hex.EncodeToString(d.Sum(nil)) != hex.EncodeToString(want[:]) {
		t.Fatal("writing after Sum produced the wrong digest")
	}
}

func TestReset(t *testing.T) {
	d := New()
	d.Write([]byte("noise"))
	d.Reset()
	fresh := Sum160(nil)
	if hex.EncodeToString(d.Sum(nil)) != hex.EncodeToString(fresh[:]) {
		t.Fatal("Reset did not restore the initial state")
	}
}
