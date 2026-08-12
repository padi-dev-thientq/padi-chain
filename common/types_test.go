package common

import (
	"math/big"
	"strings"
	"testing"
)

func TestEIP55Checksum(t *testing.T) {
	cases := []struct{ in, want string }{
		{"0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed", "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"},
		{"0xfb6916095ca1df60bb79ce92ce3ea74c37c5d359", "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359"},
		{"0xdbf03b407c01e7cd3cbea99509d93f8dddc8c6fb", "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB"},
		{"0xd1220a0cf47c7b9be7a2e6ba89f429762e7b9adb", "0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb"},
		{"0x0000000000000000000000000000000000000000", "0x0000000000000000000000000000000000000000"},
	}
	for _, c := range cases {
		got := MustHexToAddress(c.in).Checksum()
		if got != c.want {
			t.Errorf("Checksum(%s) = %s, want %s", c.in, got, c.want)
		}
	}
}

func TestAddressRoundTrip(t *testing.T) {
	a := MustHexToAddress("0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb")
	if got := MustHexToAddress(a.Hex()); got != a {
		t.Fatalf("hex round-trip changed the address: %x", got)
	}
	if got := BigToAddress(a.Big()); got != a {
		t.Fatalf("big round-trip changed the address: %x", got)
	}
}

func TestHexToAddressRejectsWrongLength(t *testing.T) {
	for _, s := range []string{"0x", "0xdeadbeef", "0x" + strings.Repeat("11", 21), "0xzz" + strings.Repeat("11", 19)} {
		if _, err := HexToAddress(s); err == nil {
			t.Errorf("HexToAddress(%q) should have failed", s)
		}
	}
}

func TestPadding(t *testing.T) {
	if got := LeftPadBytes([]byte{1, 2}, 4); string(got) != string([]byte{0, 0, 1, 2}) {
		t.Errorf("LeftPadBytes = %x", got)
	}
	if got := RightPadBytes([]byte{1, 2}, 4); string(got) != string([]byte{1, 2, 0, 0}) {
		t.Errorf("RightPadBytes = %x", got)
	}
	// Over-long inputs are truncated from the appropriate side.
	if got := LeftPadBytes([]byte{1, 2, 3}, 2); string(got) != string([]byte{2, 3}) {
		t.Errorf("LeftPadBytes truncation = %x", got)
	}
	if got := RightPadBytes([]byte{1, 2, 3}, 2); string(got) != string([]byte{1, 2}) {
		t.Errorf("RightPadBytes truncation = %x", got)
	}
}

func TestHexQuantities(t *testing.T) {
	if got := EncodeHexUint(0); got != "0x0" {
		t.Errorf("EncodeHexUint(0) = %s, want 0x0", got)
	}
	if got := EncodeHexUint(1024); got != "0x400" {
		t.Errorf("EncodeHexUint(1024) = %s, want 0x400", got)
	}
	if got := EncodeHexBig(nil); got != "0x0" {
		t.Errorf("EncodeHexBig(nil) = %s, want 0x0", got)
	}
	if got := EncodeHexBig(big.NewInt(255)); got != "0xff" {
		t.Errorf("EncodeHexBig(255) = %s", got)
	}
	v, err := DecodeHexUint("0x400")
	if err != nil || v != 1024 {
		t.Errorf("DecodeHexUint = %d, %v", v, err)
	}
	if _, err := DecodeHexUint("0x" + strings.Repeat("f", 17)); err == nil {
		t.Error("DecodeHexUint should reject values above uint64")
	}
}

func TestDecodeHexOddLength(t *testing.T) {
	b, err := DecodeHex("0x1")
	if err != nil || len(b) != 1 || b[0] != 1 {
		t.Fatalf("DecodeHex(0x1) = %x, %v", b, err)
	}
	if _, err := DecodeHex("0xqq"); err == nil {
		t.Error("DecodeHex should reject non-hex digits")
	}
}

func TestEmptyCodeHash(t *testing.T) {
	want := "0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
	if got := Hash(EmptyCodeHash).Hex(); got != want {
		t.Fatalf("EmptyCodeHash = %s, want %s", got, want)
	}
}
