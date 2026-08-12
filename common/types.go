// Package common defines the primitive value types shared across the node:
// 20-byte addresses, 32-byte hashes, and hex helpers.
package common

import (
	"database/sql/driver"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"strconv"
	"strings"

	"layer1/crypto/keccak"
)

const (
	AddressLength = 20
	HashLength    = 32
)

type Address [AddressLength]byte

type Hash [HashLength]byte

var (
	ZeroAddress Address
	ZeroHash    Hash

	// EmptyCodeHash is keccak256 of the empty byte string: the code hash of any
	// account that holds no code.
	EmptyCodeHash = keccak.Sum256(nil)
)

var ErrBadHex = errors.New("common: invalid hex string")

// BytesToAddress takes the rightmost 20 bytes of b (left-padding if shorter).
func BytesToAddress(b []byte) Address {
	var a Address
	if len(b) > AddressLength {
		b = b[len(b)-AddressLength:]
	}
	copy(a[AddressLength-len(b):], b)
	return a
}

func BigToAddress(v *big.Int) Address { return BytesToAddress(v.Bytes()) }

func HexToAddress(s string) (Address, error) {
	b, err := DecodeHex(s)
	if err != nil {
		return Address{}, err
	}
	if len(b) != AddressLength {
		return Address{}, fmt.Errorf("%w: address must be %d bytes, got %d", ErrBadHex, AddressLength, len(b))
	}
	return BytesToAddress(b), nil
}

// MustHexToAddress is for constants and tests; it panics on malformed input.
func MustHexToAddress(s string) Address {
	a, err := HexToAddress(s)
	if err != nil {
		panic(err)
	}
	return a
}

func (a Address) Bytes() []byte  { return a[:] }
func (a Address) Big() *big.Int  { return new(big.Int).SetBytes(a[:]) }
func (a Address) Hash() Hash     { return BytesToHash(a[:]) }
func (a Address) Hex() string    { return "0x" + hex.EncodeToString(a[:]) }
func (a Address) String() string { return a.Checksum() }
func (a Address) IsZero() bool   { return a == ZeroAddress }

// Checksum renders the address in EIP-55 mixed-case form.
func (a Address) Checksum() string {
	lower := hex.EncodeToString(a[:])
	sum := keccak.Sum256([]byte(lower))
	out := []byte("0x" + lower)
	for i := 0; i < len(lower); i++ {
		c := lower[i]
		if c < 'a' || c > 'f' {
			continue
		}
		nibble := sum[i/2] >> 4
		if i%2 == 1 {
			nibble = sum[i/2] & 0xf
		}
		if nibble >= 8 {
			out[2+i] = c - 'a' + 'A'
		}
	}
	return string(out)
}

func (a Address) MarshalText() ([]byte, error) { return []byte(a.Hex()), nil }

func (a *Address) UnmarshalText(text []byte) error {
	v, err := HexToAddress(string(text))
	if err != nil {
		return err
	}
	*a = v
	return nil
}

func (a Address) Value() (driver.Value, error) { return a[:], nil }

// BytesToHash takes the rightmost 32 bytes of b (left-padding if shorter).
func BytesToHash(b []byte) Hash {
	var h Hash
	if len(b) > HashLength {
		b = b[len(b)-HashLength:]
	}
	copy(h[HashLength-len(b):], b)
	return h
}

func BigToHash(v *big.Int) Hash { return BytesToHash(v.Bytes()) }

func HexToHash(s string) (Hash, error) {
	b, err := DecodeHex(s)
	if err != nil {
		return Hash{}, err
	}
	if len(b) != HashLength {
		return Hash{}, fmt.Errorf("%w: hash must be %d bytes, got %d", ErrBadHex, HashLength, len(b))
	}
	return BytesToHash(b), nil
}

func MustHexToHash(s string) Hash {
	h, err := HexToHash(s)
	if err != nil {
		panic(err)
	}
	return h
}

func (h Hash) Bytes() []byte  { return h[:] }
func (h Hash) Big() *big.Int  { return new(big.Int).SetBytes(h[:]) }
func (h Hash) Hex() string    { return "0x" + hex.EncodeToString(h[:]) }
func (h Hash) String() string { return h.Hex() }
func (h Hash) IsZero() bool   { return h == ZeroHash }

func (h Hash) MarshalText() ([]byte, error) { return []byte(h.Hex()), nil }

func (h *Hash) UnmarshalText(text []byte) error {
	v, err := HexToHash(string(text))
	if err != nil {
		return err
	}
	*h = v
	return nil
}

// Keccak256 hashes the concatenation of the given byte slices.
func Keccak256(data ...[]byte) Hash { return Hash(keccak.Sum256(data...)) }

// EncodeHex renders bytes as a 0x-prefixed lowercase hex string.
func EncodeHex(b []byte) string { return "0x" + hex.EncodeToString(b) }

// DecodeHex parses a hex string with an optional 0x prefix. An odd number of
// digits is read as having an implicit leading zero nibble.
func DecodeHex(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		s = s[2:]
	}
	if len(s)%2 == 1 {
		s = "0" + s
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBadHex, err)
	}
	return b, nil
}

// EncodeHexUint renders an integer in the minimal 0x-prefixed form used by the
// JSON-RPC API ("0x0" for zero, no leading zeros otherwise).
func EncodeHexUint(v uint64) string { return "0x" + strconv.FormatUint(v, 16) }

// EncodeHexBig renders a big.Int in minimal 0x-prefixed hex form.
func EncodeHexBig(v *big.Int) string {
	if v == nil || v.Sign() == 0 {
		return "0x0"
	}
	return "0x" + v.Text(16)
}

// DecodeHexUint parses a 0x-prefixed quantity.
func DecodeHexUint(s string) (uint64, error) {
	v, err := DecodeHexBig(s)
	if err != nil {
		return 0, err
	}
	if !v.IsUint64() {
		return 0, fmt.Errorf("%w: value overflows uint64", ErrBadHex)
	}
	return v.Uint64(), nil
}

// DecodeHexBig parses a 0x-prefixed quantity into a big.Int.
func DecodeHexBig(s string) (*big.Int, error) {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(strings.TrimPrefix(s, "0x"), "0X")
	if s == "" {
		return new(big.Int), nil
	}
	v, ok := new(big.Int).SetString(s, 16)
	if !ok {
		return nil, fmt.Errorf("%w: %q is not a hex quantity", ErrBadHex, s)
	}
	return v, nil
}

// LeftPadBytes zero-extends b on the left to exactly n bytes, truncating from
// the left if b is longer.
func LeftPadBytes(b []byte, n int) []byte {
	if len(b) >= n {
		return b[len(b)-n:]
	}
	out := make([]byte, n)
	copy(out[n-len(b):], b)
	return out
}

// RightPadBytes zero-extends b on the right to exactly n bytes.
func RightPadBytes(b []byte, n int) []byte {
	if len(b) >= n {
		return b[:n]
	}
	out := make([]byte, n)
	copy(out, b)
	return out
}

// CopyBytes returns a defensive copy, preserving nil.
func CopyBytes(b []byte) []byte {
	if b == nil {
		return nil
	}
	out := make([]byte, len(b))
	copy(out, b)
	return out
}
