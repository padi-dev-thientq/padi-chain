package secp256k1

import (
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"fmt"
	"math/big"

	"layer1/crypto/keccak"
)

const (
	// PrivateKeyLength is the length of a serialized secret scalar.
	PrivateKeyLength = 32
	// PublicKeyLength is the length of an uncompressed key without the 0x04 tag,
	// which is the form Ethereum hashes to derive addresses.
	PublicKeyLength = 64
	// SignatureLength is r || s || v.
	SignatureLength = 65
)

var (
	ErrInvalidSignature = errors.New("secp256k1: invalid signature")
	ErrRecoveryFailed   = errors.New("secp256k1: public key recovery failed")
	ErrHashLength       = errors.New("secp256k1: message hash must be 32 bytes")
)

// PrivateKey is a secret scalar in [1, N-1].
type PrivateKey struct {
	D *big.Int
}

// PublicKey is a point on the curve in affine form.
type PublicKey struct {
	X, Y *big.Int
}

// Signature is an ECDSA signature plus the recovery id V in [0,3].
type Signature struct {
	R, S *big.Int
	V    byte
}

// GenerateKey draws a uniformly random secret scalar from the OS CSPRNG.
func GenerateKey() (*PrivateKey, error) {
	for {
		buf := make([]byte, PrivateKeyLength)
		if _, err := rand.Read(buf); err != nil {
			return nil, fmt.Errorf("secp256k1: reading entropy: %w", err)
		}
		d := new(big.Int).SetBytes(buf)
		// Rejection sampling keeps the distribution uniform over [1, N-1].
		if d.Sign() != 0 && d.Cmp(N) < 0 {
			return &PrivateKey{D: d}, nil
		}
	}
}

// PrivateKeyFromBytes parses a 32-byte big-endian secret scalar.
func PrivateKeyFromBytes(b []byte) (*PrivateKey, error) {
	if len(b) != PrivateKeyLength {
		return nil, fmt.Errorf("%w: expected %d bytes, got %d", ErrInvalidKey, PrivateKeyLength, len(b))
	}
	d := new(big.Int).SetBytes(b)
	if d.Sign() == 0 || d.Cmp(N) >= 0 {
		return nil, ErrInvalidKey
	}
	return &PrivateKey{D: d}, nil
}

// PrivateKeyFromHex parses a hex-encoded secret scalar.
func PrivateKeyFromHex(s string) (*PrivateKey, error) {
	if len(s) > 1 && (s[:2] == "0x" || s[:2] == "0X") {
		s = s[2:]
	}
	d, ok := new(big.Int).SetString(s, 16)
	if !ok {
		return nil, fmt.Errorf("%w: not hex", ErrInvalidKey)
	}
	return PrivateKeyFromBytes(padTo32(d))
}

func padTo32(v *big.Int) []byte {
	out := make([]byte, 32)
	v.FillBytes(out)
	return out
}

// Bytes serializes the secret scalar as 32 big-endian bytes.
func (k *PrivateKey) Bytes() []byte { return padTo32(k.D) }

// PublicKey derives the corresponding public key.
func (k *PrivateKey) PublicKey() *PublicKey {
	x, y, ok := ScalarBaseMul(k.D).Affine()
	if !ok {
		// Unreachable for a valid scalar: only 0 maps to infinity, and the
		// constructors reject it.
		panic("secp256k1: derived the point at infinity from a nonzero scalar")
	}
	return &PublicKey{X: x, Y: y}
}

// Bytes serializes the public key as the 64-byte X || Y form.
func (p *PublicKey) Bytes() []byte {
	out := make([]byte, PublicKeyLength)
	p.X.FillBytes(out[:32])
	p.Y.FillBytes(out[32:])
	return out
}

// SEC1Uncompressed serializes as 0x04 || X || Y.
func (p *PublicKey) SEC1Uncompressed() []byte {
	return append([]byte{0x04}, p.Bytes()...)
}

// SEC1Compressed serializes as 0x02/0x03 || X.
func (p *PublicKey) SEC1Compressed() []byte {
	prefix := byte(0x02)
	if p.Y.Bit(0) == 1 {
		prefix = 0x03
	}
	out := make([]byte, 33)
	out[0] = prefix
	p.X.FillBytes(out[1:])
	return out
}

func (p *PublicKey) Point() *Point { return NewPoint(p.X, p.Y) }

func (p *PublicKey) Equal(q *PublicKey) bool {
	if p == nil || q == nil {
		return p == q
	}
	return p.X.Cmp(q.X) == 0 && p.Y.Cmp(q.Y) == 0
}

// ParsePublicKey accepts the 64-byte, 65-byte uncompressed (0x04-tagged) and
// 33-byte compressed encodings, and validates the result lies on the curve.
func ParsePublicKey(b []byte) (*PublicKey, error) {
	switch {
	case len(b) == PublicKeyLength:
		pk := &PublicKey{X: new(big.Int).SetBytes(b[:32]), Y: new(big.Int).SetBytes(b[32:])}
		if !pk.Point().OnCurve() {
			return nil, ErrInvalidPoint
		}
		return pk, nil
	case len(b) == 65 && b[0] == 0x04:
		return ParsePublicKey(b[1:])
	case len(b) == 33 && (b[0] == 0x02 || b[0] == 0x03):
		x := new(big.Int).SetBytes(b[1:])
		y, err := decompressY(x, b[0] == 0x03)
		if err != nil {
			return nil, err
		}
		return &PublicKey{X: x, Y: y}, nil
	default:
		return nil, fmt.Errorf("%w: unrecognized public key encoding of %d bytes", ErrInvalidPoint, len(b))
	}
}

// nonce derives the per-signature secret k deterministically.
//
// This is not RFC 6979 (which specifies HMAC-DRBG over SHA-256); it is the same
// construction expressed with Keccak, which the rest of the stack already uses.
// The property that matters is preserved: k depends on both the secret and the
// message, so it never repeats across distinct messages and cannot be predicted
// without the secret. The counter lets us resample in the negligible-probability
// case that a candidate is out of range.
func nonce(d *big.Int, hash []byte, counter uint32) *big.Int {
	ctr := []byte{byte(counter >> 24), byte(counter >> 16), byte(counter >> 8), byte(counter)}
	h := keccak.Sum256([]byte("layer1/secp256k1/nonce/v1"), padTo32(d), hash, ctr)
	return new(big.Int).SetBytes(h[:])
}

// Sign produces a deterministic, low-s ECDSA signature over a 32-byte hash.
func Sign(key *PrivateKey, hash []byte) (*Signature, error) {
	if len(hash) != 32 {
		return nil, ErrHashLength
	}
	if key == nil || key.D.Sign() == 0 || key.D.Cmp(N) >= 0 {
		return nil, ErrInvalidKey
	}
	z := hashToInt(hash)

	for counter := uint32(0); counter < 1000; counter++ {
		k := nonce(key.D, hash, counter)
		if k.Sign() == 0 || k.Cmp(N) >= 0 {
			continue
		}
		px, py, ok := ScalarBaseMul(k).Affine()
		if !ok {
			continue
		}
		// r = x mod n. Remember whether x exceeded n: the recovery id needs it
		// to rebuild the correct R.
		r := new(big.Int).Mod(px, N)
		if r.Sign() == 0 {
			continue
		}
		overflow := px.Cmp(N) >= 0

		kInv := new(big.Int).ModInverse(k, N)
		if kInv == nil {
			continue
		}
		s := new(big.Int).Mul(r, key.D)
		s.Add(s, z)
		s.Mul(s, kInv)
		s.Mod(s, N)
		if s.Sign() == 0 {
			continue
		}

		yOdd := py.Bit(0) == 1
		// Enforce low-s to remove signature malleability. Negating s mirrors R
		// across the x-axis, which flips the parity bit of the recovery id.
		if s.Cmp(halfN) > 0 {
			s.Sub(N, s)
			yOdd = !yOdd
		}

		v := byte(0)
		if yOdd {
			v |= 1
		}
		if overflow {
			v |= 2
		}
		return &Signature{R: r, S: s, V: v}, nil
	}
	return nil, errors.New("secp256k1: failed to derive a usable nonce")
}

// hashToInt interprets the message hash as an integer, truncating to the bit
// length of the group order as the ECDSA standard requires.
func hashToInt(hash []byte) *big.Int {
	z := new(big.Int).SetBytes(hash)
	if excess := len(hash)*8 - N.BitLen(); excess > 0 {
		z.Rsh(z, uint(excess))
	}
	return z
}

// Verify checks a signature against a public key. Signatures with high s are
// rejected: this chain accepts only the canonical form.
func Verify(pub *PublicKey, hash []byte, sig *Signature) bool {
	if pub == nil || sig == nil || len(hash) != 32 {
		return false
	}
	if sig.R.Sign() <= 0 || sig.S.Sign() <= 0 || sig.R.Cmp(N) >= 0 || sig.S.Cmp(N) >= 0 {
		return false
	}
	if sig.S.Cmp(halfN) > 0 {
		return false
	}
	point := pub.Point()
	if !point.OnCurve() || point.IsInfinity() {
		return false
	}

	z := hashToInt(hash)
	sInv := new(big.Int).ModInverse(sig.S, N)
	if sInv == nil {
		return false
	}
	u1 := new(big.Int).Mul(z, sInv)
	u1.Mod(u1, N)
	u2 := new(big.Int).Mul(sig.R, sInv)
	u2.Mod(u2, N)

	sum := ScalarBaseMul(u1).Add(point.ScalarMul(u2))
	x, _, ok := sum.Affine()
	if !ok {
		return false
	}
	x.Mod(x, N)
	return x.Cmp(sig.R) == 0
}

// Recover reconstructs the public key that signed hash, from the signature and
// its recovery id.
func Recover(hash []byte, sig *Signature) (*PublicKey, error) {
	if sig == nil || len(hash) != 32 {
		return nil, ErrInvalidSignature
	}
	if sig.V > 3 {
		return nil, fmt.Errorf("%w: recovery id %d out of range", ErrInvalidSignature, sig.V)
	}
	if sig.R.Sign() <= 0 || sig.S.Sign() <= 0 || sig.R.Cmp(N) >= 0 || sig.S.Cmp(N) >= 0 {
		return nil, ErrInvalidSignature
	}

	// Rebuild R's x coordinate; bit 1 of V says it wrapped around the group order.
	x := new(big.Int).Set(sig.R)
	if sig.V&2 != 0 {
		x.Add(x, N)
		if x.Cmp(P) >= 0 {
			return nil, fmt.Errorf("%w: recovered x exceeds the field prime", ErrRecoveryFailed)
		}
	}
	y, err := decompressY(x, sig.V&1 == 1)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrRecoveryFailed, err)
	}
	rPoint := NewPoint(x, y)

	// Q = r^-1 * (s*R - z*G)
	rInv := new(big.Int).ModInverse(sig.R, N)
	if rInv == nil {
		return nil, ErrRecoveryFailed
	}
	z := hashToInt(hash)
	u1 := new(big.Int).Mul(rInv, sig.S)
	u1.Mod(u1, N)
	u2 := new(big.Int).Neg(z)
	u2.Mul(u2, rInv)
	u2.Mod(u2, N)

	q := rPoint.ScalarMul(u1).Add(ScalarBaseMul(u2))
	qx, qy, ok := q.Affine()
	if !ok {
		return nil, ErrRecoveryFailed
	}
	return &PublicKey{X: qx, Y: qy}, nil
}

// SignatureToBytes serializes a signature as the 65-byte r || s || v form.
func (s *Signature) Bytes() []byte {
	out := make([]byte, SignatureLength)
	s.R.FillBytes(out[:32])
	s.S.FillBytes(out[32:64])
	out[64] = s.V
	return out
}

// ParseSignature reads the 65-byte r || s || v form.
func ParseSignature(b []byte) (*Signature, error) {
	if len(b) != SignatureLength {
		return nil, fmt.Errorf("%w: expected %d bytes, got %d", ErrInvalidSignature, SignatureLength, len(b))
	}
	if b[64] > 3 {
		return nil, fmt.Errorf("%w: recovery id %d out of range", ErrInvalidSignature, b[64])
	}
	return &Signature{
		R: new(big.Int).SetBytes(b[:32]),
		S: new(big.Int).SetBytes(b[32:64]),
		V: b[64],
	}, nil
}

// ConstantTimeEqualBytes compares two byte slices without leaking their content
// through timing. Used where secrets are compared.
func ConstantTimeEqualBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	return subtle.ConstantTimeCompare(a, b) == 1
}

// Zeroize best-effort wipes a secret scalar from memory.
func (k *PrivateKey) Zeroize() {
	if k != nil && k.D != nil {
		k.D.SetInt64(0)
	}
}

var _ = zero

// IsLowS reports whether s is in the canonical lower half of the group order.
// Only low-s signatures are accepted on this chain: the mirrored high-s form is
// equally valid mathematically, so allowing it would let anyone alter a signed
// transaction's hash without the key.
func IsLowS(s *big.Int) bool {
	return s != nil && s.Sign() > 0 && s.Cmp(halfN) <= 0
}
