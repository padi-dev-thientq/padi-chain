package bls12381

import (
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"

	"layer1/crypto/keccak"
)

// The BLS signature scheme.
//
//	public key  = sk * G1          (48 bytes compressed)
//	signature   = sk * H(message)  (96 bytes compressed, in G2)
//	verify      e(G1, sig) == e(pk, H(message))
//
// The property the chain is built on: signatures over the same message add.
// A thousand validators attesting to a block produce one 96-byte signature and
// one pairing check, instead of a thousand of each. That is what makes a large
// validator set affordable.

const (
	// SecretKeyLength is a serialized scalar.
	SecretKeyLength = 32
	// PublicKeyLength is a compressed G1 point.
	PublicKeyLength = 48
	// SignatureLength is a compressed G2 point.
	SignatureLength = 96
)

// Domain separators. Signing a message and proving possession of a key must be
// disjoint: without that, a proof of possession could be replayed as an
// attestation.
const (
	domainSignature  = "layer1/bls/signature/v1"
	domainPossession = "layer1/bls/proof-of-possession/v1"
)

var (
	ErrInvalidKey       = errors.New("bls12381: invalid key")
	ErrInvalidSignature = errors.New("bls12381: invalid signature")
	ErrNoKeys           = errors.New("bls12381: no public keys to verify against")
	ErrMismatchedInputs = errors.New("bls12381: number of keys does not match the number of messages")
)

// SecretKey is a scalar in [1, r-1].
type SecretKey struct{ s *big.Int }

// PublicKey is a point in G1.
type PublicKey struct{ p *G1 }

// Signature is a point in G2.
type Signature struct{ p *G2 }

// GenerateKey draws a uniformly random secret key from the OS entropy source.
func GenerateKey() (*SecretKey, error) {
	for {
		buf := make([]byte, 48) // extra bytes make the modular bias negligible
		if _, err := rand.Read(buf); err != nil {
			return nil, fmt.Errorf("bls12381: reading entropy: %w", err)
		}
		s := new(big.Int).Mod(new(big.Int).SetBytes(buf), Order)
		if s.Sign() != 0 {
			return &SecretKey{s: s}, nil
		}
	}
}

// SecretKeyFromBytes parses a 32-byte scalar.
func SecretKeyFromBytes(b []byte) (*SecretKey, error) {
	if len(b) != SecretKeyLength {
		return nil, fmt.Errorf("%w: expected %d bytes, got %d", ErrInvalidKey, SecretKeyLength, len(b))
	}
	s := new(big.Int).SetBytes(b)
	if s.Sign() == 0 || s.Cmp(Order) >= 0 {
		return nil, fmt.Errorf("%w: scalar out of range", ErrInvalidKey)
	}
	return &SecretKey{s: s}, nil
}

// DeriveSecretKey produces a key deterministically from seed material. Used to
// give a node a BLS key that follows from the key it already holds, so an
// operator manages one secret rather than two.
func DeriveSecretKey(seed []byte) *SecretKey {
	for counter := byte(0); ; counter++ {
		h := keccak.Sum256([]byte("layer1/bls/derive/v1"), seed, []byte{counter})
		s := new(big.Int).Mod(new(big.Int).SetBytes(h[:]), Order)
		if s.Sign() != 0 {
			return &SecretKey{s: s}
		}
	}
}

// Bytes serializes the secret key.
func (k *SecretKey) Bytes() []byte {
	out := make([]byte, SecretKeyLength)
	k.s.FillBytes(out)
	return out
}

// PublicKey derives the corresponding public key.
func (k *SecretKey) PublicKey() *PublicKey {
	return &PublicKey{p: G1Generator().ScalarMul(k.s)}
}

// Zeroize best-effort wipes the secret.
func (k *SecretKey) Zeroize() {
	if k != nil && k.s != nil {
		k.s.SetInt64(0)
	}
}

// Sign produces a signature over a message.
func (k *SecretKey) Sign(message []byte) *Signature {
	point := HashToG2(append([]byte(domainSignature), message...))
	return &Signature{p: point.ScalarMul(k.s)}
}

// ProvePossession signs the public key itself, under a separate domain.
//
// Without this a validator could register a public key computed as the
// difference between a key it controls and the keys of others, and then produce
// aggregate signatures nobody else agreed to — the rogue key attack. Requiring
// a proof of possession at registration means every key in an aggregate is one
// whose owner could sign for it alone.
func (k *SecretKey) ProvePossession() *Signature {
	point := HashToG2(append([]byte(domainPossession), k.PublicKey().Bytes()...))
	return &Signature{p: point.ScalarMul(k.s)}
}

// Point exposes the underlying group element.
func (p *PublicKey) Point() *G1 { return p.p.Clone() }

// Equal compares two public keys.
func (p *PublicKey) Equal(q *PublicKey) bool {
	if p == nil || q == nil {
		return p == q
	}
	return p.p.Equal(q.p)
}

// IsZero reports whether the key is the identity, which no honest key is.
func (p *PublicKey) IsZero() bool { return p.p.Infinity }

// Point exposes the underlying group element.
func (s *Signature) Point() *G2 { return s.p.Clone() }

// Equal compares two signatures.
func (s *Signature) Equal(t *Signature) bool {
	if s == nil || t == nil {
		return s == t
	}
	return s.p.Equal(t.p)
}

// Verify checks a signature against a public key and message.
func Verify(pub *PublicKey, message []byte, sig *Signature) bool {
	if pub == nil || sig == nil || pub.p.Infinity {
		return false
	}
	// Both inputs must be in the prime-order subgroup. A point outside it
	// breaks the relation the pairing check relies on.
	if !pub.p.InSubgroup() || !sig.p.InSubgroup() {
		return false
	}

	point := HashToG2(append([]byte(domainSignature), message...))
	// e(G1, sig) == e(pk, H(m))  <=>  e(-G1, sig) * e(pk, H(m)) == 1
	return PairingCheck([]Pair{
		{G1: G1Generator().Neg(), G2: sig.p},
		{G1: pub.p, G2: point},
	})
}

// VerifyPossession checks a proof of possession.
func VerifyPossession(pub *PublicKey, proof *Signature) bool {
	if pub == nil || proof == nil || pub.p.Infinity {
		return false
	}
	if !pub.p.InSubgroup() || !proof.p.InSubgroup() {
		return false
	}
	point := HashToG2(append([]byte(domainPossession), pub.Bytes()...))
	return PairingCheck([]Pair{
		{G1: G1Generator().Neg(), G2: proof.p},
		{G1: pub.p, G2: point},
	})
}

// AggregateSignatures adds signatures together. The result verifies against the
// aggregate of the corresponding public keys.
func AggregateSignatures(sigs []*Signature) (*Signature, error) {
	if len(sigs) == 0 {
		return nil, ErrInvalidSignature
	}
	sum := G2Zero()
	for _, sig := range sigs {
		if sig == nil {
			return nil, ErrInvalidSignature
		}
		sum = sum.Add(sig.p)
	}
	return &Signature{p: sum}, nil
}

// AggregatePublicKeys adds public keys together.
func AggregatePublicKeys(keys []*PublicKey) (*PublicKey, error) {
	if len(keys) == 0 {
		return nil, ErrNoKeys
	}
	sum := G1Zero()
	for _, key := range keys {
		if key == nil {
			return nil, ErrInvalidKey
		}
		sum = sum.Add(key.p)
	}
	return &PublicKey{p: sum}, nil
}

// FastAggregateVerify checks one aggregate signature over a single message
// signed by many keys — the shape a quorum certificate takes.
//
// The cost is two pairings regardless of how many validators signed, which is
// the entire reason for using BLS here. It is sound only if every key has a
// verified proof of possession; otherwise a rogue key can forge the aggregate.
func FastAggregateVerify(keys []*PublicKey, message []byte, sig *Signature) bool {
	aggregate, err := AggregatePublicKeys(keys)
	if err != nil {
		return false
	}
	return Verify(aggregate, message, sig)
}

// AggregateVerify checks an aggregate signature over distinct messages.
//
// Each message needs its own pairing, so this costs one more than the number of
// signers — worth it only when the messages genuinely differ. Distinct messages
// are required: with repeats, a signature for one signer could be replayed as
// another's.
func AggregateVerify(keys []*PublicKey, messages [][]byte, sig *Signature) bool {
	if len(keys) != len(messages) || len(keys) == 0 || sig == nil {
		return false
	}
	if !sig.p.InSubgroup() {
		return false
	}

	seen := make(map[string]struct{}, len(messages))
	pairs := make([]Pair, 0, len(keys)+1)
	pairs = append(pairs, Pair{G1: G1Generator().Neg(), G2: sig.p})

	for i, key := range keys {
		if key == nil || key.p.Infinity || !key.p.InSubgroup() {
			return false
		}
		if _, repeated := seen[string(messages[i])]; repeated {
			return false
		}
		seen[string(messages[i])] = struct{}{}
		pairs = append(pairs, Pair{
			G1: key.p,
			G2: HashToG2(append([]byte(domainSignature), messages[i]...)),
		})
	}
	return PairingCheck(pairs)
}

// --- serialization ---

// Compressed point encoding. The top bits of the first byte carry flags, as in
// the usual BLS convention: bit 7 marks compression, bit 6 the point at
// infinity, bit 5 the sign of y.
const (
	flagCompressed = 0x80
	flagInfinity   = 0x40
	flagSign       = 0x20
)

// Bytes serializes the public key as a compressed G1 point.
func (p *PublicKey) Bytes() []byte {
	out := make([]byte, PublicKeyLength)
	if p.p.Infinity {
		out[0] = flagCompressed | flagInfinity
		return out
	}
	p.p.X.Big().FillBytes(out)
	out[0] |= flagCompressed
	// The larger of the two roots is marked, so the decoder can pick the right
	// one from x alone.
	if isLexicographicallyLarger(p.p.Y) {
		out[0] |= flagSign
	}
	return out
}

// PublicKeyFromBytes parses a compressed G1 point and validates it.
func PublicKeyFromBytes(b []byte) (*PublicKey, error) {
	if len(b) != PublicKeyLength {
		return nil, fmt.Errorf("%w: expected %d bytes, got %d", ErrBadEncoding, PublicKeyLength, len(b))
	}
	if b[0]&flagCompressed == 0 {
		return nil, fmt.Errorf("%w: not marked compressed", ErrBadEncoding)
	}
	if b[0]&flagInfinity != 0 {
		return &PublicKey{p: G1Zero()}, nil
	}

	raw := append([]byte(nil), b...)
	sign := raw[0]&flagSign != 0
	raw[0] &= 0x1f

	x := new(big.Int).SetBytes(raw)
	if x.Cmp(P) >= 0 {
		return nil, fmt.Errorf("%w: x is not a field element", ErrBadEncoding)
	}
	xf := feFromBig(x)
	rhs := fpAdd(fpMul(fpMul(xf, xf), xf), curveB)
	y, ok := fpSqrtBase(rhs)
	if !ok {
		return nil, fmt.Errorf("%w: no curve point has this abscissa", ErrNotOnCurve)
	}
	if isLexicographicallyLarger(y) != sign {
		y = fpNeg(y)
	}

	point := &G1{X: xf, Y: y}
	// A key outside the prime-order subgroup would let an attacker construct
	// relations the pairing is supposed to rule out, so it is refused here
	// rather than trusted later.
	if !point.InSubgroup() {
		return nil, ErrNotInSubgroup
	}
	return &PublicKey{p: point}, nil
}

// Bytes serializes the signature as a compressed G2 point.
func (s *Signature) Bytes() []byte {
	out := make([]byte, SignatureLength)
	if s.p.Infinity {
		out[0] = flagCompressed | flagInfinity
		return out
	}
	// The imaginary coefficient comes first, matching the usual convention.
	s.p.X.C1.Big().FillBytes(out[:48])
	s.p.X.C0.Big().FillBytes(out[48:])
	out[0] |= flagCompressed
	if isFp2LexicographicallyLarger(s.p.Y) {
		out[0] |= flagSign
	}
	return out
}

// SignatureFromBytes parses a compressed G2 point and validates it.
func SignatureFromBytes(b []byte) (*Signature, error) {
	if len(b) != SignatureLength {
		return nil, fmt.Errorf("%w: expected %d bytes, got %d", ErrBadEncoding, SignatureLength, len(b))
	}
	if b[0]&flagCompressed == 0 {
		return nil, fmt.Errorf("%w: not marked compressed", ErrBadEncoding)
	}
	if b[0]&flagInfinity != 0 {
		return &Signature{p: G2Zero()}, nil
	}

	raw := append([]byte(nil), b...)
	sign := raw[0]&flagSign != 0
	raw[0] &= 0x1f

	x1 := new(big.Int).SetBytes(raw[:48])
	x0 := new(big.Int).SetBytes(raw[48:])
	if x0.Cmp(P) >= 0 || x1.Cmp(P) >= 0 {
		return nil, fmt.Errorf("%w: coordinate is not a field element", ErrBadEncoding)
	}

	x := newFp2(feFromBig(x0), feFromBig(x1))
	rhs := fp2Add(fp2Mul(fp2Square(x), x), twistB)
	y := fp2Sqrt(rhs)
	if y == nil {
		return nil, fmt.Errorf("%w: no twist point has this abscissa", ErrNotOnCurve)
	}
	if isFp2LexicographicallyLarger(y) != sign {
		y = fp2Neg(y)
	}

	point := &G2{X: x, Y: y}
	if !point.InSubgroup() {
		return nil, ErrNotInSubgroup
	}
	return &Signature{p: point}, nil
}

// isLexicographicallyLarger reports whether y is the larger of the pair
// {y, -y}. Recording which one a compressed point carries is what lets the
// decoder pick the right root from x alone.
var halfModulus = new(big.Int).Rsh(P, 1)

func isLexicographicallyLarger(y fe) bool {
	return y.Big().Cmp(halfModulus) > 0
}

func isFp2LexicographicallyLarger(y *Fp2) bool {
	if !fpIsZero(y.C1) {
		return isLexicographicallyLarger(y.C1)
	}
	return isLexicographicallyLarger(y.C0)
}
