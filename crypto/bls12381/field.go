// Package bls12381 implements the BLS12-381 pairing-friendly curve and the BLS
// signature scheme over it.
//
// What this buys the chain is aggregation: any number of signatures over the
// same message collapse into one, and verifying the aggregate costs two
// pairings regardless of how many validators signed. Without it a quorum
// certificate grows linearly with the validator set, and verification with it —
// which is what caps a secp256k1-based chain at a few hundred validators.
//
// Every curve constant here is derived from the single BLS parameter x rather
// than transcribed. A mistyped digit in a 381-bit prime fails silently in ways
// that are hard to trace; a derivation either reproduces the curve or fails
// every test at once.
package bls12381

import "math/big"

// X is the BLS parameter that generates the curve. It is negative, which the
// pairing has to account for at the end of the Miller loop.
var X = new(big.Int).Neg(mustHex("d201000000010000"))

// The field prime and group order follow from X:
//
//	r = x^4 - x^2 + 1
//	p = (x-1)^2 * r / 3 + x
var (
	// Order is the prime order of both pairing groups.
	Order = computeOrder()
	// P is the base field prime.
	P = computePrime()
)

func mustHex(s string) *big.Int {
	v, ok := new(big.Int).SetString(s, 16)
	if !ok {
		panic("bls12381: bad constant " + s)
	}
	return v
}

func computeOrder() *big.Int {
	x2 := new(big.Int).Mul(X, X)
	x4 := new(big.Int).Mul(x2, x2)
	r := new(big.Int).Sub(x4, x2)
	return r.Add(r, big.NewInt(1))
}

func computePrime() *big.Int {
	r := computeOrder()
	t := new(big.Int).Sub(X, big.NewInt(1))
	t.Mul(t, t)
	t.Mul(t, r)
	t.Div(t, big.NewInt(3))
	return t.Add(t, X)
}

// Cofactors clear a curve point into the prime-order subgroup. Both follow from
// X as well.
var (
	// G1Cofactor = (x-1)^2 / 3
	G1Cofactor = func() *big.Int {
		h := new(big.Int).Sub(X, big.NewInt(1))
		h.Mul(h, h)
		return h.Div(h, big.NewInt(3))
	}()

	// G2Cofactor = (x^8 - 4x^7 + 5x^6 - 4x^4 + 6x^3 - 4x^2 - 4x + 13) / 9
	G2Cofactor = func() *big.Int {
		pow := func(n int64) *big.Int { return new(big.Int).Exp(X, big.NewInt(n), nil) }
		term := func(c int64, n int64) *big.Int { return new(big.Int).Mul(big.NewInt(c), pow(n)) }

		h := pow(8)
		h.Add(h, term(-4, 7))
		h.Add(h, term(5, 6))
		h.Add(h, term(-4, 4))
		h.Add(h, term(6, 3))
		h.Add(h, term(-4, 2))
		h.Add(h, term(-4, 1))
		h.Add(h, big.NewInt(13))
		return h.Div(h, big.NewInt(9))
	}()
)

var (
	bigZero = big.NewInt(0)
	bigOne  = big.NewInt(1)
	bigTwo  = big.NewInt(2)
	// curveB is the constant in y^2 = x^3 + 4 over the base field.
	curveB = big.NewInt(4)
)

// --- Fp ---

func fpAdd(a, b *big.Int) *big.Int { return new(big.Int).Mod(new(big.Int).Add(a, b), P) }
func fpSub(a, b *big.Int) *big.Int { return new(big.Int).Mod(new(big.Int).Sub(a, b), P) }
func fpMul(a, b *big.Int) *big.Int { return new(big.Int).Mod(new(big.Int).Mul(a, b), P) }
func fpNeg(a *big.Int) *big.Int    { return new(big.Int).Mod(new(big.Int).Neg(a), P) }
func fpInv(a *big.Int) *big.Int    { return new(big.Int).ModInverse(a, P) }

func fpIsZero(a *big.Int) bool { return a.Sign() == 0 }

// --- Fp2 = Fp[u]/(u^2 + 1) ---

// Fp2 is an element c0 + c1*u.
type Fp2 struct{ C0, C1 *big.Int }

func newFp2(c0, c1 *big.Int) *Fp2 { return &Fp2{C0: c0, C1: c1} }
func fp2Zero() *Fp2               { return &Fp2{C0: new(big.Int), C1: new(big.Int)} }
func fp2One() *Fp2                { return &Fp2{C0: big.NewInt(1), C1: new(big.Int)} }

func (a *Fp2) IsZero() bool      { return fpIsZero(a.C0) && fpIsZero(a.C1) }
func (a *Fp2) Equal(b *Fp2) bool { return a.C0.Cmp(b.C0) == 0 && a.C1.Cmp(b.C1) == 0 }

func (a *Fp2) Clone() *Fp2 {
	return &Fp2{C0: new(big.Int).Set(a.C0), C1: new(big.Int).Set(a.C1)}
}

func fp2Add(a, b *Fp2) *Fp2 { return newFp2(fpAdd(a.C0, b.C0), fpAdd(a.C1, b.C1)) }
func fp2Sub(a, b *Fp2) *Fp2 { return newFp2(fpSub(a.C0, b.C0), fpSub(a.C1, b.C1)) }
func fp2Neg(a *Fp2) *Fp2    { return newFp2(fpNeg(a.C0), fpNeg(a.C1)) }

func fp2Mul(a, b *Fp2) *Fp2 {
	v0 := fpMul(a.C0, b.C0)
	v1 := fpMul(a.C1, b.C1)
	middle := fpSub(fpMul(fpAdd(a.C0, a.C1), fpAdd(b.C0, b.C1)), fpAdd(v0, v1))
	return newFp2(fpSub(v0, v1), middle)
}

func fp2Square(a *Fp2) *Fp2 {
	sum := fpAdd(a.C0, a.C1)
	diff := fpSub(a.C0, a.C1)
	cross := fpMul(a.C0, a.C1)
	return newFp2(fpMul(sum, diff), fpAdd(cross, cross))
}

// fp2Conjugate is the Frobenius on Fp2.
func fp2Conjugate(a *Fp2) *Fp2 { return newFp2(new(big.Int).Set(a.C0), fpNeg(a.C1)) }

func fp2Inv(a *Fp2) *Fp2 {
	norm := fpAdd(fpMul(a.C0, a.C0), fpMul(a.C1, a.C1))
	inv := fpInv(norm)
	if inv == nil {
		return nil
	}
	return newFp2(fpMul(a.C0, inv), fpNeg(fpMul(a.C1, inv)))
}

func fp2Exp(a *Fp2, e *big.Int) *Fp2 {
	result := fp2One()
	base := a.Clone()
	for i := 0; i < e.BitLen(); i++ {
		if e.Bit(i) == 1 {
			result = fp2Mul(result, base)
		}
		base = fp2Square(base)
	}
	return result
}

// xi is the non-residue the tower is built on: u + 1.
var xi = newFp2(big.NewInt(1), big.NewInt(1))

// fp2MulXi multiplies by u + 1.
func fp2MulXi(a *Fp2) *Fp2 {
	// (c0 + c1 u)(1 + u) = (c0 - c1) + (c0 + c1) u
	return newFp2(fpSub(a.C0, a.C1), fpAdd(a.C0, a.C1))
}

// twistB is the curve constant of the sextic twist: 4(u + 1).
var twistB = newFp2(big.NewInt(4), big.NewInt(4))

// sqrtExpFp is (p+1)/4, which gives square roots in the base field because
// p ≡ 3 (mod 4).
var sqrtExpFp = new(big.Int).Rsh(new(big.Int).Add(P, bigOne), 2)

// fpSqrtBase returns a square root in Fp, or nil when none exists.
func fpSqrtBase(a *big.Int) *big.Int {
	candidate := new(big.Int).Exp(a, sqrtExpFp, P)
	if fpMul(candidate, candidate).Cmp(new(big.Int).Mod(a, P)) != 0 {
		return nil
	}
	return candidate
}

// fp2Sqrt returns a square root of a, or nil when none exists.
//
// This is the complex method, which works whenever p ≡ 3 (mod 4): it reduces
// the problem to two square roots in the base field. Exponentiating in Fp2
// directly would need an exponent twice as long over elements three times as
// expensive to multiply, and getting the adjustment by roots of unity right is
// fiddly enough to fail silently on some inputs — which shows up not as a wrong
// answer but as a hash-to-curve loop that retries far more often than it should.
func fp2Sqrt(a *Fp2) *Fp2 {
	if a.IsZero() {
		return fp2Zero()
	}

	// A purely real or purely imaginary element is a special case: with a1 = 0
	// the general formula divides by zero.
	if fpIsZero(a.C1) {
		if root := fpSqrtBase(a.C0); root != nil {
			return newFp2(root, new(big.Int))
		}
		// a0 is not a square, but -a0 might be; then sqrt(a) = sqrt(-a0)*u,
		// since u^2 = -1.
		if root := fpSqrtBase(fpNeg(a.C0)); root != nil {
			return newFp2(new(big.Int), root)
		}
		return nil
	}

	// norm = a0^2 + a1^2 must be a square in Fp for a to be a square in Fp2.
	norm := fpAdd(fpMul(a.C0, a.C0), fpMul(a.C1, a.C1))
	alpha := fpSqrtBase(norm)
	if alpha == nil {
		return nil
	}

	inv2 := fpInv(bigTwo)
	// One of (a0 ± alpha)/2 is a square; try both.
	for _, delta := range []*big.Int{
		fpMul(fpAdd(a.C0, alpha), inv2),
		fpMul(fpSub(a.C0, alpha), inv2),
	} {
		x0 := fpSqrtBase(delta)
		if x0 == nil || fpIsZero(x0) {
			continue
		}
		x1 := fpMul(a.C1, fpInv(fpMul(bigTwo, x0)))
		candidate := newFp2(x0, x1)
		if fp2Square(candidate).Equal(a) {
			return candidate
		}
	}
	return nil
}
