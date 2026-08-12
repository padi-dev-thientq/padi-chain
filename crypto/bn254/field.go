// Package bn254 implements the alt_bn128 pairing-friendly curve that Ethereum
// exposes as the precompiles at 0x06, 0x07 and 0x08.
//
// These are what make on-chain zk-SNARK verification possible: a Groth16 proof
// check is a handful of curve operations and one pairing product.
//
// The construction is a tower of extensions over the base field:
//
//	Fp2  = Fp[u]  / (u^2 + 1)
//	Fp6  = Fp2[v] / (v^3 - xi)     with xi = 9 + u
//	Fp12 = Fp6[w] / (w^2 - v)
//
// The pairing's target group lives in Fp12, and the sextic twist lets the
// second input group be represented over Fp2 instead — a twelvefold saving in
// the size of the arithmetic.
package bn254

import "math/big"

// P is the base field prime.
var P, _ = new(big.Int).SetString("21888242871839275222246405745257275088696311157297823662689037894645226208583", 10)

// Order is the prime order of the pairing groups.
var Order, _ = new(big.Int).SetString("21888242871839275222246405745257275088548364400416034343698204186575808495617", 10)

var (
	bigZero = big.NewInt(0)
	bigOne  = big.NewInt(1)
	bigTwo  = big.NewInt(2)
	// curveB is the constant in y^2 = x^3 + 3.
	curveB = big.NewInt(3)
)

// --- Fp ---

func fpAdd(a, b *big.Int) *big.Int {
	out := new(big.Int).Add(a, b)
	return out.Mod(out, P)
}

func fpSub(a, b *big.Int) *big.Int {
	out := new(big.Int).Sub(a, b)
	return out.Mod(out, P)
}

func fpMul(a, b *big.Int) *big.Int {
	out := new(big.Int).Mul(a, b)
	return out.Mod(out, P)
}

func fpNeg(a *big.Int) *big.Int {
	out := new(big.Int).Neg(a)
	return out.Mod(out, P)
}

func fpInv(a *big.Int) *big.Int {
	return new(big.Int).ModInverse(a, P)
}

func fpIsZero(a *big.Int) bool { return a.Sign() == 0 }

// --- Fp2 = Fp[u]/(u^2 + 1) ---

// Fp2 is an element c0 + c1*u.
type Fp2 struct{ C0, C1 *big.Int }

func newFp2(c0, c1 *big.Int) *Fp2 { return &Fp2{C0: c0, C1: c1} }

func fp2Zero() *Fp2 { return &Fp2{C0: new(big.Int), C1: new(big.Int)} }

func fp2One() *Fp2 { return &Fp2{C0: big.NewInt(1), C1: new(big.Int)} }

func (a *Fp2) IsZero() bool { return fpIsZero(a.C0) && fpIsZero(a.C1) }

func (a *Fp2) Equal(b *Fp2) bool { return a.C0.Cmp(b.C0) == 0 && a.C1.Cmp(b.C1) == 0 }

func (a *Fp2) Clone() *Fp2 {
	return &Fp2{C0: new(big.Int).Set(a.C0), C1: new(big.Int).Set(a.C1)}
}

func fp2Add(a, b *Fp2) *Fp2 { return newFp2(fpAdd(a.C0, b.C0), fpAdd(a.C1, b.C1)) }

func fp2Sub(a, b *Fp2) *Fp2 { return newFp2(fpSub(a.C0, b.C0), fpSub(a.C1, b.C1)) }

func fp2Neg(a *Fp2) *Fp2 { return newFp2(fpNeg(a.C0), fpNeg(a.C1)) }

// fp2Mul multiplies using u^2 = -1.
func fp2Mul(a, b *Fp2) *Fp2 {
	// Karatsuba: three base-field multiplications instead of four.
	v0 := fpMul(a.C0, b.C0)
	v1 := fpMul(a.C1, b.C1)
	sumA := fpAdd(a.C0, a.C1)
	sumB := fpAdd(b.C0, b.C1)
	middle := fpSub(fpMul(sumA, sumB), fpAdd(v0, v1))
	return newFp2(fpSub(v0, v1), middle)
}

func fp2Square(a *Fp2) *Fp2 {
	// (c0 + c1 u)^2 = (c0+c1)(c0-c1) + 2 c0 c1 u
	sum := fpAdd(a.C0, a.C1)
	diff := fpSub(a.C0, a.C1)
	cross := fpMul(a.C0, a.C1)
	return newFp2(fpMul(sum, diff), fpAdd(cross, cross))
}

func fp2MulScalar(a *Fp2, s *big.Int) *Fp2 {
	return newFp2(fpMul(a.C0, s), fpMul(a.C1, s))
}

// fp2Conjugate is the Frobenius on Fp2: raising to the p-th power negates the
// u component.
func fp2Conjugate(a *Fp2) *Fp2 { return newFp2(new(big.Int).Set(a.C0), fpNeg(a.C1)) }

// fp2Inv uses the norm: 1/(c0 + c1 u) = (c0 - c1 u)/(c0^2 + c1^2).
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

// xi is the non-residue the tower is built on: 9 + u.
var xi = newFp2(big.NewInt(9), big.NewInt(1))

// fp2MulXi multiplies by xi = 9 + u.
func fp2MulXi(a *Fp2) *Fp2 {
	// (c0 + c1 u)(9 + u) = (9c0 - c1) + (c0 + 9c1) u
	nine := big.NewInt(9)
	c0 := fpSub(fpMul(a.C0, nine), a.C1)
	c1 := fpAdd(a.C0, fpMul(a.C1, nine))
	return newFp2(c0, c1)
}
