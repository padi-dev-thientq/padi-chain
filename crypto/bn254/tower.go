package bn254

import "math/big"

// --- Fp6 = Fp2[v]/(v^3 - xi) ---

// Fp6 is an element c0 + c1*v + c2*v^2 with coefficients in Fp2.
type Fp6 struct{ C0, C1, C2 *Fp2 }

func newFp6(c0, c1, c2 *Fp2) *Fp6 { return &Fp6{C0: c0, C1: c1, C2: c2} }

func fp6Zero() *Fp6 { return newFp6(fp2Zero(), fp2Zero(), fp2Zero()) }

func fp6One() *Fp6 { return newFp6(fp2One(), fp2Zero(), fp2Zero()) }

func (a *Fp6) IsZero() bool { return a.C0.IsZero() && a.C1.IsZero() && a.C2.IsZero() }

func (a *Fp6) Equal(b *Fp6) bool {
	return a.C0.Equal(b.C0) && a.C1.Equal(b.C1) && a.C2.Equal(b.C2)
}

func fp6Add(a, b *Fp6) *Fp6 {
	return newFp6(fp2Add(a.C0, b.C0), fp2Add(a.C1, b.C1), fp2Add(a.C2, b.C2))
}

func fp6Sub(a, b *Fp6) *Fp6 {
	return newFp6(fp2Sub(a.C0, b.C0), fp2Sub(a.C1, b.C1), fp2Sub(a.C2, b.C2))
}

func fp6Neg(a *Fp6) *Fp6 { return newFp6(fp2Neg(a.C0), fp2Neg(a.C1), fp2Neg(a.C2)) }

// fp6Mul multiplies with Toom-Cook style recombination, reducing v^3 to xi.
func fp6Mul(a, b *Fp6) *Fp6 {
	v0 := fp2Mul(a.C0, b.C0)
	v1 := fp2Mul(a.C1, b.C1)
	v2 := fp2Mul(a.C2, b.C2)

	// c0 = v0 + xi*((a1+a2)(b1+b2) - v1 - v2)
	t := fp2Sub(fp2Sub(fp2Mul(fp2Add(a.C1, a.C2), fp2Add(b.C1, b.C2)), v1), v2)
	c0 := fp2Add(v0, fp2MulXi(t))

	// c1 = (a0+a1)(b0+b1) - v0 - v1 + xi*v2
	t = fp2Sub(fp2Sub(fp2Mul(fp2Add(a.C0, a.C1), fp2Add(b.C0, b.C1)), v0), v1)
	c1 := fp2Add(t, fp2MulXi(v2))

	// c2 = (a0+a2)(b0+b2) - v0 - v2 + v1
	t = fp2Sub(fp2Sub(fp2Mul(fp2Add(a.C0, a.C2), fp2Add(b.C0, b.C2)), v0), v2)
	c2 := fp2Add(t, v1)

	return newFp6(c0, c1, c2)
}

func fp6Square(a *Fp6) *Fp6 { return fp6Mul(a, a) }

// fp6MulByV multiplies by v, which cycles the coefficients and folds the top
// one down by xi.
func fp6MulByV(a *Fp6) *Fp6 {
	return newFp6(fp2MulXi(a.C2), a.C0.Clone(), a.C1.Clone())
}

func fp6Inv(a *Fp6) *Fp6 {
	// Standard inversion via the norm to Fp2.
	t0 := fp2Sub(fp2Square(a.C0), fp2MulXi(fp2Mul(a.C1, a.C2)))
	t1 := fp2Sub(fp2MulXi(fp2Square(a.C2)), fp2Mul(a.C0, a.C1))
	t2 := fp2Sub(fp2Square(a.C1), fp2Mul(a.C0, a.C2))

	norm := fp2Add(
		fp2Mul(a.C0, t0),
		fp2MulXi(fp2Add(fp2Mul(a.C2, t1), fp2Mul(a.C1, t2))),
	)
	normInv := fp2Inv(norm)
	if normInv == nil {
		return nil
	}
	return newFp6(fp2Mul(t0, normInv), fp2Mul(t1, normInv), fp2Mul(t2, normInv))
}

// --- Fp12 = Fp6[w]/(w^2 - v) ---

// Fp12 is an element c0 + c1*w with coefficients in Fp6.
type Fp12 struct{ C0, C1 *Fp6 }

func newFp12(c0, c1 *Fp6) *Fp12 { return &Fp12{C0: c0, C1: c1} }

func fp12One() *Fp12 { return newFp12(fp6One(), fp6Zero()) }

func (a *Fp12) IsOne() bool { return a.C0.Equal(fp6One()) && a.C1.IsZero() }

func (a *Fp12) Equal(b *Fp12) bool { return a.C0.Equal(b.C0) && a.C1.Equal(b.C1) }

func fp12Mul(a, b *Fp12) *Fp12 {
	// (a0 + a1 w)(b0 + b1 w) = (a0b0 + a1b1 v) + ((a0+a1)(b0+b1) - a0b0 - a1b1) w
	v0 := fp6Mul(a.C0, b.C0)
	v1 := fp6Mul(a.C1, b.C1)
	c0 := fp6Add(v0, fp6MulByV(v1))
	c1 := fp6Sub(fp6Sub(fp6Mul(fp6Add(a.C0, a.C1), fp6Add(b.C0, b.C1)), v0), v1)
	return newFp12(c0, c1)
}

func fp12Square(a *Fp12) *Fp12 { return fp12Mul(a, a) }

// fp12Conjugate negates the w component, which is the Frobenius to the power
// p^6 and the cheap half of the final exponentiation.
func fp12Conjugate(a *Fp12) *Fp12 { return newFp12(a.C0, fp6Neg(a.C1)) }

func fp12Inv(a *Fp12) *Fp12 {
	// 1/(c0 + c1 w) = (c0 - c1 w)/(c0^2 - c1^2 v)
	t := fp6Sub(fp6Square(a.C0), fp6MulByV(fp6Square(a.C1)))
	tInv := fp6Inv(t)
	if tInv == nil {
		return nil
	}
	return newFp12(fp6Mul(a.C0, tInv), fp6Neg(fp6Mul(a.C1, tInv)))
}

func fp12Exp(a *Fp12, e *big.Int) *Fp12 {
	result := fp12One()
	base := a
	for i := 0; i < e.BitLen(); i++ {
		if e.Bit(i) == 1 {
			result = fp12Mul(result, base)
		}
		base = fp12Square(base)
	}
	return result
}
