package bls12381

import "math/big"

// The extension tower:
//
//	Fp2  = Fp[u]  / (u^2 + 1)
//	Fp6  = Fp2[v] / (v^3 - (u+1))
//	Fp12 = Fp6[w] / (w^2 - v)

// Fp6 is an element c0 + c1*v + c2*v^2.
type Fp6 struct{ C0, C1, C2 *Fp2 }

func newFp6(c0, c1, c2 *Fp2) *Fp6 { return &Fp6{C0: c0, C1: c1, C2: c2} }
func fp6Zero() *Fp6               { return newFp6(fp2Zero(), fp2Zero(), fp2Zero()) }
func fp6One() *Fp6                { return newFp6(fp2One(), fp2Zero(), fp2Zero()) }

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

func fp6Mul(a, b *Fp6) *Fp6 {
	v0 := fp2Mul(a.C0, b.C0)
	v1 := fp2Mul(a.C1, b.C1)
	v2 := fp2Mul(a.C2, b.C2)

	t := fp2Sub(fp2Sub(fp2Mul(fp2Add(a.C1, a.C2), fp2Add(b.C1, b.C2)), v1), v2)
	c0 := fp2Add(v0, fp2MulXi(t))

	t = fp2Sub(fp2Sub(fp2Mul(fp2Add(a.C0, a.C1), fp2Add(b.C0, b.C1)), v0), v1)
	c1 := fp2Add(t, fp2MulXi(v2))

	t = fp2Sub(fp2Sub(fp2Mul(fp2Add(a.C0, a.C2), fp2Add(b.C0, b.C2)), v0), v2)
	c2 := fp2Add(t, v1)

	return newFp6(c0, c1, c2)
}

func fp6Square(a *Fp6) *Fp6 { return fp6Mul(a, a) }

// fp6MulByV cycles the coefficients, folding the top one down by xi.
func fp6MulByV(a *Fp6) *Fp6 {
	return newFp6(fp2MulXi(a.C2), a.C0.Clone(), a.C1.Clone())
}

func fp6Inv(a *Fp6) *Fp6 {
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

// Fp12 is an element c0 + c1*w.
type Fp12 struct{ C0, C1 *Fp6 }

func newFp12(c0, c1 *Fp6) *Fp12 { return &Fp12{C0: c0, C1: c1} }
func fp12One() *Fp12            { return newFp12(fp6One(), fp6Zero()) }

func (a *Fp12) IsOne() bool        { return a.C0.Equal(fp6One()) && a.C1.IsZero() }
func (a *Fp12) Equal(b *Fp12) bool { return a.C0.Equal(b.C0) && a.C1.Equal(b.C1) }

func fp12Mul(a, b *Fp12) *Fp12 {
	v0 := fp6Mul(a.C0, b.C0)
	v1 := fp6Mul(a.C1, b.C1)
	c0 := fp6Add(v0, fp6MulByV(v1))
	c1 := fp6Sub(fp6Sub(fp6Mul(fp6Add(a.C0, a.C1), fp6Add(b.C0, b.C1)), v0), v1)
	return newFp12(c0, c1)
}

func fp12Square(a *Fp12) *Fp12 { return fp12Mul(a, a) }

// fp12Conjugate negates the w component: the Frobenius to the power p^6, and
// the cheap half of the final exponentiation.
func fp12Conjugate(a *Fp12) *Fp12 { return newFp12(a.C0, fp6Neg(a.C1)) }

func fp12Inv(a *Fp12) *Fp12 {
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

// Frobenius maps.
//
// Raising to the p-th power is what the final exponentiation is mostly made of,
// and doing it by generic exponentiation costs hundreds of Fp12 squarings. Done
// properly it is a handful of conjugations and multiplications by constants —
// the constants below, computed once from xi rather than transcribed.
var (
	// frobW is xi^((p-1)/6): the factor w picks up under Frobenius.
	frobW = fp2Exp(xi, new(big.Int).Div(new(big.Int).Sub(P, bigOne), big.NewInt(6)))
	// frobV is xi^((p-1)/3), the factor on v.
	frobV = fp2Exp(xi, new(big.Int).Div(new(big.Int).Sub(P, bigOne), big.NewInt(3)))
	// frobV2 is xi^(2(p-1)/3), the factor on v^2.
	frobV2 = fp2Exp(xi, new(big.Int).Div(new(big.Int).Mul(new(big.Int).Sub(P, bigOne), bigTwo), big.NewInt(3)))
)

// fp6MulByFp2 scales an Fp6 element by an Fp2 constant.
func fp6MulByFp2(a *Fp6, c *Fp2) *Fp6 {
	return newFp6(fp2Mul(a.C0, c), fp2Mul(a.C1, c), fp2Mul(a.C2, c))
}

// fp6Frobenius raises to the p-th power. On Fp2 that is conjugation; the v
// coefficients additionally pick up the constants above.
func fp6Frobenius(a *Fp6) *Fp6 {
	return newFp6(
		fp2Conjugate(a.C0),
		fp2Mul(fp2Conjugate(a.C1), frobV),
		fp2Mul(fp2Conjugate(a.C2), frobV2),
	)
}

// fp12Frobenius raises to the p-th power.
func fp12Frobenius(a *Fp12) *Fp12 {
	return newFp12(
		fp6Frobenius(a.C0),
		fp6MulByFp2(fp6Frobenius(a.C1), frobW),
	)
}

// fp12FrobeniusN applies the Frobenius n times.
func fp12FrobeniusN(a *Fp12, n int) *Fp12 {
	out := a
	for i := 0; i < n; i++ {
		out = fp12Frobenius(out)
	}
	return out
}

// cyclotomicSquare squares an element of the cyclotomic subgroup.
//
// After the easy part of the final exponentiation every value lives in that
// subgroup, where squaring can be done with far fewer field multiplications
// than the general formula needs. Since the hard part is almost entirely
// squarings, this is where the time goes.
//
// The formulas are the Granger-Scott ones for the degree-12 cyclotomic
// subgroup, written over the Fp6/Fp2 tower.
func cyclotomicSquare(a *Fp12) *Fp12 {
	// Decompose into the three Fp4 sub-blocks the formulas act on.
	z0, z4, z3 := a.C0.C0, a.C0.C1, a.C0.C2
	z2, z1, z5 := a.C1.C0, a.C1.C1, a.C1.C2

	t0, t1 := fp4Square(z0, z1)
	t2, t3 := fp4Square(z2, z3)
	t4, t5 := fp4Square(z4, z5)

	// z0 = 3*t0 - 2*z0
	c00 := fp2Sub(t0, z0)
	c00 = fp2Add(c00, c00)
	c00 = fp2Add(c00, t0)

	// z1 = 3*t1 + 2*z1
	c11 := fp2Add(t1, z1)
	c11 = fp2Add(c11, c11)
	c11 = fp2Add(c11, t1)

	// z2 = 3*(xi*t5) + 2*z2
	t := fp2MulXi(t5)
	c10 := fp2Add(t, z2)
	c10 = fp2Add(c10, c10)
	c10 = fp2Add(c10, t)

	// z3 = 3*t4 - 2*z3
	c02 := fp2Sub(t4, z3)
	c02 = fp2Add(c02, c02)
	c02 = fp2Add(c02, t4)

	// z4 = 3*t2 - 2*z4
	c01 := fp2Sub(t2, z4)
	c01 = fp2Add(c01, c01)
	c01 = fp2Add(c01, t2)

	// z5 = 3*t3 + 2*z5
	c12 := fp2Add(t3, z5)
	c12 = fp2Add(c12, c12)
	c12 = fp2Add(c12, t3)

	return newFp12(newFp6(c00, c01, c02), newFp6(c10, c11, c12))
}

// fp4Square squares an element of the Fp4 sub-extension, given as a pair of
// Fp2 coefficients.
func fp4Square(a, b *Fp2) (*Fp2, *Fp2) {
	t0 := fp2Square(a)
	t1 := fp2Square(b)
	c0 := fp2Add(fp2MulXi(t1), t0)
	c1 := fp2Sub(fp2Sub(fp2Square(fp2Add(a, b)), t0), t1)
	return c0, c1
}
