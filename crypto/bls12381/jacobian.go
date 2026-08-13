package bls12381

import "math/big"

// Scalar multiplication in Jacobian coordinates.
//
// Affine point arithmetic needs a field inversion for every doubling and
// addition, and an inversion costs about as much as a hundred multiplications.
// Jacobian coordinates defer all of them: the loop runs inversion-free and one
// inversion at the end converts back. For clearing the G2 cofactor — several
// hundred point operations — that is the difference between milliseconds and
// tens of milliseconds, and it is on the path of every signature.

// jacobianG1 represents the affine point (X/Z^2, Y/Z^3). Z == 0 is infinity.
type jacobianG1 struct{ X, Y, Z fe }

func (p *G1) toJacobian() *jacobianG1 {
	if p.Infinity {
		return &jacobianG1{X: feOne, Y: feOne}
	}
	return &jacobianG1{X: p.X, Y: p.Y, Z: feOne}
}

func (j *jacobianG1) toAffine() *G1 {
	if fpIsZero(j.Z) {
		return G1Zero()
	}
	zInv := fpInv(j.Z)
	zInv2 := fpMul(zInv, zInv)
	zInv3 := fpMul(zInv2, zInv)
	return &G1{X: fpMul(j.X, zInv2), Y: fpMul(j.Y, zInv3)}
}

func (j *jacobianG1) double() *jacobianG1 {
	if fpIsZero(j.Z) || fpIsZero(j.Y) {
		return &jacobianG1{X: feOne, Y: feOne}
	}
	a := fpMul(j.X, j.X)
	b := fpMul(j.Y, j.Y)
	c := fpMul(b, b)

	d := fpAdd(j.X, b)
	d = fpMul(d, d)
	d = fpSub(d, a)
	d = fpSub(d, c)
	d = fpAdd(d, d)

	e := fpAdd(fpAdd(a, a), a)
	f := fpMul(e, e)

	x := fpSub(f, fpAdd(d, d))
	eightC := fpAdd(fpAdd(fpAdd(c, c), fpAdd(c, c)), fpAdd(fpAdd(c, c), fpAdd(c, c)))
	y := fpSub(fpMul(e, fpSub(d, x)), eightC)
	z := fpMul(fpAdd(j.Y, j.Y), j.Z)
	return &jacobianG1{X: x, Y: y, Z: z}
}

// addAffine adds an affine point, which saves the operations that would handle
// the second point's Z coordinate.
func (j *jacobianG1) addAffine(q *G1) *jacobianG1 {
	if q.Infinity {
		return j
	}
	if fpIsZero(j.Z) {
		return q.toJacobian()
	}
	z1z1 := fpMul(j.Z, j.Z)
	u2 := fpMul(q.X, z1z1)
	s2 := fpMul(fpMul(q.Y, j.Z), z1z1)

	if j.X == u2 {
		if j.Y == s2 {
			return j.double()
		}
		return &jacobianG1{X: feOne, Y: feOne}
	}

	h := fpSub(u2, j.X)
	hh := fpMul(h, h)
	i := fpAdd(hh, hh)
	i = fpAdd(i, i)
	jj := fpMul(h, i)
	r := fpSub(s2, j.Y)
	r = fpAdd(r, r)
	v := fpMul(j.X, i)

	x := fpSub(fpSub(fpMul(r, r), jj), fpAdd(v, v))
	y := fpMul(j.Y, jj)
	y = fpSub(fpMul(r, fpSub(v, x)), fpAdd(y, y))
	z := fpMul(fpAdd(j.Z, j.Z), h)
	return &jacobianG1{X: x, Y: y, Z: z}
}

// scalarMulJacobian returns k*p with a single inversion at the end.
func scalarMulJacobian(p *G1, k *big.Int) *G1 {
	if k.Sign() < 0 {
		return scalarMulJacobian(p.Neg(), new(big.Int).Neg(k))
	}
	if k.Sign() == 0 || p.Infinity {
		return G1Zero()
	}
	acc := &jacobianG1{X: feOne, Y: feOne}
	for i := k.BitLen() - 1; i >= 0; i-- {
		acc = acc.double()
		if k.Bit(i) == 1 {
			acc = acc.addAffine(p)
		}
	}
	return acc.toAffine()
}

// jacobianG2 is the same construction over Fp2.
type jacobianG2 struct{ X, Y, Z *Fp2 }

func (p *G2) toJacobian() *jacobianG2 {
	if p.Infinity {
		return &jacobianG2{X: fp2One(), Y: fp2One(), Z: fp2Zero()}
	}
	return &jacobianG2{X: p.X.Clone(), Y: p.Y.Clone(), Z: fp2One()}
}

func (j *jacobianG2) toAffine() *G2 {
	if j.Z.IsZero() {
		return G2Zero()
	}
	zInv := fp2Inv(j.Z)
	zInv2 := fp2Square(zInv)
	zInv3 := fp2Mul(zInv2, zInv)
	return &G2{X: fp2Mul(j.X, zInv2), Y: fp2Mul(j.Y, zInv3)}
}

func (j *jacobianG2) double() *jacobianG2 {
	if j.Z.IsZero() || j.Y.IsZero() {
		return &jacobianG2{X: fp2One(), Y: fp2One(), Z: fp2Zero()}
	}
	a := fp2Square(j.X)
	b := fp2Square(j.Y)
	c := fp2Square(b)

	d := fp2Add(j.X, b)
	d = fp2Square(d)
	d = fp2Sub(d, a)
	d = fp2Sub(d, c)
	d = fp2Add(d, d)

	e := fp2Add(fp2Add(a, a), a)
	f := fp2Square(e)

	x := fp2Sub(f, fp2Add(d, d))
	c2 := fp2Add(c, c)
	c4 := fp2Add(c2, c2)
	c8 := fp2Add(c4, c4)
	y := fp2Sub(fp2Mul(e, fp2Sub(d, x)), c8)
	z := fp2Mul(fp2Add(j.Y, j.Y), j.Z)
	return &jacobianG2{X: x, Y: y, Z: z}
}

func (j *jacobianG2) addAffine(q *G2) *jacobianG2 {
	if q.Infinity {
		return j
	}
	if j.Z.IsZero() {
		return q.toJacobian()
	}
	z1z1 := fp2Square(j.Z)
	u2 := fp2Mul(q.X, z1z1)
	s2 := fp2Mul(fp2Mul(q.Y, j.Z), z1z1)

	if j.X.Equal(u2) {
		if j.Y.Equal(s2) {
			return j.double()
		}
		return &jacobianG2{X: fp2One(), Y: fp2One(), Z: fp2Zero()}
	}

	h := fp2Sub(u2, j.X)
	hh := fp2Square(h)
	i := fp2Add(hh, hh)
	i = fp2Add(i, i)
	jj := fp2Mul(h, i)
	r := fp2Sub(s2, j.Y)
	r = fp2Add(r, r)
	v := fp2Mul(j.X, i)

	x := fp2Sub(fp2Sub(fp2Square(r), jj), fp2Add(v, v))
	y := fp2Mul(j.Y, jj)
	y = fp2Sub(fp2Mul(r, fp2Sub(v, x)), fp2Add(y, y))
	z := fp2Mul(fp2Add(j.Z, j.Z), h)
	return &jacobianG2{X: x, Y: y, Z: z}
}

func scalarMulJacobianG2(p *G2, k *big.Int) *G2 {
	if k.Sign() < 0 {
		return scalarMulJacobianG2(p.Neg(), new(big.Int).Neg(k))
	}
	if k.Sign() == 0 || p.Infinity {
		return G2Zero()
	}
	acc := &jacobianG2{X: fp2One(), Y: fp2One(), Z: fp2Zero()}
	for i := k.BitLen() - 1; i >= 0; i-- {
		acc = acc.double()
		if k.Bit(i) == 1 {
			acc = acc.addAffine(p)
		}
	}
	return acc.toAffine()
}
