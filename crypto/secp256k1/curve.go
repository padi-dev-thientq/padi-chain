// Package secp256k1 implements the secp256k1 curve and ECDSA from scratch,
// on top of the standard library's arbitrary-precision integers only.
//
// Curve: y^2 = x^3 + 7 over F_p, p = 2^256 - 2^32 - 977.
package secp256k1

import (
	"errors"
	"math/big"
)

// Curve parameters.
var (
	// P is the field prime.
	P, _ = new(big.Int).SetString("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f", 16)
	// N is the order of the generator.
	N, _ = new(big.Int).SetString("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", 16)
	// Gx, Gy are the generator's affine coordinates.
	Gx, _ = new(big.Int).SetString("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798", 16)
	Gy, _ = new(big.Int).SetString("483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8", 16)

	// B is the curve's constant term (a is zero).
	B = big.NewInt(7)

	halfN = new(big.Int).Rsh(N, 1)

	// sqrtExp = (P+1)/4; since P ≡ 3 (mod 4) this exponent yields square roots.
	sqrtExp = new(big.Int).Rsh(new(big.Int).Add(P, big.NewInt(1)), 2)

	one  = big.NewInt(1)
	zero = big.NewInt(0)
)

var (
	ErrInvalidPoint = errors.New("secp256k1: point is not on the curve")
	ErrInvalidKey   = errors.New("secp256k1: private key out of range")
)

// Point is a curve point in Jacobian coordinates: the affine point is
// (X/Z^2, Y/Z^3). Z == 0 represents the point at infinity.
type Point struct {
	X, Y, Z *big.Int
}

// Infinity returns the identity element of the group.
func Infinity() *Point {
	return &Point{X: new(big.Int).Set(one), Y: new(big.Int).Set(one), Z: new(big.Int)}
}

// Generator returns a fresh copy of G.
func Generator() *Point {
	return &Point{X: new(big.Int).Set(Gx), Y: new(big.Int).Set(Gy), Z: new(big.Int).Set(one)}
}

// NewPoint builds a Jacobian point from affine coordinates.
func NewPoint(x, y *big.Int) *Point {
	return &Point{X: new(big.Int).Set(x), Y: new(big.Int).Set(y), Z: new(big.Int).Set(one)}
}

func (p *Point) IsInfinity() bool { return p.Z.Sign() == 0 }

// Affine converts back to affine coordinates. It returns ok == false for the
// point at infinity, which has no affine representation.
func (p *Point) Affine() (x, y *big.Int, ok bool) {
	if p.IsInfinity() {
		return nil, nil, false
	}
	zInv := new(big.Int).ModInverse(p.Z, P)
	if zInv == nil {
		return nil, nil, false
	}
	zInv2 := new(big.Int).Mul(zInv, zInv)
	zInv2.Mod(zInv2, P)
	zInv3 := new(big.Int).Mul(zInv2, zInv)
	zInv3.Mod(zInv3, P)

	x = new(big.Int).Mul(p.X, zInv2)
	x.Mod(x, P)
	y = new(big.Int).Mul(p.Y, zInv3)
	y.Mod(y, P)
	return x, y, true
}

// OnCurve reports whether the point satisfies y^2 == x^3 + 7.
func (p *Point) OnCurve() bool {
	x, y, ok := p.Affine()
	if !ok {
		return true // infinity is a valid group element
	}
	if x.Sign() < 0 || x.Cmp(P) >= 0 || y.Sign() < 0 || y.Cmp(P) >= 0 {
		return false
	}
	lhs := new(big.Int).Mul(y, y)
	lhs.Mod(lhs, P)
	rhs := new(big.Int).Mul(x, x)
	rhs.Mod(rhs, P)
	rhs.Mul(rhs, x)
	rhs.Add(rhs, B)
	rhs.Mod(rhs, P)
	return lhs.Cmp(rhs) == 0
}

func (p *Point) Equal(q *Point) bool {
	px, py, pok := p.Affine()
	qx, qy, qok := q.Affine()
	if !pok || !qok {
		return pok == qok
	}
	return px.Cmp(qx) == 0 && py.Cmp(qy) == 0
}

func fmod(v *big.Int) *big.Int { return v.Mod(v, P) }

// Double returns 2*p, using the "dbl-2009-l" formulas for a == 0.
func (p *Point) Double() *Point {
	if p.IsInfinity() || p.Y.Sign() == 0 {
		return Infinity()
	}
	a := fmod(new(big.Int).Mul(p.X, p.X))
	b := fmod(new(big.Int).Mul(p.Y, p.Y))
	c := fmod(new(big.Int).Mul(b, b))

	// d = 2*((X+B)^2 - A - C)
	d := new(big.Int).Add(p.X, b)
	d.Mul(d, d)
	d.Sub(d, a)
	d.Sub(d, c)
	d.Lsh(d, 1)
	fmod(d)

	e := new(big.Int).Mul(a, big.NewInt(3))
	fmod(e)
	f := fmod(new(big.Int).Mul(e, e))

	x3 := new(big.Int).Sub(f, new(big.Int).Lsh(d, 1))
	fmod(x3)

	y3 := new(big.Int).Sub(d, x3)
	y3.Mul(y3, e)
	y3.Sub(y3, new(big.Int).Lsh(c, 3))
	fmod(y3)

	z3 := new(big.Int).Mul(p.Y, p.Z)
	z3.Lsh(z3, 1)
	fmod(z3)

	return &Point{X: x3, Y: y3, Z: z3}
}

// Add returns p+q, using the "add-2007-bl" formulas.
func (p *Point) Add(q *Point) *Point {
	if p.IsInfinity() {
		return &Point{X: new(big.Int).Set(q.X), Y: new(big.Int).Set(q.Y), Z: new(big.Int).Set(q.Z)}
	}
	if q.IsInfinity() {
		return &Point{X: new(big.Int).Set(p.X), Y: new(big.Int).Set(p.Y), Z: new(big.Int).Set(p.Z)}
	}

	z1z1 := fmod(new(big.Int).Mul(p.Z, p.Z))
	z2z2 := fmod(new(big.Int).Mul(q.Z, q.Z))

	u1 := fmod(new(big.Int).Mul(p.X, z2z2))
	u2 := fmod(new(big.Int).Mul(q.X, z1z1))

	s1 := new(big.Int).Mul(p.Y, q.Z)
	s1.Mul(s1, z2z2)
	fmod(s1)
	s2 := new(big.Int).Mul(q.Y, p.Z)
	s2.Mul(s2, z1z1)
	fmod(s2)

	if u1.Cmp(u2) == 0 {
		if s1.Cmp(s2) == 0 {
			return p.Double()
		}
		// p == -q
		return Infinity()
	}

	h := new(big.Int).Sub(u2, u1)
	fmod(h)
	i := new(big.Int).Lsh(h, 1)
	i.Mul(i, i)
	fmod(i)
	j := fmod(new(big.Int).Mul(h, i))

	r := new(big.Int).Sub(s2, s1)
	r.Lsh(r, 1)
	fmod(r)

	v := fmod(new(big.Int).Mul(u1, i))

	x3 := new(big.Int).Mul(r, r)
	x3.Sub(x3, j)
	x3.Sub(x3, new(big.Int).Lsh(v, 1))
	fmod(x3)

	y3 := new(big.Int).Sub(v, x3)
	y3.Mul(y3, r)
	s1j := new(big.Int).Mul(s1, j)
	y3.Sub(y3, s1j.Lsh(s1j, 1))
	fmod(y3)

	z3 := new(big.Int).Add(p.Z, q.Z)
	z3.Mul(z3, z3)
	z3.Sub(z3, z1z1)
	z3.Sub(z3, z2z2)
	z3.Mul(z3, h)
	fmod(z3)

	return &Point{X: x3, Y: y3, Z: z3}
}

// Neg returns -p.
func (p *Point) Neg() *Point {
	y := new(big.Int).Neg(p.Y)
	fmod(y)
	return &Point{X: new(big.Int).Set(p.X), Y: y, Z: new(big.Int).Set(p.Z)}
}

// ScalarMul returns k*p via left-to-right double-and-add.
func (p *Point) ScalarMul(k *big.Int) *Point {
	k = new(big.Int).Mod(k, N)
	if k.Sign() == 0 {
		return Infinity()
	}
	result := Infinity()
	for i := k.BitLen() - 1; i >= 0; i-- {
		result = result.Double()
		if k.Bit(i) == 1 {
			result = result.Add(p)
		}
	}
	return result
}

// ScalarBaseMul returns k*G.
func ScalarBaseMul(k *big.Int) *Point { return Generator().ScalarMul(k) }

// decompressY solves for the y coordinate of the curve point with abscissa x,
// choosing the root whose parity matches yOdd.
func decompressY(x *big.Int, yOdd bool) (*big.Int, error) {
	if x.Sign() < 0 || x.Cmp(P) >= 0 {
		return nil, ErrInvalidPoint
	}
	// alpha = x^3 + 7
	alpha := new(big.Int).Mul(x, x)
	alpha.Mod(alpha, P)
	alpha.Mul(alpha, x)
	alpha.Add(alpha, B)
	alpha.Mod(alpha, P)

	y := new(big.Int).Exp(alpha, sqrtExp, P)
	check := new(big.Int).Mul(y, y)
	check.Mod(check, P)
	if check.Cmp(alpha) != 0 {
		return nil, ErrInvalidPoint // x is not the abscissa of any curve point
	}
	if (y.Bit(0) == 1) != yOdd {
		y.Sub(P, y)
	}
	return y, nil
}
