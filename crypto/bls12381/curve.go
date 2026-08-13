package bls12381

import (
	"errors"
	"math/big"

	"padi-chain/crypto/keccak"
)

var (
	ErrNotOnCurve    = errors.New("bls12381: point is not on the curve")
	ErrNotInSubgroup = errors.New("bls12381: point is not in the prime-order subgroup")
	ErrBadEncoding   = errors.New("bls12381: malformed point encoding")
)

// G1 is a point on y^2 = x^3 + 4 over Fp, in affine coordinates.
type G1 struct {
	X, Y     fe
	Infinity bool
}

// G1Zero returns the point at infinity.
func G1Zero() *G1 { return &G1{Infinity: true} }

func (p *G1) Clone() *G1 {
	if p.Infinity {
		return G1Zero()
	}
	out := *p
	return &out
}

// OnCurve reports whether the point satisfies the curve equation.
func (p *G1) OnCurve() bool {
	if p.Infinity {
		return true
	}
	lhs := fpMul(p.Y, p.Y)
	rhs := fpAdd(fpMul(fpMul(p.X, p.X), p.X), curveB)
	return lhs == rhs
}

// InSubgroup reports whether the point has the prime order r. A public key
// outside the subgroup would let an attacker forge relations the pairing is
// supposed to prevent, so it is checked on every decode.
func (p *G1) InSubgroup() bool {
	return p.Infinity || p.ScalarMul(Order).Infinity
}

func (p *G1) Equal(q *G1) bool {
	if p.Infinity || q.Infinity {
		return p.Infinity == q.Infinity
	}
	return p.X == q.X && p.Y == q.Y
}

func (p *G1) Neg() *G1 {
	if p.Infinity {
		return G1Zero()
	}
	return &G1{X: p.X, Y: fpNeg(p.Y)}
}

func (p *G1) Add(q *G1) *G1 {
	if p.Infinity {
		return q.Clone()
	}
	if q.Infinity {
		return p.Clone()
	}
	if p.X == q.X {
		if p.Y != q.Y {
			return G1Zero()
		}
		return p.double()
	}
	lambda := fpMul(fpSub(q.Y, p.Y), fpInv(fpSub(q.X, p.X)))
	x := fpSub(fpSub(fpMul(lambda, lambda), p.X), q.X)
	y := fpSub(fpMul(lambda, fpSub(p.X, x)), p.Y)
	return &G1{X: x, Y: y}
}

func (p *G1) double() *G1 {
	if p.Infinity || fpIsZero(p.Y) {
		return G1Zero()
	}
	num := fpMul(feThree, fpMul(p.X, p.X))
	lambda := fpMul(num, fpInv(fpMul(feTwo, p.Y)))
	x := fpSub(fpMul(lambda, lambda), fpMul(feTwo, p.X))
	y := fpSub(fpMul(lambda, fpSub(p.X, x)), p.Y)
	return &G1{X: x, Y: y}
}

// ScalarMul returns k*p, computed in Jacobian coordinates so the loop needs no
// field inversions.
func (p *G1) ScalarMul(k *big.Int) *G1 { return scalarMulJacobian(p, k) }

// G2 is a point on the sextic twist y^2 = x^3 + 4(u+1) over Fp2.
type G2 struct {
	X, Y     *Fp2
	Infinity bool
}

func G2Zero() *G2 { return &G2{X: fp2Zero(), Y: fp2Zero(), Infinity: true} }

func (p *G2) Clone() *G2 {
	if p.Infinity {
		return G2Zero()
	}
	return &G2{X: p.X.Clone(), Y: p.Y.Clone()}
}

func (p *G2) OnCurve() bool {
	if p.Infinity {
		return true
	}
	lhs := fp2Square(p.Y)
	rhs := fp2Add(fp2Mul(fp2Square(p.X), p.X), twistB)
	return lhs.Equal(rhs)
}

func (p *G2) InSubgroup() bool {
	return p.Infinity || p.ScalarMul(Order).Infinity
}

func (p *G2) Equal(q *G2) bool {
	if p.Infinity || q.Infinity {
		return p.Infinity == q.Infinity
	}
	return p.X.Equal(q.X) && p.Y.Equal(q.Y)
}

func (p *G2) Neg() *G2 {
	if p.Infinity {
		return G2Zero()
	}
	return &G2{X: p.X.Clone(), Y: fp2Neg(p.Y)}
}

func (p *G2) Add(q *G2) *G2 {
	if p.Infinity {
		return q.Clone()
	}
	if q.Infinity {
		return p.Clone()
	}
	if p.X.Equal(q.X) {
		if !p.Y.Equal(q.Y) {
			return G2Zero()
		}
		return p.double()
	}
	lambda := fp2Mul(fp2Sub(q.Y, p.Y), fp2Inv(fp2Sub(q.X, p.X)))
	x := fp2Sub(fp2Sub(fp2Square(lambda), p.X), q.X)
	y := fp2Sub(fp2Mul(lambda, fp2Sub(p.X, x)), p.Y)
	return &G2{X: x, Y: y}
}

func (p *G2) double() *G2 {
	if p.Infinity || p.Y.IsZero() {
		return G2Zero()
	}
	num := fp2Mul(fp2Three, fp2Square(p.X))
	lambda := fp2Mul(num, fp2Inv(fp2Add(p.Y, p.Y)))
	x := fp2Sub(fp2Square(lambda), fp2Add(p.X, p.X))
	y := fp2Sub(fp2Mul(lambda, fp2Sub(p.X, x)), p.Y)
	return &G2{X: x, Y: y}
}

// ScalarMul returns k*p, computed in Jacobian coordinates.
func (p *G2) ScalarMul(k *big.Int) *G2 { return scalarMulJacobianG2(p, k) }

// Generators.
//
// These are derived rather than transcribed: a deterministic search finds the
// first curve point from a fixed seed, and clearing the cofactor puts it in the
// prime-order subgroup. That removes any chance of a mistyped 381-bit constant,
// at the cost of not matching Ethereum's generators — which this chain has no
// reason to, since none of the rest of its cryptography matches either.
var (
	g1Generator = deriveG1Generator()
	g2Generator = deriveG2Generator()
)

// G1Generator returns the generator of G1.
func G1Generator() *G1 { return g1Generator.Clone() }

// G2Generator returns the generator of G2.
func G2Generator() *G2 { return g2Generator.Clone() }

func deriveG1Generator() *G1 {
	for counter := uint32(0); ; counter++ {
		seed := keccak.Sum256([]byte("padi-chain/bls12381/g1-generator"), []byte{
			byte(counter >> 24), byte(counter >> 16), byte(counter >> 8), byte(counter),
		})
		x := feFromBig(new(big.Int).SetBytes(seed[:]))

		// y^2 = x^3 + 4
		rhs := fpAdd(fpMul(fpMul(x, x), x), curveB)
		y, ok := fpSqrtBase(rhs)
		if !ok {
			continue
		}
		candidate := (&G1{X: x, Y: y}).ScalarMul(G1Cofactor)
		if !candidate.Infinity {
			return candidate
		}
	}
}

func deriveG2Generator() *G2 {
	for counter := uint32(0); ; counter++ {
		point := mapToG2Uncleared([]byte("padi-chain/bls12381/g2-generator"), counter)
		if point == nil {
			continue
		}
		candidate := point.ScalarMul(G2Cofactor)
		if !candidate.Infinity {
			return candidate
		}
	}
}

// Small constants in Montgomery form.
var (
	feTwo    = feFromBig(bigTwo)
	feThree  = feFromBig(big.NewInt(3))
	fp2Three = newFp2FromInt(3, 0)
)
