package bn254

import (
	"errors"
	"math/big"
)

var (
	ErrNotOnCurve      = errors.New("bn254: point is not on the curve")
	ErrNotInSubgroup   = errors.New("bn254: point is not in the prime-order subgroup")
	ErrCoordinateRange = errors.New("bn254: coordinate is not a field element")
)

// G1 is a point on y^2 = x^3 + 3 over Fp, in affine coordinates. A nil pair of
// coordinates is the point at infinity, which is how the precompiles encode the
// identity.
type G1 struct {
	X, Y     *big.Int
	Infinity bool
}

// G1Generator returns the standard generator (1, 2).
func G1Generator() *G1 {
	return &G1{X: big.NewInt(1), Y: big.NewInt(2)}
}

// G1Zero returns the point at infinity.
func G1Zero() *G1 { return &G1{X: new(big.Int), Y: new(big.Int), Infinity: true} }

// NewG1 builds a point from affine coordinates and validates it.
func NewG1(x, y *big.Int) (*G1, error) {
	if x.Sign() < 0 || x.Cmp(P) >= 0 || y.Sign() < 0 || y.Cmp(P) >= 0 {
		return nil, ErrCoordinateRange
	}
	// The precompiles encode infinity as (0, 0), which is not a curve point.
	if x.Sign() == 0 && y.Sign() == 0 {
		return G1Zero(), nil
	}
	p := &G1{X: new(big.Int).Set(x), Y: new(big.Int).Set(y)}
	if !p.IsOnCurve() {
		return nil, ErrNotOnCurve
	}
	return p, nil
}

// IsOnCurve reports whether the point satisfies the curve equation.
func (p *G1) IsOnCurve() bool {
	if p.Infinity {
		return true
	}
	lhs := fpMul(p.Y, p.Y)
	rhs := fpAdd(fpMul(fpMul(p.X, p.X), p.X), curveB)
	return lhs.Cmp(rhs) == 0
}

func (p *G1) Equal(q *G1) bool {
	if p.Infinity || q.Infinity {
		return p.Infinity == q.Infinity
	}
	return p.X.Cmp(q.X) == 0 && p.Y.Cmp(q.Y) == 0
}

// Neg returns -p.
func (p *G1) Neg() *G1 {
	if p.Infinity {
		return G1Zero()
	}
	return &G1{X: new(big.Int).Set(p.X), Y: fpNeg(p.Y)}
}

// Add returns p + q using the affine chord-and-tangent rules.
func (p *G1) Add(q *G1) *G1 {
	if p.Infinity {
		return q.clone()
	}
	if q.Infinity {
		return p.clone()
	}
	if p.X.Cmp(q.X) == 0 {
		if p.Y.Cmp(q.Y) != 0 {
			return G1Zero() // q == -p
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
	// lambda = 3x^2 / 2y; the curve has no a term, so that is the whole tangent.
	num := fpMul(big.NewInt(3), fpMul(p.X, p.X))
	den := fpInv(fpMul(bigTwo, p.Y))
	lambda := fpMul(num, den)

	x := fpSub(fpMul(lambda, lambda), fpMul(bigTwo, p.X))
	y := fpSub(fpMul(lambda, fpSub(p.X, x)), p.Y)
	return &G1{X: x, Y: y}
}

// ScalarMul returns k*p.
func (p *G1) ScalarMul(k *big.Int) *G1 {
	k = new(big.Int).Mod(k, Order)
	result := G1Zero()
	addend := p.clone()
	for i := 0; i < k.BitLen(); i++ {
		if k.Bit(i) == 1 {
			result = result.Add(addend)
		}
		addend = addend.double()
	}
	return result
}

func (p *G1) clone() *G1 {
	if p.Infinity {
		return G1Zero()
	}
	return &G1{X: new(big.Int).Set(p.X), Y: new(big.Int).Set(p.Y)}
}

// G2 is a point on the sextic twist y^2 = x^3 + 3/xi over Fp2.
type G2 struct {
	X, Y     *Fp2
	Infinity bool
}

// twistB is the curve constant of the twist: 3/xi.
var twistB = func() *Fp2 {
	three := newFp2(big.NewInt(3), new(big.Int))
	return fp2Mul(three, fp2Inv(xi))
}()

// G2Generator returns the standard generator of the twist.
func G2Generator() *G2 {
	x0, _ := new(big.Int).SetString("10857046999023057135944570762232829481370756359578518086990519993285655852781", 10)
	x1, _ := new(big.Int).SetString("11559732032986387107991004021392285783925812861821192530917403151452391805634", 10)
	y0, _ := new(big.Int).SetString("8495653923123431417604973247489272438418190587263600148770280649306958101930", 10)
	y1, _ := new(big.Int).SetString("4082367875863433681332203403145435568316851327593401208105741076214120093531", 10)
	return &G2{X: newFp2(x0, x1), Y: newFp2(y0, y1)}
}

// G2Zero returns the point at infinity on the twist.
func G2Zero() *G2 { return &G2{X: fp2Zero(), Y: fp2Zero(), Infinity: true} }

// NewG2 builds a twist point and validates both the curve equation and
// subgroup membership.
//
// The subgroup check matters: the twist has points outside the prime-order
// subgroup, and a pairing involving one of them produces a value an attacker
// can steer. Skipping the check is a known way to break SNARK verifiers.
func NewG2(x0, x1, y0, y1 *big.Int) (*G2, error) {
	for _, c := range []*big.Int{x0, x1, y0, y1} {
		if c.Sign() < 0 || c.Cmp(P) >= 0 {
			return nil, ErrCoordinateRange
		}
	}
	if x0.Sign() == 0 && x1.Sign() == 0 && y0.Sign() == 0 && y1.Sign() == 0 {
		return G2Zero(), nil
	}
	p := &G2{X: newFp2(x0, x1), Y: newFp2(y0, y1)}
	if !p.IsOnCurve() {
		return nil, ErrNotOnCurve
	}
	if !p.InSubgroup() {
		return nil, ErrNotInSubgroup
	}
	return p, nil
}

// IsOnCurve reports whether the point satisfies the twist equation.
func (p *G2) IsOnCurve() bool {
	if p.Infinity {
		return true
	}
	lhs := fp2Square(p.Y)
	rhs := fp2Add(fp2Mul(fp2Square(p.X), p.X), twistB)
	return lhs.Equal(rhs)
}

// InSubgroup reports whether the point has the prime order r.
func (p *G2) InSubgroup() bool {
	if p.Infinity {
		return true
	}
	return p.ScalarMul(Order).Infinity
}

func (p *G2) Equal(q *G2) bool {
	if p.Infinity || q.Infinity {
		return p.Infinity == q.Infinity
	}
	return p.X.Equal(q.X) && p.Y.Equal(q.Y)
}

// Neg returns -p.
func (p *G2) Neg() *G2 {
	if p.Infinity {
		return G2Zero()
	}
	return &G2{X: p.X.Clone(), Y: fp2Neg(p.Y)}
}

// Add returns p + q.
func (p *G2) Add(q *G2) *G2 {
	if p.Infinity {
		return q.clone()
	}
	if q.Infinity {
		return p.clone()
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
	three := newFp2(big.NewInt(3), new(big.Int))
	num := fp2Mul(three, fp2Square(p.X))
	den := fp2Inv(fp2Add(p.Y, p.Y))
	lambda := fp2Mul(num, den)

	x := fp2Sub(fp2Square(lambda), fp2Add(p.X, p.X))
	y := fp2Sub(fp2Mul(lambda, fp2Sub(p.X, x)), p.Y)
	return &G2{X: x, Y: y}
}

// ScalarMul returns k*p.
func (p *G2) ScalarMul(k *big.Int) *G2 {
	result := G2Zero()
	addend := p.clone()
	for i := 0; i < k.BitLen(); i++ {
		if k.Bit(i) == 1 {
			result = result.Add(addend)
		}
		addend = addend.double()
	}
	return result
}

func (p *G2) clone() *G2 {
	if p.Infinity {
		return G2Zero()
	}
	return &G2{X: p.X.Clone(), Y: p.Y.Clone()}
}
