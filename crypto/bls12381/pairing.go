package bls12381

import "math/big"

// The optimal ate pairing on BLS12-381.
//
// The Miller loop runs over the bits of the curve parameter x. A BLS12 curve
// needs none of the extra Frobenius steps a BN curve does, which is part of why
// it is the family Ethereum moved to.

// lineFrom builds the Fp12 value of the line with slope lambda through the twist
// point (x1, y1), evaluated at the G1 point p.
//
// BLS12-381 uses an M-type sextic twist — y^2 = x^3 + 4(u+1), with the curve
// constant multiplied by xi rather than divided by it. That flips the direction
// of the untwisting map: it sends (x, y) to (x/w^2, y/w^3) rather than
// (x*w^2, y*w^3). Getting this backwards produces a map that still lands in the
// right subgroup and still looks non-degenerate, but is not bilinear — which is
// exactly the failure worth guarding against, because only a bilinearity test
// catches it.
//
// Substituting into y - y1 - lambda*(x - x1) and clearing the 1/xi factors
// (constants in Fp6 are killed by the final exponentiation, so scaling the line
// by xi is free) gives:
//
//	yp*xi + (lambda*x1 - y1)*w^3 - lambda*xp*w^5
//
// With w^2 = v, the w^3 term lands in the v coefficient of the w half and the
// w^5 term in the v^2 coefficient.
func lineFrom(lambda, x1, y1 *Fp2, p *G1) *Fp12 {
	yp := newFp2(p.Y, feZero)
	xp := newFp2(p.X, feZero)

	c0 := newFp6(fp2MulXi(yp), fp2Zero(), fp2Zero())
	c1 := newFp6(
		fp2Zero(),
		fp2Sub(fp2Mul(lambda, x1), y1),
		fp2Neg(fp2Mul(lambda, xp)),
	)
	return newFp12(c0, c1)
}

func doublingStep(t *G2, p *G1) (*Fp12, *G2) {
	if t.Infinity || t.Y.IsZero() {
		return fp12One(), G2Zero()
	}
	lambda := fp2Mul(fp2Mul(fp2Three, fp2Square(t.X)), fp2Inv(fp2Add(t.Y, t.Y)))
	line := lineFrom(lambda, t.X, t.Y, p)

	x := fp2Sub(fp2Square(lambda), fp2Add(t.X, t.X))
	y := fp2Sub(fp2Mul(lambda, fp2Sub(t.X, x)), t.Y)
	return line, &G2{X: x, Y: y}
}

func additionStep(t, q *G2, p *G1) (*Fp12, *G2) {
	if t.Infinity {
		return fp12One(), q.Clone()
	}
	if q.Infinity {
		return fp12One(), t.Clone()
	}
	if t.X.Equal(q.X) {
		if t.Y.Equal(q.Y) {
			return doublingStep(t, p)
		}
		// A vertical line contributes a factor the final exponentiation
		// removes, so it can be skipped.
		return fp12One(), G2Zero()
	}
	lambda := fp2Mul(fp2Sub(q.Y, t.Y), fp2Inv(fp2Sub(q.X, t.X)))
	line := lineFrom(lambda, t.X, t.Y, p)

	x := fp2Sub(fp2Sub(fp2Square(lambda), t.X), q.X)
	y := fp2Sub(fp2Mul(lambda, fp2Sub(t.X, x)), t.Y)
	return line, &G2{X: x, Y: y}
}

// Pair is one term of a pairing product.
type Pair struct {
	G1 *G1
	G2 *G2
}

// absX is |x|, the Miller loop counter.
var absX = new(big.Int).Abs(X)

// millerLoop accumulates the line functions for every pair into one value, so a
// product of pairings costs one final exponentiation rather than one per pair.
func millerLoop(pairs []Pair) *Fp12 {
	f := fp12One()
	states := make([]*G2, len(pairs))
	for i, pair := range pairs {
		states[i] = pair.G2.Clone()
	}

	for i := absX.BitLen() - 2; i >= 0; i-- {
		f = fp12Square(f)
		for j, pair := range pairs {
			line, next := doublingStep(states[j], pair.G1)
			f = fp12Mul(f, line)
			states[j] = next
		}
		if absX.Bit(i) == 1 {
			for j, pair := range pairs {
				line, next := additionStep(states[j], pair.G2, pair.G1)
				f = fp12Mul(f, line)
				states[j] = next
			}
		}
	}

	// x is negative for this curve, which inverts the loop's result.
	//
	// Conjugation would be the cheap way to invert, but only inside the
	// cyclotomic subgroup — and the raw Miller output is not in it yet. The
	// easy part of the final exponentiation is what puts it there, so here the
	// inversion has to be a real one.
	if X.Sign() < 0 {
		if inv := fp12Inv(f); inv != nil {
			f = inv
		}
	}
	return f
}

// cyclotomicExp exponentiates using cyclotomic squaring.
func cyclotomicExp(a *Fp12, e *big.Int) *Fp12 {
	result := fp12One()
	base := a
	for i := 0; i < e.BitLen(); i++ {
		if e.Bit(i) == 1 {
			result = fp12Mul(result, base)
		}
		base = cyclotomicSquare(base)
	}
	return result
}

// expByX raises to the power x. The curve parameter is 64 bits where the hard
// exponent is over 1200, which is the whole reason the chain below is worth
// having.
func expByX(a *Fp12) *Fp12 {
	result := cyclotomicExp(a, absX)
	if X.Sign() < 0 {
		return fp12Conjugate(result)
	}
	return result
}

// expByHalfX raises to the power x/2. The curve parameter is even, so this is
// exact.
func expByHalfX(a *Fp12) *Fp12 {
	result := cyclotomicExp(a, new(big.Int).Rsh(absX, 1))
	if X.Sign() < 0 {
		return fp12Conjugate(result)
	}
	return result
}

// finalExponentiation maps the Miller loop's output to a unique value.
//
// Without it the result depends on which representative of a coset the loop
// produced, and the pairing would not be well defined.
//
// The easy part, f^((p^6-1)(p^2+1)), is Frobenius maps and one inversion. It
// also lands the value in the cyclotomic subgroup, where inversion becomes
// conjugation and squaring becomes cheaper — both of which the hard part relies
// on.
//
// The hard part raises to (p^4-p^2+1)/r. Done directly that is a 1200-bit
// exponentiation. The addition chain here expresses it through the 64-bit curve
// parameter instead, which removes most of the cost of a pairing.
func finalExponentiation(f *Fp12) *Fp12 {
	inv := fp12Inv(f)
	if inv == nil {
		return fp12One()
	}
	easy := fp12Mul(fp12Conjugate(f), inv)
	easy = fp12Mul(fp12FrobeniusN(easy, 2), easy)

	y0 := cyclotomicSquare(easy)
	y1 := expByX(y0)
	y2 := expByHalfX(y1)
	y3 := fp12Conjugate(easy)

	y1 = fp12Mul(y1, y3)
	y1 = fp12Conjugate(y1)
	y1 = fp12Mul(y1, y2)

	y2 = expByX(y1)
	y3 = expByX(y2)
	y1 = fp12Conjugate(y1)
	y3 = fp12Mul(y3, y1)
	y1 = fp12Conjugate(y1)

	y1 = fp12FrobeniusN(y1, 3)
	y2 = fp12FrobeniusN(y2, 2)
	y1 = fp12Mul(y1, y2)

	y2 = expByX(y3)
	y2 = fp12Mul(y2, y0)
	y2 = fp12Mul(y2, easy)

	y1 = fp12Mul(y1, y2)
	y2 = fp12Frobenius(y3)
	return fp12Mul(y1, y2)
}

// Pairing returns e(a, b).
func Pairing(a *G1, b *G2) *Fp12 {
	if a.Infinity || b.Infinity {
		return fp12One()
	}
	return finalExponentiation(millerLoop([]Pair{{G1: a, G2: b}}))
}

// PairingCheck reports whether the product of the pairings is one, which is the
// form every signature verification takes.
func PairingCheck(pairs []Pair) bool {
	var active []Pair
	for _, pair := range pairs {
		if pair.G1 == nil || pair.G2 == nil || pair.G1.Infinity || pair.G2.Infinity {
			continue
		}
		active = append(active, pair)
	}
	if len(active) == 0 {
		return true
	}
	return finalExponentiation(millerLoop(active)).IsOne()
}
