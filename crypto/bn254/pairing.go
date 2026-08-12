package bn254

import "math/big"

// The optimal ate pairing.
//
// The Miller loop accumulates the line functions through the multiples of the
// second argument, evaluated at the first. Because the twist represents G2 over
// Fp2, each line is untwisted into Fp12 as it is used: under the untwisting map
// (x, y) -> (x*w^2, y*w^3), a line through twist points becomes a sparse Fp12
// element whose only nonzero parts are the ones written below.

// ateLoopCount is |6x + 2| for the BN parameter x = 4965661367192848881.
var ateLoopCount, _ = new(big.Int).SetString("29793968203157093288", 10)

// frobeniusGamma1 = xi^((p-1)/3) and frobeniusGamma2 = xi^((p-1)/2) map the
// twist through the p-power Frobenius. They are computed rather than
// hardcoded, so a transcription slip cannot go unnoticed.
var (
	frobeniusGamma1 = fp2Exp(xi, new(big.Int).Div(new(big.Int).Sub(P, bigOne), big.NewInt(3)))
	frobeniusGamma2 = fp2Exp(xi, new(big.Int).Div(new(big.Int).Sub(P, bigOne), bigTwo))
)

// frobenius applies the untwisted p-power Frobenius to a twist point.
func frobenius(p *G2) *G2 {
	if p.Infinity {
		return G2Zero()
	}
	// Raising an Fp2 element to the p-th power is conjugation.
	return &G2{
		X: fp2Mul(fp2Conjugate(p.X), frobeniusGamma1),
		Y: fp2Mul(fp2Conjugate(p.Y), frobeniusGamma2),
	}
}

// lineFrom builds the Fp12 value of the line with slope lambda through the
// twist point (x1, y1), evaluated at the G1 point p.
//
// Untwisting turns y - y1 - lambda*(x - x1) into
//
//	yp - lambda*xp*w + (lambda*x1 - y1)*w^3
//
// and since w^2 = v, the w^3 term lands in the v coefficient of the w half.
func lineFrom(lambda, x1, y1 *Fp2, p *G1) *Fp12 {
	yp := newFp2(new(big.Int).Set(p.Y), new(big.Int))
	xp := newFp2(new(big.Int).Set(p.X), new(big.Int))

	c0 := newFp6(yp, fp2Zero(), fp2Zero())
	c1 := newFp6(
		fp2Neg(fp2Mul(lambda, xp)),
		fp2Sub(fp2Mul(lambda, x1), y1),
		fp2Zero(),
	)
	return newFp12(c0, c1)
}

// doublingStep returns the tangent line at t evaluated at p, and 2t.
func doublingStep(t *G2, p *G1) (*Fp12, *G2) {
	if t.Infinity || t.Y.IsZero() {
		return fp12One(), G2Zero()
	}
	three := newFp2(big.NewInt(3), new(big.Int))
	lambda := fp2Mul(fp2Mul(three, fp2Square(t.X)), fp2Inv(fp2Add(t.Y, t.Y)))

	line := lineFrom(lambda, t.X, t.Y, p)

	x := fp2Sub(fp2Square(lambda), fp2Add(t.X, t.X))
	y := fp2Sub(fp2Mul(lambda, fp2Sub(t.X, x)), t.Y)
	return line, &G2{X: x, Y: y}
}

// additionStep returns the chord through t and q evaluated at p, and t+q.
func additionStep(t, q *G2, p *G1) (*Fp12, *G2) {
	if t.Infinity {
		return fp12One(), q.clone()
	}
	if q.Infinity {
		return fp12One(), t.clone()
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

// millerLoop computes the unreduced pairing of the given pairs.
//
// Accumulating all pairs into one Fp12 value means a product of pairings costs
// one final exponentiation rather than one per pair, which is why the
// precompile takes a list.
func millerLoop(pairs []Pair) *Fp12 {
	f := fp12One()
	states := make([]*G2, len(pairs))
	for i, pair := range pairs {
		states[i] = pair.G2.clone()
	}

	for i := ateLoopCount.BitLen() - 2; i >= 0; i-- {
		f = fp12Square(f)
		for j, pair := range pairs {
			line, next := doublingStep(states[j], pair.G1)
			f = fp12Mul(f, line)
			states[j] = next
		}
		if ateLoopCount.Bit(i) == 1 {
			for j, pair := range pairs {
				line, next := additionStep(states[j], pair.G2, pair.G1)
				f = fp12Mul(f, line)
				states[j] = next
			}
		}
	}

	// The two extra steps that make the ate pairing bilinear on a BN curve.
	for j, pair := range pairs {
		q1 := frobenius(pair.G2)
		q2 := frobenius(q1).Neg()

		line, next := additionStep(states[j], q1, pair.G1)
		f = fp12Mul(f, line)
		states[j] = next

		line, next = additionStep(states[j], q2, pair.G1)
		f = fp12Mul(f, line)
		states[j] = next
	}
	return f
}

// finalExponent is (p^12 - 1)/r, the power that maps the Miller loop's output
// into the target group.
var finalExponent = func() *big.Int {
	p12 := new(big.Int).Exp(P, big.NewInt(12), nil)
	p12.Sub(p12, bigOne)
	return p12.Div(p12, Order)
}()

// finalExponentiation reduces the Miller loop output to a unique value.
//
// Without it the result depends on which representative of a coset the loop
// happened to produce, and the pairing would not be well defined. The easy part
// is applied with Frobenius and an inversion; the hard part is a single
// exponentiation, which is the clearest formulation rather than the fastest —
// the specialised addition chain for BN curves is an optimisation this does not
// need to be correct.
func finalExponentiation(f *Fp12) *Fp12 {
	// Easy part: f^(p^6 - 1) then f^(p^2 + 1).
	inv := fp12Inv(f)
	if inv == nil {
		return fp12One()
	}
	t := fp12Mul(fp12Conjugate(f), inv)
	t = fp12Mul(fp12Frobenius2(t), t)

	// Hard part.
	return fp12Exp(t, hardExponent)
}

// hardExponent is (p^4 - p^2 + 1)/r.
var hardExponent = func() *big.Int {
	p2 := new(big.Int).Mul(P, P)
	p4 := new(big.Int).Mul(p2, p2)
	e := new(big.Int).Sub(p4, p2)
	e.Add(e, bigOne)
	return e.Div(e, Order)
}()

// fp12Frobenius2 raises to the p^2 power, used by the easy part.
func fp12Frobenius2(a *Fp12) *Fp12 {
	p2 := new(big.Int).Mul(P, P)
	return fp12Exp(a, p2)
}

// Pair is one term of a pairing product.
type Pair struct {
	G1 *G1
	G2 *G2
}

// Pairing returns e(a, b).
func Pairing(a *G1, b *G2) *Fp12 {
	if a.Infinity || b.Infinity {
		return fp12One()
	}
	return finalExponentiation(millerLoop([]Pair{{G1: a, G2: b}}))
}

// PairingCheck reports whether the product of the pairings is one, which is
// the question every SNARK verifier actually asks.
func PairingCheck(pairs []Pair) bool {
	var active []Pair
	for _, pair := range pairs {
		// A term with an identity input contributes a factor of one.
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
