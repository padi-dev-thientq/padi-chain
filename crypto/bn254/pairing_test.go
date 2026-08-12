package bn254

import (
	"math/big"
	"testing"
)

func TestGeneratorsAreOnCurve(t *testing.T) {
	if !G1Generator().IsOnCurve() {
		t.Fatal("the G1 generator is not on the curve")
	}
	g2 := G2Generator()
	if !g2.IsOnCurve() {
		t.Fatal("the G2 generator is not on the twist")
	}
	if !g2.InSubgroup() {
		t.Fatal("the G2 generator is not in the prime-order subgroup")
	}
}

func TestGroupOrder(t *testing.T) {
	if !G1Generator().ScalarMul(Order).Infinity {
		t.Fatal("r*G1 is not the identity")
	}
	if !G2Generator().ScalarMul(Order).Infinity {
		t.Fatal("r*G2 is not the identity")
	}
}

func TestG1Arithmetic(t *testing.T) {
	g := G1Generator()

	// Repeated addition must agree with scalar multiplication.
	acc := G1Zero()
	for i := 0; i < 10; i++ {
		acc = acc.Add(g)
	}
	if !acc.Equal(g.ScalarMul(big.NewInt(10))) {
		t.Fatal("10*G disagrees with ten additions")
	}
	if !g.Add(g.Neg()).Infinity {
		t.Fatal("G + (-G) is not the identity")
	}
	// (a+b)*G == a*G + b*G
	a, b := big.NewInt(12345), big.NewInt(67890)
	lhs := g.ScalarMul(new(big.Int).Add(a, b))
	rhs := g.ScalarMul(a).Add(g.ScalarMul(b))
	if !lhs.Equal(rhs) {
		t.Fatal("scalar multiplication is not linear")
	}
}

func TestG2Arithmetic(t *testing.T) {
	g := G2Generator()
	acc := G2Zero()
	for i := 0; i < 8; i++ {
		acc = acc.Add(g)
	}
	if !acc.Equal(g.ScalarMul(big.NewInt(8))) {
		t.Fatal("8*G2 disagrees with eight additions")
	}
	if !g.Add(g.Neg()).Infinity {
		t.Fatal("G2 + (-G2) is not the identity")
	}
}

func TestFieldTower(t *testing.T) {
	a := newFp2(big.NewInt(7), big.NewInt(11))

	if !fp2Mul(a, fp2Inv(a)).Equal(fp2One()) {
		t.Fatal("Fp2 inversion is wrong")
	}
	if !fp2Square(a).Equal(fp2Mul(a, a)) {
		t.Fatal("Fp2 squaring disagrees with multiplication")
	}

	x := newFp6(a, newFp2(big.NewInt(3), big.NewInt(5)), newFp2(big.NewInt(2), big.NewInt(9)))
	if !fp6Mul(x, fp6Inv(x)).Equal(fp6One()) {
		t.Fatal("Fp6 inversion is wrong")
	}
	// v^3 must reduce to xi.
	v := newFp6(fp2Zero(), fp2One(), fp2Zero())
	v3 := fp6Mul(fp6Mul(v, v), v)
	if !v3.Equal(newFp6(xi, fp2Zero(), fp2Zero())) {
		t.Fatal("v^3 does not reduce to xi")
	}

	y := newFp12(x, fp6One())
	if !fp12Mul(y, fp12Inv(y)).Equal(fp12One()) {
		t.Fatal("Fp12 inversion is wrong")
	}
	// w^2 must reduce to v.
	w := newFp12(fp6Zero(), fp6One())
	if !fp12Square(w).Equal(newFp12(v, fp6Zero())) {
		t.Fatal("w^2 does not reduce to v")
	}
}

func TestPairingIsNonDegenerate(t *testing.T) {
	e := Pairing(G1Generator(), G2Generator())
	if e.IsOne() {
		t.Fatal("e(G1, G2) is one: the pairing is degenerate and useless")
	}
	// The result must have order r in the target group.
	if !fp12Exp(e, Order).IsOne() {
		t.Fatal("e(G1, G2) does not have order r")
	}
}

func TestPairingBilinearity(t *testing.T) {
	g1, g2 := G1Generator(), G2Generator()
	a := big.NewInt(31337)
	b := big.NewInt(42424242)

	// e(aP, bQ) == e(P, Q)^(ab)
	lhs := Pairing(g1.ScalarMul(a), g2.ScalarMul(b))
	rhs := fp12Exp(Pairing(g1, g2), new(big.Int).Mul(a, b))
	if !lhs.Equal(rhs) {
		t.Fatal("the pairing is not bilinear")
	}

	// e(aP, Q) == e(P, aQ)
	if !Pairing(g1.ScalarMul(a), g2).Equal(Pairing(g1, g2.ScalarMul(a))) {
		t.Fatal("the pairing does not move scalars between arguments")
	}
}

func TestPairingWithIdentity(t *testing.T) {
	if !Pairing(G1Zero(), G2Generator()).IsOne() {
		t.Fatal("e(O, Q) must be one")
	}
	if !Pairing(G1Generator(), G2Zero()).IsOne() {
		t.Fatal("e(P, O) must be one")
	}
}

func TestPairingCheck(t *testing.T) {
	g1, g2 := G1Generator(), G2Generator()

	// e(P, Q) * e(-P, Q) == 1: the product form every verifier relies on.
	if !PairingCheck([]Pair{{g1, g2}, {g1.Neg(), g2}}) {
		t.Fatal("e(P,Q)*e(-P,Q) should be one")
	}
	// A single non-trivial pairing is not one.
	if PairingCheck([]Pair{{g1, g2}}) {
		t.Fatal("e(P,Q) alone should not be one")
	}
	// An empty product is one by convention.
	if !PairingCheck(nil) {
		t.Fatal("an empty pairing product must be one")
	}

	// e(aP, bQ) * e(-abP, Q) == 1
	a, b := big.NewInt(7), big.NewInt(9)
	ab := new(big.Int).Mul(a, b)
	if !PairingCheck([]Pair{
		{g1.ScalarMul(a), g2.ScalarMul(b)},
		{g1.ScalarMul(ab).Neg(), g2},
	}) {
		t.Fatal("the bilinear product check failed")
	}
}

func TestRejectsInvalidPoints(t *testing.T) {
	// A point that satisfies no curve equation.
	if _, err := NewG1(big.NewInt(1), big.NewInt(3)); err == nil {
		t.Error("an off-curve G1 point was accepted")
	}
	// Coordinates must be reduced field elements.
	if _, err := NewG1(new(big.Int).Set(P), big.NewInt(2)); err == nil {
		t.Error("an unreduced coordinate was accepted")
	}
	// (0,0) is the encoding of infinity, not a curve point.
	p, err := NewG1(new(big.Int), new(big.Int))
	if err != nil || !p.Infinity {
		t.Errorf("(0,0) should decode to the identity, got %v %v", p, err)
	}
	// An off-curve G2 point.
	if _, err := NewG2(big.NewInt(1), big.NewInt(1), big.NewInt(1), big.NewInt(1)); err == nil {
		t.Error("an off-curve G2 point was accepted")
	}
}

func BenchmarkPairing(b *testing.B) {
	g1, g2 := G1Generator(), G2Generator()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Pairing(g1, g2)
	}
}
