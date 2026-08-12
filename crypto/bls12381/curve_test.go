package bls12381

import (
	"math/big"
	"testing"
)

func TestDerivedConstantsMatchTheCurve(t *testing.T) {
	// The published BLS12-381 prime and group order. If the derivation from X
	// is wrong, everything else in this package is meaningless, so it is
	// checked against the values the curve is known by.
	wantP := "1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab"
	wantR := "73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001"

	if got := P.Text(16); got != wantP {
		t.Fatalf("derived prime =\n  %s\nwant\n  %s", got, wantP)
	}
	if got := Order.Text(16); got != wantR {
		t.Fatalf("derived order =\n  %s\nwant\n  %s", got, wantR)
	}
	if P.BitLen() != 381 {
		t.Fatalf("prime is %d bits, want 381", P.BitLen())
	}
	if Order.BitLen() != 255 {
		t.Fatalf("order is %d bits, want 255", Order.BitLen())
	}
	// p ≡ 3 (mod 4) is what makes the square root formulas used here valid.
	if new(big.Int).Mod(P, big.NewInt(4)).Int64() != 3 {
		t.Fatal("the square root formulas assume p ≡ 3 (mod 4)")
	}
}

func TestGeneratorsAreValid(t *testing.T) {
	g1 := G1Generator()
	if !g1.OnCurve() {
		t.Fatal("the G1 generator is not on the curve")
	}
	if !g1.InSubgroup() {
		t.Fatal("the G1 generator is not in the prime-order subgroup")
	}
	if g1.Infinity {
		t.Fatal("the G1 generator is the identity")
	}

	g2 := G2Generator()
	if !g2.OnCurve() {
		t.Fatal("the G2 generator is not on the twist")
	}
	if !g2.InSubgroup() {
		t.Fatal("the G2 generator is not in the prime-order subgroup")
	}
	if g2.Infinity {
		t.Fatal("the G2 generator is the identity")
	}
}

func TestGeneratorsAreDeterministic(t *testing.T) {
	// Derived generators are only usable if every node derives the same ones.
	if !deriveG1Generator().Equal(G1Generator()) {
		t.Fatal("the G1 generator derivation is not deterministic")
	}
	if !deriveG2Generator().Equal(G2Generator()) {
		t.Fatal("the G2 generator derivation is not deterministic")
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

func TestGroupArithmetic(t *testing.T) {
	g1 := G1Generator()
	acc := G1Zero()
	for i := 0; i < 12; i++ {
		acc = acc.Add(g1)
	}
	if !acc.Equal(g1.ScalarMul(big.NewInt(12))) {
		t.Fatal("G1: repeated addition disagrees with scalar multiplication")
	}
	if !g1.Add(g1.Neg()).Infinity {
		t.Fatal("G1: P + (-P) is not the identity")
	}

	g2 := G2Generator()
	acc2 := G2Zero()
	for i := 0; i < 12; i++ {
		acc2 = acc2.Add(g2)
	}
	if !acc2.Equal(g2.ScalarMul(big.NewInt(12))) {
		t.Fatal("G2: repeated addition disagrees with scalar multiplication")
	}
	if !g2.Add(g2.Neg()).Infinity {
		t.Fatal("G2: P + (-P) is not the identity")
	}
}

func TestFieldTower(t *testing.T) {
	a := newFp2(big.NewInt(7), big.NewInt(11))
	if !fp2Mul(a, fp2Inv(a)).Equal(fp2One()) {
		t.Fatal("Fp2 inversion is wrong")
	}
	// v^3 must reduce to xi = u + 1.
	v := newFp6(fp2Zero(), fp2One(), fp2Zero())
	if !fp6Mul(fp6Mul(v, v), v).Equal(newFp6(xi, fp2Zero(), fp2Zero())) {
		t.Fatal("v^3 does not reduce to u+1")
	}
	x := newFp6(a, newFp2(big.NewInt(3), big.NewInt(5)), newFp2(big.NewInt(2), big.NewInt(9)))
	if !fp6Mul(x, fp6Inv(x)).Equal(fp6One()) {
		t.Fatal("Fp6 inversion is wrong")
	}
	// w^2 must reduce to v.
	w := newFp12(fp6Zero(), fp6One())
	if !fp12Square(w).Equal(newFp12(v, fp6Zero())) {
		t.Fatal("w^2 does not reduce to v")
	}
	y := newFp12(x, fp6One())
	if !fp12Mul(y, fp12Inv(y)).Equal(fp12One()) {
		t.Fatal("Fp12 inversion is wrong")
	}
}

func TestFp2SquareRoot(t *testing.T) {
	for _, a := range []*Fp2{
		newFp2(big.NewInt(4), new(big.Int)),
		newFp2(big.NewInt(7), big.NewInt(11)),
		newFp2(new(big.Int), big.NewInt(3)),
	} {
		square := fp2Square(a)
		root := fp2Sqrt(square)
		if root == nil {
			t.Fatalf("no root found for a perfect square %v", square)
		}
		if !fp2Square(root).Equal(square) {
			t.Fatal("the returned root does not square back")
		}
	}
}

func TestPairingIsNonDegenerate(t *testing.T) {
	e := Pairing(G1Generator(), G2Generator())
	if e.IsOne() {
		t.Fatal("e(G1, G2) is one: the pairing is degenerate")
	}
	if !fp12Exp(e, Order).IsOne() {
		t.Fatal("e(G1, G2) does not have order r")
	}
}

func TestPairingBilinearity(t *testing.T) {
	g1, g2 := G1Generator(), G2Generator()
	a := big.NewInt(31337)
	b := big.NewInt(1234567)

	lhs := Pairing(g1.ScalarMul(a), g2.ScalarMul(b))
	rhs := fp12Exp(Pairing(g1, g2), new(big.Int).Mul(a, b))
	if !lhs.Equal(rhs) {
		t.Fatal("the pairing is not bilinear")
	}
	if !Pairing(g1.ScalarMul(a), g2).Equal(Pairing(g1, g2.ScalarMul(a))) {
		t.Fatal("the pairing does not move scalars between arguments")
	}
}

func TestPairingCheck(t *testing.T) {
	g1, g2 := G1Generator(), G2Generator()
	if !PairingCheck([]Pair{{g1, g2}, {g1.Neg(), g2}}) {
		t.Fatal("e(P,Q)*e(-P,Q) should be one")
	}
	if PairingCheck([]Pair{{g1, g2}}) {
		t.Fatal("e(P,Q) alone should not be one")
	}
}

func TestHashToG2(t *testing.T) {
	a := HashToG2([]byte("a message"))
	if !a.OnCurve() {
		t.Fatal("the hashed point is not on the curve")
	}
	// Without cofactor clearing the point would not be in the subgroup the
	// pairing is defined over, and no signature over it would verify.
	if !a.InSubgroup() {
		t.Fatal("the hashed point is not in the prime-order subgroup")
	}
	if a.Infinity {
		t.Fatal("the hash produced the identity")
	}

	// Deterministic, and different messages give different points.
	if !HashToG2([]byte("a message")).Equal(a) {
		t.Fatal("hashing is not deterministic")
	}
	if HashToG2([]byte("another message")).Equal(a) {
		t.Fatal("two messages hashed to the same point")
	}
	// The empty message must work too.
	if !HashToG2(nil).InSubgroup() {
		t.Fatal("the empty message did not map into the subgroup")
	}
}
