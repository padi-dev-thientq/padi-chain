package bls12381

import (
	"math/big"
	"testing"
)

func BenchmarkFpMul(b *testing.B) {
	x := new(big.Int).Sub(P, big.NewInt(12345))
	y := new(big.Int).Rsh(P, 3)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		fpMul(x, y)
	}
}

func BenchmarkFpInv(b *testing.B) {
	x := new(big.Int).Rsh(P, 3)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		fpInv(x)
	}
}

func BenchmarkFp12Mul(b *testing.B) {
	a := newFp12(
		newFp6(newFp2(big.NewInt(1), big.NewInt(2)), newFp2(big.NewInt(3), big.NewInt(4)), newFp2(big.NewInt(5), big.NewInt(6))),
		newFp6(newFp2(big.NewInt(7), big.NewInt(8)), newFp2(big.NewInt(9), big.NewInt(10)), newFp2(big.NewInt(11), big.NewInt(12))),
	)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		fp12Mul(a, a)
	}
}

func BenchmarkMillerLoop(b *testing.B) {
	pair := []Pair{{G1: G1Generator(), G2: G2Generator()}}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		millerLoop(pair)
	}
}

func BenchmarkFinalExponentiation(b *testing.B) {
	f := millerLoop([]Pair{{G1: G1Generator(), G2: G2Generator()}})
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		finalExponentiation(f)
	}
}

func BenchmarkHashToG2(b *testing.B) {
	msg := []byte("a message to hash")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		HashToG2(msg)
	}
}

func BenchmarkG2ScalarMul(b *testing.B) {
	g := G2Generator()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		g.ScalarMul(G2Cofactor)
	}
}

func BenchmarkFp2Sqrt(b *testing.B) {
	a := fp2Square(newFp2(big.NewInt(7), big.NewInt(11)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		fp2Sqrt(a)
	}
}
