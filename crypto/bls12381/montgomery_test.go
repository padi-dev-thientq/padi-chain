package bls12381

import (
	"math/big"
	"math/rand"
	"testing"
)

func TestMontgomeryAgainstBigInt(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	for i := 0; i < 5000; i++ {
		x := new(big.Int).Rand(rng, P)
		y := new(big.Int).Rand(rng, P)
		a, b := feFromBig(x), feFromBig(y)

		if got, want := montMul(&a, &b).Big(), new(big.Int).Mod(new(big.Int).Mul(x, y), P); got.Cmp(want) != 0 {
			t.Fatalf("mul: %s * %s = %s, want %s", x, y, got, want)
		}
		if got, want := montAdd(&a, &b).Big(), new(big.Int).Mod(new(big.Int).Add(x, y), P); got.Cmp(want) != 0 {
			t.Fatalf("add: %s + %s = %s, want %s", x, y, got, want)
		}
		if got, want := montSub(&a, &b).Big(), new(big.Int).Mod(new(big.Int).Sub(x, y), P); got.Cmp(want) != 0 {
			t.Fatalf("sub: %s - %s = %s, want %s", x, y, got, want)
		}
		if got, want := montNeg(&a).Big(), new(big.Int).Mod(new(big.Int).Neg(x), P); got.Cmp(want) != 0 {
			t.Fatalf("neg: -%s = %s, want %s", x, got, want)
		}
		if x.Sign() != 0 {
			inv := montInv(&a)
			product := montMul(&a, &inv)
			if !product.Equal(&feOne) {
				t.Fatalf("inv: a * a^-1 != 1 for %s", x)
			}
		}
	}
}

func TestMontgomeryEdgeCases(t *testing.T) {
	zero := feFromUint64(0)
	one := feFromUint64(1)
	pMinus1 := feFromBig(new(big.Int).Sub(P, big.NewInt(1)))

	if !(&zero).IsZero() {
		t.Fatal("zero is not zero")
	}
	if !(&one).Equal(&feOne) {
		t.Fatal("one does not match the precomputed constant")
	}
	// (p-1) + 1 wraps to zero.
	if got := montAdd(&pMinus1, &one); !(&got).IsZero() {
		t.Fatalf("(p-1)+1 = %s, want 0", got.Big())
	}
	// 0 - 1 is p-1.
	if got := montSub(&zero, &one); !(&got).Equal(&pMinus1) {
		t.Fatalf("0-1 = %s, want p-1", got.Big())
	}
	// (p-1)^2 = 1 mod p.
	if got := montSquare(&pMinus1).Big(); got.Cmp(big.NewInt(1)) != 0 {
		t.Fatalf("(p-1)^2 = %s, want 1", got)
	}
}

func BenchmarkMontMul(b *testing.B) {
	x := feFromBig(new(big.Int).Sub(P, big.NewInt(12345)))
	y := feFromBig(new(big.Int).Rsh(P, 3))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		montMul(&x, &y)
	}
}
