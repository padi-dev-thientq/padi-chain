package uint256

import (
	"math/big"
	"math/rand"
	"testing"
)

var (
	maxU256 = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 256), big.NewInt(1))
	mod256  = new(big.Int).Lsh(big.NewInt(1), 256)
)

func wrap(v *big.Int) *big.Int {
	out := new(big.Int).Mod(v, mod256)
	if out.Sign() < 0 {
		out.Add(out, mod256)
	}
	return out
}

// randInt draws a value biased toward the interesting magnitudes: small values,
// single-limb values and full-width values.
func randInt(rng *rand.Rand) *big.Int {
	switch rng.Intn(4) {
	case 0:
		return big.NewInt(rng.Int63n(1000))
	case 1:
		return new(big.Int).SetUint64(rng.Uint64())
	case 2:
		return new(big.Int).Rand(rng, new(big.Int).Lsh(big.NewInt(1), 128))
	default:
		return new(big.Int).Rand(rng, mod256)
	}
}

// toSigned reads a 256-bit value as two's-complement.
func toSigned(v *big.Int) *big.Int {
	if v.Bit(255) == 1 {
		return new(big.Int).Sub(v, mod256)
	}
	return new(big.Int).Set(v)
}

func TestConversionRoundTrip(t *testing.T) {
	for _, v := range []*big.Int{big.NewInt(0), big.NewInt(1), big.NewInt(255), maxU256,
		new(big.Int).Lsh(big.NewInt(1), 200)} {
		got := FromBig(v).ToBig()
		if got.Cmp(v) != 0 {
			t.Fatalf("round-trip of %s gave %s", v, got)
		}
	}
}

func TestBytesRoundTrip(t *testing.T) {
	v := FromBig(new(big.Int).Lsh(big.NewInt(0xdeadbeef), 100))
	b := v.Bytes32()
	if got := new(Int).SetBytes(b[:]); !got.Eq(v) {
		t.Fatalf("Bytes32 round-trip gave %s", got.Hex())
	}
	// The trimmed form must round-trip too.
	if got := new(Int).SetBytes(v.Bytes()); !got.Eq(v) {
		t.Fatalf("Bytes round-trip gave %s", got.Hex())
	}
	if got := new(Int).SetBytes(nil); !got.IsZero() {
		t.Fatal("empty bytes must decode to zero")
	}
	// Oversized input keeps the low 32 bytes.
	long := make([]byte, 40)
	long[7] = 1 // outside the low 32 bytes, so it must be discarded
	long[39] = 9
	got := new(Int).SetBytes(long)
	if !got.Eq(NewInt(9)) {
		t.Fatalf("bytes beyond the low 32 must be dropped, got %s", got.Hex())
	}
}

func TestArithmeticAgainstBigInt(t *testing.T) {
	rng := rand.New(rand.NewSource(42))
	for i := 0; i < 20000; i++ {
		xb, yb := randInt(rng), randInt(rng)
		x, y := FromBig(xb), FromBig(yb)

		if got, want := new(Int).Add(x, y).ToBig(), wrap(new(big.Int).Add(xb, yb)); got.Cmp(want) != 0 {
			t.Fatalf("%s + %s = %s, want %s", xb, yb, got, want)
		}
		if got, want := new(Int).Sub(x, y).ToBig(), wrap(new(big.Int).Sub(xb, yb)); got.Cmp(want) != 0 {
			t.Fatalf("%s - %s = %s, want %s", xb, yb, got, want)
		}
		if got, want := new(Int).Mul(x, y).ToBig(), wrap(new(big.Int).Mul(xb, yb)); got.Cmp(want) != 0 {
			t.Fatalf("%s * %s = %s, want %s", xb, yb, got, want)
		}

		wantDiv, wantMod := new(big.Int), new(big.Int)
		if yb.Sign() != 0 {
			wantDiv.Div(xb, yb)
			wantMod.Mod(xb, yb)
		}
		if got := new(Int).Div(x, y).ToBig(); got.Cmp(wantDiv) != 0 {
			t.Fatalf("%s / %s = %s, want %s", xb, yb, got, wantDiv)
		}
		if got := new(Int).Mod(x, y).ToBig(); got.Cmp(wantMod) != 0 {
			t.Fatalf("%s %% %s = %s, want %s", xb, yb, got, wantMod)
		}
	}
}

func TestSignedArithmeticAgainstBigInt(t *testing.T) {
	rng := rand.New(rand.NewSource(7))
	for i := 0; i < 20000; i++ {
		xb, yb := randInt(rng), randInt(rng)
		x, y := FromBig(xb), FromBig(yb)
		xs, ys := toSigned(xb), toSigned(yb)

		wantDiv, wantMod := new(big.Int), new(big.Int)
		if ys.Sign() != 0 {
			// Go's Quo/Rem truncate toward zero, which is what the EVM's
			// SDIV and SMOD specify.
			wantDiv.Quo(xs, ys)
			wantMod.Rem(xs, ys)
		}
		if got := toSigned(new(Int).SDiv(x, y).ToBig()); got.Cmp(wantDiv) != 0 {
			t.Fatalf("sdiv(%s, %s) = %s, want %s", xs, ys, got, wantDiv)
		}
		if got := toSigned(new(Int).SMod(x, y).ToBig()); got.Cmp(wantMod) != 0 {
			t.Fatalf("smod(%s, %s) = %s, want %s", xs, ys, got, wantMod)
		}
		if got, want := x.SLt(y), xs.Cmp(ys) < 0; got != want {
			t.Fatalf("slt(%s, %s) = %v", xs, ys, got)
		}
		if got, want := x.SGt(y), xs.Cmp(ys) > 0; got != want {
			t.Fatalf("sgt(%s, %s) = %v", xs, ys, got)
		}
	}
}

func TestModularArithmetic(t *testing.T) {
	rng := rand.New(rand.NewSource(9))
	for i := 0; i < 5000; i++ {
		xb, yb, mb := randInt(rng), randInt(rng), randInt(rng)
		x, y, m := FromBig(xb), FromBig(yb), FromBig(mb)

		wantAdd, wantMul := new(big.Int), new(big.Int)
		if mb.Sign() != 0 {
			wantAdd.Mod(new(big.Int).Add(xb, yb), mb)
			wantMul.Mod(new(big.Int).Mul(xb, yb), mb)
		}
		if got := new(Int).AddMod(x, y, m).ToBig(); got.Cmp(wantAdd) != 0 {
			t.Fatalf("addmod(%s, %s, %s) = %s, want %s", xb, yb, mb, got, wantAdd)
		}
		if got := new(Int).MulMod(x, y, m).ToBig(); got.Cmp(wantMul) != 0 {
			t.Fatalf("mulmod(%s, %s, %s) = %s, want %s", xb, yb, mb, got, wantMul)
		}
	}
}

func TestMulModMaxValues(t *testing.T) {
	// The worst case for the 512-bit intermediate product.
	max := new(Int).SetAllOnes()
	m := FromBig(new(big.Int).Sub(maxU256, big.NewInt(58)))
	want := new(big.Int).Mod(new(big.Int).Mul(maxU256, maxU256), m.ToBig())
	if got := new(Int).MulMod(max, max, m).ToBig(); got.Cmp(want) != 0 {
		t.Fatalf("mulmod of maximal values = %s, want %s", got, want)
	}
}

func TestExp(t *testing.T) {
	cases := []struct{ base, exp uint64 }{{2, 10}, {3, 5}, {0, 0}, {0, 5}, {7, 0}, {2, 255}, {2, 256}}
	for _, c := range cases {
		want := wrap(new(big.Int).Exp(new(big.Int).SetUint64(c.base), new(big.Int).SetUint64(c.exp), nil))
		got := new(Int).Exp(NewInt(c.base), NewInt(c.exp)).ToBig()
		if got.Cmp(want) != 0 {
			t.Errorf("%d^%d = %s, want %s", c.base, c.exp, got, want)
		}
	}
	// Overflowing exponentiation wraps rather than growing.
	big7 := FromBig(new(big.Int).Lsh(big.NewInt(1), 200))
	want := wrap(new(big.Int).Exp(big7.ToBig(), big.NewInt(3), nil))
	if got := new(Int).Exp(big7, NewInt(3)).ToBig(); got.Cmp(want) != 0 {
		t.Errorf("large exponentiation = %s, want %s", got, want)
	}
}

func TestShifts(t *testing.T) {
	rng := rand.New(rand.NewSource(11))
	for i := 0; i < 5000; i++ {
		xb := randInt(rng)
		x := FromBig(xb)
		n := uint(rng.Intn(300))

		if got, want := new(Int).Lsh(x, n).ToBig(), wrap(new(big.Int).Lsh(xb, n)); got.Cmp(want) != 0 {
			t.Fatalf("%s << %d = %s, want %s", xb, n, got, want)
		}
		wantRsh := new(big.Int)
		if n < 256 {
			wantRsh.Rsh(xb, n)
		}
		if got := new(Int).Rsh(x, n).ToBig(); got.Cmp(wantRsh) != 0 {
			t.Fatalf("%s >> %d = %s, want %s", xb, n, got, wantRsh)
		}

		// Arithmetic shift: compare against a signed big.Int shift.
		xs := toSigned(xb)
		var wantSar *big.Int
		if n >= 256 {
			if xs.Sign() < 0 {
				wantSar = big.NewInt(-1)
			} else {
				wantSar = big.NewInt(0)
			}
		} else {
			wantSar = new(big.Int).Rsh(xs, n)
			if xs.Sign() < 0 {
				// big.Int's Rsh on negatives already floors, matching SAR.
				wantSar = new(big.Int).Div(xs, new(big.Int).Lsh(big.NewInt(1), n))
			}
		}
		if got := toSigned(new(Int).SRsh(x, n).ToBig()); got.Cmp(wantSar) != 0 {
			t.Fatalf("sar(%s, %d) = %s, want %s", xs, n, got, wantSar)
		}
	}
}

func TestByte(t *testing.T) {
	v := FromBig(new(big.Int).SetBytes([]byte{0xaa, 0xbb, 0xcc}))
	// Byte 31 is the least significant.
	if got := new(Int).Byte(v, NewInt(31)); got.Uint64() != 0xcc {
		t.Errorf("byte 31 = %#x, want 0xcc", got.Uint64())
	}
	if got := new(Int).Byte(v, NewInt(29)); got.Uint64() != 0xaa {
		t.Errorf("byte 29 = %#x, want 0xaa", got.Uint64())
	}
	if got := new(Int).Byte(v, NewInt(0)); !got.IsZero() {
		t.Errorf("byte 0 = %#x, want 0", got.Uint64())
	}
	// Out-of-range indices are zero, not an error.
	if got := new(Int).Byte(v, NewInt(32)); !got.IsZero() {
		t.Error("byte 32 must be zero")
	}
	if got := new(Int).Byte(v, FromBig(maxU256)); !got.IsZero() {
		t.Error("a huge index must yield zero")
	}
}

func TestSignExtend(t *testing.T) {
	cases := []struct {
		n    uint64
		x    string
		want string
	}{
		// 0xff extended from byte 0 becomes -1.
		{0, "0xff", "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"},
		// 0x7f is positive, so it is unchanged.
		{0, "0x7f", "0x7f"},
		// A larger index leaves the value alone.
		{31, "0x1234", "0x1234"},
		{1, "0xff80", "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff80"},
		{1, "0x7fff", "0x7fff"},
	}
	for _, c := range cases {
		xb, _ := new(big.Int).SetString(c.x[2:], 16)
		wantB, _ := new(big.Int).SetString(c.want[2:], 16)
		got := new(Int).SignExtend(NewInt(c.n), FromBig(xb)).ToBig()
		if got.Cmp(wantB) != 0 {
			t.Errorf("signextend(%d, %s) = %#x, want %s", c.n, c.x, got, c.want)
		}
	}
}

func TestOverflowReporting(t *testing.T) {
	max := new(Int).SetAllOnes()
	if _, overflow := new(Int).AddOverflow(max, NewInt(1)); !overflow {
		t.Error("max + 1 must report overflow")
	}
	if _, overflow := new(Int).AddOverflow(NewInt(1), NewInt(1)); overflow {
		t.Error("1 + 1 must not overflow")
	}
	if _, underflow := new(Int).SubOverflow(NewInt(0), NewInt(1)); !underflow {
		t.Error("0 - 1 must report underflow")
	}
	if _, overflow := new(Int).MulOverflow(max, NewInt(2)); !overflow {
		t.Error("max * 2 must report overflow")
	}
	if _, overflow := new(Int).MulOverflow(NewInt(1<<32), NewInt(1<<32)); overflow {
		t.Error("2^32 * 2^32 fits in 256 bits")
	}
}

func TestBitLenAndByteLen(t *testing.T) {
	cases := []struct {
		v       *Int
		bitLen  int
		byteLen int
	}{
		{NewInt(0), 0, 0},
		{NewInt(1), 1, 1},
		{NewInt(255), 8, 1},
		{NewInt(256), 9, 2},
		{new(Int).SetAllOnes(), 256, 32},
		{new(Int).Lsh(NewInt(1), 200), 201, 26},
	}
	for _, c := range cases {
		if got := c.v.BitLen(); got != c.bitLen {
			t.Errorf("BitLen(%s) = %d, want %d", c.v.Hex(), got, c.bitLen)
		}
		if got := c.v.ByteLen(); got != c.byteLen {
			t.Errorf("ByteLen(%s) = %d, want %d", c.v.Hex(), got, c.byteLen)
		}
	}
}

func TestNegativeBigIntWrapsToTwosComplement(t *testing.T) {
	got := FromBig(big.NewInt(-1))
	if !got.Eq(new(Int).SetAllOnes()) {
		t.Fatalf("-1 = %s, want all ones", got.Hex())
	}
	if !got.IsNegative() {
		t.Fatal("-1 must read as negative")
	}
}

func BenchmarkMul(b *testing.B) {
	x := new(Int).SetAllOnes()
	y := NewInt(0xdeadbeefcafebabe)
	z := new(Int)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		z.Mul(x, y)
	}
}

func BenchmarkDiv(b *testing.B) {
	x := new(Int).SetAllOnes()
	y := new(Int).Lsh(NewInt(1), 100)
	z := new(Int)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		z.Div(x, y)
	}
}
