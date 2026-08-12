// Package uint256 provides the fixed-width 256-bit unsigned integer the EVM
// operates on.
//
// Every arithmetic operation wraps modulo 2^256 and division by zero yields
// zero, which is what the EVM specifies — using arbitrary-precision integers
// instead would require masking after every step and would still get the
// signed operations subtly wrong.
package uint256

import (
	"math/big"
	"math/bits"
)

// Int is a 256-bit unsigned integer stored as four 64-bit limbs, least
// significant first.
type Int [4]uint64

var (
	zero = Int{}
	one  = Int{1}
)

// NewInt returns v as an Int.
func NewInt(v uint64) *Int { return &Int{v} }

// Zero returns a new zero value.
func Zero() *Int { return new(Int) }

// Clear sets z to zero and returns it.
func (z *Int) Clear() *Int {
	z[0], z[1], z[2], z[3] = 0, 0, 0, 0
	return z
}

// Set sets z to x and returns z.
func (z *Int) Set(x *Int) *Int {
	*z = *x
	return z
}

// SetUint64 sets z to v.
func (z *Int) SetUint64(v uint64) *Int {
	z[0], z[1], z[2], z[3] = v, 0, 0, 0
	return z
}

// SetOne sets z to one.
func (z *Int) SetOne() *Int { return z.SetUint64(1) }

// Clone returns a copy of z.
func (z *Int) Clone() *Int {
	out := *z
	return &out
}

// IsZero reports whether z is zero.
func (z *Int) IsZero() bool { return z[0]|z[1]|z[2]|z[3] == 0 }

// Uint64 returns the low 64 bits.
func (z *Int) Uint64() uint64 { return z[0] }

// IsUint64 reports whether z fits in 64 bits.
func (z *Int) IsUint64() bool { return z[1]|z[2]|z[3] == 0 }

// Uint64WithOverflow returns the low 64 bits and whether anything was lost.
func (z *Int) Uint64WithOverflow() (uint64, bool) { return z[0], !z.IsUint64() }

// SetBytes interprets b as a big-endian integer, taking the low 32 bytes.
func (z *Int) SetBytes(b []byte) *Int {
	z.Clear()
	if len(b) > 32 {
		b = b[len(b)-32:]
	}
	for i, c := range b {
		// Position from the right determines the limb and the shift.
		pos := len(b) - 1 - i
		z[pos/8] |= uint64(c) << (8 * uint(pos%8))
	}
	return z
}

// Bytes32 returns the big-endian 32-byte encoding.
func (z *Int) Bytes32() [32]byte {
	var out [32]byte
	for i := 0; i < 4; i++ {
		limb := z[i]
		base := 24 - i*8
		for j := 0; j < 8; j++ {
			out[base+7-j] = byte(limb >> (8 * uint(j)))
		}
	}
	return out
}

// Bytes returns the big-endian encoding with leading zeros stripped.
func (z *Int) Bytes() []byte {
	full := z.Bytes32()
	i := 0
	for i < 32 && full[i] == 0 {
		i++
	}
	return full[i:]
}

// ByteLen returns the minimum number of bytes needed to represent z.
func (z *Int) ByteLen() int { return (z.BitLen() + 7) / 8 }

// BitLen returns the position of the highest set bit.
func (z *Int) BitLen() int {
	switch {
	case z[3] != 0:
		return 192 + bits.Len64(z[3])
	case z[2] != 0:
		return 128 + bits.Len64(z[2])
	case z[1] != 0:
		return 64 + bits.Len64(z[1])
	default:
		return bits.Len64(z[0])
	}
}

// Bit returns bit i of z.
func (z *Int) Bit(i int) uint64 {
	if i < 0 || i >= 256 {
		return 0
	}
	return (z[i/64] >> uint(i%64)) & 1
}

// Sign reports whether z is zero (0) or positive (1); an Int is never negative.
func (z *Int) Sign() int {
	if z.IsZero() {
		return 0
	}
	return 1
}

// SetBig sets z to v truncated to 256 bits.
func (z *Int) SetBig(v *big.Int) *Int {
	if v == nil {
		return z.Clear()
	}
	if v.Sign() < 0 {
		// Two's-complement wrap for negative inputs.
		abs := new(big.Int).Neg(v)
		z.SetBytes(abs.Bytes())
		return z.Neg(z)
	}
	return z.SetBytes(v.Bytes())
}

// ToBig returns z as a big.Int.
func (z *Int) ToBig() *big.Int {
	b := z.Bytes32()
	return new(big.Int).SetBytes(b[:])
}

// FromBig returns v truncated to 256 bits.
func FromBig(v *big.Int) *Int { return new(Int).SetBig(v) }

// Cmp compares z and x: -1, 0 or 1.
func (z *Int) Cmp(x *Int) int {
	for i := 3; i >= 0; i-- {
		if z[i] != x[i] {
			if z[i] < x[i] {
				return -1
			}
			return 1
		}
	}
	return 0
}

// Eq reports whether z == x.
func (z *Int) Eq(x *Int) bool { return *z == *x }

// Lt reports whether z < x.
func (z *Int) Lt(x *Int) bool { return z.Cmp(x) < 0 }

// Gt reports whether z > x.
func (z *Int) Gt(x *Int) bool { return z.Cmp(x) > 0 }

// SLt compares z and x as signed two's-complement values.
func (z *Int) SLt(x *Int) bool {
	zNeg, xNeg := z.IsNegative(), x.IsNegative()
	switch {
	case zNeg && !xNeg:
		return true
	case !zNeg && xNeg:
		return false
	default:
		return z.Lt(x)
	}
}

// SGt is the signed greater-than comparison.
func (z *Int) SGt(x *Int) bool {
	zNeg, xNeg := z.IsNegative(), x.IsNegative()
	switch {
	case zNeg && !xNeg:
		return false
	case !zNeg && xNeg:
		return true
	default:
		return z.Gt(x)
	}
}

// IsNegative reports whether the top bit is set, i.e. z is negative when read
// as a signed value.
func (z *Int) IsNegative() bool { return z[3]&0x8000000000000000 != 0 }

// Add sets z = x + y (mod 2^256) and returns z.
func (z *Int) Add(x, y *Int) *Int {
	var carry uint64
	z[0], carry = bits.Add64(x[0], y[0], 0)
	z[1], carry = bits.Add64(x[1], y[1], carry)
	z[2], carry = bits.Add64(x[2], y[2], carry)
	z[3], _ = bits.Add64(x[3], y[3], carry)
	return z
}

// AddOverflow sets z = x + y and reports whether it wrapped.
func (z *Int) AddOverflow(x, y *Int) (*Int, bool) {
	var carry uint64
	z[0], carry = bits.Add64(x[0], y[0], 0)
	z[1], carry = bits.Add64(x[1], y[1], carry)
	z[2], carry = bits.Add64(x[2], y[2], carry)
	z[3], carry = bits.Add64(x[3], y[3], carry)
	return z, carry != 0
}

// Sub sets z = x - y (mod 2^256).
func (z *Int) Sub(x, y *Int) *Int {
	var borrow uint64
	z[0], borrow = bits.Sub64(x[0], y[0], 0)
	z[1], borrow = bits.Sub64(x[1], y[1], borrow)
	z[2], borrow = bits.Sub64(x[2], y[2], borrow)
	z[3], _ = bits.Sub64(x[3], y[3], borrow)
	return z
}

// SubOverflow sets z = x - y and reports whether it underflowed.
func (z *Int) SubOverflow(x, y *Int) (*Int, bool) {
	var borrow uint64
	z[0], borrow = bits.Sub64(x[0], y[0], 0)
	z[1], borrow = bits.Sub64(x[1], y[1], borrow)
	z[2], borrow = bits.Sub64(x[2], y[2], borrow)
	z[3], borrow = bits.Sub64(x[3], y[3], borrow)
	return z, borrow != 0
}

// Neg sets z to the two's-complement negation of x.
func (z *Int) Neg(x *Int) *Int {
	return z.Sub(&zero, x)
}

// Not sets z to the bitwise complement of x.
func (z *Int) Not(x *Int) *Int {
	z[0], z[1], z[2], z[3] = ^x[0], ^x[1], ^x[2], ^x[3]
	return z
}

// And sets z = x & y.
func (z *Int) And(x, y *Int) *Int {
	z[0], z[1], z[2], z[3] = x[0]&y[0], x[1]&y[1], x[2]&y[2], x[3]&y[3]
	return z
}

// Or sets z = x | y.
func (z *Int) Or(x, y *Int) *Int {
	z[0], z[1], z[2], z[3] = x[0]|y[0], x[1]|y[1], x[2]|y[2], x[3]|y[3]
	return z
}

// Xor sets z = x ^ y.
func (z *Int) Xor(x, y *Int) *Int {
	z[0], z[1], z[2], z[3] = x[0]^y[0], x[1]^y[1], x[2]^y[2], x[3]^y[3]
	return z
}

// umul returns the full 512-bit product of x and y as eight limbs.
func umul(x, y *Int) [8]uint64 {
	var out [8]uint64
	for i := 0; i < 4; i++ {
		var carry uint64
		for j := 0; j < 4; j++ {
			hi, lo := bits.Mul64(x[i], y[j])
			// Accumulate lo into position i+j, hi into i+j+1, carrying upward.
			var c uint64
			out[i+j], c = bits.Add64(out[i+j], lo, 0)
			hi, _ = bits.Add64(hi, 0, c)
			out[i+j+1], c = bits.Add64(out[i+j+1], hi, 0)
			carryPos := i + j + 2
			for c != 0 && carryPos < 8 {
				out[carryPos], c = bits.Add64(out[carryPos], 0, c)
				carryPos++
			}
			_ = carry
		}
	}
	return out
}

// Mul sets z = x * y (mod 2^256).
func (z *Int) Mul(x, y *Int) *Int {
	p := umul(x, y)
	z[0], z[1], z[2], z[3] = p[0], p[1], p[2], p[3]
	return z
}

// MulOverflow sets z = x * y and reports whether the true product exceeded
// 256 bits.
func (z *Int) MulOverflow(x, y *Int) (*Int, bool) {
	p := umul(x, y)
	overflow := p[4]|p[5]|p[6]|p[7] != 0
	z[0], z[1], z[2], z[3] = p[0], p[1], p[2], p[3]
	return z, overflow
}

// Div sets z = x / y, or zero when y is zero.
func (z *Int) Div(x, y *Int) *Int {
	q, _ := divMod(x, y)
	return z.Set(q)
}

// Mod sets z = x % y, or zero when y is zero.
func (z *Int) Mod(x, y *Int) *Int {
	_, r := divMod(x, y)
	return z.Set(r)
}

// DivMod sets z = x / y and m = x % y, returning both.
func (z *Int) DivMod(x, y, m *Int) (*Int, *Int) {
	q, r := divMod(x, y)
	z.Set(q)
	m.Set(r)
	return z, m
}

func divMod(x, y *Int) (*Int, *Int) {
	if y.IsZero() {
		// The EVM defines division by zero as zero rather than a fault.
		return new(Int), new(Int)
	}
	if x.Cmp(y) < 0 {
		return new(Int), x.Clone()
	}
	if y.IsUint64() {
		// Single-limb divisor: one pass of long division over the limbs.
		d := y[0]
		var q Int
		var rem uint64
		for i := 3; i >= 0; i-- {
			q[i], rem = bits.Div64(rem, x[i], d)
		}
		return &q, &Int{rem}
	}
	// General case: shift-and-subtract, one bit at a time.
	var q, rem Int
	for i := x.BitLen() - 1; i >= 0; i-- {
		// The remainder always stays below the divisor, which is at least
		// 2^64 here, so shifting it left can never lose a bit.
		rem.Lsh(&rem, 1)
		rem[0] |= x.Bit(i)
		if rem.Cmp(y) >= 0 {
			rem.Sub(&rem, y)
			q[i/64] |= 1 << uint(i%64)
		}
	}
	return &q, &rem
}

// SDiv sets z to the signed quotient of x and y, truncating toward zero.
func (z *Int) SDiv(x, y *Int) *Int {
	if y.IsZero() {
		return z.Clear()
	}
	negative := x.IsNegative() != y.IsNegative()
	xa, ya := absOf(x), absOf(y)
	q, _ := divMod(xa, ya)
	if negative {
		return z.Neg(q)
	}
	return z.Set(q)
}

// SMod sets z to the signed remainder, whose sign follows the dividend.
func (z *Int) SMod(x, y *Int) *Int {
	if y.IsZero() {
		return z.Clear()
	}
	negative := x.IsNegative()
	xa, ya := absOf(x), absOf(y)
	_, r := divMod(xa, ya)
	if negative {
		return z.Neg(r)
	}
	return z.Set(r)
}

func absOf(x *Int) *Int {
	if x.IsNegative() {
		return new(Int).Neg(x)
	}
	return x.Clone()
}

// AddMod sets z = (x + y) mod m.
func (z *Int) AddMod(x, y, m *Int) *Int {
	if m.IsZero() {
		return z.Clear()
	}
	xr := new(Int).Mod(x, m)
	yr := new(Int).Mod(y, m)
	sum, overflow := new(Int).AddOverflow(xr, yr)
	// Both operands are already reduced, so the true sum is below 2m and a
	// single subtraction brings it back into range.
	if overflow || sum.Cmp(m) >= 0 {
		sum.Sub(sum, m)
	}
	return z.Set(sum)
}

// MulMod sets z = (x * y) mod m, computed on the full 512-bit product.
func (z *Int) MulMod(x, y, m *Int) *Int {
	if m.IsZero() {
		return z.Clear()
	}
	p := umul(x, y)
	// Reduce the 512-bit product bit by bit, which needs no wider arithmetic.
	var rem Int
	for i := 511; i >= 0; i-- {
		top := rem[3]&0x8000000000000000 != 0
		rem.Lsh(&rem, 1)
		rem[0] |= (p[i/64] >> uint(i%64)) & 1
		if top || rem.Cmp(m) >= 0 {
			rem.Sub(&rem, m)
		}
	}
	return z.Set(&rem)
}

// Exp sets z = base^exponent (mod 2^256) by square-and-multiply.
func (z *Int) Exp(base, exponent *Int) *Int {
	result := new(Int).SetOne()
	b := base.Clone()
	for i := 0; i < exponent.BitLen(); i++ {
		if exponent.Bit(i) == 1 {
			result.Mul(result, b)
		}
		b.Mul(b, b)
	}
	return z.Set(result)
}

// Lsh sets z = x << n.
func (z *Int) Lsh(x *Int, n uint) *Int {
	if n >= 256 {
		return z.Clear()
	}
	limbShift := n / 64
	bitShift := n % 64
	var out Int
	for i := 3; i >= int(limbShift); i-- {
		src := i - int(limbShift)
		v := x[src] << bitShift
		if bitShift > 0 && src > 0 {
			v |= x[src-1] >> (64 - bitShift)
		}
		out[i] = v
	}
	return z.Set(&out)
}

// Rsh sets z = x >> n.
func (z *Int) Rsh(x *Int, n uint) *Int {
	if n >= 256 {
		return z.Clear()
	}
	limbShift := n / 64
	bitShift := n % 64
	var out Int
	for i := 0; i+int(limbShift) < 4; i++ {
		src := i + int(limbShift)
		v := x[src] >> bitShift
		if bitShift > 0 && src+1 < 4 {
			v |= x[src+1] << (64 - bitShift)
		}
		out[i] = v
	}
	return z.Set(&out)
}

// SRsh sets z to the arithmetic (sign-propagating) right shift of x by n.
func (z *Int) SRsh(x *Int, n uint) *Int {
	negative := x.IsNegative()
	if n >= 256 {
		if negative {
			return z.SetAllOnes()
		}
		return z.Clear()
	}
	z.Rsh(x, n)
	if negative && n > 0 {
		// Fill the vacated high bits with ones.
		mask := new(Int).SetAllOnes()
		mask.Lsh(mask, 256-n)
		z.Or(z, mask)
	}
	return z
}

// SetAllOnes sets z to 2^256 - 1.
func (z *Int) SetAllOnes() *Int {
	z[0], z[1], z[2], z[3] = ^uint64(0), ^uint64(0), ^uint64(0), ^uint64(0)
	return z
}

// Byte sets z to the n-th byte of x counting from the most significant, or
// zero when n is 32 or more. This is the EVM's BYTE opcode.
func (z *Int) Byte(x *Int, n *Int) *Int {
	if !n.IsUint64() || n[0] >= 32 {
		return z.Clear()
	}
	b := x.Bytes32()
	return z.SetUint64(uint64(b[n[0]]))
}

// SignExtend sets z to x sign-extended from the byte at index n, treating that
// byte's top bit as the sign. This is the EVM's SIGNEXTEND opcode.
func (z *Int) SignExtend(n, x *Int) *Int {
	if !n.IsUint64() || n[0] >= 31 {
		return z.Set(x)
	}
	// Bit position of the sign within the value.
	signBit := uint(n[0])*8 + 7
	mask := new(Int).SetAllOnes()
	mask.Lsh(mask, signBit+1)

	if x.Bit(int(signBit)) == 1 {
		return z.Or(x, mask)
	}
	return z.And(x, mask.Not(mask))
}

// String renders z in decimal.
func (z *Int) String() string { return z.ToBig().String() }

// Hex renders z in minimal 0x-prefixed hex form.
func (z *Int) Hex() string {
	if z.IsZero() {
		return "0x0"
	}
	return "0x" + z.ToBig().Text(16)
}
