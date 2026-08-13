package bls12381

import (
	"math/big"
	"math/bits"
)

// Montgomery arithmetic over the base field.
//
// A 381-bit modular multiplication done with arbitrary-precision integers
// spends almost all of its time in the reduction, because reducing means
// dividing. Montgomery's trick replaces the division with a multiply and a
// shift: values are held as aR mod p for a fixed R, and the product of two such
// values reduces by multiplying by a precomputed constant instead.
//
// Everything above this file — the extension tower, the curves, the pairing —
// is written against these operations, so the representation change is confined
// here. The property that makes that safe is that Montgomery form is closed
// under addition and multiplication and agrees with ordinary arithmetic on
// comparisons with zero.

// limbs is the number of 64-bit words in a field element: 381 bits rounds up
// to six.
const limbs = 6

// fe is a field element in Montgomery form, least significant limb first.
type fe [limbs]uint64

// Field constants, all derived from p rather than transcribed.
var (
	// modulus is p in limb form.
	modulus = splitLimbs(P)
	// n0 is -p^-1 mod 2^64, the constant that makes the reduction work.
	n0 = computeN0()
	// r2 is R^2 mod p, which converts a plain value into Montgomery form:
	// montMul(x, r2) = x*R^2*R^-1 = xR.
	r2 = toLimbs(func() *big.Int {
		r := new(big.Int).Lsh(bigOne, 64*limbs)
		r.Mod(r, P)
		r.Mul(r, r)
		return r.Mod(r, P)
	}())
	// feOne is 1 in Montgomery form, which is R mod p.
	feOne = toLimbs(func() *big.Int {
		r := new(big.Int).Lsh(bigOne, 64*limbs)
		return r.Mod(r, P)
	}())
	feZero = fe{}
)

// toLimbs reduces a value and splits it into limbs, without converting to
// Montgomery form.
func toLimbs(v *big.Int) fe { return splitLimbs(new(big.Int).Mod(v, P)) }

// splitLimbs splits a value into limbs as it stands.
//
// The modulus itself has to go through this rather than toLimbs: reducing p
// modulo p gives zero, and a zero modulus makes every Montgomery reduction
// silently return zero — which still round-trips, so conversions look correct
// and only a comparison against an independently derived value catches it.
func splitLimbs(v *big.Int) fe {
	var out fe
	buf := make([]byte, limbs*8)
	v.FillBytes(buf)
	for i := 0; i < limbs; i++ {
		// FillBytes writes big-endian; limbs are little-endian.
		start := len(buf) - (i+1)*8
		out[i] = uint64(buf[start])<<56 | uint64(buf[start+1])<<48 |
			uint64(buf[start+2])<<40 | uint64(buf[start+3])<<32 |
			uint64(buf[start+4])<<24 | uint64(buf[start+5])<<16 |
			uint64(buf[start+6])<<8 | uint64(buf[start+7])
	}
	return out
}

// toBig reassembles limbs into a big.Int, without leaving Montgomery form.
func (a *fe) toBig() *big.Int {
	buf := make([]byte, limbs*8)
	for i := 0; i < limbs; i++ {
		start := len(buf) - (i+1)*8
		v := a[i]
		buf[start] = byte(v >> 56)
		buf[start+1] = byte(v >> 48)
		buf[start+2] = byte(v >> 40)
		buf[start+3] = byte(v >> 32)
		buf[start+4] = byte(v >> 24)
		buf[start+5] = byte(v >> 16)
		buf[start+6] = byte(v >> 8)
		buf[start+7] = byte(v)
	}
	return new(big.Int).SetBytes(buf)
}

// computeN0 finds -p^-1 mod 2^64 by Newton iteration: each step doubles the
// number of correct bits, so six steps cover 64.
func computeN0() uint64 {
	// splitLimbs, not toLimbs: reducing the modulus by itself gives zero.
	p0 := splitLimbs(P)[0]
	inv := uint64(1)
	for i := 0; i < 6; i++ {
		inv *= 2 - p0*inv
	}
	return -inv
}

// feFromBig converts an ordinary integer into Montgomery form.
func feFromBig(v *big.Int) fe {
	limbs := toLimbs(v)
	return montMul(&limbs, &r2)
}

// feFromUint64 converts a small integer into Montgomery form.
func feFromUint64(v uint64) fe {
	return feFromBig(new(big.Int).SetUint64(v))
}

// Big converts back to an ordinary integer.
func (a fe) Big() *big.Int {
	one := fe{1}
	out := montMul(&a, &one)
	return out.toBig()
}

// IsZero reports whether the element is zero. Montgomery form maps zero to
// zero, so this needs no conversion.
func (a *fe) IsZero() bool {
	for _, limb := range a {
		if limb != 0 {
			return false
		}
	}
	return true
}

// Equal compares two elements.
func (a *fe) Equal(b *fe) bool { return *a == *b }

// montMul multiplies two Montgomery-form elements, using the coarsely
// integrated operand scanning form: each pass folds one limb of the multiplier
// in and immediately reduces, so no intermediate ever exceeds limbs+2 words.
func montMul(a, b *fe) fe {
	var t [limbs + 2]uint64

	for i := 0; i < limbs; i++ {
		// t += a[j]*b[i], accumulating the carry across the row.
		var carry uint64
		for j := 0; j < limbs; j++ {
			hi, lo := bits.Mul64(a[j], b[i])
			var c uint64
			lo, c = bits.Add64(lo, carry, 0)
			hi += c
			t[j], c = bits.Add64(t[j], lo, 0)
			carry = hi + c
		}
		var c uint64
		t[limbs], c = bits.Add64(t[limbs], carry, 0)
		t[limbs+1] = c

		// Choose m so that t + m*p is divisible by 2^64, then shift it down.
		// That division is the whole point: it is a shift, not a division.
		m := t[0] * n0
		hi, lo := bits.Mul64(m, modulus[0])
		_, c = bits.Add64(t[0], lo, 0)
		carry = hi + c

		for j := 1; j < limbs; j++ {
			hi, lo := bits.Mul64(m, modulus[j])
			lo, c = bits.Add64(lo, carry, 0)
			hi += c
			t[j-1], c = bits.Add64(t[j], lo, 0)
			carry = hi + c
		}
		t[limbs-1], c = bits.Add64(t[limbs], carry, 0)
		t[limbs] = t[limbs+1] + c
	}

	var out fe
	copy(out[:], t[:limbs])
	// The result is below 2p, so at most one subtraction brings it into range.
	if t[limbs] != 0 || !lessThanModulus(&out) {
		out = subModulus(&out)
	}
	return out
}

// lessThanModulus reports whether a < p.
func lessThanModulus(a *fe) bool {
	for i := limbs - 1; i >= 0; i-- {
		if a[i] != modulus[i] {
			return a[i] < modulus[i]
		}
	}
	return false
}

// subModulus returns a - p, wrapping.
func subModulus(a *fe) fe {
	var out fe
	var borrow uint64
	for i := 0; i < limbs; i++ {
		out[i], borrow = bits.Sub64(a[i], modulus[i], borrow)
	}
	return out
}

// montAdd adds two field elements.
func montAdd(a, b *fe) fe {
	var out fe
	var carry uint64
	for i := 0; i < limbs; i++ {
		out[i], carry = bits.Add64(a[i], b[i], carry)
	}
	// Both inputs are below p, so the sum is below 2p.
	if carry != 0 || !lessThanModulus(&out) {
		out = subModulus(&out)
	}
	return out
}

// montSub subtracts two field elements.
func montSub(a, b *fe) fe {
	var out fe
	var borrow uint64
	for i := 0; i < limbs; i++ {
		out[i], borrow = bits.Sub64(a[i], b[i], borrow)
	}
	if borrow != 0 {
		var carry uint64
		for i := 0; i < limbs; i++ {
			out[i], carry = bits.Add64(out[i], modulus[i], carry)
		}
	}
	return out
}

// montNeg returns -a, which is p - a rather than a - p: the two differ by 2p,
// and only the first is in range.
func montNeg(a *fe) fe {
	if a.IsZero() {
		return feZero
	}
	var out fe
	var borrow uint64
	for i := 0; i < limbs; i++ {
		out[i], borrow = bits.Sub64(modulus[i], a[i], borrow)
	}
	return out
}

// montSquare squares an element.
func montSquare(a *fe) fe { return montMul(a, a) }

// montInv inverts an element.
//
// Fermat's little theorem would work but costs nearly six hundred
// multiplications; the extended Euclidean algorithm is an order of magnitude
// faster even with the conversions in and out. Inversions are rare enough that
// the conversion overhead does not matter.
func montInv(a *fe) fe {
	if a.IsZero() {
		return feZero
	}
	inv := new(big.Int).ModInverse(a.Big(), P)
	if inv == nil {
		return feZero
	}
	return feFromBig(inv)
}
