// Package ripemd160 implements the RIPEMD-160 hash, which Ethereum exposes as
// the precompile at address 0x03.
//
// The design runs two independent 80-round lines over the same message and
// combines them at the end, which is what makes it structurally different from
// the MD/SHA family it otherwise resembles.
package ripemd160

import (
	"encoding/binary"
	"hash"
)

// Size is the digest length in bytes.
const Size = 20

// BlockSize is the compression block size.
const BlockSize = 64

// Initial chaining values.
var initialState = [5]uint32{
	0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0,
}

// Message word order for the left and right lines.
var (
	leftIndex = [80]uint8{
		0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
		7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
		3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12,
		1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,
		4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13,
	}
	rightIndex = [80]uint8{
		5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12,
		6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
		15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13,
		8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14,
		12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11,
	}
	leftShift = [80]uint8{
		11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8,
		7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
		11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5,
		11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
		9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6,
	}
	rightShift = [80]uint8{
		8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6,
		9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
		9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5,
		15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8,
		8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11,
	}
)

// Round constants, one per 16-round group in each line.
var (
	leftConstants  = [5]uint32{0x00000000, 0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xa953fd4e}
	rightConstants = [5]uint32{0x50a28be6, 0x5c4dd124, 0x6d703ef3, 0x7a6d76e9, 0x00000000}
)

func rotl(x uint32, n uint) uint32 { return x<<n | x>>(32-n) }

// round applies the nonlinear function for the given round group.
func round(group int, x, y, z uint32) uint32 {
	switch group {
	case 0:
		return x ^ y ^ z
	case 1:
		return (x & y) | (^x & z)
	case 2:
		return (x | ^y) ^ z
	case 3:
		return (x & z) | (y & ^z)
	default:
		return x ^ (y | ^z)
	}
}

// Digest is a streaming RIPEMD-160 state.
type Digest struct {
	state [5]uint32
	buf   [BlockSize]byte
	n     int
	total uint64
}

var _ hash.Hash = (*Digest)(nil)

// New returns a fresh digest.
func New() *Digest {
	d := new(Digest)
	d.Reset()
	return d
}

func (d *Digest) Size() int      { return Size }
func (d *Digest) BlockSize() int { return BlockSize }

func (d *Digest) Reset() {
	d.state = initialState
	d.n = 0
	d.total = 0
}

// compress processes one 64-byte block.
func (d *Digest) compress(block []byte) {
	var x [16]uint32
	for i := 0; i < 16; i++ {
		x[i] = binary.LittleEndian.Uint32(block[i*4:])
	}

	// The two lines start from the same chaining value and never interact
	// until the combination step below.
	al, bl, cl, dl, el := d.state[0], d.state[1], d.state[2], d.state[3], d.state[4]
	ar, br, cr, dr, er := al, bl, cl, dl, el

	for i := 0; i < 80; i++ {
		group := i / 16

		t := al + round(group, bl, cl, dl) + x[leftIndex[i]] + leftConstants[group]
		t = rotl(t, uint(leftShift[i])) + el
		al, bl, cl, dl, el = el, t, bl, rotl(cl, 10), dl

		t = ar + round(4-group, br, cr, dr) + x[rightIndex[i]] + rightConstants[group]
		t = rotl(t, uint(rightShift[i])) + er
		ar, br, cr, dr, er = er, t, br, rotl(cr, 10), dr
	}

	// Combine the two lines, rotating the chaining value by one word.
	t := d.state[1] + cl + dr
	d.state[1] = d.state[2] + dl + er
	d.state[2] = d.state[3] + el + ar
	d.state[3] = d.state[4] + al + br
	d.state[4] = d.state[0] + bl + cr
	d.state[0] = t
}

func (d *Digest) Write(p []byte) (int, error) {
	written := len(p)
	d.total += uint64(len(p))

	if d.n > 0 {
		fill := BlockSize - d.n
		if fill > len(p) {
			fill = len(p)
		}
		copy(d.buf[d.n:], p[:fill])
		d.n += fill
		p = p[fill:]
		if d.n == BlockSize {
			d.compress(d.buf[:])
			d.n = 0
		}
	}
	for len(p) >= BlockSize {
		d.compress(p[:BlockSize])
		p = p[BlockSize:]
	}
	if len(p) > 0 {
		copy(d.buf[:], p)
		d.n = len(p)
	}
	return written, nil
}

// Sum appends the digest to b, leaving the receiver usable.
func (d *Digest) Sum(b []byte) []byte {
	dup := *d

	// Pad with 0x80, then zeros, then the bit length little-endian.
	length := dup.total
	var padding [BlockSize * 2]byte
	padding[0] = 0x80
	padLen := BlockSize - int((length+8)%BlockSize)
	if padLen <= 0 {
		padLen += BlockSize
	}
	binary.LittleEndian.PutUint64(padding[padLen:], length<<3)
	dup.total = 0 // Write would otherwise double-count the padding
	dup.Write(padding[:padLen+8])

	var out [Size]byte
	for i, word := range dup.state {
		binary.LittleEndian.PutUint32(out[i*4:], word)
	}
	return append(b, out[:]...)
}

// Sum160 hashes data in one shot.
func Sum160(data []byte) [Size]byte {
	d := New()
	d.Write(data)
	var out [Size]byte
	copy(out[:], d.Sum(nil))
	return out
}
