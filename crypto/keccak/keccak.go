// Package keccak implements Keccak-256 with the original padding rule used by
// Ethereum (0x01 domain byte), which differs from NIST SHA3-256 (0x06).
package keccak

import "hash"

const (
	rounds = 24
	rate   = 136 // bytes absorbed per permutation for a 256-bit output
	Size   = 32
)

var roundConstants = [rounds]uint64{
	0x0000000000000001, 0x0000000000008082, 0x800000000000808a, 0x8000000080008000,
	0x000000000000808b, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
	0x000000000000008a, 0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
	0x000000008000808b, 0x800000000000008b, 0x8000000000008089, 0x8000000000008003,
	0x8000000000008002, 0x8000000000000080, 0x000000000000800a, 0x800000008000000a,
	0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
}

var rotationOffsets = [24]uint{
	1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44,
}

var piLane = [24]int{
	10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1,
}

func rotl(x uint64, n uint) uint64 { return x<<n | x>>(64-n) }

// permute applies the Keccak-f[1600] permutation in place.
func permute(a *[25]uint64) {
	for r := 0; r < rounds; r++ {
		// Theta
		var c [5]uint64
		for x := 0; x < 5; x++ {
			c[x] = a[x] ^ a[x+5] ^ a[x+10] ^ a[x+15] ^ a[x+20]
		}
		for x := 0; x < 5; x++ {
			d := c[(x+4)%5] ^ rotl(c[(x+1)%5], 1)
			for y := 0; y < 5; y++ {
				a[x+y*5] ^= d
			}
		}
		// Rho and Pi
		last := a[1]
		for i := 0; i < 24; i++ {
			j := piLane[i]
			tmp := a[j]
			a[j] = rotl(last, rotationOffsets[i])
			last = tmp
		}
		// Chi
		for y := 0; y < 5; y++ {
			var row [5]uint64
			copy(row[:], a[y*5:y*5+5])
			for x := 0; x < 5; x++ {
				a[y*5+x] = row[x] ^ (^row[(x+1)%5] & row[(x+2)%5])
			}
		}
		// Iota
		a[0] ^= roundConstants[r]
	}
}

// Digest is a streaming Keccak-256 state implementing hash.Hash.
type Digest struct {
	state [25]uint64
	buf   [rate]byte
	n     int
}

var _ hash.Hash = (*Digest)(nil)

// New returns a fresh Keccak-256 digest.
func New() *Digest { return &Digest{} }

func (d *Digest) Size() int      { return Size }
func (d *Digest) BlockSize() int { return rate }

func (d *Digest) Reset() {
	d.state = [25]uint64{}
	d.buf = [rate]byte{}
	d.n = 0
}

func (d *Digest) absorbBlock() {
	for i := 0; i < rate/8; i++ {
		var w uint64
		for j := 0; j < 8; j++ {
			w |= uint64(d.buf[i*8+j]) << (8 * uint(j)) // little-endian lane
		}
		d.state[i] ^= w
	}
	permute(&d.state)
}

func (d *Digest) Write(p []byte) (int, error) {
	written := len(p)
	for len(p) > 0 {
		take := rate - d.n
		if take > len(p) {
			take = len(p)
		}
		copy(d.buf[d.n:], p[:take])
		d.n += take
		p = p[take:]
		if d.n == rate {
			d.absorbBlock()
			d.n = 0
		}
	}
	return written, nil
}

// Sum appends the digest to b. The receiver's state is not modified, so a
// Digest may keep being written to after Sum.
func (d *Digest) Sum(b []byte) []byte {
	dup := *d
	// Keccak pad10*1 with Ethereum's 0x01 domain separator.
	for i := dup.n; i < rate; i++ {
		dup.buf[i] = 0
	}
	dup.buf[dup.n] = 0x01
	dup.buf[rate-1] |= 0x80
	dup.absorbBlock()

	var out [Size]byte
	for i := 0; i < Size/8; i++ {
		w := dup.state[i]
		for j := 0; j < 8; j++ {
			out[i*8+j] = byte(w >> (8 * uint(j)))
		}
	}
	return append(b, out[:]...)
}

// Sum256 hashes data in one shot.
func Sum256(data ...[]byte) [32]byte {
	d := New()
	for _, part := range data {
		d.Write(part)
	}
	var out [32]byte
	copy(out[:], d.Sum(nil))
	return out
}

// Sum256Bytes is Sum256 returning a slice, for callers that need one.
func Sum256Bytes(data ...[]byte) []byte {
	h := Sum256(data...)
	return h[:]
}
