// Package blake2b implements the BLAKE2b compression function F, which
// Ethereum exposes as the precompile at address 0x09.
//
// The precompile deliberately exposes the compression function rather than the
// whole hash: that lets a contract verify a BLAKE2b computation with any
// parameters, which is what interoperability with chains that use BLAKE2b
// requires.
package blake2b

import "encoding/binary"

// IV is the initialisation vector, the same constants as SHA-512.
var IV = [8]uint64{
	0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
	0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179,
}

// sigma is the message word permutation for each round.
var sigma = [10][16]uint8{
	{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
	{14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
	{11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4},
	{7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8},
	{9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13},
	{2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9},
	{12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11},
	{13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10},
	{6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5},
	{10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0},
}

func rotr(x uint64, n uint) uint64 { return x>>n | x<<(64-n) }

// mix is the G function: the quarter-round that all of BLAKE2's diffusion
// comes from.
func mix(v *[16]uint64, a, b, c, d int, x, y uint64) {
	v[a] = v[a] + v[b] + x
	v[d] = rotr(v[d]^v[a], 32)
	v[c] = v[c] + v[d]
	v[b] = rotr(v[b]^v[c], 24)
	v[a] = v[a] + v[b] + y
	v[d] = rotr(v[d]^v[a], 16)
	v[c] = v[c] + v[d]
	v[b] = rotr(v[b]^v[c], 63)
}

// F is the BLAKE2b compression function.
//
// h is the chaining state, m the message block, t the offset counters, final
// the last-block flag, and rounds the number of rounds to run. h is updated in
// place. The round count is a parameter rather than the usual 12 because the
// precompile is defined that way, and gas is charged per round.
func F(h *[8]uint64, m [16]uint64, t [2]uint64, final bool, rounds uint32) {
	var v [16]uint64
	copy(v[:8], h[:])
	copy(v[8:], IV[:])

	v[12] ^= t[0]
	v[13] ^= t[1]
	if final {
		v[14] = ^v[14]
	}

	for r := uint32(0); r < rounds; r++ {
		// The permutation cycles every ten rounds, so a caller asking for more
		// than ten simply reuses them in order.
		s := &sigma[r%10]

		mix(&v, 0, 4, 8, 12, m[s[0]], m[s[1]])
		mix(&v, 1, 5, 9, 13, m[s[2]], m[s[3]])
		mix(&v, 2, 6, 10, 14, m[s[4]], m[s[5]])
		mix(&v, 3, 7, 11, 15, m[s[6]], m[s[7]])

		mix(&v, 0, 5, 10, 15, m[s[8]], m[s[9]])
		mix(&v, 1, 6, 11, 12, m[s[10]], m[s[11]])
		mix(&v, 2, 7, 8, 13, m[s[12]], m[s[13]])
		mix(&v, 3, 4, 9, 14, m[s[14]], m[s[15]])
	}

	for i := 0; i < 8; i++ {
		h[i] ^= v[i] ^ v[i+8]
	}
}

// InputLength is the exact size of the precompile's input, as EIP-152 defines
// it: 4 bytes of round count, 64 of state, 128 of message, 16 of counters and
// one flag byte.
const InputLength = 4 + 64 + 128 + 16 + 1

// ParseInput decodes the precompile's input. Everything but the round count is
// little-endian, which is BLAKE2b's native byte order.
func ParseInput(input []byte) (rounds uint32, h [8]uint64, m [16]uint64, t [2]uint64, final bool, ok bool) {
	if len(input) != InputLength {
		return 0, h, m, t, false, false
	}
	flag := input[InputLength-1]
	// The flag byte is strictly boolean; anything else is malformed input
	// rather than a value to coerce.
	if flag != 0 && flag != 1 {
		return 0, h, m, t, false, false
	}

	rounds = binary.BigEndian.Uint32(input[:4])
	for i := 0; i < 8; i++ {
		h[i] = binary.LittleEndian.Uint64(input[4+i*8:])
	}
	for i := 0; i < 16; i++ {
		m[i] = binary.LittleEndian.Uint64(input[68+i*8:])
	}
	t[0] = binary.LittleEndian.Uint64(input[196:])
	t[1] = binary.LittleEndian.Uint64(input[204:])
	return rounds, h, m, t, flag == 1, true
}

// EncodeState renders the chaining state as the precompile's 64-byte output.
func EncodeState(h [8]uint64) []byte {
	out := make([]byte, 64)
	for i, word := range h {
		binary.LittleEndian.PutUint64(out[i*8:], word)
	}
	return out
}
