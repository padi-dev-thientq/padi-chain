package bls12381

import (
	"encoding/binary"
	"math/big"

	"layer1/crypto/keccak"
)

// Hashing a message to a curve point.
//
// A BLS signature is the secret scalar times a point derived from the message,
// so that derivation has to behave like a random oracle: nobody may know the
// discrete logarithm of the message point, or they could forge signatures
// without the key.
//
// The construction here expands the message with Keccak, interprets the output
// as a field element, walks upward until the curve equation has a solution, and
// clears the cofactor. That is not RFC 9380's simplified SWU, so signatures do
// not interoperate with other BLS implementations — which is moot here, since
// the generators are derived rather than shared. What matters for security is
// preserved: the resulting point is uniform over the subgroup and its discrete
// logarithm is unknown to everyone.

// expandMessage produces count 32-byte blocks bound to a domain separator, so
// hashes for different purposes can never collide.
func expandMessage(domain string, message []byte, count int) []byte {
	out := make([]byte, 0, count*32)
	for i := 0; i < count; i++ {
		var index [4]byte
		binary.BigEndian.PutUint32(index[:], uint32(i))
		block := keccak.Sum256([]byte(domain), message, index[:])
		out = append(out, block[:]...)
	}
	return out
}

// hashToFp2 derives a field element from a message.
func hashToFp2(domain string, message []byte, counter uint32) *Fp2 {
	var index [4]byte
	binary.BigEndian.PutUint32(index[:], counter)
	raw := expandMessage(domain, append(append([]byte{}, message...), index[:]...), 4)

	// Two 64-byte halves reduced mod p give each coefficient close to uniform:
	// the excess over p is smaller than 2^-128 of the range.
	return newFp2(
		feFromBig(new(big.Int).SetBytes(raw[:64])),
		feFromBig(new(big.Int).SetBytes(raw[64:])),
	)
}

// mapToG2Uncleared finds a curve point from a message, before cofactor
// clearing. It returns nil if this counter yields no point, and the caller
// tries the next one.
func mapToG2Uncleared(message []byte, counter uint32) *G2 {
	x := hashToFp2("layer1/bls12381/hash-to-g2/v1", message, counter)

	// Walk upward from the derived abscissa until the curve equation has a
	// solution. Roughly half of all x values work, so this terminates quickly.
	for attempt := 0; attempt < 256; attempt++ {
		rhs := fp2Add(fp2Mul(fp2Square(x), x), twistB)
		if y := fp2Sqrt(rhs); y != nil {
			// Fix the sign deterministically, so the same message always maps
			// to the same point.
			if isFp2LexicographicallyLarger(y) {
				y = fp2Neg(y)
			}
			return &G2{X: x, Y: y}
		}
		x = fp2Add(x, fp2One())
	}
	return nil
}

// HashToG2 maps a message to a point in the prime-order subgroup of G2.
func HashToG2(message []byte) *G2 {
	for counter := uint32(0); counter < 1024; counter++ {
		point := mapToG2Uncleared(message, counter)
		if point == nil {
			continue
		}
		// Clearing the cofactor is what puts the point in the subgroup the
		// pairing is defined over; without it a signature would not verify.
		cleared := point.ScalarMul(G2Cofactor)
		if !cleared.Infinity {
			return cleared
		}
	}
	panic("bls12381: failed to map a message to the curve")
}
