package core

import (
	"math/big"

	"layer1/common"
)

// BloomByteLength is the size of a block's log bloom filter.
const BloomByteLength = 256

// BloomBitLength is the filter's width in bits.
const BloomBitLength = BloomByteLength * 8

// Bloom is the 2048-bit filter over log addresses and topics. It lets a light
// client rule out blocks that cannot contain a log of interest, at the cost of
// occasional false positives.
type Bloom [BloomByteLength]byte

// Add sets the three bits derived from d.
func (b *Bloom) Add(d []byte) {
	i1, v1, i2, v2, i3, v3 := bloomPositions(d)
	b[i1] |= v1
	b[i2] |= v2
	b[i3] |= v3
}

// Or merges another filter into b.
func (b *Bloom) Or(other *Bloom) {
	for i := range b {
		b[i] |= other[i]
	}
}

// Test reports whether d may have been added. A false result is definitive; a
// true result may be a false positive.
func (b *Bloom) Test(d []byte) bool {
	i1, v1, i2, v2, i3, v3 := bloomPositions(d)
	return v1 == b[i1]&v1 && v2 == b[i2]&v2 && v3 == b[i3]&v3
}

func (b Bloom) Big() *big.Int { return new(big.Int).SetBytes(b[:]) }
func (b Bloom) Bytes() []byte { return b[:] }
func (b Bloom) Hex() string   { return common.EncodeHex(b[:]) }
func (b Bloom) IsZero() bool  { return b == Bloom{} }

// bloomPositions derives three (byte index, bit mask) pairs from the low six
// bytes of keccak256(d): each pair of hash bytes selects one of the 2048 bits.
func bloomPositions(d []byte) (i1 uint, v1 byte, i2 uint, v2 byte, i3 uint, v3 byte) {
	h := common.Keccak256(d)
	pos := func(off int) (uint, byte) {
		bit := (uint(h[off])<<8 | uint(h[off+1])) & 0x7ff
		// Bit 0 lives in the last byte: the filter is big-endian throughout.
		return BloomByteLength - 1 - bit/8, byte(1 << (bit % 8))
	}
	i1, v1 = pos(0)
	i2, v2 = pos(2)
	i3, v3 = pos(4)
	return
}

// CreateBloom builds the filter covering a receipt's logs.
func CreateBloom(r *Receipt) Bloom {
	var out Bloom
	for _, log := range r.Logs {
		out.Add(log.Address[:])
		for _, topic := range log.Topics {
			out.Add(topic[:])
		}
	}
	return out
}

// CreateBloomFromReceipts builds the filter for a whole block.
func CreateBloomFromReceipts(receipts Receipts) Bloom {
	var out Bloom
	for _, r := range receipts {
		for _, log := range r.Logs {
			out.Add(log.Address[:])
			for _, topic := range log.Topics {
				out.Add(topic[:])
			}
		}
	}
	return out
}

// BloomLookup reports whether a filter may contain the given topic or address.
func BloomLookup(b Bloom, topic []byte) bool { return b.Test(topic) }
