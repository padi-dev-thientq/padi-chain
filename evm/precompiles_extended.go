package evm

import (
	"errors"
	"math/big"

	"layer1/common"
	"layer1/crypto/blake2b"
	"layer1/crypto/bn254"
	"layer1/crypto/ripemd160"
)

// The precompiles beyond the original four. Between them they are what lets a
// contract verify a zk-SNARK proof, hash with algorithms the EVM does not have,
// and interoperate with chains built on BLAKE2b.

var (
	ripemd160Address = common.BytesToAddress([]byte{3})
	bn256AddAddress  = common.BytesToAddress([]byte{6})
	bn256MulAddress  = common.BytesToAddress([]byte{7})
	bn256PairAddress = common.BytesToAddress([]byte{8})
	blake2FAddress   = common.BytesToAddress([]byte{9})
)

func init() {
	precompiles[ripemd160Address] = &ripemd160Hash{}
	precompiles[bn256AddAddress] = &bn256Add{}
	precompiles[bn256MulAddress] = &bn256ScalarMul{}
	precompiles[bn256PairAddress] = &bn256Pairing{}
	precompiles[blake2FAddress] = &blake2F{}
}

// ripemd160Hash is the RIPEMD-160 precompile at 0x03.
type ripemd160Hash struct{}

func (c *ripemd160Hash) RequiredGas(input []byte) uint64 {
	return 600 + 120*toWordSize(uint64(len(input)))
}

func (c *ripemd160Hash) Run(input []byte) ([]byte, error) {
	sum := ripemd160.Sum160(input)
	// The 20-byte digest is returned left-padded to a full word.
	return common.LeftPadBytes(sum[:], 32), nil
}

// readG1 decodes a G1 point from 64 bytes of input, zero-padding a short tail.
func readG1(input []byte, offset int) (*bn254.G1, error) {
	buf := common.RightPadBytes(input, offset+64)
	x := new(big.Int).SetBytes(buf[offset : offset+32])
	y := new(big.Int).SetBytes(buf[offset+32 : offset+64])
	return bn254.NewG1(x, y)
}

// writeG1 encodes a G1 point as two 32-byte words.
func writeG1(p *bn254.G1) []byte {
	out := make([]byte, 64)
	if p.Infinity {
		// Infinity is encoded as (0, 0), which is what a caller must be able
		// to feed straight back in.
		return out
	}
	p.X.FillBytes(out[:32])
	p.Y.FillBytes(out[32:])
	return out
}

// bn256Add is the BN254 point addition precompile at 0x06.
type bn256Add struct{}

func (c *bn256Add) RequiredGas(input []byte) uint64 { return 150 }

func (c *bn256Add) Run(input []byte) ([]byte, error) {
	a, err := readG1(input, 0)
	if err != nil {
		return nil, err
	}
	b, err := readG1(input, 64)
	if err != nil {
		return nil, err
	}
	return writeG1(a.Add(b)), nil
}

// bn256ScalarMul is the BN254 scalar multiplication precompile at 0x07.
type bn256ScalarMul struct{}

func (c *bn256ScalarMul) RequiredGas(input []byte) uint64 { return 6000 }

func (c *bn256ScalarMul) Run(input []byte) ([]byte, error) {
	p, err := readG1(input, 0)
	if err != nil {
		return nil, err
	}
	buf := common.RightPadBytes(input, 96)
	k := new(big.Int).SetBytes(buf[64:96])
	return writeG1(p.ScalarMul(k)), nil
}

// pairSize is the encoded length of one pairing term: a G1 point and a G2 point.
const pairSize = 192

var errBadPairingInput = errors.New("evm: bn256 pairing input is not a whole number of pairs")

// bn256Pairing is the BN254 pairing check precompile at 0x08.
type bn256Pairing struct{}

func (c *bn256Pairing) RequiredGas(input []byte) uint64 {
	// A fixed cost plus a charge per pair: the Miller loop runs once per pair,
	// the final exponentiation only once overall.
	return 45000 + 34000*uint64(len(input)/pairSize)
}

func (c *bn256Pairing) Run(input []byte) ([]byte, error) {
	if len(input)%pairSize != 0 {
		return nil, errBadPairingInput
	}

	pairs := make([]bn254.Pair, 0, len(input)/pairSize)
	for offset := 0; offset < len(input); offset += pairSize {
		chunk := input[offset : offset+pairSize]

		g1, err := readG1(chunk, 0)
		if err != nil {
			return nil, err
		}
		// EIP-197 encodes an Fp2 element with the imaginary part first, so
		// each coordinate arrives as (c1, c0).
		x1 := new(big.Int).SetBytes(chunk[64:96])
		x0 := new(big.Int).SetBytes(chunk[96:128])
		y1 := new(big.Int).SetBytes(chunk[128:160])
		y0 := new(big.Int).SetBytes(chunk[160:192])

		g2, err := bn254.NewG2(x0, x1, y0, y1)
		if err != nil {
			return nil, err
		}
		pairs = append(pairs, bn254.Pair{G1: g1, G2: g2})
	}

	out := make([]byte, 32)
	if bn254.PairingCheck(pairs) {
		out[31] = 1
	}
	return out, nil
}

// blake2F is the BLAKE2b compression precompile at 0x09.
type blake2F struct{}

func (c *blake2F) RequiredGas(input []byte) uint64 {
	// Charged strictly per round, which is the only thing that varies.
	if len(input) != blake2b.InputLength {
		return 0
	}
	rounds := uint64(input[0])<<24 | uint64(input[1])<<16 | uint64(input[2])<<8 | uint64(input[3])
	return rounds
}

var errBadBlake2Input = errors.New("evm: blake2f input is malformed")

func (c *blake2F) Run(input []byte) ([]byte, error) {
	rounds, h, m, t, final, ok := blake2b.ParseInput(input)
	if !ok {
		return nil, errBadBlake2Input
	}
	blake2b.F(&h, m, t, final, rounds)
	return blake2b.EncodeState(h), nil
}
