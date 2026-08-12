package evm

import (
	"crypto/sha256"
	"errors"
	"math/big"

	"layer1/common"
	"layer1/crypto/secp256k1"
)

// PrecompiledContract is a contract implemented natively rather than in
// bytecode, for operations that would be prohibitively expensive to interpret.
type PrecompiledContract interface {
	// RequiredGas returns the cost of running the contract on the given input.
	RequiredGas(input []byte) uint64
	Run(input []byte) ([]byte, error)
}

// Precompile addresses, following the Ethereum numbering.
var (
	ecrecoverAddress = common.BytesToAddress([]byte{1})
	sha256Address    = common.BytesToAddress([]byte{2})
	identityAddress  = common.BytesToAddress([]byte{4})
	modexpAddress    = common.BytesToAddress([]byte{5})
)

// precompiles maps addresses to their native implementations.
var precompiles = map[common.Address]PrecompiledContract{
	ecrecoverAddress: &ecrecover{},
	sha256Address:    &sha256Hash{},
	identityAddress:  &identity{},
	modexpAddress:    &modExp{},
}

// PrecompileAddresses returns every active precompile address, which the
// transaction preamble pre-warms.
func PrecompileAddresses() []common.Address {
	out := make([]common.Address, 0, len(precompiles))
	for addr := range precompiles {
		out = append(out, addr)
	}
	return out
}

// precompile looks up the native contract at an address.
func (evm *EVM) precompile(addr common.Address) (PrecompiledContract, bool) {
	p, ok := precompiles[addr]
	return p, ok
}

// runPrecompile charges gas and executes a native contract.
func runPrecompile(p PrecompiledContract, input []byte, gas uint64) ([]byte, uint64, error) {
	cost := p.RequiredGas(input)
	if gas < cost {
		return nil, 0, ErrOutOfGas
	}
	gas -= cost
	out, err := p.Run(input)
	return out, gas, err
}

// ecrecover recovers the address that signed a hash, at address 0x01.
type ecrecover struct{}

func (c *ecrecover) RequiredGas(input []byte) uint64 { return 3000 }

func (c *ecrecover) Run(input []byte) ([]byte, error) {
	// Input is hash(32) || v(32) || r(32) || s(32), zero-padded.
	const inputLen = 128
	input = common.RightPadBytes(input, inputLen)

	hash := input[:32]
	v := new(big.Int).SetBytes(input[32:64])
	r := new(big.Int).SetBytes(input[64:96])
	s := new(big.Int).SetBytes(input[96:128])

	// A malformed input is not an error: the precompile returns nothing and
	// the caller is expected to check for an empty result.
	if !v.IsUint64() || (v.Uint64() != 27 && v.Uint64() != 28) {
		return nil, nil
	}
	if r.Sign() <= 0 || s.Sign() <= 0 || r.Cmp(secp256k1.N) >= 0 || s.Cmp(secp256k1.N) >= 0 {
		return nil, nil
	}
	if !secp256k1.IsLowS(s) {
		return nil, nil
	}

	pub, err := secp256k1.Recover(hash, &secp256k1.Signature{R: r, S: s, V: byte(v.Uint64() - 27)})
	if err != nil {
		return nil, nil
	}
	addr := common.Keccak256(pub.Bytes())
	// The result is the address left-padded to a full word.
	return common.LeftPadBytes(addr[12:], 32), nil
}

// sha256Hash is the SHA-256 precompile at address 0x02.
type sha256Hash struct{}

func (c *sha256Hash) RequiredGas(input []byte) uint64 {
	return 60 + 12*toWordSize(uint64(len(input)))
}

func (c *sha256Hash) Run(input []byte) ([]byte, error) {
	sum := sha256.Sum256(input)
	return sum[:], nil
}

// identity echoes its input, at address 0x04. It exists because copying data
// through a call is cheaper than doing it in bytecode.
type identity struct{}

func (c *identity) RequiredGas(input []byte) uint64 {
	return 15 + 3*toWordSize(uint64(len(input)))
}

func (c *identity) Run(input []byte) ([]byte, error) {
	return common.CopyBytes(input), nil
}

// modExp computes base^exponent mod modulus over arbitrary-length integers, at
// address 0x05. It is what makes RSA and other modular-arithmetic schemes
// affordable on chain.
type modExp struct{}

// parseModExpLengths reads the three length headers.
func parseModExpLengths(input []byte) (baseLen, expLen, modLen *big.Int) {
	padded := common.RightPadBytes(input, 96)
	baseLen = new(big.Int).SetBytes(padded[0:32])
	expLen = new(big.Int).SetBytes(padded[32:64])
	modLen = new(big.Int).SetBytes(padded[64:96])
	return
}

func (c *modExp) RequiredGas(input []byte) uint64 {
	baseLen, expLen, modLen := parseModExpLengths(input)
	if !baseLen.IsUint64() || !expLen.IsUint64() || !modLen.IsUint64() {
		return ^uint64(0) // unaffordable, which is the correct outcome
	}
	baseLength, expLength, modLength := baseLen.Uint64(), expLen.Uint64(), modLen.Uint64()

	// Multiplication complexity grows with the square of the operand words.
	maxLength := baseLength
	if modLength > maxLength {
		maxLength = modLength
	}
	words := toWordSize(maxLength)
	multiplicationComplexity := words * words

	// The exponent's bit length drives the number of squarings.
	var expHead *big.Int
	if baseLength+96 < uint64(len(input)) {
		expBytes := common.RightPadBytes(input[96+baseLength:], 32)
		limit := expLength
		if limit > 32 {
			limit = 32
		}
		expHead = new(big.Int).SetBytes(expBytes[:limit])
	} else {
		expHead = new(big.Int)
	}
	iterationCount := uint64(0)
	switch {
	case expLength <= 32 && expHead.Sign() == 0:
		iterationCount = 0
	case expLength <= 32:
		iterationCount = uint64(expHead.BitLen() - 1)
	default:
		iterationCount = 8*(expLength-32) + uint64(max(expHead.BitLen()-1, 0))
	}
	if iterationCount == 0 {
		iterationCount = 1
	}

	gas := multiplicationComplexity * iterationCount / 3
	if gas < 200 {
		return 200
	}
	return gas
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func (c *modExp) Run(input []byte) ([]byte, error) {
	baseLen, expLen, modLen := parseModExpLengths(input)
	if !baseLen.IsUint64() || !expLen.IsUint64() || !modLen.IsUint64() {
		return nil, errors.New("evm: modexp operand length overflows")
	}
	baseLength, expLength, modLength := baseLen.Uint64(), expLen.Uint64(), modLen.Uint64()

	if modLength == 0 {
		return nil, nil
	}
	// Guard against absurd allocations from a hostile input.
	const maxOperand = 1 << 20
	if baseLength > maxOperand || expLength > maxOperand || modLength > maxOperand {
		return nil, errors.New("evm: modexp operand too large")
	}

	body := input
	if len(body) > 96 {
		body = body[96:]
	} else {
		body = nil
	}
	read := func(offset, length uint64) *big.Int {
		if length == 0 {
			return new(big.Int)
		}
		if offset >= uint64(len(body)) {
			return new(big.Int)
		}
		end := offset + length
		if end > uint64(len(body)) {
			end = uint64(len(body))
		}
		buf := make([]byte, length)
		copy(buf, body[offset:end])
		return new(big.Int).SetBytes(buf)
	}

	base := read(0, baseLength)
	exponent := read(baseLength, expLength)
	modulus := read(baseLength+expLength, modLength)

	out := make([]byte, modLength)
	if modulus.Sign() == 0 {
		return out, nil
	}
	result := new(big.Int).Exp(base, exponent, modulus)
	result.FillBytes(out)
	return out, nil
}
