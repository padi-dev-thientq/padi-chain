package evm

import (
	"padi-chain/common"
	"padi-chain/uint256"
)

// ContractRef is something that can act as the caller of a contract.
type ContractRef interface {
	Address() common.Address
}

// AccountRef is a plain address acting as a caller.
type AccountRef common.Address

func (a AccountRef) Address() common.Address { return common.Address(a) }

// Contract is one frame of execution: the code being run, who called it, and
// the gas available to it.
type Contract struct {
	// CallerAddress is the address that appears as CALLER inside this frame.
	// For a delegate call it is the original caller, not the immediate one,
	// which is what lets a library run in its caller's context.
	CallerAddress common.Address
	caller        ContractRef
	self          ContractRef

	Code     []byte
	CodeHash common.Hash
	CodeAddr *common.Address
	Input    []byte

	Gas   uint64
	value *uint256.Int

	// analysis caches the valid jump destinations of Code.
	analysis bitvec
	analysed bool
}

// NewContract creates a frame.
func NewContract(caller ContractRef, object ContractRef, value *uint256.Int, gas uint64) *Contract {
	c := &Contract{
		CallerAddress: caller.Address(),
		caller:        caller,
		self:          object,
		Gas:           gas,
		value:         new(uint256.Int),
	}
	if value != nil {
		c.value.Set(value)
	}
	return c
}

// AsDelegate re-points the frame at the original caller's identity, which is
// what DELEGATECALL means: run this code as if it were the caller's own.
func (c *Contract) AsDelegate() *Contract {
	parent := c.caller.(*Contract)
	c.CallerAddress = parent.CallerAddress
	c.value = parent.value.Clone()
	return c
}

// Address returns the address this frame executes as.
func (c *Contract) Address() common.Address { return c.self.Address() }

// Caller returns the address that appears as CALLER.
func (c *Contract) Caller() common.Address { return c.CallerAddress }

// Value returns the value transferred into this frame.
func (c *Contract) Value() *uint256.Int { return c.value }

// SetCallCode installs the code to execute and the address it came from.
func (c *Contract) SetCallCode(addr *common.Address, hash common.Hash, code []byte) {
	c.Code = code
	c.CodeHash = hash
	c.CodeAddr = addr
	c.analysed = false
}

// UseGas deducts gas, reporting whether there was enough.
func (c *Contract) UseGas(amount uint64) bool {
	if c.Gas < amount {
		return false
	}
	c.Gas -= amount
	return true
}

// RefundGas returns unused gas to the frame.
func (c *Contract) RefundGas(amount uint64) { c.Gas += amount }

// GetOp returns the instruction at pc, or STOP past the end of the code.
func (c *Contract) GetOp(pc uint64) OpCode {
	if pc < uint64(len(c.Code)) {
		return OpCode(c.Code[pc])
	}
	return STOP
}

// validJumpdest reports whether dest is a JUMPDEST that is not part of a push
// instruction's immediate data. Without that second condition, data bytes that
// happen to equal 0x5b would be jumpable.
func (c *Contract) validJumpdest(dest *uint256.Int) bool {
	if !dest.IsUint64() {
		return false
	}
	pos := dest.Uint64()
	if pos >= uint64(len(c.Code)) {
		return false
	}
	if OpCode(c.Code[pos]) != JUMPDEST {
		return false
	}
	if !c.analysed {
		c.analysis = codeBitmap(c.Code)
		c.analysed = true
	}
	return c.analysis.isCode(pos)
}

// bitvec marks which byte positions in the code are instructions rather than
// push immediates.
type bitvec []byte

func (b bitvec) set(pos uint64)         { b[pos/8] |= 1 << (pos % 8) }
func (b bitvec) isCode(pos uint64) bool { return b[pos/8]&(1<<(pos%8)) == 0 }

// codeBitmap marks the immediate bytes that follow every push instruction.
func codeBitmap(code []byte) bitvec {
	bits := make(bitvec, len(code)/8+1+4)
	for pc := uint64(0); pc < uint64(len(code)); {
		op := OpCode(code[pc])
		pc++
		if !op.IsPush() {
			continue
		}
		size := uint64(op.PushSize())
		for i := uint64(0); i < size && pc+i < uint64(len(code)); i++ {
			bits.set(pc + i)
		}
		pc += size
	}
	return bits
}
