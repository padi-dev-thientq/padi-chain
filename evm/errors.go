package evm

import "errors"

// Execution errors. All of these consume the remaining gas except
// ErrExecutionReverted, which returns it — that asymmetry is what makes REVERT
// usable for input validation.
var (
	ErrOutOfGas                 = errors.New("evm: out of gas")
	ErrCodeStoreOutOfGas        = errors.New("evm: contract creation ran out of gas storing code")
	ErrDepthLimit               = errors.New("evm: call depth limit reached")
	ErrInsufficientBalance      = errors.New("evm: insufficient balance for transfer")
	ErrContractAddressCollision = errors.New("evm: contract address collision")
	ErrExecutionReverted        = errors.New("evm: execution reverted")
	ErrMaxCodeSizeExceeded      = errors.New("evm: max code size exceeded")
	ErrInvalidJump              = errors.New("evm: invalid jump destination")
	ErrWriteProtection          = errors.New("evm: state modification in a static call")
	ErrReturnDataOutOfBounds    = errors.New("evm: return data access out of bounds")
	ErrGasUintOverflow          = errors.New("evm: gas calculation overflowed")
	ErrInvalidCode              = errors.New("evm: deployed code starts with the reserved 0xEF byte")
	ErrNonceOverflow            = errors.New("evm: account nonce overflow")
	ErrStackUnderflow           = errors.New("evm: stack underflow")
	ErrStackOverflow            = errors.New("evm: stack overflow")
)

// ErrInvalidOpCode reports an undefined instruction.
type ErrInvalidOpCode struct{ OpCode OpCode }

func (e *ErrInvalidOpCode) Error() string {
	return "evm: invalid opcode " + e.OpCode.String()
}
