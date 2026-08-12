package evm

import (
	"errors"
	"fmt"

	"layer1/common"
	"layer1/core"
	"layer1/uint256"
)

// Tracer observes execution, one call per instruction.
type Tracer interface {
	CaptureState(pc uint64, op OpCode, gas, cost uint64, memory *Memory, stack *Stack, contract *Contract, depth int, err error)
	CaptureEnter(typ OpCode, from, to common.Address, input []byte, gas uint64, value *uint256.Int)
	CaptureExit(output []byte, gasUsed uint64, err error)
	CaptureFault(pc uint64, op OpCode, gas, cost uint64, depth int, err error)
}

// Interpreter runs EVM bytecode.
type Interpreter struct {
	evm *EVM

	// returnData holds the output of the most recent sub-call, which
	// RETURNDATASIZE and RETURNDATACOPY read.
	returnData []byte
	// readOnly marks that this frame and everything it calls may not write state.
	readOnly bool
}

// NewInterpreter builds an interpreter bound to an EVM.
func NewInterpreter(evm *EVM) *Interpreter {
	return &Interpreter{evm: evm}
}

// Run executes contract's code until it stops, returns, reverts or faults.
//
// A revert returns ErrExecutionReverted together with the revert data; every
// other error means the frame consumed all of its gas.
func (in *Interpreter) Run(contract *Contract, input []byte, readOnly bool) (ret []byte, err error) {
	in.evm.depth++
	defer func() { in.evm.depth-- }()

	// The read-only flag is sticky: once inside a static call, every nested
	// frame is static too.
	if readOnly && !in.readOnly {
		in.readOnly = true
		defer func() { in.readOnly = false }()
	}

	// Return data does not survive into a new frame.
	in.returnData = nil

	if len(contract.Code) == 0 {
		return nil, nil
	}

	var (
		op      OpCode
		mem     = newMemory()
		stack   = newStack()
		pc      = uint64(0)
		gasCopy uint64
		logged  bool
		res     []byte
	)
	contract.Input = input

	defer func() {
		returnStack(stack)
		returnMemory(mem)
	}()

	for {
		if in.evm.abort {
			return nil, errors.New("evm: execution aborted")
		}

		op = contract.GetOp(pc)
		gasCopy = contract.Gas
		logged = false

		cost, memSize, err := in.gasCost(op, contract, stack, mem)
		if err != nil {
			in.traceFault(pc, op, gasCopy, 0, err)
			return nil, err
		}
		if !contract.UseGas(cost) {
			in.traceFault(pc, op, gasCopy, cost, ErrOutOfGas)
			return nil, ErrOutOfGas
		}
		if memSize > 0 {
			mem.Resize(memSize)
		}

		if in.evm.Config.Tracer != nil {
			in.evm.Config.Tracer.CaptureState(pc, op, gasCopy, cost, mem, stack, contract, in.evm.depth, nil)
			logged = true
		}
		_ = logged

		res, err = in.execute(op, &pc, contract, stack, mem)
		switch {
		case err != nil:
			in.traceFault(pc, op, gasCopy, cost, err)
			return res, err
		case op == RETURN:
			return res, nil
		case op == REVERT:
			return res, ErrExecutionReverted
		case op == STOP || op == SELFDESTRUCT:
			return nil, nil
		}
		pc++
	}
}

func (in *Interpreter) traceFault(pc uint64, op OpCode, gas, cost uint64, err error) {
	if in.evm.Config.Tracer != nil {
		in.evm.Config.Tracer.CaptureFault(pc, op, gas, cost, in.evm.depth, err)
	}
}

// stackRequirement returns how many values an instruction pops and pushes.
func stackRequirement(op OpCode) (pops, pushes int) {
	switch {
	case op.IsPush():
		return 0, 1
	case op >= DUP1 && op <= DUP16:
		n := int(op-DUP1) + 1
		return n, n + 1
	case op >= SWAP1 && op <= SWAP16:
		n := int(op-SWAP1) + 2
		return n, n
	case op >= LOG0 && op <= LOG4:
		return int(op-LOG0) + 2, 0
	}
	switch op {
	case STOP, JUMPDEST, PC, MSIZE, GAS, ADDRESS, ORIGIN, CALLER, CALLVALUE,
		CALLDATASIZE, CODESIZE, GASPRICE, RETURNDATASIZE, COINBASE, TIMESTAMP,
		NUMBER, PREVRANDAO, GASLIMIT, CHAINID, SELFBALANCE, BASEFEE, PUSH0:
		if op == STOP || op == JUMPDEST {
			return 0, 0
		}
		return 0, 1
	case POP, JUMP, SELFDESTRUCT:
		return 1, 0
	case ISZERO, NOT, BALANCE, CALLDATALOAD, EXTCODESIZE, EXTCODEHASH, BLOCKHASH,
		MLOAD, SLOAD, TLOAD:
		return 1, 1
	case ADD, MUL, SUB, DIV, SDIV, MOD, SMOD, EXP, SIGNEXTEND, LT, GT, SLT, SGT,
		EQ, AND, OR, XOR, BYTE, SHL, SHR, SAR, KECCAK256:
		return 2, 1
	case JUMPI, MSTORE, MSTORE8, SSTORE, TSTORE, RETURN, REVERT:
		return 2, 0
	case ADDMOD, MULMOD, CREATE:
		if op == CREATE {
			return 3, 1
		}
		return 3, 1
	case CALLDATACOPY, CODECOPY, RETURNDATACOPY, MCOPY:
		return 3, 0
	case EXTCODECOPY:
		return 4, 0
	case CREATE2:
		return 4, 1
	case DELEGATECALL, STATICCALL:
		return 6, 1
	case CALL, CALLCODE:
		return 7, 1
	default:
		return 0, 0
	}
}

// gasCost computes the cost of the next instruction and the memory size it
// needs. Both are determined before any state is touched, so an instruction
// that cannot be paid for has no effect at all.
func (in *Interpreter) gasCost(op OpCode, contract *Contract, stack *Stack, mem *Memory) (cost uint64, memSize uint64, err error) {
	pops, pushes := stackRequirement(op)
	if err := stack.checkLimits(pops, pushes); err != nil {
		return 0, 0, err
	}

	base, ok := baseGas(op)
	if !ok {
		return 0, 0, &ErrInvalidOpCode{OpCode: op}
	}
	cost = base

	// Instructions that touch memory pay for any growth they cause.
	var extent uint64
	switch op {
	case MLOAD, MSTORE:
		if !stack.back(0).IsUint64() {
			return 0, 0, ErrGasUintOverflow
		}
		extent, err = safeAdd(stack.back(0).Uint64(), 32)
	case MSTORE8:
		if !stack.back(0).IsUint64() {
			return 0, 0, ErrGasUintOverflow
		}
		extent, err = safeAdd(stack.back(0).Uint64(), 1)
	case KECCAK256, RETURN, REVERT, LOG0, LOG1, LOG2, LOG3, LOG4:
		extent, err = memoryExtent(stack.back(0), stack.back(1))
	case CALLDATACOPY, CODECOPY, RETURNDATACOPY:
		extent, err = memoryExtent(stack.back(0), stack.back(2))
	case MCOPY:
		dst, err1 := memoryExtent(stack.back(0), stack.back(2))
		src, err2 := memoryExtent(stack.back(1), stack.back(2))
		if err1 != nil {
			return 0, 0, err1
		}
		if err2 != nil {
			return 0, 0, err2
		}
		extent = max64(dst, src)
	case EXTCODECOPY:
		extent, err = memoryExtent(stack.back(1), stack.back(3))
	case CREATE:
		extent, err = memoryExtent(stack.back(1), stack.back(2))
	case CREATE2:
		extent, err = memoryExtent(stack.back(1), stack.back(2))
	case CALL, CALLCODE:
		in1, err1 := memoryExtent(stack.back(3), stack.back(4))
		out1, err2 := memoryExtent(stack.back(5), stack.back(6))
		if err1 != nil {
			return 0, 0, err1
		}
		if err2 != nil {
			return 0, 0, err2
		}
		extent = max64(in1, out1)
	case DELEGATECALL, STATICCALL:
		in1, err1 := memoryExtent(stack.back(2), stack.back(3))
		out1, err2 := memoryExtent(stack.back(4), stack.back(5))
		if err1 != nil {
			return 0, 0, err1
		}
		if err2 != nil {
			return 0, 0, err2
		}
		extent = max64(in1, out1)
	}
	if err != nil {
		return 0, 0, err
	}
	if extent > 0 {
		memFee, err := memoryGasCost(mem, extent)
		if err != nil {
			return 0, 0, err
		}
		if cost, err = safeAdd(cost, memFee); err != nil {
			return 0, 0, err
		}
		memSize = extent
	}

	// Per-instruction dynamic costs.
	dynamic, err := in.dynamicGas(op, contract, stack)
	if err != nil {
		return 0, 0, err
	}
	if cost, err = safeAdd(cost, dynamic); err != nil {
		return 0, 0, err
	}
	return cost, memSize, nil
}

func max64(a, b uint64) uint64 {
	if a > b {
		return a
	}
	return b
}

// wordCopyGas charges for copying size bytes, rounded up to whole words.
func wordCopyGas(size *uint256.Int) (uint64, error) {
	if size.IsZero() {
		return 0, nil
	}
	if !size.IsUint64() {
		return 0, ErrGasUintOverflow
	}
	return safeMul(toWordSize(size.Uint64()), GasCopyWord)
}

func (in *Interpreter) dynamicGas(op OpCode, contract *Contract, stack *Stack) (uint64, error) {
	db := in.evm.StateDB

	switch op {
	case KECCAK256:
		size := stack.back(1)
		if !size.IsUint64() {
			return 0, ErrGasUintOverflow
		}
		return safeMul(toWordSize(size.Uint64()), GasKeccakWord)

	case CALLDATACOPY, CODECOPY, RETURNDATACOPY:
		return wordCopyGas(stack.back(2))

	case MCOPY:
		return wordCopyGas(stack.back(2))

	case EXTCODECOPY:
		copyGas, err := wordCopyGas(stack.back(3))
		if err != nil {
			return 0, err
		}
		access := in.accountAccessGas(common.BytesToAddress(stack.back(0).Bytes()))
		return safeAdd(copyGas, access)

	case BALANCE, EXTCODESIZE, EXTCODEHASH:
		return in.accountAccessGas(common.BytesToAddress(stack.back(0).Bytes())), nil

	case EXP:
		exponent := stack.back(1)
		if exponent.IsZero() {
			return 0, nil
		}
		return safeMul(uint64(exponent.ByteLen()), GasExpByte)

	case SLOAD:
		key := common.Hash(stack.back(0).Bytes32())
		_, slotWarm := db.SlotInAccessList(contract.Address(), key)
		db.AddSlotToAccessList(contract.Address(), key)
		if slotWarm {
			return GasWarmStorageRead, nil
		}
		return GasColdSloadCost, nil

	case SSTORE:
		if in.readOnly {
			return 0, ErrWriteProtection
		}
		// EIP-2200 requires a minimum gas reserve, so a contract can always
		// detect that it is out of gas rather than being stopped mid-write.
		if contract.Gas <= GasCallStipend {
			return 0, fmt.Errorf("%w: SSTORE requires more than %d gas in reserve", ErrOutOfGas, GasCallStipend)
		}
		addr := contract.Address()
		key := common.Hash(stack.back(0).Bytes32())
		value := common.Hash(stack.back(1).Bytes32())

		_, slotWarm := db.SlotInAccessList(addr, key)
		db.AddSlotToAccessList(addr, key)

		cost, refund := sstoreGas(db.GetCommittedState(addr, key), db.GetState(addr, key), value, !slotWarm)
		if refund > 0 {
			db.AddRefund(uint64(refund))
		} else if refund < 0 {
			db.SubRefund(uint64(-refund))
		}
		return cost, nil

	case TSTORE:
		if in.readOnly {
			return 0, ErrWriteProtection
		}
		return 0, nil

	case LOG0, LOG1, LOG2, LOG3, LOG4:
		if in.readOnly {
			return 0, ErrWriteProtection
		}
		topics := uint64(op - LOG0)
		size := stack.back(1)
		if !size.IsUint64() {
			return 0, ErrGasUintOverflow
		}
		byteGas, err := safeMul(size.Uint64(), GasLogByte)
		if err != nil {
			return 0, err
		}
		topicGas, err := safeMul(topics, GasLogTopic)
		if err != nil {
			return 0, err
		}
		total, err := safeAdd(byteGas, topicGas)
		if err != nil {
			return 0, err
		}
		return total, nil

	case CREATE, CREATE2:
		if in.readOnly {
			return 0, ErrWriteProtection
		}
		size := stack.back(2)
		if !size.IsUint64() {
			return 0, ErrGasUintOverflow
		}
		if size.Uint64() > MaxInitCodeSize {
			return 0, ErrMaxCodeSizeExceeded
		}
		// EIP-3860 charges for init code by the word, since it must be hashed
		// and analysed before it runs.
		initGas, err := safeMul(toWordSize(size.Uint64()), GasInitCodeWord)
		if err != nil {
			return 0, err
		}
		if op == CREATE2 {
			// CREATE2 also hashes the init code to derive the address.
			hashGas, err := safeMul(toWordSize(size.Uint64()), GasKeccakWord)
			if err != nil {
				return 0, err
			}
			if initGas, err = safeAdd(initGas, hashGas); err != nil {
				return 0, err
			}
		}
		return initGas, nil

	case CALL:
		addr := common.BytesToAddress(stack.back(1).Bytes())
		value := stack.back(2)
		if in.readOnly && !value.IsZero() {
			return 0, ErrWriteProtection
		}
		gas := in.accountAccessGas(addr)
		if !value.IsZero() {
			var err error
			if gas, err = safeAdd(gas, GasCallValue); err != nil {
				return 0, err
			}
			// Creating an account to receive value is charged separately.
			if !db.Exist(addr) {
				if gas, err = safeAdd(gas, GasNewAccount); err != nil {
					return 0, err
				}
			}
		}
		return gas, nil

	case CALLCODE:
		gas := in.accountAccessGas(common.BytesToAddress(stack.back(1).Bytes()))
		if !stack.back(2).IsZero() {
			return safeAdd(gas, GasCallValue)
		}
		return gas, nil

	case DELEGATECALL, STATICCALL:
		return in.accountAccessGas(common.BytesToAddress(stack.back(1).Bytes())), nil

	case SELFDESTRUCT:
		if in.readOnly {
			return 0, ErrWriteProtection
		}
		beneficiary := common.BytesToAddress(stack.back(0).Bytes())
		gas := uint64(0)
		if !db.AddressInAccessList(beneficiary) {
			db.AddAddressToAccessList(beneficiary)
			gas += GasColdAccountAccess
		}
		// Sending the balance to an account that does not exist creates it.
		if db.Empty(beneficiary) && db.GetBalance(contract.Address()).Sign() != 0 {
			gas += GasNewAccount
		}
		return gas, nil

	default:
		return 0, nil
	}
}

// accountAccessGas charges the EIP-2929 cold or warm access cost and marks the
// address warm.
func (in *Interpreter) accountAccessGas(addr common.Address) uint64 {
	if in.evm.StateDB.AddressInAccessList(addr) {
		return GasWarmStorageRead
	}
	in.evm.StateDB.AddAddressToAccessList(addr)
	return GasColdAccountAccess
}

// baseGas returns the constant part of an instruction's cost. The second result
// is false for undefined opcodes.
func baseGas(op OpCode) (uint64, bool) {
	switch {
	case op.IsPush():
		return GasVeryLow, true
	case op >= DUP1 && op <= DUP16:
		return GasVeryLow, true
	case op >= SWAP1 && op <= SWAP16:
		return GasVeryLow, true
	case op >= LOG0 && op <= LOG4:
		return GasLog, true
	}
	switch op {
	case STOP, RETURN, REVERT:
		return GasZero, true
	case JUMPDEST:
		return GasJumpDest, true
	case PUSH0:
		return GasBase, true
	case ADDRESS, ORIGIN, CALLER, CALLVALUE, CALLDATASIZE, CODESIZE, GASPRICE,
		COINBASE, TIMESTAMP, NUMBER, PREVRANDAO, GASLIMIT, POP, PC, MSIZE, GAS,
		RETURNDATASIZE, CHAINID, BASEFEE:
		return GasBase, true
	case ADD, SUB, NOT, LT, GT, SLT, SGT, EQ, ISZERO, AND, OR, XOR, BYTE,
		CALLDATALOAD, MLOAD, MSTORE, MSTORE8, SHL, SHR, SAR, CALLDATACOPY,
		CODECOPY, RETURNDATACOPY, MCOPY:
		return GasVeryLow, true
	case MUL, DIV, SDIV, MOD, SMOD, SIGNEXTEND, SELFBALANCE:
		return GasLow, true
	case ADDMOD, MULMOD, JUMP:
		return GasMid, true
	case JUMPI:
		return GasHigh, true
	case KECCAK256:
		return GasKeccak256, true
	case EXP:
		return GasHigh, true
	case BLOCKHASH:
		return 20, true
	case BALANCE, EXTCODESIZE, EXTCODEHASH, SLOAD, EXTCODECOPY:
		return 0, true // charged entirely as dynamic access gas
	case TLOAD, TSTORE:
		return GasWarmStorageRead, true
	case SSTORE:
		return 0, true
	case CREATE:
		return GasCreate, true
	case CREATE2:
		return GasCreate, true
	case CALL, CALLCODE, DELEGATECALL, STATICCALL:
		return 0, true
	case SELFDESTRUCT:
		return GasSelfDestruct, true
	case INVALID:
		return 0, true
	default:
		return 0, false
	}
}

// execute performs one instruction. It returns the frame's output for RETURN
// and REVERT, and nil otherwise.
func (in *Interpreter) execute(op OpCode, pc *uint64, contract *Contract, stack *Stack, mem *Memory) ([]byte, error) {
	evm := in.evm
	db := evm.StateDB

	switch {
	case op.IsPush():
		size := uint64(op.PushSize())
		start := *pc + 1
		var value uint256.Int
		// Reading past the end of the code yields zero bytes, per the spec.
		if start < uint64(len(contract.Code)) {
			end := min64(start+size, uint64(len(contract.Code)))
			padded := make([]byte, size)
			copy(padded, contract.Code[start:end])
			value.SetBytes(padded)
		}
		stack.push(&value)
		*pc += size
		return nil, nil

	case op >= DUP1 && op <= DUP16:
		stack.dup(int(op-DUP1) + 1)
		return nil, nil

	case op >= SWAP1 && op <= SWAP16:
		stack.swap(int(op-SWAP1) + 1)
		return nil, nil

	case op >= LOG0 && op <= LOG4:
		return nil, in.opLog(op, contract, stack, mem)
	}

	switch op {
	case STOP:
		return nil, nil

	// For every binary instruction the first operand is on top of the stack
	// and the second is below it, so `x` is popped and the result is written
	// back over the remaining word.
	case ADD:
		x := stack.pop()
		stack.peek().Add(&x, stack.peek())
	case SUB:
		x := stack.pop()
		stack.peek().Sub(&x, stack.peek())
	case MUL:
		x := stack.pop()
		stack.peek().Mul(&x, stack.peek())
	case DIV:
		x := stack.pop()
		stack.peek().Div(&x, stack.peek())
	case SDIV:
		x := stack.pop()
		stack.peek().SDiv(&x, stack.peek())
	case MOD:
		x := stack.pop()
		stack.peek().Mod(&x, stack.peek())
	case SMOD:
		x := stack.pop()
		stack.peek().SMod(&x, stack.peek())
	case ADDMOD:
		x, y := stack.pop(), stack.pop()
		stack.peek().AddMod(&x, &y, stack.peek())
	case MULMOD:
		x, y := stack.pop(), stack.pop()
		stack.peek().MulMod(&x, &y, stack.peek())
	case EXP:
		base := stack.pop()
		stack.peek().Exp(&base, stack.peek())
	case SIGNEXTEND:
		index := stack.pop()
		stack.peek().SignExtend(&index, stack.peek())

	case LT:
		x := stack.pop()
		stack.peek().SetUint64(boolToUint(x.Lt(stack.peek())))
	case GT:
		x := stack.pop()
		stack.peek().SetUint64(boolToUint(x.Gt(stack.peek())))
	case SLT:
		x := stack.pop()
		stack.peek().SetUint64(boolToUint(x.SLt(stack.peek())))
	case SGT:
		x := stack.pop()
		stack.peek().SetUint64(boolToUint(x.SGt(stack.peek())))
	case EQ:
		x := stack.pop()
		stack.peek().SetUint64(boolToUint(x.Eq(stack.peek())))
	case ISZERO:
		stack.peek().SetUint64(boolToUint(stack.peek().IsZero()))

	case AND:
		x := stack.pop()
		stack.peek().And(&x, stack.peek())
	case OR:
		x := stack.pop()
		stack.peek().Or(&x, stack.peek())
	case XOR:
		x := stack.pop()
		stack.peek().Xor(&x, stack.peek())
	case NOT:
		stack.peek().Not(stack.peek())
	case BYTE:
		// The byte index is on top, the value below it.
		index := stack.pop()
		stack.peek().Byte(stack.peek(), &index)
	case SHL:
		// The shift amount is on top, the value to shift below it.
		shift := stack.pop()
		if shift.IsUint64() && shift.Uint64() < 256 {
			stack.peek().Lsh(stack.peek(), uint(shift.Uint64()))
		} else {
			stack.peek().Clear()
		}
	case SHR:
		shift := stack.pop()
		if shift.IsUint64() && shift.Uint64() < 256 {
			stack.peek().Rsh(stack.peek(), uint(shift.Uint64()))
		} else {
			stack.peek().Clear()
		}
	case SAR:
		shift := stack.pop()
		if shift.IsUint64() && shift.Uint64() < 256 {
			stack.peek().SRsh(stack.peek(), uint(shift.Uint64()))
		} else {
			stack.peek().SRsh(stack.peek(), 256)
		}

	case KECCAK256:
		offset, size := stack.pop(), stack.pop()
		data := mem.GetPtr(offset.Uint64(), size.Uint64())
		var result uint256.Int
		h := common.Keccak256(data)
		result.SetBytes(h[:])
		stack.push(&result)

	case ADDRESS:
		var v uint256.Int
		addr := contract.Address()
		stack.push(v.SetBytes(addr[:]))
	case BALANCE:
		addr := common.BytesToAddress(stack.peek().Bytes())
		stack.peek().SetBig(db.GetBalance(addr))
	case ORIGIN:
		var v uint256.Int
		stack.push(v.SetBytes(evm.TxContext.Origin[:]))
	case CALLER:
		var v uint256.Int
		caller := contract.Caller()
		stack.push(v.SetBytes(caller[:]))
	case CALLVALUE:
		stack.push(contract.Value().Clone())
	case CALLDATALOAD:
		offset := stack.peek()
		stack.peek().SetBytes(getDataPadded(contract.Input, offset, 32))
	case CALLDATASIZE:
		stack.push(uint256.NewInt(uint64(len(contract.Input))))
	case CALLDATACOPY:
		memOffset, dataOffset, size := stack.pop(), stack.pop(), stack.pop()
		mem.Set(memOffset.Uint64(), size.Uint64(), getDataPadded(contract.Input, &dataOffset, size.Uint64()))
	case CODESIZE:
		stack.push(uint256.NewInt(uint64(len(contract.Code))))
	case CODECOPY:
		memOffset, codeOffset, size := stack.pop(), stack.pop(), stack.pop()
		mem.Set(memOffset.Uint64(), size.Uint64(), getDataPadded(contract.Code, &codeOffset, size.Uint64()))
	case GASPRICE:
		stack.push(uint256.FromBig(evm.TxContext.GasPrice))
	case EXTCODESIZE:
		addr := common.BytesToAddress(stack.peek().Bytes())
		stack.peek().SetUint64(uint64(db.GetCodeSize(addr)))
	case EXTCODECOPY:
		addrWord, memOffset, codeOffset, size := stack.pop(), stack.pop(), stack.pop(), stack.pop()
		addr := common.BytesToAddress(addrWord.Bytes())
		mem.Set(memOffset.Uint64(), size.Uint64(), getDataPadded(db.GetCode(addr), &codeOffset, size.Uint64()))
	case EXTCODEHASH:
		addr := common.BytesToAddress(stack.peek().Bytes())
		if db.Empty(addr) {
			// An empty account has no code hash at all, distinct from the hash
			// of empty code.
			stack.peek().Clear()
		} else {
			h := db.GetCodeHash(addr)
			stack.peek().SetBytes(h[:])
		}
	case RETURNDATASIZE:
		stack.push(uint256.NewInt(uint64(len(in.returnData))))
	case RETURNDATACOPY:
		memOffset, dataOffset, size := stack.pop(), stack.pop(), stack.pop()
		end, overflow := new(uint256.Int).AddOverflow(&dataOffset, &size)
		if overflow || !end.IsUint64() || end.Uint64() > uint64(len(in.returnData)) {
			// Unlike call data, reading past the end of return data is an
			// error rather than zero padding.
			return nil, ErrReturnDataOutOfBounds
		}
		mem.Set(memOffset.Uint64(), size.Uint64(), in.returnData[dataOffset.Uint64():end.Uint64()])

	case BLOCKHASH:
		number := stack.peek()
		if !number.IsUint64() {
			number.Clear()
			break
		}
		current := evm.Context.BlockNumber.Uint64()
		requested := number.Uint64()
		// Only the last 256 blocks are addressable.
		if requested >= current || current-requested > 256 {
			number.Clear()
		} else {
			h := evm.Context.GetHash(requested)
			number.SetBytes(h[:])
		}
	case COINBASE:
		var v uint256.Int
		stack.push(v.SetBytes(evm.Context.Coinbase[:]))
	case TIMESTAMP:
		stack.push(uint256.NewInt(evm.Context.Time))
	case NUMBER:
		stack.push(uint256.FromBig(evm.Context.BlockNumber))
	case PREVRANDAO:
		var v uint256.Int
		stack.push(v.SetBytes(evm.Context.Random[:]))
	case GASLIMIT:
		stack.push(uint256.NewInt(evm.Context.GasLimit))
	case CHAINID:
		stack.push(uint256.FromBig(evm.ChainConfig.ChainID))
	case SELFBALANCE:
		stack.push(uint256.FromBig(db.GetBalance(contract.Address())))
	case BASEFEE:
		stack.push(uint256.FromBig(evm.Context.BaseFee))

	case POP:
		stack.pop()
	case MLOAD:
		offset := stack.peek()
		stack.peek().SetBytes(mem.GetCopy(offset.Uint64(), 32))
	case MSTORE:
		offset, value := stack.pop(), stack.pop()
		mem.Set32(offset.Uint64(), &value)
	case MSTORE8:
		offset, value := stack.pop(), stack.pop()
		mem.Set(offset.Uint64(), 1, []byte{byte(value.Uint64())})
	case MCOPY:
		dst, src, size := stack.pop(), stack.pop(), stack.pop()
		if size.IsZero() {
			break
		}
		// Copy through a temporary so overlapping ranges behave like memmove.
		data := mem.GetCopy(src.Uint64(), size.Uint64())
		mem.Set(dst.Uint64(), size.Uint64(), data)

	case SLOAD:
		key := common.Hash(stack.peek().Bytes32())
		value := db.GetState(contract.Address(), key)
		stack.peek().SetBytes(value[:])
	case SSTORE:
		if in.readOnly {
			return nil, ErrWriteProtection
		}
		key, value := stack.pop(), stack.pop()
		db.SetState(contract.Address(), common.Hash(key.Bytes32()), common.Hash(value.Bytes32()))
	case TLOAD:
		key := common.Hash(stack.peek().Bytes32())
		value := db.GetTransientState(contract.Address(), key)
		stack.peek().SetBytes(value[:])
	case TSTORE:
		if in.readOnly {
			return nil, ErrWriteProtection
		}
		key, value := stack.pop(), stack.pop()
		db.SetTransientState(contract.Address(), common.Hash(key.Bytes32()), common.Hash(value.Bytes32()))

	case JUMP:
		dest := stack.pop()
		if !contract.validJumpdest(&dest) {
			return nil, fmt.Errorf("%w: %s", ErrInvalidJump, dest.Hex())
		}
		// The loop increments pc after every instruction, so step back one.
		*pc = dest.Uint64() - 1
	case JUMPI:
		dest, condition := stack.pop(), stack.pop()
		if !condition.IsZero() {
			if !contract.validJumpdest(&dest) {
				return nil, fmt.Errorf("%w: %s", ErrInvalidJump, dest.Hex())
			}
			*pc = dest.Uint64() - 1
		}
	case JUMPDEST:
		// A marker only; it exists so jumps cannot land in the middle of data.
	case PC:
		stack.push(uint256.NewInt(*pc))
	case MSIZE:
		stack.push(uint256.NewInt(uint64(mem.Len())))
	case GAS:
		stack.push(uint256.NewInt(contract.Gas))
	case PUSH0:
		stack.push(new(uint256.Int))

	case CREATE, CREATE2:
		return nil, in.opCreate(op, contract, stack, mem)

	case CALL, CALLCODE, DELEGATECALL, STATICCALL:
		return nil, in.opCall(op, contract, stack, mem)

	case RETURN:
		offset, size := stack.pop(), stack.pop()
		return mem.GetCopy(offset.Uint64(), size.Uint64()), nil

	case REVERT:
		offset, size := stack.pop(), stack.pop()
		out := mem.GetCopy(offset.Uint64(), size.Uint64())
		in.returnData = out
		return out, nil

	case SELFDESTRUCT:
		if in.readOnly {
			return nil, ErrWriteProtection
		}
		target := stack.pop()
		beneficiary := common.BytesToAddress(target.Bytes())
		balance := db.GetBalance(contract.Address())
		db.AddBalance(beneficiary, balance)
		db.SelfDestruct(contract.Address())

	case INVALID:
		return nil, &ErrInvalidOpCode{OpCode: op}

	default:
		return nil, &ErrInvalidOpCode{OpCode: op}
	}
	return nil, nil
}

func boolToUint(b bool) uint64 {
	if b {
		return 1
	}
	return 0
}

// getDataPadded reads size bytes from data at offset, zero-padding past the end.
func getDataPadded(data []byte, offset *uint256.Int, size uint64) []byte {
	if size == 0 {
		return nil
	}
	out := make([]byte, size)
	if !offset.IsUint64() {
		return out
	}
	start := offset.Uint64()
	if start >= uint64(len(data)) {
		return out
	}
	end := start + size
	if end > uint64(len(data)) || end < start {
		end = uint64(len(data))
	}
	copy(out, data[start:end])
	return out
}

func (in *Interpreter) opLog(op OpCode, contract *Contract, stack *Stack, mem *Memory) error {
	if in.readOnly {
		return ErrWriteProtection
	}
	count := int(op - LOG0)
	offset, size := stack.pop(), stack.pop()

	topics := make([]common.Hash, count)
	for i := 0; i < count; i++ {
		t := stack.pop()
		topics[i] = common.Hash(t.Bytes32())
	}
	in.evm.StateDB.AddLog(&core.Log{
		Address:     contract.Address(),
		Topics:      topics,
		Data:        mem.GetCopy(offset.Uint64(), size.Uint64()),
		BlockNumber: in.evm.Context.BlockNumber.Uint64(),
	})
	return nil
}

func (in *Interpreter) opCreate(op OpCode, contract *Contract, stack *Stack, mem *Memory) error {
	if in.readOnly {
		return ErrWriteProtection
	}
	var (
		value        = stack.pop()
		offset, size = stack.pop(), stack.pop()
		salt         uint256.Int
	)
	if op == CREATE2 {
		salt = stack.pop()
	}
	input := mem.GetCopy(offset.Uint64(), size.Uint64())

	// EIP-150: the child frame gets all but a 64th of the available gas.
	gas := contract.Gas - contract.Gas/64
	contract.UseGas(gas)

	var (
		ret      []byte
		addr     common.Address
		leftOver uint64
		err      error
	)
	if op == CREATE {
		ret, addr, leftOver, err = in.evm.Create(contract, input, gas, value.ToBig())
	} else {
		ret, addr, leftOver, err = in.evm.Create2(contract, input, gas, value.ToBig(), &salt)
	}

	var result uint256.Int
	if err != nil {
		// A failed creation pushes zero; the caller keeps running.
		result.Clear()
	} else {
		result.SetBytes(addr[:])
	}
	stack.push(&result)
	contract.RefundGas(leftOver)

	// Only a revert makes the child's output visible to the caller.
	if errors.Is(err, ErrExecutionReverted) {
		in.returnData = ret
	} else {
		in.returnData = nil
	}
	return nil
}

func (in *Interpreter) opCall(op OpCode, contract *Contract, stack *Stack, mem *Memory) error {
	var (
		gasWord  = stack.pop()
		addrWord = stack.pop()
		addr     = common.BytesToAddress(addrWord.Bytes())
		value    uint256.Int
	)
	if op == CALL || op == CALLCODE {
		value = stack.pop()
	}
	inOffset, inSize := stack.pop(), stack.pop()
	retOffset, retSize := stack.pop(), stack.pop()

	if in.readOnly && op == CALL && !value.IsZero() {
		return ErrWriteProtection
	}

	input := mem.GetCopy(inOffset.Uint64(), inSize.Uint64())

	gas, err := callGas(contract.Gas, 0, &gasWord)
	if err != nil {
		return err
	}
	contract.UseGas(gas)

	// A value-bearing call always gets a stipend, so the recipient can at
	// least emit a log or read its own state.
	if (op == CALL || op == CALLCODE) && !value.IsZero() {
		gas += GasCallStipend
	}

	var (
		ret      []byte
		leftOver uint64
		callErr  error
	)
	switch op {
	case CALL:
		ret, leftOver, callErr = in.evm.Call(contract, addr, input, gas, value.ToBig())
	case CALLCODE:
		ret, leftOver, callErr = in.evm.CallCode(contract, addr, input, gas, value.ToBig())
	case DELEGATECALL:
		ret, leftOver, callErr = in.evm.DelegateCall(contract, addr, input, gas)
	case STATICCALL:
		ret, leftOver, callErr = in.evm.StaticCall(contract, addr, input, gas)
	}

	var result uint256.Int
	if callErr == nil {
		result.SetOne()
	}
	stack.push(&result)

	// The caller decides how much of the output to keep.
	if callErr == nil || errors.Is(callErr, ErrExecutionReverted) {
		in.returnData = ret
		if retSize.Uint64() > 0 {
			mem.Set(retOffset.Uint64(), min64(retSize.Uint64(), uint64(len(ret))), ret)
		}
	} else {
		in.returnData = nil
	}
	contract.RefundGas(leftOver)
	return nil
}
