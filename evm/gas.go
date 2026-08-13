package evm

import (
	"padi-chain/common"
	"padi-chain/uint256"
)

// Base gas costs. The tiers mirror the yellow paper's grouping of
// instructions by how much work they actually cost a node to execute.
const (
	GasZero         uint64 = 0
	GasJumpDest     uint64 = 1
	GasBase         uint64 = 2
	GasVeryLow      uint64 = 3
	GasLow          uint64 = 5
	GasMid          uint64 = 8
	GasHigh         uint64 = 10
	GasKeccak256    uint64 = 30
	GasKeccakWord   uint64 = 6
	GasCopyWord     uint64 = 3
	GasLog          uint64 = 375
	GasLogTopic     uint64 = 375
	GasLogByte      uint64 = 8
	GasCreate       uint64 = 32000
	GasCodeDeposit  uint64 = 200
	GasCallValue    uint64 = 9000
	GasCallStipend  uint64 = 2300
	GasNewAccount   uint64 = 25000
	GasSelfDestruct uint64 = 5000
	GasExpByte      uint64 = 50
	GasMemoryWord   uint64 = 3
)

// EIP-2929 state access costs: the first touch of an account or slot pays for
// the disk read, later touches are nearly free.
const (
	GasColdAccountAccess uint64 = 2600
	GasColdSloadCost     uint64 = 2100
	GasWarmStorageRead   uint64 = 100
)

// Storage write costs under EIP-2200 net metering, adjusted by EIP-3529.
const (
	GasSstoreSet    uint64 = 20000 // zero -> nonzero
	GasSstoreReset  uint64 = 5000  // nonzero -> different nonzero
	GasSstoreClear  uint64 = 4800  // refund for nonzero -> zero
	GasSstoreRefund uint64 = 19900 // refund for restoring a slot to its original zero
)

// Protocol limits.
const (
	// MaxCodeSize caps deployed contract code (EIP-170).
	MaxCodeSize = 24576
	// MaxInitCodeSize caps the initialisation code of a creation (EIP-3860).
	MaxInitCodeSize = 2 * MaxCodeSize
	// GasInitCodeWord is charged per word of init code (EIP-3860).
	GasInitCodeWord uint64 = 2
	// MaxCallDepth is the deepest nesting of calls and creations.
	MaxCallDepth = 1024
	// RefundQuotient caps the refund at a fraction of gas used (EIP-3529).
	RefundQuotient uint64 = 5
)

// Transaction-level gas.
const (
	// TxGas is the intrinsic cost of any transaction.
	TxGas uint64 = 21000
	// TxGasContractCreation is the intrinsic cost of a creation transaction.
	TxGasContractCreation uint64 = 53000
	// TxDataZeroGas is charged per zero byte of call data.
	TxDataZeroGas uint64 = 4
	// TxDataNonZeroGas is charged per non-zero byte of call data.
	TxDataNonZeroGas uint64 = 16
	// TxAccessListAddressGas is charged per address in an access list.
	TxAccessListAddressGas uint64 = 2400
	// TxAccessListStorageKeyGas is charged per storage key in an access list.
	TxAccessListStorageKeyGas uint64 = 1900
)

// memoryGasCost returns the cost of growing memory to newSize bytes, given the
// cost already paid. The quadratic term is what makes large allocations
// prohibitively expensive.
func memoryGasCost(mem *Memory, newSize uint64) (uint64, error) {
	if newSize == 0 {
		return 0, nil
	}
	// Guard the squaring below against overflow.
	if newSize > 0x1FFFFFFFE0 {
		return 0, ErrGasUintOverflow
	}
	newWords := toWordSize(newSize)
	newTotal := newWords*GasMemoryWord + newWords*newWords/512

	if newTotal <= mem.lastGasCost {
		return 0, nil
	}
	fee := newTotal - mem.lastGasCost
	mem.lastGasCost = newTotal
	return fee, nil
}

// safeAdd adds with overflow detection.
func safeAdd(a, b uint64) (uint64, error) {
	sum := a + b
	if sum < a {
		return 0, ErrGasUintOverflow
	}
	return sum, nil
}

// safeMul multiplies with overflow detection.
func safeMul(a, b uint64) (uint64, error) {
	if a == 0 || b == 0 {
		return 0, nil
	}
	product := a * b
	if product/a != b {
		return 0, ErrGasUintOverflow
	}
	return product, nil
}

// memoryExtent converts an offset/size pair from the stack into the memory size
// required to cover it. A zero size never grows memory, whatever the offset.
func memoryExtent(offset, size *uint256.Int) (uint64, error) {
	if size.IsZero() {
		return 0, nil
	}
	if !offset.IsUint64() || !size.IsUint64() {
		return 0, ErrGasUintOverflow
	}
	return safeAdd(offset.Uint64(), size.Uint64())
}

// callGas implements the 63/64 rule of EIP-150: a caller can never forward all
// of its gas, which bounds how deep reentrancy can go before gas runs out.
func callGas(availableGas, base uint64, requested *uint256.Int) (uint64, error) {
	if availableGas < base {
		return 0, ErrOutOfGas
	}
	available := availableGas - base
	allowed := available - available/64

	if !requested.IsUint64() || requested.Uint64() > allowed {
		return allowed, nil
	}
	return requested.Uint64(), nil
}

// sstoreGas computes the cost and refund of a storage write under EIP-2200 net
// metering with the EIP-2929 cold/warm surcharge and EIP-3529 refunds.
//
// original is the value at the start of the transaction, current is the value
// now, and value is what is being written.
func sstoreGas(original, current, value common.Hash, cold bool) (cost uint64, refund int64) {
	if cold {
		cost += GasColdSloadCost
	}

	switch {
	case current == value:
		// No-op write: only the read is charged.
		cost += GasWarmStorageRead

	case original == current:
		// First write to this slot in the transaction.
		if original == (common.Hash{}) {
			cost += GasSstoreSet
		} else {
			cost += GasSstoreReset
			if value == (common.Hash{}) {
				refund += int64(GasSstoreClear)
			}
		}

	default:
		// The slot was already modified in this transaction, so the expensive
		// part is already paid for; only the warm read is charged, and earlier
		// refunds are adjusted to stay consistent with the final value.
		cost += GasWarmStorageRead
		if original != (common.Hash{}) {
			if current == (common.Hash{}) {
				refund -= int64(GasSstoreClear) // undo the clearing refund
			} else if value == (common.Hash{}) {
				refund += int64(GasSstoreClear)
			}
		}
		if original == value {
			// The slot ends up back where it started; refund the difference
			// between what was charged and what a no-op would have cost.
			if original == (common.Hash{}) {
				refund += int64(GasSstoreSet - GasWarmStorageRead)
			} else {
				refund += int64(GasSstoreReset - GasColdSloadCost - GasWarmStorageRead)
			}
		}
	}
	return cost, refund
}
