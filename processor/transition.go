// Package processor applies transactions and blocks to the world state.
package processor

import (
	"errors"
	"fmt"
	"math/big"

	"layer1/common"
	"layer1/core"
	"layer1/evm"
	"layer1/staking"
	"layer1/state"
)

// Errors that make a transaction inadmissible. These are checked before any
// execution, so a rejected transaction has no effect and pays nothing.
var (
	ErrNonceTooLow        = errors.New("processor: nonce too low")
	ErrNonceTooHigh       = errors.New("processor: nonce too high")
	ErrInsufficientFunds  = errors.New("processor: insufficient funds for gas * price + value")
	ErrIntrinsicGas       = errors.New("processor: gas limit below the intrinsic cost")
	ErrGasLimitReached    = errors.New("processor: block gas limit reached")
	ErrSenderNotEOA       = errors.New("processor: sender has contract code")
	ErrFeeCapBelowBaseFee = errors.New("processor: max fee per gas is below the block base fee")
	ErrTipAboveFeeCap     = errors.New("processor: priority fee exceeds the max fee per gas")
	ErrInitCodeTooLarge   = errors.New("processor: init code exceeds the maximum size")
)

// ExecutionResult reports the outcome of running one transaction.
type ExecutionResult struct {
	UsedGas    uint64
	Err        error  // the reason execution stopped, nil on success
	ReturnData []byte // output of the top-level frame
}

// Failed reports whether execution reverted or faulted.
func (r *ExecutionResult) Failed() bool { return r.Err != nil }

// Revert returns the revert data, if any.
func (r *ExecutionResult) Revert() []byte {
	if !errors.Is(r.Err, evm.ErrExecutionReverted) {
		return nil
	}
	return r.ReturnData
}

// Message is a transaction reduced to what execution needs. Decoupling the two
// lets eth_call run a synthetic message that was never signed.
type Message struct {
	From       common.Address
	To         *common.Address
	Nonce      uint64
	Value      *big.Int
	GasLimit   uint64
	GasPrice   *big.Int
	GasFeeCap  *big.Int
	GasTipCap  *big.Int
	Data       []byte
	AccessList core.AccessList
	// SkipChecks bypasses nonce and balance validation, for simulated calls.
	SkipChecks bool
}

// MessageFromTx converts a signed transaction into a message.
func MessageFromTx(tx *core.Transaction, signer *core.Signer, baseFee *big.Int) (*Message, error) {
	from, err := signer.Sender(tx)
	if err != nil {
		return nil, err
	}
	return &Message{
		From:       from,
		To:         tx.To(),
		Nonce:      tx.Nonce(),
		Value:      tx.Value(),
		GasLimit:   tx.Gas(),
		GasPrice:   tx.EffectiveGasPrice(baseFee),
		GasFeeCap:  tx.GasFeeCap(),
		GasTipCap:  tx.GasTipCap(),
		Data:       tx.Data(),
		AccessList: tx.AccessList(),
	}, nil
}

// GasPool tracks the gas still available in the block being built or verified.
type GasPool uint64

// AddGas returns gas to the pool.
func (gp *GasPool) AddGas(amount uint64) *GasPool {
	*gp += GasPool(amount)
	return gp
}

// SubGas takes gas from the pool.
func (gp *GasPool) SubGas(amount uint64) error {
	if uint64(*gp) < amount {
		return fmt.Errorf("%w: %d requested, %d remaining", ErrGasLimitReached, amount, uint64(*gp))
	}
	*gp -= GasPool(amount)
	return nil
}

// Gas returns the remaining gas.
func (gp *GasPool) Gas() uint64 { return uint64(*gp) }

// IntrinsicGas is the cost a transaction owes before any code runs: a flat fee,
// a charge per byte of call data, and the access list.
func IntrinsicGas(data []byte, accessList core.AccessList, isContractCreation bool) (uint64, error) {
	gas := evm.TxGas
	if isContractCreation {
		gas = evm.TxGasContractCreation
	}

	if len(data) > 0 {
		var nonZero uint64
		for _, b := range data {
			if b != 0 {
				nonZero++
			}
		}
		zero := uint64(len(data)) - nonZero

		// Overflow here would let a huge payload be charged nothing.
		if (^uint64(0)-gas)/evm.TxDataNonZeroGas < nonZero {
			return 0, evm.ErrGasUintOverflow
		}
		gas += nonZero * evm.TxDataNonZeroGas
		if (^uint64(0)-gas)/evm.TxDataZeroGas < zero {
			return 0, evm.ErrGasUintOverflow
		}
		gas += zero * evm.TxDataZeroGas

		if isContractCreation {
			words := uint64((len(data) + 31) / 32)
			if (^uint64(0)-gas)/evm.GasInitCodeWord < words {
				return 0, evm.ErrGasUintOverflow
			}
			gas += words * evm.GasInitCodeWord
		}
	}

	if len(accessList) > 0 {
		gas += uint64(len(accessList)) * evm.TxAccessListAddressGas
		gas += uint64(accessList.StorageKeyCount()) * evm.TxAccessListStorageKeyGas
	}
	return gas, nil
}

// StateTransition applies a single message to the state.
type StateTransition struct {
	evm        *evm.EVM
	msg        *Message
	state      *state.StateDB
	gasPool    *GasPool
	gas        uint64
	initialGas uint64
}

// NewStateTransition prepares to apply msg.
func NewStateTransition(vm *evm.EVM, msg *Message, gp *GasPool, statedb *state.StateDB) *StateTransition {
	return &StateTransition{evm: vm, msg: msg, gasPool: gp, state: statedb}
}

// ApplyMessage runs a message to completion and returns the result. The state
// is modified in place; on a failed execution only the gas payment remains.
func ApplyMessage(vm *evm.EVM, msg *Message, gp *GasPool, statedb *state.StateDB) (*ExecutionResult, error) {
	return NewStateTransition(vm, msg, gp, statedb).run()
}

func (st *StateTransition) run() (*ExecutionResult, error) {
	if err := st.preCheck(); err != nil {
		return nil, err
	}

	msg := st.msg
	isCreate := msg.To == nil

	intrinsic, err := IntrinsicGas(msg.Data, msg.AccessList, isCreate)
	if err != nil {
		return nil, err
	}
	if st.gas < intrinsic {
		return nil, fmt.Errorf("%w: have %d, need %d", ErrIntrinsicGas, st.gas, intrinsic)
	}
	st.gas -= intrinsic

	if isCreate && len(msg.Data) > evm.MaxInitCodeSize {
		return nil, fmt.Errorf("%w: %d bytes exceeds %d", ErrInitCodeTooLarge, len(msg.Data), evm.MaxInitCodeSize)
	}

	// Warm the addresses that are always touched, so they are not charged the
	// cold-access surcharge.
	st.state.Prepare(msg.From, st.evm.Context.Coinbase, msg.To, evm.PrecompileAddresses(), msg.AccessList)

	// A staking operation is executed by the protocol rather than the EVM, so
	// the registry's invariants live in one place and cannot be disturbed by a
	// contract.
	if IsStakingCall(msg) {
		return st.runStakingCall()
	}

	var (
		ret   []byte
		vmErr error
	)
	if isCreate {
		ret, _, st.gas, vmErr = st.evm.Create(evm.AccountRef(msg.From), msg.Data, st.gas, msg.Value)
	} else {
		// The sender's nonce increments before the call, so a contract the
		// transaction creates sees the post-increment value.
		st.state.SetNonce(msg.From, st.state.GetNonce(msg.From)+1)
		ret, st.gas, vmErr = st.evm.Call(evm.AccountRef(msg.From), *msg.To, msg.Data, st.gas, msg.Value)
	}

	st.refundGas()
	st.payProposer()

	return &ExecutionResult{
		UsedGas:    st.gasUsed(),
		Err:        vmErr,
		ReturnData: ret,
	}, nil
}

// runStakingCall applies a staking operation, moving the value it carries into
// the staking account first.
//
// A rejected operation is reverted but still charged: submitting an invalid
// deposit or a forged slashing report has to cost something, or the mempool
// becomes free to spam.
func (st *StateTransition) runStakingCall() (*ExecutionResult, error) {
	msg := st.msg
	epoch := stakingEpochOf(st.evm.Context.BlockNumber)

	st.state.SetNonce(msg.From, st.state.GetNonce(msg.From)+1)
	snapshot := st.state.Snapshot()

	var opErr error
	if msg.Value.Sign() > 0 {
		if st.state.GetBalance(msg.From).Cmp(msg.Value) < 0 {
			opErr = ErrInsufficientFunds
		} else {
			st.state.SubBalance(msg.From, msg.Value)
			st.state.AddBalance(staking.StakingAddress, msg.Value)
		}
	}

	cost := GasExit // the cheapest operation, charged even when the call fails
	if opErr == nil {
		used, err := st.applyStakingCall(epoch)
		opErr = err
		if used > cost {
			cost = used
		}
	}

	if !st.useGas(cost) {
		st.state.RevertToSnapshot(snapshot)
		st.gas = 0
		st.refundGas()
		st.payProposer()
		return &ExecutionResult{UsedGas: st.gasUsed(), Err: evm.ErrOutOfGas}, nil
	}
	if opErr != nil {
		st.state.RevertToSnapshot(snapshot)
	}

	st.refundGas()
	st.payProposer()
	return &ExecutionResult{UsedGas: st.gasUsed(), Err: opErr}, nil
}

// useGas deducts gas from the transaction's remaining budget.
func (st *StateTransition) useGas(amount uint64) bool {
	if st.gas < amount {
		return false
	}
	st.gas -= amount
	return true
}

// stakingEpochOf returns the epoch a block belongs to.
func stakingEpochOf(blockNumber *big.Int) uint64 {
	return staking.EpochOf(blockNumber.Uint64())
}

// preCheck validates the message and charges the sender for the gas up front.
func (st *StateTransition) preCheck() error {
	msg := st.msg

	if !msg.SkipChecks {
		stateNonce := st.state.GetNonce(msg.From)
		switch {
		case stateNonce < msg.Nonce:
			return fmt.Errorf("%w: address %s has nonce %d, transaction has %d", ErrNonceTooHigh, msg.From, stateNonce, msg.Nonce)
		case stateNonce > msg.Nonce:
			return fmt.Errorf("%w: address %s has nonce %d, transaction has %d", ErrNonceTooLow, msg.From, stateNonce, msg.Nonce)
		}

		// EIP-3607: an account with code cannot originate a transaction, which
		// stops a contract address from being impersonated.
		codeHash := st.state.GetCodeHash(msg.From)
		if codeHash != (common.Hash{}) && codeHash != common.Hash(common.EmptyCodeHash) {
			return fmt.Errorf("%w: %s", ErrSenderNotEOA, msg.From)
		}

		if msg.GasFeeCap != nil && msg.GasTipCap != nil && msg.GasFeeCap.Cmp(msg.GasTipCap) < 0 {
			return fmt.Errorf("%w: fee cap %s, tip cap %s", ErrTipAboveFeeCap, msg.GasFeeCap, msg.GasTipCap)
		}
		if baseFee := st.evm.Context.BaseFee; baseFee != nil && !st.evm.Config.NoBaseFee {
			if msg.GasFeeCap != nil && msg.GasFeeCap.Cmp(baseFee) < 0 {
				return fmt.Errorf("%w: fee cap %s, base fee %s", ErrFeeCapBelowBaseFee, msg.GasFeeCap, baseFee)
			}
		}
	}
	return st.buyGas()
}

// buyGas debits the sender for the maximum the transaction could cost and
// reserves the gas from the block's pool.
func (st *StateTransition) buyGas() error {
	msg := st.msg

	feeCap := msg.GasFeeCap
	if feeCap == nil {
		feeCap = msg.GasPrice
	}
	maxCost := new(big.Int).Mul(new(big.Int).SetUint64(msg.GasLimit), feeCap)
	total := new(big.Int).Add(maxCost, msg.Value)

	if !msg.SkipChecks {
		if have := st.state.GetBalance(msg.From); have.Cmp(total) < 0 {
			return fmt.Errorf("%w: address %s has %s, needs %s", ErrInsufficientFunds, msg.From, have, total)
		}
	}
	if err := st.gasPool.SubGas(msg.GasLimit); err != nil {
		return err
	}

	st.gas = msg.GasLimit
	st.initialGas = msg.GasLimit
	if !msg.SkipChecks {
		st.state.SubBalance(msg.From, maxCost)
	}
	return nil
}

// gasUsed returns the gas consumed so far.
func (st *StateTransition) gasUsed() uint64 { return st.initialGas - st.gas }

// refundGas returns unused gas to the sender, plus the storage refund capped at
// a fifth of the gas used (EIP-3529).
func (st *StateTransition) refundGas() {
	refund := st.state.GetRefund()
	if cap := st.gasUsed() / evm.RefundQuotient; refund > cap {
		refund = cap
	}
	st.gas += refund

	if !st.msg.SkipChecks {
		remaining := new(big.Int).Mul(new(big.Int).SetUint64(st.gas), st.effectiveFeeCap())
		st.state.AddBalance(st.msg.From, remaining)
	}
	// Unused gas goes back to the block, so later transactions can use it.
	st.gasPool.AddGas(st.gas)
}

func (st *StateTransition) effectiveFeeCap() *big.Int {
	if st.msg.GasFeeCap != nil {
		return st.msg.GasFeeCap
	}
	return st.msg.GasPrice
}

// payProposer credits the proposer with the priority fee. The base fee is not
// paid to anyone: it is burned, which is what ties issuance to demand.
func (st *StateTransition) payProposer() {
	if st.msg.SkipChecks {
		return
	}
	tip := new(big.Int).Set(st.msg.GasPrice)
	if baseFee := st.evm.Context.BaseFee; baseFee != nil && !st.evm.Config.NoBaseFee {
		tip = new(big.Int).Sub(st.msg.GasPrice, baseFee)
		if tip.Sign() < 0 {
			tip.SetInt64(0)
		}
	}
	fee := new(big.Int).Mul(new(big.Int).SetUint64(st.gasUsed()), tip)
	st.state.AddBalance(st.evm.Context.Coinbase, fee)

	// The sender paid the fee cap up front; return the difference between that
	// and the effective price.
	overpaid := new(big.Int).Sub(st.effectiveFeeCap(), st.msg.GasPrice)
	if overpaid.Sign() > 0 {
		st.state.AddBalance(st.msg.From, new(big.Int).Mul(new(big.Int).SetUint64(st.gasUsed()), overpaid))
	}
}
