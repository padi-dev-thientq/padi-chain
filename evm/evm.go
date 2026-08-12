package evm

import (
	"errors"
	"fmt"
	"math/big"

	"layer1/common"
	"layer1/core"
	"layer1/rlp"
	"layer1/uint256"
)

// StateDB is the state interface the EVM needs. The concrete implementation
// lives in the state package; this narrower view keeps the EVM testable and
// breaks what would otherwise be an import cycle.
type StateDB interface {
	CreateAccount(common.Address)

	SubBalance(common.Address, *big.Int)
	AddBalance(common.Address, *big.Int)
	GetBalance(common.Address) *big.Int

	GetNonce(common.Address) uint64
	SetNonce(common.Address, uint64)

	GetCodeHash(common.Address) common.Hash
	GetCode(common.Address) []byte
	SetCode(common.Address, []byte)
	GetCodeSize(common.Address) int

	AddRefund(uint64)
	SubRefund(uint64)
	GetRefund() uint64

	GetCommittedState(common.Address, common.Hash) common.Hash
	GetState(common.Address, common.Hash) common.Hash
	SetState(common.Address, common.Hash, common.Hash)

	GetTransientState(common.Address, common.Hash) common.Hash
	SetTransientState(common.Address, common.Hash, common.Hash)

	SelfDestruct(common.Address)
	HasSelfDestructed(common.Address) bool

	Exist(common.Address) bool
	Empty(common.Address) bool

	AddressInAccessList(common.Address) bool
	SlotInAccessList(common.Address, common.Hash) (bool, bool)
	AddAddressToAccessList(common.Address)
	AddSlotToAccessList(common.Address, common.Hash)

	Snapshot() int
	RevertToSnapshot(int)

	AddLog(*core.Log)
}

// BlockContext is the block-level environment a transaction executes in.
type BlockContext struct {
	// CanTransfer reports whether an account holds at least the given amount.
	CanTransfer func(StateDB, common.Address, *big.Int) bool
	// Transfer moves value between accounts.
	Transfer func(StateDB, common.Address, common.Address, *big.Int)
	// GetHash returns the hash of the block at the given height, for BLOCKHASH.
	GetHash func(uint64) common.Hash

	Coinbase    common.Address
	GasLimit    uint64
	BlockNumber *big.Int
	Time        uint64
	BaseFee     *big.Int
	Random      common.Hash
}

// TxContext is the transaction-level environment.
type TxContext struct {
	Origin   common.Address
	GasPrice *big.Int
}

// Config tunes the interpreter.
type Config struct {
	// Tracer, if set, is called around every instruction.
	Tracer Tracer
	// NoBaseFee treats the base fee as zero, used for eth_call style
	// simulations where the caller has no funds.
	NoBaseFee bool
}

// ChainConfig identifies the chain the EVM is running for.
type ChainConfig struct {
	ChainID *big.Int
}

// EVM is the execution environment for one transaction.
type EVM struct {
	Context     BlockContext
	TxContext   TxContext
	StateDB     StateDB
	Config      Config
	ChainConfig *ChainConfig

	interpreter *Interpreter

	// depth is the current call nesting level.
	depth int
	// abort is set when execution must stop early.
	abort bool
	// readOnly marks that no state modification is permitted in this subtree.
	readOnly bool
}

// NewEVM builds an execution environment.
func NewEVM(blockCtx BlockContext, txCtx TxContext, statedb StateDB, chainConfig *ChainConfig, config Config) *EVM {
	evm := &EVM{
		Context:     blockCtx,
		TxContext:   txCtx,
		StateDB:     statedb,
		Config:      config,
		ChainConfig: chainConfig,
	}
	evm.interpreter = NewInterpreter(evm)
	return evm
}

// Reset prepares the EVM for another transaction in the same block.
func (evm *EVM) Reset(txCtx TxContext, statedb StateDB) {
	evm.TxContext = txCtx
	evm.StateDB = statedb
	evm.depth = 0
	evm.abort = false
	evm.readOnly = false
}

// Cancel aborts execution as soon as the interpreter checks.
func (evm *EVM) Cancel() { evm.abort = true }

// Depth returns the current call depth.
func (evm *EVM) Depth() int { return evm.depth }

// Interpreter exposes the bytecode interpreter.
func (evm *EVM) Interpreter() *Interpreter { return evm.interpreter }

// Call executes the code at addr with the given input and value.
//
// On failure the state is rolled back to a snapshot taken here, and all gas is
// consumed — except for a revert, which returns the remaining gas along with
// the revert data.
func (evm *EVM) Call(caller ContractRef, addr common.Address, input []byte, gas uint64, value *big.Int) (ret []byte, leftOverGas uint64, err error) {
	if evm.depth > MaxCallDepth {
		return nil, gas, ErrDepthLimit
	}
	if value.Sign() != 0 && !evm.Context.CanTransfer(evm.StateDB, caller.Address(), value) {
		return nil, gas, ErrInsufficientBalance
	}
	// A static frame may not move value.
	if evm.readOnly && value.Sign() != 0 {
		return nil, gas, ErrWriteProtection
	}

	snapshot := evm.StateDB.Snapshot()
	precompile, isPrecompile := evm.precompile(addr)

	if !evm.StateDB.Exist(addr) {
		if !isPrecompile && value.Sign() == 0 {
			// Calling a nonexistent account with no value is a no-op, and must
			// not create the account.
			return nil, gas, nil
		}
		evm.StateDB.CreateAccount(addr)
	}
	evm.Context.Transfer(evm.StateDB, caller.Address(), addr, value)

	if isPrecompile {
		ret, gas, err = runPrecompile(precompile, input, gas)
	} else {
		code := evm.StateDB.GetCode(addr)
		if len(code) == 0 {
			ret, err = nil, nil
		} else {
			contract := NewContract(caller, AccountRef(addr), fromBig(value), gas)
			contract.SetCallCode(&addr, evm.StateDB.GetCodeHash(addr), code)
			contract.Input = input
			ret, err = evm.interpreter.Run(contract, input, false)
			gas = contract.Gas
		}
	}

	if err != nil {
		evm.StateDB.RevertToSnapshot(snapshot)
		if !errors.Is(err, ErrExecutionReverted) {
			// Anything but an explicit revert burns the gas: it is the only
			// defence against a caller probing execution for free.
			gas = 0
		}
	}
	return ret, gas, err
}

// CallCode runs another account's code against the caller's own storage, with
// the caller's address as the executing address.
func (evm *EVM) CallCode(caller ContractRef, addr common.Address, input []byte, gas uint64, value *big.Int) (ret []byte, leftOverGas uint64, err error) {
	if evm.depth > MaxCallDepth {
		return nil, gas, ErrDepthLimit
	}
	if value.Sign() != 0 && !evm.Context.CanTransfer(evm.StateDB, caller.Address(), value) {
		return nil, gas, ErrInsufficientBalance
	}
	snapshot := evm.StateDB.Snapshot()

	if precompile, isPrecompile := evm.precompile(addr); isPrecompile {
		ret, gas, err = runPrecompile(precompile, input, gas)
	} else {
		contract := NewContract(caller, AccountRef(caller.Address()), fromBig(value), gas)
		contract.SetCallCode(&addr, evm.StateDB.GetCodeHash(addr), evm.StateDB.GetCode(addr))
		contract.Input = input
		ret, err = evm.interpreter.Run(contract, input, false)
		gas = contract.Gas
	}
	if err != nil {
		evm.StateDB.RevertToSnapshot(snapshot)
		if !errors.Is(err, ErrExecutionReverted) {
			gas = 0
		}
	}
	return ret, gas, err
}

// DelegateCall runs another account's code with the caller's storage, address
// and value — the mechanism behind upgradeable proxies and libraries.
func (evm *EVM) DelegateCall(caller ContractRef, addr common.Address, input []byte, gas uint64) (ret []byte, leftOverGas uint64, err error) {
	if evm.depth > MaxCallDepth {
		return nil, gas, ErrDepthLimit
	}
	snapshot := evm.StateDB.Snapshot()

	if precompile, isPrecompile := evm.precompile(addr); isPrecompile {
		ret, gas, err = runPrecompile(precompile, input, gas)
	} else {
		contract := NewContract(caller, AccountRef(caller.Address()), nil, gas).AsDelegate()
		contract.SetCallCode(&addr, evm.StateDB.GetCodeHash(addr), evm.StateDB.GetCode(addr))
		contract.Input = input
		ret, err = evm.interpreter.Run(contract, input, false)
		gas = contract.Gas
	}
	if err != nil {
		evm.StateDB.RevertToSnapshot(snapshot)
		if !errors.Is(err, ErrExecutionReverted) {
			gas = 0
		}
	}
	return ret, gas, err
}

// StaticCall executes code that is forbidden from modifying state.
func (evm *EVM) StaticCall(caller ContractRef, addr common.Address, input []byte, gas uint64) (ret []byte, leftOverGas uint64, err error) {
	if evm.depth > MaxCallDepth {
		return nil, gas, ErrDepthLimit
	}
	snapshot := evm.StateDB.Snapshot()

	if precompile, isPrecompile := evm.precompile(addr); isPrecompile {
		ret, gas, err = runPrecompile(precompile, input, gas)
	} else {
		contract := NewContract(caller, AccountRef(addr), new(uint256.Int), gas)
		contract.SetCallCode(&addr, evm.StateDB.GetCodeHash(addr), evm.StateDB.GetCode(addr))
		contract.Input = input
		ret, err = evm.interpreter.Run(contract, input, true)
		gas = contract.Gas
	}
	if err != nil {
		evm.StateDB.RevertToSnapshot(snapshot)
		if !errors.Is(err, ErrExecutionReverted) {
			gas = 0
		}
	}
	return ret, gas, err
}

// Create deploys a contract at an address derived from the sender and nonce.
func (evm *EVM) Create(caller ContractRef, code []byte, gas uint64, value *big.Int) (ret []byte, contractAddr common.Address, leftOverGas uint64, err error) {
	nonce := evm.StateDB.GetNonce(caller.Address())
	if nonce+1 < nonce {
		return nil, common.Address{}, gas, ErrNonceOverflow
	}
	contractAddr = CreateAddress(caller.Address(), nonce)
	return evm.create(caller, code, gas, value, contractAddr, CREATE)
}

// Create2 deploys a contract at an address derived from the sender, a salt and
// the init code, so the address can be computed before the deployment happens.
func (evm *EVM) Create2(caller ContractRef, code []byte, gas uint64, endowment *big.Int, salt *uint256.Int) (ret []byte, contractAddr common.Address, leftOverGas uint64, err error) {
	saltBytes := salt.Bytes32()
	contractAddr = CreateAddress2(caller.Address(), saltBytes, code)
	return evm.create(caller, code, gas, endowment, contractAddr, CREATE2)
}

func (evm *EVM) create(caller ContractRef, code []byte, gas uint64, value *big.Int, address common.Address, op OpCode) (ret []byte, contractAddr common.Address, leftOverGas uint64, err error) {
	if evm.depth > MaxCallDepth {
		return nil, common.Address{}, gas, ErrDepthLimit
	}
	if !evm.Context.CanTransfer(evm.StateDB, caller.Address(), value) {
		return nil, common.Address{}, gas, ErrInsufficientBalance
	}
	if evm.readOnly {
		return nil, common.Address{}, gas, ErrWriteProtection
	}

	// The creator's nonce increments whether or not the deployment succeeds,
	// so a failed creation cannot be retried at the same address.
	nonce := evm.StateDB.GetNonce(caller.Address())
	evm.StateDB.SetNonce(caller.Address(), nonce+1)

	// An address already carrying code or a nonce cannot be deployed over.
	contractHash := evm.StateDB.GetCodeHash(address)
	if evm.StateDB.GetNonce(address) != 0 ||
		(contractHash != (common.Hash{}) && contractHash != common.Hash(common.EmptyCodeHash)) {
		return nil, common.Address{}, 0, ErrContractAddressCollision
	}

	snapshot := evm.StateDB.Snapshot()
	evm.StateDB.CreateAccount(address)
	// EIP-161: a new contract starts at nonce 1, so its own CREATEs differ from
	// the address it was deployed at.
	evm.StateDB.SetNonce(address, 1)
	evm.Context.Transfer(evm.StateDB, caller.Address(), address, value)

	contract := NewContract(caller, AccountRef(address), fromBig(value), gas)
	contract.SetCallCode(&address, common.Keccak256(code), code)

	ret, err = evm.interpreter.Run(contract, nil, false)

	// Whatever the init code returns becomes the deployed code, charged per byte.
	if err == nil {
		if len(ret) > MaxCodeSize {
			err = ErrMaxCodeSizeExceeded
		} else if len(ret) > 0 && ret[0] == 0xEF {
			// EIP-3541 reserves this prefix for future EVM object formats.
			err = ErrInvalidCode
		} else {
			createDataGas := uint64(len(ret)) * GasCodeDeposit
			if !contract.UseGas(createDataGas) {
				err = ErrCodeStoreOutOfGas
			} else {
				evm.StateDB.SetCode(address, ret)
			}
		}
	}

	if err != nil {
		evm.StateDB.RevertToSnapshot(snapshot)
		if !errors.Is(err, ErrExecutionReverted) {
			contract.UseGas(contract.Gas)
		}
	}
	return ret, address, contract.Gas, err
}

// CreateAddress derives the address of a contract created by sender at nonce.
func CreateAddress(sender common.Address, nonce uint64) common.Address {
	enc, err := rlp.Encode([]any{sender, nonce})
	if err != nil {
		panic(fmt.Sprintf("evm: encoding creation address: %v", err))
	}
	return common.BytesToAddress(common.Keccak256(enc).Bytes()[12:])
}

// CreateAddress2 derives a CREATE2 address, which depends only on the sender,
// the salt and the init code — never on the sender's nonce.
func CreateAddress2(sender common.Address, salt [32]byte, initCode []byte) common.Address {
	codeHash := common.Keccak256(initCode)
	h := common.Keccak256([]byte{0xff}, sender[:], salt[:], codeHash[:])
	return common.BytesToAddress(h.Bytes()[12:])
}

// fromBig converts a big.Int amount to the EVM's word type.
func fromBig(v *big.Int) *uint256.Int {
	if v == nil {
		return new(uint256.Int)
	}
	return uint256.FromBig(v)
}

// CanTransfer reports whether an account can afford an amount.
func CanTransfer(db StateDB, addr common.Address, amount *big.Int) bool {
	return db.GetBalance(addr).Cmp(amount) >= 0
}

// Transfer moves value between two accounts.
func Transfer(db StateDB, sender, recipient common.Address, amount *big.Int) {
	if amount.Sign() == 0 {
		return
	}
	db.SubBalance(sender, amount)
	db.AddBalance(recipient, amount)
}
