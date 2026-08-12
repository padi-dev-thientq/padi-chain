package processor

import (
	"errors"
	"fmt"
	"math/big"

	"layer1/common"
	"layer1/core"
	"layer1/evm"
	"layer1/state"
)

// ChainContext gives the processor access to the chain it is extending, which
// the BLOCKHASH instruction needs.
type ChainContext interface {
	GetHeaderByNumber(number uint64) *core.Header
}

// Config is the chain's execution parameters.
type Config struct {
	ChainID *big.Int
	// ElasticityMultiplier is how far a block may exceed the gas target.
	ElasticityMultiplier uint64
	// BaseFeeChangeDenominator bounds how fast the base fee can move per block.
	BaseFeeChangeDenominator uint64
	// MinBaseFee is the floor the base fee never drops below.
	MinBaseFee *big.Int
}

// DefaultConfig returns the standard fee-market parameters.
func DefaultConfig(chainID *big.Int) *Config {
	return &Config{
		ChainID:                  chainID,
		ElasticityMultiplier:     2,
		BaseFeeChangeDenominator: 8,
		MinBaseFee:               big.NewInt(1_000_000_000),
	}
}

// Processor applies whole blocks.
type Processor struct {
	config *Config
	chain  ChainContext
	signer *core.Signer
}

// NewProcessor builds a block processor.
func NewProcessor(config *Config, chain ChainContext) *Processor {
	return &Processor{
		config: config,
		chain:  chain,
		signer: core.NewSigner(config.ChainID),
	}
}

// Signer returns the transaction signer for this chain.
func (p *Processor) Signer() *core.Signer { return p.signer }

// Config returns the chain configuration.
func (p *Processor) Config() *Config { return p.config }

// Process executes every transaction in a block against statedb and returns
// the receipts, the logs and the total gas used. It does not commit: the caller
// decides whether the resulting state is accepted.
func (p *Processor) Process(block *core.Block, statedb *state.StateDB) (core.Receipts, []*core.Log, uint64, error) {
	var (
		receipts     core.Receipts
		logs         []*core.Log
		usedGas      uint64
		gasPool      = new(GasPool).AddGas(block.GasLimit())
		header       = block.Header()
		blockContext = p.NewBlockContext(header)
	)

	vm := evm.NewEVM(blockContext, evm.TxContext{}, statedb, &evm.ChainConfig{ChainID: p.config.ChainID}, evm.Config{})

	for i, tx := range block.Transactions() {
		statedb.SetTxContext(tx.Hash(), i)
		receipt, err := p.applyTransaction(vm, tx, statedb, gasPool, &usedGas, header)
		if err != nil {
			return nil, nil, 0, fmt.Errorf("processor: transaction %d (%s): %w", i, tx.Hash(), err)
		}
		receipts = append(receipts, receipt)
		logs = append(logs, receipt.Logs...)
	}

	if usedGas != block.GasUsed() {
		return nil, nil, 0, fmt.Errorf("processor: block claims %d gas used, execution used %d", block.GasUsed(), usedGas)
	}
	return receipts, logs, usedGas, nil
}

// ApplyTransaction executes one transaction against statedb, updating usedGas
// and returning its receipt. Used both when building a block and when
// verifying one.
func (p *Processor) ApplyTransaction(vm *evm.EVM, tx *core.Transaction, statedb *state.StateDB, gp *GasPool, usedGas *uint64, header *core.Header) (*core.Receipt, error) {
	return p.applyTransaction(vm, tx, statedb, gp, usedGas, header)
}

func (p *Processor) applyTransaction(vm *evm.EVM, tx *core.Transaction, statedb *state.StateDB, gp *GasPool, usedGas *uint64, header *core.Header) (*core.Receipt, error) {
	msg, err := MessageFromTx(tx, p.signer, header.BaseFee)
	if err != nil {
		return nil, err
	}

	vm.Reset(evm.TxContext{Origin: msg.From, GasPrice: msg.GasPrice}, statedb)

	result, err := ApplyMessage(vm, msg, gp, statedb)
	if err != nil {
		return nil, err
	}

	// Finalising here is what makes each transaction's state changes visible
	// to the next one while keeping their journals separate.
	statedb.Finalise(true)
	*usedGas += result.UsedGas

	status := core.ReceiptStatusSuccessful
	if result.Failed() {
		status = core.ReceiptStatusFailed
	}
	receipt := core.NewReceipt(tx.Type(), status, *usedGas, statedb.GetLogs(tx.Hash()))
	receipt.TxHash = tx.Hash()
	receipt.GasUsed = result.UsedGas
	receipt.EffectiveGasPrice = msg.GasPrice
	if tx.IsContractCreation() {
		receipt.ContractAddress = evm.CreateAddress(msg.From, tx.Nonce())
	}
	receipt.BlockNumber = header.Number
	return receipt, nil
}

// NewBlockContext builds the EVM's view of the block being executed.
func (p *Processor) NewBlockContext(header *core.Header) evm.BlockContext {
	return evm.BlockContext{
		CanTransfer: evm.CanTransfer,
		Transfer:    evm.Transfer,
		GetHash:     p.getHashFn(),
		Coinbase:    header.Coinbase,
		GasLimit:    header.GasLimit,
		BlockNumber: new(big.Int).Set(header.Number),
		Time:        header.Time,
		BaseFee:     new(big.Int).Set(header.BaseFee),
		Random:      common.Keccak256(header.ParentHash[:], header.Extra),
	}
}

func (p *Processor) getHashFn() func(uint64) common.Hash {
	return func(number uint64) common.Hash {
		if p.chain == nil {
			return common.Hash{}
		}
		header := p.chain.GetHeaderByNumber(number)
		if header == nil {
			return common.Hash{}
		}
		return header.Hash()
	}
}

// CalcBaseFee derives a block's base fee from its parent, moving it toward the
// gas target: blocks fuller than the target raise it, emptier blocks lower it.
// The change is capped per block, so the fee moves smoothly rather than
// spiking.
func (c *Config) CalcBaseFee(parent *core.Header) *big.Int {
	if parent == nil {
		return new(big.Int).Set(c.MinBaseFee)
	}
	parentBaseFee := parent.BaseFee
	if parentBaseFee == nil || parentBaseFee.Sign() == 0 {
		return new(big.Int).Set(c.MinBaseFee)
	}

	target := parent.GasLimit / c.ElasticityMultiplier
	if target == 0 {
		return new(big.Int).Set(parentBaseFee)
	}

	switch {
	case parent.GasUsed == target:
		return new(big.Int).Set(parentBaseFee)

	case parent.GasUsed > target:
		delta := parent.GasUsed - target
		change := new(big.Int).Mul(parentBaseFee, new(big.Int).SetUint64(delta))
		change.Div(change, new(big.Int).SetUint64(target))
		change.Div(change, new(big.Int).SetUint64(c.BaseFeeChangeDenominator))
		// Always move by at least one wei, so a persistently full chain keeps
		// getting more expensive.
		if change.Sign() == 0 {
			change.SetInt64(1)
		}
		return new(big.Int).Add(parentBaseFee, change)

	default:
		delta := target - parent.GasUsed
		change := new(big.Int).Mul(parentBaseFee, new(big.Int).SetUint64(delta))
		change.Div(change, new(big.Int).SetUint64(target))
		change.Div(change, new(big.Int).SetUint64(c.BaseFeeChangeDenominator))
		fee := new(big.Int).Sub(parentBaseFee, change)
		if fee.Cmp(c.MinBaseFee) < 0 {
			return new(big.Int).Set(c.MinBaseFee)
		}
		return fee
	}
}

// VerifyBaseFee checks that a header's base fee follows from its parent.
func (c *Config) VerifyBaseFee(header, parent *core.Header) error {
	want := c.CalcBaseFee(parent)
	if header.BaseFee == nil || header.BaseFee.Cmp(want) != 0 {
		return fmt.Errorf("processor: base fee is %v, expected %v", header.BaseFee, want)
	}
	return nil
}

// ErrGasLimitDelta reports a gas limit that moved too far in one block.
var ErrGasLimitDelta = errors.New("processor: gas limit changed too much between blocks")

// GasLimitBoundDivisor bounds how fast the gas limit may drift.
const GasLimitBoundDivisor = 1024

// MinGasLimit is the floor for a block's gas limit.
const MinGasLimit = 5000

// VerifyGasLimit checks that a block's gas limit is a legal step from its
// parent's, which stops a single proposer from changing capacity abruptly.
func VerifyGasLimit(parentLimit, limit uint64) error {
	if limit < MinGasLimit {
		return fmt.Errorf("processor: gas limit %d is below the minimum %d", limit, MinGasLimit)
	}
	var diff uint64
	if limit > parentLimit {
		diff = limit - parentLimit
	} else {
		diff = parentLimit - limit
	}
	if diff >= parentLimit/GasLimitBoundDivisor {
		return fmt.Errorf("%w: %d -> %d", ErrGasLimitDelta, parentLimit, limit)
	}
	return nil
}
