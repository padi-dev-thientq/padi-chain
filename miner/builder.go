// Package miner assembles blocks from pending transactions.
package miner

import (
	"errors"
	"fmt"
	"math/big"
	"time"

	"layer1/chain"
	"layer1/common"
	"layer1/consensus"
	"layer1/core"
	"layer1/crypto/secp256k1"
	"layer1/evm"
	"layer1/processor"
	"layer1/state"
)

// ErrNotOurTurn means this validator may not propose the next block yet.
var ErrNotOurTurn = errors.New("miner: not this validator's turn to propose")

// Builder constructs blocks on top of the chain head.
type Builder struct {
	chain  *chain.BlockChain
	engine consensus.Engine
	key    *secp256k1.PrivateKey
	// coinbase is the address fees are credited to; it must be the validator's.
	coinbase common.Address
	// attestations supplies the quorum certificate a new block carries, which
	// is how finality reaches nodes that were not online to collect the votes.
	attestations *consensus.AttestationPool
}

// SetAttestationPool attaches the pool a block's justification is drawn from.
func (b *Builder) SetAttestationPool(pool *consensus.AttestationPool) {
	b.attestations = pool
}

// NewBuilder creates a block builder for a validator key.
func NewBuilder(bc *chain.BlockChain, engine consensus.Engine, key *secp256k1.PrivateKey) *Builder {
	coinbase := common.BytesToAddress(common.Keccak256(key.PublicKey().Bytes()).Bytes()[12:])
	return &Builder{chain: bc, engine: engine, key: key, coinbase: coinbase}
}

// Coinbase returns the validator's address.
func (b *Builder) Coinbase() common.Address { return b.coinbase }

// Result is a freshly built block and everything derived from it.
type Result struct {
	Block    *core.Block
	Receipts core.Receipts
	State    *state.StateDB
	// Included and Rejected split the candidate transactions by outcome.
	Included core.Transactions
	Rejected []RejectedTx
}

// RejectedTx records why a candidate transaction did not make it into a block.
type RejectedTx struct {
	Tx  *core.Transaction
	Err error
}

// BuildBlock assembles a block containing as many of the candidate
// transactions as fit, seals it, and returns it without inserting it.
func (b *Builder) BuildBlock(candidates core.Transactions) (*Result, error) {
	parent := b.chain.CurrentBlock()
	parentHeader := parent.Header()
	next := parent.NumberU64() + 1

	if !b.engineIsOurTurn(next, parentHeader.Time) {
		proposer, _ := b.engine.ProposerAt(next)
		return nil, fmt.Errorf("%w: block %d belongs to %s", ErrNotOurTurn, next, proposer)
	}

	config := b.chain.Config()
	header := &core.Header{
		ParentHash: parent.Hash(),
		Number:     new(big.Int).SetUint64(next),
		GasLimit:   parentHeader.GasLimit,
		BaseFee:    config.CalcBaseFee(parentHeader),
		Extra:      []byte("layer1"),
	}
	if err := b.engine.Prepare(b.chain, header); err != nil {
		return nil, err
	}

	// Carry proof that the parent is final, when the votes are in. Embedding it
	// makes finality part of the chain rather than per-node local knowledge.
	if b.attestations != nil {
		if qc := b.attestations.Certificate(parent.NumberU64(), parent.Hash()); qc != nil {
			encoded, err := qc.Encode()
			if err != nil {
				return nil, err
			}
			header.Justification = encoded
		}
	}

	statedb, err := b.chain.StateAt(parent.StateRoot())
	if err != nil {
		return nil, fmt.Errorf("miner: loading parent state: %w", err)
	}

	proc := b.chain.Processor()
	gasPool := new(processor.GasPool).AddGas(header.GasLimit)
	vm := evm.NewEVM(proc.NewBlockContext(header), evm.TxContext{}, statedb,
		&evm.ChainConfig{ChainID: config.ChainID}, evm.Config{})

	var (
		included core.Transactions
		receipts core.Receipts
		rejected []RejectedTx
		usedGas  uint64
	)

	for _, tx := range candidates {
		// Leave the block rather than fail it when gas runs out; the
		// transaction stays pending for a later block.
		if gasPool.Gas() < tx.Gas() {
			rejected = append(rejected, RejectedTx{Tx: tx, Err: processor.ErrGasLimitReached})
			continue
		}
		// Take a snapshot so a transaction that turns out to be inapplicable
		// leaves no trace in the block being built.
		snapshot := statedb.Snapshot()
		statedb.SetTxContext(tx.Hash(), len(included))

		receipt, err := proc.ApplyTransaction(vm, tx, statedb, gasPool, &usedGas, header)
		if err != nil {
			statedb.RevertToSnapshot(snapshot)
			rejected = append(rejected, RejectedTx{Tx: tx, Err: err})
			continue
		}
		included = append(included, tx)
		receipts = append(receipts, receipt)
	}

	header.GasUsed = usedGas

	// The state root has to be computed before the block is sealed, since the
	// seal signs the header that contains it.
	root, err := statedb.Commit(true)
	if err != nil {
		return nil, fmt.Errorf("miner: committing state: %w", err)
	}
	header.StateRoot = root

	block := core.NewBlock(header, included, receipts)
	sealed, err := b.engine.Seal(block, b.key)
	if err != nil {
		return nil, err
	}

	return &Result{
		Block:    sealed,
		Receipts: receipts,
		State:    statedb,
		Included: included,
		Rejected: rejected,
	}, nil
}

// engineIsOurTurn reports whether this validator may propose, accounting for
// any fallback rounds that have opened since the parent.
func (b *Builder) engineIsOurTurn(number, parentTime uint64) bool {
	if poa, ok := b.engine.(*consensus.PoA); ok {
		return poa.IsMyTurn(b.coinbase, number, parentTime)
	}
	proposer, err := b.engine.ProposerAt(number)
	return err == nil && proposer == b.coinbase
}

// Commit builds a block and inserts it into the chain.
func (b *Builder) Commit(candidates core.Transactions) (*Result, error) {
	result, err := b.BuildBlock(candidates)
	if err != nil {
		return nil, err
	}
	if err := b.chain.InsertBlock(result.Block); err != nil {
		return nil, err
	}
	return result, nil
}

// WaitUntilTurn blocks until this validator may propose the next block, or
// until the deadline passes.
func (b *Builder) WaitUntilTurn(timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		head := b.chain.CurrentBlock()
		if b.engineIsOurTurn(head.NumberU64()+1, head.Time()) {
			return nil
		}
		time.Sleep(50 * time.Millisecond)
	}
	return ErrNotOurTurn
}
