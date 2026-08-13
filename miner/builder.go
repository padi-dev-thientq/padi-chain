// Package miner assembles blocks from pending transactions.
package miner

import (
	"errors"
	"fmt"
	"math/big"
	"time"

	"padi-chain/chain"
	"padi-chain/common"
	"padi-chain/consensus"
	"padi-chain/core"
	"padi-chain/crypto/bls12381"
	"padi-chain/crypto/secp256k1"
	"padi-chain/evm"
	"padi-chain/processor"
	"padi-chain/staking"
	"padi-chain/state"
)

// ErrNotOurTurn means this validator may not propose the next block yet.
var ErrNotOurTurn = errors.New("miner: not this validator's turn to propose")

// Builder constructs blocks on top of the chain head.
type Builder struct {
	chain  *chain.BlockChain
	engine consensus.Engine
	key    *secp256k1.PrivateKey
	// blsKey signs the randomness reveal every block carries.
	blsKey *bls12381.SecretKey
	// coinbase is the address fees are credited to; it must be the validator's.
	coinbase common.Address
	// attestations supplies the quorum certificate a new block carries, which
	// is how finality reaches nodes that were not online to collect the votes.
	attestations *consensus.AttestationPool
}

// SetBLSKey attaches the key the proposer reveals randomness with. Without it
// a block carries no reveal and contributes nothing to the mix.
func (b *Builder) SetBLSKey(key *bls12381.SecretKey) { b.blsKey = key }

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
		Extra:      []byte("padi-chain"),
	}
	if err := b.engine.Prepare(b.chain, header); err != nil {
		return nil, err
	}

	// Reveal this proposer's randomness contribution. It signs the epoch, not
	// the block, so it is fixed before the proposer knows what it will build.
	if b.blsKey != nil {
		header.RandaoReveal = core.SignRandaoReveal(b.blsKey, config.ChainID, staking.EpochOf(next))
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

	// Fold in the randomness reveal, then run the end-of-epoch transition —
	// the same operations a verifier performs, in the same order. Skipping
	// either would produce a state root nobody else agrees with.
	if err := proc.ApplyRandao(statedb, header); err != nil {
		return nil, fmt.Errorf("miner: randao: %w", err)
	}

	// Run the same end-of-epoch transition a verifier will run. Skipping it
	// here would produce a state root nobody else agrees with.
	if _, err := proc.ProcessEpochBoundary(statedb, header, b.chain.FinalizedNumber()); err != nil {
		return nil, fmt.Errorf("miner: epoch transition: %w", err)
	}

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
