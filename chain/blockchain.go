package chain

import (
	"errors"
	"fmt"
	"math/big"
	"sync"

	"layer1/common"
	"layer1/consensus"
	"layer1/core"
	"layer1/db"
	"layer1/processor"
	"layer1/state"
	"layer1/trie"
)

var (
	ErrKnownBlock          = errors.New("chain: block is already known")
	ErrUnknownAncestor     = errors.New("chain: parent block is unknown")
	ErrStateRootMismatch   = errors.New("chain: state root does not match execution")
	ErrReceiptRootMismatch = errors.New("chain: receipt root does not match execution")
	ErrGenesisMismatch     = errors.New("chain: store belongs to a different genesis")
	ErrBlockTooLarge       = errors.New("chain: block gas used exceeds its limit")
)

// BlockChain holds the canonical chain and the state that goes with it.
//
// Blocks arrive from the network or the local proposer; each is verified,
// executed, and only then written. When a competing branch grows longer, the
// chain reorganises onto it.
type BlockChain struct {
	mu sync.RWMutex

	store     db.Database
	engine    consensus.Engine
	processor *processor.Processor
	config    *processor.Config

	genesis   *core.Block
	current   *core.Block
	finalized *core.Block

	// subscribers are notified after every canonical head change.
	subMu       sync.Mutex
	subscribers []chan<- ChainEvent
}

// ChainEvent describes a change to the canonical chain.
type ChainEvent struct {
	Block    *core.Block
	Receipts core.Receipts
	Logs     []*core.Log
	// Reverted lists blocks removed from the canonical chain by a reorg.
	Reverted core.Blocks
}

// NewBlockChain opens (or initialises) a chain in store.
func NewBlockChain(store db.Database, genesis *Genesis, engine consensus.Engine) (*BlockChain, error) {
	bc := &BlockChain{
		store:  store,
		engine: engine,
		config: processor.DefaultConfig(genesis.ChainID),
	}
	bc.processor = processor.NewProcessor(bc.config, bc)

	// Either load the existing chain or write the genesis block.
	stored, err := ReadGenesisHash(store)
	switch {
	case err == nil:
		block, err := ReadBlock(store, stored)
		if err != nil {
			return nil, fmt.Errorf("chain: loading genesis block: %w", err)
		}
		// Re-deriving genesis from the spec must reproduce the stored hash,
		// otherwise the node is pointed at data for a different network.
		expected, err := genesis.ToBlock(db.NewMemoryDB())
		if err != nil {
			return nil, err
		}
		if expected.Hash() != stored {
			return nil, fmt.Errorf("%w: store has %s, configuration derives %s", ErrGenesisMismatch, stored, expected.Hash())
		}
		bc.genesis = block

	default:
		block, err := genesis.Commit(store)
		if err != nil {
			return nil, err
		}
		bc.genesis = block
	}

	if hash, err := ReadFinalizedHash(store); err == nil {
		if block, err := ReadBlock(store, hash); err == nil {
			bc.finalized = block
		}
	}

	head, err := ReadHeadBlockHash(store)
	if err != nil {
		bc.current = bc.genesis
	} else {
		block, err := ReadBlock(store, head)
		if err != nil {
			return nil, fmt.Errorf("chain: loading head block: %w", err)
		}
		bc.current = block
	}
	return bc, nil
}

// Genesis returns the genesis block.
func (bc *BlockChain) Genesis() *core.Block { return bc.genesis }

// CurrentBlock returns the canonical head.
func (bc *BlockChain) CurrentBlock() *core.Block {
	bc.mu.RLock()
	defer bc.mu.RUnlock()
	return bc.current
}

// CurrentHeader returns the canonical head's header.
func (bc *BlockChain) CurrentHeader() *core.Header { return bc.CurrentBlock().Header() }

// Config returns the chain's execution configuration.
func (bc *BlockChain) Config() *processor.Config { return bc.config }

// Processor returns the block processor.
func (bc *BlockChain) Processor() *processor.Processor { return bc.processor }

// Engine returns the consensus engine.
func (bc *BlockChain) Engine() consensus.Engine { return bc.engine }

// Store returns the underlying key/value store.
func (bc *BlockChain) Store() db.Database { return bc.store }

// Subscribe registers a channel to receive head-change events. The channel
// should be buffered; a send that would block is dropped rather than stalling
// block import.
func (bc *BlockChain) Subscribe(ch chan<- ChainEvent) {
	bc.subMu.Lock()
	defer bc.subMu.Unlock()
	bc.subscribers = append(bc.subscribers, ch)
}

func (bc *BlockChain) publish(event ChainEvent) {
	bc.subMu.Lock()
	defer bc.subMu.Unlock()
	for _, ch := range bc.subscribers {
		select {
		case ch <- event:
		default:
			// A slow subscriber must not hold up consensus.
		}
	}
}

// GetBlockByHash returns a block by hash, or nil.
func (bc *BlockChain) GetBlockByHash(hash common.Hash) *core.Block {
	block, err := ReadBlock(bc.store, hash)
	if err != nil {
		return nil
	}
	return block
}

// GetBlockByNumber returns the canonical block at a height, or nil.
func (bc *BlockChain) GetBlockByNumber(number uint64) *core.Block {
	hash, err := ReadCanonicalHash(bc.store, number)
	if err != nil {
		return nil
	}
	return bc.GetBlockByHash(hash)
}

// GetHeaderByHash returns a header by hash, or nil.
func (bc *BlockChain) GetHeaderByHash(hash common.Hash) *core.Header {
	number, err := ReadHeaderNumber(bc.store, hash)
	if err != nil {
		return nil
	}
	header, err := ReadHeader(bc.store, number, hash)
	if err != nil {
		return nil
	}
	return header
}

// GetHeaderByNumber returns the canonical header at a height, or nil.
func (bc *BlockChain) GetHeaderByNumber(number uint64) *core.Header {
	hash, err := ReadCanonicalHash(bc.store, number)
	if err != nil {
		return nil
	}
	header, err := ReadHeader(bc.store, number, hash)
	if err != nil {
		return nil
	}
	return header
}

// HasBlock reports whether a block is stored.
func (bc *BlockChain) HasBlock(hash common.Hash) bool {
	ok, err := bc.store.Has(bodyKey(hash))
	return err == nil && ok
}

// GetReceipts returns the receipts of a stored block.
func (bc *BlockChain) GetReceipts(hash common.Hash) core.Receipts {
	receipts, err := ReadReceipts(bc.store, hash)
	if err != nil {
		return nil
	}
	block := bc.GetBlockByHash(hash)
	if block != nil {
		// Fill in the fields that are derived rather than stored.
		receipts.DeriveFields(bc.processor.Signer(), hash, block.NumberU64(), block.BaseFee(), block.Transactions())
	}
	return receipts
}

// GetTransaction looks up a transaction by hash and returns it with its
// location in the chain.
func (bc *BlockChain) GetTransaction(hash common.Hash) (*core.Transaction, *TxLookupEntry) {
	entry, err := ReadTxLookup(bc.store, hash)
	if err != nil {
		return nil, nil
	}
	block := bc.GetBlockByHash(entry.BlockHash)
	if block == nil {
		return nil, nil
	}
	txs := block.Transactions()
	if entry.Index >= uint64(len(txs)) {
		return nil, nil
	}
	return txs[entry.Index], entry
}

// StateAt returns a state view at the given root.
func (bc *BlockChain) StateAt(root common.Hash) (*state.StateDB, error) {
	return state.New(root, bc.store)
}

// State returns a state view at the canonical head.
func (bc *BlockChain) State() (*state.StateDB, error) {
	return bc.StateAt(bc.CurrentBlock().StateRoot())
}

// InsertBlock verifies and adds a block, extending or reorganising the chain.
func (bc *BlockChain) InsertBlock(block *core.Block) error {
	bc.mu.Lock()
	defer bc.mu.Unlock()
	return bc.insertLocked(block)
}

// InsertChain inserts a sequence of blocks, stopping at the first failure.
func (bc *BlockChain) InsertChain(blocks core.Blocks) (int, error) {
	bc.mu.Lock()
	defer bc.mu.Unlock()
	for i, block := range blocks {
		if err := bc.insertLocked(block); err != nil {
			if errors.Is(err, ErrKnownBlock) {
				continue
			}
			return i, err
		}
	}
	return len(blocks), nil
}

func (bc *BlockChain) insertLocked(block *core.Block) error {
	if bc.HasBlock(block.Hash()) {
		return ErrKnownBlock
	}

	parent := bc.GetBlockByHash(block.ParentHash())
	if parent == nil {
		return fmt.Errorf("%w: %s", ErrUnknownAncestor, block.ParentHash())
	}

	if err := bc.verifyBlock(block, parent); err != nil {
		return err
	}
	if err := bc.checkFinalityLocked(block); err != nil {
		return err
	}

	// Execute against the parent's state.
	statedb, err := bc.StateAt(parent.StateRoot())
	if err != nil {
		return fmt.Errorf("chain: loading parent state: %w", err)
	}
	receipts, logs, _, err := bc.processor.Process(block, statedb)
	if err != nil {
		return err
	}

	// The roots the block claims must match what execution produced. This is
	// the check that makes a block self-verifying.
	if want := deriveReceiptRoot(receipts); want != block.ReceiptRoot() {
		return fmt.Errorf("%w: header says %s, execution derives %s", ErrReceiptRootMismatch, block.ReceiptRoot(), want)
	}
	root, err := statedb.Commit(true)
	if err != nil {
		return fmt.Errorf("chain: committing state: %w", err)
	}
	if root != block.StateRoot() {
		return fmt.Errorf("%w: header says %s, execution derives %s", ErrStateRootMismatch, block.StateRoot(), root)
	}

	// Persist the block and its receipts.
	batch := bc.store.NewBatch()
	if err := WriteBlock(batch, block); err != nil {
		return err
	}
	if err := WriteReceipts(batch, block.Hash(), receipts); err != nil {
		return err
	}
	if err := batch.Write(); err != nil {
		return err
	}

	// A block may carry proof that an ancestor is final; acting on it before
	// the fork choice means the head can only move to a branch that respects
	// the newly settled history.
	if qc, err := block.Justification(); err == nil && !qc.IsEmpty() {
		if _, err := qc.Verify(bc.config.ChainID, bc.engine.Validators()); err == nil {
			bc.finalizeLocked(qc)
		}
	}

	// A longer chain wins, but only among branches that extend finalized
	// history. Equal length keeps the incumbent, so a node does not flip-flop
	// between branches of the same height.
	if block.NumberU64() > bc.current.NumberU64() {
		reverted, err := bc.reorgTo(block)
		if err != nil {
			return err
		}
		bc.publish(ChainEvent{Block: block, Receipts: receipts, Logs: logs, Reverted: reverted})
	}
	return nil
}

// finalizeLocked applies a verified certificate; callers must hold the lock.
func (bc *BlockChain) finalizeLocked(qc *core.QuorumCert) {
	block := bc.getBlock(qc.BlockHash)
	if block == nil || block.NumberU64() != qc.Number {
		return
	}
	if bc.finalized != nil && block.NumberU64() <= bc.finalized.NumberU64() {
		return
	}
	if bc.finalized != nil && !bc.isDescendantLocked(block, bc.finalized) {
		return
	}
	if err := WriteFinalizedHash(bc.store, block.Hash()); err != nil {
		return
	}
	bc.finalized = block
}

// verifyBlock applies the consensus and structural rules that do not require
// executing the block.
func (bc *BlockChain) verifyBlock(block *core.Block, parent *core.Block) error {
	header := block.Header()
	parentHeader := parent.Header()

	if err := bc.engine.VerifyHeader(bc, header, parentHeader); err != nil {
		return err
	}
	if block.GasUsed() > block.GasLimit() {
		return fmt.Errorf("%w: used %d of %d", ErrBlockTooLarge, block.GasUsed(), block.GasLimit())
	}
	if err := processor.VerifyGasLimit(parentHeader.GasLimit, header.GasLimit); err != nil {
		return err
	}
	if err := bc.config.VerifyBaseFee(header, parentHeader); err != nil {
		return err
	}
	if len(header.Justification) > 0 {
		qc, err := core.DecodeQuorumCert(header.Justification)
		if err != nil {
			return err
		}
		if qc.Number >= block.NumberU64() {
			return fmt.Errorf("chain: block %d justifies height %d, which is not an ancestor", block.NumberU64(), qc.Number)
		}
		if _, err := qc.Verify(bc.config.ChainID, bc.engine.Validators()); err != nil {
			return fmt.Errorf("chain: block %d carries an invalid justification: %w", block.NumberU64(), err)
		}
	}
	// The transaction root is checked when the block is decoded, but a locally
	// constructed block has not been through that path.
	want := common.Hash(trie.EmptyRoot)
	if len(block.Transactions()) > 0 {
		want = trie.DeriveRoot(block.Transactions().EncodeForRoot())
	}
	if want != block.TxRoot() {
		return fmt.Errorf("%w: header says %s, body derives %s", core.ErrTxRootMismatch, block.TxRoot(), want)
	}
	return nil
}

// reorgTo makes block the canonical head, rewriting the canonical index and
// returning the blocks that left the chain.
func (bc *BlockChain) reorgTo(block *core.Block) (core.Blocks, error) {
	batch := bc.store.NewBatch()

	// Walk back from both heads to their common ancestor.
	var (
		newChain core.Blocks
		oldChain core.Blocks
		newBlock = block
		oldBlock = bc.current
	)
	for newBlock.NumberU64() > oldBlock.NumberU64() {
		newChain = append(newChain, newBlock)
		parent := bc.GetBlockByHash(newBlock.ParentHash())
		if parent == nil {
			return nil, fmt.Errorf("%w: %s", ErrUnknownAncestor, newBlock.ParentHash())
		}
		newBlock = parent
	}
	for oldBlock.NumberU64() > newBlock.NumberU64() {
		oldChain = append(oldChain, oldBlock)
		parent := bc.GetBlockByHash(oldBlock.ParentHash())
		if parent == nil {
			return nil, fmt.Errorf("%w: %s", ErrUnknownAncestor, oldBlock.ParentHash())
		}
		oldBlock = parent
	}
	for newBlock.Hash() != oldBlock.Hash() {
		newChain = append(newChain, newBlock)
		oldChain = append(oldChain, oldBlock)
		newParent := bc.GetBlockByHash(newBlock.ParentHash())
		oldParent := bc.GetBlockByHash(oldBlock.ParentHash())
		if newParent == nil || oldParent == nil {
			return nil, ErrUnknownAncestor
		}
		newBlock, oldBlock = newParent, oldParent
	}

	// Drop the old branch from the canonical index.
	for _, b := range oldChain {
		if err := DeleteTxLookups(batch, b); err != nil {
			return nil, err
		}
		if err := DeleteCanonicalHash(batch, b.NumberU64()); err != nil {
			return nil, err
		}
	}
	// Write the new branch, oldest first.
	for i := len(newChain) - 1; i >= 0; i-- {
		b := newChain[i]
		if err := WriteCanonicalHash(batch, b.NumberU64(), b.Hash()); err != nil {
			return nil, err
		}
		if err := WriteTxLookups(batch, b); err != nil {
			return nil, err
		}
	}
	if err := WriteHeadBlockHash(batch, block.Hash()); err != nil {
		return nil, err
	}
	if err := batch.Write(); err != nil {
		return nil, err
	}

	bc.current = block
	return oldChain, nil
}

// deriveReceiptRoot computes the receipt root of a block's execution.
func deriveReceiptRoot(receipts core.Receipts) common.Hash {
	if len(receipts) == 0 {
		return common.Hash(trie.EmptyRoot)
	}
	return trie.DeriveRoot(receipts.EncodeForRoot())
}

// GetLogs returns every log in a canonical block.
func (bc *BlockChain) GetLogs(hash common.Hash) []*core.Log {
	receipts := bc.GetReceipts(hash)
	var out []*core.Log
	for _, r := range receipts {
		out = append(out, r.Logs...)
	}
	return out
}

// TotalDifficulty is the chain's work measure. Under proof of authority every
// block counts the same, so the height is the measure.
func (bc *BlockChain) TotalDifficulty() *big.Int {
	return new(big.Int).SetUint64(bc.CurrentBlock().NumberU64())
}
