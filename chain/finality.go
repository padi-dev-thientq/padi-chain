package chain

import (
	"errors"
	"fmt"

	"layer1/common"
	"layer1/core"
	"layer1/db"
	"layer1/state"
)

// Finality tracking.
//
// A block is finalized once more than two thirds of validators have attested to
// it. Finalized history is never reorganised: a competing branch that does not
// descend from the finalized block is rejected outright, however long it is.
// Without that rule, a longer chain built in secret could erase settled history.

var (
	ErrConflictsWithFinalized = errors.New("chain: block conflicts with finalized history")
	ErrFinalityRegression     = errors.New("chain: refusing to move finality backwards")
)

var keyFinalizedBlock = []byte("FinalizedBlock")

// WriteFinalizedHash records the highest finalized block.
func WriteFinalizedHash(store db.Writer, hash common.Hash) error {
	return store.Put(keyFinalizedBlock, hash[:])
}

// ReadFinalizedHash returns the highest finalized block hash.
func ReadFinalizedHash(store db.Reader) (common.Hash, error) {
	enc, err := store.Get(keyFinalizedBlock)
	if err != nil {
		return common.Hash{}, ErrNotFound
	}
	return common.BytesToHash(enc), nil
}

// FinalizedBlock returns the highest block known to be final.
func (bc *BlockChain) FinalizedBlock() *core.Block {
	bc.mu.RLock()
	defer bc.mu.RUnlock()
	return bc.finalized
}

// FinalizedNumber returns the height of the highest finalized block.
func (bc *BlockChain) FinalizedNumber() uint64 {
	block := bc.FinalizedBlock()
	if block == nil {
		return 0
	}
	return block.NumberU64()
}

// Finalize marks a block final after verifying the certificate that proves it.
//
// The certificate is checked against the validator set rather than trusted,
// because finality is the one claim a peer could make that would let it erase
// history if believed on its word.
func (bc *BlockChain) Finalize(qc *core.QuorumCert) error {
	if qc.IsEmpty() {
		return core.ErrQuorumNotMet
	}
	if _, err := qc.Verify(bc.config.ChainID, bc.engine.Validators()); err != nil {
		return err
	}

	bc.mu.Lock()
	defer bc.mu.Unlock()

	block := bc.getBlock(qc.BlockHash)
	if block == nil {
		return fmt.Errorf("%w: block %s is unknown", ErrUnknownAncestor, qc.BlockHash)
	}
	if block.NumberU64() != qc.Number {
		return fmt.Errorf("chain: certificate says height %d, the block is at %d", qc.Number, block.NumberU64())
	}
	if bc.finalized != nil && block.NumberU64() <= bc.finalized.NumberU64() {
		return nil // already final, or older: nothing to do
	}

	// The newly finalized block must extend what is already final, otherwise
	// two conflicting quorums exist and the validator set has equivocated.
	if bc.finalized != nil && !bc.isDescendantLocked(block, bc.finalized) {
		return fmt.Errorf("%w: %s does not descend from finalized %s",
			ErrFinalityRegression, block.Hash(), bc.finalized.Hash())
	}

	// A finalized block must be on the canonical chain. If it is not, the
	// canonical chain is wrong and has to move, whatever the heights say.
	canonical, _ := ReadCanonicalHash(bc.store, block.NumberU64())
	if canonical != block.Hash() {
		if _, err := bc.reorgTo(block); err != nil {
			return err
		}
	}

	if err := WriteFinalizedHash(bc.store, block.Hash()); err != nil {
		return err
	}
	bc.finalized = block
	return nil
}

// isDescendantLocked reports whether block descends from ancestor.
func (bc *BlockChain) isDescendantLocked(block, ancestor *core.Block) bool {
	if ancestor == nil {
		return true
	}
	current := block
	for current != nil && current.NumberU64() > ancestor.NumberU64() {
		current = bc.getBlock(current.ParentHash())
	}
	return current != nil && current.Hash() == ancestor.Hash()
}

// getBlock reads a block without taking the lock; callers must hold it.
func (bc *BlockChain) getBlock(hash common.Hash) *core.Block {
	block, err := ReadBlock(bc.store, hash)
	if err != nil {
		return nil
	}
	return block
}

// checkFinalityLocked rejects a block that contradicts finalized history.
func (bc *BlockChain) checkFinalityLocked(block *core.Block) error {
	if bc.finalized == nil {
		return nil
	}
	final := bc.finalized

	// A block at or below the finalized height may only be the finalized block
	// itself or one of its ancestors.
	if block.NumberU64() <= final.NumberU64() {
		canonical, err := ReadCanonicalHash(bc.store, block.NumberU64())
		if err == nil && canonical != block.Hash() {
			return fmt.Errorf("%w: block %d %s contradicts the canonical chain below finalized height %d",
				ErrConflictsWithFinalized, block.NumberU64(), block.Hash(), final.NumberU64())
		}
		return nil
	}

	// Above it, the block must descend from the finalized block.
	if !bc.isDescendantLocked(block, final) {
		return fmt.Errorf("%w: %s does not descend from finalized %s at %d",
			ErrConflictsWithFinalized, block.Hash(), final.Hash(), final.NumberU64())
	}
	return nil
}

// ImportSnapshot adopts a finalized block whose state was obtained by snapshot
// sync rather than by executing the chain.
//
// This is the one path that installs a state root without executing anything,
// so it is deliberately narrow: the block must be proved final by a quorum of
// the validator set, the state it claims must already be present and complete
// in the store, and the local chain must still be at genesis. A node with
// history of its own has no business adopting someone else's head.
func (bc *BlockChain) ImportSnapshot(block *core.Block, qc *core.QuorumCert) error {
	if qc.IsEmpty() {
		return core.ErrQuorumNotMet
	}
	if qc.BlockHash != block.Hash() || qc.Number != block.NumberU64() {
		return fmt.Errorf("chain: the certificate does not name the offered block")
	}
	// The signatures are the whole basis for trusting this state.
	if _, err := qc.Verify(bc.config.ChainID, bc.engine.Validators()); err != nil {
		return fmt.Errorf("chain: snapshot certificate: %w", err)
	}

	bc.mu.Lock()
	defer bc.mu.Unlock()

	if bc.current.NumberU64() != 0 {
		return fmt.Errorf("chain: refusing to adopt a snapshot over %d blocks of local history", bc.current.NumberU64())
	}
	if block.NumberU64() == 0 {
		return nil // the snapshot is genesis; nothing to do
	}

	// The state must actually be here. Adopting a head whose state is missing
	// would leave the node unable to execute the next block.
	statedb, err := state.New(block.StateRoot(), bc.store)
	if err != nil {
		return fmt.Errorf("chain: snapshot state %s is not available: %w", block.StateRoot(), err)
	}
	_ = statedb

	batch := bc.store.NewBatch()
	if err := WriteBlock(batch, block); err != nil {
		return err
	}
	if err := WriteCanonicalHash(batch, block.NumberU64(), block.Hash()); err != nil {
		return err
	}
	if err := WriteTxLookups(batch, block); err != nil {
		return err
	}
	if err := WriteHeadBlockHash(batch, block.Hash()); err != nil {
		return err
	}
	if err := WriteFinalizedHash(batch, block.Hash()); err != nil {
		return err
	}
	if err := batch.Write(); err != nil {
		return err
	}

	bc.current = block
	bc.finalized = block
	return nil
}
