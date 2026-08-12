package node

import (
	"sync"
	"time"

	"layer1/common"
	"layer1/core"
	"layer1/statesync"
)

// Snapshot sync.
//
// A node starting from nothing would otherwise have to execute every block
// since genesis, which gets slower every day the network runs. Instead it takes
// a finalized block from a peer, downloads the state that block commits to, and
// starts from there.
//
// What makes that safe is finality, not trust in the peer. The block comes with
// a quorum certificate, so the state root is one that more than two thirds of
// the validator set signed for; and every state node is checked against the
// hash that referenced it, so the peer serving the data cannot alter any of it.

// SnapSyncThreshold is how far behind a node must be before it prefers
// downloading state to replaying blocks. Below it, replaying is simpler and
// leaves the node with full history.
const SnapSyncThreshold = 128

type snapSync struct {
	mu sync.Mutex

	syncer *statesync.Syncer
	block  *core.Block
	cert   *core.QuorumCert
	active bool
	done   bool
}

// LocalSnapshot returns this node's finalized block and the certificate proving
// it, for a peer that wants to skip replaying the chain.
func (n *Node) LocalSnapshot() (*core.Block, *core.QuorumCert) {
	final := n.chain.FinalizedBlock()
	if final == nil || final.NumberU64() == 0 {
		return nil, nil
	}
	// The certificate lives in whichever descendant carried it; the pool has
	// it if this node collected the votes itself.
	if qc := n.attestations.Certificate(final.NumberU64(), final.Hash()); qc != nil {
		return final, qc
	}
	// Otherwise look for the block that justified it.
	for number := final.NumberU64() + 1; number <= final.NumberU64()+8; number++ {
		descendant := n.chain.GetBlockByNumber(number)
		if descendant == nil {
			break
		}
		qc, err := descendant.Justification()
		if err != nil || qc.IsEmpty() {
			continue
		}
		if qc.BlockHash == final.Hash() {
			return final, qc
		}
	}
	return nil, nil
}

// HandleSnapshot considers a peer's offer of a finalized block to sync from.
func (n *Node) HandleSnapshot(block *core.Block, qc *core.QuorumCert) {
	n.snap.mu.Lock()
	defer n.snap.mu.Unlock()

	if n.snap.active || n.snap.done {
		return
	}
	// Only a node with no history of its own has anything to gain, and only a
	// node far behind has enough to gain to be worth it.
	threshold := n.config.SnapSyncThreshold
	if threshold == 0 {
		threshold = SnapSyncThreshold
	}
	head := n.chain.CurrentBlock()
	if head.NumberU64() != 0 || block.NumberU64() < threshold {
		return
	}
	// Refuse an offer that is not actually proved final before doing any work.
	if qc.IsEmpty() || qc.BlockHash != block.Hash() {
		return
	}
	if _, err := qc.Verify(n.ChainID(), n.engine.Validators()); err != nil {
		n.log.Warn("rejected a snapshot offer with an invalid certificate", "err", err)
		return
	}

	n.snap.block = block
	n.snap.cert = qc
	n.snap.syncer = statesync.New(n.chain.Store(), block.StateRoot())
	n.snap.active = true

	n.log.Info("starting snapshot sync",
		"block", block.NumberU64(), "root", block.StateRoot(), "peer-finalized", qc.Number)

	n.wg.Add(1)
	go n.snapSyncLoop()
}

// snapSyncLoop drives the download until the state is complete.
func (n *Node) snapSyncLoop() {
	defer n.wg.Done()

	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()

	var idle int
	for {
		select {
		case <-n.quit:
			return
		case <-ticker.C:
		}

		n.snap.mu.Lock()
		syncer := n.snap.syncer
		active := n.snap.active
		n.snap.mu.Unlock()
		if !active || syncer == nil {
			return
		}

		if syncer.Done() {
			n.finishSnapSync()
			return
		}

		requests := syncer.Missing(statesync.MaxRequestBatch)
		if len(requests) == 0 {
			continue
		}
		if n.network == nil || !n.network.RequestStateNodes(requests) {
			// No peer to ask; put the work back and wait for one.
			syncer.Retry(requests)
			idle++
			if idle > 300 {
				n.log.Warn("snapshot sync has no peer to fetch state from; falling back to replaying blocks")
				n.abandonSnapSync()
				return
			}
			continue
		}
		idle = 0
	}
}

// HandleStateNodes feeds downloaded state into the running sync.
func (n *Node) HandleStateNodes(blobs [][]byte) {
	n.snap.mu.Lock()
	syncer := n.snap.syncer
	active := n.snap.active
	n.snap.mu.Unlock()

	if !active || syncer == nil {
		return
	}
	accepted, err := syncer.Process(blobs)
	if err != nil {
		n.log.Warn("storing synced state failed", "err", err)
		return
	}
	n.metrics.StateNodesSynced.Add(uint64(accepted))
}

// finishSnapSync verifies the downloaded state and adopts the snapshot head.
func (n *Node) finishSnapSync() {
	n.snap.mu.Lock()
	block, cert, syncer := n.snap.block, n.snap.cert, n.snap.syncer
	n.snap.mu.Unlock()

	// Reaching zero outstanding nodes says everything asked for arrived; this
	// says the pieces actually form the trie the block committed to.
	if err := syncer.Verify(); err != nil {
		n.log.Error("the synced state did not verify; discarding it", "err", err)
		n.abandonSnapSync()
		return
	}
	if err := n.chain.ImportSnapshot(block, cert); err != nil {
		n.log.Error("adopting the snapshot failed", "err", err)
		n.abandonSnapSync()
		return
	}

	n.snap.mu.Lock()
	n.snap.active = false
	n.snap.done = true
	n.snap.mu.Unlock()

	n.log.Info("snapshot sync complete",
		"block", block.NumberU64(), "root", block.StateRoot(), "nodes", syncer.Stored())

	// The snapshot lands at the finalized block; everything after it still has
	// to be fetched the ordinary way.
	if n.network != nil {
		n.network.SyncFromPeers()
	}
}

// abandonSnapSync gives up and leaves the node to sync by replaying blocks.
func (n *Node) abandonSnapSync() {
	n.snap.mu.Lock()
	defer n.snap.mu.Unlock()
	n.snap.active = false
	n.snap.syncer = nil
	n.snap.block = nil
	n.snap.cert = nil
}

// SnapSyncing reports whether a snapshot sync is in progress.
func (n *Node) SnapSyncing() bool {
	n.snap.mu.Lock()
	defer n.snap.mu.Unlock()
	return n.snap.active
}

// ServeStateNodes answers a peer's request for state blobs.
func (n *Node) ServeStateNodes(hashes []common.Hash) [][]byte {
	return statesync.Serve(n.chain.Store(), hashes, statesync.MaxRequestBatch)
}
