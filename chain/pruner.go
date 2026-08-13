package chain

import (
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"padi-chain/common"
	"padi-chain/core"
	"padi-chain/db"
	"padi-chain/trie"
)

// State pruning.
//
// The trie is persistent: every commit writes new nodes and leaves the old ones
// in place, because a node shared with an earlier state must not be disturbed.
// That is what makes historical state queryable, and also what makes the store
// grow forever if nothing removes what no longer matters.
//
// The pruner is mark and sweep. It computes the set of nodes reachable from the
// roots worth keeping, then deletes everything else. Reference counting would
// be cheaper, but a single miscounted reference silently destroys state that is
// still in use; a walk from the roots cannot be wrong about what is reachable.

var ErrPruneInProgress = errors.New("chain: a prune is already running")

// PruneConfig controls what the pruner keeps.
type PruneConfig struct {
	// Retain is how many recent blocks' states to keep queryable. It must
	// comfortably exceed the deepest reorg the chain can experience, or the
	// node could be unable to rebuild after one.
	Retain uint64
	// Interval is how often to prune.
	Interval time.Duration
	// Enabled turns pruning on. An archive node leaves it off.
	Enabled bool
}

// DefaultPruneConfig returns settings suitable for a validator or full node.
func DefaultPruneConfig() *PruneConfig {
	return &PruneConfig{
		Retain:   256,
		Interval: 10 * time.Minute,
		Enabled:  true,
	}
}

// PruneStats reports what a prune did.
type PruneStats struct {
	Roots     int
	Reachable int
	Deleted   int
	Skipped   int
	Duration  time.Duration
}

// Pruner removes state that no retained block references.
type Pruner struct {
	chain   *BlockChain
	tracker *db.TrackingDB
	config  *PruneConfig
	log     *slog.Logger

	mu      sync.Mutex
	running bool
	last    PruneStats
}

// NewPruner creates a pruner over a chain.
func NewPruner(bc *BlockChain, tracker *db.TrackingDB, config *PruneConfig, log *slog.Logger) *Pruner {
	if config == nil {
		config = DefaultPruneConfig()
	}
	if log == nil {
		log = slog.Default()
	}
	return &Pruner{chain: bc, tracker: tracker, config: config, log: log}
}

// LastRun returns the statistics of the most recent prune.
func (p *Pruner) LastRun() PruneStats {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.last
}

// retainedRoots returns the state roots that must survive: the finalized block,
// the recent window, and genesis.
func (p *Pruner) retainedRoots() []common.Hash {
	seen := make(map[common.Hash]struct{})
	var roots []common.Hash

	add := func(block *core.Block) {
		if block == nil {
			return
		}
		root := block.StateRoot()
		if _, ok := seen[root]; ok {
			return
		}
		seen[root] = struct{}{}
		roots = append(roots, root)
	}

	head := p.chain.CurrentBlock()
	add(head)

	// Everything back to the retention horizon stays queryable, and stays
	// available to rebuild from if the chain reorganises.
	for i := uint64(0); i < p.config.Retain && i < head.NumberU64(); i++ {
		add(p.chain.GetBlockByNumber(head.NumberU64() - i - 1))
	}

	// The finalized block is the chain's settlement point; it is never
	// discarded however far behind the window it falls.
	add(p.chain.FinalizedBlock())
	// Genesis keeps the "earliest" queries answerable.
	add(p.chain.Genesis())

	return roots
}

// Run performs one prune.
func (p *Pruner) Run() (PruneStats, error) {
	p.mu.Lock()
	if p.running {
		p.mu.Unlock()
		return PruneStats{}, ErrPruneInProgress
	}
	p.running = true
	p.mu.Unlock()

	defer func() {
		p.mu.Lock()
		p.running = false
		p.mu.Unlock()
	}()

	start := time.Now()

	// Anything written from here on is live by definition, whether or not the
	// mark phase sees it. This is what makes pruning safe to run while blocks
	// are still being imported.
	p.tracker.StartTracking()
	defer p.tracker.StopTracking()

	roots := p.retainedRoots()
	reachable, err := p.mark(roots)
	if err != nil {
		return PruneStats{}, err
	}

	stats, err := p.sweep(reachable)
	if err != nil {
		return PruneStats{}, err
	}
	stats.Roots = len(roots)
	stats.Reachable = len(reachable)
	stats.Duration = time.Since(start)

	p.mu.Lock()
	p.last = stats
	p.mu.Unlock()
	return stats, nil
}

// mark collects every store key reachable from the retained roots: the account
// trie nodes, every account's storage trie nodes, and every contract's code.
func (p *Pruner) mark(roots []common.Hash) (map[string]struct{}, error) {
	reachable := make(map[string]struct{})
	store := p.chain.Store()

	for _, root := range roots {
		accounts, err := trie.New(root, store)
		if err != nil {
			// A root whose nodes are already gone is not an error: an earlier
			// prune may have removed it, or it may predate this node's state.
			p.log.Debug("prune: skipping an unavailable root", "root", root, "err", err)
			continue
		}

		err = accounts.VisitNodes(
			func(hash common.Hash) error {
				reachable[string(trie.NodeKey(hash))] = struct{}{}
				return nil
			},
			func(_, value []byte) error {
				account, err := core.DecodeAccount(value)
				if err != nil {
					return fmt.Errorf("prune: decoding an account under root %s: %w", root, err)
				}
				if account.HasCode() {
					reachable[string(codeKey(common.BytesToHash(account.CodeHash)))] = struct{}{}
				}
				if account.Root == core.EmptyRoot || account.Root == (common.Hash{}) {
					return nil
				}
				storage, err := trie.New(account.Root, store)
				if err != nil {
					return fmt.Errorf("prune: opening storage %s: %w", account.Root, err)
				}
				return storage.VisitNodes(func(hash common.Hash) error {
					reachable[string(trie.NodeKey(hash))] = struct{}{}
					return nil
				}, nil)
			},
		)
		if err != nil {
			return nil, err
		}
	}
	return reachable, nil
}

// sweep deletes stored state that the mark phase did not reach.
func (p *Pruner) sweep(reachable map[string]struct{}) (PruneStats, error) {
	var stats PruneStats
	store := p.chain.Store()

	// Keys written since the mark began are live regardless of reachability.
	recent := p.tracker.Written()

	var doomed [][]byte
	collect := func(prefix []byte) error {
		return store.Iterate(prefix, func(key, _ []byte) bool {
			k := string(key)
			if _, ok := reachable[k]; ok {
				return true
			}
			if _, ok := recent[k]; ok {
				stats.Skipped++
				return true
			}
			doomed = append(doomed, append([]byte(nil), key...))
			return true
		})
	}
	if err := collect(trie.NodeKeyPrefix); err != nil {
		return stats, err
	}
	if err := collect(codeKeyPrefix); err != nil {
		return stats, err
	}

	// Re-check against writes that landed while the keys were being collected,
	// so a node committed mid-sweep is never removed.
	recent = p.tracker.Written()

	batch := store.NewBatch()
	for _, key := range doomed {
		if _, ok := recent[string(key)]; ok {
			stats.Skipped++
			continue
		}
		if err := batch.Delete(key); err != nil {
			return stats, err
		}
		stats.Deleted++
		// Flush in chunks so a large sweep does not build one enormous batch.
		if batch.Len() >= 4096 {
			if err := batch.Write(); err != nil {
				return stats, err
			}
		}
	}
	if err := batch.Write(); err != nil {
		return stats, err
	}
	return stats, nil
}

// codeKeyPrefix is the namespace contract code occupies in the store. It
// mirrors the state package's layout, which the pruner has to know to sweep.
var codeKeyPrefix = []byte("c")

func codeKey(hash common.Hash) []byte {
	return append(append([]byte{}, codeKeyPrefix...), hash[:]...)
}
