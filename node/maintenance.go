package node

import (
	"time"

	"layer1/chain"
	"layer1/db"
)

// Background maintenance.
//
// Two jobs keep the store from growing without bound: pruning removes state no
// retained block references, and compaction reclaims the space that overwritten
// and deleted records still occupy in the append-only log. Neither is on the
// critical path of block production, so both run on their own schedule and
// yield rather than compete with it.

// Compactor is a store that can reclaim space from its own log.
type Compactor interface {
	NeedsCompaction() bool
	Compact() error
}

// maintenanceLoop runs pruning and compaction on a schedule.
func (n *Node) maintenanceLoop() {
	defer n.wg.Done()

	interval := n.config.Prune.Interval
	if interval <= 0 {
		interval = 10 * time.Minute
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-n.quit:
			return
		case <-ticker.C:
			n.runMaintenance()
		}
	}
}

func (n *Node) runMaintenance() {
	if n.pruner != nil {
		stats, err := n.pruner.Run()
		switch {
		case err == chain.ErrPruneInProgress:
			// A previous run is still going; skipping is the right response.
		case err != nil:
			n.log.Warn("state prune failed", "err", err)
		default:
			n.metrics.PruneRuns.Inc()
			n.metrics.PrunedNodes.Add(uint64(stats.Deleted))
			n.log.Info("pruned state",
				"deleted", stats.Deleted,
				"reachable", stats.Reachable,
				"roots", stats.Roots,
				"skipped", stats.Skipped,
				"took", stats.Duration.Truncate(time.Millisecond))
		}
	}

	// Deleting records does not shrink an append-only log; compaction is what
	// actually returns the disk. It rewrites the whole store, so it only runs
	// once dead records outnumber live ones.
	if compactor, ok := n.chain.BaseStore().(Compactor); ok && compactor.NeedsCompaction() {
		start := time.Now()
		if err := compactor.Compact(); err != nil {
			n.log.Warn("store compaction failed", "err", err)
			return
		}
		n.metrics.CompactionRuns.Inc()
		n.log.Info("compacted store", "took", time.Since(start).Truncate(time.Millisecond))
	}
}

// Prune runs a state prune immediately, for an operator who wants to reclaim
// space now rather than at the next tick.
func (n *Node) Prune() (chain.PruneStats, error) {
	if n.pruner == nil {
		return chain.PruneStats{}, nil
	}
	return n.pruner.Run()
}

// compactorOf reports whether a store supports compaction.
func compactorOf(store db.Database) (Compactor, bool) {
	c, ok := store.(Compactor)
	return c, ok
}
