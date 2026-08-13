// Package metrics records what the node is doing, so an operator can see it.
//
// The collectors here are deliberately simple: counters, gauges and histograms
// with fixed buckets, exported in the Prometheus text format. Nothing is
// sampled or aggregated away, because the questions that matter during an
// incident are usually about the tail.
package metrics

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Counter is a value that only increases.
type Counter struct {
	name string
	help string
	v    atomic.Uint64
}

// Add increases the counter.
func (c *Counter) Add(delta uint64) { c.v.Add(delta) }

// Inc increases the counter by one.
func (c *Counter) Inc() { c.v.Add(1) }

// Value returns the current count.
func (c *Counter) Value() uint64 { return c.v.Load() }

// Gauge is a value that moves in both directions.
type Gauge struct {
	name string
	help string
	v    atomic.Int64
}

// Set replaces the gauge's value.
func (g *Gauge) Set(v int64) { g.v.Store(v) }

// Add adjusts the gauge.
func (g *Gauge) Add(delta int64) { g.v.Add(delta) }

// Value returns the current value.
func (g *Gauge) Value() int64 { return g.v.Load() }

// Histogram records a distribution in fixed buckets.
type Histogram struct {
	name   string
	help   string
	bounds []float64
	mu     sync.Mutex
	counts []uint64
	sum    float64
	total  uint64
}

// Observe records a sample.
func (h *Histogram) Observe(v float64) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.sum += v
	h.total++
	// Buckets are cumulative in the export, so record only the first match here.
	for i, bound := range h.bounds {
		if v <= bound {
			h.counts[i]++
			return
		}
	}
	h.counts[len(h.counts)-1]++
}

// ObserveDuration records a duration in seconds.
func (h *Histogram) ObserveDuration(d time.Duration) { h.Observe(d.Seconds()) }

// Registry holds the node's metrics.
type Registry struct {
	mu         sync.RWMutex
	counters   map[string]*Counter
	gauges     map[string]*Gauge
	histograms map[string]*Histogram
}

// NewRegistry creates an empty registry.
func NewRegistry() *Registry {
	return &Registry{
		counters:   make(map[string]*Counter),
		gauges:     make(map[string]*Gauge),
		histograms: make(map[string]*Histogram),
	}
}

// Counter returns the named counter, creating it on first use.
func (r *Registry) Counter(name, help string) *Counter {
	r.mu.Lock()
	defer r.mu.Unlock()
	if c, ok := r.counters[name]; ok {
		return c
	}
	c := &Counter{name: name, help: help}
	r.counters[name] = c
	return c
}

// Gauge returns the named gauge, creating it on first use.
func (r *Registry) Gauge(name, help string) *Gauge {
	r.mu.Lock()
	defer r.mu.Unlock()
	if g, ok := r.gauges[name]; ok {
		return g
	}
	g := &Gauge{name: name, help: help}
	r.gauges[name] = g
	return g
}

// DefaultBuckets covers the range from a fast local operation to a stall.
var DefaultBuckets = []float64{0.001, 0.005, 0.01, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10}

// Histogram returns the named histogram, creating it on first use.
func (r *Registry) Histogram(name, help string, bounds []float64) *Histogram {
	r.mu.Lock()
	defer r.mu.Unlock()
	if h, ok := r.histograms[name]; ok {
		return h
	}
	if bounds == nil {
		bounds = DefaultBuckets
	}
	h := &Histogram{
		name:   name,
		help:   help,
		bounds: bounds,
		counts: make([]uint64, len(bounds)+1),
	}
	r.histograms[name] = h
	return h
}

// Write renders the registry in the Prometheus text exposition format.
func (r *Registry) Write(w *strings.Builder) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	names := make([]string, 0, len(r.counters))
	for name := range r.counters {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		c := r.counters[name]
		fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s counter\n%s %d\n", name, c.help, name, name, c.Value())
	}

	names = names[:0]
	for name := range r.gauges {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		g := r.gauges[name]
		fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s gauge\n%s %d\n", name, g.help, name, name, g.Value())
	}

	names = names[:0]
	for name := range r.histograms {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		h := r.histograms[name]
		h.mu.Lock()
		fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s histogram\n", name, h.help, name)
		var cumulative uint64
		for i, bound := range h.bounds {
			cumulative += h.counts[i]
			fmt.Fprintf(w, "%s_bucket{le=\"%g\"} %d\n", name, bound, cumulative)
		}
		cumulative += h.counts[len(h.counts)-1]
		fmt.Fprintf(w, "%s_bucket{le=\"+Inf\"} %d\n", name, cumulative)
		fmt.Fprintf(w, "%s_sum %g\n%s_count %d\n", name, h.sum, name, h.total)
		h.mu.Unlock()
	}
}

// Render returns the registry as a string.
func (r *Registry) Render() string {
	var b strings.Builder
	r.Write(&b)
	return b.String()
}

// NodeMetrics is the set of measurements the node keeps.
type NodeMetrics struct {
	registry *Registry

	BlocksImported   *Counter
	BlocksProduced   *Counter
	BlocksRejected   *Counter
	TxAccepted       *Counter
	TxRejected       *Counter
	AttestationsSeen *Counter
	Equivocations    *Counter
	PeersBanned      *Counter
	RPCRequests      *Counter
	RPCErrors        *Counter
	PruneRuns        *Counter
	PrunedNodes      *Counter
	CompactionRuns   *Counter
	StateNodesSynced *Counter
	SlashingReports  *Counter

	ChainHead      *Gauge
	ChainFinalized *Gauge
	PeerCount      *Gauge
	TxPoolPending  *Gauge
	TxPoolQueued   *Gauge

	BlockExecution *Histogram
	BlockGasUsed   *Histogram
	RPCLatency     *Histogram
}

// NewNodeMetrics creates the node's metric set.
func NewNodeMetrics() *NodeMetrics {
	r := NewRegistry()
	return &NodeMetrics{
		registry: r,

		BlocksImported:   r.Counter("padi_blocks_imported_total", "Blocks accepted from peers."),
		BlocksProduced:   r.Counter("padi_blocks_produced_total", "Blocks sealed by this validator."),
		BlocksRejected:   r.Counter("padi_blocks_rejected_total", "Blocks that failed verification."),
		TxAccepted:       r.Counter("padi_transactions_accepted_total", "Transactions admitted to the pool."),
		TxRejected:       r.Counter("padi_transactions_rejected_total", "Transactions the pool refused."),
		AttestationsSeen: r.Counter("padi_attestations_total", "Validator attestations recorded."),
		Equivocations:    r.Counter("padi_equivocations_total", "Validators caught signing conflicting attestations."),
		PeersBanned:      r.Counter("padi_peers_banned_total", "Peers banned for misbehaviour."),
		RPCRequests:      r.Counter("padi_rpc_requests_total", "JSON-RPC calls served."),
		RPCErrors:        r.Counter("padi_rpc_errors_total", "JSON-RPC calls that returned an error."),
		PruneRuns:        r.Counter("padi_prune_runs_total", "Completed state prunes."),
		PrunedNodes:      r.Counter("padi_pruned_nodes_total", "Trie nodes and code entries removed by pruning."),
		CompactionRuns:   r.Counter("padi_compaction_runs_total", "Completed store compactions."),
		StateNodesSynced: r.Counter("padi_state_nodes_synced_total", "State nodes downloaded during snapshot sync."),
		SlashingReports:  r.Counter("padi_slashing_reports_total", "Equivocation proofs submitted for slashing."),

		ChainHead:      r.Gauge("padi_chain_head", "Height of the canonical head."),
		ChainFinalized: r.Gauge("padi_chain_finalized", "Height of the highest finalized block."),
		PeerCount:      r.Gauge("padi_peers", "Connected peers."),
		TxPoolPending:  r.Gauge("padi_txpool_pending", "Executable transactions in the pool."),
		TxPoolQueued:   r.Gauge("padi_txpool_queued", "Transactions waiting on a nonce gap."),

		BlockExecution: r.Histogram("padi_block_execution_seconds", "Time to execute and verify a block.", nil),
		BlockGasUsed: r.Histogram("padi_block_gas_used", "Gas used per block.",
			[]float64{100000, 1000000, 5000000, 10000000, 15000000, 20000000, 30000000}),
		RPCLatency: r.Histogram("padi_rpc_latency_seconds", "Time to serve a JSON-RPC call.", nil),
	}
}

// Registry exposes the underlying registry.
func (m *NodeMetrics) Registry() *Registry { return m.registry }

// Render returns the metrics in Prometheus format.
func (m *NodeMetrics) Render() string { return m.registry.Render() }
