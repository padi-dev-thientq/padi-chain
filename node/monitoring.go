package node

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"time"
)

// Monitoring endpoints.
//
// These live on their own listener, separate from the JSON-RPC port. An
// operator needs to reach them when the RPC port is saturated or firewalled
// off, which is exactly when they matter most.

// startMonitoring brings up the metrics and health endpoints.
func (n *Node) startMonitoring(addr string) error {
	mux := http.NewServeMux()

	// Prometheus scrape target.
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		n.refreshMetrics()
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		fmt.Fprint(w, n.metrics.Render())
	})

	// Liveness: is the process running at all? A load balancer uses this to
	// decide whether to restart the node, so it must not depend on peers or
	// consensus, only on the process being able to answer.
	mux.HandleFunc("/health/live", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, "ok")
	})

	// Readiness: should this node receive traffic? A node whose head has
	// stopped advancing is running but useless to serve from, so it is
	// reported unready and taken out of rotation rather than serving stale
	// answers.
	mux.HandleFunc("/health/ready", func(w http.ResponseWriter, r *http.Request) {
		status, code := n.readiness()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		json.NewEncoder(w).Encode(status)
	})

	// Manual prune. This lives on the monitoring listener rather than the
	// public RPC deliberately: it is expensive, and an operator port is the
	// right place for something an operator does on purpose.
	mux.HandleFunc("/admin/prune", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "use POST", http.StatusMethodNotAllowed)
			return
		}
		if n.pruner == nil {
			http.Error(w, "pruning is disabled on this node", http.StatusConflict)
			return
		}
		stats, err := n.pruner.Run()
		w.Header().Set("Content-Type", "application/json")
		if err != nil {
			w.WriteHeader(http.StatusConflict)
			json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}
		json.NewEncoder(w).Encode(map[string]any{
			"deleted":    stats.Deleted,
			"reachable":  stats.Reachable,
			"roots":      stats.Roots,
			"skipped":    stats.Skipped,
			"durationMs": stats.Duration.Milliseconds(),
		})
	})

	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("node: monitoring listener on %s: %w", addr, err)
	}
	n.monitorListener = listener
	n.monitorServer = &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
	}
	go n.monitorServer.Serve(listener)
	n.log.Info("monitoring listening", "addr", listener.Addr().String())
	return nil
}

// StalenessThreshold is how far behind the expected block time the head may
// fall before the node reports itself unready.
const StalenessThreshold = 30

// readiness reports whether the node is fit to serve.
func (n *Node) readiness() (map[string]any, int) {
	head := n.chain.CurrentBlock()
	now := uint64(time.Now().Unix())

	// Allow a generous multiple of the block period before calling the chain
	// stalled, so an ordinary missed slot does not flap the health check.
	tolerance := n.engine.Period()*StalenessThreshold + StalenessThreshold
	age := uint64(0)
	if now > head.Time() {
		age = now - head.Time()
	}
	stale := age > tolerance

	status := map[string]any{
		"head":         head.NumberU64(),
		"finalized":    n.chain.FinalizedNumber(),
		"headAgeSecs":  age,
		"peers":        n.PeerCount(),
		"validators":   len(n.engine.Validators()),
		"chainStalled": stale,
	}

	if stale {
		status["ready"] = false
		status["reason"] = fmt.Sprintf("the head has not advanced for %ds", age)
		return status, http.StatusServiceUnavailable
	}
	status["ready"] = true
	return status, http.StatusOK
}

// refreshMetrics samples the values that are not updated as events happen.
func (n *Node) refreshMetrics() {
	head := n.chain.CurrentBlock()
	n.metrics.ChainHead.Set(int64(head.NumberU64()))
	n.metrics.ChainFinalized.Set(int64(n.chain.FinalizedNumber()))
	n.metrics.PeerCount.Set(int64(n.PeerCount()))

	pending, queued := n.txpool.Stats()
	n.metrics.TxPoolPending.Set(int64(pending))
	n.metrics.TxPoolQueued.Set(int64(queued))
}

// MonitoringAddr returns the address the monitoring endpoints are served on.
func (n *Node) MonitoringAddr() string {
	if n.monitorListener == nil {
		return ""
	}
	return n.monitorListener.Addr().String()
}
