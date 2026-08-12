package rpc

import (
	"net"
	"net/http"
	"sync"
	"time"
)

// Resource limits.
//
// The RPC endpoint is the node's most exposed surface: it is reachable by
// anyone who can open a socket, and some methods cost far more than others.
// Without limits, a single client can occupy every worker with expensive calls
// and starve everyone else.

// Limits configures admission control.
type Limits struct {
	// RequestsPerSecond is the sustained per-client budget, measured in cost
	// units rather than requests: an eth_call costs more than a block number.
	RequestsPerSecond float64
	// Burst is how much budget a client may accumulate while idle.
	Burst float64
	// MaxConcurrent caps how many calls execute at once across all clients,
	// bounding memory and CPU regardless of how many connect.
	MaxConcurrent int
	// CallTimeout bounds how long one call may run.
	CallTimeout time.Duration
	// ClientTTL is how long an idle client's budget is remembered.
	ClientTTL time.Duration
}

// DefaultLimits returns limits suitable for a public endpoint.
func DefaultLimits() *Limits {
	return &Limits{
		RequestsPerSecond: 50,
		Burst:             200,
		MaxConcurrent:     64,
		CallTimeout:       20 * time.Second,
		ClientTTL:         10 * time.Minute,
	}
}

// methodCost is what a call draws from a client's budget. The numbers are
// relative: they encode how much work a method can make the node do, not how
// long it takes on any particular machine.
var methodCost = map[string]float64{
	"eth_call":               20,
	"eth_estimateGas":        40, // binary search: many executions per call
	"eth_getLogs":            30, // can scan a range of blocks
	"eth_sendRawTransaction": 10,
	"eth_getBlockByNumber":   3,
	"eth_getBlockByHash":     3,
	"debug_traceTransaction": 50,
}

// costOf returns a method's cost, defaulting to the cheapest tier.
func costOf(method string) float64 {
	if cost, ok := methodCost[method]; ok {
		return cost
	}
	return 1
}

// clientBudget is one client's token bucket.
type clientBudget struct {
	tokens float64
	last   time.Time
}

// limiter tracks per-client budgets and the global concurrency cap.
type limiter struct {
	limits *Limits

	mu      sync.Mutex
	clients map[string]*clientBudget

	slots chan struct{}
	now   func() time.Time
}

func newLimiter(limits *Limits) *limiter {
	if limits == nil {
		limits = DefaultLimits()
	}
	return &limiter{
		limits:  limits,
		clients: make(map[string]*clientBudget),
		slots:   make(chan struct{}, limits.MaxConcurrent),
		now:     time.Now,
	}
}

// allow charges a client for a call and reports whether it may proceed.
func (l *limiter) allow(client string, cost float64) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.now()
	budget, ok := l.clients[client]
	if !ok {
		budget = &clientBudget{tokens: l.limits.Burst, last: now}
		l.clients[client] = budget
	}

	budget.tokens += now.Sub(budget.last).Seconds() * l.limits.RequestsPerSecond
	if budget.tokens > l.limits.Burst {
		budget.tokens = l.limits.Burst
	}
	budget.last = now

	if budget.tokens < cost {
		return false
	}
	budget.tokens -= cost
	return true
}

// acquire takes a concurrency slot, waiting up to the call timeout. Queuing
// briefly is better than refusing: a burst that the node can absorb should be
// absorbed, and only sustained overload should be rejected.
func (l *limiter) acquire() bool {
	select {
	case l.slots <- struct{}{}:
		return true
	case <-time.After(l.limits.CallTimeout):
		return false
	}
}

func (l *limiter) release() {
	select {
	case <-l.slots:
	default:
	}
}

// sweep drops budgets for clients that have gone away, so the map cannot grow
// without bound from clients that connect once each.
func (l *limiter) sweep() {
	l.mu.Lock()
	defer l.mu.Unlock()

	cutoff := l.now().Add(-l.limits.ClientTTL)
	for client, budget := range l.clients {
		if budget.last.Before(cutoff) {
			delete(l.clients, client)
		}
	}
}

// clientKey identifies the caller for rate limiting. The socket address is used
// rather than a forwarded header, which a client controls and could forge to
// escape its own limit.
func clientKey(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
