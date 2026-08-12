package p2p

import (
	"sync"
	"time"
)

// Peer reputation.
//
// Scores are keyed by node identity rather than network address: an address is
// free to change, a node key is not. A peer that sends malformed data, invalid
// blocks or floods the connection loses score, and is disconnected and refused
// for a while once it runs out. Honest peers slowly recover, so a transient
// fault does not become a permanent exclusion.

// Penalties, in score points. The scale is chosen so a peer can survive a
// handful of honest mistakes but not a sustained attack.
const (
	penaltyBadMessage   = 10  // undecodable or protocol-violating message
	penaltyInvalidBlock = 25  // a block that failed verification
	penaltyInvalidTx    = 2   // a transaction the pool refused
	penaltyFlood        = 20  // exceeded a rate limit
	penaltyEquivocation = 100 // relayed proof of validator misbehaviour

	// initialScore is what a peer starts with, and the ceiling it recovers to.
	initialScore = 100
	// banThreshold is the score at or below which a peer is disconnected.
	banThreshold = 0
	// banDuration is how long a banned peer is refused.
	banDuration = 30 * time.Minute
	// recoveryInterval is how often a peer regains a point.
	recoveryInterval = time.Minute
	// recoveryAmount is how much score is restored each interval.
	recoveryAmount = 5
)

type reputation struct {
	score       int
	lastRecover time.Time
	bannedUntil time.Time
}

type scoreboard struct {
	mu    sync.Mutex
	peers map[NodeID]*reputation
	now   func() time.Time
}

func newScoreboard() *scoreboard {
	return &scoreboard{peers: make(map[NodeID]*reputation), now: time.Now}
}

func (b *scoreboard) entry(id NodeID) *reputation {
	entry, ok := b.peers[id]
	if !ok {
		entry = &reputation{score: initialScore, lastRecover: b.now()}
		b.peers[id] = entry
	}
	return entry
}

// recoverLocked restores score for the time that has passed.
func (b *scoreboard) recoverLocked(entry *reputation) {
	now := b.now()
	elapsed := now.Sub(entry.lastRecover)
	if elapsed < recoveryInterval {
		return
	}
	intervals := int(elapsed / recoveryInterval)
	entry.score += intervals * recoveryAmount
	if entry.score > initialScore {
		entry.score = initialScore
	}
	entry.lastRecover = now
}

// penalise deducts score and reports whether the peer is now banned.
func (b *scoreboard) penalise(id NodeID, amount int) bool {
	b.mu.Lock()
	defer b.mu.Unlock()

	entry := b.entry(id)
	b.recoverLocked(entry)
	entry.score -= amount

	if entry.score <= banThreshold {
		entry.bannedUntil = b.now().Add(banDuration)
		entry.score = initialScore / 2 // give it something to work with on return
		return true
	}
	return false
}

// isBanned reports whether a peer is currently refused.
func (b *scoreboard) isBanned(id NodeID) bool {
	b.mu.Lock()
	defer b.mu.Unlock()

	entry, ok := b.peers[id]
	if !ok {
		return false
	}
	return b.now().Before(entry.bannedUntil)
}

// score returns a peer's current score.
func (b *scoreboard) scoreOf(id NodeID) int {
	b.mu.Lock()
	defer b.mu.Unlock()

	entry := b.entry(id)
	b.recoverLocked(entry)
	return entry.score
}

// rateLimiter is a token bucket, used to cap how fast a peer may send.
type rateLimiter struct {
	mu       sync.Mutex
	tokens   float64
	capacity float64
	refill   float64 // tokens per second
	last     time.Time
	now      func() time.Time
}

func newRateLimiter(capacity, perSecond float64) *rateLimiter {
	return &rateLimiter{
		tokens:   capacity,
		capacity: capacity,
		refill:   perSecond,
		last:     time.Now(),
		now:      time.Now,
	}
}

// allow consumes one token, reporting whether the caller is within its budget.
func (r *rateLimiter) allow() bool { return r.allowN(1) }

// allowN consumes n tokens.
func (r *rateLimiter) allowN(n float64) bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := r.now()
	elapsed := now.Sub(r.last).Seconds()
	r.last = now

	r.tokens += elapsed * r.refill
	if r.tokens > r.capacity {
		r.tokens = r.capacity
	}
	if r.tokens < n {
		return false
	}
	r.tokens -= n
	return true
}
