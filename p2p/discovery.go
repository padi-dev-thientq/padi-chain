package p2p

import (
	"net"
	"sort"
	"sync"
	"time"
)

// Peer exchange.
//
// Bootstrap addresses get a node onto the network; they should not be what
// keeps it there. Peers periodically tell each other which addresses they have
// working connections to, so the network's connectivity outlives any particular
// bootstrap host.
//
// Addresses learned this way are advisory. A peer can claim anything, so an
// address is only ever a candidate to dial, and the handshake decides whether
// whoever answers is worth talking to.

// MaxAddressesPerMessage bounds a peer exchange message.
const MaxAddressesPerMessage = 32

// AddressesPayload carries peer addresses.
type AddressesPayload struct {
	Addresses []string
}

// addressBook remembers where peers can be reached.
type addressBook struct {
	mu    sync.Mutex
	known map[string]*addressEntry
	limit int
	now   func() time.Time
}

type addressEntry struct {
	addr string
	// lastSeen is when the address was last advertised or connected to.
	lastSeen time.Time
	// failures counts consecutive unsuccessful dials.
	failures int
}

func newAddressBook(limit int) *addressBook {
	return &addressBook{known: make(map[string]*addressEntry), limit: limit, now: time.Now}
}

// add records an address, ignoring anything unusable.
func (b *addressBook) add(addr string) bool {
	if !isDialable(addr) {
		return false
	}
	b.mu.Lock()
	defer b.mu.Unlock()

	if entry, ok := b.known[addr]; ok {
		entry.lastSeen = b.now()
		return false
	}
	if len(b.known) >= b.limit {
		b.evictWorstLocked()
	}
	b.known[addr] = &addressEntry{addr: addr, lastSeen: b.now()}
	return true
}

// evictWorstLocked drops the least promising entry: the one that has failed
// most, breaking ties by age.
func (b *addressBook) evictWorstLocked() {
	var worst *addressEntry
	for _, entry := range b.known {
		if worst == nil ||
			entry.failures > worst.failures ||
			(entry.failures == worst.failures && entry.lastSeen.Before(worst.lastSeen)) {
			worst = entry
		}
	}
	if worst != nil {
		delete(b.known, worst.addr)
	}
}

// markFailure records an unsuccessful dial, forgetting an address that has
// failed persistently.
func (b *addressBook) markFailure(addr string) {
	b.mu.Lock()
	defer b.mu.Unlock()

	entry, ok := b.known[addr]
	if !ok {
		return
	}
	entry.failures++
	if entry.failures >= 5 {
		delete(b.known, addr)
	}
}

// markSuccess records a working connection.
func (b *addressBook) markSuccess(addr string) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if entry, ok := b.known[addr]; ok {
		entry.failures = 0
		entry.lastSeen = b.now()
	}
}

// sample returns up to n addresses, freshest first.
func (b *addressBook) sample(n int) []string {
	b.mu.Lock()
	defer b.mu.Unlock()

	entries := make([]*addressEntry, 0, len(b.known))
	for _, entry := range b.known {
		entries = append(entries, entry)
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].failures != entries[j].failures {
			return entries[i].failures < entries[j].failures
		}
		return entries[i].lastSeen.After(entries[j].lastSeen)
	})

	if n > len(entries) {
		n = len(entries)
	}
	out := make([]string, 0, n)
	for _, entry := range entries[:n] {
		out = append(out, entry.addr)
	}
	return out
}

// size returns how many addresses are known.
func (b *addressBook) size() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.known)
}

// isDialable rejects addresses that cannot be connected to, so a peer cannot
// fill the book with junk or point the node at itself.
func isDialable(addr string) bool {
	host, port, err := net.SplitHostPort(addr)
	if err != nil || host == "" || port == "" || port == "0" {
		return false
	}
	if ip := net.ParseIP(host); ip != nil {
		if ip.IsUnspecified() || ip.IsMulticast() {
			return false
		}
	}
	return true
}

// AddressBookSize returns how many peer addresses the node knows.
func (s *Server) AddressBookSize() int { return s.addresses.size() }

// KnownAddresses returns the addresses the node could dial.
func (s *Server) KnownAddresses() []string { return s.addresses.sample(MaxAddressesPerMessage) }

// discoveryLoop periodically shares addresses and tops up connections.
func (s *Server) discoveryLoop() {
	defer s.wg.Done()

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-s.quit:
			return
		case <-ticker.C:
			s.exchangeAddresses()
			s.topUpPeers()
		}
	}
}

// exchangeAddresses asks peers for addresses and offers our own.
func (s *Server) exchangeAddresses() {
	addresses := s.addresses.sample(MaxAddressesPerMessage)
	if s.listener != nil {
		// Advertise where we can be reached, so peers can dial back.
		addresses = append(addresses, s.listener.Addr().String())
	}
	payload, err := encodePayload(&AddressesPayload{Addresses: addresses})
	if err != nil {
		return
	}
	for _, peer := range s.Peers() {
		peer.sendRaw(MsgAddresses, payload)
		peer.Send(MsgGetAddresses, nil)
	}
}

// topUpPeers dials known addresses when the node is short of connections.
func (s *Server) topUpPeers() {
	needed := s.config.MaxPeers/2 - s.PeerCount()
	if needed <= 0 {
		return
	}

	connected := make(map[string]struct{})
	for _, peer := range s.Peers() {
		connected[peer.RemoteAddr()] = struct{}{}
	}

	for _, addr := range s.addresses.sample(needed * 2) {
		if needed <= 0 {
			return
		}
		if _, ok := connected[addr]; ok {
			continue
		}
		if addr == s.Addr() {
			continue
		}
		conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
		if err != nil {
			s.addresses.markFailure(addr)
			continue
		}
		s.addresses.markSuccess(addr)
		needed--

		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.handleConnection(conn, false)
		}()
	}
}
