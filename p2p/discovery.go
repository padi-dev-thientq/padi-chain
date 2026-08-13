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
	// Entries may be bare host:port or full node URLs, so dialability is
	// judged on the address the URL resolves to rather than the raw string.
	if _, err := ParseNodeURL(addr); err != nil {
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
// evictWorstLocked frees a slot, taking from the most crowded netgroup first.
//
// Ranking purely on failures and age would hand the book to whoever floods it:
// a few thousand freshly minted addresses from one attacker's subnet all look
// new and unfailed, so they push out every peer the node had actually reached,
// and from then on it hears only from that attacker. Evicting from whichever
// netgroup is largest means a flood displaces itself, and the cost of filling
// the book stops being a matter of inventing addresses and starts being a
// matter of controlling networks.
func (b *addressBook) evictWorstLocked() {
	counts := make(map[string]int, len(b.known))
	for _, entry := range b.known {
		counts[netgroup(entry.addr)]++
	}

	var worst *addressEntry
	worstCount := 0
	for _, entry := range b.known {
		count := counts[netgroup(entry.addr)]
		if worst == nil || worseThan(entry, count, worst, worstCount) {
			worst, worstCount = entry, count
		}
	}
	if worst != nil {
		delete(b.known, worst.addr)
	}
}

// worseThan orders eviction candidates: crowded netgroup first, then the entry
// that has failed most, then the one heard from longest ago.
func worseThan(a *addressEntry, aCount int, b *addressEntry, bCount int) bool {
	if aCount != bCount {
		return aCount > bCount
	}
	if a.failures != b.failures {
		return a.failures > b.failures
	}
	return a.lastSeen.Before(b.lastSeen)
}

// netgroup is the part of an address an attacker cannot cheaply vary.
//
// Addresses are grouped by the first sixteen bits for IPv4 and the first
// thirty-two for IPv6, which is Bitcoin's rule. It is a rough proxy for "under
// one party's control" — wrong at the edges in both directions, and still the
// difference between an attacker needing many networks and merely needing many
// addresses. A name that has not been resolved is its own group.
func netgroup(addr string) string {
	target, err := ParseNodeURL(addr)
	if err != nil {
		return addr
	}
	host, _, err := net.SplitHostPort(target.Addr)
	if err != nil {
		return addr
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return host
	}
	if v4 := ip.To4(); v4 != nil {
		return "v4:" + v4[:2].String()
	}
	return "v6:" + ip.To16()[:4].String()
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

	// Take at most one address per netgroup on each pass. The order above still
	// decides who goes first, but a party holding many addresses in one network
	// cannot take more than its share of the connections this node is about to
	// make, or of the addresses it is about to pass on to others.
	var order []string
	byGroup := make(map[string][]string, len(entries))
	for _, entry := range entries {
		group := netgroup(entry.addr)
		if _, ok := byGroup[group]; !ok {
			order = append(order, group)
		}
		byGroup[group] = append(byGroup[group], entry.addr)
	}

	out := make([]string, 0, n)
	for round := 0; len(out) < n; round++ {
		progressed := false
		for _, group := range order {
			if len(out) == n {
				break
			}
			if round >= len(byGroup[group]) {
				continue
			}
			out = append(out, byGroup[group][round])
			progressed = true
		}
		if !progressed {
			break
		}
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
	// Advertise where we can be reached, so peers can dial back. This has to be
	// the address the outside world sees, not the socket this node bound: bound
	// to 0.0.0.0 the socket's address is 0.0.0.0, and telling peers to dial
	// that sends them nowhere.
	// The full node URL is shared rather than the bare address, so the identity
	// travels with it and a peer two hops away can still check who answers.
	if url := s.NodeURL(); url != "" {
		addresses = append(addresses, url)
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
		if addr == s.Addr() || addr == s.NodeURL() {
			continue
		}
		target, err := ParseNodeURL(addr)
		if err != nil {
			continue
		}
		conn, err := net.DialTimeout("tcp", target.Addr, 5*time.Second)
		if err != nil {
			s.addresses.markFailure(addr)
			continue
		}
		s.addresses.markSuccess(addr)
		needed--

		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.handleConnectionAs(conn, false, target)
		}()
	}
}
