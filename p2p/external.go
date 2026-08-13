package p2p

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
)

// minObservations is how many peers must agree on an address before this node
// believes it.
//
// One peer's word is not enough. A node that took the first answer it was given
// would advertise whatever address a single hostile peer chose to name — an
// address that peer controls, or one belonging to a victim it wants the network
// to connect to on its behalf. Requiring agreement means an attacker has to own
// a majority of this node's connections to move its address, which is the same
// position it would need to eclipse the node anyway.
const minObservations = 3

// NATMode says how a node works out the address it advertises to peers.
type NATMode struct {
	// fixed is the address given on the command line, if any.
	fixed net.IP
	// disabled suppresses advertising altogether.
	disabled bool
}

// ParseNATMode reads the -nat setting.
//
// The vocabulary follows geth's, minus the mapping protocols: "none" advertises
// nothing, "extip:<ip>" states the address outright, and "auto" learns it from
// what peers report seeing.
func ParseNATMode(spec string) (NATMode, error) {
	switch {
	case spec == "" || spec == "auto":
		return NATMode{}, nil
	case spec == "none":
		return NATMode{disabled: true}, nil
	case strings.HasPrefix(spec, "extip:"):
		ip := net.ParseIP(strings.TrimPrefix(spec, "extip:"))
		if ip == nil {
			return NATMode{}, fmt.Errorf("p2p: %q is not an IP address", strings.TrimPrefix(spec, "extip:"))
		}
		return NATMode{fixed: ip}, nil
	default:
		return NATMode{}, fmt.Errorf("p2p: unknown nat mode %q, want none, auto or extip:<ip>", spec)
	}
}

// externalAddress tracks what this node should tell peers to dial.
type externalAddress struct {
	mu sync.Mutex
	// votes counts how many distinct peers reported each address.
	votes map[string]map[string]struct{}
	// settled is the address that has won, once one has.
	settled string
}

func newExternalAddress() *externalAddress {
	return &externalAddress{votes: make(map[string]map[string]struct{})}
}

// note records one peer's claim about where it sees us, and reports whether
// that changed the answer.
//
// The port is deliberately thrown away. A peer sees the port a connection was
// dialled from, which for an outbound connection is an ephemeral one that
// nothing is listening on; only the IP carries information, and the port has to
// come from this node's own listener.
func (e *externalAddress) note(observed string, from string, listenPort int) bool {
	host, _, err := net.SplitHostPort(observed)
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	if ip == nil || !isRoutable(ip) {
		return false
	}
	candidate := net.JoinHostPort(ip.String(), strconv.Itoa(listenPort))

	e.mu.Lock()
	defer e.mu.Unlock()
	if e.votes[candidate] == nil {
		e.votes[candidate] = make(map[string]struct{})
	}
	e.votes[candidate][from] = struct{}{}
	if len(e.votes[candidate]) < minObservations || e.settled == candidate {
		return false
	}
	e.settled = candidate
	return true
}

func (e *externalAddress) get() string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.settled
}

// isRoutable reports whether an address is one a stranger on the internet could
// reach. Private and link-local addresses are perfectly good on a LAN, but
// advertising one to the wider network sends peers nowhere.
func isRoutable(ip net.IP) bool {
	return !ip.IsUnspecified() &&
		!ip.IsLoopback() &&
		!ip.IsPrivate() &&
		!ip.IsLinkLocalUnicast() &&
		!ip.IsLinkLocalMulticast()
}
