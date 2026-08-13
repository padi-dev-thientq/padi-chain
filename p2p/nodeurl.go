package p2p

import (
	"encoding/hex"
	"fmt"
	"strings"
)

// URLScheme prefixes a node URL, the way enode:// prefixes Ethereum's.
const URLScheme = "padi://"

// NodeURL names a node by identity and address: padi://<node id>@host:port.
//
// A bare host:port says where to connect but not to whom. That is enough to
// start a handshake and not enough to know it succeeded with the right party:
// anyone who can answer on that address — the operator of the machine, whoever
// controls the route to it, a DNS answer pointing elsewhere — completes a
// perfectly valid encrypted session as somebody else. Naming the key turns the
// handshake into a check, which is why Ethereum carries the public key in every
// enode URL and why bootstrap addresses in particular should always be written
// this way: those are the addresses that decide which network a node joins.
type NodeURL struct {
	ID   NodeID
	Addr string
}

// ParseNodeURL accepts either a full node URL or a bare host:port.
//
// The bare form is kept because it is what an operator reaches for first, and
// refusing it would make the common case of a private cluster harder for no
// benefit there. It returns a zero ID, and a zero ID means the dialler accepts
// whoever answers.
func ParseNodeURL(raw string) (NodeURL, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return NodeURL{}, fmt.Errorf("p2p: empty peer address")
	}
	rest := strings.TrimPrefix(raw, URLScheme)
	at := strings.LastIndex(rest, "@")
	if at < 0 {
		if !isDialable(rest) {
			return NodeURL{}, fmt.Errorf("p2p: %q is not a dialable address", raw)
		}
		return NodeURL{Addr: rest}, nil
	}

	key, err := hex.DecodeString(rest[:at])
	if err != nil {
		return NodeURL{}, fmt.Errorf("p2p: node id in %q is not hex: %w", raw, err)
	}
	if len(key) != len(NodeID{}) {
		return NodeURL{}, fmt.Errorf("p2p: node id in %q is %d bytes, want %d", raw, len(key), len(NodeID{}))
	}
	addr := rest[at+1:]
	if !isDialable(addr) {
		return NodeURL{}, fmt.Errorf("p2p: %q is not a dialable address", addr)
	}
	var url NodeURL
	copy(url.ID[:], key)
	url.Addr = addr
	return url, nil
}

// String renders the URL, or just the address when no identity is known.
func (u NodeURL) String() string {
	if u.ID == (NodeID{}) {
		return u.Addr
	}
	return URLScheme + hex.EncodeToString(u.ID[:]) + "@" + u.Addr
}

// wantsID reports whether this URL pins the identity of who must answer.
func (u NodeURL) wantsID() bool { return u.ID != (NodeID{}) }

// NodeURL returns the address other nodes should use to reach this one, or
// empty if it does not know a routable address yet.
func (s *Server) NodeURL() string {
	external := s.ExternalAddr()
	if external == "" {
		return ""
	}
	return NodeURL{ID: NodeIDOf(s.config.NodeKey), Addr: external}.String()
}
