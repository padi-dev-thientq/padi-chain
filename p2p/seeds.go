package p2p

import (
	"context"
	"net"
	"strings"
	"time"
)

// Bootnodes is the list a node falls back on when the operator names no peers.
//
// It is empty here, and that is a statement rather than an omission: there is no
// public padi-chain network to seed from. Ethereum and Bitcoin ship the
// addresses of machines their foundations run, which is what makes a fresh
// install able to find the network with no configuration; whoever launches a
// network on this software has to run those machines and put their node URLs
// here. Bare addresses would do nothing for authenticity — a bootstrap address
// decides which chain a node ends up on, so these should always carry the key.
var Bootnodes = []string{}

// dnsSeedTimeout bounds a seed lookup, which happens while the node is starting.
const dnsSeedTimeout = 5 * time.Second

// resolveSeeds turns DNS seed domains into peer addresses.
//
// The domain's TXT records hold node URLs, one per record, the way Ethereum's
// EIP-1459 discovery does; a record that is only an address still works, and
// only means the node it names is not authenticated. This is the cheapest way
// to change the entry points of a network after clients have shipped, which is
// why every chain that has run for any length of time has something like it.
//
// A seed operator sees the IP of everyone who resolves, and a compromised seed
// hands out whatever peers it likes, so what comes back is treated as a hint:
// addresses to try, not a set of peers to trust. The genesis check in the
// handshake is what stops a bad hint from putting a node on the wrong chain.
func resolveSeeds(domains []string) []string {
	if len(domains) == 0 {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), dnsSeedTimeout)
	defer cancel()

	var found []string
	seen := make(map[string]struct{})
	resolver := net.DefaultResolver
	for _, domain := range domains {
		records, err := resolver.LookupTXT(ctx, domain)
		if err != nil {
			continue
		}
		for _, record := range records {
			for _, field := range strings.Fields(record) {
				url, err := ParseNodeURL(field)
				if err != nil {
					continue
				}
				if _, ok := seen[url.String()]; ok {
					continue
				}
				seen[url.String()] = struct{}{}
				found = append(found, url.String())
			}
		}
	}
	return found
}

// bootstrapAddresses is every entry point this node will try, in the order it
// trusts them: what the operator asked for, then the network's own seeds.
func (s *Server) bootstrapAddresses() []string {
	if len(s.config.Bootstrap) > 0 {
		return s.config.Bootstrap
	}
	addresses := append([]string(nil), Bootnodes...)
	if seeds := resolveSeeds(s.config.DNSSeeds); len(seeds) > 0 {
		s.log.Info("resolved dns seeds", "domains", len(s.config.DNSSeeds), "peers", len(seeds))
		addresses = append(addresses, seeds...)
	}
	return addresses
}
