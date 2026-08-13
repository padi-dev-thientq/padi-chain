package p2p

import (
	"fmt"
	"net"
	"strings"
	"testing"
)

func TestExternalAddressNeedsAgreement(t *testing.T) {
	e := newExternalAddress()

	// One peer's word does not move the address, and neither does the same
	// peer repeating itself: an attacker with a single connection would
	// otherwise choose what this node advertises to everyone.
	for i := 0; i < 10; i++ {
		if e.note("203.0.113.7:51000", "liar", 30303) {
			t.Fatal("a single peer settled the address")
		}
	}
	if e.get() != "" {
		t.Fatalf("address = %q, want none", e.get())
	}

	e = newExternalAddress()
	e.note("203.0.113.7:51000", "a", 30303)
	e.note("203.0.113.7:40000", "b", 30303)
	if e.get() != "" {
		t.Fatal("two peers should not be enough")
	}
	if !e.note("203.0.113.7:33333", "c", 30303) {
		t.Fatal("three peers agreeing should settle the address")
	}

	// The port comes from our own listener, never from what the peer saw: the
	// port it saw is the one we dialled out from, which nothing is listening on.
	if got, want := e.get(), "203.0.113.7:30303"; got != want {
		t.Fatalf("address = %q, want %q", got, want)
	}
}

func TestExternalAddressIgnoresUnreachableReports(t *testing.T) {
	// Addresses that are fine on a LAN but meaningless to a stranger must not
	// be advertised: a peer told to dial 192.168.1.4 goes to its own network.
	for _, observed := range []string{
		"0.0.0.0:30303",
		"127.0.0.1:30303",
		"192.168.1.4:30303",
		"10.0.0.9:30303",
		"169.254.3.3:30303",
		"not-an-address",
	} {
		e := newExternalAddress()
		for _, peer := range []string{"a", "b", "c", "d"} {
			e.note(observed, peer, 30303)
		}
		if e.get() != "" {
			t.Fatalf("%s was adopted as an external address", observed)
		}
	}
}

func TestParseNATMode(t *testing.T) {
	for _, spec := range []string{"", "auto"} {
		mode, err := ParseNATMode(spec)
		if err != nil || mode.disabled || mode.fixed != nil {
			t.Fatalf("%q should mean learn it from peers", spec)
		}
	}
	if mode, err := ParseNATMode("none"); err != nil || !mode.disabled {
		t.Fatal("none should suppress advertising")
	}
	mode, err := ParseNATMode("extip:198.51.100.4")
	if err != nil || !mode.fixed.Equal(net.ParseIP("198.51.100.4")) {
		t.Fatalf("extip did not parse: %v", err)
	}
	// A stated address is taken at face value even if it is private: that is
	// the operator's call, and it is how a LAN cluster is configured.
	if mode, err := ParseNATMode("extip:192.168.1.4"); err != nil || mode.fixed == nil {
		t.Fatal("a private extip should be accepted")
	}
	if _, err := ParseNATMode("extip:not-an-ip"); err == nil {
		t.Fatal("a malformed extip was accepted")
	}
	if _, err := ParseNATMode("upnp"); err == nil {
		t.Fatal("an unsupported mode was accepted")
	}
}

func TestParseNodeURL(t *testing.T) {
	id := "aabbccdd"
	for len(id) < 128 {
		id += "ef"
	}

	url, err := ParseNodeURL(URLScheme + id + "@198.51.100.4:30303")
	if err != nil {
		t.Fatal(err)
	}
	if url.Addr != "198.51.100.4:30303" || !url.wantsID() {
		t.Fatalf("parsed %+v", url)
	}
	if url.String() != URLScheme+id+"@198.51.100.4:30303" {
		t.Fatalf("round trip gave %q", url.String())
	}

	// A bare address is still accepted, and pins nobody.
	bare, err := ParseNodeURL("198.51.100.4:30303")
	if err != nil {
		t.Fatal(err)
	}
	if bare.wantsID() {
		t.Fatal("a bare address must not pin an identity")
	}
	if bare.String() != "198.51.100.4:30303" {
		t.Fatalf("bare round trip gave %q", bare.String())
	}

	for _, bad := range []string{
		"",
		"nonsense",
		"198.51.100.4",
		URLScheme + "tooshort@198.51.100.4:30303",
		URLScheme + id + "@198.51.100.4",
		URLScheme + "zz" + id[2:] + "@198.51.100.4:30303",
	} {
		if _, err := ParseNodeURL(bad); err == nil {
			t.Fatalf("%q was accepted", bad)
		}
	}
}

// TestAddressBookResistsAFlood is the eclipse attack in miniature: one party
// offers far more addresses than everyone else combined, and must not end up
// owning the connections this node makes.
func TestAddressBookResistsAFlood(t *testing.T) {
	book := newAddressBook(64)

	// A handful of honest peers, each from its own network.
	honest := []string{
		"198.51.100.1:30303",
		"203.0.113.1:30303",
		"192.0.2.1:30303",
	}
	for _, addr := range honest {
		if !book.add(addr) {
			t.Fatalf("%s was refused", addr)
		}
	}
	// The attacker holds one /16 and fills it.
	for i := 0; i < 500; i++ {
		book.add(net.JoinHostPort(fmt.Sprintf("100.64.%d.%d", i/256, i%256), "30303"))
	}

	// Every honest address survived the flood.
	known := make(map[string]struct{})
	for _, addr := range book.sample(book.size()) {
		known[addr] = struct{}{}
	}
	for _, addr := range honest {
		if _, ok := known[addr]; !ok {
			t.Fatalf("%s was evicted by the flood", addr)
		}
	}

	// And the attacker cannot take more than one of the first few slots the
	// node would dial.
	attacker := 0
	for _, addr := range book.sample(4) {
		if strings.HasPrefix(addr, "100.64.") {
			attacker++
		}
	}
	if attacker > 1 {
		t.Fatalf("%d of the first four addresses came from one netgroup", attacker)
	}
}

func TestNetgroupSeparatesNetworks(t *testing.T) {
	same := netgroup("198.51.100.1:30303") == netgroup("198.51.100.9:30303")
	if !same {
		t.Fatal("two addresses in one /16 should share a netgroup")
	}
	if netgroup("198.51.100.1:30303") == netgroup("198.52.100.1:30303") {
		t.Fatal("addresses in different /16s should not share a netgroup")
	}
	// The identity in a node URL must not change which network it belongs to.
	id := strings.Repeat("ab", 64)
	if netgroup(URLScheme+id+"@198.51.100.1:30303") != netgroup("198.51.100.1:30303") {
		t.Fatal("the node url form landed in a different netgroup")
	}
}
