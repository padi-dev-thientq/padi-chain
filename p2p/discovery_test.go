package p2p

import (
	"fmt"
	"testing"
	"time"
)

func TestAddressBookAddAndSample(t *testing.T) {
	book := newAddressBook(10)

	if !book.add("192.0.2.1:30303") {
		t.Fatal("a fresh address was not recorded")
	}
	if book.add("192.0.2.1:30303") {
		t.Fatal("the same address was recorded twice")
	}
	if book.size() != 1 {
		t.Fatalf("book holds %d addresses, want 1", book.size())
	}

	sample := book.sample(5)
	if len(sample) != 1 || sample[0] != "192.0.2.1:30303" {
		t.Fatalf("sample = %v", sample)
	}
}

func TestAddressBookRejectsJunk(t *testing.T) {
	book := newAddressBook(10)
	// A peer can claim anything, so unusable addresses must not take up space.
	for _, bad := range []string{"", "not-an-address", "192.0.2.1", "0.0.0.0:30303", "192.0.2.1:0", "224.0.0.1:30303"} {
		if book.add(bad) {
			t.Errorf("accepted the unusable address %q", bad)
		}
	}
	if book.size() != 0 {
		t.Fatalf("book holds %d junk addresses", book.size())
	}
}

func TestAddressBookIsBounded(t *testing.T) {
	book := newAddressBook(16)
	for i := 0; i < 100; i++ {
		book.add(fmt.Sprintf("192.0.2.%d:30303", i%254+1))
	}
	if book.size() > 16 {
		t.Fatalf("book grew to %d entries past its limit of 16", book.size())
	}
}

func TestFailingAddressesAreForgotten(t *testing.T) {
	book := newAddressBook(10)
	addr := "192.0.2.1:30303"
	book.add(addr)

	for i := 0; i < 4; i++ {
		book.markFailure(addr)
		if book.size() != 1 {
			t.Fatalf("the address was dropped after only %d failures", i+1)
		}
	}
	book.markFailure(addr)
	if book.size() != 0 {
		t.Fatal("an address that never answers should be forgotten")
	}
}

func TestWorkingAddressesArePreferred(t *testing.T) {
	book := newAddressBook(10)
	now := time.Now()
	book.now = func() time.Time { return now }

	book.add("192.0.2.1:30303")
	book.add("192.0.2.2:30303")
	book.markFailure("192.0.2.1:30303")

	// The one that has never failed should be offered first.
	if got := book.sample(2); got[0] != "192.0.2.2:30303" {
		t.Fatalf("sample order = %v, want the working address first", got)
	}

	book.markSuccess("192.0.2.1:30303")
	now = now.Add(time.Minute)
	book.add("192.0.2.2:30303") // refresh
	if got := book.sample(2); len(got) != 2 {
		t.Fatalf("sample = %v", got)
	}
}

func TestSuccessClearsFailures(t *testing.T) {
	book := newAddressBook(10)
	addr := "192.0.2.1:30303"
	book.add(addr)

	for i := 0; i < 4; i++ {
		book.markFailure(addr)
	}
	// A peer that comes back gets a clean slate, so a transient outage does
	// not permanently cost the network an address.
	book.markSuccess(addr)
	for i := 0; i < 4; i++ {
		book.markFailure(addr)
	}
	if book.size() != 1 {
		t.Fatal("a recovered address was dropped too eagerly")
	}
}
