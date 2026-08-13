package statesync

import (
	"fmt"
	"math/big"
	"testing"

	"padi-chain/common"
	"padi-chain/db"
	"padi-chain/state"
	"padi-chain/trie"
)

// buildState creates a populated state and returns its store and root.
func buildState(t *testing.T, accounts int) (db.Database, common.Hash) {
	t.Helper()
	store := db.NewMemoryDB()
	statedb, err := state.New(common.Hash{}, store)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < accounts; i++ {
		addr := common.BytesToAddress([]byte(fmt.Sprintf("account-%d", i)))
		statedb.AddBalance(addr, big.NewInt(int64(i+1)*1000))
		statedb.SetNonce(addr, uint64(i))
		// Every third account is a contract, so the sync has code and storage
		// tries to follow, not just the account trie.
		if i%3 == 0 {
			statedb.SetCode(addr, []byte(fmt.Sprintf("code-for-%d", i)))
			for j := 0; j < 4; j++ {
				statedb.SetState(addr,
					common.BytesToHash([]byte{byte(j)}),
					common.BytesToHash([]byte(fmt.Sprintf("v%d-%d", i, j))))
			}
		}
	}
	root, err := statedb.Commit(true)
	if err != nil {
		t.Fatal(err)
	}
	return store, root
}

// runSync drives a syncer against a source store until it finishes.
func runSync(t *testing.T, source db.Database, target db.Database, root common.Hash, batchSize int) *Syncer {
	t.Helper()
	syncer := New(target, root)

	for round := 0; !syncer.Done(); round++ {
		if round > 10000 {
			t.Fatal("the sync did not converge")
		}
		requests := syncer.Missing(batchSize)
		if len(requests) == 0 {
			t.Fatal("the sync stalled with work outstanding")
		}
		blobs := Serve(source, requests, batchSize)
		if _, err := syncer.Process(blobs); err != nil {
			t.Fatal(err)
		}
	}
	return syncer
}

func TestSyncReproducesState(t *testing.T) {
	source, root := buildState(t, 60)
	target := db.NewMemoryDB()

	syncer := runSync(t, source, target, root, 16)
	if err := syncer.Verify(); err != nil {
		t.Fatalf("the synced state did not verify: %v", err)
	}

	// The synced store must answer exactly as the original does.
	original, err := state.New(root, source)
	if err != nil {
		t.Fatal(err)
	}
	synced, err := state.New(root, target)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 60; i++ {
		addr := common.BytesToAddress([]byte(fmt.Sprintf("account-%d", i)))
		if got, want := synced.GetBalance(addr), original.GetBalance(addr); got.Cmp(want) != 0 {
			t.Fatalf("account %d balance = %s, want %s", i, got, want)
		}
		if got, want := synced.GetNonce(addr), original.GetNonce(addr); got != want {
			t.Fatalf("account %d nonce = %d, want %d", i, got, want)
		}
		if got, want := synced.GetCode(addr), original.GetCode(addr); string(got) != string(want) {
			t.Fatalf("account %d code = %q, want %q", i, got, want)
		}
		if i%3 == 0 {
			for j := 0; j < 4; j++ {
				key := common.BytesToHash([]byte{byte(j)})
				if got, want := synced.GetState(addr, key), original.GetState(addr, key); got != want {
					t.Fatalf("account %d slot %d = %s, want %s", i, j, got, want)
				}
			}
		}
	}
	t.Logf("synced %d blobs", syncer.Stored())
}

func TestSyncRejectsCorruptedNodes(t *testing.T) {
	source, root := buildState(t, 20)
	target := db.NewMemoryDB()
	syncer := New(target, root)

	requests := syncer.Missing(4)
	blobs := Serve(source, requests, 4)

	// A peer that alters a node cannot get it stored: the hash no longer
	// matches anything that was asked for.
	corrupted := make([][]byte, len(blobs))
	for i, blob := range blobs {
		corrupted[i] = append([]byte(nil), blob...)
		corrupted[i][len(corrupted[i])-1] ^= 0xff
	}
	accepted, err := syncer.Process(corrupted)
	if err != nil {
		t.Fatal(err)
	}
	if accepted != 0 {
		t.Fatalf("%d corrupted nodes were accepted", accepted)
	}
	if syncer.Stored() != 0 {
		t.Fatal("a corrupted node reached the store")
	}

	// The genuine nodes still work afterwards, so one bad peer does not spoil
	// the sync.
	if accepted, err := syncer.Process(blobs); err != nil || accepted == 0 {
		t.Fatalf("genuine nodes were refused after corruption: %d, %v", accepted, err)
	}
}

func TestSyncIgnoresUnsolicitedData(t *testing.T) {
	source, root := buildState(t, 10)
	target := db.NewMemoryDB()
	syncer := New(target, root)

	// Well-formed data that nothing asked for must not be stored: otherwise a
	// peer could fill the store with anything it liked.
	junk := [][]byte{[]byte("perfectly valid bytes, entirely unrequested")}
	accepted, err := syncer.Process(junk)
	if err != nil {
		t.Fatal(err)
	}
	if accepted != 0 || syncer.Stored() != 0 {
		t.Fatal("unrequested data was stored")
	}
	_ = source
}

func TestSyncSurvivesUnansweredRequests(t *testing.T) {
	source, root := buildState(t, 30)
	target := db.NewMemoryDB()
	syncer := New(target, root)

	dropped := 0
	for round := 0; !syncer.Done(); round++ {
		if round > 10000 {
			t.Fatal("the sync did not converge despite retries")
		}
		requests := syncer.Missing(8)
		if len(requests) == 0 {
			t.Fatal("the sync stalled")
		}
		// Every other round, the peer answers nothing at all.
		if round%2 == 0 {
			syncer.Retry(requests)
			dropped++
			continue
		}
		blobs := Serve(source, requests, 8)
		if _, err := syncer.Process(blobs); err != nil {
			t.Fatal(err)
		}
	}
	if dropped == 0 {
		t.Fatal("the test did not actually drop any responses")
	}
	if err := syncer.Verify(); err != nil {
		t.Fatal(err)
	}
}

func TestSyncSkipsWhatIsAlreadyHeld(t *testing.T) {
	source, root := buildState(t, 25)

	// Sync once, then sync the same root again into the same store: the second
	// pass should have nothing to fetch.
	target := db.NewMemoryDB()
	runSync(t, source, target, root, 32)

	second := New(target, root)
	if !second.Done() {
		t.Fatalf("a repeat sync still wants %d blobs", second.Pending())
	}
	if err := second.Verify(); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyRejectsIncompleteSync(t *testing.T) {
	source, root := buildState(t, 40)
	target := db.NewMemoryDB()
	syncer := New(target, root)

	// Stop partway through.
	for i := 0; i < 3 && !syncer.Done(); i++ {
		requests := syncer.Missing(4)
		blobs := Serve(source, requests, 4)
		syncer.Process(blobs)
	}
	if syncer.Done() {
		t.Skip("the state was too small to leave the sync incomplete")
	}
	if err := syncer.Verify(); err == nil {
		t.Fatal("an unfinished sync reported itself verified")
	}
}

func TestServeReturnsOnlyWhatItHas(t *testing.T) {
	source, root := buildState(t, 5)

	missing := common.Keccak256([]byte("a node nobody has"))
	blobs := Serve(source, []common.Hash{root, missing}, 10)
	if len(blobs) != 1 {
		t.Fatalf("Serve returned %d blobs, want 1", len(blobs))
	}
	if common.Keccak256(blobs[0]) != root {
		t.Fatal("Serve returned the wrong blob")
	}

	// The limit must be respected, so one request cannot pull the whole store.
	var many []common.Hash
	source.Iterate(trie.NodeKeyPrefix, func(key, _ []byte) bool {
		many = append(many, common.BytesToHash(key[1:]))
		return true
	})
	if got := Serve(source, many, 3); len(got) > 3 {
		t.Fatalf("Serve returned %d blobs past a limit of 3", len(got))
	}
}
