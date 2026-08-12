package trie

import (
	"bytes"
	"fmt"
	"math/rand"
	"testing"

	"layer1/common"
	"layer1/db"
)

func newTrie() *Trie { return NewEmpty(db.NewMemoryDB()) }

func update(t *testing.T, tr *Trie, k, v string) {
	t.Helper()
	if err := tr.Update([]byte(k), []byte(v)); err != nil {
		t.Fatal(err)
	}
}

func TestEmptyRootMatchesSpec(t *testing.T) {
	want := "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421"
	if got := EmptyRoot.Hex(); got != want {
		t.Fatalf("EmptyRoot = %s, want %s", got, want)
	}
	if got := newTrie().Hash().Hex(); got != want {
		t.Fatalf("empty trie hash = %s, want %s", got, want)
	}
}

// Root hashes taken from the Ethereum reference trie test suite.
func TestKnownRootHashes(t *testing.T) {
	cases := []struct {
		name  string
		pairs [][2]string
		want  string
	}{
		{
			name: "branching keys",
			pairs: [][2]string{
				{"doe", "reindeer"},
				{"dog", "puppy"},
				{"dogglesworth", "cat"},
			},
			want: "0x8aad789dff2f538bca5d8ea56e8abe10f4c7ba3a5dea95fea4cd6e7c3a1168d3",
		},
		{
			name: "extension and branch mix",
			pairs: [][2]string{
				{"do", "verb"},
				{"horse", "stallion"},
				{"doge", "coin"},
				{"dog", "puppy"},
			},
			want: "0x5991bb8c6514148a29db676a14ac506cd2cd5775ace63c30a4fe457715e9ac84",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			tr := newTrie()
			for _, p := range c.pairs {
				update(t, tr, p[0], p[1])
			}
			got := tr.Hash().Hex()
			if c.want != "" && got != c.want {
				t.Errorf("root = %s, want %s", got, c.want)
			}
		})
	}
}

func TestOrderIndependence(t *testing.T) {
	pairs := [][2]string{{"do", "verb"}, {"horse", "stallion"}, {"doge", "coin"}, {"dog", "puppy"}}
	a := newTrie()
	for _, p := range pairs {
		update(t, a, p[0], p[1])
	}
	b := newTrie()
	for i := len(pairs) - 1; i >= 0; i-- {
		update(t, b, pairs[i][0], pairs[i][1])
	}
	if a.Hash() != b.Hash() {
		t.Fatalf("insertion order changed the root: %s vs %s", a.Hash(), b.Hash())
	}
}

func TestGetAndUpdate(t *testing.T) {
	tr := newTrie()
	update(t, tr, "key", "value")
	got, err := tr.Get([]byte("key"))
	if err != nil || string(got) != "value" {
		t.Fatalf("Get = %q, %v", got, err)
	}
	// Overwriting replaces the value.
	update(t, tr, "key", "replaced")
	got, _ = tr.Get([]byte("key"))
	if string(got) != "replaced" {
		t.Fatalf("Get after overwrite = %q", got)
	}
	// Absent keys return nil, not an error.
	got, err = tr.Get([]byte("absent"))
	if err != nil || got != nil {
		t.Fatalf("Get(absent) = %q, %v", got, err)
	}
}

func TestDeleteRestoresPreviousRoot(t *testing.T) {
	tr := newTrie()
	update(t, tr, "do", "verb")
	update(t, tr, "dog", "puppy")
	before := tr.Hash()

	update(t, tr, "doge", "coin")
	if tr.Hash() == before {
		t.Fatal("insertion did not change the root")
	}
	if err := tr.Delete([]byte("doge")); err != nil {
		t.Fatal(err)
	}
	if tr.Hash() != before {
		t.Fatalf("root after delete = %s, want %s", tr.Hash(), before)
	}
	if v, _ := tr.Get([]byte("doge")); v != nil {
		t.Fatalf("deleted key still resolves to %q", v)
	}
}

func TestDeleteEverythingReturnsToEmpty(t *testing.T) {
	tr := newTrie()
	keys := []string{"a", "ab", "abc", "b", "xyz", "xy"}
	for _, k := range keys {
		update(t, tr, k, "v-"+k)
	}
	for _, k := range keys {
		if err := tr.Delete([]byte(k)); err != nil {
			t.Fatal(err)
		}
	}
	if tr.Hash() != EmptyRoot {
		t.Fatalf("root after deleting everything = %s, want the empty root", tr.Hash())
	}
}

func TestUpdateWithEmptyValueDeletes(t *testing.T) {
	tr := newTrie()
	update(t, tr, "k1", "v1")
	update(t, tr, "k2", "v2")
	withBoth := tr.Hash()
	update(t, tr, "k2", "")
	if v, _ := tr.Get([]byte("k2")); v != nil {
		t.Fatal("storing an empty value must delete the key")
	}
	update(t, tr, "k2", "v2")
	if tr.Hash() != withBoth {
		t.Fatal("reinserting did not restore the original root")
	}
}

func TestCommitAndReload(t *testing.T) {
	store := db.NewMemoryDB()
	tr := NewEmpty(store)
	pairs := map[string]string{}
	for i := 0; i < 200; i++ {
		k := fmt.Sprintf("key-%d", i)
		v := fmt.Sprintf("value-%d-%s", i, bytes.Repeat([]byte("x"), i%40))
		pairs[k] = v
		update(t, tr, k, v)
	}
	root, err := tr.CommitTo(store)
	if err != nil {
		t.Fatal(err)
	}
	if root != tr.Hash() {
		t.Fatalf("Commit root %s disagrees with Hash %s", root, tr.Hash())
	}

	reloaded, err := New(root, store)
	if err != nil {
		t.Fatal(err)
	}
	for k, want := range pairs {
		got, err := reloaded.Get([]byte(k))
		if err != nil {
			t.Fatalf("Get(%s): %v", k, err)
		}
		if string(got) != want {
			t.Fatalf("Get(%s) = %q, want %q", k, got, want)
		}
	}
	if reloaded.Hash() != root {
		t.Fatalf("reloaded root = %s, want %s", reloaded.Hash(), root)
	}
}

func TestCommitSmallTrieIsReloadable(t *testing.T) {
	// A trie whose root node encodes to under 32 bytes is a special case: the
	// root is not referenced by hash anywhere, so Commit has to store it anyway.
	store := db.NewMemoryDB()
	tr := NewEmpty(store)
	update(t, tr, "a", "b")
	root, err := tr.CommitTo(store)
	if err != nil {
		t.Fatal(err)
	}
	reloaded, err := New(root, store)
	if err != nil {
		t.Fatalf("small root did not reload: %v", err)
	}
	got, _ := reloaded.Get([]byte("a"))
	if string(got) != "b" {
		t.Fatalf("value after reload = %q", got)
	}
}

func TestMutationAfterReload(t *testing.T) {
	store := db.NewMemoryDB()
	tr := NewEmpty(store)
	for i := 0; i < 50; i++ {
		update(t, tr, fmt.Sprintf("k%02d", i), fmt.Sprintf("v%02d", i))
	}
	root, _ := tr.CommitTo(store)

	reloaded, err := New(root, store)
	if err != nil {
		t.Fatal(err)
	}
	// Deleting through hash nodes forces them to resolve from the store.
	if err := reloaded.Delete([]byte("k25")); err != nil {
		t.Fatal(err)
	}
	update(t, reloaded, "k99", "v99")

	fresh := NewEmpty(db.NewMemoryDB())
	for i := 0; i < 50; i++ {
		if i == 25 {
			continue
		}
		update(t, fresh, fmt.Sprintf("k%02d", i), fmt.Sprintf("v%02d", i))
	}
	update(t, fresh, "k99", "v99")

	if reloaded.Hash() != fresh.Hash() {
		t.Fatalf("mutating a reloaded trie diverged: %s vs %s", reloaded.Hash(), fresh.Hash())
	}
}

func TestForEach(t *testing.T) {
	tr := newTrie()
	want := map[string]string{"alpha": "1", "beta": "2", "gamma": "3", "a": "4"}
	for k, v := range want {
		update(t, tr, k, v)
	}
	got := map[string]string{}
	err := tr.ForEach(func(k, v []byte) bool {
		got[string(k)] = string(v)
		return true
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(want) {
		t.Fatalf("ForEach visited %d entries, want %d: %v", len(got), len(want), got)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("ForEach[%s] = %q, want %q", k, got[k], v)
		}
	}
}

func TestProofOfInclusion(t *testing.T) {
	tr := newTrie()
	entries := map[string]string{}
	for i := 0; i < 100; i++ {
		k := fmt.Sprintf("account-%d", i)
		v := fmt.Sprintf("balance-%d", i*1000)
		entries[k] = v
		update(t, tr, k, v)
	}
	root := tr.Hash()

	for k, want := range entries {
		proof, err := tr.Prove([]byte(k))
		if err != nil {
			t.Fatalf("Prove(%s): %v", k, err)
		}
		got, err := VerifyProof(root, []byte(k), proof)
		if err != nil {
			t.Fatalf("VerifyProof(%s): %v", k, err)
		}
		if string(got) != want {
			t.Fatalf("proof for %s yielded %q, want %q", k, got, want)
		}
	}
}

func TestProofOfExclusion(t *testing.T) {
	tr := newTrie()
	for i := 0; i < 50; i++ {
		update(t, tr, fmt.Sprintf("present-%d", i), "yes")
	}
	root := tr.Hash()

	for _, missing := range []string{"absent", "present-999", "zzz", ""} {
		proof, err := tr.Prove([]byte(missing))
		if err != nil {
			t.Fatalf("Prove(%q): %v", missing, err)
		}
		got, err := VerifyProof(root, []byte(missing), proof)
		if err != nil {
			t.Fatalf("VerifyProof(%q): %v", missing, err)
		}
		if got != nil {
			t.Fatalf("exclusion proof for %q returned %q", missing, got)
		}
	}
}

func TestProofRejectsWrongRoot(t *testing.T) {
	tr := newTrie()
	for i := 0; i < 20; i++ {
		update(t, tr, fmt.Sprintf("k%d", i), "v")
	}
	proof, err := tr.Prove([]byte("k5"))
	if err != nil {
		t.Fatal(err)
	}
	bogus := common.Keccak256([]byte("not the root"))
	if _, err := VerifyProof(bogus, []byte("k5"), proof); err == nil {
		t.Fatal("a proof must not verify against an unrelated root")
	}
}

func TestProofRejectsTamperedNode(t *testing.T) {
	tr := newTrie()
	for i := 0; i < 20; i++ {
		update(t, tr, fmt.Sprintf("key%d", i), fmt.Sprintf("value%d", i))
	}
	root := tr.Hash()
	proof, err := tr.Prove([]byte("key5"))
	if err != nil {
		t.Fatal(err)
	}
	// Corrupting any node breaks the hash chain, so verification must fail
	// rather than return a forged value.
	tampered := make([][]byte, len(proof))
	for i, n := range proof {
		tampered[i] = append([]byte(nil), n...)
	}
	tampered[0][len(tampered[0])-1] ^= 0xff

	if _, err := VerifyProof(root, []byte("key5"), tampered); err == nil {
		t.Fatal("a proof whose root node was altered must not verify")
	}
}

func TestDeriveRootIsDeterministic(t *testing.T) {
	items := [][]byte{[]byte("tx1"), []byte("tx2"), []byte("tx3")}
	a := DeriveRoot(items)
	b := DeriveRoot(items)
	if a != b {
		t.Fatal("DeriveRoot is not deterministic")
	}
	if DeriveRoot(nil) != EmptyRoot {
		t.Fatal("an empty list must derive the empty root")
	}
	// Order matters: these roots commit to positions, not just contents.
	swapped := [][]byte{items[1], items[0], items[2]}
	if DeriveRoot(swapped) == a {
		t.Fatal("reordering must change the derived root")
	}
}

func TestRandomizedAgainstReferenceMap(t *testing.T) {
	// Cross-check the trie against a plain map over a long random workload,
	// including deletes and reinserts, then confirm the root is reproducible.
	rng := rand.New(rand.NewSource(1))
	store := db.NewMemoryDB()
	tr := NewEmpty(store)
	ref := map[string]string{}

	for step := 0; step < 3000; step++ {
		key := fmt.Sprintf("k%d", rng.Intn(200))
		switch rng.Intn(4) {
		case 0:
			if err := tr.Delete([]byte(key)); err != nil {
				t.Fatal(err)
			}
			delete(ref, key)
		default:
			value := fmt.Sprintf("v%d", rng.Intn(1000))
			update(t, tr, key, value)
			ref[key] = value
		}

		if step%500 == 0 {
			for k, want := range ref {
				got, err := tr.Get([]byte(k))
				if err != nil {
					t.Fatal(err)
				}
				if string(got) != want {
					t.Fatalf("step %d: trie[%s] = %q, want %q", step, k, got, want)
				}
			}
		}
	}

	for k, want := range ref {
		got, _ := tr.Get([]byte(k))
		if string(got) != want {
			t.Fatalf("final: trie[%s] = %q, want %q", k, got, want)
		}
	}

	// The same content built from scratch must hash identically.
	fresh := NewEmpty(db.NewMemoryDB())
	for k, v := range ref {
		update(t, fresh, k, v)
	}
	if tr.Hash() != fresh.Hash() {
		t.Fatalf("root after churn %s != freshly built root %s", tr.Hash(), fresh.Hash())
	}

	// And it must survive a commit/reload cycle.
	root, err := tr.CommitTo(store)
	if err != nil {
		t.Fatal(err)
	}
	reloaded, err := New(root, store)
	if err != nil {
		t.Fatal(err)
	}
	for k, want := range ref {
		got, err := reloaded.Get([]byte(k))
		if err != nil || string(got) != want {
			t.Fatalf("reloaded[%s] = %q, %v", k, got, err)
		}
	}
}

func TestHexPrefixRoundTrip(t *testing.T) {
	cases := [][]byte{
		{},
		{1},
		{1, 2},
		{1, 2, 3},
		{16},
		{1, 16},
		{1, 2, 16},
		{0, 0, 0, 16},
	}
	for _, nibbles := range cases {
		got, err := hexPrefixDecode(hexPrefixEncode(nibbles))
		if err != nil {
			t.Fatalf("%v: %v", nibbles, err)
		}
		if !bytes.Equal(got, nibbles) {
			t.Fatalf("round-trip of %v gave %v", nibbles, got)
		}
	}
}

func TestNibbleConversionRoundTrip(t *testing.T) {
	for _, key := range [][]byte{{}, {0x00}, {0xff}, {0xde, 0xad, 0xbe, 0xef}} {
		if got := nibblesToKey(keyToNibbles(key)); !bytes.Equal(got, key) {
			t.Fatalf("round-trip of %x gave %x", key, got)
		}
	}
}

func TestMissingNodeIsReported(t *testing.T) {
	store := db.NewMemoryDB()
	tr := NewEmpty(store)
	for i := 0; i < 100; i++ {
		update(t, tr, fmt.Sprintf("k%d", i), fmt.Sprintf("v%d", i))
	}
	root, _ := tr.CommitTo(store)

	// Wipe the store: loading the root must fail loudly rather than silently
	// behaving like an empty trie.
	empty := db.NewMemoryDB()
	if _, err := New(root, empty); err == nil {
		t.Fatal("loading a root with no backing nodes must fail")
	}
}

func BenchmarkTrieUpdate(b *testing.B) {
	tr := NewEmpty(db.NewMemoryDB())
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tr.Update([]byte(fmt.Sprintf("key-%d", i)), []byte("value"))
	}
}

func BenchmarkTrieHash(b *testing.B) {
	tr := NewEmpty(db.NewMemoryDB())
	for i := 0; i < 1000; i++ {
		tr.Update([]byte(fmt.Sprintf("key-%d", i)), []byte(fmt.Sprintf("value-%d", i)))
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tr.Update([]byte("changing"), []byte(fmt.Sprintf("%d", i)))
		tr.Hash()
	}
}
