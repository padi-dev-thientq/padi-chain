package db

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

// runDatabaseSuite exercises the contract every Database implementation must meet.
func runDatabaseSuite(t *testing.T, open func(t *testing.T) Database) {
	t.Run("put get delete", func(t *testing.T) {
		d := open(t)
		if err := d.Put([]byte("k"), []byte("v")); err != nil {
			t.Fatal(err)
		}
		got, err := d.Get([]byte("k"))
		if err != nil || string(got) != "v" {
			t.Fatalf("Get = %q, %v", got, err)
		}
		if ok, _ := d.Has([]byte("k")); !ok {
			t.Fatal("Has = false for a present key")
		}
		if err := d.Delete([]byte("k")); err != nil {
			t.Fatal(err)
		}
		if _, err := d.Get([]byte("k")); err != ErrNotFound {
			t.Fatalf("Get after Delete = %v, want ErrNotFound", err)
		}
		if ok, _ := d.Has([]byte("k")); ok {
			t.Fatal("Has = true after Delete")
		}
	})

	t.Run("overwrite", func(t *testing.T) {
		d := open(t)
		d.Put([]byte("k"), []byte("first"))
		d.Put([]byte("k"), []byte("second"))
		got, _ := d.Get([]byte("k"))
		if string(got) != "second" {
			t.Fatalf("Get = %q, want second", got)
		}
	})

	t.Run("empty value", func(t *testing.T) {
		d := open(t)
		d.Put([]byte("empty"), []byte{})
		got, err := d.Get([]byte("empty"))
		if err != nil || len(got) != 0 {
			t.Fatalf("Get = %q, %v", got, err)
		}
	})

	t.Run("missing key", func(t *testing.T) {
		d := open(t)
		if _, err := d.Get([]byte("nope")); err != ErrNotFound {
			t.Fatalf("got %v, want ErrNotFound", err)
		}
	})

	t.Run("batch is atomic on write", func(t *testing.T) {
		d := open(t)
		b := d.NewBatch()
		b.Put([]byte("a"), []byte("1"))
		b.Put([]byte("b"), []byte("2"))
		b.Delete([]byte("a"))
		if b.Len() != 3 {
			t.Fatalf("Len = %d, want 3", b.Len())
		}
		// Nothing is visible before Write.
		if ok, _ := d.Has([]byte("b")); ok {
			t.Fatal("batch leaked before Write")
		}
		if err := b.Write(); err != nil {
			t.Fatal(err)
		}
		if ok, _ := d.Has([]byte("a")); ok {
			t.Fatal("delete in batch was not applied")
		}
		got, _ := d.Get([]byte("b"))
		if string(got) != "2" {
			t.Fatalf("b = %q", got)
		}
		if b.Len() != 0 {
			t.Fatal("batch should be empty after Write")
		}
	})

	t.Run("batch reset discards", func(t *testing.T) {
		d := open(t)
		b := d.NewBatch()
		b.Put([]byte("x"), []byte("y"))
		b.Reset()
		if err := b.Write(); err != nil {
			t.Fatal(err)
		}
		if ok, _ := d.Has([]byte("x")); ok {
			t.Fatal("Reset did not discard the pending write")
		}
	})

	t.Run("iterate by prefix in order", func(t *testing.T) {
		d := open(t)
		d.Put([]byte("aa"), []byte("1"))
		d.Put([]byte("ab"), []byte("2"))
		d.Put([]byte("ba"), []byte("3"))

		var keys []string
		if err := d.Iterate([]byte("a"), func(k, v []byte) bool {
			keys = append(keys, string(k))
			return true
		}); err != nil {
			t.Fatal(err)
		}
		if len(keys) != 2 || keys[0] != "aa" || keys[1] != "ab" {
			t.Fatalf("prefix iteration = %v", keys)
		}

		// An empty prefix visits everything.
		count := 0
		d.Iterate(nil, func(k, v []byte) bool { count++; return true })
		if count != 3 {
			t.Fatalf("full iteration visited %d keys, want 3", count)
		}

		// Returning false stops early.
		visited := 0
		d.Iterate(nil, func(k, v []byte) bool { visited++; return false })
		if visited != 1 {
			t.Fatalf("early stop visited %d keys, want 1", visited)
		}
	})

	t.Run("value is copied out", func(t *testing.T) {
		d := open(t)
		value := []byte("mutable")
		d.Put([]byte("k"), value)
		value[0] = 'X' // mutating the caller's buffer must not affect the store
		got, _ := d.Get([]byte("k"))
		if string(got) != "mutable" {
			t.Fatalf("store aliased the caller's slice: %q", got)
		}
	})
}

func TestMemoryDB(t *testing.T) {
	runDatabaseSuite(t, func(t *testing.T) Database { return NewMemoryDB() })
}

func TestFileDB(t *testing.T) {
	runDatabaseSuite(t, func(t *testing.T) Database {
		d, err := OpenFile(filepath.Join(t.TempDir(), "test.db"), Options{})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { d.Close() })
		return d
	})
}

func TestFileDBPersistsAcrossReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "persist.db")
	d, err := OpenFile(path, Options{Sync: true})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 100; i++ {
		if err := d.Put([]byte(fmt.Sprintf("key%03d", i)), []byte(fmt.Sprintf("value%d", i))); err != nil {
			t.Fatal(err)
		}
	}
	d.Delete([]byte("key007"))
	d.Put([]byte("key008"), []byte("overwritten"))
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := OpenFile(path, Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()

	if _, err := reopened.Get([]byte("key007")); err != ErrNotFound {
		t.Error("deletion did not survive reopen")
	}
	got, _ := reopened.Get([]byte("key008"))
	if string(got) != "overwritten" {
		t.Errorf("key008 = %q after reopen", got)
	}
	got, _ = reopened.Get([]byte("key042"))
	if string(got) != "value42" {
		t.Errorf("key042 = %q after reopen", got)
	}
}

func TestFileDBRecoversFromTornWrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "torn.db")
	d, err := OpenFile(path, Options{Sync: true})
	if err != nil {
		t.Fatal(err)
	}
	d.Put([]byte("good1"), []byte("v1"))
	d.Put([]byte("good2"), []byte("v2"))
	d.Close()

	// Simulate a crash partway through appending a third record.
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	f.Write([]byte{opPut, 0, 0, 0, 5, 0, 0}) // truncated header
	f.Close()

	recovered, err := OpenFile(path, Options{})
	if err != nil {
		t.Fatalf("open must recover from a torn tail, got %v", err)
	}
	defer recovered.Close()

	if got, _ := recovered.Get([]byte("good2")); string(got) != "v2" {
		t.Errorf("intact records lost during recovery: %q", got)
	}
	// The store must be usable again after recovery.
	if err := recovered.Put([]byte("after"), []byte("ok")); err != nil {
		t.Fatal(err)
	}
	if got, _ := recovered.Get([]byte("after")); string(got) != "ok" {
		t.Error("write after recovery failed")
	}
}

func TestFileDBDetectsCorruptRecord(t *testing.T) {
	path := filepath.Join(t.TempDir(), "corrupt.db")
	d, _ := OpenFile(path, Options{Sync: true})
	d.Put([]byte("keep"), []byte("value"))
	d.Put([]byte("corrupt"), []byte("payload"))
	d.Close()

	// Flip a byte inside the second record's payload; its CRC no longer matches.
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	raw[len(raw)-1] ^= 0xff
	os.WriteFile(path, raw, 0o644)

	reopened, err := OpenFile(path, Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()

	if got, _ := reopened.Get([]byte("keep")); string(got) != "value" {
		t.Error("records before the corruption should survive")
	}
	if _, err := reopened.Get([]byte("corrupt")); err != ErrNotFound {
		t.Error("a record failing its checksum must not be trusted")
	}
}

func TestFileDBCompaction(t *testing.T) {
	path := filepath.Join(t.TempDir(), "compact.db")
	d, err := OpenFile(path, Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()

	// Rewrite the same keys repeatedly so most of the log is dead weight.
	for round := 0; round < 50; round++ {
		for i := 0; i < 10; i++ {
			d.Put([]byte(fmt.Sprintf("k%d", i)), bytes.Repeat([]byte{byte(round)}, 64))
		}
	}
	d.Delete([]byte("k0"))

	before, _ := os.Stat(path)
	if err := d.Compact(); err != nil {
		t.Fatal(err)
	}
	after, _ := os.Stat(path)
	if after.Size() >= before.Size() {
		t.Fatalf("compaction did not shrink the log: %d -> %d", before.Size(), after.Size())
	}

	// Live data must be intact and the store still writable.
	if _, err := d.Get([]byte("k0")); err != ErrNotFound {
		t.Error("deleted key reappeared after compaction")
	}
	got, err := d.Get([]byte("k5"))
	if err != nil || !bytes.Equal(got, bytes.Repeat([]byte{49}, 64)) {
		t.Errorf("k5 after compaction = %x, %v", got, err)
	}
	if err := d.Put([]byte("new"), []byte("value")); err != nil {
		t.Fatal(err)
	}
	if got, _ := d.Get([]byte("new")); string(got) != "value" {
		t.Error("write after compaction failed")
	}
}

func TestFileDBSurvivesCompactionReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "compact-reopen.db")
	d, _ := OpenFile(path, Options{})
	for i := 0; i < 20; i++ {
		d.Put([]byte("key"), []byte(fmt.Sprintf("v%d", i)))
	}
	d.Compact()
	d.Put([]byte("post"), []byte("compact"))
	d.Close()

	reopened, err := OpenFile(path, Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if got, _ := reopened.Get([]byte("key")); string(got) != "v19" {
		t.Errorf("key = %q after compaction and reopen", got)
	}
	if got, _ := reopened.Get([]byte("post")); string(got) != "compact" {
		t.Errorf("post = %q after compaction and reopen", got)
	}
}

func TestConcurrentAccess(t *testing.T) {
	for name, d := range map[string]Database{
		"memory": NewMemoryDB(),
		"file": func() Database {
			f, err := OpenFile(filepath.Join(t.TempDir(), "concurrent.db"), Options{})
			if err != nil {
				t.Fatal(err)
			}
			return f
		}(),
	} {
		t.Run(name, func(t *testing.T) {
			defer d.Close()
			var wg sync.WaitGroup
			for w := 0; w < 8; w++ {
				wg.Add(1)
				go func(w int) {
					defer wg.Done()
					for i := 0; i < 100; i++ {
						key := []byte(fmt.Sprintf("w%d-k%d", w, i))
						if err := d.Put(key, []byte("v")); err != nil {
							t.Error(err)
							return
						}
						if _, err := d.Get(key); err != nil {
							t.Error(err)
							return
						}
					}
				}(w)
			}
			wg.Wait()
		})
	}
}
