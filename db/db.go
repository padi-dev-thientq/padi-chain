// Package db provides the key/value storage the node is built on: an in-memory
// store for tests and ephemeral nodes, and a durable append-only log store for
// real chain data.
package db

import (
	"errors"
	"sort"
	"sync"
)

// ErrNotFound is returned by Get for absent keys.
var ErrNotFound = errors.New("db: key not found")

// Reader is the read half of a store.
type Reader interface {
	Get(key []byte) ([]byte, error)
	Has(key []byte) (bool, error)
}

// Writer is the write half of a store.
type Writer interface {
	Put(key, value []byte) error
	Delete(key []byte) error
}

// Batch accumulates writes that are applied together.
type Batch interface {
	Writer
	// Len reports the number of pending operations.
	Len() int
	// Write applies every pending operation to the underlying store.
	Write() error
	// Reset discards pending operations so the batch can be reused.
	Reset()
}

// Database is a key/value store with batching and prefix iteration.
type Database interface {
	Reader
	Writer
	NewBatch() Batch
	// Iterate calls fn for each key with the given prefix, in key order.
	// Returning false from fn stops the iteration.
	Iterate(prefix []byte, fn func(key, value []byte) bool) error
	Close() error
}

// MemoryDB is a concurrency-safe in-memory Database.
type MemoryDB struct {
	mu   sync.RWMutex
	data map[string][]byte
}

func NewMemoryDB() *MemoryDB {
	return &MemoryDB{data: make(map[string][]byte)}
}

func (m *MemoryDB) Get(key []byte) ([]byte, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	v, ok := m.data[string(key)]
	if !ok {
		return nil, ErrNotFound
	}
	out := make([]byte, len(v))
	copy(out, v)
	return out, nil
}

func (m *MemoryDB) Has(key []byte) (bool, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	_, ok := m.data[string(key)]
	return ok, nil
}

func (m *MemoryDB) Put(key, value []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	v := make([]byte, len(value))
	copy(v, value)
	m.data[string(key)] = v
	return nil
}

func (m *MemoryDB) Delete(key []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.data, string(key))
	return nil
}

func (m *MemoryDB) Len() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.data)
}

func (m *MemoryDB) Iterate(prefix []byte, fn func(key, value []byte) bool) error {
	m.mu.RLock()
	keys := make([]string, 0, len(m.data))
	for k := range m.data {
		if hasPrefix(k, prefix) {
			keys = append(keys, k)
		}
	}
	m.mu.RUnlock()

	sort.Strings(keys)
	for _, k := range keys {
		v, err := m.Get([]byte(k))
		if errors.Is(err, ErrNotFound) {
			continue // removed while iterating
		}
		if err != nil {
			return err
		}
		if !fn([]byte(k), v) {
			return nil
		}
	}
	return nil
}

func (m *MemoryDB) Close() error { return nil }

func (m *MemoryDB) NewBatch() Batch { return &memBatch{db: m} }

func hasPrefix(s string, prefix []byte) bool {
	if len(prefix) == 0 {
		return true
	}
	return len(s) >= len(prefix) && s[:len(prefix)] == string(prefix)
}

type memOp struct {
	key    []byte
	value  []byte
	delete bool
}

type memBatch struct {
	db  *MemoryDB
	ops []memOp
}

func (b *memBatch) Put(key, value []byte) error {
	b.ops = append(b.ops, memOp{key: clone(key), value: clone(value)})
	return nil
}

func (b *memBatch) Delete(key []byte) error {
	b.ops = append(b.ops, memOp{key: clone(key), delete: true})
	return nil
}

func (b *memBatch) Len() int { return len(b.ops) }

func (b *memBatch) Write() error {
	b.db.mu.Lock()
	defer b.db.mu.Unlock()
	for _, op := range b.ops {
		if op.delete {
			delete(b.db.data, string(op.key))
		} else {
			b.db.data[string(op.key)] = op.value
		}
	}
	b.ops = b.ops[:0]
	return nil
}

func (b *memBatch) Reset() { b.ops = b.ops[:0] }

func clone(b []byte) []byte {
	out := make([]byte, len(b))
	copy(out, b)
	return out
}

// TrackingDB records the keys written through it.
//
// A mark-and-sweep pruner needs this: anything written while it is deciding
// what is reachable has not been marked, and deleting it would corrupt the
// state that was just committed. Recording those writes lets the sweep skip
// them instead.
type TrackingDB struct {
	Database

	mu       sync.Mutex
	tracking bool
	written  map[string]struct{}
}

// NewTrackingDB wraps a database with write tracking, initially disabled.
func NewTrackingDB(base Database) *TrackingDB {
	return &TrackingDB{Database: base, written: make(map[string]struct{})}
}

// StartTracking begins recording writes, discarding anything recorded before.
func (t *TrackingDB) StartTracking() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.tracking = true
	t.written = make(map[string]struct{})
}

// StopTracking stops recording and returns the keys written since tracking
// began.
func (t *TrackingDB) StopTracking() map[string]struct{} {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.tracking = false
	out := t.written
	t.written = make(map[string]struct{})
	return out
}

// Written returns the keys recorded so far without stopping.
func (t *TrackingDB) Written() map[string]struct{} {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make(map[string]struct{}, len(t.written))
	for k := range t.written {
		out[k] = struct{}{}
	}
	return out
}

func (t *TrackingDB) record(key []byte) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.tracking {
		t.written[string(key)] = struct{}{}
	}
}

func (t *TrackingDB) Put(key, value []byte) error {
	t.record(key)
	return t.Database.Put(key, value)
}

func (t *TrackingDB) NewBatch() Batch {
	return &trackingBatch{Batch: t.Database.NewBatch(), tracker: t}
}

type trackingBatch struct {
	Batch
	tracker *TrackingDB
}

func (b *trackingBatch) Put(key, value []byte) error {
	// Record at queue time rather than at write time: the pruner's sweep must
	// treat a key as live from the moment a commit intends to write it.
	b.tracker.record(key)
	return b.Batch.Put(key, value)
}
