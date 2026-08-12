// Package statesync downloads a state trie from peers instead of rebuilding it
// by executing every block since genesis.
//
// The trie is content-addressed: a node's hash is the hash of its encoding, and
// each node names its children by hash. A syncer therefore never has to trust
// what a peer sends. It asks for a specific hash, checks that what arrives
// hashes to it, and discards anything else. A hostile peer can refuse to answer
// or send garbage; it cannot substitute state.
//
// The one thing that has to be established out of band is the root, and that
// comes from a finalized block: a quorum of the validator set signed for it.
package statesync

import (
	"errors"
	"fmt"
	"sync"

	"layer1/common"
	"layer1/core"
	"layer1/db"
	"layer1/trie"
)

var (
	ErrUnexpectedNode = errors.New("statesync: received a node that was not requested")
	ErrHashMismatch   = errors.New("statesync: node does not hash to the value it was requested under")
	ErrIncomplete     = errors.New("statesync: the sync is not finished")
)

// kind distinguishes the two things a hash can name.
type kind uint8

const (
	kindNode kind = iota // a trie node, whose children must be followed
	kindCode             // contract bytecode, which is a leaf
)

// MaxRequestBatch is how many blobs to ask for at once. Large enough that a
// sync makes progress, small enough that one response stays a reasonable
// message.
const MaxRequestBatch = 256

// Syncer downloads everything reachable from a state root.
type Syncer struct {
	mu sync.Mutex

	store db.Database
	root  common.Hash

	// pending is what has been requested but not yet received; queue is the
	// order to ask in. Both are keyed by hash, so a node referenced from two
	// places is only ever fetched once.
	pending map[common.Hash]kind
	queue   []common.Hash

	// done records hashes already stored, so a re-reference costs nothing.
	done map[common.Hash]struct{}

	// inFlight is what has been handed out to a peer and not yet answered.
	inFlight map[common.Hash]struct{}

	stored    int
	codeCount int
}

// New starts a sync toward a state root.
func New(store db.Database, root common.Hash) *Syncer {
	s := &Syncer{
		store:    store,
		root:     root,
		pending:  make(map[common.Hash]kind),
		done:     make(map[common.Hash]struct{}),
		inFlight: make(map[common.Hash]struct{}),
	}
	s.schedule(root, kindNode)
	return s
}

// Root returns the target state root.
func (s *Syncer) Root() common.Hash { return s.root }

// schedule adds a hash to the work list if it is not already known.
func (s *Syncer) schedule(hash common.Hash, k kind) {
	if hash == (common.Hash{}) || hash == common.Hash(trie.EmptyRoot) {
		return
	}
	// Code that hashes to the empty string is not stored anywhere.
	if k == kindCode && hash == common.Hash(common.EmptyCodeHash) {
		return
	}
	if _, ok := s.done[hash]; ok {
		return
	}
	if _, ok := s.pending[hash]; ok {
		return
	}
	// Anything the store already holds from an earlier sync or a prior life is
	// not worth downloading again.
	if have, err := s.has(hash, k); err == nil && have {
		s.done[hash] = struct{}{}
		// Its children still have to be followed, or the walk stops here.
		if k == kindNode {
			if enc, err := s.store.Get(trie.NodeKey(hash)); err == nil {
				s.expand(enc)
			}
		}
		return
	}
	s.pending[hash] = k
	s.queue = append(s.queue, hash)
}

func (s *Syncer) has(hash common.Hash, k kind) (bool, error) {
	if k == kindCode {
		return s.store.Has(CodeKey(hash))
	}
	return s.store.Has(trie.NodeKey(hash))
}

// Missing returns up to max hashes to request, marking them in flight.
func (s *Syncer) Missing(max int) []common.Hash {
	s.mu.Lock()
	defer s.mu.Unlock()

	var out []common.Hash
	var remaining []common.Hash
	for _, hash := range s.queue {
		if len(out) >= max {
			remaining = append(remaining, hash)
			continue
		}
		if _, ok := s.pending[hash]; !ok {
			continue // already satisfied
		}
		if _, ok := s.inFlight[hash]; ok {
			remaining = append(remaining, hash)
			continue
		}
		s.inFlight[hash] = struct{}{}
		out = append(out, hash)
	}
	s.queue = remaining
	// Requests can go unanswered, so anything handed out stays on the list to
	// be asked for again rather than being lost.
	s.queue = append(s.queue, out...)
	return out
}

// Process stores received blobs and follows what they reference. It returns
// how many were accepted.
//
// A blob that does not hash to something outstanding is rejected rather than
// stored: that check is the entire trust model.
func (s *Syncer) Process(blobs [][]byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	batch := s.store.NewBatch()
	accepted := 0

	for _, blob := range blobs {
		hash := common.Keccak256(blob)
		k, wanted := s.pending[hash]
		if !wanted {
			// Either unsolicited or already satisfied; neither is a reason to
			// store it.
			continue
		}

		if k == kindCode {
			if err := batch.Put(CodeKey(hash), blob); err != nil {
				return accepted, err
			}
			s.codeCount++
		} else {
			if err := batch.Put(trie.NodeKey(hash), blob); err != nil {
				return accepted, err
			}
			if err := s.expandLocked(blob); err != nil {
				return accepted, err
			}
		}

		delete(s.pending, hash)
		delete(s.inFlight, hash)
		s.done[hash] = struct{}{}
		s.stored++
		accepted++
	}

	if err := batch.Write(); err != nil {
		return accepted, err
	}
	s.compactQueue()
	return accepted, nil
}

// expand schedules whatever a node references, without the lock.
func (s *Syncer) expand(enc []byte) {
	s.expandLocked(enc)
}

// expandLocked schedules a node's children and, for account leaves, the storage
// trie and code they name.
func (s *Syncer) expandLocked(enc []byte) error {
	children, values, err := trie.NodeReferences(enc)
	if err != nil {
		return fmt.Errorf("statesync: %w", err)
	}
	for _, child := range children {
		s.schedule(child, kindNode)
	}
	for _, value := range values {
		// A leaf in the account trie is an account; a leaf in a storage trie is
		// a slot value, which decodes as an account only by accident. Decoding
		// failures are therefore expected and ignored.
		account, err := core.DecodeAccount(value)
		if err != nil {
			continue
		}
		if account.Root != (common.Hash{}) {
			s.schedule(account.Root, kindNode)
		}
		if len(account.CodeHash) == common.HashLength {
			s.schedule(common.BytesToHash(account.CodeHash), kindCode)
		}
	}
	return nil
}

// compactQueue drops entries that have already been satisfied.
func (s *Syncer) compactQueue() {
	filtered := s.queue[:0]
	seen := make(map[common.Hash]struct{}, len(s.queue))
	for _, hash := range s.queue {
		if _, ok := s.pending[hash]; !ok {
			continue
		}
		if _, ok := seen[hash]; ok {
			continue
		}
		seen[hash] = struct{}{}
		filtered = append(filtered, hash)
	}
	s.queue = filtered
}

// Retry puts hashes back on the queue after a peer failed to answer.
func (s *Syncer) Retry(hashes []common.Hash) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, hash := range hashes {
		delete(s.inFlight, hash)
	}
}

// Pending returns how many hashes are still outstanding.
func (s *Syncer) Pending() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.pending)
}

// Stored returns how many blobs have been written.
func (s *Syncer) Stored() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.stored
}

// Done reports whether everything reachable from the root has been stored.
func (s *Syncer) Done() bool { return s.Pending() == 0 }

// Verify walks the synced trie to confirm it is complete and consistent with
// the target root. Reaching zero pending nodes means every node that was asked
// for arrived; this confirms they actually form the trie they claimed to.
func (s *Syncer) Verify() error {
	if !s.Done() {
		return ErrIncomplete
	}
	t, err := trie.New(s.root, s.store)
	if err != nil {
		return fmt.Errorf("statesync: opening the synced root: %w", err)
	}
	if t.Hash() != s.root {
		return fmt.Errorf("statesync: synced trie hashes to %s, want %s", t.Hash(), s.root)
	}

	// Walk it in full: a missing node deep in the trie would otherwise only
	// surface later, when some account turned out to be unreadable.
	return t.VisitNodes(nil, func(_, value []byte) error {
		account, err := core.DecodeAccount(value)
		if err != nil {
			return nil
		}
		if account.Root != (common.Hash{}) && account.Root != core.EmptyRoot {
			storage, err := trie.New(account.Root, s.store)
			if err != nil {
				return fmt.Errorf("statesync: storage trie %s is incomplete: %w", account.Root, err)
			}
			if err := storage.VisitNodes(nil, nil); err != nil {
				return err
			}
		}
		if account.HasCode() {
			if ok, _ := s.store.Has(CodeKey(common.BytesToHash(account.CodeHash))); !ok {
				return fmt.Errorf("statesync: code %x is missing", account.CodeHash)
			}
		}
		return nil
	})
}

// CodeKey is the store key contract code lives under. It mirrors the state
// package's layout, which both the syncer and the pruner have to agree on.
func CodeKey(hash common.Hash) []byte {
	return append([]byte("c"), hash[:]...)
}

// Serve answers a request for state blobs from a store, returning whatever it
// holds. Unknown hashes are simply omitted; the requester will ask again.
func Serve(store db.Database, hashes []common.Hash, limit int) [][]byte {
	out := make([][]byte, 0, len(hashes))
	for _, hash := range hashes {
		if len(out) >= limit {
			break
		}
		if enc, err := store.Get(trie.NodeKey(hash)); err == nil {
			out = append(out, enc)
			continue
		}
		if code, err := store.Get(CodeKey(hash)); err == nil {
			out = append(out, code)
		}
	}
	return out
}
