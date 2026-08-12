// Package state manages the world state: the mapping from addresses to
// accounts, their code and their storage, committed into a Merkle Patricia
// Trie whose root the block header carries.
package state

import (
	"errors"
	"fmt"
	"math/big"
	"sort"

	"layer1/common"
	"layer1/core"
	"layer1/db"
	"layer1/trie"
)

// StateDB is a mutable view of the world state.
//
// Writes accumulate in memory and are journaled, so any prefix of them can be
// rolled back — which is what makes a reverted contract call leave no trace
// while the outer transaction keeps its effects.
type StateDB struct {
	store db.Database
	trie  *trie.Trie

	objects      map[common.Address]*stateObject
	objectsDirty map[common.Address]struct{}

	// codeCache holds contract code by code hash.
	codeCache map[common.Hash][]byte

	journal   *journal
	revisions []revision
	nextRevID int

	refund  uint64
	logs    map[common.Hash][]*core.Log
	logSize uint

	// EIP-2929 access lists: touching cold state costs more than warm state.
	accessedAddresses map[common.Address]struct{}
	accessedSlots     map[common.Address]map[common.Hash]struct{}

	// transient storage is discarded at the end of every transaction.
	transient map[common.Address]map[common.Hash]common.Hash

	thash   common.Hash
	txIndex int

	err error
}

type revision struct {
	id           int
	journalIndex int
}

var (
	ErrStateMissing = errors.New("state: state root is not available")
	ErrInsufficient = errors.New("state: insufficient balance")
)

// New opens the state at the given root.
func New(root common.Hash, store db.Database) (*StateDB, error) {
	t, err := trie.New(root, store)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrStateMissing, err)
	}
	return &StateDB{
		store:             store,
		trie:              t,
		objects:           make(map[common.Address]*stateObject),
		objectsDirty:      make(map[common.Address]struct{}),
		codeCache:         make(map[common.Hash][]byte),
		journal:           newJournal(),
		logs:              make(map[common.Hash][]*core.Log),
		accessedAddresses: make(map[common.Address]struct{}),
		accessedSlots:     make(map[common.Address]map[common.Hash]struct{}),
		transient:         make(map[common.Address]map[common.Hash]common.Hash),
		txIndex:           -1,
	}, nil
}

// Error returns the first error that made the state inconsistent, if any.
func (s *StateDB) Error() error { return s.err }

func (s *StateDB) setError(err error) {
	if s.err == nil {
		s.err = err
	}
}

// stateObject is an account together with its pending changes.
type stateObject struct {
	address common.Address
	data    core.Account

	code      []byte
	codeDirty bool

	// originStorage caches values as they are in the committed trie;
	// dirtyStorage holds writes made during this transaction.
	originStorage map[common.Hash]common.Hash
	dirtyStorage  map[common.Hash]common.Hash

	selfDestructed bool
	deleted        bool
	created        bool
}

func newObject(addr common.Address, data core.Account) *stateObject {
	if data.Balance == nil {
		data.Balance = new(big.Int)
	}
	if len(data.CodeHash) == 0 {
		data.CodeHash = common.CopyBytes(common.EmptyCodeHash[:])
	}
	if data.Root == (common.Hash{}) {
		data.Root = core.EmptyRoot
	}
	return &stateObject{
		address:       addr,
		data:          data,
		originStorage: make(map[common.Hash]common.Hash),
		dirtyStorage:  make(map[common.Hash]common.Hash),
	}
}

func (o *stateObject) empty() bool { return o.data.IsEmpty() }

// getStateObject loads an account, returning nil if it does not exist.
func (s *StateDB) getStateObject(addr common.Address) *stateObject {
	if obj, ok := s.objects[addr]; ok {
		if obj.deleted {
			return nil
		}
		return obj
	}
	// Accounts are keyed by the hash of the address, which keeps the trie
	// balanced regardless of how addresses are chosen.
	key := common.Keccak256(addr[:])
	enc, err := s.trie.Get(key[:])
	if err != nil {
		s.setError(fmt.Errorf("state: reading account %s: %w", addr, err))
		return nil
	}
	if len(enc) == 0 {
		return nil
	}
	account, err := core.DecodeAccount(enc)
	if err != nil {
		s.setError(fmt.Errorf("state: decoding account %s: %w", addr, err))
		return nil
	}
	obj := newObject(addr, *account)
	s.objects[addr] = obj
	return obj
}

// getOrNewStateObject loads an account, creating an empty one if absent.
func (s *StateDB) getOrNewStateObject(addr common.Address) *stateObject {
	if obj := s.getStateObject(addr); obj != nil {
		return obj
	}
	return s.createObject(addr)
}

func (s *StateDB) createObject(addr common.Address) *stateObject {
	prev := s.objects[addr]
	obj := newObject(addr, *core.NewAccount())
	obj.created = true
	s.journal.append(createObjectChange{account: addr, prev: prev})
	s.objects[addr] = obj
	s.markDirty(addr)
	return obj
}

func (s *StateDB) markDirty(addr common.Address) { s.objectsDirty[addr] = struct{}{} }

// CreateAccount prepares an address to receive code. A balance already sent to
// the address is preserved: value can arrive before the contract exists.
func (s *StateDB) CreateAccount(addr common.Address) {
	prev := s.getStateObject(addr)
	obj := s.createObject(addr)
	if prev != nil {
		obj.data.Balance = new(big.Int).Set(prev.data.Balance)
	}
}

// Exist reports whether the account exists in state at all, including empty
// accounts that have merely been touched.
func (s *StateDB) Exist(addr common.Address) bool {
	return s.getStateObject(addr) != nil
}

// Empty implements the EIP-161 emptiness test.
func (s *StateDB) Empty(addr common.Address) bool {
	obj := s.getStateObject(addr)
	return obj == nil || obj.empty()
}

// GetBalance returns the account's balance, zero for a missing account.
func (s *StateDB) GetBalance(addr common.Address) *big.Int {
	if obj := s.getStateObject(addr); obj != nil {
		return new(big.Int).Set(obj.data.Balance)
	}
	return new(big.Int)
}

// AddBalance credits an account.
func (s *StateDB) AddBalance(addr common.Address, amount *big.Int) {
	if amount.Sign() == 0 {
		// A zero-value transfer still touches the account, which matters for
		// the emptiness rules.
		if s.Exist(addr) {
			s.getOrNewStateObject(addr)
		}
		return
	}
	obj := s.getOrNewStateObject(addr)
	s.setBalance(obj, new(big.Int).Add(obj.data.Balance, amount))
}

// SubBalance debits an account.
func (s *StateDB) SubBalance(addr common.Address, amount *big.Int) {
	if amount.Sign() == 0 {
		return
	}
	obj := s.getOrNewStateObject(addr)
	s.setBalance(obj, new(big.Int).Sub(obj.data.Balance, amount))
}

// SetBalance overwrites an account's balance.
func (s *StateDB) SetBalance(addr common.Address, amount *big.Int) {
	s.setBalance(s.getOrNewStateObject(addr), new(big.Int).Set(amount))
}

func (s *StateDB) setBalance(obj *stateObject, amount *big.Int) {
	s.journal.append(balanceChange{account: obj.address, prev: new(big.Int).Set(obj.data.Balance)})
	obj.data.Balance = amount
	s.markDirty(obj.address)
}

// GetNonce returns the account's nonce.
func (s *StateDB) GetNonce(addr common.Address) uint64 {
	if obj := s.getStateObject(addr); obj != nil {
		return obj.data.Nonce
	}
	return 0
}

// SetNonce overwrites the account's nonce.
func (s *StateDB) SetNonce(addr common.Address, nonce uint64) {
	obj := s.getOrNewStateObject(addr)
	s.journal.append(nonceChange{account: addr, prev: obj.data.Nonce})
	obj.data.Nonce = nonce
	s.markDirty(addr)
}

// GetCode returns the account's contract code.
func (s *StateDB) GetCode(addr common.Address) []byte {
	obj := s.getStateObject(addr)
	if obj == nil {
		return nil
	}
	return s.codeOf(obj)
}

func (s *StateDB) codeOf(obj *stateObject) []byte {
	if obj.code != nil {
		return obj.code
	}
	hash := common.BytesToHash(obj.data.CodeHash)
	if hash == common.Hash(common.EmptyCodeHash) {
		return nil
	}
	if code, ok := s.codeCache[hash]; ok {
		obj.code = code
		return code
	}
	code, err := s.store.Get(codeKey(hash))
	if err != nil {
		s.setError(fmt.Errorf("state: missing code %s for %s: %w", hash, obj.address, err))
		return nil
	}
	s.codeCache[hash] = code
	obj.code = code
	return code
}

// GetCodeSize returns the length of the account's code.
func (s *StateDB) GetCodeSize(addr common.Address) int { return len(s.GetCode(addr)) }

// GetCodeHash returns the hash of the account's code.
func (s *StateDB) GetCodeHash(addr common.Address) common.Hash {
	obj := s.getStateObject(addr)
	if obj == nil {
		return common.Hash{}
	}
	return common.BytesToHash(obj.data.CodeHash)
}

// SetCode installs contract code on an account.
func (s *StateDB) SetCode(addr common.Address, code []byte) {
	obj := s.getOrNewStateObject(addr)
	prevCode := s.codeOf(obj)
	s.journal.append(codeChange{
		account:  addr,
		prevCode: prevCode,
		prevHash: common.CopyBytes(obj.data.CodeHash),
	})
	hash := common.Keccak256(code)
	obj.code = common.CopyBytes(code)
	obj.data.CodeHash = hash[:]
	obj.codeDirty = true
	s.codeCache[hash] = obj.code
	s.markDirty(addr)
}

// GetState returns the current value of a storage slot, including writes made
// earlier in this transaction.
func (s *StateDB) GetState(addr common.Address, key common.Hash) common.Hash {
	obj := s.getStateObject(addr)
	if obj == nil {
		return common.Hash{}
	}
	if value, ok := obj.dirtyStorage[key]; ok {
		return value
	}
	return s.committedState(obj, key)
}

// GetCommittedState returns a slot's value as of the start of the transaction,
// ignoring pending writes. SSTORE's gas rules are defined against this value.
func (s *StateDB) GetCommittedState(addr common.Address, key common.Hash) common.Hash {
	obj := s.getStateObject(addr)
	if obj == nil {
		return common.Hash{}
	}
	return s.committedState(obj, key)
}

func (s *StateDB) committedState(obj *stateObject, key common.Hash) common.Hash {
	if value, ok := obj.originStorage[key]; ok {
		return value
	}
	// A freshly created account cannot have inherited storage.
	if obj.created {
		obj.originStorage[key] = common.Hash{}
		return common.Hash{}
	}
	st, err := trie.New(obj.data.Root, s.store)
	if err != nil {
		s.setError(fmt.Errorf("state: opening storage of %s: %w", obj.address, err))
		return common.Hash{}
	}
	slotKey := common.Keccak256(key[:])
	enc, err := st.Get(slotKey[:])
	if err != nil {
		s.setError(fmt.Errorf("state: reading storage of %s: %w", obj.address, err))
		return common.Hash{}
	}
	var value common.Hash
	if len(enc) > 0 {
		// Storage values are stored RLP-encoded with leading zeros stripped.
		var raw []byte
		if err := decodeStorageValue(enc, &raw); err != nil {
			s.setError(fmt.Errorf("state: decoding storage of %s: %w", obj.address, err))
			return common.Hash{}
		}
		value = common.BytesToHash(raw)
	}
	obj.originStorage[key] = value
	return value
}

// SetState writes a storage slot.
func (s *StateDB) SetState(addr common.Address, key, value common.Hash) {
	obj := s.getOrNewStateObject(addr)
	prev := s.GetState(addr, key)
	if prev == value {
		return
	}
	s.journal.append(storageChange{account: addr, key: key, prev: prev, existed: hasDirty(obj, key)})
	obj.dirtyStorage[key] = value
	s.markDirty(addr)
}

func hasDirty(obj *stateObject, key common.Hash) bool {
	_, ok := obj.dirtyStorage[key]
	return ok
}

// GetTransientState reads transient storage, which lives only for the duration
// of a transaction and is never written to the trie.
func (s *StateDB) GetTransientState(addr common.Address, key common.Hash) common.Hash {
	if slots, ok := s.transient[addr]; ok {
		return slots[key]
	}
	return common.Hash{}
}

// SetTransientState writes transient storage.
func (s *StateDB) SetTransientState(addr common.Address, key, value common.Hash) {
	prev := s.GetTransientState(addr, key)
	if prev == value {
		return
	}
	s.journal.append(transientStorageChange{account: addr, key: key, prev: prev})
	if s.transient[addr] == nil {
		s.transient[addr] = make(map[common.Hash]common.Hash)
	}
	s.transient[addr][key] = value
}

// SelfDestruct schedules an account for deletion at the end of the transaction
// and moves its balance to the beneficiary.
func (s *StateDB) SelfDestruct(addr common.Address) {
	obj := s.getStateObject(addr)
	if obj == nil {
		return
	}
	s.journal.append(selfDestructChange{
		account:     addr,
		prev:        obj.selfDestructed,
		prevBalance: new(big.Int).Set(obj.data.Balance),
	})
	obj.selfDestructed = true
	obj.data.Balance = new(big.Int)
	s.markDirty(addr)
}

// HasSelfDestructed reports whether the account is scheduled for deletion.
func (s *StateDB) HasSelfDestructed(addr common.Address) bool {
	obj := s.getStateObject(addr)
	return obj != nil && obj.selfDestructed
}

// AddRefund accumulates a gas refund.
func (s *StateDB) AddRefund(gas uint64) {
	s.journal.append(refundChange{prev: s.refund})
	s.refund += gas
}

// SubRefund removes from the accumulated refund.
func (s *StateDB) SubRefund(gas uint64) {
	s.journal.append(refundChange{prev: s.refund})
	if gas > s.refund {
		s.setError(fmt.Errorf("state: refund underflow: removing %d from %d", gas, s.refund))
		s.refund = 0
		return
	}
	s.refund -= gas
}

// GetRefund returns the accumulated refund.
func (s *StateDB) GetRefund() uint64 { return s.refund }

// AddLog records a log emitted by the transaction currently executing.
func (s *StateDB) AddLog(log *core.Log) {
	s.journal.append(addLogChange{txhash: s.thash})
	log.TxHash = s.thash
	log.TxIndex = uint(s.txIndex)
	log.Index = s.logSize
	s.logs[s.thash] = append(s.logs[s.thash], log)
	s.logSize++
}

// GetLogs returns the logs emitted by the given transaction.
func (s *StateDB) GetLogs(hash common.Hash) []*core.Log { return s.logs[hash] }

// Logs returns every log recorded in this state, in transaction order.
func (s *StateDB) Logs() []*core.Log {
	var out []*core.Log
	for _, logs := range s.logs {
		out = append(out, logs...)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Index < out[j].Index })
	return out
}

// SetTxContext identifies the transaction whose execution follows, so logs can
// be attributed to it.
func (s *StateDB) SetTxContext(hash common.Hash, index int) {
	s.thash = hash
	s.txIndex = index
}

// Snapshot marks a point the state can be rolled back to.
func (s *StateDB) Snapshot() int {
	id := s.nextRevID
	s.nextRevID++
	s.revisions = append(s.revisions, revision{id: id, journalIndex: s.journal.length()})
	return id
}

// RevertToSnapshot undoes every change made since the snapshot was taken.
func (s *StateDB) RevertToSnapshot(id int) {
	idx := sort.Search(len(s.revisions), func(i int) bool { return s.revisions[i].id >= id })
	if idx == len(s.revisions) || s.revisions[idx].id != id {
		panic(fmt.Sprintf("state: snapshot %d is not available", id))
	}
	target := s.revisions[idx].journalIndex
	s.journal.revert(s, target)
	s.revisions = s.revisions[:idx]
}

// Finalise applies end-of-transaction deletions: self-destructed accounts and,
// under EIP-161, accounts left empty by the transaction.
func (s *StateDB) Finalise(deleteEmptyObjects bool) {
	for addr := range s.objectsDirty {
		obj, ok := s.objects[addr]
		if !ok {
			continue
		}
		if obj.selfDestructed || (deleteEmptyObjects && obj.empty()) {
			obj.deleted = true
			obj.dirtyStorage = make(map[common.Hash]common.Hash)
		}
	}
	// Journal entries cannot outlive the transaction that produced them.
	s.journal = newJournal()
	s.revisions = s.revisions[:0]
	s.refund = 0
	s.transient = make(map[common.Address]map[common.Hash]common.Hash)
}

// IntermediateRoot finalises the transaction and returns the state root that
// would result, without writing anything.
func (s *StateDB) IntermediateRoot(deleteEmptyObjects bool) (common.Hash, error) {
	s.Finalise(deleteEmptyObjects)
	batch := db.NewMemoryDB().NewBatch()
	return s.commitTo(batch, false)
}

// Commit writes all pending state to the store and returns the new root.
func (s *StateDB) Commit(deleteEmptyObjects bool) (common.Hash, error) {
	s.Finalise(deleteEmptyObjects)
	batch := s.store.NewBatch()
	root, err := s.commitTo(batch, true)
	if err != nil {
		return common.Hash{}, err
	}
	if err := batch.Write(); err != nil {
		return common.Hash{}, fmt.Errorf("state: writing commit batch: %w", err)
	}
	return root, nil
}

// commitTo writes accounts, storage and code into batch and returns the root.
// When persist is false the batch is a scratch buffer used only to derive the
// root, so code does not need to be written.
func (s *StateDB) commitTo(batch db.Batch, persist bool) (common.Hash, error) {
	if s.err != nil {
		return common.Hash{}, s.err
	}

	// Commit in address order so the work is deterministic and reproducible.
	addrs := make([]common.Address, 0, len(s.objectsDirty))
	for addr := range s.objectsDirty {
		addrs = append(addrs, addr)
	}
	sort.Slice(addrs, func(i, j int) bool {
		return string(addrs[i][:]) < string(addrs[j][:])
	})

	for _, addr := range addrs {
		obj := s.objects[addr]
		if obj == nil {
			continue
		}
		key := common.Keccak256(addr[:])

		if obj.deleted {
			if err := s.trie.Delete(key[:]); err != nil {
				return common.Hash{}, err
			}
			continue
		}

		// Fold pending storage writes into the account's storage trie.
		if len(obj.dirtyStorage) > 0 {
			root, err := s.commitStorage(obj, batch, persist)
			if err != nil {
				return common.Hash{}, err
			}
			obj.data.Root = root
		}

		if persist && obj.codeDirty && len(obj.code) > 0 {
			if err := batch.Put(codeKey(common.BytesToHash(obj.data.CodeHash)), obj.code); err != nil {
				return common.Hash{}, err
			}
			obj.codeDirty = false
		}

		enc, err := obj.data.Encode()
		if err != nil {
			return common.Hash{}, err
		}
		if err := s.trie.Update(key[:], enc); err != nil {
			return common.Hash{}, err
		}
	}

	root, err := s.trie.Commit(batch)
	if err != nil {
		return common.Hash{}, err
	}

	if persist {
		// Committed writes become the new baseline for subsequent reads.
		for _, addr := range addrs {
			if obj := s.objects[addr]; obj != nil && !obj.deleted {
				for k, v := range obj.dirtyStorage {
					obj.originStorage[k] = v
				}
				obj.dirtyStorage = make(map[common.Hash]common.Hash)
				obj.created = false
			}
		}
		s.objectsDirty = make(map[common.Address]struct{})
	}
	return root, nil
}

func (s *StateDB) commitStorage(obj *stateObject, batch db.Batch, persist bool) (common.Hash, error) {
	st, err := trie.New(obj.data.Root, s.store)
	if err != nil {
		return common.Hash{}, fmt.Errorf("state: opening storage trie of %s: %w", obj.address, err)
	}
	keys := make([]common.Hash, 0, len(obj.dirtyStorage))
	for k := range obj.dirtyStorage {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return string(keys[i][:]) < string(keys[j][:]) })

	for _, k := range keys {
		value := obj.dirtyStorage[k]
		slotKey := common.Keccak256(k[:])
		if value == (common.Hash{}) {
			// Zero means absent: the slot is deleted rather than stored.
			if err := st.Delete(slotKey[:]); err != nil {
				return common.Hash{}, err
			}
			continue
		}
		enc, err := encodeStorageValue(value)
		if err != nil {
			return common.Hash{}, err
		}
		if err := st.Update(slotKey[:], enc); err != nil {
			return common.Hash{}, err
		}
	}
	return st.Commit(batch)
}

// Copy returns a deep copy of the state, sharing only the immutable backing
// store. Used to run speculative execution without disturbing the original.
func (s *StateDB) Copy() *StateDB {
	out := &StateDB{
		store:             s.store,
		trie:              s.trie.Copy(),
		objects:           make(map[common.Address]*stateObject, len(s.objects)),
		objectsDirty:      make(map[common.Address]struct{}, len(s.objectsDirty)),
		codeCache:         make(map[common.Hash][]byte, len(s.codeCache)),
		journal:           newJournal(),
		refund:            s.refund,
		logs:              make(map[common.Hash][]*core.Log, len(s.logs)),
		logSize:           s.logSize,
		accessedAddresses: make(map[common.Address]struct{}, len(s.accessedAddresses)),
		accessedSlots:     make(map[common.Address]map[common.Hash]struct{}, len(s.accessedSlots)),
		transient:         make(map[common.Address]map[common.Hash]common.Hash),
		thash:             s.thash,
		txIndex:           s.txIndex,
		err:               s.err,
	}
	for addr, obj := range s.objects {
		out.objects[addr] = obj.copy()
	}
	for addr := range s.objectsDirty {
		out.objectsDirty[addr] = struct{}{}
	}
	for hash, code := range s.codeCache {
		out.codeCache[hash] = code
	}
	for hash, logs := range s.logs {
		copied := make([]*core.Log, len(logs))
		for i, l := range logs {
			cl := *l
			copied[i] = &cl
		}
		out.logs[hash] = copied
	}
	for addr := range s.accessedAddresses {
		out.accessedAddresses[addr] = struct{}{}
	}
	for addr, slots := range s.accessedSlots {
		copied := make(map[common.Hash]struct{}, len(slots))
		for k := range slots {
			copied[k] = struct{}{}
		}
		out.accessedSlots[addr] = copied
	}
	for addr, slots := range s.transient {
		copied := make(map[common.Hash]common.Hash, len(slots))
		for k, v := range slots {
			copied[k] = v
		}
		out.transient[addr] = copied
	}
	return out
}

func (o *stateObject) copy() *stateObject {
	out := &stateObject{
		address:        o.address,
		data:           *o.data.Copy(),
		code:           common.CopyBytes(o.code),
		codeDirty:      o.codeDirty,
		originStorage:  make(map[common.Hash]common.Hash, len(o.originStorage)),
		dirtyStorage:   make(map[common.Hash]common.Hash, len(o.dirtyStorage)),
		selfDestructed: o.selfDestructed,
		deleted:        o.deleted,
		created:        o.created,
	}
	for k, v := range o.originStorage {
		out.originStorage[k] = v
	}
	for k, v := range o.dirtyStorage {
		out.dirtyStorage[k] = v
	}
	return out
}

// ForEachStorage walks an account's storage, including pending writes.
func (s *StateDB) ForEachStorage(addr common.Address, fn func(key, value common.Hash) bool) error {
	obj := s.getStateObject(addr)
	if obj == nil {
		return nil
	}
	seen := make(map[common.Hash]struct{})
	for k, v := range obj.dirtyStorage {
		seen[k] = struct{}{}
		if !fn(k, v) {
			return nil
		}
	}
	st, err := trie.New(obj.data.Root, s.store)
	if err != nil {
		return err
	}
	// The trie is keyed by hashed slots, so the preimage has to come from the
	// values we already know about.
	var walkErr error
	err = st.ForEach(func(hashedKey, enc []byte) bool {
		for k := range obj.originStorage {
			hk := common.Keccak256(k[:])
			if string(hk[:]) != string(hashedKey) {
				continue
			}
			if _, ok := seen[k]; ok {
				return true
			}
			var raw []byte
			if err := decodeStorageValue(enc, &raw); err != nil {
				walkErr = err
				return false
			}
			return fn(k, common.BytesToHash(raw))
		}
		return true
	})
	if walkErr != nil {
		return walkErr
	}
	return err
}

// codeKey namespaces contract code within the shared store.
func codeKey(hash common.Hash) []byte { return append([]byte("c"), hash[:]...) }
