package state

import (
	"math/big"

	"layer1/common"
)

// journalEntry is a single reversible modification to the state.
type journalEntry interface {
	// revert undoes the change.
	revert(*StateDB)
	// dirtied reports the account the change touched, if any.
	dirtied() *common.Address
}

// journal is the append-only log of state changes that makes snapshots and
// reverts possible. The EVM needs this because a failed call must leave no
// trace, while the transaction that contained it keeps running.
type journal struct {
	entries []journalEntry
	dirties map[common.Address]int
}

func newJournal() *journal {
	return &journal{dirties: make(map[common.Address]int)}
}

func (j *journal) append(entry journalEntry) {
	j.entries = append(j.entries, entry)
	if addr := entry.dirtied(); addr != nil {
		j.dirties[*addr]++
	}
}

func (j *journal) length() int { return len(j.entries) }

// revert undoes entries down to the given length, newest first.
func (j *journal) revert(s *StateDB, target int) {
	for i := len(j.entries) - 1; i >= target; i-- {
		j.entries[i].revert(s)
		if addr := j.entries[i].dirtied(); addr != nil {
			if j.dirties[*addr]--; j.dirties[*addr] == 0 {
				delete(j.dirties, *addr)
			}
		}
	}
	j.entries = j.entries[:target]
}

type (
	createObjectChange struct {
		account common.Address
		prev    *stateObject
	}
	balanceChange struct {
		account common.Address
		prev    *big.Int
	}
	nonceChange struct {
		account common.Address
		prev    uint64
	}
	codeChange struct {
		account  common.Address
		prevCode []byte
		prevHash []byte
	}
	storageChange struct {
		account common.Address
		key     common.Hash
		prev    common.Hash
		existed bool
	}
	transientStorageChange struct {
		account common.Address
		key     common.Hash
		prev    common.Hash
	}
	selfDestructChange struct {
		account     common.Address
		prev        bool
		prevBalance *big.Int
	}
	refundChange struct {
		prev uint64
	}
	addLogChange struct {
		txhash common.Hash
	}
	accessListAddAccountChange struct {
		address common.Address
	}
	accessListAddSlotChange struct {
		address common.Address
		slot    common.Hash
	}
)

func (ch createObjectChange) revert(s *StateDB) {
	if ch.prev == nil {
		delete(s.objects, ch.account)
		delete(s.objectsDirty, ch.account)
		return
	}
	// Restore whatever object the creation displaced.
	s.objects[ch.account] = ch.prev
}

func (ch createObjectChange) dirtied() *common.Address { return &ch.account }

func (ch balanceChange) revert(s *StateDB) {
	if obj := s.objects[ch.account]; obj != nil {
		obj.data.Balance = ch.prev
	}
}

func (ch balanceChange) dirtied() *common.Address { return &ch.account }

func (ch nonceChange) revert(s *StateDB) {
	if obj := s.objects[ch.account]; obj != nil {
		obj.data.Nonce = ch.prev
	}
}

func (ch nonceChange) dirtied() *common.Address { return &ch.account }

func (ch codeChange) revert(s *StateDB) {
	if obj := s.objects[ch.account]; obj != nil {
		obj.code = ch.prevCode
		obj.data.CodeHash = ch.prevHash
	}
}

func (ch codeChange) dirtied() *common.Address { return &ch.account }

func (ch storageChange) revert(s *StateDB) {
	obj := s.objects[ch.account]
	if obj == nil {
		return
	}
	if !ch.existed && ch.prev == (common.Hash{}) {
		// The slot had no pending write before: remove the entry entirely so a
		// later read falls through to the committed value.
		delete(obj.dirtyStorage, ch.key)
		return
	}
	obj.dirtyStorage[ch.key] = ch.prev
}

func (ch storageChange) dirtied() *common.Address { return &ch.account }

func (ch transientStorageChange) revert(s *StateDB) {
	slots := s.transient[ch.account]
	if slots == nil {
		return
	}
	if ch.prev == (common.Hash{}) {
		delete(slots, ch.key)
		return
	}
	slots[ch.key] = ch.prev
}

func (ch transientStorageChange) dirtied() *common.Address { return nil }

func (ch selfDestructChange) revert(s *StateDB) {
	if obj := s.objects[ch.account]; obj != nil {
		obj.selfDestructed = ch.prev
		obj.data.Balance = ch.prevBalance
	}
}

func (ch selfDestructChange) dirtied() *common.Address { return &ch.account }

func (ch refundChange) revert(s *StateDB) { s.refund = ch.prev }

func (ch refundChange) dirtied() *common.Address { return nil }

func (ch addLogChange) revert(s *StateDB) {
	logs := s.logs[ch.txhash]
	if len(logs) == 1 {
		delete(s.logs, ch.txhash)
	} else {
		s.logs[ch.txhash] = logs[:len(logs)-1]
	}
	s.logSize--
}

func (ch addLogChange) dirtied() *common.Address { return nil }

func (ch accessListAddAccountChange) revert(s *StateDB) {
	// An address and its slots are added together, so removing the address is
	// enough to undo the whole entry.
	delete(s.accessedAddresses, ch.address)
	delete(s.accessedSlots, ch.address)
}

func (ch accessListAddAccountChange) dirtied() *common.Address { return nil }

func (ch accessListAddSlotChange) revert(s *StateDB) {
	if slots := s.accessedSlots[ch.address]; slots != nil {
		delete(slots, ch.slot)
	}
}

func (ch accessListAddSlotChange) dirtied() *common.Address { return nil }
