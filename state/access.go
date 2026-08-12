package state

import (
	"layer1/common"
	"layer1/core"
	"layer1/rlp"
)

// The access list tracks which addresses and storage slots a transaction has
// already touched. Under EIP-2929 the first (cold) access to state costs far
// more than later (warm) ones, which prices the underlying disk reads honestly.

// AddressInAccessList reports whether the address has already been accessed.
func (s *StateDB) AddressInAccessList(addr common.Address) bool {
	_, ok := s.accessedAddresses[addr]
	return ok
}

// SlotInAccessList reports whether the address and slot have been accessed.
func (s *StateDB) SlotInAccessList(addr common.Address, slot common.Hash) (addressPresent, slotPresent bool) {
	_, addressPresent = s.accessedAddresses[addr]
	if slots, ok := s.accessedSlots[addr]; ok {
		_, slotPresent = slots[slot]
	}
	return addressPresent, slotPresent
}

// AddAddressToAccessList marks an address warm.
func (s *StateDB) AddAddressToAccessList(addr common.Address) {
	if _, ok := s.accessedAddresses[addr]; ok {
		return
	}
	s.accessedAddresses[addr] = struct{}{}
	s.journal.append(accessListAddAccountChange{address: addr})
}

// AddSlotToAccessList marks a storage slot warm, warming its account too.
func (s *StateDB) AddSlotToAccessList(addr common.Address, slot common.Hash) {
	s.AddAddressToAccessList(addr)
	if slots, ok := s.accessedSlots[addr]; ok {
		if _, ok := slots[slot]; ok {
			return
		}
		slots[slot] = struct{}{}
	} else {
		s.accessedSlots[addr] = map[common.Hash]struct{}{slot: {}}
	}
	s.journal.append(accessListAddSlotChange{address: addr, slot: slot})
}

// Prepare resets the access list for a new transaction and pre-warms the
// addresses that are always touched: the sender, the recipient, the precompiles
// and everything the transaction declared up front.
func (s *StateDB) Prepare(sender common.Address, coinbase common.Address, dest *common.Address, precompiles []common.Address, list core.AccessList) {
	s.accessedAddresses = make(map[common.Address]struct{})
	s.accessedSlots = make(map[common.Address]map[common.Hash]struct{})

	s.AddAddressToAccessList(sender)
	if dest != nil {
		s.AddAddressToAccessList(*dest)
	}
	for _, addr := range precompiles {
		s.AddAddressToAccessList(addr)
	}
	for _, tuple := range list {
		s.AddAddressToAccessList(tuple.Address)
		for _, key := range tuple.StorageKeys {
			s.AddSlotToAccessList(tuple.Address, key)
		}
	}
	// The proposer is paid at the end of every transaction, so it is never cold.
	s.AddAddressToAccessList(coinbase)
}

// encodeStorageValue renders a slot value the way the storage trie stores it:
// RLP of the big-endian value with leading zeros stripped.
func encodeStorageValue(value common.Hash) ([]byte, error) {
	trimmed := value[:]
	for len(trimmed) > 0 && trimmed[0] == 0 {
		trimmed = trimmed[1:]
	}
	return rlp.Encode(trimmed)
}

func decodeStorageValue(enc []byte, out *[]byte) error {
	return rlp.Decode(enc, out)
}
