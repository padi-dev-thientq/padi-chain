// Package core defines the chain's data model: accounts, transactions,
// receipts, block headers and blocks.
package core

import (
	"fmt"
	"math/big"

	"padi-chain/common"
	"padi-chain/rlp"
)

// Account is the state stored for an address in the state trie.
type Account struct {
	Nonce    uint64
	Balance  *big.Int
	Root     common.Hash // storage trie root
	CodeHash []byte
}

// NewAccount returns an empty account with the canonical zero values.
func NewAccount() *Account {
	return &Account{
		Balance:  new(big.Int),
		Root:     common.Hash(emptyTrieRoot),
		CodeHash: common.CopyBytes(common.EmptyCodeHash[:]),
	}
}

// emptyTrieRoot mirrors trie.EmptyRoot without importing the trie package,
// which would be a cycle. The value is keccak256(rlp("")).
var emptyTrieRoot = common.Keccak256([]byte{0x80})

// EmptyRoot is the storage root of an account with no storage.
var EmptyRoot = common.Hash(emptyTrieRoot)

// Copy returns a deep copy.
func (a *Account) Copy() *Account {
	return &Account{
		Nonce:    a.Nonce,
		Balance:  new(big.Int).Set(a.Balance),
		Root:     a.Root,
		CodeHash: common.CopyBytes(a.CodeHash),
	}
}

// HasCode reports whether the account is a contract.
func (a *Account) HasCode() bool {
	return len(a.CodeHash) > 0 && common.BytesToHash(a.CodeHash) != common.Hash(common.EmptyCodeHash)
}

// IsEmpty implements the EIP-161 notion of emptiness: no nonce, no balance and
// no code. Empty accounts are deleted rather than written to the trie.
func (a *Account) IsEmpty() bool {
	return a.Nonce == 0 && a.Balance.Sign() == 0 && !a.HasCode()
}

// CreateContractAddress derives the address of a contract created by sender at
// the given nonce: the low 20 bytes of keccak256(rlp([sender, nonce])).
func CreateContractAddress(sender common.Address, nonce uint64) common.Address {
	enc, err := rlp.Encode([]any{sender, nonce})
	if err != nil {
		panic(fmt.Sprintf("core: encoding creation address: %v", err))
	}
	return common.BytesToAddress(common.Keccak256(enc).Bytes()[12:])
}

// Encode serializes the account for storage in the state trie.
func (a *Account) Encode() ([]byte, error) { return rlp.Encode(a) }

// DecodeAccount parses the state trie's account encoding.
func DecodeAccount(data []byte) (*Account, error) {
	a := new(Account)
	if err := rlp.Decode(data, a); err != nil {
		return nil, fmt.Errorf("core: decoding account: %w", err)
	}
	if a.Balance == nil {
		a.Balance = new(big.Int)
	}
	return a, nil
}
