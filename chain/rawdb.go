// Package chain stores and validates the canonical block chain.
package chain

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"

	"layer1/common"
	"layer1/core"
	"layer1/db"
	"layer1/rlp"
)

// Key prefixes namespace the different record types inside the shared store.
var (
	prefixHeader    = []byte("h") // h + num + hash -> header
	prefixBody      = []byte("b") // b + hash       -> block
	prefixReceipts  = []byte("r") // r + hash       -> receipts
	prefixCanonical = []byte("H") // H + num        -> canonical block hash
	prefixTxLookup  = []byte("l") // l + txhash     -> block number + index
	prefixHeaderNum = []byte("N") // N + hash       -> block number
	keyHeadBlock    = []byte("LastBlock")
	keyGenesisHash  = []byte("GenesisHash")
	keyChainConfig  = []byte("ChainConfig")
)

// ErrNotFound means the record is absent.
var ErrNotFound = errors.New("chain: record not found")

func encodeNumber(n uint64) []byte {
	var out [8]byte
	binary.BigEndian.PutUint64(out[:], n)
	return out[:]
}

func canonicalKey(number uint64) []byte {
	return append(append([]byte{}, prefixCanonical...), encodeNumber(number)...)
}

func headerKey(number uint64, hash common.Hash) []byte {
	key := append(append([]byte{}, prefixHeader...), encodeNumber(number)...)
	return append(key, hash[:]...)
}

func bodyKey(hash common.Hash) []byte {
	return append(append([]byte{}, prefixBody...), hash[:]...)
}

func receiptsKey(hash common.Hash) []byte {
	return append(append([]byte{}, prefixReceipts...), hash[:]...)
}

func txLookupKey(hash common.Hash) []byte {
	return append(append([]byte{}, prefixTxLookup...), hash[:]...)
}

func headerNumberKey(hash common.Hash) []byte {
	return append(append([]byte{}, prefixHeaderNum...), hash[:]...)
}

// WriteBlock stores a block and indexes its header by hash.
func WriteBlock(store db.Writer, block *core.Block) error {
	enc, err := block.MarshalBinary()
	if err != nil {
		return err
	}
	hash := block.Hash()
	if err := store.Put(bodyKey(hash), enc); err != nil {
		return err
	}
	headerEnc, err := rlp.Encode(block.Header())
	if err != nil {
		return err
	}
	if err := store.Put(headerKey(block.NumberU64(), hash), headerEnc); err != nil {
		return err
	}
	return store.Put(headerNumberKey(hash), encodeNumber(block.NumberU64()))
}

// ReadBlock loads a block by hash.
func ReadBlock(store db.Reader, hash common.Hash) (*core.Block, error) {
	enc, err := store.Get(bodyKey(hash))
	if err != nil {
		return nil, fmt.Errorf("%w: block %s", ErrNotFound, hash)
	}
	block := new(core.Block)
	if err := block.UnmarshalBinary(enc); err != nil {
		return nil, err
	}
	return block, nil
}

// ReadHeader loads a header by number and hash.
func ReadHeader(store db.Reader, number uint64, hash common.Hash) (*core.Header, error) {
	enc, err := store.Get(headerKey(number, hash))
	if err != nil {
		return nil, fmt.Errorf("%w: header %d/%s", ErrNotFound, number, hash)
	}
	header := new(core.Header)
	if err := rlp.Decode(enc, header); err != nil {
		return nil, err
	}
	if header.Number == nil {
		header.Number = new(big.Int)
	}
	if header.BaseFee == nil {
		header.BaseFee = new(big.Int)
	}
	return header, nil
}

// ReadHeaderNumber returns the height of a block from its hash.
func ReadHeaderNumber(store db.Reader, hash common.Hash) (uint64, error) {
	enc, err := store.Get(headerNumberKey(hash))
	if err != nil || len(enc) != 8 {
		return 0, fmt.Errorf("%w: header number for %s", ErrNotFound, hash)
	}
	return binary.BigEndian.Uint64(enc), nil
}

// WriteCanonicalHash records which block at a height is on the canonical chain.
func WriteCanonicalHash(store db.Writer, number uint64, hash common.Hash) error {
	return store.Put(canonicalKey(number), hash[:])
}

// ReadCanonicalHash returns the canonical block hash at a height.
func ReadCanonicalHash(store db.Reader, number uint64) (common.Hash, error) {
	enc, err := store.Get(canonicalKey(number))
	if err != nil {
		return common.Hash{}, fmt.Errorf("%w: canonical hash at %d", ErrNotFound, number)
	}
	return common.BytesToHash(enc), nil
}

// DeleteCanonicalHash removes a height from the canonical chain, which a reorg
// does before writing the new branch.
func DeleteCanonicalHash(store db.Writer, number uint64) error {
	return store.Delete(canonicalKey(number))
}

// storedReceipts is the on-disk form of a block's receipts.
type storedReceipts struct {
	Encoded [][]byte
}

// WriteReceipts stores the receipts of a block.
func WriteReceipts(store db.Writer, hash common.Hash, receipts core.Receipts) error {
	enc, err := rlp.Encode(&storedReceipts{Encoded: receipts.EncodeForRoot()})
	if err != nil {
		return err
	}
	return store.Put(receiptsKey(hash), enc)
}

// ReadReceipts loads the receipts of a block.
func ReadReceipts(store db.Reader, hash common.Hash) (core.Receipts, error) {
	enc, err := store.Get(receiptsKey(hash))
	if err != nil {
		return nil, fmt.Errorf("%w: receipts for %s", ErrNotFound, hash)
	}
	var stored storedReceipts
	if err := rlp.Decode(enc, &stored); err != nil {
		return nil, err
	}
	out := make(core.Receipts, 0, len(stored.Encoded))
	for _, item := range stored.Encoded {
		r := new(core.Receipt)
		if err := r.UnmarshalBinary(item); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, nil
}

// TxLookupEntry locates a transaction within the chain.
type TxLookupEntry struct {
	BlockHash  common.Hash
	BlockIndex uint64
	Index      uint64
}

// WriteTxLookups indexes every transaction in a block by hash.
func WriteTxLookups(store db.Writer, block *core.Block) error {
	for i, tx := range block.Transactions() {
		entry := TxLookupEntry{
			BlockHash:  block.Hash(),
			BlockIndex: block.NumberU64(),
			Index:      uint64(i),
		}
		enc, err := rlp.Encode(&entry)
		if err != nil {
			return err
		}
		if err := store.Put(txLookupKey(tx.Hash()), enc); err != nil {
			return err
		}
	}
	return nil
}

// DeleteTxLookups removes a block's transaction index entries, used when a
// block leaves the canonical chain.
func DeleteTxLookups(store db.Writer, block *core.Block) error {
	for _, tx := range block.Transactions() {
		if err := store.Delete(txLookupKey(tx.Hash())); err != nil {
			return err
		}
	}
	return nil
}

// ReadTxLookup finds where a transaction was included.
func ReadTxLookup(store db.Reader, hash common.Hash) (*TxLookupEntry, error) {
	enc, err := store.Get(txLookupKey(hash))
	if err != nil {
		return nil, fmt.Errorf("%w: transaction %s", ErrNotFound, hash)
	}
	entry := new(TxLookupEntry)
	if err := rlp.Decode(enc, entry); err != nil {
		return nil, err
	}
	return entry, nil
}

// WriteHeadBlockHash records the head of the canonical chain.
func WriteHeadBlockHash(store db.Writer, hash common.Hash) error {
	return store.Put(keyHeadBlock, hash[:])
}

// ReadHeadBlockHash returns the head of the canonical chain.
func ReadHeadBlockHash(store db.Reader) (common.Hash, error) {
	enc, err := store.Get(keyHeadBlock)
	if err != nil {
		return common.Hash{}, ErrNotFound
	}
	return common.BytesToHash(enc), nil
}

// WriteGenesisHash records which genesis this store belongs to.
func WriteGenesisHash(store db.Writer, hash common.Hash) error {
	return store.Put(keyGenesisHash, hash[:])
}

// ReadGenesisHash returns the store's genesis hash.
func ReadGenesisHash(store db.Reader) (common.Hash, error) {
	enc, err := store.Get(keyGenesisHash)
	if err != nil {
		return common.Hash{}, ErrNotFound
	}
	return common.BytesToHash(enc), nil
}

// WriteChainConfig stores the chain configuration alongside the data.
func WriteChainConfig(store db.Writer, enc []byte) error {
	return store.Put(keyChainConfig, enc)
}

// ReadChainConfig loads the stored chain configuration.
func ReadChainConfig(store db.Reader) ([]byte, error) {
	enc, err := store.Get(keyChainConfig)
	if err != nil {
		return nil, ErrNotFound
	}
	return enc, nil
}
