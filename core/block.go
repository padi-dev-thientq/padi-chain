package core

import (
	"errors"
	"fmt"
	"math/big"
	"sync/atomic"
	"time"

	"layer1/common"
	"layer1/rlp"
	"layer1/trie"
)

// Header is the block header: the part of a block that consensus commits to.
type Header struct {
	ParentHash  common.Hash
	Coinbase    common.Address
	StateRoot   common.Hash
	TxRoot      common.Hash
	ReceiptRoot common.Hash
	Bloom       Bloom
	Number      *big.Int
	GasLimit    uint64
	GasUsed     uint64
	Time        uint64
	Extra       []byte
	BaseFee     *big.Int
	// Round is the consensus round this block was produced in. Round 0 is the
	// scheduled proposer; higher rounds are the fallback proposers that take
	// over when the scheduled one does not deliver, which is what keeps the
	// chain alive through a validator outage.
	Round uint64
	// RandaoReveal is the proposer's BLS signature over the epoch number. It
	// is unpredictable to everyone but the proposer and cannot be ground for a
	// favourable outcome, because a BLS signature is unique: there is exactly
	// one valid signature per key and message, so the proposer has no choice
	// about what it contributes.
	RandaoReveal []byte
	// Justification is the encoded quorum certificate finalizing an ancestor.
	// Carrying it in the header is what lets a node that was offline when the
	// votes were cast still verify finality from the chain alone.
	Justification []byte
	// ProposerSeal is the proposer's signature over the sealing hash. It is
	// excluded from that hash, since a signature cannot commit to itself.
	ProposerSeal []byte
}

// Block is a header together with the transactions it commits to.
type Block struct {
	header *Header
	txs    Transactions

	hash atomic.Pointer[common.Hash]
	size atomic.Uint64
}

var (
	ErrUnknownAncestor = errors.New("core: unknown parent block")
	ErrInvalidNumber   = errors.New("core: block number does not follow its parent")
	ErrTxRootMismatch  = errors.New("core: transaction root does not match the body")
)

// CopyHeader returns a deep copy.
func CopyHeader(h *Header) *Header {
	out := *h
	out.Number = copyBig(h.Number)
	out.BaseFee = copyBig(h.BaseFee)
	out.Extra = common.CopyBytes(h.Extra)
	out.RandaoReveal = common.CopyBytes(h.RandaoReveal)
	out.Justification = common.CopyBytes(h.Justification)
	out.ProposerSeal = common.CopyBytes(h.ProposerSeal)
	return &out
}

// SealingHash is the digest a proposer signs: the header with the seal removed.
func (h *Header) SealingHash() common.Hash {
	enc, err := rlp.Encode([]any{
		h.ParentHash, h.Coinbase, h.StateRoot, h.TxRoot, h.ReceiptRoot,
		h.Bloom, h.Number, h.GasLimit, h.GasUsed, h.Time, h.Extra, h.BaseFee,
		h.Round, h.RandaoReveal, h.Justification,
	})
	if err != nil {
		panic(fmt.Sprintf("core: encoding sealing hash: %v", err))
	}
	return common.Keccak256(enc)
}

// Hash is the block's identifier: the hash of the complete header, seal included.
func (h *Header) Hash() common.Hash {
	enc, err := rlp.Encode(h)
	if err != nil {
		panic(fmt.Sprintf("core: encoding header: %v", err))
	}
	return common.Keccak256(enc)
}

// NumberU64 returns the block height.
func (h *Header) NumberU64() uint64 {
	if h.Number == nil {
		return 0
	}
	return h.Number.Uint64()
}

// NewBlock assembles a block and fills in the roots derived from its contents.
// The header is copied, so later changes to it do not affect the block.
func NewBlock(header *Header, txs Transactions, receipts Receipts) *Block {
	b := &Block{header: CopyHeader(header)}

	if len(txs) == 0 {
		b.header.TxRoot = common.Hash(trie.EmptyRoot)
	} else {
		b.header.TxRoot = trie.DeriveRoot(txs.EncodeForRoot())
		b.txs = make(Transactions, len(txs))
		copy(b.txs, txs)
	}
	if len(receipts) == 0 {
		b.header.ReceiptRoot = common.Hash(trie.EmptyRoot)
	} else {
		b.header.ReceiptRoot = trie.DeriveRoot(receipts.EncodeForRoot())
		b.header.Bloom = receipts.Bloom()
	}
	return b
}

// NewBlockWithHeader wraps a header with no body.
func NewBlockWithHeader(header *Header) *Block {
	return &Block{header: CopyHeader(header)}
}

// WithBody returns a copy of the block carrying the given transactions.
func (b *Block) WithBody(txs Transactions) *Block {
	out := &Block{header: CopyHeader(b.header), txs: make(Transactions, len(txs))}
	copy(out.txs, txs)
	return out
}

// WithSeal returns a copy of the block whose header carries the given seal.
func (b *Block) WithSeal(seal []byte) *Block {
	header := CopyHeader(b.header)
	header.ProposerSeal = common.CopyBytes(seal)
	out := &Block{header: header, txs: make(Transactions, len(b.txs))}
	copy(out.txs, b.txs)
	return out
}

func (b *Block) Header() *Header            { return CopyHeader(b.header) }
func (b *Block) Transactions() Transactions { return b.txs }
func (b *Block) Number() *big.Int           { return copyBig(b.header.Number) }
func (b *Block) NumberU64() uint64          { return b.header.NumberU64() }
func (b *Block) ParentHash() common.Hash    { return b.header.ParentHash }
func (b *Block) StateRoot() common.Hash     { return b.header.StateRoot }
func (b *Block) TxRoot() common.Hash        { return b.header.TxRoot }
func (b *Block) ReceiptRoot() common.Hash   { return b.header.ReceiptRoot }
func (b *Block) Coinbase() common.Address   { return b.header.Coinbase }
func (b *Block) GasLimit() uint64           { return b.header.GasLimit }
func (b *Block) GasUsed() uint64            { return b.header.GasUsed }
func (b *Block) Time() uint64               { return b.header.Time }
func (b *Block) BaseFee() *big.Int          { return copyBig(b.header.BaseFee) }
func (b *Block) Bloom() Bloom               { return b.header.Bloom }
func (b *Block) Extra() []byte              { return common.CopyBytes(b.header.Extra) }
func (b *Block) Seal() []byte               { return common.CopyBytes(b.header.ProposerSeal) }
func (b *Block) Round() uint64              { return b.header.Round }

func (b *Block) RandaoReveal() []byte { return common.CopyBytes(b.header.RandaoReveal) }

// Justification returns the quorum certificate this block carries, or nil when
// it justifies nothing.
func (b *Block) Justification() (*QuorumCert, error) {
	return DecodeQuorumCert(b.header.Justification)
}

// Timestamp returns the block time as a Go time value.
func (b *Block) Timestamp() time.Time { return time.Unix(int64(b.header.Time), 0).UTC() }

// SealingHash is the digest the proposer signs for this block.
func (b *Block) SealingHash() common.Hash { return b.header.SealingHash() }

// Hash returns the block hash, computing it once.
func (b *Block) Hash() common.Hash {
	if cached := b.hash.Load(); cached != nil {
		return *cached
	}
	h := b.header.Hash()
	b.hash.Store(&h)
	return h
}

// Transaction returns the transaction with the given hash, or nil.
func (b *Block) Transaction(hash common.Hash) *Transaction {
	for _, tx := range b.txs {
		if tx.Hash() == hash {
			return tx
		}
	}
	return nil
}

// blockBody is the wire form of a block: header plus transactions.
type blockBody struct {
	Header *Header
	Txs    []*Transaction
}

// MarshalBinary encodes the whole block.
func (b *Block) MarshalBinary() ([]byte, error) {
	return rlp.Encode(&blockBody{Header: b.header, Txs: b.txs})
}

// UnmarshalBinary decodes a block and checks the body against the header's
// transaction root, so a mismatched body cannot masquerade as a valid block.
func (b *Block) UnmarshalBinary(data []byte) error {
	var body blockBody
	if err := rlp.Decode(data, &body); err != nil {
		return fmt.Errorf("core: decoding block: %w", err)
	}
	if body.Header == nil {
		return errors.New("core: block has no header")
	}
	if body.Header.Number == nil {
		body.Header.Number = new(big.Int)
	}
	if body.Header.BaseFee == nil {
		body.Header.BaseFee = new(big.Int)
	}

	want := common.Hash(trie.EmptyRoot)
	if len(body.Txs) > 0 {
		want = trie.DeriveRoot(Transactions(body.Txs).EncodeForRoot())
	}
	if want != body.Header.TxRoot {
		return fmt.Errorf("%w: header says %s, body derives %s", ErrTxRootMismatch, body.Header.TxRoot, want)
	}

	b.header = body.Header
	b.txs = body.Txs
	b.hash.Store(nil)
	b.size.Store(0)
	return nil
}

// Size returns the encoded size of the block in bytes.
func (b *Block) Size() uint64 {
	if cached := b.size.Load(); cached != 0 {
		return cached
	}
	enc, err := b.MarshalBinary()
	if err != nil {
		return 0
	}
	b.size.Store(uint64(len(enc)))
	return uint64(len(enc))
}

// Blocks is a list of blocks.
type Blocks []*Block
