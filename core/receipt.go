package core

import (
	"fmt"
	"math/big"

	"layer1/common"
	"layer1/rlp"
)

// Receipt statuses.
const (
	ReceiptStatusFailed     uint64 = 0
	ReceiptStatusSuccessful uint64 = 1
)

// Log is an event emitted by a contract.
type Log struct {
	Address common.Address
	Topics  []common.Hash
	Data    []byte

	// Context filled in when the receipt is stored; not part of the consensus
	// encoding, so these fields are excluded from RLP.
	BlockNumber uint64      `rlp:"-"`
	BlockHash   common.Hash `rlp:"-"`
	TxHash      common.Hash `rlp:"-"`
	TxIndex     uint        `rlp:"-"`
	Index       uint        `rlp:"-"`
	Removed     bool        `rlp:"-"`
}

// Receipt records the outcome of executing one transaction.
type Receipt struct {
	Type              byte `rlp:"-"`
	Status            uint64
	CumulativeGasUsed uint64
	Bloom             Bloom
	Logs              []*Log

	// Derived fields, kept out of the consensus encoding.
	TxHash            common.Hash    `rlp:"-"`
	ContractAddress   common.Address `rlp:"-"`
	GasUsed           uint64         `rlp:"-"`
	EffectiveGasPrice *big.Int       `rlp:"-"`
	BlockHash         common.Hash    `rlp:"-"`
	BlockNumber       *big.Int       `rlp:"-"`
	TxIndex           uint           `rlp:"-"`
}

// NewReceipt builds a receipt for a completed transaction.
func NewReceipt(txType byte, status uint64, cumulativeGasUsed uint64, logs []*Log) *Receipt {
	r := &Receipt{
		Type:              txType,
		Status:            status,
		CumulativeGasUsed: cumulativeGasUsed,
		Logs:              logs,
	}
	r.Bloom = CreateBloom(r)
	return r
}

// MarshalBinary returns the consensus encoding, with the EIP-2718 type prefix
// for typed transactions.
func (r *Receipt) MarshalBinary() ([]byte, error) {
	payload, err := rlp.Encode(r)
	if err != nil {
		return nil, err
	}
	if r.Type == LegacyTxType {
		return payload, nil
	}
	return append([]byte{r.Type}, payload...), nil
}

// UnmarshalBinary parses the consensus encoding.
func (r *Receipt) UnmarshalBinary(b []byte) error {
	if len(b) == 0 {
		return fmt.Errorf("core: empty receipt encoding")
	}
	if b[0] >= 0xC0 {
		r.Type = LegacyTxType
		return rlp.Decode(b, r)
	}
	r.Type = b[0]
	return rlp.Decode(b[1:], r)
}

// Receipts is a list of receipts.
type Receipts []*Receipt

func (rs Receipts) Len() int { return len(rs) }

// EncodeForRoot returns the consensus encodings used to derive the receipt root.
func (rs Receipts) EncodeForRoot() [][]byte {
	out := make([][]byte, len(rs))
	for i, r := range rs {
		enc, err := r.MarshalBinary()
		if err != nil {
			panic(fmt.Sprintf("core: encoding receipt %d: %v", i, err))
		}
		out[i] = enc
	}
	return out
}

// Bloom returns the union of every receipt's bloom filter, which is what the
// block header carries.
func (rs Receipts) Bloom() Bloom {
	var out Bloom
	for _, r := range rs {
		out.Or(&r.Bloom)
	}
	return out
}

// DeriveFields fills in the receipt fields that are not part of consensus but
// are needed to answer RPC queries.
func (rs Receipts) DeriveFields(blockHash common.Hash, number uint64, baseFee *big.Int, txs Transactions) error {
	if len(rs) != len(txs) {
		return fmt.Errorf("core: %d receipts for %d transactions", len(rs), len(txs))
	}
	logIndex := uint(0)
	for i, r := range rs {
		tx := txs[i]
		r.Type = tx.Type()
		r.TxHash = tx.Hash()
		r.BlockHash = blockHash
		r.BlockNumber = new(big.Int).SetUint64(number)
		r.TxIndex = uint(i)
		r.EffectiveGasPrice = tx.EffectiveGasPrice(baseFee)

		// Gas used by this transaction alone is the delta in the running total.
		if i == 0 {
			r.GasUsed = r.CumulativeGasUsed
		} else {
			r.GasUsed = r.CumulativeGasUsed - rs[i-1].CumulativeGasUsed
		}

		for _, log := range r.Logs {
			log.BlockNumber = number
			log.BlockHash = blockHash
			log.TxHash = r.TxHash
			log.TxIndex = uint(i)
			log.Index = logIndex
			logIndex++
		}
	}
	return nil
}
