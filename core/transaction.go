package core

import (
	"errors"
	"fmt"
	"io"
	"math/big"
	"sync/atomic"

	"layer1/common"
	"layer1/crypto/secp256k1"
	"layer1/rlp"
)

// Transaction types. Legacy transactions have no type byte; typed transactions
// are prefixed with their type, following the EIP-2718 envelope scheme.
const (
	LegacyTxType  = 0x00
	DynamicTxType = 0x02 // EIP-1559 style fee market
)

var (
	ErrInvalidTxType    = errors.New("core: unsupported transaction type")
	ErrInvalidSignature = errors.New("core: invalid transaction signature")
	ErrUnsignedTx       = errors.New("core: transaction is not signed")
	ErrChainIDMismatch  = errors.New("core: transaction is for a different chain")
	ErrFeeCapTooLow     = errors.New("core: max fee per gas is below the priority fee")
)

// TxData is the type-specific payload of a transaction.
type TxData interface {
	txType() byte
	// copy returns a deep copy of the payload.
	copy() TxData

	chainID() *big.Int
	nonce() uint64
	gasLimit() uint64
	gasPrice() *big.Int
	gasTipCap() *big.Int
	gasFeeCap() *big.Int
	to() *common.Address
	value() *big.Int
	data() []byte

	rawSignature() (v, r, s *big.Int)
	setSignature(chainID, v, r, s *big.Int)
}

// Transaction is a signed state transition request.
type Transaction struct {
	inner TxData

	// Caches, filled lazily and safe for concurrent use.
	hash   atomic.Pointer[common.Hash]
	sender atomic.Pointer[common.Address]
	size   atomic.Uint64
}

// NewTx wraps a type-specific payload.
func NewTx(inner TxData) *Transaction {
	return &Transaction{inner: inner.copy()}
}

// LegacyTx is a pre-EIP-1559 transaction with a single gas price.
type LegacyTx struct {
	Nonce    uint64
	GasPrice *big.Int
	Gas      uint64
	To       *common.Address `rlp:"nil"`
	Value    *big.Int
	Data     []byte
	V, R, S  *big.Int
}

// DynamicFeeTx splits the gas price into a base-fee cap and a priority tip,
// which is what lets the base fee be burned and the tip paid to the proposer.
type DynamicFeeTx struct {
	ChainID    *big.Int
	Nonce      uint64
	GasTipCap  *big.Int // maximum priority fee per gas
	GasFeeCap  *big.Int // maximum total fee per gas
	Gas        uint64
	To         *common.Address `rlp:"nil"`
	Value      *big.Int
	Data       []byte
	AccessList AccessList
	V, R, S    *big.Int
}

// AccessTuple pre-declares state a transaction will touch.
type AccessTuple struct {
	Address     common.Address
	StorageKeys []common.Hash
}

// AccessList is a list of pre-declared state accesses.
type AccessList []AccessTuple

// StorageKeyCount reports the total number of declared storage slots.
func (al AccessList) StorageKeyCount() int {
	n := 0
	for _, tuple := range al {
		n += len(tuple.StorageKeys)
	}
	return n
}

func (tx *LegacyTx) txType() byte { return LegacyTxType }

func (tx *LegacyTx) copy() TxData {
	out := &LegacyTx{
		Nonce:    tx.Nonce,
		Gas:      tx.Gas,
		Data:     common.CopyBytes(tx.Data),
		GasPrice: copyBig(tx.GasPrice),
		Value:    copyBig(tx.Value),
		V:        copyBig(tx.V),
		R:        copyBig(tx.R),
		S:        copyBig(tx.S),
	}
	if tx.To != nil {
		to := *tx.To
		out.To = &to
	}
	return out
}

// chainID recovers the chain id embedded in V by EIP-155. A V of 27 or 28 is a
// pre-EIP-155 signature with no chain id at all.
func (tx *LegacyTx) chainID() *big.Int {
	if tx.V == nil {
		return nil
	}
	v := tx.V.Uint64()
	if v == 27 || v == 28 {
		return nil
	}
	// v = chainID*2 + 35 + parity
	id := new(big.Int).Sub(tx.V, big.NewInt(35))
	return id.Rsh(id, 1)
}

func (tx *LegacyTx) nonce() uint64       { return tx.Nonce }
func (tx *LegacyTx) gasLimit() uint64    { return tx.Gas }
func (tx *LegacyTx) gasPrice() *big.Int  { return tx.GasPrice }
func (tx *LegacyTx) gasTipCap() *big.Int { return tx.GasPrice }
func (tx *LegacyTx) gasFeeCap() *big.Int { return tx.GasPrice }
func (tx *LegacyTx) to() *common.Address { return tx.To }
func (tx *LegacyTx) value() *big.Int     { return tx.Value }
func (tx *LegacyTx) data() []byte        { return tx.Data }

func (tx *LegacyTx) rawSignature() (v, r, s *big.Int) { return tx.V, tx.R, tx.S }

func (tx *LegacyTx) setSignature(chainID, v, r, s *big.Int) {
	tx.V, tx.R, tx.S = v, r, s
}

func (tx *DynamicFeeTx) txType() byte { return DynamicTxType }

func (tx *DynamicFeeTx) copy() TxData {
	out := &DynamicFeeTx{
		Nonce:      tx.Nonce,
		Gas:        tx.Gas,
		Data:       common.CopyBytes(tx.Data),
		AccessList: make(AccessList, len(tx.AccessList)),
		ChainID:    copyBig(tx.ChainID),
		GasTipCap:  copyBig(tx.GasTipCap),
		GasFeeCap:  copyBig(tx.GasFeeCap),
		Value:      copyBig(tx.Value),
		V:          copyBig(tx.V),
		R:          copyBig(tx.R),
		S:          copyBig(tx.S),
	}
	copy(out.AccessList, tx.AccessList)
	if tx.To != nil {
		to := *tx.To
		out.To = &to
	}
	return out
}

func (tx *DynamicFeeTx) chainID() *big.Int   { return tx.ChainID }
func (tx *DynamicFeeTx) nonce() uint64       { return tx.Nonce }
func (tx *DynamicFeeTx) gasLimit() uint64    { return tx.Gas }
func (tx *DynamicFeeTx) gasPrice() *big.Int  { return tx.GasFeeCap }
func (tx *DynamicFeeTx) gasTipCap() *big.Int { return tx.GasTipCap }
func (tx *DynamicFeeTx) gasFeeCap() *big.Int { return tx.GasFeeCap }
func (tx *DynamicFeeTx) to() *common.Address { return tx.To }
func (tx *DynamicFeeTx) value() *big.Int     { return tx.Value }
func (tx *DynamicFeeTx) data() []byte        { return tx.Data }

func (tx *DynamicFeeTx) rawSignature() (v, r, s *big.Int) { return tx.V, tx.R, tx.S }

func (tx *DynamicFeeTx) setSignature(chainID, v, r, s *big.Int) {
	tx.ChainID, tx.V, tx.R, tx.S = chainID, v, r, s
}

func copyBig(v *big.Int) *big.Int {
	if v == nil {
		return new(big.Int)
	}
	return new(big.Int).Set(v)
}

// Accessors.

func (tx *Transaction) Type() byte                       { return tx.inner.txType() }
func (tx *Transaction) ChainID() *big.Int                { return tx.inner.chainID() }
func (tx *Transaction) Nonce() uint64                    { return tx.inner.nonce() }
func (tx *Transaction) Gas() uint64                      { return tx.inner.gasLimit() }
func (tx *Transaction) GasPrice() *big.Int               { return copyBig(tx.inner.gasPrice()) }
func (tx *Transaction) GasTipCap() *big.Int              { return copyBig(tx.inner.gasTipCap()) }
func (tx *Transaction) GasFeeCap() *big.Int              { return copyBig(tx.inner.gasFeeCap()) }
func (tx *Transaction) Value() *big.Int                  { return copyBig(tx.inner.value()) }
func (tx *Transaction) Data() []byte                     { return common.CopyBytes(tx.inner.data()) }
func (tx *Transaction) RawSignature() (v, r, s *big.Int) { return tx.inner.rawSignature() }

// To returns the recipient, or nil for a contract creation.
func (tx *Transaction) To() *common.Address {
	to := tx.inner.to()
	if to == nil {
		return nil
	}
	out := *to
	return &out
}

// IsContractCreation reports whether the transaction deploys code.
func (tx *Transaction) IsContractCreation() bool { return tx.inner.to() == nil }

// AccessList returns the declared access list, which is empty for legacy types.
func (tx *Transaction) AccessList() AccessList {
	if dyn, ok := tx.inner.(*DynamicFeeTx); ok {
		return dyn.AccessList
	}
	return nil
}

// EffectiveGasPrice returns what the sender actually pays per gas at the given
// base fee: the base fee plus the tip, capped by the fee cap.
func (tx *Transaction) EffectiveGasPrice(baseFee *big.Int) *big.Int {
	if baseFee == nil || tx.Type() == LegacyTxType {
		return tx.GasPrice()
	}
	tip := new(big.Int).Sub(tx.inner.gasFeeCap(), baseFee)
	if tip.Sign() < 0 {
		tip.SetInt64(0)
	}
	if tip.Cmp(tx.inner.gasTipCap()) > 0 {
		tip.Set(tx.inner.gasTipCap())
	}
	return tip.Add(tip, baseFee)
}

// EffectiveTip returns the proposer's share per gas at the given base fee.
func (tx *Transaction) EffectiveTip(baseFee *big.Int) *big.Int {
	if baseFee == nil {
		return tx.GasTipCap()
	}
	return new(big.Int).Sub(tx.EffectiveGasPrice(baseFee), baseFee)
}

// Cost is the maximum the sender can be charged: gas * fee cap + value.
func (tx *Transaction) Cost() *big.Int {
	total := new(big.Int).Mul(tx.inner.gasFeeCap(), new(big.Int).SetUint64(tx.inner.gasLimit()))
	return total.Add(total, tx.inner.value())
}

// MarshalBinary returns the canonical wire encoding: bare RLP for legacy
// transactions, and type-byte-prefixed RLP for typed ones.
func (tx *Transaction) MarshalBinary() ([]byte, error) {
	if tx.Type() == LegacyTxType {
		return rlp.Encode(tx.inner)
	}
	payload, err := rlp.Encode(tx.inner)
	if err != nil {
		return nil, err
	}
	return append([]byte{tx.Type()}, payload...), nil
}

// UnmarshalBinary parses the wire encoding produced by MarshalBinary.
func (tx *Transaction) UnmarshalBinary(b []byte) error {
	if len(b) == 0 {
		return errors.New("core: empty transaction encoding")
	}
	// A leading byte of 0xC0 or above starts an RLP list, so it is a legacy
	// transaction; anything lower is an EIP-2718 type byte.
	if b[0] >= 0xC0 {
		inner := new(LegacyTx)
		if err := rlp.Decode(b, inner); err != nil {
			return fmt.Errorf("core: decoding legacy transaction: %w", err)
		}
		tx.setInner(inner)
		return nil
	}
	switch b[0] {
	case DynamicTxType:
		inner := new(DynamicFeeTx)
		if err := rlp.Decode(b[1:], inner); err != nil {
			return fmt.Errorf("core: decoding dynamic fee transaction: %w", err)
		}
		tx.setInner(inner)
		return nil
	default:
		return fmt.Errorf("%w: 0x%02x", ErrInvalidTxType, b[0])
	}
}

func (tx *Transaction) setInner(inner TxData) {
	tx.inner = inner
	tx.hash.Store(nil)
	tx.sender.Store(nil)
	tx.size.Store(0)
}

// EncodeRLP lets transactions nest inside RLP structures (a block body, say)
// using their canonical wire form.
func (tx *Transaction) EncodeRLP(w io.Writer) error {
	b, err := tx.MarshalBinary()
	if err != nil {
		return err
	}
	if tx.Type() == LegacyTxType {
		_, err = w.Write(b)
		return err
	}
	// Typed transactions travel as an opaque byte string inside a list.
	_, err = w.Write(rlp.EncodeBytes(b))
	return err
}

// DecodeRLP is the counterpart to EncodeRLP.
func (tx *Transaction) DecodeRLP(s *rlp.Stream) error {
	kind, _, err := s.Kind()
	if err != nil {
		return err
	}
	if kind == rlp.List {
		raw, err := s.Raw()
		if err != nil {
			return err
		}
		return tx.UnmarshalBinary(raw)
	}
	b, err := s.Bytes()
	if err != nil {
		return err
	}
	return tx.UnmarshalBinary(b)
}

// Hash is the transaction's identifier: the hash of its wire encoding.
func (tx *Transaction) Hash() common.Hash {
	if cached := tx.hash.Load(); cached != nil {
		return *cached
	}
	enc, err := tx.MarshalBinary()
	if err != nil {
		// Only an unencodable payload can get here, which the constructors
		// already rule out.
		panic(fmt.Sprintf("core: hashing an unencodable transaction: %v", err))
	}
	h := common.Keccak256(enc)
	tx.hash.Store(&h)
	return h
}

// Size returns the length of the wire encoding, used for pool accounting.
func (tx *Transaction) Size() uint64 {
	if cached := tx.size.Load(); cached != 0 {
		return cached
	}
	enc, err := tx.MarshalBinary()
	if err != nil {
		return 0
	}
	tx.size.Store(uint64(len(enc)))
	return uint64(len(enc))
}

// Transactions is a list of transactions.
type Transactions []*Transaction

func (txs Transactions) Len() int { return len(txs) }

// EncodeForRoot returns each transaction's wire encoding, in order, for
// deriving the transaction root of a block.
func (txs Transactions) EncodeForRoot() [][]byte {
	out := make([][]byte, len(txs))
	for i, tx := range txs {
		enc, err := tx.MarshalBinary()
		if err != nil {
			panic(fmt.Sprintf("core: encoding transaction %d: %v", i, err))
		}
		out[i] = enc
	}
	return out
}

// Signer computes the hash a transaction is signed over and recovers senders.
// The chain id is bound into the signature so a transaction valid on one chain
// cannot be replayed on another.
type Signer struct {
	chainID *big.Int
}

func NewSigner(chainID *big.Int) *Signer {
	return &Signer{chainID: new(big.Int).Set(chainID)}
}

func (s *Signer) ChainID() *big.Int { return new(big.Int).Set(s.chainID) }

// SigningHash returns the message digest the sender signs.
func (s *Signer) SigningHash(tx *Transaction) (common.Hash, error) {
	switch inner := tx.inner.(type) {
	case *LegacyTx:
		// EIP-155: the chain id is appended to the signed payload.
		enc, err := rlp.Encode([]any{
			inner.Nonce, inner.GasPrice, inner.Gas, addrOrEmpty(inner.To),
			inner.Value, inner.Data, s.chainID, uint64(0), uint64(0),
		})
		if err != nil {
			return common.Hash{}, err
		}
		return common.Keccak256(enc), nil

	case *DynamicFeeTx:
		enc, err := rlp.Encode([]any{
			s.chainID, inner.Nonce, inner.GasTipCap, inner.GasFeeCap, inner.Gas,
			addrOrEmpty(inner.To), inner.Value, inner.Data, inner.AccessList,
		})
		if err != nil {
			return common.Hash{}, err
		}
		return common.Keccak256(append([]byte{DynamicTxType}, enc...)), nil

	default:
		return common.Hash{}, ErrInvalidTxType
	}
}

// addrOrEmpty renders a recipient for signing: an empty byte string means
// contract creation.
func addrOrEmpty(a *common.Address) []byte {
	if a == nil {
		return []byte{}
	}
	return a[:]
}

// SignTx signs tx with key and returns a new signed transaction.
func (s *Signer) SignTx(tx *Transaction, key *secp256k1.PrivateKey) (*Transaction, error) {
	hash, err := s.SigningHash(tx)
	if err != nil {
		return nil, err
	}
	sig, err := secp256k1.Sign(key, hash[:])
	if err != nil {
		return nil, err
	}

	signed := &Transaction{inner: tx.inner.copy()}
	switch signed.inner.(type) {
	case *LegacyTx:
		// EIP-155 packs the chain id and the parity bit into V.
		v := new(big.Int).SetUint64(uint64(sig.V & 1))
		v.Add(v, big.NewInt(35))
		v.Add(v, new(big.Int).Lsh(s.chainID, 1))
		signed.inner.setSignature(s.chainID, v, sig.R, sig.S)
	default:
		// Typed transactions carry the parity bit alone; the chain id is a field.
		signed.inner.setSignature(s.chainID, new(big.Int).SetUint64(uint64(sig.V&1)), sig.R, sig.S)
	}
	return signed, nil
}

// Sender recovers the address that signed tx, caching the result.
func (s *Signer) Sender(tx *Transaction) (common.Address, error) {
	if cached := tx.sender.Load(); cached != nil {
		return *cached, nil
	}
	v, r, sVal := tx.inner.rawSignature()
	if v == nil || r == nil || sVal == nil || (r.Sign() == 0 && sVal.Sign() == 0) {
		return common.Address{}, ErrUnsignedTx
	}
	if !secp256k1.IsLowS(sVal) {
		// Reject the mirrored form outright: accepting it would let a third
		// party change a signed transaction's hash without holding the key.
		return common.Address{}, fmt.Errorf("%w: s is not canonical (high-s)", ErrInvalidSignature)
	}
	if id := tx.ChainID(); id != nil && id.Sign() != 0 && id.Cmp(s.chainID) != 0 {
		return common.Address{}, fmt.Errorf("%w: got %s, want %s", ErrChainIDMismatch, id, s.chainID)
	}

	// Reduce V to the bare recovery id.
	var recoveryID byte
	switch tx.Type() {
	case LegacyTxType:
		vv := v.Uint64()
		switch {
		case vv == 27 || vv == 28:
			recoveryID = byte(vv - 27)
		default:
			// v = chainID*2 + 35 + parity
			expected := new(big.Int).Lsh(s.chainID, 1)
			expected.Add(expected, big.NewInt(35))
			parity := new(big.Int).Sub(v, expected)
			if parity.Sign() < 0 || parity.Cmp(big.NewInt(1)) > 0 {
				return common.Address{}, fmt.Errorf("%w: V=%s is not valid for chain %s", ErrInvalidSignature, v, s.chainID)
			}
			recoveryID = byte(parity.Uint64())
		}
	default:
		if v.Cmp(big.NewInt(1)) > 0 {
			return common.Address{}, fmt.Errorf("%w: typed transaction V=%s must be 0 or 1", ErrInvalidSignature, v)
		}
		recoveryID = byte(v.Uint64())
	}

	hash, err := s.SigningHash(tx)
	if err != nil {
		return common.Address{}, err
	}
	pub, err := secp256k1.Recover(hash[:], &secp256k1.Signature{R: r, S: sVal, V: recoveryID})
	if err != nil {
		return common.Address{}, fmt.Errorf("%w: %v", ErrInvalidSignature, err)
	}
	addr := common.BytesToAddress(common.Keccak256(pub.Bytes()).Bytes()[12:])
	tx.sender.Store(&addr)
	return addr, nil
}
