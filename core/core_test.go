package core

import (
	"math/big"
	"testing"

	"padi-chain/common"
	"padi-chain/crypto/secp256k1"
)

func testKey(t *testing.T) *secp256k1.PrivateKey {
	t.Helper()
	k, err := secp256k1.PrivateKeyFromHex("0x4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318")
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func keyAddress(k *secp256k1.PrivateKey) common.Address {
	return common.BytesToAddress(common.Keccak256(k.PublicKey().Bytes()).Bytes()[12:])
}

func TestAccountEncoding(t *testing.T) {
	a := NewAccount()
	a.Nonce = 7
	a.Balance = big.NewInt(1000)

	enc, err := a.Encode()
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeAccount(enc)
	if err != nil {
		t.Fatal(err)
	}
	if got.Nonce != 7 || got.Balance.Cmp(big.NewInt(1000)) != 0 || got.Root != a.Root {
		t.Fatalf("round-trip changed the account: %+v", got)
	}
	if got.HasCode() {
		t.Error("an account with the empty code hash must not report code")
	}
	if !NewAccount().IsEmpty() {
		t.Error("a fresh account must be empty")
	}
	a.Nonce = 0
	a.Balance = new(big.Int)
	if !a.IsEmpty() {
		t.Error("zero nonce, zero balance and no code is empty")
	}
}

func TestLegacyTxSignAndRecover(t *testing.T) {
	key := testKey(t)
	signer := NewSigner(big.NewInt(1337))
	to := common.MustHexToAddress("0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed")

	tx := NewTx(&LegacyTx{
		Nonce:    3,
		GasPrice: big.NewInt(1_000_000_000),
		Gas:      21000,
		To:       &to,
		Value:    big.NewInt(1_000_000),
		Data:     nil,
	})
	signed, err := signer.SignTx(tx, key)
	if err != nil {
		t.Fatal(err)
	}
	sender, err := signer.Sender(signed)
	if err != nil {
		t.Fatal(err)
	}
	if sender != keyAddress(key) {
		t.Fatalf("recovered %s, want %s", sender, keyAddress(key))
	}
	// EIP-155: V must encode the chain id.
	if got := signed.ChainID(); got == nil || got.Cmp(big.NewInt(1337)) != 0 {
		t.Fatalf("chain id in V = %v, want 1337", got)
	}
}

func TestDynamicFeeTxSignAndRecover(t *testing.T) {
	key := testKey(t)
	signer := NewSigner(big.NewInt(1337))
	to := common.MustHexToAddress("0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed")

	tx := NewTx(&DynamicFeeTx{
		Nonce:     1,
		GasTipCap: big.NewInt(2_000_000_000),
		GasFeeCap: big.NewInt(30_000_000_000),
		Gas:       21000,
		To:        &to,
		Value:     big.NewInt(500),
		AccessList: AccessList{{
			Address:     to,
			StorageKeys: []common.Hash{{1}, {2}},
		}},
	})
	signed, err := signer.SignTx(tx, key)
	if err != nil {
		t.Fatal(err)
	}
	if signed.Type() != DynamicTxType {
		t.Fatalf("type = %d", signed.Type())
	}
	sender, err := signer.Sender(signed)
	if err != nil {
		t.Fatal(err)
	}
	if sender != keyAddress(key) {
		t.Fatalf("recovered %s, want %s", sender, keyAddress(key))
	}
	if signed.AccessList().StorageKeyCount() != 2 {
		t.Error("access list did not survive signing")
	}
}

func TestTxWireRoundTrip(t *testing.T) {
	key := testKey(t)
	signer := NewSigner(big.NewInt(1337))
	to := common.MustHexToAddress("0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed")

	for name, inner := range map[string]TxData{
		"legacy": &LegacyTx{Nonce: 1, GasPrice: big.NewInt(1), Gas: 21000, To: &to, Value: big.NewInt(2), Data: []byte{1, 2, 3}},
		"dynamic": &DynamicFeeTx{Nonce: 1, GasTipCap: big.NewInt(1), GasFeeCap: big.NewInt(10),
			Gas: 21000, To: &to, Value: big.NewInt(2), Data: []byte{4, 5}},
		"creation": &LegacyTx{Nonce: 0, GasPrice: big.NewInt(1), Gas: 100000, To: nil, Value: new(big.Int), Data: []byte{0x60, 0x00}},
	} {
		t.Run(name, func(t *testing.T) {
			signed, err := signer.SignTx(NewTx(inner), key)
			if err != nil {
				t.Fatal(err)
			}
			enc, err := signed.MarshalBinary()
			if err != nil {
				t.Fatal(err)
			}
			var got Transaction
			if err := got.UnmarshalBinary(enc); err != nil {
				t.Fatal(err)
			}
			if got.Hash() != signed.Hash() {
				t.Fatalf("hash changed across the wire: %s vs %s", got.Hash(), signed.Hash())
			}
			sender, err := signer.Sender(&got)
			if err != nil {
				t.Fatal(err)
			}
			if sender != keyAddress(key) {
				t.Fatalf("sender after round-trip = %s", sender)
			}
			if got.IsContractCreation() != signed.IsContractCreation() {
				t.Fatal("contract-creation flag lost in the round-trip")
			}
		})
	}
}

func TestSenderRejectsWrongChain(t *testing.T) {
	key := testKey(t)
	signed, err := NewSigner(big.NewInt(1337)).SignTx(
		NewTx(&LegacyTx{Nonce: 0, GasPrice: big.NewInt(1), Gas: 21000, Value: new(big.Int)}), key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewSigner(big.NewInt(1)).Sender(signed); err == nil {
		t.Fatal("a transaction signed for chain 1337 must not be valid on chain 1")
	}
}

func TestSenderRejectsUnsignedAndMalleable(t *testing.T) {
	signer := NewSigner(big.NewInt(1337))
	unsigned := NewTx(&LegacyTx{Nonce: 0, GasPrice: big.NewInt(1), Gas: 21000, Value: new(big.Int)})
	if _, err := signer.Sender(unsigned); err == nil {
		t.Error("an unsigned transaction must have no sender")
	}

	signed, _ := signer.SignTx(unsigned, testKey(t))
	v, r, s := signed.RawSignature()
	// Mirror s across the group order: still a valid curve signature, but the
	// canonical form is the only one this chain accepts.
	mirrored := NewTx(&LegacyTx{
		Nonce: 0, GasPrice: big.NewInt(1), Gas: 21000, Value: new(big.Int),
		V: v, R: r, S: new(big.Int).Sub(secp256k1.N, s),
	})
	if _, err := signer.Sender(mirrored); err == nil {
		t.Error("a high-s signature must be rejected")
	}
}

func TestEffectiveGasPrice(t *testing.T) {
	baseFee := big.NewInt(100)
	tx := NewTx(&DynamicFeeTx{
		GasTipCap: big.NewInt(10),
		GasFeeCap: big.NewInt(200),
		Gas:       21000,
		Value:     new(big.Int),
	})
	// Below the cap: the sender pays the base fee plus the full tip.
	if got := tx.EffectiveGasPrice(baseFee); got.Cmp(big.NewInt(110)) != 0 {
		t.Errorf("effective price = %s, want 110", got)
	}
	if got := tx.EffectiveTip(baseFee); got.Cmp(big.NewInt(10)) != 0 {
		t.Errorf("effective tip = %s, want 10", got)
	}

	// When the base fee approaches the cap the tip is squeezed, never negative.
	squeezed := tx.EffectiveGasPrice(big.NewInt(195))
	if squeezed.Cmp(big.NewInt(200)) != 0 {
		t.Errorf("effective price at a high base fee = %s, want the fee cap 200", squeezed)
	}
	if tip := tx.EffectiveTip(big.NewInt(200)); tip.Sign() != 0 {
		t.Errorf("tip at the fee cap = %s, want 0", tip)
	}

	// Legacy transactions always pay their gas price.
	legacy := NewTx(&LegacyTx{GasPrice: big.NewInt(50), Gas: 21000, Value: new(big.Int)})
	if got := legacy.EffectiveGasPrice(baseFee); got.Cmp(big.NewInt(50)) != 0 {
		t.Errorf("legacy effective price = %s, want 50", got)
	}
}

func TestTxCost(t *testing.T) {
	tx := NewTx(&LegacyTx{GasPrice: big.NewInt(10), Gas: 100, Value: big.NewInt(7)})
	if got := tx.Cost(); got.Cmp(big.NewInt(1007)) != 0 {
		t.Fatalf("cost = %s, want 1007", got)
	}
}

func TestBlockRootsAndHash(t *testing.T) {
	key := testKey(t)
	signer := NewSigner(big.NewInt(1337))
	var txs Transactions
	for i := 0; i < 3; i++ {
		tx, err := signer.SignTx(NewTx(&LegacyTx{
			Nonce: uint64(i), GasPrice: big.NewInt(1), Gas: 21000, Value: big.NewInt(int64(i)),
		}), key)
		if err != nil {
			t.Fatal(err)
		}
		txs = append(txs, tx)
	}
	receipts := Receipts{
		NewReceipt(LegacyTxType, ReceiptStatusSuccessful, 21000, nil),
		NewReceipt(LegacyTxType, ReceiptStatusSuccessful, 42000, nil),
		NewReceipt(LegacyTxType, ReceiptStatusFailed, 63000, nil),
	}

	header := &Header{
		ParentHash: common.Keccak256([]byte("parent")),
		Number:     big.NewInt(1),
		GasLimit:   30_000_000,
		GasUsed:    63000,
		Time:       1700000000,
		BaseFee:    big.NewInt(1_000_000_000),
	}
	block := NewBlock(header, txs, receipts)

	if block.TxRoot() == (common.Hash{}) {
		t.Fatal("transaction root was not derived")
	}
	// The same contents must always produce the same roots.
	again := NewBlock(header, txs, receipts)
	if again.TxRoot() != block.TxRoot() || again.ReceiptRoot() != block.ReceiptRoot() {
		t.Fatal("block roots are not deterministic")
	}
	// Changing the body must change the transaction root.
	fewer := NewBlock(header, txs[:2], receipts[:2])
	if fewer.TxRoot() == block.TxRoot() {
		t.Fatal("dropping a transaction did not change the root")
	}
	if block.Transaction(txs[1].Hash()) == nil {
		t.Fatal("Transaction lookup by hash failed")
	}
}

func TestBlockWireRoundTrip(t *testing.T) {
	key := testKey(t)
	signer := NewSigner(big.NewInt(1337))
	tx, _ := signer.SignTx(NewTx(&LegacyTx{Nonce: 0, GasPrice: big.NewInt(1), Gas: 21000, Value: new(big.Int)}), key)

	block := NewBlock(&Header{
		ParentHash: common.Keccak256([]byte("parent")),
		Number:     big.NewInt(5),
		GasLimit:   30_000_000,
		Time:       1700000000,
		BaseFee:    big.NewInt(7),
		Extra:      []byte("padi-chain"),
	}, Transactions{tx}, Receipts{NewReceipt(LegacyTxType, ReceiptStatusSuccessful, 21000, nil)})

	enc, err := block.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	var got Block
	if err := got.UnmarshalBinary(enc); err != nil {
		t.Fatal(err)
	}
	if got.Hash() != block.Hash() {
		t.Fatalf("block hash changed across the wire: %s vs %s", got.Hash(), block.Hash())
	}
	if len(got.Transactions()) != 1 || got.Transactions()[0].Hash() != tx.Hash() {
		t.Fatal("transactions did not survive the round-trip")
	}
}

func TestBlockRejectsMismatchedBody(t *testing.T) {
	key := testKey(t)
	signer := NewSigner(big.NewInt(1337))
	tx, _ := signer.SignTx(NewTx(&LegacyTx{Nonce: 0, GasPrice: big.NewInt(1), Gas: 21000, Value: new(big.Int)}), key)
	other, _ := signer.SignTx(NewTx(&LegacyTx{Nonce: 1, GasPrice: big.NewInt(1), Gas: 21000, Value: new(big.Int)}), key)

	block := NewBlock(&Header{Number: big.NewInt(1), BaseFee: new(big.Int)}, Transactions{tx}, nil)
	// Swap the body without updating the header: decoding must reject it.
	tampered := block.WithBody(Transactions{other})
	enc, err := tampered.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	var got Block
	if err := got.UnmarshalBinary(enc); err == nil {
		t.Fatal("a body that disagrees with the header's transaction root must be rejected")
	}
}

func TestSealIsExcludedFromSealingHash(t *testing.T) {
	header := &Header{Number: big.NewInt(1), BaseFee: new(big.Int), Time: 1}
	block := NewBlockWithHeader(header)
	before := block.SealingHash()

	sealed := block.WithSeal([]byte("a proposer signature"))
	if sealed.SealingHash() != before {
		t.Fatal("the seal must not affect the hash the proposer signs")
	}
	if sealed.Hash() == block.Hash() {
		t.Fatal("the seal must be committed to by the block hash")
	}
}

func TestReceiptRoundTrip(t *testing.T) {
	r := NewReceipt(DynamicTxType, ReceiptStatusSuccessful, 50000, []*Log{{
		Address: common.MustHexToAddress("0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"),
		Topics:  []common.Hash{common.Keccak256([]byte("Transfer(address,address,uint256)"))},
		Data:    []byte{1, 2, 3},
	}})
	enc, err := r.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if enc[0] != DynamicTxType {
		t.Fatalf("typed receipt must carry its type prefix, got 0x%02x", enc[0])
	}
	var got Receipt
	if err := got.UnmarshalBinary(enc); err != nil {
		t.Fatal(err)
	}
	if got.Status != r.Status || got.CumulativeGasUsed != r.CumulativeGasUsed || len(got.Logs) != 1 {
		t.Fatalf("round-trip changed the receipt: %+v", got)
	}
	if got.Bloom != r.Bloom {
		t.Fatal("bloom filter did not survive the round-trip")
	}
}

func TestReceiptDeriveFields(t *testing.T) {
	key := testKey(t)
	signer := NewSigner(big.NewInt(1337))
	var txs Transactions
	for i := 0; i < 2; i++ {
		tx, _ := signer.SignTx(NewTx(&LegacyTx{Nonce: uint64(i), GasPrice: big.NewInt(5), Gas: 21000, Value: new(big.Int)}), key)
		txs = append(txs, tx)
	}
	receipts := Receipts{
		NewReceipt(LegacyTxType, ReceiptStatusSuccessful, 21000, []*Log{{Address: common.Address{1}}}),
		NewReceipt(LegacyTxType, ReceiptStatusSuccessful, 45000, []*Log{{Address: common.Address{2}}}),
	}
	blockHash := common.Keccak256([]byte("block"))
	if err := receipts.DeriveFields(signer, blockHash, 9, big.NewInt(1), txs); err != nil {
		t.Fatal(err)
	}
	if receipts[0].GasUsed != 21000 {
		t.Errorf("first receipt gas used = %d, want 21000", receipts[0].GasUsed)
	}
	// The second transaction's own gas is the delta in the cumulative total.
	if receipts[1].GasUsed != 24000 {
		t.Errorf("second receipt gas used = %d, want 24000", receipts[1].GasUsed)
	}
	if receipts[1].Logs[0].Index != 1 {
		t.Errorf("log index = %d, want 1 (indices run across the block)", receipts[1].Logs[0].Index)
	}
	if receipts[0].TxHash != txs[0].Hash() || receipts[0].BlockHash != blockHash {
		t.Error("receipt context fields were not filled in")
	}
	if err := receipts.DeriveFields(signer, blockHash, 9, big.NewInt(1), txs[:1]); err == nil {
		t.Error("a receipt/transaction count mismatch must be an error")
	}
}

func TestBloomFilter(t *testing.T) {
	addr := common.MustHexToAddress("0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed")
	topic := common.Keccak256([]byte("Transfer(address,address,uint256)"))
	r := NewReceipt(LegacyTxType, ReceiptStatusSuccessful, 0, []*Log{{
		Address: addr,
		Topics:  []common.Hash{topic},
	}})

	if !r.Bloom.Test(addr[:]) {
		t.Error("the emitting address must match the filter")
	}
	if !r.Bloom.Test(topic[:]) {
		t.Error("the topic must match the filter")
	}
	// An unrelated value should almost never match; with 2048 bits and three
	// probes a false positive here would be a one-in-a-billion accident.
	absent := common.Keccak256([]byte("never logged"))
	if r.Bloom.Test(absent[:]) {
		t.Error("an unrelated value matched the filter")
	}

	var empty Bloom
	if !empty.IsZero() {
		t.Error("a fresh bloom must be zero")
	}
	empty.Or(&r.Bloom)
	if empty != r.Bloom {
		t.Error("Or did not merge the filter")
	}
}
