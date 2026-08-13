package txpool

import (
	"errors"
	"math/big"
	"testing"

	"padi-chain/common"
	"padi-chain/core"
	"padi-chain/crypto/secp256k1"
	"padi-chain/db"
	"padi-chain/state"
)

var testChainID = big.NewInt(1337)

// stubChain is a minimal StateReader backed by a mutable state.
type stubChain struct {
	statedb  *state.StateDB
	gasLimit uint64
	baseFee  *big.Int
}

func (c *stubChain) CurrentState() (*state.StateDB, error) { return c.statedb, nil }
func (c *stubChain) CurrentGasLimit() uint64               { return c.gasLimit }
func (c *stubChain) CurrentBaseFee() *big.Int              { return c.baseFee }

func newTestPool(t *testing.T) (*TxPool, *stubChain, []*secp256k1.PrivateKey, []common.Address) {
	t.Helper()
	statedb, err := state.New(common.Hash{}, db.NewMemoryDB())
	if err != nil {
		t.Fatal(err)
	}
	var keys []*secp256k1.PrivateKey
	var addrs []common.Address
	for i := 1; i <= 3; i++ {
		key, err := secp256k1.PrivateKeyFromBytes(common.LeftPadBytes([]byte{byte(i)}, 32))
		if err != nil {
			t.Fatal(err)
		}
		addr := common.BytesToAddress(common.Keccak256(key.PublicKey().Bytes()).Bytes()[12:])
		statedb.AddBalance(addr, new(big.Int).Lsh(big.NewInt(1), 70))
		keys = append(keys, key)
		addrs = append(addrs, addr)
	}
	chain := &stubChain{statedb: statedb, gasLimit: 30_000_000, baseFee: big.NewInt(1_000_000_000)}
	return New(DefaultConfig(), testChainID, chain), chain, keys, addrs
}

func makeTx(t *testing.T, key *secp256k1.PrivateKey, nonce uint64, tip, feeCap int64, gas uint64) *core.Transaction {
	t.Helper()
	to := common.MustHexToAddress("0x9999999999999999999999999999999999999999")
	signer := core.NewSigner(testChainID)
	tx, err := signer.SignTx(core.NewTx(&core.DynamicFeeTx{
		Nonce:     nonce,
		GasTipCap: big.NewInt(tip),
		GasFeeCap: big.NewInt(feeCap),
		Gas:       gas,
		To:        &to,
		Value:     big.NewInt(1),
	}), key)
	if err != nil {
		t.Fatal(err)
	}
	return tx
}

func TestAddPendingTransaction(t *testing.T) {
	pool, _, keys, _ := newTestPool(t)
	tx := makeTx(t, keys[0], 0, 1e9, 10e9, 21000)

	if err := pool.Add(tx); err != nil {
		t.Fatal(err)
	}
	pending, queued := pool.Stats()
	if pending != 1 || queued != 0 {
		t.Fatalf("pending=%d queued=%d, want 1/0", pending, queued)
	}
	if !pool.Has(tx.Hash()) || pool.Get(tx.Hash()) == nil {
		t.Fatal("the transaction is not retrievable")
	}
}

func TestDuplicateRejected(t *testing.T) {
	pool, _, keys, _ := newTestPool(t)
	tx := makeTx(t, keys[0], 0, 1e9, 10e9, 21000)
	if err := pool.Add(tx); err != nil {
		t.Fatal(err)
	}
	if err := pool.Add(tx); !errors.Is(err, ErrAlreadyKnown) {
		t.Fatalf("got %v, want ErrAlreadyKnown", err)
	}
}

func TestNonceGapQueuesThenPromotes(t *testing.T) {
	pool, _, keys, _ := newTestPool(t)

	// Nonce 2 arrives first and has to wait.
	if err := pool.Add(makeTx(t, keys[0], 2, 1e9, 10e9, 21000)); err != nil {
		t.Fatal(err)
	}
	if pending, queued := pool.Stats(); pending != 0 || queued != 1 {
		t.Fatalf("pending=%d queued=%d, want 0/1", pending, queued)
	}

	// Nonce 0 makes nothing executable beyond itself.
	if err := pool.Add(makeTx(t, keys[0], 0, 1e9, 10e9, 21000)); err != nil {
		t.Fatal(err)
	}
	if pending, queued := pool.Stats(); pending != 1 || queued != 1 {
		t.Fatalf("pending=%d queued=%d, want 1/1", pending, queued)
	}

	// Nonce 1 closes the gap, so 2 is promoted with it.
	if err := pool.Add(makeTx(t, keys[0], 1, 1e9, 10e9, 21000)); err != nil {
		t.Fatal(err)
	}
	if pending, queued := pool.Stats(); pending != 3 || queued != 0 {
		t.Fatalf("pending=%d queued=%d, want 3/0", pending, queued)
	}
}

func TestNonceTooLowRejected(t *testing.T) {
	pool, chain, keys, addrs := newTestPool(t)
	chain.statedb.SetNonce(addrs[0], 5)

	if err := pool.Add(makeTx(t, keys[0], 3, 1e9, 10e9, 21000)); !errors.Is(err, ErrNonceTooLow) {
		t.Fatalf("got %v, want ErrNonceTooLow", err)
	}
}

func TestInsufficientFunds(t *testing.T) {
	pool, chain, keys, addrs := newTestPool(t)
	chain.statedb.SetBalance(addrs[0], big.NewInt(1000))

	if err := pool.Add(makeTx(t, keys[0], 0, 1e9, 10e9, 21000)); !errors.Is(err, ErrInsufficientFunds) {
		t.Fatalf("got %v, want ErrInsufficientFunds", err)
	}
}

func TestCumulativeCostAcrossPooledTransactions(t *testing.T) {
	pool, chain, keys, addrs := newTestPool(t)
	// Enough for exactly one transaction at this fee cap, plus a little.
	oneCost := new(big.Int).Mul(big.NewInt(10e9), big.NewInt(21000))
	chain.statedb.SetBalance(addrs[0], new(big.Int).Add(oneCost, big.NewInt(1000)))

	if err := pool.Add(makeTx(t, keys[0], 0, 1e9, 10e9, 21000)); err != nil {
		t.Fatal(err)
	}
	// The second one cannot be afforded on top of the first.
	if err := pool.Add(makeTx(t, keys[0], 1, 1e9, 10e9, 21000)); !errors.Is(err, ErrInsufficientFunds) {
		t.Fatalf("got %v, want ErrInsufficientFunds for the second transaction", err)
	}
}

func TestIntrinsicGasRejected(t *testing.T) {
	pool, _, keys, _ := newTestPool(t)
	if err := pool.Add(makeTx(t, keys[0], 0, 1e9, 10e9, 20999)); !errors.Is(err, ErrIntrinsicGas) {
		t.Fatalf("got %v, want ErrIntrinsicGas", err)
	}
}

func TestGasLimitAboveBlockLimit(t *testing.T) {
	pool, chain, keys, _ := newTestPool(t)
	if err := pool.Add(makeTx(t, keys[0], 0, 1e9, 10e9, chain.gasLimit+1)); !errors.Is(err, ErrGasLimitTooHigh) {
		t.Fatalf("got %v, want ErrGasLimitTooHigh", err)
	}
}

func TestReplacementRequiresPriceBump(t *testing.T) {
	pool, _, keys, _ := newTestPool(t)
	original := makeTx(t, keys[0], 0, 1e9, 10e9, 21000)
	if err := pool.Add(original); err != nil {
		t.Fatal(err)
	}

	// A marginally higher fee is not enough.
	if err := pool.Add(makeTx(t, keys[0], 0, 1e9, 10.5e9, 21000)); !errors.Is(err, ErrReplaceUnderpriced) {
		t.Fatalf("got %v, want ErrReplaceUnderpriced", err)
	}
	// A 10% bump on both the cap and the tip is.
	replacement := makeTx(t, keys[0], 0, 1.2e9, 12e9, 21000)
	if err := pool.Add(replacement); err != nil {
		t.Fatal(err)
	}
	if pool.Has(original.Hash()) {
		t.Fatal("the replaced transaction is still in the pool")
	}
	if !pool.Has(replacement.Hash()) {
		t.Fatal("the replacement is not in the pool")
	}
	if pending, _ := pool.Stats(); pending != 1 {
		t.Fatalf("pending=%d after replacement, want 1", pending)
	}
}

func TestUnderpricedRejected(t *testing.T) {
	statedb, _ := state.New(common.Hash{}, db.NewMemoryDB())
	key, _ := secp256k1.PrivateKeyFromBytes(common.LeftPadBytes([]byte{1}, 32))
	addr := common.BytesToAddress(common.Keccak256(key.PublicKey().Bytes()).Bytes()[12:])
	statedb.AddBalance(addr, new(big.Int).Lsh(big.NewInt(1), 70))

	config := DefaultConfig()
	config.PriceLimit = big.NewInt(5_000_000_000)
	pool := New(config, testChainID, &stubChain{statedb: statedb, gasLimit: 30_000_000, baseFee: big.NewInt(1)})

	if err := pool.Add(makeTx(t, key, 0, 1e9, 1e9, 21000)); !errors.Is(err, ErrUnderpriced) {
		t.Fatalf("got %v, want ErrUnderpriced", err)
	}
}

func TestReadyOrdersByTip(t *testing.T) {
	pool, _, keys, _ := newTestPool(t)

	// Three senders bidding different tips.
	low := makeTx(t, keys[0], 0, 1e9, 20e9, 21000)
	high := makeTx(t, keys[1], 0, 5e9, 20e9, 21000)
	mid := makeTx(t, keys[2], 0, 3e9, 20e9, 21000)
	for _, tx := range []*core.Transaction{low, high, mid} {
		if err := pool.Add(tx); err != nil {
			t.Fatal(err)
		}
	}

	ready := pool.Ready(0)
	if len(ready) != 3 {
		t.Fatalf("Ready returned %d transactions, want 3", len(ready))
	}
	if ready[0].Hash() != high.Hash() || ready[2].Hash() != low.Hash() {
		t.Fatal("Ready did not order by effective tip")
	}
}

func TestReadyPreservesNonceOrder(t *testing.T) {
	pool, _, keys, _ := newTestPool(t)

	// One sender whose later transaction pays far more: it still cannot jump
	// ahead of its own predecessor.
	first := makeTx(t, keys[0], 0, 1e9, 20e9, 21000)
	second := makeTx(t, keys[0], 1, 9e9, 20e9, 21000)
	if err := pool.Add(first); err != nil {
		t.Fatal(err)
	}
	if err := pool.Add(second); err != nil {
		t.Fatal(err)
	}

	ready := pool.Ready(0)
	if len(ready) != 2 || ready[0].Hash() != first.Hash() || ready[1].Hash() != second.Hash() {
		t.Fatal("Ready broke an account's nonce ordering")
	}
}

func TestReadyRespectsLimit(t *testing.T) {
	pool, _, keys, _ := newTestPool(t)
	for i := 0; i < 5; i++ {
		if err := pool.Add(makeTx(t, keys[0], uint64(i), 1e9, 20e9, 21000)); err != nil {
			t.Fatal(err)
		}
	}
	if got := len(pool.Ready(3)); got != 3 {
		t.Fatalf("Ready(3) returned %d transactions", got)
	}
}

func TestNonceTracksPool(t *testing.T) {
	pool, _, keys, addrs := newTestPool(t)
	for i := 0; i < 3; i++ {
		if err := pool.Add(makeTx(t, keys[0], uint64(i), 1e9, 20e9, 21000)); err != nil {
			t.Fatal(err)
		}
	}
	nonce, err := pool.Nonce(addrs[0])
	if err != nil {
		t.Fatal(err)
	}
	if nonce != 3 {
		t.Fatalf("next nonce = %d, want 3 (accounting for pooled transactions)", nonce)
	}
}

func TestResetDropsIncludedTransactions(t *testing.T) {
	pool, chain, keys, addrs := newTestPool(t)
	var txs core.Transactions
	for i := 0; i < 3; i++ {
		tx := makeTx(t, keys[0], uint64(i), 1e9, 20e9, 21000)
		if err := pool.Add(tx); err != nil {
			t.Fatal(err)
		}
		txs = append(txs, tx)
	}

	// The first two were mined: the account nonce advances and they leave.
	chain.statedb.SetNonce(addrs[0], 2)
	pool.Reset(txs[:2])

	if pool.Has(txs[0].Hash()) || pool.Has(txs[1].Hash()) {
		t.Fatal("included transactions were not removed")
	}
	if !pool.Has(txs[2].Hash()) {
		t.Fatal("the still-pending transaction was dropped")
	}
	if pending, queued := pool.Stats(); pending != 1 || queued != 0 {
		t.Fatalf("pending=%d queued=%d after reset, want 1/0", pending, queued)
	}
}

func TestResetDropsUnaffordableTransactions(t *testing.T) {
	pool, chain, keys, addrs := newTestPool(t)
	tx := makeTx(t, keys[0], 0, 1e9, 20e9, 21000)
	if err := pool.Add(tx); err != nil {
		t.Fatal(err)
	}

	// The sender's balance drained away, so the transaction can no longer be
	// paid for and must not linger.
	chain.statedb.SetBalance(addrs[0], big.NewInt(1))
	pool.Reset(nil)

	if pool.Has(tx.Hash()) {
		t.Fatal("an unaffordable transaction survived the reset")
	}
}

func TestAccountSlotLimit(t *testing.T) {
	statedb, _ := state.New(common.Hash{}, db.NewMemoryDB())
	key, _ := secp256k1.PrivateKeyFromBytes(common.LeftPadBytes([]byte{1}, 32))
	addr := common.BytesToAddress(common.Keccak256(key.PublicKey().Bytes()).Bytes()[12:])
	statedb.AddBalance(addr, new(big.Int).Lsh(big.NewInt(1), 70))

	config := DefaultConfig()
	config.AccountSlots = 3
	pool := New(config, testChainID, &stubChain{statedb: statedb, gasLimit: 30_000_000, baseFee: big.NewInt(1)})

	for i := 0; i < 3; i++ {
		if err := pool.Add(makeTx(t, key, uint64(i), 1e9, 20e9, 21000)); err != nil {
			t.Fatalf("transaction %d: %v", i, err)
		}
	}
	if err := pool.Add(makeTx(t, key, 3, 1e9, 20e9, 21000)); !errors.Is(err, ErrPoolFull) {
		t.Fatalf("got %v, want ErrPoolFull once the account slot limit is reached", err)
	}
}

func TestSubscribersSeeNewTransactions(t *testing.T) {
	pool, _, keys, _ := newTestPool(t)
	ch := make(chan []*core.Transaction, 4)
	pool.Subscribe(ch)

	tx := makeTx(t, keys[0], 0, 1e9, 20e9, 21000)
	if err := pool.Add(tx); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-ch:
		if len(got) != 1 || got[0].Hash() != tx.Hash() {
			t.Fatal("the wrong transaction was announced")
		}
	default:
		t.Fatal("no announcement was published")
	}
}

func TestAddBatchReportsPerTransaction(t *testing.T) {
	pool, _, keys, _ := newTestPool(t)
	good := makeTx(t, keys[0], 0, 1e9, 20e9, 21000)
	bad := makeTx(t, keys[1], 0, 1e9, 20e9, 1) // below the intrinsic cost

	errs := pool.AddBatch([]*core.Transaction{good, bad})
	if errs[0] != nil {
		t.Fatalf("the valid transaction was rejected: %v", errs[0])
	}
	if !errors.Is(errs[1], ErrIntrinsicGas) {
		t.Fatalf("got %v for the invalid transaction, want ErrIntrinsicGas", errs[1])
	}
}
