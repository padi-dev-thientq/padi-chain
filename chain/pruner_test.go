package chain_test

import (
	"errors"
	"math/big"
	"sync/atomic"
	"testing"
	"time"

	"layer1/chain"
	"layer1/common"
	"layer1/consensus"
	"layer1/core"
	"layer1/crypto/secp256k1"
	"layer1/db"
	"layer1/miner"
	"layer1/staking"
	"layer1/state"
	"layer1/trie"
)

// testClock lets a test drive consensus time explicitly. The clock must be
// steady within a single block build: if it advanced on every read, the open
// round would shift mid-build and the proposer would change underneath the
// builder.
type testClock struct{ offset atomic.Int64 }

// advance moves the clock forward by one block period.
func (c *testClock) advance() { c.offset.Add(1) }

// newPruneTestChain builds a chain whose clock a test drives, so it can mine
// far more blocks than the block period would allow in real time.
func newPruneTestChain(t *testing.T, keys []*secp256k1.PrivateKey, addrs []common.Address) (*chain.BlockChain, *consensus.PoA) {
	bc, engine, clock := newControlledChain(t, keys, addrs)
	// Tests that do not drive the clock themselves get one that keeps pace
	// with the blocks they mine.
	go func() {
		for i := 0; i < 100000; i++ {
			clock.advance()
			time.Sleep(time.Millisecond)
		}
	}()
	return bc, engine
}

// newControlledChain builds a chain and hands back the clock driving it.
func newControlledChain(t *testing.T, keys []*secp256k1.PrivateKey, addrs []common.Address) (*chain.BlockChain, *consensus.PoA, *testClock) {
	t.Helper()

	genesis := chain.DefaultGenesis(chainID, addrs[:1])
	genesis.BlockPeriod = 1
	for _, addr := range addrs {
		genesis.Alloc[addr] = chain.GenesisAccount{Balance: new(big.Int).Lsh(big.NewInt(1), 80)}
	}
	engine, err := consensus.NewPoA(genesis.Validators, genesis.BlockPeriod)
	if err != nil {
		t.Fatal(err)
	}
	clock := new(testClock)
	base := time.Now().Add(time.Hour)
	engine.SetClock(func() time.Time {
		return base.Add(time.Duration(clock.offset.Load()) * time.Second)
	})

	bc, err := chain.NewBlockChain(db.NewMemoryDB(), genesis, engine)
	if err != nil {
		t.Fatal(err)
	}
	return bc, engine, clock
}

// countKeys returns how many records the store holds under a prefix.
func countKeys(t *testing.T, bc *chain.BlockChain, prefix []byte) int {
	t.Helper()
	n := 0
	if err := bc.Store().Iterate(prefix, func(_, _ []byte) bool {
		n++
		return true
	}); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestPrunerRemovesUnreachableState(t *testing.T) {
	keys, addrs := testKeys(t, 2)
	bc, engine := newPruneTestChain(t, keys, addrs)
	builder := miner.NewBuilder(bc, engine, keys[0])

	recipient := common.MustHexToAddress("0x9999999999999999999999999999999999999999")
	for i := 0; i < 20; i++ {
		tx := signTx(t, keys[1], uint64(i), &recipient, big.NewInt(int64(i+1)), 21000, nil)
		if _, err := builder.Commit(core.Transactions{tx}); err != nil {
			t.Fatal(err)
		}
	}

	before := countKeys(t, bc, trie.NodeKeyPrefix)
	if before == 0 {
		t.Fatal("no trie nodes were written")
	}

	// Keep only the last two states: everything older becomes unreachable.
	config := &chain.PruneConfig{Retain: 2, Enabled: true}
	pruner := chain.NewPruner(bc, bc.Tracker(), config, nil)

	stats, err := pruner.Run()
	if err != nil {
		t.Fatal(err)
	}
	if stats.Deleted == 0 {
		t.Fatal("the prune removed nothing despite twenty states of churn")
	}

	after := countKeys(t, bc, trie.NodeKeyPrefix)
	if after >= before {
		t.Fatalf("the store did not shrink: %d -> %d", before, after)
	}
	t.Logf("pruned %d of %d nodes, %d reachable", stats.Deleted, before, stats.Reachable)
}

func TestPrunerKeepsRetainedStatesUsable(t *testing.T) {
	keys, addrs := testKeys(t, 2)
	bc, engine := newPruneTestChain(t, keys, addrs)
	builder := miner.NewBuilder(bc, engine, keys[0])

	recipient := common.MustHexToAddress("0x9999999999999999999999999999999999999999")
	for i := 0; i < 12; i++ {
		tx := signTx(t, keys[1], uint64(i), &recipient, big.NewInt(100), 21000, nil)
		if _, err := builder.Commit(core.Transactions{tx}); err != nil {
			t.Fatal(err)
		}
	}

	head := bc.CurrentBlock().NumberU64()
	pruner := chain.NewPruner(bc, bc.Tracker(), &chain.PruneConfig{Retain: 4, Enabled: true}, nil)
	if _, err := pruner.Run(); err != nil {
		t.Fatal(err)
	}

	// Every retained state must still open and read correctly.
	for i := uint64(0); i < 4; i++ {
		number := head - i
		block := bc.GetBlockByNumber(number)
		statedb, err := bc.StateAt(block.StateRoot())
		if err != nil {
			t.Fatalf("retained state at block %d is unusable: %v", number, err)
		}
		want := new(big.Int).Mul(big.NewInt(100), big.NewInt(int64(number)))
		if got := statedb.GetBalance(recipient); got.Cmp(want) != 0 {
			t.Fatalf("state at block %d reads %s, want %s", number, got, want)
		}
	}

	// And genesis, which is retained unconditionally.
	if _, err := bc.StateAt(bc.Genesis().StateRoot()); err != nil {
		t.Fatalf("genesis state was pruned away: %v", err)
	}
}

func TestPrunerKeepsFinalizedState(t *testing.T) {
	keys, addrs := testKeys(t, 2)
	bc, engine := newPruneTestChain(t, keys, addrs)
	builder := miner.NewBuilder(bc, engine, keys[0])

	recipient := common.MustHexToAddress("0x9999999999999999999999999999999999999999")
	for i := 0; i < 3; i++ {
		tx := signTx(t, keys[1], uint64(i), &recipient, big.NewInt(50), 21000, nil)
		if _, err := builder.Commit(core.Transactions{tx}); err != nil {
			t.Fatal(err)
		}
	}
	// Finalize an early block, then bury it well outside the retention window.
	// Block 2 carries the first two transfers.
	finalized := bc.GetBlockByNumber(2)
	const balanceAtBlock2 = 100
	finalize(t, bc, finalized, keys[:1])

	for i := 3; i < 15; i++ {
		tx := signTx(t, keys[1], uint64(i), &recipient, big.NewInt(50), 21000, nil)
		if _, err := builder.Commit(core.Transactions{tx}); err != nil {
			t.Fatal(err)
		}
	}

	pruner := chain.NewPruner(bc, bc.Tracker(), &chain.PruneConfig{Retain: 2, Enabled: true}, nil)
	if _, err := pruner.Run(); err != nil {
		t.Fatal(err)
	}

	// The settlement point must survive regardless of how far behind it falls.
	statedb, err := bc.StateAt(finalized.StateRoot())
	if err != nil {
		t.Fatalf("the finalized state was pruned away: %v", err)
	}
	if got := statedb.GetBalance(recipient); got.Cmp(big.NewInt(balanceAtBlock2)) != 0 {
		t.Fatalf("finalized state reads %s, want %d", got, balanceAtBlock2)
	}
}

func TestPrunerPreservesContractCodeAndStorage(t *testing.T) {
	keys, addrs := testKeys(t, 2)
	bc, engine := newPruneTestChain(t, keys, addrs)
	builder := miner.NewBuilder(bc, engine, keys[0])

	// Deploy a contract that writes a storage slot, then exercise it.
	runtime := []byte{
		0x60, 0x00, 0x35, // PUSH1 0 CALLDATALOAD
		0x60, 0x00, 0x55, // PUSH1 0 SSTORE
		0x00, // STOP
	}
	initCode := append([]byte{
		0x60, byte(len(runtime)), 0x60, 12, 0x60, 0x00, 0x39,
		0x60, byte(len(runtime)), 0x60, 0x00, 0xf3,
	}, runtime...)

	deploy := signTx(t, keys[1], 0, nil, new(big.Int), 500_000, initCode)
	result, err := builder.Commit(core.Transactions{deploy})
	if err != nil {
		t.Fatal(err)
	}
	contractAddr := result.Receipts[0].ContractAddress

	for i := 1; i < 10; i++ {
		value := common.LeftPadBytes([]byte{byte(i)}, 32)
		tx := signTx(t, keys[1], uint64(i), &contractAddr, new(big.Int), 200_000, value)
		if _, err := builder.Commit(core.Transactions{tx}); err != nil {
			t.Fatal(err)
		}
	}

	pruner := chain.NewPruner(bc, bc.Tracker(), &chain.PruneConfig{Retain: 2, Enabled: true}, nil)
	stats, err := pruner.Run()
	if err != nil {
		t.Fatal(err)
	}
	if stats.Deleted == 0 {
		t.Fatal("nothing was pruned")
	}

	// Code and current storage must both survive: they are reachable from the
	// head, whatever happened to the intermediate states.
	statedb, err := bc.State()
	if err != nil {
		t.Fatal(err)
	}
	if len(statedb.GetCode(contractAddr)) != len(runtime) {
		t.Fatalf("contract code was pruned: %d bytes remain", len(statedb.GetCode(contractAddr)))
	}
	if got := statedb.GetState(contractAddr, common.Hash{}); got != common.BytesToHash([]byte{9}) {
		t.Fatalf("contract storage after pruning = %s, want 9", got)
	}
}

func TestChainKeepsWorkingAfterPruning(t *testing.T) {
	keys, addrs := testKeys(t, 2)
	bc, engine := newPruneTestChain(t, keys, addrs)
	builder := miner.NewBuilder(bc, engine, keys[0])

	recipient := common.MustHexToAddress("0x9999999999999999999999999999999999999999")
	for i := 0; i < 10; i++ {
		tx := signTx(t, keys[1], uint64(i), &recipient, big.NewInt(10), 21000, nil)
		if _, err := builder.Commit(core.Transactions{tx}); err != nil {
			t.Fatal(err)
		}
	}

	pruner := chain.NewPruner(bc, bc.Tracker(), &chain.PruneConfig{Retain: 3, Enabled: true}, nil)
	if _, err := pruner.Run(); err != nil {
		t.Fatal(err)
	}

	// The point of the retention window: the chain must still extend normally.
	for i := 10; i < 15; i++ {
		tx := signTx(t, keys[1], uint64(i), &recipient, big.NewInt(10), 21000, nil)
		if _, err := builder.Commit(core.Transactions{tx}); err != nil {
			t.Fatalf("block production broke after pruning: %v", err)
		}
	}
	statedb, err := bc.State()
	if err != nil {
		t.Fatal(err)
	}
	if got := statedb.GetBalance(recipient); got.Cmp(big.NewInt(150)) != 0 {
		t.Fatalf("balance after pruning and further blocks = %s, want 150", got)
	}
}

func TestConcurrentPruneIsRejected(t *testing.T) {
	keys, addrs := testKeys(t, 2)
	bc, _ := newTestChain(t, keys, addrs)
	pruner := chain.NewPruner(bc, bc.Tracker(), chain.DefaultPruneConfig(), nil)

	// Two sweeps at once would each see the other's writes as garbage.
	started := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		close(started)
		_, err := pruner.Run()
		done <- err
	}()
	<-started

	// The second attempt either finds the first running, or the first has
	// already finished; both are fine, a silent overlap is not.
	if _, err := pruner.Run(); err != nil && !errors.Is(err, chain.ErrPruneInProgress) {
		t.Fatalf("got %v, want ErrPruneInProgress or success", err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

// newStandaloneRegistry returns a registry over empty state, for tests that
// exercise selection logic without building a chain.
func newStandaloneRegistry(t *testing.T) *staking.Registry {
	t.Helper()
	sdb, err := state.New(common.Hash{}, db.NewMemoryDB())
	if err != nil {
		t.Fatal(err)
	}
	return staking.NewRegistry(sdb)
}
