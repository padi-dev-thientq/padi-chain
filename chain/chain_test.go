package chain_test

import (
	"errors"
	"math/big"
	"testing"
	"time"

	"padi-chain/chain"
	"padi-chain/common"
	"padi-chain/consensus"
	"padi-chain/core"
	"padi-chain/crypto/secp256k1"
	"padi-chain/db"
	"padi-chain/evm"
	"padi-chain/miner"
)

var chainID = big.NewInt(1337)

// testKeys returns deterministic keys and their addresses.
func testKeys(t *testing.T, n int) ([]*secp256k1.PrivateKey, []common.Address) {
	t.Helper()
	var keys []*secp256k1.PrivateKey
	var addrs []common.Address
	for i := 1; i <= n; i++ {
		key, err := secp256k1.PrivateKeyFromBytes(common.LeftPadBytes([]byte{byte(i)}, 32))
		if err != nil {
			t.Fatal(err)
		}
		keys = append(keys, key)
		addrs = append(addrs, common.BytesToAddress(common.Keccak256(key.PublicKey().Bytes()).Bytes()[12:]))
	}
	return keys, addrs
}

// newTestChain builds a chain whose sole validator is keys[0], with every
// address pre-funded.
func newTestChain(t *testing.T, keys []*secp256k1.PrivateKey, addrs []common.Address) (*chain.BlockChain, *consensus.PoA) {
	t.Helper()

	genesis := chain.DefaultGenesis(chainID, addrs[:1])
	genesis.BlockPeriod = 1
	for _, addr := range addrs {
		genesis.Alloc[addr] = chain.GenesisAccount{
			Balance: new(big.Int).Lsh(big.NewInt(1), 80),
		}
	}

	engine, err := consensus.NewPoA(genesis.Validators, genesis.BlockPeriod)
	if err != nil {
		t.Fatal(err)
	}
	// Run the clock ahead so freshly sealed blocks are never "in the future".
	engine.SetClock(func() time.Time { return time.Now().Add(time.Hour) })

	bc, err := chain.NewBlockChain(db.NewMemoryDB(), genesis, engine)
	if err != nil {
		t.Fatal(err)
	}
	return bc, engine
}

func signTx(t *testing.T, key *secp256k1.PrivateKey, nonce uint64, to *common.Address, value *big.Int, gas uint64, data []byte) *core.Transaction {
	t.Helper()
	signer := core.NewSigner(chainID)
	tx, err := signer.SignTx(core.NewTx(&core.DynamicFeeTx{
		Nonce:     nonce,
		GasTipCap: big.NewInt(1_000_000_000),
		GasFeeCap: big.NewInt(10_000_000_000),
		Gas:       gas,
		To:        to,
		Value:     value,
		Data:      data,
	}), key)
	if err != nil {
		t.Fatal(err)
	}
	return tx
}

func TestGenesisIsDeterministic(t *testing.T) {
	_, addrs := testKeys(t, 2)
	genesis := chain.DefaultGenesis(chainID, addrs[:1])
	genesis.Alloc[addrs[1]] = chain.GenesisAccount{Balance: big.NewInt(1000)}

	first, err := genesis.ToBlock(db.NewMemoryDB())
	if err != nil {
		t.Fatal(err)
	}
	second, err := genesis.ToBlock(db.NewMemoryDB())
	if err != nil {
		t.Fatal(err)
	}
	if first.Hash() != second.Hash() {
		t.Fatalf("genesis is not deterministic: %s vs %s", first.Hash(), second.Hash())
	}
	if first.NumberU64() != 0 || !first.ParentHash().IsZero() {
		t.Fatal("genesis must be block 0 with no parent")
	}
}

func TestGenesisAllocIsInState(t *testing.T) {
	keys, addrs := testKeys(t, 2)
	bc, _ := newTestChain(t, keys, addrs)

	statedb, err := bc.State()
	if err != nil {
		t.Fatal(err)
	}
	want := new(big.Int).Lsh(big.NewInt(1), 80)
	if got := statedb.GetBalance(addrs[1]); got.Cmp(want) != 0 {
		t.Fatalf("genesis balance = %s, want %s", got, want)
	}
}

func TestGenesisMismatchIsRejected(t *testing.T) {
	keys, addrs := testKeys(t, 2)
	store := db.NewMemoryDB()

	genesis := chain.DefaultGenesis(chainID, addrs[:1])
	genesis.Alloc[addrs[0]] = chain.GenesisAccount{Balance: big.NewInt(1)}
	engine, _ := consensus.NewPoA(genesis.Validators, 1)
	if _, err := chain.NewBlockChain(store, genesis, engine); err != nil {
		t.Fatal(err)
	}

	// Reopening with a different allocation must be refused rather than
	// silently producing a chain that disagrees with its peers.
	other := chain.DefaultGenesis(chainID, addrs[:1])
	other.Alloc[addrs[0]] = chain.GenesisAccount{Balance: big.NewInt(2)}
	if _, err := chain.NewBlockChain(store, other, engine); !errors.Is(err, chain.ErrGenesisMismatch) {
		t.Fatalf("got %v, want ErrGenesisMismatch", err)
	}
	_ = keys
}

func TestMineEmptyBlocks(t *testing.T) {
	keys, addrs := testKeys(t, 1)
	bc, engine := newTestChain(t, keys, addrs)
	builder := miner.NewBuilder(bc, engine, keys[0])

	for i := 1; i <= 5; i++ {
		result, err := builder.Commit(nil)
		if err != nil {
			t.Fatalf("block %d: %v", i, err)
		}
		if result.Block.NumberU64() != uint64(i) {
			t.Fatalf("built block %d, want %d", result.Block.NumberU64(), i)
		}
	}
	if got := bc.CurrentBlock().NumberU64(); got != 5 {
		t.Fatalf("head is at %d, want 5", got)
	}
	// Every block must be reachable by number and by hash.
	for i := uint64(0); i <= 5; i++ {
		block := bc.GetBlockByNumber(i)
		if block == nil {
			t.Fatalf("block %d is missing", i)
		}
		if bc.GetBlockByHash(block.Hash()) == nil {
			t.Fatalf("block %d is not indexed by hash", i)
		}
	}
}

func TestValueTransfer(t *testing.T) {
	keys, addrs := testKeys(t, 2)
	bc, engine := newTestChain(t, keys, addrs)
	builder := miner.NewBuilder(bc, engine, keys[0])

	recipient := common.MustHexToAddress("0x9999999999999999999999999999999999999999")
	amount := big.NewInt(1_000_000)
	tx := signTx(t, keys[1], 0, &recipient, amount, 21000, nil)

	result, err := builder.Commit(core.Transactions{tx})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Included) != 1 {
		t.Fatalf("included %d transactions, rejected %v", len(result.Included), result.Rejected)
	}
	if result.Receipts[0].Status != core.ReceiptStatusSuccessful {
		t.Fatal("transfer failed")
	}

	statedb, err := bc.State()
	if err != nil {
		t.Fatal(err)
	}
	if got := statedb.GetBalance(recipient); got.Cmp(amount) != 0 {
		t.Fatalf("recipient balance = %s, want %s", got, amount)
	}
	if statedb.GetNonce(addrs[1]) != 1 {
		t.Fatal("the sender's nonce was not incremented")
	}
	// The proposer collected the priority fee.
	if statedb.GetBalance(addrs[0]).Sign() == 0 {
		t.Fatal("the proposer received no fees")
	}
}

func TestBaseFeeIsBurned(t *testing.T) {
	keys, addrs := testKeys(t, 2)
	bc, engine := newTestChain(t, keys, addrs)
	builder := miner.NewBuilder(bc, engine, keys[0])

	before, _ := bc.State()
	totalBefore := new(big.Int)
	for _, a := range addrs {
		totalBefore.Add(totalBefore, before.GetBalance(a))
	}

	recipient := common.MustHexToAddress("0x9999999999999999999999999999999999999999")
	tx := signTx(t, keys[1], 0, &recipient, big.NewInt(1000), 21000, nil)
	if _, err := builder.Commit(core.Transactions{tx}); err != nil {
		t.Fatal(err)
	}

	after, _ := bc.State()
	totalAfter := new(big.Int)
	for _, a := range addrs {
		totalAfter.Add(totalAfter, after.GetBalance(a))
	}
	totalAfter.Add(totalAfter, after.GetBalance(recipient))

	// Supply must fall by exactly the base fee times the gas used.
	burned := new(big.Int).Sub(totalBefore, totalAfter)
	expectedBurn := new(big.Int).Mul(bc.CurrentBlock().BaseFee(), big.NewInt(21000))
	if burned.Cmp(expectedBurn) != 0 {
		t.Fatalf("burned %s, want %s", burned, expectedBurn)
	}
}

func TestContractDeployAndCall(t *testing.T) {
	keys, addrs := testKeys(t, 2)
	bc, engine := newTestChain(t, keys, addrs)
	builder := miner.NewBuilder(bc, engine, keys[0])

	// Runtime: store calldata word 0 into slot 0, then return it.
	runtime := []byte{
		byte(evm.PUSH1), 0x00, byte(evm.CALLDATALOAD), // value
		byte(evm.PUSH1), 0x00, byte(evm.SSTORE), // slot 0 = value
		byte(evm.PUSH1), 0x00, byte(evm.SLOAD),
		byte(evm.PUSH1), 0x00, byte(evm.MSTORE),
		byte(evm.PUSH1), 0x20, byte(evm.PUSH1), 0x00, byte(evm.RETURN),
	}
	// Init code copies the runtime out of its own code and returns it.
	initCode := []byte{
		byte(evm.PUSH1), byte(len(runtime)),
		byte(evm.PUSH1), 12, // offset of the runtime within this code
		byte(evm.PUSH1), 0x00,
		byte(evm.CODECOPY),
		byte(evm.PUSH1), byte(len(runtime)),
		byte(evm.PUSH1), 0x00,
		byte(evm.RETURN),
	}
	initCode = append(initCode, runtime...)

	deploy := signTx(t, keys[1], 0, nil, new(big.Int), 500_000, initCode)
	result, err := builder.Commit(core.Transactions{deploy})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Receipts) != 1 || result.Receipts[0].Status != core.ReceiptStatusSuccessful {
		t.Fatalf("deployment failed: %+v, rejected: %v", result.Receipts, result.Rejected)
	}
	contractAddr := result.Receipts[0].ContractAddress
	if contractAddr.IsZero() {
		t.Fatal("no contract address in the receipt")
	}

	statedb, _ := bc.State()
	if len(statedb.GetCode(contractAddr)) != len(runtime) {
		t.Fatalf("deployed code is %d bytes, want %d", len(statedb.GetCode(contractAddr)), len(runtime))
	}

	// Call it with a value to store.
	value := common.LeftPadBytes([]byte{0x2a}, 32)
	call := signTx(t, keys[1], 1, &contractAddr, new(big.Int), 200_000, value)
	result, err = builder.Commit(core.Transactions{call})
	if err != nil {
		t.Fatal(err)
	}
	if result.Receipts[0].Status != core.ReceiptStatusSuccessful {
		t.Fatal("the contract call failed")
	}

	statedb, _ = bc.State()
	if got := statedb.GetState(contractAddr, common.Hash{}); got != common.BytesToHash([]byte{0x2a}) {
		t.Fatalf("contract storage = %s, want 0x2a", got)
	}
	_ = addrs
}

func TestReceiptsAndTransactionLookup(t *testing.T) {
	keys, addrs := testKeys(t, 2)
	bc, engine := newTestChain(t, keys, addrs)
	builder := miner.NewBuilder(bc, engine, keys[0])

	recipient := common.MustHexToAddress("0x9999999999999999999999999999999999999999")
	var txs core.Transactions
	for i := 0; i < 3; i++ {
		txs = append(txs, signTx(t, keys[1], uint64(i), &recipient, big.NewInt(100), 21000, nil))
	}
	result, err := builder.Commit(txs)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Included) != 3 {
		t.Fatalf("included %d of 3 transactions: %v", len(result.Included), result.Rejected)
	}

	block := bc.CurrentBlock()
	receipts := bc.GetReceipts(block.Hash())
	if len(receipts) != 3 {
		t.Fatalf("stored %d receipts, want 3", len(receipts))
	}
	// Cumulative gas must be monotonic and each receipt must know its own use.
	for i, r := range receipts {
		if r.GasUsed != 21000 {
			t.Errorf("receipt %d used %d gas, want 21000", i, r.GasUsed)
		}
		if r.CumulativeGasUsed != uint64(i+1)*21000 {
			t.Errorf("receipt %d cumulative gas = %d", i, r.CumulativeGasUsed)
		}
		if r.BlockHash != block.Hash() {
			t.Errorf("receipt %d has the wrong block hash", i)
		}
	}

	for i, tx := range txs {
		found, entry := bc.GetTransaction(tx.Hash())
		if found == nil {
			t.Fatalf("transaction %d is not indexed", i)
		}
		if entry.Index != uint64(i) || entry.BlockHash != block.Hash() {
			t.Errorf("transaction %d indexed at %+v", i, entry)
		}
	}
}

func TestBlockGasLimitBoundsInclusion(t *testing.T) {
	keys, addrs := testKeys(t, 2)
	bc, engine := newTestChain(t, keys, addrs)
	builder := miner.NewBuilder(bc, engine, keys[0])

	limit := bc.CurrentBlock().GasLimit()
	recipient := common.MustHexToAddress("0x9999999999999999999999999999999999999999")

	// A transaction that reserves more gas than the whole block can never be
	// included, however cheap its actual execution would be.
	oversized := signTx(t, keys[1], 0, &recipient, big.NewInt(1), limit+1, nil)
	normal := signTx(t, keys[1], 0, &recipient, big.NewInt(1), 21000, nil)

	result, err := builder.Commit(core.Transactions{oversized, normal})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Included) != 1 || result.Included[0].Hash() != normal.Hash() {
		t.Fatalf("included %d transactions, want only the normal one", len(result.Included))
	}
	if len(result.Rejected) != 1 || result.Rejected[0].Tx.Hash() != oversized.Hash() {
		t.Fatalf("expected the oversized transaction to be rejected, got %v", result.Rejected)
	}
	head := bc.CurrentBlock()
	if head.GasUsed() > head.GasLimit() {
		t.Fatal("the block exceeded its own gas limit")
	}
}

func TestInvalidTransactionIsSkippedNotFatal(t *testing.T) {
	keys, addrs := testKeys(t, 2)
	bc, engine := newTestChain(t, keys, addrs)
	builder := miner.NewBuilder(bc, engine, keys[0])

	recipient := common.MustHexToAddress("0x9999999999999999999999999999999999999999")
	good := signTx(t, keys[1], 0, &recipient, big.NewInt(1), 21000, nil)
	// A transaction with a nonce far in the future can never apply now.
	future := signTx(t, keys[1], 99, &recipient, big.NewInt(1), 21000, nil)

	result, err := builder.Commit(core.Transactions{future, good})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Included) != 1 || result.Included[0].Hash() != good.Hash() {
		t.Fatalf("expected only the valid transaction to be included, got %d", len(result.Included))
	}
	if len(result.Rejected) != 1 {
		t.Fatalf("expected the future-nonce transaction to be rejected, got %v", result.Rejected)
	}
}

func TestBlockValidationRejectsTampering(t *testing.T) {
	keys, addrs := testKeys(t, 1)
	bc, engine := newTestChain(t, keys, addrs)
	builder := miner.NewBuilder(bc, engine, keys[0])

	result, err := builder.BuildBlock(nil)
	if err != nil {
		t.Fatal(err)
	}

	// A block whose state root has been altered must not be accepted.
	header := result.Block.Header()
	header.StateRoot = common.Keccak256([]byte("a lie"))
	tampered := core.NewBlockWithHeader(header)
	if err := bc.InsertBlock(tampered); err == nil {
		t.Fatal("a block with a forged state root was accepted")
	}

	// Neither must one whose seal was stripped.
	header = result.Block.Header()
	header.ProposerSeal = nil
	unsealed := core.NewBlockWithHeader(header)
	if err := bc.InsertBlock(unsealed); err == nil {
		t.Fatal("an unsealed block was accepted")
	}

	// The genuine block still inserts.
	if err := bc.InsertBlock(result.Block); err != nil {
		t.Fatalf("the valid block was rejected: %v", err)
	}
}

func TestUnauthorizedProposerRejected(t *testing.T) {
	keys, addrs := testKeys(t, 2)
	bc, engine := newTestChain(t, keys, addrs)

	// keys[1] is not in the validator set.
	outsider := miner.NewBuilder(bc, engine, keys[1])
	if _, err := outsider.BuildBlock(nil); !errors.Is(err, miner.ErrNotOurTurn) {
		t.Fatalf("got %v, want ErrNotOurTurn", err)
	}
}

func TestRoundRobinProposers(t *testing.T) {
	keys, addrs := testKeys(t, 3)

	genesis := chain.DefaultGenesis(chainID, addrs)
	genesis.BlockPeriod = 1
	for _, addr := range addrs {
		genesis.Alloc[addr] = chain.GenesisAccount{Balance: new(big.Int).Lsh(big.NewInt(1), 80)}
	}
	engine, err := consensus.NewPoA(genesis.Validators, genesis.BlockPeriod)
	if err != nil {
		t.Fatal(err)
	}
	engine.SetClock(func() time.Time { return time.Now().Add(time.Hour) })

	bc, err := chain.NewBlockChain(db.NewMemoryDB(), genesis, engine)
	if err != nil {
		t.Fatal(err)
	}

	// Each height has exactly one authorized proposer; the others must fail.
	for height := uint64(1); height <= 6; height++ {
		proposer, err := engine.ProposerAt(height)
		if err != nil {
			t.Fatal(err)
		}
		var scheduled *secp256k1.PrivateKey
		for i, key := range keys {
			if addrs[i] == proposer {
				scheduled = key
				continue
			}
			builder := miner.NewBuilder(bc, engine, key)
			if _, err := builder.BuildBlock(nil); !errors.Is(err, miner.ErrNotOurTurn) {
				t.Fatalf("height %d: %s built a block out of turn (%v)", height, addrs[i], err)
			}
		}
		if scheduled == nil {
			t.Fatalf("height %d: the scheduled proposer %s is not one of the test keys", height, proposer)
		}
		if _, err := miner.NewBuilder(bc, engine, scheduled).Commit(nil); err != nil {
			t.Fatalf("height %d: the scheduled proposer failed: %v", height, err)
		}
	}
	if bc.CurrentBlock().NumberU64() != 6 {
		t.Fatalf("chain height = %d, want 6", bc.CurrentBlock().NumberU64())
	}
}

func TestChainReorg(t *testing.T) {
	keys, addrs := testKeys(t, 2)
	recipient := common.MustHexToAddress("0x9999999999999999999999999999999999999999")

	// Build two independent chains from the same genesis, then feed the
	// longer one's blocks to the shorter one's node.
	buildChain := func(t *testing.T) (*chain.BlockChain, *miner.Builder) {
		bc, engine := newTestChain(t, keys, addrs)
		return bc, miner.NewBuilder(bc, engine, keys[0])
	}

	nodeA, minerA := buildChain(t)
	nodeB, minerB := buildChain(t)

	// A mines two blocks, one of them carrying a transaction.
	tx := signTx(t, keys[1], 0, &recipient, big.NewInt(500), 21000, nil)
	if _, err := minerA.Commit(core.Transactions{tx}); err != nil {
		t.Fatal(err)
	}
	if _, err := minerA.Commit(nil); err != nil {
		t.Fatal(err)
	}

	// B mines three empty blocks, so its chain is longer.
	var bBlocks core.Blocks
	for i := 0; i < 3; i++ {
		result, err := minerB.Commit(nil)
		if err != nil {
			t.Fatal(err)
		}
		bBlocks = append(bBlocks, result.Block)
	}

	// A hears about B's chain and must switch to it.
	events := make(chan chain.ChainEvent, 8)
	nodeA.Subscribe(events)

	if _, err := nodeA.InsertChain(bBlocks); err != nil {
		t.Fatalf("importing the longer chain failed: %v", err)
	}
	if got := nodeA.CurrentBlock().Hash(); got != nodeB.CurrentBlock().Hash() {
		t.Fatalf("head is %s, want B's head %s", got, nodeB.CurrentBlock().Hash())
	}
	if got := nodeA.CurrentBlock().NumberU64(); got != 3 {
		t.Fatalf("head is at %d, want 3", got)
	}

	// The reorganised-out transaction must no longer resolve on the canonical
	// chain, and the canonical index must point at B's blocks.
	if found, _ := nodeA.GetTransaction(tx.Hash()); found != nil {
		t.Fatal("a transaction from the abandoned branch is still indexed")
	}
	for i := uint64(1); i <= 3; i++ {
		if got := nodeA.GetBlockByNumber(i).Hash(); got != bBlocks[i-1].Hash() {
			t.Fatalf("canonical block %d is %s, want %s", i, got, bBlocks[i-1].Hash())
		}
	}

	// The reorg must have been reported, listing the abandoned blocks.
	var sawReorg bool
	for len(events) > 0 {
		event := <-events
		if len(event.Reverted) > 0 {
			sawReorg = true
		}
	}
	if !sawReorg {
		t.Fatal("no reorg event was published")
	}

	// State must follow the new chain: the reverted transfer is undone.
	statedb, err := nodeA.State()
	if err != nil {
		t.Fatal(err)
	}
	if got := statedb.GetBalance(recipient); got.Sign() != 0 {
		t.Fatalf("the reverted transfer is still reflected in state: %s", got)
	}
}

func TestShorterChainDoesNotReorg(t *testing.T) {
	keys, addrs := testKeys(t, 2)
	nodeA, engineA := newTestChain(t, keys, addrs)
	minerA := miner.NewBuilder(nodeA, engineA, keys[0])

	nodeB, engineB := newTestChain(t, keys, addrs)
	minerB := miner.NewBuilder(nodeB, engineB, keys[0])

	for i := 0; i < 3; i++ {
		if _, err := minerA.Commit(nil); err != nil {
			t.Fatal(err)
		}
	}
	var bBlocks core.Blocks
	for i := 0; i < 2; i++ {
		result, err := minerB.Commit(nil)
		if err != nil {
			t.Fatal(err)
		}
		bBlocks = append(bBlocks, result.Block)
	}

	headBefore := nodeA.CurrentBlock().Hash()
	if _, err := nodeA.InsertChain(bBlocks); err != nil {
		t.Fatal(err)
	}
	if nodeA.CurrentBlock().Hash() != headBefore {
		t.Fatal("a shorter branch must not become canonical")
	}
	// The blocks are still stored, just not canonical.
	if !nodeA.HasBlock(bBlocks[0].Hash()) {
		t.Fatal("side-chain blocks should still be retained")
	}
}

func TestUnknownParentIsRejected(t *testing.T) {
	keys, addrs := testKeys(t, 1)
	bc, engine := newTestChain(t, keys, addrs)

	orphanHeader := &core.Header{
		ParentHash: common.Keccak256([]byte("nonexistent parent")),
		Number:     big.NewInt(1),
		GasLimit:   30_000_000,
		BaseFee:    big.NewInt(1_000_000_000),
	}
	orphan := core.NewBlockWithHeader(orphanHeader)
	if err := bc.InsertBlock(orphan); !errors.Is(err, chain.ErrUnknownAncestor) {
		t.Fatalf("got %v, want ErrUnknownAncestor", err)
	}
	_ = engine
}

func TestDuplicateBlockIsIgnored(t *testing.T) {
	keys, addrs := testKeys(t, 1)
	bc, engine := newTestChain(t, keys, addrs)
	builder := miner.NewBuilder(bc, engine, keys[0])

	result, err := builder.Commit(nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := bc.InsertBlock(result.Block); !errors.Is(err, chain.ErrKnownBlock) {
		t.Fatalf("got %v, want ErrKnownBlock", err)
	}
}

func TestBaseFeeRespondsToUsage(t *testing.T) {
	keys, addrs := testKeys(t, 2)
	bc, engine := newTestChain(t, keys, addrs)
	builder := miner.NewBuilder(bc, engine, keys[0])

	// An empty block is well below the gas target, so the base fee must fall
	// (or hold at the floor).
	start := bc.CurrentBlock().BaseFee()
	if _, err := builder.Commit(nil); err != nil {
		t.Fatal(err)
	}
	if bc.CurrentBlock().BaseFee().Cmp(start) > 0 {
		t.Fatal("the base fee rose after an empty block")
	}

	// Fill a block past the target and the fee must rise.
	config := bc.Config()
	parent := bc.CurrentBlock().Header()
	parent.GasUsed = parent.GasLimit // completely full
	raised := config.CalcBaseFee(parent)
	if raised.Cmp(parent.BaseFee) <= 0 {
		t.Fatalf("a full block must raise the base fee: %s -> %s", parent.BaseFee, raised)
	}
	_ = addrs
}

func TestChainPersistsAcrossRestart(t *testing.T) {
	keys, addrs := testKeys(t, 2)
	store := db.NewMemoryDB()

	genesis := chain.DefaultGenesis(chainID, addrs[:1])
	genesis.BlockPeriod = 1
	for _, addr := range addrs {
		genesis.Alloc[addr] = chain.GenesisAccount{Balance: new(big.Int).Lsh(big.NewInt(1), 80)}
	}
	engine, _ := consensus.NewPoA(genesis.Validators, genesis.BlockPeriod)
	engine.SetClock(func() time.Time { return time.Now().Add(time.Hour) })

	bc, err := chain.NewBlockChain(store, genesis, engine)
	if err != nil {
		t.Fatal(err)
	}
	builder := miner.NewBuilder(bc, engine, keys[0])

	recipient := common.MustHexToAddress("0x9999999999999999999999999999999999999999")
	tx := signTx(t, keys[1], 0, &recipient, big.NewInt(4242), 21000, nil)
	if _, err := builder.Commit(core.Transactions{tx}); err != nil {
		t.Fatal(err)
	}
	if _, err := builder.Commit(nil); err != nil {
		t.Fatal(err)
	}
	headHash := bc.CurrentBlock().Hash()

	// Reopen the same store: the chain, its state and its indexes must all
	// still be there.
	reopened, err := chain.NewBlockChain(store, genesis, engine)
	if err != nil {
		t.Fatal(err)
	}
	if reopened.CurrentBlock().Hash() != headHash {
		t.Fatalf("head after restart = %s, want %s", reopened.CurrentBlock().Hash(), headHash)
	}
	statedb, err := reopened.State()
	if err != nil {
		t.Fatal(err)
	}
	if got := statedb.GetBalance(recipient); got.Cmp(big.NewInt(4242)) != 0 {
		t.Fatalf("balance after restart = %s, want 4242", got)
	}
	if found, _ := reopened.GetTransaction(tx.Hash()); found == nil {
		t.Fatal("the transaction index did not survive the restart")
	}
}
