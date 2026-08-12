package chain_test

import (
	"math/big"
	"testing"

	"layer1/chain"
	"layer1/common"
	"layer1/core"
	"layer1/crypto/secp256k1"
	"layer1/miner"
	"layer1/processor"
	"layer1/rlp"
	"layer1/staking"
)

// mineTo extends the chain to a target height. The test clock runs ahead of
// real time, so which round is open shifts as blocks are produced; rather than
// predict it, every builder is offered the turn and whichever one is entitled
// to it takes it.
func mineTo(t *testing.T, bc *chain.BlockChain, builders map[common.Address]*miner.Builder, clock *testClock, target uint64, txs map[uint64]core.Transactions) {
	t.Helper()
	for bc.CurrentBlock().NumberU64() < target {
		next := bc.CurrentBlock().NumberU64() + 1
		clock.advance()

		proposer, err := bc.Engine().ProposerAt(next)
		if err != nil {
			t.Fatal(err)
		}
		builder, ok := builders[proposer]
		if !ok {
			t.Fatalf("block %d belongs to %s, which no test builder holds a key for", next, proposer)
		}
		if _, err := builder.Commit(txs[next]); err != nil {
			t.Fatalf("block %d: %v", next, err)
		}
	}
}

// depositTx builds a transaction that stakes for the sender.
func depositTx(t *testing.T, key *secp256k1.PrivateKey, nonce uint64, withdrawal common.Address, amount *big.Int) *core.Transaction {
	t.Helper()
	data := append([]byte{processor.OpDeposit}, withdrawal[:]...)
	to := staking.StakingAddress
	return signTxData(t, key, nonce, &to, amount, 200_000, data)
}

func signTxData(t *testing.T, key *secp256k1.PrivateKey, nonce uint64, to *common.Address, value *big.Int, gas uint64, data []byte) *core.Transaction {
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

func TestGenesisValidatorsAreStaked(t *testing.T) {
	keys, addrs := testKeys(t, 2)
	bc, _, _ := newControlledChain(t, keys, addrs)

	registry, err := bc.StakingRegistry()
	if err != nil {
		t.Fatal(err)
	}
	if registry.Count() != 1 {
		t.Fatalf("%d validators registered at genesis, want 1", registry.Count())
	}
	v, err := registry.ByAddress(addrs[0])
	if err != nil {
		t.Fatal(err)
	}
	if v.Status != staking.StatusActive {
		t.Fatalf("genesis validator status = %s, want active", v.Status)
	}
	if v.Balance.Cmp(staking.MinDeposit) != 0 {
		t.Fatalf("genesis validator stake = %s, want %s", v.Balance, staking.MinDeposit)
	}
	// It must be the set that governs the first epoch.
	set, err := bc.ValidatorsAt(1)
	if err != nil {
		t.Fatal(err)
	}
	if len(set) != 1 || set[0] != addrs[0] {
		t.Fatalf("validator set at block 1 = %v", set)
	}
}

func TestDepositActivatesAValidator(t *testing.T) {
	keys, addrs := testKeys(t, 2)
	bc, engine, clock := newControlledChain(t, keys, addrs)
	builders := map[common.Address]*miner.Builder{
		addrs[0]: miner.NewBuilder(bc, engine, keys[0]),
		addrs[1]: miner.NewBuilder(bc, engine, keys[1]),
	}

	// The second key stakes for itself.
	deposit := depositTx(t, keys[1], 0, addrs[1], staking.MinDeposit)
	mineTo(t, bc, builders, clock, 1, map[uint64]core.Transactions{1: {deposit}})

	registry, err := bc.StakingRegistry()
	if err != nil {
		t.Fatal(err)
	}
	v, err := registry.ByAddress(addrs[1])
	if err != nil {
		t.Fatalf("the deposit did not register a validator: %v", err)
	}
	if v.Status != staking.StatusPending {
		t.Fatalf("status after deposit = %s, want pending", v.Status)
	}
	// A deposit does not put anyone in the set immediately: the set a block is
	// verified against has to be settled before that block exists.
	if set, _ := bc.ValidatorsAt(2); len(set) != 1 {
		t.Fatalf("the depositor joined the set immediately: %v", set)
	}

	// Cross the epoch boundary, which is where activation happens.
	mineTo(t, bc, builders, clock, staking.EpochLength, nil)

	registry, _ = bc.StakingRegistry()
	v, _ = registry.ByAddress(addrs[1])
	if v.Status != staking.StatusActive {
		t.Fatalf("status after the epoch boundary = %s, want active", v.Status)
	}

	// And it governs the epoch its activation named, once the chain has
	// reached it. The set for an epoch is read from the state at the end of
	// the previous one, so it cannot be answered before those blocks exist —
	// which is exactly why activation is scheduled an epoch ahead.
	activeAt := staking.EpochStart(v.ActivationEpoch)
	mineTo(t, bc, builders, clock, activeAt, nil)

	set, err := bc.ValidatorsAt(activeAt)
	if err != nil {
		t.Fatal(err)
	}
	if len(set) != 2 {
		t.Fatalf("validator set at block %d = %v, want both validators", activeAt, set)
	}
}

func TestNewValidatorProposesBlocks(t *testing.T) {
	keys, addrs := testKeys(t, 2)
	bc, engine, clock := newControlledChain(t, keys, addrs)
	builders := map[common.Address]*miner.Builder{
		addrs[0]: miner.NewBuilder(bc, engine, keys[0]),
		addrs[1]: miner.NewBuilder(bc, engine, keys[1]),
	}

	deposit := depositTx(t, keys[1], 0, addrs[1], staking.MinDeposit)
	mineTo(t, bc, builders, clock, 1, map[uint64]core.Transactions{1: {deposit}})

	// Two epochs on, the new validator is in the set and takes its turns.
	mineTo(t, bc, builders, clock, 2*staking.EpochLength+4, nil)

	proposers := map[common.Address]int{}
	for number := uint64(2*staking.EpochLength + 1); number <= 2*staking.EpochLength+4; number++ {
		block := bc.GetBlockByNumber(number)
		if block == nil {
			t.Fatalf("block %d is missing", number)
		}
		proposers[block.Coinbase()]++
	}
	if proposers[addrs[1]] == 0 {
		t.Fatalf("the staked validator never proposed: %v", proposers)
	}
	if proposers[addrs[0]] == 0 {
		t.Fatalf("the genesis validator stopped proposing: %v", proposers)
	}
}

func TestExitRemovesAValidator(t *testing.T) {
	keys, addrs := testKeys(t, 2)
	bc, engine, clock := newControlledChain(t, keys, addrs)
	builders := map[common.Address]*miner.Builder{
		addrs[0]: miner.NewBuilder(bc, engine, keys[0]),
		addrs[1]: miner.NewBuilder(bc, engine, keys[1]),
	}

	deposit := depositTx(t, keys[1], 0, addrs[1], staking.MinDeposit)
	mineTo(t, bc, builders, clock, 1, map[uint64]core.Transactions{1: {deposit}})
	mineTo(t, bc, builders, clock, staking.EpochLength+1, nil)

	// Now leave.
	to := staking.StakingAddress
	exit := signTxData(t, keys[1], 1, &to, new(big.Int), 200_000, []byte{processor.OpExit})
	next := bc.CurrentBlock().NumberU64() + 1
	mineTo(t, bc, builders, clock, next, map[uint64]core.Transactions{next: {exit}})

	registry, _ := bc.StakingRegistry()
	v, err := registry.ByAddress(addrs[1])
	if err != nil {
		t.Fatal(err)
	}
	if v.Status != staking.StatusExiting {
		t.Fatalf("status after requesting exit = %s, want exiting", v.Status)
	}
	// The stake stays locked well past the exit, so evidence that surfaces
	// later can still be acted on.
	if v.WithdrawableEpoch <= v.ExitEpoch {
		t.Fatal("withdrawal is not delayed past the exit")
	}
	if v.IsActiveAt(v.ExitEpoch) {
		t.Fatal("a validator is still in the set at its exit epoch")
	}
}

func TestSlashingThroughEvidence(t *testing.T) {
	keys, addrs := testKeys(t, 2)
	bc, engine, clock := newControlledChain(t, keys, addrs)
	builders := map[common.Address]*miner.Builder{
		addrs[0]: miner.NewBuilder(bc, engine, keys[0]),
		addrs[1]: miner.NewBuilder(bc, engine, keys[1]),
	}

	deposit := depositTx(t, keys[1], 0, addrs[1], staking.MinDeposit)
	mineTo(t, bc, builders, clock, 1, map[uint64]core.Transactions{1: {deposit}})
	mineTo(t, bc, builders, clock, staking.EpochLength, nil)

	// The staked validator signs two different blocks at the same height.
	first, err := core.SignAttestation(keys[1], chainID, 7, common.Keccak256([]byte("block A")))
	if err != nil {
		t.Fatal(err)
	}
	second, err := core.SignAttestation(keys[1], chainID, 7, common.Keccak256([]byte("block B")))
	if err != nil {
		t.Fatal(err)
	}
	evidence := &core.Equivocation{Validator: addrs[1], Number: 7, First: first, Second: second}
	encoded, err := rlp.Encode(evidence)
	if err != nil {
		t.Fatal(err)
	}

	// Anyone may report it; the chain re-derives the proof from the signatures.
	to := staking.StakingAddress
	report := signTxData(t, keys[0], 0, &to, new(big.Int), 300_000, append([]byte{processor.OpSlash}, encoded...))
	next := bc.CurrentBlock().NumberU64() + 1
	mineTo(t, bc, builders, clock, next, map[uint64]core.Transactions{next: {report}})

	registry, _ := bc.StakingRegistry()
	v, err := registry.ByAddress(addrs[1])
	if err != nil {
		t.Fatal(err)
	}
	if v.Status != staking.StatusSlashed {
		t.Fatalf("status after slashing = %s, want slashed", v.Status)
	}
	if v.Balance.Cmp(staking.MinDeposit) >= 0 {
		t.Fatalf("stake after slashing = %s, was not reduced from %s", v.Balance, staking.MinDeposit)
	}
	// Ejection is immediate; churn limits protect the set from disruption, not
	// an attacker from consequences.
	if v.IsActiveAt(staking.EpochOf(next)) {
		t.Fatal("a slashed validator is still in the set")
	}
}

func TestForgedEvidenceDoesNotSlash(t *testing.T) {
	keys, addrs := testKeys(t, 2)
	bc, engine, clock := newControlledChain(t, keys, addrs)
	builders := map[common.Address]*miner.Builder{
		addrs[0]: miner.NewBuilder(bc, engine, keys[0]),
	}

	// Two honest attestations for the same block are not equivocation, however
	// the evidence is labelled.
	a, _ := core.SignAttestation(keys[0], chainID, 3, common.Keccak256([]byte("same block")))
	evidence := &core.Equivocation{Validator: addrs[0], Number: 3, First: a, Second: a}
	encoded, _ := rlp.Encode(evidence)

	to := staking.StakingAddress
	report := signTxData(t, keys[1], 0, &to, new(big.Int), 300_000, append([]byte{processor.OpSlash}, encoded...))
	mineTo(t, bc, builders, clock, 1, map[uint64]core.Transactions{1: {report}})

	registry, _ := bc.StakingRegistry()
	v, err := registry.ByAddress(addrs[0])
	if err != nil {
		t.Fatal(err)
	}
	if v.Status == staking.StatusSlashed {
		t.Fatal("forged evidence slashed an honest validator")
	}
	if v.Balance.Cmp(staking.MinDeposit) != 0 {
		t.Fatalf("stake changed on forged evidence: %s", v.Balance)
	}
	_ = addrs
}

func TestUnderfundedDepositIsRejectedButPaidFor(t *testing.T) {
	keys, addrs := testKeys(t, 2)
	bc, engine, clock := newControlledChain(t, keys, addrs)
	builders := map[common.Address]*miner.Builder{addrs[0]: miner.NewBuilder(bc, engine, keys[0])}

	small := new(big.Int).Div(staking.MinDeposit, big.NewInt(2))
	deposit := depositTx(t, keys[1], 0, addrs[1], small)

	statedb, _ := bc.State()
	before := statedb.GetBalance(addrs[1])

	mineTo(t, bc, builders, clock, 1, map[uint64]core.Transactions{1: {deposit}})

	registry, _ := bc.StakingRegistry()
	if _, err := registry.ByAddress(addrs[1]); err == nil {
		t.Fatal("an underfunded deposit registered a validator")
	}
	statedb, _ = bc.State()
	after := statedb.GetBalance(addrs[1])
	// The value is returned by the revert, but the gas is not: a rejected
	// operation still has to cost something.
	if after.Cmp(before) >= 0 {
		t.Fatal("a rejected staking call was free")
	}
	// And the value did not stay in the staking account.
	if got := statedb.GetBalance(staking.StakingAddress); got.Cmp(staking.MinDeposit) != 0 {
		t.Fatalf("staking account holds %s, want only the genesis stake %s", got, staking.MinDeposit)
	}
}

func TestStakingInvariantAcrossAChain(t *testing.T) {
	keys, addrs := testKeys(t, 3)
	bc, engine, clock := newControlledChain(t, keys, addrs)
	builders := map[common.Address]*miner.Builder{
		addrs[0]: miner.NewBuilder(bc, engine, keys[0]),
		addrs[1]: miner.NewBuilder(bc, engine, keys[1]),
		addrs[2]: miner.NewBuilder(bc, engine, keys[2]),
	}

	txs := map[uint64]core.Transactions{
		1: {depositTx(t, keys[1], 0, addrs[1], staking.MinDeposit)},
		2: {depositTx(t, keys[2], 0, addrs[2], staking.MinDeposit)},
	}
	mineTo(t, bc, builders, clock, staking.EpochLength+2, txs)

	// The staking account must hold exactly what the registry says validators
	// own, through deposits, activations and epoch rewards alike.
	statedb, err := bc.State()
	if err != nil {
		t.Fatal(err)
	}
	manager := staking.NewManager(statedb)
	total, err := manager.TotalStaked()
	if err != nil {
		t.Fatal(err)
	}
	if got := statedb.GetBalance(staking.StakingAddress); got.Cmp(total) != 0 {
		t.Fatalf("the staking account holds %s but validators own %s", got, total)
	}
}
