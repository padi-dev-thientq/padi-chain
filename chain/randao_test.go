package chain_test

import (
	"math/big"
	"testing"

	"padi-chain/common"
	"padi-chain/core"
	"padi-chain/crypto/bls12381"
	"padi-chain/miner"
	"padi-chain/staking"
)

func TestRandaoMixAdvances(t *testing.T) {
	keys, addrs := testKeys(t, 2)
	bc, engine, clock := newControlledChain(t, keys, addrs)
	builder := miner.NewBuilder(bc, engine, keys[0])
	builder.SetBLSKey(staking.DeriveGenesisBLSKey(addrs[0]))
	builders := map[common.Address]*miner.Builder{addrs[0]: builder}

	registry, _ := bc.StakingRegistry()
	before := registry.RandaoMix()

	mineTo(t, bc, builders, clock, 3, nil)

	registry, _ = bc.StakingRegistry()
	after := registry.RandaoMix()
	if after == before {
		t.Fatal("the randao mix did not change as blocks were produced")
	}

	// Every block must carry a reveal, and it must be committed to by the
	// header — otherwise a proposer could swap it after sealing.
	block := bc.GetBlockByNumber(2)
	if len(block.RandaoReveal()) != bls12381.SignatureLength {
		t.Fatalf("block 2 carries a %d-byte reveal", len(block.RandaoReveal()))
	}
	header := block.Header()
	sealingBefore := header.SealingHash()
	header.RandaoReveal = make([]byte, bls12381.SignatureLength)
	if header.SealingHash() == sealingBefore {
		t.Fatal("the reveal is not committed to by the hash the proposer signs")
	}
}

func TestRandaoRevealIsDeterministicPerEpoch(t *testing.T) {
	_, addrs := testKeys(t, 1)
	key := staking.DeriveGenesisBLSKey(addrs[0])

	// A BLS signature is unique per key and message, so a proposer cannot try
	// alternatives until one yields a seed it prefers. Signing the epoch rather
	// than the block also fixes it before the proposer knows what it will build.
	first := core.SignRandaoReveal(key, chainID, 3)
	second := core.SignRandaoReveal(key, chainID, 3)
	if string(first) != string(second) {
		t.Fatal("a proposer can produce two different reveals for the same epoch")
	}
	if string(core.SignRandaoReveal(key, chainID, 4)) == string(first) {
		t.Fatal("the reveal does not depend on the epoch")
	}
	// And it is bound to the chain.
	if string(core.SignRandaoReveal(key, big.NewInt(999), 3)) == string(first) {
		t.Fatal("the reveal is not bound to the chain")
	}
}

func TestForgedRevealIsRejected(t *testing.T) {
	keys, addrs := testKeys(t, 2)
	bc, engine, clock := newControlledChain(t, keys, addrs)

	// A proposer signing with a key that is not the one it registered must not
	// be able to steer the randomness.
	builder := miner.NewBuilder(bc, engine, keys[0])
	builder.SetBLSKey(bls12381.DeriveSecretKey([]byte("not the registered key")))
	builders := map[common.Address]*miner.Builder{addrs[0]: builder}

	clock.advance()
	if _, err := builders[addrs[0]].Commit(nil); err == nil {
		t.Fatal("a block with a reveal signed by the wrong key was accepted")
	}
}

func TestProposerSelectionIsStakeWeighted(t *testing.T) {
	registry := newStandaloneRegistry(t)

	// Three validators; the first holds four times the stake of the others.
	addresses := []common.Address{{1}, {2}, {3}}
	weights := []int64{32, 8, 8}
	for i, addr := range addresses {
		v := &staking.Validator{
			Address:           addr,
			WithdrawalAddress: addr,
			Balance:           new(big.Int).Mul(big.NewInt(weights[i]), staking.Ether),
			Status:            staking.StatusActive,
			ActivationEpoch:   0,
			ExitEpoch:         staking.FarFutureEpoch,
			WithdrawableEpoch: staking.FarFutureEpoch,
		}
		registry.Append(v)
	}

	seed := common.Keccak256([]byte("seed"))
	counts := map[common.Address]int{}
	const slots = 2000
	for slot := uint64(0); slot < slots; slot++ {
		proposer, err := registry.ProposerAt(0, seed, slot, 0)
		if err != nil {
			t.Fatal(err)
		}
		counts[proposer]++
	}

	// The heavy validator should take roughly two thirds of the slots. The
	// bounds are loose because the point is that stake matters, not that the
	// sample is perfectly uniform.
	heavy := counts[addresses[0]]
	if heavy < slots/2 || heavy > slots*8/10 {
		t.Fatalf("the validator with two thirds of the stake proposed %d of %d slots: %v", heavy, slots, counts)
	}
	for _, addr := range addresses[1:] {
		if counts[addr] == 0 {
			t.Fatalf("a staked validator never proposed: %v", counts)
		}
	}
}

func TestProposerDependsOnSeedAndRound(t *testing.T) {
	registry := newStandaloneRegistry(t)
	for i := 1; i <= 8; i++ {
		addr := common.BytesToAddress([]byte{byte(i)})
		registry.Append(&staking.Validator{
			Address:           addr,
			WithdrawalAddress: addr,
			Balance:           staking.MinDeposit,
			Status:            staking.StatusActive,
			ExitEpoch:         staking.FarFutureEpoch,
			WithdrawableEpoch: staking.FarFutureEpoch,
		})
	}

	seedA := common.Keccak256([]byte("seed A"))
	seedB := common.Keccak256([]byte("seed B"))

	// A different seed must reshuffle the schedule; otherwise the randomness
	// would not be doing anything.
	var differences int
	for slot := uint64(0); slot < 50; slot++ {
		a, _ := registry.ProposerAt(0, seedA, slot, 0)
		b, _ := registry.ProposerAt(0, seedB, slot, 0)
		if a != b {
			differences++
		}
	}
	if differences < 20 {
		t.Fatalf("only %d of 50 slots changed with the seed", differences)
	}

	// A fallback round must hand the turn to someone else, or an offline
	// proposer would still hold up the slot.
	var moved int
	for slot := uint64(0); slot < 50; slot++ {
		first, _ := registry.ProposerAt(0, seedA, slot, 0)
		second, _ := registry.ProposerAt(0, seedA, slot, 1)
		if first != second {
			moved++
		}
	}
	if moved < 30 {
		t.Fatalf("the fallback round changed the proposer in only %d of 50 slots", moved)
	}
}

func TestProposerIsDeterministic(t *testing.T) {
	registry := newStandaloneRegistry(t)
	for i := 1; i <= 5; i++ {
		addr := common.BytesToAddress([]byte{byte(i)})
		registry.Append(&staking.Validator{
			Address:           addr,
			WithdrawalAddress: addr,
			Balance:           staking.MinDeposit,
			Status:            staking.StatusActive,
			ExitEpoch:         staking.FarFutureEpoch,
			WithdrawableEpoch: staking.FarFutureEpoch,
		})
	}
	seed := common.Keccak256([]byte("seed"))
	// Every node must derive the same schedule from the same state, or they
	// would disagree about which blocks are valid.
	for slot := uint64(0); slot < 20; slot++ {
		first, _ := registry.ProposerAt(0, seed, slot, 0)
		second, _ := registry.ProposerAt(0, seed, slot, 0)
		if first != second {
			t.Fatal("proposer selection is not deterministic")
		}
	}
}
