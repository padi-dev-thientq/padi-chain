package node_test

import (
	"math/big"
	"testing"
	"time"

	"layer1/chain"
	"layer1/common"
	"layer1/core"
	"layer1/node"
	"layer1/staking"
)

func TestSnapshotSync(t *testing.T) {
	if testing.Short() {
		t.Skip("snapshot sync is slow")
	}

	validatorKey, validator := devKey(t, 1)
	senderKey, sender := devKey(t, 2)
	genesis := newGenesis(validator, sender)

	// A node with history: it mines blocks, finalizes them, and accumulates
	// state that a newcomer would otherwise have to replay.
	source := startNode(t, &node.Config{
		DataDir:    t.TempDir(),
		Genesis:    genesis,
		Validator:  validatorKey,
		Mine:       true,
		ListenAddr: "127.0.0.1:0",
		Logger:     quietLogger(),
	})

	// Put real state on the chain, not just empty blocks.
	signer := core.NewSigner(testChainID)
	for i := 0; i < 5; i++ {
		recipient := common.BytesToAddress([]byte{byte(0xa0 + i)})
		tx, err := signer.SignTx(core.NewTx(&core.DynamicFeeTx{
			Nonce:     uint64(i),
			GasTipCap: big.NewInt(1_000_000_000),
			GasFeeCap: big.NewInt(20_000_000_000),
			Gas:       21000,
			To:        &recipient,
			Value:     big.NewInt(int64(i+1) * 1000),
		}), senderKey)
		if err != nil {
			t.Fatal(err)
		}
		if err := source.TxPool().Add(tx); err != nil {
			t.Fatal(err)
		}
	}

	waitFor(t, 30*time.Second, "the source chain to build and finalize history", func() bool {
		return source.Chain().FinalizedNumber() >= 6
	})

	finalized := source.Chain().FinalizedBlock()
	sourceState, err := source.Chain().State()
	if err != nil {
		t.Fatal(err)
	}

	// A fresh node, with a threshold low enough that this short chain counts
	// as far enough behind to be worth snapshotting.
	follower := startNode(t, &node.Config{
		DataDir:           t.TempDir(),
		Genesis:           genesis,
		ListenAddr:        "127.0.0.1:0",
		Bootstrap:         []string{source.P2PAddr()},
		SnapSyncThreshold: 3,
		Logger:            quietLogger(),
	})

	waitFor(t, 30*time.Second, "the nodes to connect", func() bool {
		return follower.PeerCount() > 0 && source.PeerCount() > 0
	})

	waitFor(t, 60*time.Second, "the follower to adopt a snapshot", func() bool {
		return follower.Chain().FinalizedNumber() > 0
	})

	adopted := follower.Chain().FinalizedBlock()
	if adopted == nil {
		t.Fatal("the follower finalized nothing")
	}
	if adopted.NumberU64() < finalized.NumberU64() {
		t.Fatalf("the follower adopted block %d, the source had finalized %d",
			adopted.NumberU64(), finalized.NumberU64())
	}

	// The whole point: state the follower never executed a block to produce.
	followerState, err := follower.Chain().StateAt(adopted.StateRoot())
	if err != nil {
		t.Fatalf("the adopted state is not usable: %v", err)
	}
	if got := followerState.GetBalance(sender); got.Sign() == 0 {
		t.Fatal("the synced state has no balance for the funded account")
	}
	for i := 0; i < 5; i++ {
		recipient := common.BytesToAddress([]byte{byte(0xa0 + i)})
		want := sourceState.GetBalance(recipient)
		if want.Sign() == 0 {
			continue
		}
		if got := followerState.GetBalance(recipient); got.Cmp(want) != 0 {
			t.Fatalf("recipient %d: synced balance %s, source %s", i, got, want)
		}
	}

	// And it must carry on from there rather than stopping at the snapshot.
	heightAtAdoption := follower.Chain().CurrentBlock().NumberU64()
	waitFor(t, 60*time.Second, "the follower to keep following", func() bool {
		return follower.Chain().CurrentBlock().NumberU64() > heightAtAdoption
	})
}

func TestSnapshotOfferWithBadCertificateIsRefused(t *testing.T) {
	validatorKey, validator := devKey(t, 1)
	genesis := newGenesis(validator)

	n := startNode(t, &node.Config{
		DataDir:           t.TempDir(),
		Genesis:           genesis,
		SnapSyncThreshold: 1,
		Logger:            quietLogger(),
	})

	// A block that claims to be final, with a certificate signed by nobody.
	header := &core.Header{
		ParentHash: n.Chain().Genesis().Hash(),
		Number:     big.NewInt(500),
		GasLimit:   30_000_000,
		BaseFee:    big.NewInt(1_000_000_000),
		StateRoot:  common.Keccak256([]byte("a state that does not exist")),
	}
	block := core.NewBlockWithHeader(header)
	qc := &core.QuorumCert{
		Number:    500,
		BlockHash: block.Hash(),
		Signers:   core.NewBitfield(1),
		Signature: make([]byte, 96),
	}
	qc.Signers.Set(0)

	n.HandleSnapshot(block, qc)

	if n.SnapSyncing() {
		t.Fatal("the node started syncing from an unproven snapshot")
	}
	if n.Chain().FinalizedNumber() != 0 {
		t.Fatal("an unproven snapshot was adopted")
	}
	_ = validatorKey
}

func TestSnapshotIsRefusedWhenLocalHistoryExists(t *testing.T) {
	validatorKey, validator := devKey(t, 1)
	genesis := newGenesis(validator)

	// A node that has been mining has history of its own, and must not throw
	// it away for someone else's head.
	n := startNode(t, &node.Config{
		DataDir:           t.TempDir(),
		Genesis:           genesis,
		Validator:         validatorKey,
		Mine:              true,
		SnapSyncThreshold: 1,
		Logger:            quietLogger(),
	})
	waitFor(t, 15*time.Second, "the node to build history", func() bool {
		return n.Chain().CurrentBlock().NumberU64() >= 2
	})

	block, qc := n.LocalSnapshot()
	if block == nil {
		t.Skip("nothing finalized yet")
	}
	before := n.Chain().CurrentBlock().Hash()
	n.HandleSnapshot(block, qc)

	if n.SnapSyncing() {
		t.Fatal("a node with its own history started a snapshot sync")
	}
	if n.Chain().CurrentBlock().Hash() != before {
		t.Fatal("the head moved on a refused snapshot")
	}
}

func TestImportSnapshotRequiresPresentState(t *testing.T) {
	keys, addrs := newValidatorSet(t, 1)
	genesis := chain.DefaultGenesis(testChainID, addrs)
	genesis.BlockPeriod = 1
	genesis.Alloc[addrs[0]] = chain.GenesisAccount{Balance: big.NewInt(1000)}

	n := startNode(t, &node.Config{
		DataDir: t.TempDir(),
		Genesis: genesis,
		Logger:  quietLogger(),
	})

	// A properly signed certificate for a block whose state was never
	// downloaded must still be refused: adopting it would leave the node
	// unable to execute anything.
	header := &core.Header{
		ParentHash: n.Chain().Genesis().Hash(),
		Number:     big.NewInt(10),
		GasLimit:   30_000_000,
		BaseFee:    big.NewInt(1_000_000_000),
		StateRoot:  common.Keccak256([]byte("absent state")),
	}
	block := core.NewBlockWithHeader(header)

	secret := staking.DeriveGenesisBLSKey(addrs[0])
	votes := map[int][]byte{0: core.SignAttestationBLS(secret, testChainID, block.NumberU64(), block.Hash())}
	qc, err := core.NewQuorumCert(block.NumberU64(), block.Hash(), 1, votes)
	if err != nil {
		t.Fatal(err)
	}
	_ = keys

	if err := n.Chain().ImportSnapshot(block, qc); err == nil {
		t.Fatal("a snapshot whose state is missing was adopted")
	}
	if n.Chain().FinalizedNumber() != 0 {
		t.Fatal("the chain finalized a block it has no state for")
	}
}
