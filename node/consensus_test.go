package node_test

import (
	"math/big"
	"testing"
	"time"

	"padi-chain/chain"
	"padi-chain/common"
	"padi-chain/consensus"
	"padi-chain/core"
	"padi-chain/crypto/secp256k1"
	"padi-chain/db"
	"padi-chain/keystore"
	"padi-chain/miner"
	"padi-chain/node"
)

// newValidatorSet returns n keys and their addresses.
func newValidatorSet(t *testing.T, n int) ([]*secp256k1.PrivateKey, []common.Address) {
	t.Helper()
	var keys []*secp256k1.PrivateKey
	var addrs []common.Address
	for i := 1; i <= n; i++ {
		key, addr := devKey(t, byte(i))
		keys = append(keys, key)
		addrs = append(addrs, addr)
	}
	return keys, addrs
}

// startCluster brings up a fully connected set of validator nodes.
func startCluster(t *testing.T, keys []*secp256k1.PrivateKey, addrs []common.Address) []*node.Node {
	t.Helper()

	genesis := chain.DefaultGenesis(testChainID, addrs)
	genesis.BlockPeriod = 1
	genesis.Timestamp = uint64(time.Now().Add(-time.Minute).Unix())
	balance := new(big.Int).Mul(big.NewInt(1000), big.NewInt(1e18))
	for _, addr := range addrs {
		genesis.Alloc[addr] = chain.GenesisAccount{Balance: balance}
	}

	var nodes []*node.Node
	for i, key := range keys {
		config := &node.Config{
			DataDir:    t.TempDir(),
			Genesis:    genesis,
			Validator:  key,
			Mine:       true,
			ListenAddr: "127.0.0.1:0",
			NodeName:   string(rune('a' + i)),
			Logger:     quietLogger(),
		}
		// Every node after the first dials the ones already running, so the
		// cluster is fully connected.
		for _, peer := range nodes {
			config.Bootstrap = append(config.Bootstrap, peer.P2PAddr())
		}
		n := startNode(t, config)
		nodes = append(nodes, n)
	}
	return nodes
}

func headOf(n *node.Node) uint64 { return n.Chain().CurrentBlock().NumberU64() }

func TestClusterReachesFinality(t *testing.T) {
	if testing.Short() {
		t.Skip("cluster tests are slow")
	}
	keys, addrs := newValidatorSet(t, 4)
	nodes := startCluster(t, keys, addrs)

	waitFor(t, 30*time.Second, "the cluster to connect", func() bool {
		for _, n := range nodes {
			if n.PeerCount() < len(nodes)-1 {
				return false
			}
		}
		return true
	})

	// Blocks must be produced by all four validators in turn, not just one.
	waitFor(t, 60*time.Second, "the chain to advance", func() bool {
		return headOf(nodes[0]) >= 4
	})

	proposers := map[common.Address]bool{}
	for height := uint64(1); height <= 4; height++ {
		block := nodes[0].Chain().GetBlockByNumber(height)
		if block == nil {
			t.Fatalf("block %d is missing", height)
		}
		proposers[block.Coinbase()] = true
	}
	if len(proposers) < 2 {
		t.Fatalf("only %d validator(s) proposed across four blocks; the rotation is not working", len(proposers))
	}

	// Finality must advance, and it must be the same everywhere.
	waitFor(t, 60*time.Second, "finality to advance", func() bool {
		for _, n := range nodes {
			if n.Chain().FinalizedNumber() < 2 {
				return false
			}
		}
		return true
	})

	finalized := nodes[0].Chain().FinalizedNumber()
	reference := nodes[0].Chain().GetBlockByNumber(finalized).Hash()
	for i, n := range nodes {
		block := n.Chain().GetBlockByNumber(finalized)
		if block == nil || block.Hash() != reference {
			t.Fatalf("node %d disagrees about finalized block %d", i, finalized)
		}
	}

	// A quorum out of four is three, so no node may finalize on fewer votes.
	if quorum := nodes[0].Attestations().Quorum(); quorum != 3 {
		t.Fatalf("quorum is %d, want 3 for a set of four", quorum)
	}
}

func TestClusterSurvivesValidatorOutage(t *testing.T) {
	if testing.Short() {
		t.Skip("cluster tests are slow")
	}
	keys, addrs := newValidatorSet(t, 4)
	nodes := startCluster(t, keys, addrs)

	waitFor(t, 30*time.Second, "the cluster to connect", func() bool {
		for _, n := range nodes {
			if n.PeerCount() < len(nodes)-1 {
				return false
			}
		}
		return true
	})
	waitFor(t, 60*time.Second, "the chain to start", func() bool {
		return headOf(nodes[0]) >= 2
	})

	// Take one validator down. With four validators a quorum is three, so the
	// remaining three can still both produce and finalize — that is the whole
	// point of the threshold.
	victim := nodes[len(nodes)-1]
	victimAddr := keystore.AddressOf(keys[len(keys)-1])
	if err := victim.Stop(); err != nil {
		t.Fatal(err)
	}
	survivors := nodes[:len(nodes)-1]

	heightAtOutage := headOf(survivors[0])
	finalizedAtOutage := survivors[0].Chain().FinalizedNumber()

	// Block production must continue: the missing validator's slots are taken
	// over by the next in the rotation after the round timeout.
	waitFor(t, 90*time.Second, "the chain to advance past the outage", func() bool {
		return headOf(survivors[0]) >= heightAtOutage+3
	})

	// And finality must keep up, not just block production.
	waitFor(t, 90*time.Second, "finality to advance past the outage", func() bool {
		return survivors[0].Chain().FinalizedNumber() > finalizedAtOutage
	})

	// The downed validator must not have proposed anything after it stopped.
	for height := heightAtOutage + 2; height <= headOf(survivors[0]); height++ {
		block := survivors[0].Chain().GetBlockByNumber(height)
		if block != nil && block.Coinbase() == victimAddr {
			t.Fatalf("block %d was attributed to the stopped validator", height)
		}
	}

	// The survivors must still agree with each other.
	height := headOf(survivors[0])
	for i := 1; i < len(survivors); i++ {
		waitFor(t, 30*time.Second, "the survivors to converge", func() bool {
			return headOf(survivors[i]) >= height
		})
		mine := survivors[i].Chain().GetBlockByNumber(height)
		theirs := survivors[0].Chain().GetBlockByNumber(height)
		if mine == nil || theirs == nil || mine.Hash() != theirs.Hash() {
			t.Fatalf("survivors disagree about block %d", height)
		}
	}
}

func TestTransactionsFinalizeAcrossCluster(t *testing.T) {
	if testing.Short() {
		t.Skip("cluster tests are slow")
	}
	keys, addrs := newValidatorSet(t, 4)
	nodes := startCluster(t, keys, addrs)

	waitFor(t, 30*time.Second, "the cluster to connect", func() bool {
		for _, n := range nodes {
			if n.PeerCount() < len(nodes)-1 {
				return false
			}
		}
		return true
	})

	recipient := common.MustHexToAddress("0x8888888888888888888888888888888888888888")
	signer := core.NewSigner(testChainID)
	tx, err := signer.SignTx(core.NewTx(&core.DynamicFeeTx{
		Nonce:     0,
		GasTipCap: big.NewInt(1_000_000_000),
		GasFeeCap: big.NewInt(20_000_000_000),
		Gas:       21000,
		To:        &recipient,
		Value:     big.NewInt(7777),
	}), keys[0])
	if err != nil {
		t.Fatal(err)
	}

	// Submit to one node; every node must end up with it, finalized.
	if err := nodes[1].TxPool().Add(tx); err != nil {
		t.Fatal(err)
	}

	waitFor(t, 90*time.Second, "the transaction to be mined everywhere", func() bool {
		for _, n := range nodes {
			if found, _ := n.Chain().GetTransaction(tx.Hash()); found == nil {
				return false
			}
		}
		return true
	})

	_, entry := nodes[0].Chain().GetTransaction(tx.Hash())
	waitFor(t, 90*time.Second, "the including block to finalize", func() bool {
		for _, n := range nodes {
			if n.Chain().FinalizedNumber() < entry.BlockIndex {
				return false
			}
		}
		return true
	})

	for i, n := range nodes {
		statedb, err := n.Chain().State()
		if err != nil {
			t.Fatal(err)
		}
		if got := statedb.GetBalance(recipient); got.Cmp(big.NewInt(7777)) != 0 {
			t.Fatalf("node %d has balance %s for the recipient, want 7777", i, got)
		}
	}
}

// TestDivergedNodesConvergeOnceConnected covers the case a cluster started all
// at once used to hide: two nodes that each hold a branch the other has never
// seen.
//
// The node that is behind cannot be helped by asking for blocks above its own
// height, because every one of them descends from a block it never had. Unless
// it searches backwards for the height where the two chains last agreed, it
// stays on its own branch for good — connected to the network, exchanging
// messages, and permanently unable to import anything.
func TestDivergedNodesConvergeOnceConnected(t *testing.T) {
	if testing.Short() {
		t.Skip("cluster tests are slow")
	}
	keys, addrs := newValidatorSet(t, 2)
	genesis := forkTestGenesis(addrs)

	// Two branches from the same genesis, built offline so the divergence is
	// exact rather than a matter of timing.
	// The branches are made to differ by content rather than by timing, so the
	// divergence is the same on every run.
	long := buildBranch(t, genesis, keys, 6, markerTx(t, keys[0], 7777))
	short := buildBranch(t, genesis, keys, 2, markerTx(t, keys[0], 8888))
	if long[0].Hash() == short[0].Hash() {
		t.Fatal("the two branches were supposed to differ from block one")
	}

	nodes := startIsolated(t, keys, genesis)
	seed(t, nodes[0], long)
	seed(t, nodes[1], short)

	if err := nodes[1].AddPeer(nodes[0].P2PAddr()); err != nil {
		t.Fatal(err)
	}

	waitFor(t, 60*time.Second, "the branch that was behind to be replaced", func() bool {
		return nodes[1].Chain().CurrentBlock().Hash() == long[len(long)-1].Hash()
	})
}

func forkTestGenesis(addrs []common.Address) *chain.Genesis {
	genesis := chain.DefaultGenesis(testChainID, addrs)
	genesis.BlockPeriod = 1
	genesis.Timestamp = uint64(time.Now().Add(-time.Hour).Unix())
	balance := new(big.Int).Mul(big.NewInt(1000), big.NewInt(1e18))
	for _, addr := range addrs {
		genesis.Alloc[addr] = chain.GenesisAccount{Balance: balance}
	}
	return genesis
}

// markerTx is a transfer whose only job is to make one branch differ from
// another.
func markerTx(t *testing.T, key *secp256k1.PrivateKey, value int64) *core.Transaction {
	t.Helper()
	recipient := common.MustHexToAddress("0x8888888888888888888888888888888888888888")
	tx, err := core.NewSigner(testChainID).SignTx(core.NewTx(&core.DynamicFeeTx{
		Nonce:     0,
		GasTipCap: big.NewInt(1_000_000_000),
		GasFeeCap: big.NewInt(20_000_000_000),
		Gas:       21000,
		To:        &recipient,
		Value:     big.NewInt(value),
	}), key)
	if err != nil {
		t.Fatal(err)
	}
	return tx
}

// buildBranch mines n blocks on a throwaway chain, putting the given
// transaction in the first, and returns them.
func buildBranch(t *testing.T, genesis *chain.Genesis, keys []*secp256k1.PrivateKey, n int, first *core.Transaction) core.Blocks {
	t.Helper()
	engine, err := consensus.NewPoA(genesis.Validators, genesis.BlockPeriod)
	if err != nil {
		t.Fatal(err)
	}
	bc, err := chain.NewBlockChain(db.NewMemoryDB(), genesis, engine)
	if err != nil {
		t.Fatal(err)
	}
	var blocks core.Blocks
	for i := 0; i < n; i++ {
		next := bc.CurrentBlock().NumberU64() + 1
		proposer, _ := engine.ProposerAt(next)
		var key *secp256k1.PrivateKey
		for j, addr := range genesis.Validators {
			if addr == proposer {
				key = keys[j]
			}
		}
		var txs core.Transactions
		if i == 0 {
			txs = core.Transactions{first}
		}
		result, err := miner.NewBuilder(bc, engine, key).Commit(txs)
		if err != nil {
			t.Fatal(err)
		}
		blocks = append(blocks, result.Block)
	}
	return blocks
}

func seed(t *testing.T, n *node.Node, blocks core.Blocks) {
	t.Helper()
	if _, err := n.Chain().InsertChain(blocks); err != nil {
		t.Fatal(err)
	}
}

// startIsolated starts nodes that share a genesis but not a network, and that
// do not mine, so each one holds exactly the branch it is given.
func startIsolated(t *testing.T, keys []*secp256k1.PrivateKey, genesis *chain.Genesis) []*node.Node {
	t.Helper()
	var nodes []*node.Node
	for i, key := range keys {
		nodes = append(nodes, startNode(t, &node.Config{
			DataDir:    t.TempDir(),
			Genesis:    genesis,
			Validator:  key,
			ListenAddr: "127.0.0.1:0",
			NodeName:   string(rune('a' + i)),
			Logger:     quietLogger(),
		}))
	}
	return nodes
}
