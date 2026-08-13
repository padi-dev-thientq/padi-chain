package chain_test

import (
	"errors"
	"math/big"
	"testing"
	"time"

	"layer1/chain"
	"layer1/common"
	"layer1/consensus"
	"layer1/core"
	"layer1/crypto/bls12381"
	"layer1/crypto/secp256k1"
	"layer1/db"
	"layer1/miner"
	"layer1/staking"
)

// finalize has every validator in the set attest to a block and applies the
// resulting certificate.
//
// The attestation keys come from the registry rather than the test, because the
// bitfield indexes into the ordered set the chain derives — a certificate built
// against any other ordering would name the wrong signers.
func finalize(t *testing.T, bc *chain.BlockChain, block *core.Block, _ []*secp256k1.PrivateKey) *core.QuorumCert {
	t.Helper()

	addresses, err := bc.ValidatorsAt(block.NumberU64())
	if err != nil {
		t.Fatal(err)
	}
	votes := make(map[int][]byte, len(addresses))
	for i, addr := range addresses {
		secret := validatorBLSKey(t, bc, addr)
		if secret == nil {
			t.Fatalf("no attestation key for validator %s", addr)
		}
		votes[i] = core.SignAttestationBLS(secret, chainID, block.NumberU64(), block.Hash())
	}

	qc, err := core.NewQuorumCert(block.NumberU64(), block.Hash(), len(addresses), votes)
	if err != nil {
		t.Fatal(err)
	}
	if err := bc.Finalize(qc); err != nil {
		t.Fatalf("finalizing block %d: %v", block.NumberU64(), err)
	}
	return qc
}

// validatorBLSKey finds the secret matching the key the registry holds.
func validatorBLSKey(t *testing.T, bc *chain.BlockChain, addr common.Address) *bls12381.SecretKey {
	t.Helper()
	registry, err := bc.StakingRegistry()
	if err != nil {
		t.Fatal(err)
	}
	v, err := registry.ByAddress(addr)
	if err != nil {
		return nil
	}
	for _, candidate := range []*bls12381.SecretKey{
		staking.DeriveGenesisBLSKey(addr),
		blsKeyFor(addr),
	} {
		if string(candidate.PublicKey().Bytes()) == string(v.BLSPublicKey) {
			return candidate
		}
	}
	return nil
}

func TestFinalizedHistoryCannotBeReorganised(t *testing.T) {
	keys, addrs := testKeys(t, 2)

	// Two nodes from the same genesis, each mining its own branch.
	nodeA, engineA := newTestChain(t, keys, addrs)
	minerA := miner.NewBuilder(nodeA, engineA, keys[0])

	nodeB, engineB := newTestChain(t, keys, addrs)
	minerB := miner.NewBuilder(nodeB, engineB, keys[0])

	// A mines two blocks and finalizes the second.
	recipient := common.MustHexToAddress("0x9999999999999999999999999999999999999999")
	tx := signTx(t, keys[1], 0, &recipient, big.NewInt(1000), 21000, nil)
	if _, err := minerA.Commit(core.Transactions{tx}); err != nil {
		t.Fatal(err)
	}
	resultA, err := minerA.Commit(nil)
	if err != nil {
		t.Fatal(err)
	}
	finalize(t, nodeA, resultA.Block, keys[:1])

	if got := nodeA.FinalizedNumber(); got != 2 {
		t.Fatalf("finalized height = %d, want 2", got)
	}

	// B builds a longer, conflicting branch — the classic long-range attack.
	var bBlocks core.Blocks
	for i := 0; i < 5; i++ {
		result, err := minerB.Commit(nil)
		if err != nil {
			t.Fatal(err)
		}
		bBlocks = append(bBlocks, result.Block)
	}

	headBefore := nodeA.CurrentBlock().Hash()
	_, err = nodeA.InsertChain(bBlocks)
	if err == nil {
		t.Fatal("a longer branch that abandons finalized history must be rejected")
	}
	if !errors.Is(err, chain.ErrConflictsWithFinalized) {
		t.Fatalf("got %v, want ErrConflictsWithFinalized", err)
	}
	if nodeA.CurrentBlock().Hash() != headBefore {
		t.Fatal("the head moved onto a branch that contradicts finality")
	}
	// The finalized transaction is still there.
	if found, _ := nodeA.GetTransaction(tx.Hash()); found == nil {
		t.Fatal("a finalized transaction was lost")
	}
}

func TestUnfinalizedHistoryStillReorganises(t *testing.T) {
	keys, addrs := testKeys(t, 2)

	nodeA, engineA := newTestChain(t, keys, addrs)
	minerA := miner.NewBuilder(nodeA, engineA, keys[0])
	nodeB, engineB := newTestChain(t, keys, addrs)
	minerB := miner.NewBuilder(nodeB, engineB, keys[0])

	// Nothing is finalized, so the longer branch must still win: finality is a
	// floor, not a freeze.
	if _, err := minerA.Commit(nil); err != nil {
		t.Fatal(err)
	}
	var bBlocks core.Blocks
	for i := 0; i < 3; i++ {
		result, err := minerB.Commit(nil)
		if err != nil {
			t.Fatal(err)
		}
		bBlocks = append(bBlocks, result.Block)
	}
	if _, err := nodeA.InsertChain(bBlocks); err != nil {
		t.Fatal(err)
	}
	if nodeA.CurrentBlock().Hash() != nodeB.CurrentBlock().Hash() {
		t.Fatal("an unfinalized branch should have been replaced by the longer one")
	}
}

func TestFinalityRequiresAValidCertificate(t *testing.T) {
	keys, addrs := testKeys(t, 3)

	// A three-validator chain: a quorum is three of three under the
	// more-than-two-thirds rule.
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

	proposer, _ := engine.ProposerAt(1)
	var proposerKey *secp256k1.PrivateKey
	for i, addr := range addrs {
		if addr == proposer {
			proposerKey = keys[i]
		}
	}
	result, err := miner.NewBuilder(bc, engine, proposerKey).Commit(nil)
	if err != nil {
		t.Fatal(err)
	}
	block := result.Block

	t.Run("a minority certificate is refused", func(t *testing.T) {
		// One vote out of three: valid, but short of the two-thirds threshold.
		set, err := bc.ValidatorsAt(block.NumberU64())
		if err != nil {
			t.Fatal(err)
		}
		secret := validatorBLSKey(t, bc, set[0])
		votes := map[int][]byte{0: core.SignAttestationBLS(secret, chainID, block.NumberU64(), block.Hash())}
		qc, _ := core.NewQuorumCert(block.NumberU64(), block.Hash(), len(set), votes)
		if err := bc.Finalize(qc); err == nil {
			t.Fatal("a minority certificate finalized a block")
		}
		if bc.FinalizedNumber() != 0 {
			t.Fatal("a minority certificate finalized a block")
		}
	})

	t.Run("a certificate for an unknown block is refused", func(t *testing.T) {
		ghost := common.Keccak256([]byte("a block nobody has"))
		set, _ := bc.ValidatorsAt(1)
		votes := make(map[int][]byte, len(set))
		for i, addr := range set {
			votes[i] = core.SignAttestationBLS(validatorBLSKey(t, bc, addr), chainID, 1, ghost)
		}
		qc, _ := core.NewQuorumCert(1, ghost, len(set), votes)
		if err := bc.Finalize(qc); err == nil {
			t.Fatal("a certificate for an unknown block must not finalize anything")
		}
	})

	t.Run("a full quorum finalizes", func(t *testing.T) {
		finalize(t, bc, block, keys)
		if bc.FinalizedNumber() != 1 {
			t.Fatalf("finalized height = %d, want 1", bc.FinalizedNumber())
		}
	})
}

func TestJustificationTravelsInHeaders(t *testing.T) {
	keys, addrs := testKeys(t, 2)
	bc, engine := newTestChain(t, keys, addrs)

	set, err := bc.ValidatorsAt(1)
	if err != nil {
		t.Fatal(err)
	}
	encodedKeys, err := bc.RawKeysForTest(1)
	if err != nil {
		t.Fatal(err)
	}
	pool := consensus.NewAttestationPool(chainID, set, encodedKeys)
	builder := miner.NewBuilder(bc, engine, keys[0])
	builder.SetAttestationPool(pool)

	first, err := builder.Commit(nil)
	if err != nil {
		t.Fatal(err)
	}

	// The sole validator attests to its own block.
	secret := validatorBLSKey(t, bc, set[0])
	attestation := pool.Attest(secret, 0, first.Block.NumberU64(), first.Block.Hash())
	if _, err := pool.Add(attestation); err != nil {
		t.Fatal(err)
	}

	// The next block should carry the certificate that finalizes the first.
	second, err := builder.Commit(nil)
	if err != nil {
		t.Fatal(err)
	}
	qc, err := second.Block.Justification()
	if err != nil {
		t.Fatal(err)
	}
	if qc.IsEmpty() {
		t.Fatal("the block carries no justification")
	}
	if qc.BlockHash != first.Block.Hash() || qc.Number != first.Block.NumberU64() {
		t.Fatalf("the justification targets %d/%s, want %d/%s",
			qc.Number, qc.BlockHash, first.Block.NumberU64(), first.Block.Hash())
	}

	// Importing that block on a fresh node must finalize the parent there too,
	// without the node having seen a single vote.
	follower, followerEngine := newTestChain(t, keys, addrs)
	_ = followerEngine
	if _, err := follower.InsertChain(core.Blocks{first.Block, second.Block}); err != nil {
		t.Fatal(err)
	}
	if follower.FinalizedNumber() != first.Block.NumberU64() {
		t.Fatalf("the follower finalized height %d, want %d", follower.FinalizedNumber(), first.Block.NumberU64())
	}
}

func TestForgedJustificationIsRejected(t *testing.T) {
	keys, addrs := testKeys(t, 2)
	bc, engine := newTestChain(t, keys, addrs)
	builder := miner.NewBuilder(bc, engine, keys[0])

	result, err := builder.BuildBlock(nil)
	if err != nil {
		t.Fatal(err)
	}

	// Attach a certificate signed by someone who is not a validator.
	outsider := bls12381.DeriveSecretKey([]byte("not a validator"))
	votes := map[int][]byte{0: core.SignAttestationBLS(outsider, chainID, 0, bc.Genesis().Hash())}
	qc, _ := core.NewQuorumCert(0, bc.Genesis().Hash(), 1, votes)
	encoded, _ := qc.Encode()

	header := result.Block.Header()
	header.Justification = encoded
	forged := core.NewBlockWithHeader(header)

	if err := bc.InsertBlock(forged); err == nil {
		t.Fatal("a block carrying a forged justification was accepted")
	}
	if bc.FinalizedNumber() != 0 {
		t.Fatal("a forged justification finalized a block")
	}
}
