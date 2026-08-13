package consensus

import (
	"errors"
	"math/big"
	"testing"
	"time"

	"padi-chain/common"
	"padi-chain/core"
	"padi-chain/crypto/bls12381"
)

var testChainID = big.NewInt(1337)

// validatorSet returns n validators: their addresses and the BLS keys they
// attest with.
func validatorSet(t *testing.T, n int) ([]*bls12381.SecretKey, []common.Address, [][]byte) {
	t.Helper()
	var secrets []*bls12381.SecretKey
	var addrs []common.Address
	var keys [][]byte
	for i := 1; i <= n; i++ {
		secret := bls12381.DeriveSecretKey([]byte{byte(i)})
		secrets = append(secrets, secret)
		addrs = append(addrs, common.BytesToAddress([]byte{byte(i)}))
		keys = append(keys, secret.PublicKey().Bytes())
	}
	return secrets, addrs, keys
}

func TestQuorumThreshold(t *testing.T) {
	// More than two thirds. The threshold matters: at exactly two thirds, two
	// disjoint quorums could exist and finality would mean nothing.
	cases := map[int]int{1: 1, 2: 2, 3: 3, 4: 3, 5: 4, 6: 5, 7: 5, 10: 7, 100: 67}
	for validators, want := range cases {
		if got := core.Quorum(validators); got != want {
			t.Errorf("Quorum(%d) = %d, want %d", validators, got, want)
		}
	}
	// Two quorums out of the same set must always overlap.
	for n := 1; n <= 50; n++ {
		q := core.Quorum(n)
		if 2*q <= n {
			t.Fatalf("with %d validators two quorums of %d could be disjoint", n, q)
		}
	}
}

func TestAttestationVerification(t *testing.T) {
	secrets, _, keys := validatorSet(t, 2)
	hash := common.Keccak256([]byte("block"))

	attestation := core.SignAttestation(secrets[0], testChainID, 0, 7, hash)
	pub, err := bls12381.PublicKeyFromBytes(keys[0])
	if err != nil {
		t.Fatal(err)
	}
	if err := attestation.Verify(testChainID, pub); err != nil {
		t.Fatalf("a valid vote failed verification: %v", err)
	}

	// A vote is bound to its chain, height and block.
	other, _ := bls12381.PublicKeyFromBytes(keys[1])
	if attestation.Verify(testChainID, other) == nil {
		t.Fatal("the vote verified against another validator's key")
	}
	if attestation.Verify(big.NewInt(999), pub) == nil {
		t.Fatal("the vote verified on a different chain")
	}
	wrongHeight := core.SignAttestation(secrets[0], testChainID, 0, 8, hash)
	wrongHeight.Number = 7
	if wrongHeight.Verify(testChainID, pub) == nil {
		t.Fatal("a vote for another height verified")
	}
}

func TestAggregateCertificateVerifies(t *testing.T) {
	secrets, addrs, keys := validatorSet(t, 4)
	pool := NewAttestationPool(testChainID, addrs, keys)
	hash := common.Keccak256([]byte("target"))
	quorum := core.Quorum(4) // 3

	for i := 0; i < quorum; i++ {
		if added, err := pool.Add(pool.Attest(secrets[i], uint64(i), 5, hash)); err != nil || !added {
			t.Fatalf("vote %d: added=%v err=%v", i, added, err)
		}
	}
	qc := pool.Certificate(5, hash)
	if qc == nil {
		t.Fatal("no certificate at quorum")
	}
	if qc.Count() != quorum {
		t.Fatalf("certificate names %d signers, want %d", qc.Count(), quorum)
	}

	publics := make([]*bls12381.PublicKey, len(keys))
	for i, raw := range keys {
		publics[i], _ = bls12381.PublicKeyFromBytes(raw)
	}
	if _, err := qc.Verify(testChainID, publics); err != nil {
		t.Fatalf("the pool produced a certificate that does not verify: %v", err)
	}
	// One signature, whatever the number of signers.
	if len(qc.Signature) != bls12381.SignatureLength {
		t.Fatalf("certificate signature is %d bytes", len(qc.Signature))
	}
}

func TestCertificateNeedsAQuorum(t *testing.T) {
	secrets, addrs, keys := validatorSet(t, 4)
	pool := NewAttestationPool(testChainID, addrs, keys)
	hash := common.Keccak256([]byte("target"))

	for i := 0; i < core.Quorum(4)-1; i++ {
		pool.Add(pool.Attest(secrets[i], uint64(i), 5, hash))
		if pool.Certificate(5, hash) != nil {
			t.Fatalf("a certificate formed after only %d votes", i+1)
		}
	}
}

func TestPoolRejectsOutsidersAndForgeries(t *testing.T) {
	secrets, addrs, keys := validatorSet(t, 4)
	pool := NewAttestationPool(testChainID, addrs, keys)
	hash := common.Keccak256([]byte("block"))

	// An index outside the set.
	stray := core.SignAttestation(secrets[0], testChainID, 99, 1, hash)
	if _, err := pool.Add(stray); !errors.Is(err, ErrUnknownIndex) {
		t.Fatalf("got %v, want ErrUnknownIndex", err)
	}

	// A vote signed by one validator but claiming another's index. With BLS
	// the signature does not name its signer, so the forgery is only caught
	// when the aggregate is checked — and what matters is that it never
	// produces a valid certificate.
	impostor := core.SignAttestation(secrets[0], testChainID, 1, 1, hash)
	if _, err := pool.Add(impostor); err != nil {
		t.Fatalf("the pool refused to hold the vote: %v", err)
	}
	for i := 2; i < 4; i++ {
		pool.Add(pool.Attest(secrets[i], uint64(i), 1, hash))
	}
	// Three votes are a quorum for four validators, but one of them is forged.
	if qc := pool.Certificate(1, hash); qc != nil {
		t.Fatal("a certificate was built from a forged vote")
	}
	// The forgery is evicted, so an honest quorum can still form afterwards.
	if _, err := pool.Add(pool.Attest(secrets[1], 1, 1, hash)); err != nil {
		t.Fatal(err)
	}
	if pool.Certificate(1, hash) == nil {
		t.Fatal("the pool could not recover after evicting the forged vote")
	}

	// A repeat of the same vote is not new.
	good := pool.Attest(secrets[0], 0, 2, hash)
	if added, _ := pool.Add(good); !added {
		t.Fatal("the first vote was not recorded")
	}
	if added, _ := pool.Add(good); added {
		t.Fatal("the same vote was counted twice")
	}
}

func TestEquivocationIsDetectedAndProvable(t *testing.T) {
	secrets, addrs, keys := validatorSet(t, 4)
	pool := NewAttestationPool(testChainID, addrs, keys)

	first := common.Keccak256([]byte("block A"))
	second := common.Keccak256([]byte("block B"))

	if _, err := pool.Add(pool.Attest(secrets[0], 0, 1, first)); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Add(pool.Attest(secrets[0], 0, 1, second)); !errors.Is(err, ErrEquivocation) {
		t.Fatalf("got %v, want ErrEquivocation", err)
	}

	evidence := pool.Evidence()
	if len(evidence) != 1 {
		t.Fatalf("collected %d proofs, want 1", len(evidence))
	}
	if evidence[0].Index != 0 || evidence[0].Validator != addrs[0] {
		t.Fatalf("evidence names validator %d (%s)", evidence[0].Index, evidence[0].Validator)
	}
	pub, _ := bls12381.PublicKeyFromBytes(keys[0])
	if err := evidence[0].Verify(testChainID, pub); err != nil {
		t.Fatalf("the pool produced evidence that does not verify: %v", err)
	}
	// The conflicting vote must not count toward any quorum.
	if pool.VoteCount(1, second) != 0 {
		t.Fatal("an equivocating vote was counted")
	}
}

func TestForgedEvidenceIsRejected(t *testing.T) {
	secrets, addrs, keys := validatorSet(t, 4)
	pool := NewAttestationPool(testChainID, addrs, keys)
	hash := common.Keccak256([]byte("block"))

	a := core.SignAttestation(secrets[0], testChainID, 0, 1, hash)
	b := core.SignAttestation(secrets[1], testChainID, 1, 1, hash)

	// Two different validators agreeing is not misbehaviour.
	if err := pool.AddEvidence(&core.Equivocation{Index: 0, Number: 1, First: a, Second: b}); err == nil {
		t.Fatal("evidence citing two different validators was accepted")
	}
	// Nor is the same validator voting the same way twice.
	if err := pool.AddEvidence(&core.Equivocation{Index: 0, Number: 1, First: a, Second: a}); err == nil {
		t.Fatal("evidence citing identical votes was accepted")
	}
	// Nor evidence attributed to a validator who did not sign it.
	conflicting := core.SignAttestation(secrets[0], testChainID, 0, 1, common.Keccak256([]byte("other")))
	if err := pool.AddEvidence(&core.Equivocation{Index: 2, Number: 1, First: a, Second: conflicting}); err == nil {
		t.Fatal("misattributed evidence was accepted")
	}
	_ = addrs
}

func TestPoolFollowsAChangingValidatorSet(t *testing.T) {
	secrets, addrs, keys := validatorSet(t, 4)
	// The pool starts with the first two validators.
	pool := NewAttestationPool(testChainID, addrs[:2], keys[:2])
	hash := common.Keccak256([]byte("block"))

	if got := pool.Quorum(); got != core.Quorum(2) {
		t.Fatalf("quorum = %d, want %d", got, core.Quorum(2))
	}
	newcomer := core.SignAttestation(secrets[2], testChainID, 2, 1, hash)
	if _, err := pool.Add(newcomer); err == nil {
		t.Fatal("a vote from outside the set was accepted")
	}

	pool.UpdateValidators(addrs, keys)
	if got := pool.Quorum(); got != core.Quorum(4) {
		t.Fatalf("quorum = %d, want %d once the set has grown", got, core.Quorum(4))
	}
	if added, err := pool.Add(newcomer); err != nil || !added {
		t.Fatalf("the newcomer's vote was still refused: %v", err)
	}
}

func TestQuorumGrowsWithTheSet(t *testing.T) {
	_, addrs, keys := validatorSet(t, 4)
	pool := NewAttestationPool(testChainID, addrs[:1], keys[:1])

	// A single validator finalizes alone; two do not, because a set of two
	// needs both. Getting this wrong would let a minority finalize.
	if pool.Quorum() != 1 {
		t.Fatalf("quorum for one validator = %d, want 1", pool.Quorum())
	}
	pool.UpdateValidators(addrs[:2], keys[:2])
	if pool.Quorum() != 2 {
		t.Fatalf("quorum for two validators = %d, want 2", pool.Quorum())
	}
	pool.UpdateValidators(addrs, keys)
	if pool.Quorum() != 3 {
		t.Fatalf("quorum for four validators = %d, want 3", pool.Quorum())
	}
}

func TestRoundBasedProposerFallback(t *testing.T) {
	_, addrs, _ := validatorSet(t, 3)
	engine, err := NewPoA(addrs, 2)
	if err != nil {
		t.Fatal(err)
	}
	engine.SetRoundTimeout(4)

	// Each round hands the turn to the next validator, so no single validator
	// can hold the chain hostage.
	seen := map[common.Address]bool{}
	for round := uint64(0); round < 3; round++ {
		proposer, err := engine.ProposerAtRound(1, round)
		if err != nil {
			t.Fatal(err)
		}
		if seen[proposer] {
			t.Fatalf("round %d repeats proposer %s", round, proposer)
		}
		seen[proposer] = true
	}
	if len(seen) != 3 {
		t.Fatalf("three rounds covered %d distinct validators, want 3", len(seen))
	}
}

func TestRoundOpensOnlyAfterItsTimeout(t *testing.T) {
	_, addrs, _ := validatorSet(t, 3)
	engine, err := NewPoA(addrs, 2)
	if err != nil {
		t.Fatal(err)
	}
	engine.SetRoundTimeout(4)

	parentTime := uint64(1000)
	cases := []struct {
		at   uint64
		want uint64
	}{
		{1000, 0}, // before the period has even elapsed
		{1002, 0}, // the scheduled proposer's slot opens
		{1005, 0}, // still within round 0
		{1006, 1}, // period + one timeout: the first fallback opens
		{1010, 2}, // period + two timeouts
	}
	for _, c := range cases {
		got := engine.RoundFor(parentTime, time.Unix(int64(c.at), 0))
		if got != c.want {
			t.Errorf("at t=%d the open round is %d, want %d", c.at, got, c.want)
		}
	}
}
