package consensus

import (
	"errors"
	"math/big"
	"testing"
	"time"

	"layer1/common"
	"layer1/core"
	"layer1/crypto/secp256k1"
)

var testChainID = big.NewInt(1337)

func validatorKeys(t *testing.T, n int) ([]*secp256k1.PrivateKey, []common.Address) {
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

func TestAttestationSignAndRecover(t *testing.T) {
	keys, addrs := validatorKeys(t, 1)
	hash := common.Keccak256([]byte("block"))

	attestation, err := core.SignAttestation(keys[0], testChainID, 7, hash)
	if err != nil {
		t.Fatal(err)
	}
	attester, err := attestation.Attester(testChainID)
	if err != nil {
		t.Fatal(err)
	}
	if attester != addrs[0] {
		t.Fatalf("recovered %s, want %s", attester, addrs[0])
	}

	// An attestation is bound to its chain: the same signature must not
	// recover the validator on another network.
	if other, err := attestation.Attester(big.NewInt(999)); err == nil && other == addrs[0] {
		t.Fatal("an attestation must not be valid on a different chain")
	}
}

func TestQuorumCertificateVerification(t *testing.T) {
	keys, addrs := validatorKeys(t, 4)
	hash := common.Keccak256([]byte("target"))
	quorum := core.Quorum(4) // 3

	attest := func(i int) *core.Attestation {
		a, err := core.SignAttestation(keys[i], testChainID, 5, hash)
		if err != nil {
			t.Fatal(err)
		}
		return a
	}

	t.Run("a quorum verifies", func(t *testing.T) {
		qc, err := core.NewQuorumCert(5, hash, []*core.Attestation{attest(0), attest(1), attest(2)})
		if err != nil {
			t.Fatal(err)
		}
		attesters, err := qc.Verify(testChainID, addrs)
		if err != nil {
			t.Fatal(err)
		}
		if len(attesters) != quorum {
			t.Fatalf("verified %d attesters, want %d", len(attesters), quorum)
		}
	})

	t.Run("short of a quorum is rejected", func(t *testing.T) {
		qc, _ := core.NewQuorumCert(5, hash, []*core.Attestation{attest(0), attest(1)})
		if _, err := qc.Verify(testChainID, addrs); !errors.Is(err, core.ErrQuorumNotMet) {
			t.Fatalf("got %v, want ErrQuorumNotMet", err)
		}
	})

	t.Run("the same validator cannot be counted twice", func(t *testing.T) {
		// Padding a certificate with duplicates is how a minority would try to
		// manufacture a quorum.
		qc, _ := core.NewQuorumCert(5, hash, []*core.Attestation{attest(0), attest(0), attest(0)})
		if _, err := qc.Verify(testChainID, addrs); !errors.Is(err, core.ErrDuplicateAttester) {
			t.Fatalf("got %v, want ErrDuplicateAttester", err)
		}
	})

	t.Run("outsiders are rejected", func(t *testing.T) {
		outsiderKey, _ := secp256k1.PrivateKeyFromBytes(common.LeftPadBytes([]byte{99}, 32))
		outsider, _ := core.SignAttestation(outsiderKey, testChainID, 5, hash)
		qc, _ := core.NewQuorumCert(5, hash, []*core.Attestation{attest(0), attest(1), outsider})
		if _, err := qc.Verify(testChainID, addrs); !errors.Is(err, core.ErrUnknownAttester) {
			t.Fatalf("got %v, want ErrUnknownAttester", err)
		}
	})

	t.Run("a tampered signature is rejected", func(t *testing.T) {
		qc, _ := core.NewQuorumCert(5, hash, []*core.Attestation{attest(0), attest(1), attest(2)})
		qc.Signatures[0] = append([]byte(nil), qc.Signatures[0]...)
		qc.Signatures[0][10] ^= 0xff
		if _, err := qc.Verify(testChainID, addrs); err == nil {
			t.Fatal("a certificate with a mutated signature must not verify")
		}
	})

	t.Run("votes for another block do not count", func(t *testing.T) {
		other := common.Keccak256([]byte("another block"))
		stray, _ := core.SignAttestation(keys[3], testChainID, 5, other)
		if _, err := core.NewQuorumCert(5, hash, []*core.Attestation{attest(0), stray}); !errors.Is(err, core.ErrWrongTarget) {
			t.Fatalf("got %v, want ErrWrongTarget", err)
		}
	})

	t.Run("encoding round-trips", func(t *testing.T) {
		qc, _ := core.NewQuorumCert(5, hash, []*core.Attestation{attest(0), attest(1), attest(2)})
		enc, err := qc.Encode()
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := core.DecodeQuorumCert(enc)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := decoded.Verify(testChainID, addrs); err != nil {
			t.Fatalf("the decoded certificate does not verify: %v", err)
		}
	})

	t.Run("certificates are deterministic", func(t *testing.T) {
		// Two nodes that collected the same votes in different orders must
		// produce byte-identical certificates, or they would build different
		// blocks from the same information.
		a, _ := core.NewQuorumCert(5, hash, []*core.Attestation{attest(0), attest(1), attest(2)})
		b, _ := core.NewQuorumCert(5, hash, []*core.Attestation{attest(2), attest(0), attest(1)})
		encA, _ := a.Encode()
		encB, _ := b.Encode()
		if string(encA) != string(encB) {
			t.Fatal("certificate encoding depends on the order votes arrived in")
		}
	})
}

func TestAttestationPoolReachesQuorum(t *testing.T) {
	keys, addrs := validatorKeys(t, 4)
	pool := NewAttestationPool(testChainID, addrs)
	hash := common.Keccak256([]byte("block"))

	for i := 0; i < 2; i++ {
		a, _ := core.SignAttestation(keys[i], testChainID, 1, hash)
		added, err := pool.Add(a)
		if err != nil || !added {
			t.Fatalf("vote %d: added=%v err=%v", i, added, err)
		}
		if pool.Certificate(1, hash) != nil {
			t.Fatalf("a certificate formed after only %d votes, quorum is %d", i+1, pool.Quorum())
		}
	}

	third, _ := core.SignAttestation(keys[2], testChainID, 1, hash)
	if _, err := pool.Add(third); err != nil {
		t.Fatal(err)
	}
	qc := pool.Certificate(1, hash)
	if qc == nil {
		t.Fatal("no certificate at quorum")
	}
	if _, err := qc.Verify(testChainID, addrs); err != nil {
		t.Fatalf("the pool produced a certificate that does not verify: %v", err)
	}
}

func TestAttestationPoolRejectsRepeatsAndOutsiders(t *testing.T) {
	keys, addrs := validatorKeys(t, 4)
	pool := NewAttestationPool(testChainID, addrs)
	hash := common.Keccak256([]byte("block"))

	a, _ := core.SignAttestation(keys[0], testChainID, 1, hash)
	if added, _ := pool.Add(a); !added {
		t.Fatal("the first vote was not recorded")
	}
	if added, _ := pool.Add(a); added {
		t.Fatal("the same vote was counted twice")
	}

	outsiderKey, _ := secp256k1.PrivateKeyFromBytes(common.LeftPadBytes([]byte{99}, 32))
	outsider, _ := core.SignAttestation(outsiderKey, testChainID, 1, hash)
	if _, err := pool.Add(outsider); !errors.Is(err, core.ErrUnknownAttester) {
		t.Fatalf("got %v, want ErrUnknownAttester", err)
	}
}

func TestEquivocationIsDetectedAndProvable(t *testing.T) {
	keys, addrs := validatorKeys(t, 4)
	pool := NewAttestationPool(testChainID, addrs)

	first := common.Keccak256([]byte("block A"))
	second := common.Keccak256([]byte("block B"))

	honest, _ := core.SignAttestation(keys[0], testChainID, 1, first)
	if _, err := pool.Add(honest); err != nil {
		t.Fatal(err)
	}

	// The same validator now votes for a different block at the same height.
	conflicting, _ := core.SignAttestation(keys[0], testChainID, 1, second)
	if _, err := pool.Add(conflicting); !errors.Is(err, ErrEquivocation) {
		t.Fatalf("got %v, want ErrEquivocation", err)
	}

	evidence := pool.Evidence()
	if len(evidence) != 1 {
		t.Fatalf("collected %d proofs, want 1", len(evidence))
	}
	if evidence[0].Validator != addrs[0] || evidence[0].Number != 1 {
		t.Fatalf("evidence names %s at %d", evidence[0].Validator, evidence[0].Number)
	}
	if err := evidence[0].Verify(testChainID); err != nil {
		t.Fatalf("the pool produced evidence that does not verify: %v", err)
	}

	// The conflicting vote must not have been counted toward any quorum.
	if pool.VoteCount(1, second) != 0 {
		t.Fatal("an equivocating vote was counted")
	}
}

func TestForgedEvidenceIsRejected(t *testing.T) {
	keys, addrs := validatorKeys(t, 4)
	pool := NewAttestationPool(testChainID, addrs)
	hash := common.Keccak256([]byte("block"))

	a, _ := core.SignAttestation(keys[0], testChainID, 1, hash)
	b, _ := core.SignAttestation(keys[1], testChainID, 1, hash)

	// Two different validators agreeing is not misbehaviour.
	if err := pool.AddEvidence(&core.Equivocation{
		Validator: addrs[0], Number: 1, First: a, Second: b,
	}); err == nil {
		t.Fatal("evidence naming two different signers must be rejected")
	}

	// Nor is the same validator voting the same way twice.
	if err := pool.AddEvidence(&core.Equivocation{
		Validator: addrs[0], Number: 1, First: a, Second: a,
	}); err == nil {
		t.Fatal("evidence citing identical votes must be rejected")
	}

	// Evidence attributed to the wrong validator must not stick.
	conflicting, _ := core.SignAttestation(keys[0], testChainID, 1, common.Keccak256([]byte("other")))
	if err := pool.AddEvidence(&core.Equivocation{
		Validator: addrs[2], Number: 1, First: a, Second: conflicting,
	}); err == nil {
		t.Fatal("misattributed evidence must be rejected")
	}
}

func TestDifferentHeightsAreNotEquivocation(t *testing.T) {
	keys, _ := validatorKeys(t, 1)
	a, _ := core.SignAttestation(keys[0], testChainID, 1, common.Keccak256([]byte("x")))
	b, _ := core.SignAttestation(keys[0], testChainID, 2, common.Keccak256([]byte("y")))

	proof, err := core.DetectEquivocation(testChainID, a, b)
	if err != nil {
		t.Fatal(err)
	}
	if proof != nil {
		t.Fatal("voting at two different heights is normal, not equivocation")
	}
}

func TestRoundBasedProposerFallback(t *testing.T) {
	_, addrs := validatorKeys(t, 3)
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
	_, addrs := validatorKeys(t, 3)
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
