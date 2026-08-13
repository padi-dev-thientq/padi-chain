package core

import (
	"math/big"
	"testing"

	"padi-chain/common"
	"padi-chain/crypto/bls12381"
)

var aggChainID = big.NewInt(1337)

func blsKeys(t *testing.T, n int) ([]*bls12381.SecretKey, []*bls12381.PublicKey) {
	t.Helper()
	var secrets []*bls12381.SecretKey
	var publics []*bls12381.PublicKey
	for i := 0; i < n; i++ {
		k := bls12381.DeriveSecretKey([]byte{byte(i + 1)})
		secrets = append(secrets, k)
		publics = append(publics, k.PublicKey())
	}
	return secrets, publics
}

func TestBitfield(t *testing.T) {
	b := NewBitfield(20)
	if len(b) != 3 {
		t.Fatalf("bitfield for 20 validators is %d bytes, want 3", len(b))
	}
	b.Set(0)
	b.Set(7)
	b.Set(19)
	if !b.Has(0) || !b.Has(7) || !b.Has(19) {
		t.Fatal("a set index does not read back")
	}
	if b.Has(1) || b.Has(18) {
		t.Fatal("an unset index reads as set")
	}
	if b.Count() != 3 {
		t.Fatalf("count = %d, want 3", b.Count())
	}
	got := b.Indices(20)
	if len(got) != 3 || got[0] != 0 || got[1] != 7 || got[2] != 19 {
		t.Fatalf("indices = %v", got)
	}
	// Out-of-range writes are ignored rather than corrupting neighbours.
	b.Set(100)
	b.Set(-1)
	if b.Count() != 3 {
		t.Fatal("an out-of-range index changed the bitfield")
	}
}

func TestBitfieldOverlap(t *testing.T) {
	a := NewBitfield(16)
	b := NewBitfield(16)
	a.Set(1)
	a.Set(2)
	b.Set(3)
	if a.Overlaps(b) {
		t.Fatal("disjoint bitfields reported as overlapping")
	}
	b.Set(2)
	if !a.Overlaps(b) {
		t.Fatal("shared index not detected")
	}
	a.Or(b)
	if a.Count() != 3 {
		t.Fatalf("after Or, count = %d, want 3", a.Count())
	}
}

func TestBitfieldRejectsTrailingBits(t *testing.T) {
	// A bit past the end of the validator set must invalidate the field: two
	// encodings that name the same signers would otherwise both be accepted.
	b := NewBitfield(10) // 2 bytes, 6 spare bits
	b.Set(3)
	if !b.fits(10) {
		t.Fatal("a well-formed bitfield was rejected")
	}
	b[1] |= 0x80 // index 15, past the set
	if b.fits(10) {
		t.Fatal("a bitfield with bits past the validator set was accepted")
	}
	if b.fits(9) {
		t.Fatal("a wrongly sized bitfield was accepted")
	}
}

func TestAggregateVerifies(t *testing.T) {
	secrets, publics := blsKeys(t, 8)
	hash := common.Keccak256([]byte("block 5"))

	agg := NewAggregate(5, hash, len(publics))
	for i := 0; i < 6; i++ {
		sig := SignAttestationBLS(secrets[i], aggChainID, 5, hash)
		if err := agg.Add(i, sig); err != nil {
			t.Fatal(err)
		}
	}

	indices, err := agg.Verify(aggChainID, publics)
	if err != nil {
		t.Fatal(err)
	}
	if len(indices) != 6 {
		t.Fatalf("verified %d signers, want 6", len(indices))
	}
	// One signature stands for all six.
	if len(agg.Signature) != bls12381.SignatureLength {
		t.Fatalf("aggregate signature is %d bytes", len(agg.Signature))
	}
}

func TestAggregateRejectsWrongSigners(t *testing.T) {
	secrets, publics := blsKeys(t, 8)
	hash := common.Keccak256([]byte("block 5"))

	agg := NewAggregate(5, hash, len(publics))
	for i := 0; i < 4; i++ {
		agg.Add(i, SignAttestationBLS(secrets[i], aggChainID, 5, hash))
	}

	// Claiming an extra signer must fail: the bitfield is what the aggregate
	// is checked against.
	tampered := *agg
	tampered.Signers = append(Bitfield(nil), agg.Signers...)
	tampered.Signers.Set(5)
	if _, err := tampered.Verify(aggChainID, publics); err == nil {
		t.Fatal("an aggregate claiming an extra signer verified")
	}

	// Dropping a signer must fail too.
	fewer := *agg
	fewer.Signers = NewBitfield(len(publics))
	fewer.Signers.Set(0)
	fewer.Signers.Set(1)
	if _, err := fewer.Verify(aggChainID, publics); err == nil {
		t.Fatal("an aggregate claiming fewer signers verified")
	}
}

func TestAggregateIsBoundToItsTarget(t *testing.T) {
	secrets, publics := blsKeys(t, 4)
	hash := common.Keccak256([]byte("block 5"))

	agg := NewAggregate(5, hash, len(publics))
	for i := range secrets {
		agg.Add(i, SignAttestationBLS(secrets[i], aggChainID, 5, hash))
	}

	// A different height or block must not verify with the same signature.
	wrongHeight := *agg
	wrongHeight.Number = 6
	if _, err := wrongHeight.Verify(aggChainID, publics); err == nil {
		t.Fatal("the aggregate verified at the wrong height")
	}
	wrongBlock := *agg
	wrongBlock.BlockHash = common.Keccak256([]byte("another block"))
	if _, err := wrongBlock.Verify(aggChainID, publics); err == nil {
		t.Fatal("the aggregate verified for the wrong block")
	}
	// Nor on another chain.
	if _, err := agg.Verify(big.NewInt(999), publics); err == nil {
		t.Fatal("the aggregate verified on a different chain")
	}
}

func TestDuplicateSignatureIsIgnored(t *testing.T) {
	secrets, publics := blsKeys(t, 4)
	hash := common.Keccak256([]byte("block 9"))

	agg := NewAggregate(9, hash, len(publics))
	sig := SignAttestationBLS(secrets[0], aggChainID, 9, hash)
	agg.Add(0, sig)
	// Adding the same validator twice would corrupt the aggregate into one
	// that verifies against nothing.
	agg.Add(0, sig)
	agg.Add(1, SignAttestationBLS(secrets[1], aggChainID, 9, hash))

	if agg.Count() != 2 {
		t.Fatalf("count = %d, want 2", agg.Count())
	}
	if _, err := agg.Verify(aggChainID, publics); err != nil {
		t.Fatalf("a duplicate submission corrupted the aggregate: %v", err)
	}
}

func TestMergeAggregates(t *testing.T) {
	secrets, publics := blsKeys(t, 8)
	hash := common.Keccak256([]byte("block 3"))

	// Two peers each collect part of the quorum; the proposer combines them.
	first := NewAggregate(3, hash, len(publics))
	for i := 0; i < 3; i++ {
		first.Add(i, SignAttestationBLS(secrets[i], aggChainID, 3, hash))
	}
	second := NewAggregate(3, hash, len(publics))
	for i := 3; i < 6; i++ {
		second.Add(i, SignAttestationBLS(secrets[i], aggChainID, 3, hash))
	}

	if err := first.Merge(second); err != nil {
		t.Fatal(err)
	}
	if first.Count() != 6 {
		t.Fatalf("merged count = %d, want 6", first.Count())
	}
	if _, err := first.Verify(aggChainID, publics); err != nil {
		t.Fatalf("the merged aggregate did not verify: %v", err)
	}
}

func TestOverlappingMergeIsRefused(t *testing.T) {
	secrets, publics := blsKeys(t, 8)
	hash := common.Keccak256([]byte("block 3"))

	a := NewAggregate(3, hash, len(publics))
	a.Add(0, SignAttestationBLS(secrets[0], aggChainID, 3, hash))
	a.Add(1, SignAttestationBLS(secrets[1], aggChainID, 3, hash))

	b := NewAggregate(3, hash, len(publics))
	b.Add(1, SignAttestationBLS(secrets[1], aggChainID, 3, hash))
	b.Add(2, SignAttestationBLS(secrets[2], aggChainID, 3, hash))

	// Merging these would count validator 1 twice and destroy the signature.
	if err := a.Merge(b); err == nil {
		t.Fatal("overlapping aggregates were merged")
	}
	if _, err := a.Verify(aggChainID, publics); err != nil {
		t.Fatalf("the refused merge corrupted the original: %v", err)
	}
}

func TestAggregateEncodingRoundTrip(t *testing.T) {
	secrets, publics := blsKeys(t, 6)
	hash := common.Keccak256([]byte("block 11"))

	agg := NewAggregate(11, hash, len(publics))
	for i := 0; i < 5; i++ {
		agg.Add(i, SignAttestationBLS(secrets[i], aggChainID, 11, hash))
	}

	encoded, err := agg.Encode()
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeAggregate(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Count() != 5 || decoded.Number != 11 || decoded.BlockHash != hash {
		t.Fatalf("round trip changed the aggregate: %+v", decoded)
	}
	if _, err := decoded.Verify(aggChainID, publics); err != nil {
		t.Fatalf("the decoded aggregate did not verify: %v", err)
	}
}

func TestAggregateSizeIsIndependentOfSignerCount(t *testing.T) {
	// The whole point: a certificate for a thousand validators is the same
	// size as one for ten, plus one bit each.
	sizes := map[int]int{}
	for _, count := range []int{4, 32, 256} {
		secrets, publics := blsKeys(t, count)
		hash := common.Keccak256([]byte("block 1"))
		agg := NewAggregate(1, hash, count)
		for i := range secrets {
			agg.Add(i, SignAttestationBLS(secrets[i], aggChainID, 1, hash))
		}
		encoded, err := agg.Encode()
		if err != nil {
			t.Fatal(err)
		}
		sizes[count] = len(encoded)
		if _, err := agg.Verify(aggChainID, publics); err != nil {
			t.Fatalf("%d signers: %v", count, err)
		}
	}
	// Growing the set 64-fold must not grow the certificate more than the
	// bitfield does.
	growth := sizes[256] - sizes[4]
	if growth > 64 {
		t.Fatalf("certificate grew by %d bytes from 4 to 256 signers", growth)
	}
	t.Logf("certificate sizes: %v bytes", sizes)
}
