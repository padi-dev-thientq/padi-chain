package core

import (
	"errors"
	"fmt"
	"math/big"
	"sort"

	"layer1/common"
	"layer1/crypto/bls12381"
)

// An attestation is a validator's signed statement that a block is the one it
// saw at that height. Once more than two thirds of the validator set has
// attested to a block, the block is final: reversing it would require a third
// of the set to have signed two conflicting statements, which is detectable and
// punishable.
//
// Votes are BLS signatures so they can be aggregated. A BLS signature does not
// reveal who produced it, so a vote carries the signer's index in the ordered
// validator set — the same index the aggregate's bitfield records.

var (
	ErrAttestationInvalid = errors.New("core: attestation signature is invalid")
	ErrQuorumNotMet       = errors.New("core: not enough attestations for a quorum")
	ErrDuplicateAttester  = errors.New("core: the same validator attested twice")
	ErrUnknownAttester    = errors.New("core: attestation from a non-validator")
	ErrWrongTarget        = errors.New("core: attestation targets a different block")
)

// Attestation is one validator's vote for a block, before aggregation.
type Attestation struct {
	Number    uint64
	BlockHash common.Hash
	Index     uint64
	Signature []byte
}

// SignAttestation produces a validator's vote for a block.
func SignAttestation(key *bls12381.SecretKey, chainID *big.Int, index uint64, number uint64, blockHash common.Hash) *Attestation {
	return &Attestation{
		Number:    number,
		BlockHash: blockHash,
		Index:     index,
		Signature: SignAttestationBLS(key, chainID, number, blockHash),
	}
}

// Verify checks the vote against the public key of the validator it names.
func (a *Attestation) Verify(chainID *big.Int, key *bls12381.PublicKey) error {
	if key == nil {
		return fmt.Errorf("%w: validator %d has no attestation key", ErrUnknownAttester, a.Index)
	}
	sig, err := bls12381.SignatureFromBytes(a.Signature)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrAttestationInvalid, err)
	}
	if !bls12381.Verify(key, AttestationMessage(chainID, a.Number, a.BlockHash), sig) {
		return ErrAttestationInvalid
	}
	return nil
}

// Hash identifies an attestation for gossip deduplication.
func (a *Attestation) Hash() common.Hash {
	return common.Keccak256(a.Signature)
}

// QuorumCert is proof that more than two thirds of the validator set attested
// to a block.
//
// It is an aggregate: one BLS signature and a bitfield naming who is in it,
// rather than one signature per validator. That is what keeps a certificate the
// same size — and the same cost to verify — whether ten validators signed or a
// hundred thousand.
type QuorumCert = AggregateAttestation

// NewQuorumCert assembles a certificate from individual votes, keyed by the
// signer's index in the ordered validator set.
func NewQuorumCert(number uint64, blockHash common.Hash, validators int, votes map[int][]byte) (*QuorumCert, error) {
	agg := NewAggregate(number, blockHash, validators)
	indices := make([]int, 0, len(votes))
	for index := range votes {
		indices = append(indices, index)
	}
	// Aggregation is commutative, but ordering the inputs keeps the encoding
	// identical across nodes that collected the same votes in different orders.
	sort.Ints(indices)
	for _, index := range indices {
		if err := agg.Add(index, votes[index]); err != nil {
			return nil, err
		}
	}
	return agg, nil
}

// Quorum returns the number of attestations needed from a validator set of the
// given size: more than two thirds. With that threshold two conflicting
// certificates at the same height require at least a third of validators to
// have signed both, which is exactly the condition slashing punishes.
func Quorum(validators int) int {
	if validators <= 0 {
		return 0
	}
	return validators*2/3 + 1
}

// DecodeQuorumCert parses a certificate from a header.
func DecodeQuorumCert(data []byte) (*QuorumCert, error) { return DecodeAggregate(data) }

// Equivocation is proof that a validator attested to two different blocks at
// the same height. It is the misbehaviour a proof-of-stake network slashes for,
// and the only way finality can be violated without a two-thirds majority.
type Equivocation struct {
	Validator common.Address
	Number    uint64
	Index     uint64
	First     *Attestation
	Second    *Attestation
}

// DetectEquivocation reports whether two votes from the same validator
// conflict. Both must verify against the validator's key, or the "proof" would
// be nothing more than an accusation.
func DetectEquivocation(chainID *big.Int, key *bls12381.PublicKey, a, b *Attestation) (*Equivocation, error) {
	if a.Number != b.Number || a.Index != b.Index {
		return nil, nil // different heights or different validators
	}
	if a.BlockHash == b.BlockHash {
		return nil, nil // the same vote, seen twice
	}
	if err := a.Verify(chainID, key); err != nil {
		return nil, err
	}
	if err := b.Verify(chainID, key); err != nil {
		return nil, err
	}
	return &Equivocation{Number: a.Number, Index: a.Index, First: a, Second: b}, nil
}

// Verify re-checks an equivocation proof from scratch, so evidence received
// from a peer is never trusted on its word: a forged proof would otherwise let
// anyone get a validator slashed.
func (e *Equivocation) Verify(chainID *big.Int, key *bls12381.PublicKey) error {
	if e.First == nil || e.Second == nil {
		return errors.New("core: incomplete equivocation evidence")
	}
	proof, err := DetectEquivocation(chainID, key, e.First, e.Second)
	if err != nil {
		return err
	}
	if proof == nil {
		return errors.New("core: the attestations do not conflict")
	}
	if proof.Number != e.Number || proof.Index != e.Index {
		return fmt.Errorf("core: evidence names validator %d at height %d, the signatures say %d at %d",
			e.Index, e.Number, proof.Index, proof.Number)
	}
	return nil
}
