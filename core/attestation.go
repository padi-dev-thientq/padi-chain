package core

import (
	"errors"
	"fmt"
	"math/big"
	"sort"

	"layer1/common"
	"layer1/crypto/secp256k1"
	"layer1/rlp"
)

// An attestation is a validator's signed statement that a block is the one it
// saw at that height. Once more than two thirds of the validator set has
// attested to a block, the block is final: reversing it would require a third
// of the set to have signed two conflicting statements, which is detectable and
// punishable.

var (
	ErrAttestationInvalid = errors.New("core: attestation signature is invalid")
	ErrQuorumNotMet       = errors.New("core: not enough attestations for a quorum")
	ErrDuplicateAttester  = errors.New("core: the same validator attested twice")
	ErrUnknownAttester    = errors.New("core: attestation from a non-validator")
	ErrWrongTarget        = errors.New("core: attestation targets a different block")
)

// Attestation is one validator's vote for a block.
type Attestation struct {
	Number    uint64
	BlockHash common.Hash
	// Signature is 65 bytes of r || s || v over the attestation digest, from
	// which the attesting validator is recovered.
	Signature []byte
}

// AttestationDigest is what a validator signs. The chain id is bound in so an
// attestation cannot be replayed onto another network, and the domain string
// keeps it disjoint from every other signature this protocol produces.
func AttestationDigest(chainID *big.Int, number uint64, blockHash common.Hash) common.Hash {
	enc, err := rlp.Encode([]any{
		[]byte("layer1/attestation/v1"),
		chainID,
		number,
		blockHash,
	})
	if err != nil {
		panic(fmt.Sprintf("core: encoding attestation digest: %v", err))
	}
	return common.Keccak256(enc)
}

// SignAttestation produces a validator's vote for a block.
func SignAttestation(key *secp256k1.PrivateKey, chainID *big.Int, number uint64, blockHash common.Hash) (*Attestation, error) {
	digest := AttestationDigest(chainID, number, blockHash)
	sig, err := secp256k1.Sign(key, digest[:])
	if err != nil {
		return nil, err
	}
	return &Attestation{Number: number, BlockHash: blockHash, Signature: sig.Bytes()}, nil
}

// Attester recovers the validator that produced the attestation.
func (a *Attestation) Attester(chainID *big.Int) (common.Address, error) {
	sig, err := secp256k1.ParseSignature(a.Signature)
	if err != nil {
		return common.Address{}, fmt.Errorf("%w: %v", ErrAttestationInvalid, err)
	}
	if !secp256k1.IsLowS(sig.S) {
		return common.Address{}, fmt.Errorf("%w: non-canonical signature", ErrAttestationInvalid)
	}
	digest := AttestationDigest(chainID, a.Number, a.BlockHash)
	pub, err := secp256k1.Recover(digest[:], sig)
	if err != nil {
		return common.Address{}, fmt.Errorf("%w: %v", ErrAttestationInvalid, err)
	}
	return common.BytesToAddress(common.Keccak256(pub.Bytes()).Bytes()[12:]), nil
}

// Hash identifies an attestation for gossip deduplication.
func (a *Attestation) Hash() common.Hash {
	return common.Keccak256(a.Signature)
}

// QuorumCert is a set of attestations proving a block is final.
//
// It is embedded in a later block's header, which is what makes finality
// verifiable by a node that was not online to collect the votes itself.
type QuorumCert struct {
	Number     uint64
	BlockHash  common.Hash
	Signatures [][]byte
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

// NewQuorumCert assembles a certificate from attestations, all of which must
// target the same block.
func NewQuorumCert(number uint64, blockHash common.Hash, attestations []*Attestation) (*QuorumCert, error) {
	qc := &QuorumCert{Number: number, BlockHash: blockHash}
	for _, a := range attestations {
		if a.Number != number || a.BlockHash != blockHash {
			return nil, fmt.Errorf("%w: attestation for %d/%s in a certificate for %d/%s",
				ErrWrongTarget, a.Number, a.BlockHash, number, blockHash)
		}
		qc.Signatures = append(qc.Signatures, common.CopyBytes(a.Signature))
	}
	// A canonical ordering makes the certificate's encoding deterministic, so
	// two nodes that collected the same votes produce the same block.
	sort.Slice(qc.Signatures, func(i, j int) bool {
		return string(qc.Signatures[i]) < string(qc.Signatures[j])
	})
	return qc, nil
}

// IsEmpty reports whether the certificate carries no votes.
func (qc *QuorumCert) IsEmpty() bool {
	return qc == nil || len(qc.Signatures) == 0
}

// Encode serializes the certificate for inclusion in a header.
func (qc *QuorumCert) Encode() ([]byte, error) {
	if qc.IsEmpty() {
		return nil, nil
	}
	return rlp.Encode(qc)
}

// DecodeQuorumCert parses a certificate from a header.
func DecodeQuorumCert(data []byte) (*QuorumCert, error) {
	if len(data) == 0 {
		return nil, nil
	}
	qc := new(QuorumCert)
	if err := rlp.Decode(data, qc); err != nil {
		return nil, fmt.Errorf("core: decoding quorum certificate: %w", err)
	}
	return qc, nil
}

// Verify checks that the certificate carries a quorum of distinct, authorized
// signatures over its target, and returns the attesting validators.
func (qc *QuorumCert) Verify(chainID *big.Int, validators []common.Address) ([]common.Address, error) {
	if qc.IsEmpty() {
		return nil, ErrQuorumNotMet
	}

	authorized := make(map[common.Address]struct{}, len(validators))
	for _, v := range validators {
		authorized[v] = struct{}{}
	}

	seen := make(map[common.Address]struct{}, len(qc.Signatures))
	attesters := make([]common.Address, 0, len(qc.Signatures))

	for _, raw := range qc.Signatures {
		attestation := &Attestation{Number: qc.Number, BlockHash: qc.BlockHash, Signature: raw}
		attester, err := attestation.Attester(chainID)
		if err != nil {
			return nil, err
		}
		if _, ok := authorized[attester]; !ok {
			return nil, fmt.Errorf("%w: %s", ErrUnknownAttester, attester)
		}
		// Counting a validator twice would let a minority manufacture a quorum.
		if _, ok := seen[attester]; ok {
			return nil, fmt.Errorf("%w: %s", ErrDuplicateAttester, attester)
		}
		seen[attester] = struct{}{}
		attesters = append(attesters, attester)
	}

	if need := Quorum(len(validators)); len(attesters) < need {
		return nil, fmt.Errorf("%w: %d of %d, need %d", ErrQuorumNotMet, len(attesters), len(validators), need)
	}
	return attesters, nil
}

// Equivocation is proof that a validator attested to two different blocks at
// the same height. It is the misbehaviour a proof-of-stake network slashes for,
// and the only way finality can be violated without a two-thirds majority.
type Equivocation struct {
	Validator common.Address
	Number    uint64
	First     *Attestation
	Second    *Attestation
}

// DetectEquivocation reports whether two attestations from the same validator
// conflict.
func DetectEquivocation(chainID *big.Int, a, b *Attestation) (*Equivocation, error) {
	if a.Number != b.Number {
		return nil, nil // different heights: not a conflict
	}
	if a.BlockHash == b.BlockHash {
		return nil, nil // the same vote, seen twice
	}

	first, err := a.Attester(chainID)
	if err != nil {
		return nil, err
	}
	second, err := b.Attester(chainID)
	if err != nil {
		return nil, err
	}
	if first != second {
		return nil, nil // two validators disagreeing is normal, not misbehaviour
	}
	return &Equivocation{Validator: first, Number: a.Number, First: a, Second: b}, nil
}

// Verify re-checks an equivocation proof from scratch, so evidence received
// from a peer is never trusted on its word.
func (e *Equivocation) Verify(chainID *big.Int) error {
	if e.First == nil || e.Second == nil {
		return errors.New("core: incomplete equivocation evidence")
	}
	proof, err := DetectEquivocation(chainID, e.First, e.Second)
	if err != nil {
		return err
	}
	if proof == nil {
		return errors.New("core: the attestations do not conflict")
	}
	if proof.Validator != e.Validator || proof.Number != e.Number {
		return fmt.Errorf("core: evidence names %s at %d, the signatures say %s at %d",
			e.Validator, e.Number, proof.Validator, proof.Number)
	}
	return nil
}
