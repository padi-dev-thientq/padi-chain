package consensus

import (
	"errors"
	"fmt"
	"math/big"
	"sync"

	"layer1/common"
	"layer1/core"
	"layer1/crypto/secp256k1"
)

var (
	ErrConflictsWithFinal   = errors.New("consensus: block conflicts with finalized history")
	ErrJustificationInvalid = errors.New("consensus: header justification is not a valid quorum certificate")
	ErrEquivocation         = errors.New("consensus: validator signed conflicting attestations")
)

// AttestationPool collects votes until they form a quorum, and notices when a
// validator votes for two different blocks at the same height.
//
// Equivocation is the only way a finalized block can be reversed, so the pool
// treats detecting it as a first-class job rather than a side effect.
type AttestationPool struct {
	mu sync.RWMutex

	chainID    *big.Int
	validators map[common.Address]struct{}
	size       int

	// votes maps height -> block hash -> validator -> attestation.
	votes map[uint64]map[common.Hash]map[common.Address]*core.Attestation
	// byValidator maps height -> validator -> the block it voted for, which is
	// what makes a second, different vote detectable in constant time.
	byValidator map[uint64]map[common.Address]*core.Attestation

	evidence []*core.Equivocation

	// finalized is the highest height a quorum has been reached at.
	finalized uint64
	// retain bounds how much history the pool keeps.
	retain uint64
}

// NewAttestationPool creates a pool for a validator set.
func NewAttestationPool(chainID *big.Int, validators []common.Address) *AttestationPool {
	set := make(map[common.Address]struct{}, len(validators))
	for _, v := range validators {
		set[v] = struct{}{}
	}
	return &AttestationPool{
		chainID:     new(big.Int).Set(chainID),
		validators:  set,
		size:        len(validators),
		votes:       make(map[uint64]map[common.Hash]map[common.Address]*core.Attestation),
		byValidator: make(map[uint64]map[common.Address]*core.Attestation),
		retain:      256,
	}
}

// Quorum returns the number of votes a certificate needs.
func (p *AttestationPool) Quorum() int { return core.Quorum(p.size) }

// Add records an attestation and reports whether it was new.
//
// An attestation that conflicts with one already seen from the same validator
// is recorded as evidence and rejected: it must not be counted toward any
// quorum, or a single equivocating validator could be counted twice.
func (p *AttestationPool) Add(attestation *core.Attestation) (bool, error) {
	attester, err := attestation.Attester(p.chainID)
	if err != nil {
		return false, err
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	if _, ok := p.validators[attester]; !ok {
		return false, fmt.Errorf("%w: %s", core.ErrUnknownAttester, attester)
	}
	// Votes for already-finalized history change nothing.
	if attestation.Number <= p.finalized && p.finalized > 0 {
		return false, nil
	}

	byValidator := p.byValidator[attestation.Number]
	if byValidator == nil {
		byValidator = make(map[common.Address]*core.Attestation)
		p.byValidator[attestation.Number] = byValidator
	}

	if previous, ok := byValidator[attester]; ok {
		if previous.BlockHash == attestation.BlockHash {
			return false, nil // the same vote again
		}
		proof, err := core.DetectEquivocation(p.chainID, previous, attestation)
		if err != nil {
			return false, err
		}
		if proof != nil {
			p.evidence = append(p.evidence, proof)
			return false, fmt.Errorf("%w: %s at height %d", ErrEquivocation, attester, attestation.Number)
		}
		return false, nil
	}

	byValidator[attester] = attestation

	byHash := p.votes[attestation.Number]
	if byHash == nil {
		byHash = make(map[common.Hash]map[common.Address]*core.Attestation)
		p.votes[attestation.Number] = byHash
	}
	if byHash[attestation.BlockHash] == nil {
		byHash[attestation.BlockHash] = make(map[common.Address]*core.Attestation)
	}
	byHash[attestation.BlockHash][attester] = attestation
	return true, nil
}

// Certificate returns a quorum certificate for a block, or nil if the votes
// collected so far fall short.
func (p *AttestationPool) Certificate(number uint64, blockHash common.Hash) *core.QuorumCert {
	p.mu.RLock()
	defer p.mu.RUnlock()

	votes := p.votes[number][blockHash]
	if len(votes) < p.Quorum() {
		return nil
	}
	list := make([]*core.Attestation, 0, len(votes))
	for _, a := range votes {
		list = append(list, a)
	}
	qc, err := core.NewQuorumCert(number, blockHash, list)
	if err != nil {
		return nil
	}
	return qc
}

// VoteCount returns how many distinct validators have voted for a block.
func (p *AttestationPool) VoteCount(number uint64, blockHash common.Hash) int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return len(p.votes[number][blockHash])
}

// MarkFinalized records that a height is final and drops the history the pool
// no longer needs.
func (p *AttestationPool) MarkFinalized(number uint64) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if number <= p.finalized {
		return
	}
	p.finalized = number

	if number <= p.retain {
		return
	}
	cutoff := number - p.retain
	for height := range p.votes {
		if height < cutoff {
			delete(p.votes, height)
			delete(p.byValidator, height)
		}
	}
}

// Finalized returns the highest finalized height the pool knows of.
func (p *AttestationPool) Finalized() uint64 {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.finalized
}

// Evidence returns the equivocation proofs collected so far.
func (p *AttestationPool) Evidence() []*core.Equivocation {
	p.mu.RLock()
	defer p.mu.RUnlock()
	out := make([]*core.Equivocation, len(p.evidence))
	copy(out, p.evidence)
	return out
}

// AddEvidence records an equivocation proof received from a peer, after
// re-verifying it. Evidence is never trusted on a peer's word: a forged proof
// would otherwise let anyone get a validator slashed.
func (p *AttestationPool) AddEvidence(proof *core.Equivocation) error {
	if err := proof.Verify(p.chainID); err != nil {
		return err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if _, ok := p.validators[proof.Validator]; !ok {
		return fmt.Errorf("%w: %s", core.ErrUnknownAttester, proof.Validator)
	}
	for _, existing := range p.evidence {
		if existing.Validator == proof.Validator && existing.Number == proof.Number {
			return nil // already known
		}
	}
	p.evidence = append(p.evidence, proof)
	return nil
}

// Attest signs a vote for a block.
func (p *AttestationPool) Attest(key *secp256k1.PrivateKey, number uint64, blockHash common.Hash) (*core.Attestation, error) {
	return core.SignAttestation(key, p.chainID, number, blockHash)
}

// VerifyJustification checks a header's embedded certificate.
func (p *PoA) VerifyJustification(chainID *big.Int, header *core.Header) (*core.QuorumCert, error) {
	qc, err := core.DecodeQuorumCert(header.Justification)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrJustificationInvalid, err)
	}
	if qc == nil {
		return nil, nil
	}
	// A justification may only point backwards: a block cannot carry proof
	// that it or a descendant is already final.
	if qc.Number >= header.NumberU64() {
		return nil, fmt.Errorf("%w: certificate for %d in block %d", ErrJustificationInvalid, qc.Number, header.NumberU64())
	}
	if _, err := qc.Verify(chainID, p.validators); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrJustificationInvalid, err)
	}
	return qc, nil
}
