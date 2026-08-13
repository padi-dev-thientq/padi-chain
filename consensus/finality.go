package consensus

import (
	"errors"
	"fmt"
	"math/big"
	"sync"

	"layer1/common"
	"layer1/core"
	"layer1/crypto/bls12381"
)

var (
	ErrConflictsWithFinal   = errors.New("consensus: block conflicts with finalized history")
	ErrJustificationInvalid = errors.New("consensus: header justification is not a valid quorum certificate")
	ErrEquivocation         = errors.New("consensus: validator signed conflicting attestations")
	ErrUnknownIndex         = errors.New("consensus: attestation names a validator outside the set")
)

// AttestationPool collects votes until they form a quorum, and notices when a
// validator votes for two different blocks at the same height.
//
// Equivocation is the only way a finalized block can be reversed, so the pool
// treats detecting it as a first-class job rather than a side effect.
//
// Votes are BLS signatures indexed by position in the ordered validator set,
// which is what lets a quorum collapse into a single aggregate signature.
type AttestationPool struct {
	mu sync.RWMutex

	chainID *big.Int
	// keys is the ordered attestation key of each validator; a vote's index
	// selects one. The order has to match what every other node derives.
	keys []*bls12381.PublicKey
	// addresses is the same set by address, for naming a slashed validator.
	addresses []common.Address

	// votes maps height -> block hash -> validator index -> signature.
	votes map[uint64]map[common.Hash]map[int][]byte
	// byIndex maps height -> validator index -> the vote it cast, which makes
	// a second, different vote detectable in constant time.
	byIndex map[uint64]map[int]*core.Attestation

	evidence []*core.Equivocation

	finalized uint64
	retain    uint64
}

// NewAttestationPool creates a pool for a validator set.
func NewAttestationPool(chainID *big.Int, addresses []common.Address, keys [][]byte) *AttestationPool {
	p := &AttestationPool{
		chainID: new(big.Int).Set(chainID),
		votes:   make(map[uint64]map[common.Hash]map[int][]byte),
		byIndex: make(map[uint64]map[int]*core.Attestation),
		retain:  256,
	}
	p.setValidators(addresses, keys)
	return p
}

func (p *AttestationPool) setValidators(addresses []common.Address, keys [][]byte) {
	p.addresses = append([]common.Address(nil), addresses...)
	p.keys = make([]*bls12381.PublicKey, len(keys))
	for i, raw := range keys {
		if len(raw) == 0 {
			continue // a validator with no registered key cannot attest
		}
		if key, err := bls12381.PublicKeyFromBytes(raw); err == nil {
			p.keys[i] = key
		}
	}
}

// UpdateValidators replaces the set the pool accepts votes from.
//
// Under proof of stake the set changes as validators join and leave, so a pool
// pinned to the genesis set would reject a new validator's votes and keep
// computing a quorum for a set that no longer exists. Votes already collected
// are kept: they were valid when cast, and a validator that has since left was
// still accountable for the height it voted at.
func (p *AttestationPool) UpdateValidators(addresses []common.Address, keys [][]byte) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.setValidators(addresses, keys)
}

// Size returns how many validators the pool is tracking.
func (p *AttestationPool) Size() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return len(p.keys)
}

// Quorum returns the number of votes a certificate needs.
func (p *AttestationPool) Quorum() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return core.Quorum(len(p.keys))
}

// Validators returns the set the pool currently accepts votes from.
func (p *AttestationPool) Validators() []common.Address {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return append([]common.Address(nil), p.addresses...)
}

// IndexOf returns a validator's position in the ordered set.
func (p *AttestationPool) IndexOf(addr common.Address) (int, bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	for i, candidate := range p.addresses {
		if candidate == addr {
			return i, true
		}
	}
	return 0, false
}

// Add records a vote and reports whether it was new.
//
// A vote that conflicts with one already seen from the same validator is
// recorded as evidence and rejected: it must not count toward any quorum, or a
// single equivocating validator could be counted twice.
func (p *AttestationPool) Add(attestation *core.Attestation) (bool, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	index := int(attestation.Index)
	if index < 0 || index >= len(p.keys) {
		return false, fmt.Errorf("%w: index %d of %d", ErrUnknownIndex, index, len(p.keys))
	}
	key := p.keys[index]
	if key == nil {
		return false, fmt.Errorf("%w: validator %d has no attestation key", ErrUnknownIndex, index)
	}
	// Votes for already-finalized history change nothing.
	if p.finalized > 0 && attestation.Number <= p.finalized {
		return false, nil
	}

	byIndex := p.byIndex[attestation.Number]
	if byIndex == nil {
		byIndex = make(map[int]*core.Attestation)
		p.byIndex[attestation.Number] = byIndex
	}

	if previous, ok := byIndex[index]; ok {
		if previous.BlockHash == attestation.BlockHash {
			return false, nil // the same vote again
		}
		// Both votes are verified here rather than taken at face value: acting
		// on unverified evidence would let anyone get an honest validator
		// slashed by forging a vote in its name.
		proof, err := core.DetectEquivocation(p.chainID, key, previous, attestation)
		if err != nil {
			return false, err
		}
		if proof != nil {
			if index < len(p.addresses) {
				proof.Validator = p.addresses[index]
			}
			p.evidence = append(p.evidence, proof)
			return false, fmt.Errorf("%w: validator %d at height %d", ErrEquivocation, index, attestation.Number)
		}
		return false, nil
	}

	// The signature is deliberately not checked here.
	//
	// Verifying every vote on arrival costs one pairing check per vote, which
	// is exactly the work aggregation exists to avoid — the whole point is that
	// a quorum should cost two pairings, not two hundred. Instead the aggregate
	// is verified once when a certificate is built, and if it fails the pool
	// falls back to checking votes individually to find the culprit.
	//
	// The one case that cannot wait is a conflicting vote, because acting on it
	// gets a validator slashed. Those are verified below before any evidence is
	// recorded.
	byIndex[index] = attestation

	byHash := p.votes[attestation.Number]
	if byHash == nil {
		byHash = make(map[common.Hash]map[int][]byte)
		p.votes[attestation.Number] = byHash
	}
	if byHash[attestation.BlockHash] == nil {
		byHash[attestation.BlockHash] = make(map[int][]byte)
	}
	byHash[attestation.BlockHash][index] = attestation.Signature
	return true, nil
}

// Certificate returns a quorum certificate for a block, or nil if the votes
// collected so far fall short or do not verify.
//
// This is where signatures are actually checked: once, over the aggregate, for
// however many validators are in it. A single bad vote makes the aggregate fail
// without saying which one it was, so the fallback below finds and evicts it,
// and the next attempt succeeds with the rest.
func (p *AttestationPool) Certificate(number uint64, blockHash common.Hash) *core.QuorumCert {
	p.mu.Lock()
	defer p.mu.Unlock()

	for {
		votes := p.votes[number][blockHash]
		if len(votes) < core.Quorum(len(p.keys)) {
			return nil
		}
		qc, err := core.NewQuorumCert(number, blockHash, len(p.keys), votes)
		if err != nil {
			return nil
		}
		if _, err := qc.Verify(p.chainID, p.keys); err == nil {
			return qc
		}
		// Something in there does not verify. Find it the slow way, drop it,
		// and try again with what is left.
		if !p.evictInvalidLocked(number, blockHash) {
			return nil
		}
	}
}

// evictInvalidLocked removes votes that fail individual verification, and
// reports whether it removed any.
func (p *AttestationPool) evictInvalidLocked(number uint64, blockHash common.Hash) bool {
	votes := p.votes[number][blockHash]
	removed := false
	for index, signature := range votes {
		if index >= len(p.keys) || p.keys[index] == nil {
			delete(votes, index)
			removed = true
			continue
		}
		attestation := &core.Attestation{
			Number:    number,
			BlockHash: blockHash,
			Index:     uint64(index),
			Signature: signature,
		}
		if err := attestation.Verify(p.chainID, p.keys[index]); err != nil {
			delete(votes, index)
			delete(p.byIndex[number], index)
			removed = true
		}
	}
	return removed
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
			delete(p.byIndex, height)
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
	return append([]*core.Equivocation(nil), p.evidence...)
}

// AddEvidence records an equivocation proof received from a peer, after
// re-verifying it against the named validator's key.
func (p *AttestationPool) AddEvidence(proof *core.Equivocation) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	index := int(proof.Index)
	if index < 0 || index >= len(p.keys) || p.keys[index] == nil {
		return fmt.Errorf("%w: index %d", ErrUnknownIndex, index)
	}
	if err := proof.Verify(p.chainID, p.keys[index]); err != nil {
		return err
	}
	for _, existing := range p.evidence {
		if existing.Index == proof.Index && existing.Number == proof.Number {
			return nil // already known
		}
	}
	if index < len(p.addresses) {
		proof.Validator = p.addresses[index]
	}
	p.evidence = append(p.evidence, proof)
	return nil
}

// Attest signs a vote for a block on behalf of the validator at an index.
func (p *AttestationPool) Attest(key *bls12381.SecretKey, index uint64, number uint64, blockHash common.Hash) *core.Attestation {
	return core.SignAttestation(key, p.chainID, index, number, blockHash)
}

// VerifyJustification checks a header's embedded certificate against the
// attestation keys of the set that governed its height.
func (p *PoA) VerifyJustification(chainID *big.Int, keys []*bls12381.PublicKey, header *core.Header) (*core.QuorumCert, error) {
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
	if _, err := qc.Verify(chainID, keys); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrJustificationInvalid, err)
	}
	return qc, nil
}
