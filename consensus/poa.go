// Package consensus decides which blocks are valid and who may produce them.
//
// The engine here is proof of authority: a fixed set of validators takes turns
// proposing blocks in round-robin order, and each block carries the proposer's
// signature over the header. It gives immediate finality within the validator
// set without the energy cost of proof of work, which is what a permissioned
// or bootstrapping network wants.
package consensus

import (
	"errors"
	"fmt"
	"math/big"
	"sort"
	"time"

	"layer1/common"
	"layer1/core"
	"layer1/crypto/secp256k1"
)

var (
	ErrUnauthorizedProposer = errors.New("consensus: block proposed by a non-validator")
	ErrWrongProposerTurn    = errors.New("consensus: proposer is out of turn")
	ErrMissingSeal          = errors.New("consensus: header has no proposer seal")
	ErrInvalidSeal          = errors.New("consensus: proposer seal is invalid")
	ErrFutureBlock          = errors.New("consensus: block timestamp is in the future")
	ErrTimestampTooEarly    = errors.New("consensus: block timestamp does not respect the block period")
	ErrUnknownParent        = errors.New("consensus: parent block is unknown")
	ErrInvalidNumber        = errors.New("consensus: block number does not follow its parent")
	ErrNoValidators         = errors.New("consensus: validator set is empty")
	ErrExtraDataTooLong     = errors.New("consensus: extra data exceeds the limit")
	ErrRoundTooHigh         = errors.New("consensus: round number is out of range")
)

// MaxExtraDataSize caps the free-form header field.
const MaxExtraDataSize = 32

// AllowedFutureDrift is how far ahead of local time a block may be stamped
// before it is rejected outright, which tolerates ordinary clock skew.
const AllowedFutureDrift = 15 * time.Second

// HeaderReader is the part of the chain the engine needs to verify a header.
type HeaderReader interface {
	GetHeaderByHash(hash common.Hash) *core.Header
	GetHeaderByNumber(number uint64) *core.Header
}

// Engine produces and validates blocks.
type Engine interface {
	// Author recovers the address that sealed a header.
	Author(header *core.Header) (common.Address, error)
	// VerifyHeader checks a header against its parent.
	VerifyHeader(chain HeaderReader, header, parent *core.Header) error
	// Prepare fills in the consensus fields of a header being built.
	Prepare(chain HeaderReader, header *core.Header) error
	// Seal signs a block as its proposer.
	Seal(block *core.Block, key *secp256k1.PrivateKey) (*core.Block, error)
	// ProposerAt returns whose turn it is at the given height in round 0.
	ProposerAt(number uint64) (common.Address, error)
	// ProposerAtRound returns whose turn it is in a given round.
	ProposerAtRound(number, round uint64) (common.Address, error)
	// Validators returns the authorized set.
	Validators() []common.Address
	// Quorum returns the number of attestations that finalize a block.
	Quorum() int
}

// ValidatorSetProvider supplies the validator set for a given height, read from
// chain state. With one attached the engine becomes proof of stake: the set is
// consensus state that deposits and exits change, rather than configuration.
type ValidatorSetProvider interface {
	// ValidatorsAt returns the set that governs the given block height.
	ValidatorsAt(blockNumber uint64) ([]common.Address, error)
}

// PoA is a round-based engine over a validator set. The set is fixed at genesis
// unless a ValidatorSetProvider is attached, in which case it is whatever the
// staking registry says it is.
type PoA struct {
	validators []common.Address
	period     uint64
	// roundTimeout is how long a round lasts. If the scheduled proposer has
	// not produced a block within it, the next validator in the rotation may
	// take over. Without this the chain stops dead at the first outage.
	roundTimeout uint64
	// now is the clock, replaceable in tests.
	now func() time.Time

	// provider, when set, replaces the static set with one read from state.
	provider ValidatorSetProvider
}

// SetValidatorProvider makes the validator set dynamic.
func (p *PoA) SetValidatorProvider(provider ValidatorSetProvider) { p.provider = provider }

// setFor returns the validator set governing a height, sorted so every node
// derives the same rotation from the same set.
func (p *PoA) setFor(blockNumber uint64) []common.Address {
	if p.provider == nil {
		return p.validators
	}
	set, err := p.provider.ValidatorsAt(blockNumber)
	if err != nil || len(set) == 0 {
		// A set that cannot be read is not an empty set. Falling back to the
		// genesis validators keeps the chain verifiable rather than declaring
		// every block invalid.
		return p.validators
	}
	sorted := make([]common.Address, len(set))
	copy(sorted, set)
	sort.Slice(sorted, func(i, j int) bool { return string(sorted[i][:]) < string(sorted[j][:]) })
	return sorted
}

// NewPoA builds an engine over a validator set. The set is sorted so every node
// derives the same proposer schedule regardless of configuration order.
func NewPoA(validators []common.Address, period uint64) (*PoA, error) {
	if len(validators) == 0 {
		return nil, ErrNoValidators
	}
	sorted := make([]common.Address, len(validators))
	copy(sorted, validators)
	sort.Slice(sorted, func(i, j int) bool {
		return string(sorted[i][:]) < string(sorted[j][:])
	})
	// Reject duplicates: they would silently give one validator extra turns.
	for i := 1; i < len(sorted); i++ {
		if sorted[i] == sorted[i-1] {
			return nil, fmt.Errorf("consensus: validator %s listed twice", sorted[i])
		}
	}
	if period == 0 {
		period = 1
	}
	return &PoA{
		validators:   sorted,
		period:       period,
		roundTimeout: period,
		now:          time.Now,
	}, nil
}

// SetRoundTimeout overrides how long a proposer has before the next validator
// may take over.
func (p *PoA) SetRoundTimeout(seconds uint64) {
	if seconds == 0 {
		seconds = 1
	}
	p.roundTimeout = seconds
}

// RoundTimeout returns the per-round timeout in seconds.
func (p *PoA) RoundTimeout() uint64 { return p.roundTimeout }

// Quorum returns the number of attestations that finalize a block.
func (p *PoA) Quorum() int { return core.Quorum(len(p.validators)) }

// SetClock replaces the engine's clock. Tests use it to control timing.
func (p *PoA) SetClock(now func() time.Time) { p.now = now }

// Period returns the target seconds between blocks.
func (p *PoA) Period() uint64 { return p.period }

// Validators returns a copy of the authorized set.
func (p *PoA) Validators() []common.Address {
	out := make([]common.Address, len(p.validators))
	copy(out, p.validators)
	return out
}

// IsValidator reports whether addr may propose blocks.
func (p *PoA) IsValidator(addr common.Address) bool {
	for _, v := range p.validators {
		if v == addr {
			return true
		}
	}
	return false
}

// ProposerAt returns the validator scheduled to propose at a height.
func (p *PoA) ProposerAt(number uint64) (common.Address, error) {
	return p.ProposerAtRound(number, 0)
}

// ProposerAtRound returns the validator entitled to propose at a height in a
// given round. Each round hands the turn to the next validator in the
// rotation, so an unavailable proposer costs one round rather than the chain.
func (p *PoA) ProposerAtRound(number, round uint64) (common.Address, error) {
	set := p.setFor(number)
	if len(set) == 0 {
		return common.Address{}, ErrNoValidators
	}
	return set[(number+round)%uint64(len(set))], nil
}

// ValidatorsFor returns the set governing a height.
func (p *PoA) ValidatorsFor(blockNumber uint64) []common.Address {
	set := p.setFor(blockNumber)
	out := make([]common.Address, len(set))
	copy(out, set)
	return out
}

// IsValidatorAt reports whether an address is in the set at a height.
func (p *PoA) IsValidatorAt(addr common.Address, blockNumber uint64) bool {
	for _, v := range p.setFor(blockNumber) {
		if v == addr {
			return true
		}
	}
	return false
}

// QuorumFor returns how many attestations finalize a block at a height.
func (p *PoA) QuorumFor(blockNumber uint64) int { return core.Quorum(len(p.setFor(blockNumber))) }

// earliestTimeFor returns the first timestamp at which a block for the given
// round is permitted. A fallback proposer has to wait out the rounds before
// it, which is what stops it from racing the validator whose turn it is.
func (p *PoA) earliestTimeFor(parentTime, round uint64) uint64 {
	return parentTime + p.period + round*p.roundTimeout
}

// RoundFor returns the highest round whose start time has passed.
func (p *PoA) RoundFor(parentTime uint64, at time.Time) uint64 {
	now := uint64(at.Unix())
	earliest := p.earliestTimeFor(parentTime, 0)
	if now <= earliest || p.roundTimeout == 0 {
		return 0
	}
	return (now - earliest) / p.roundTimeout
}

// Author recovers the address that sealed a header.
func (p *PoA) Author(header *core.Header) (common.Address, error) {
	if len(header.ProposerSeal) == 0 {
		return common.Address{}, ErrMissingSeal
	}
	sig, err := secp256k1.ParseSignature(header.ProposerSeal)
	if err != nil {
		return common.Address{}, fmt.Errorf("%w: %v", ErrInvalidSeal, err)
	}
	digest := header.SealingHash()
	pub, err := secp256k1.Recover(digest[:], sig)
	if err != nil {
		return common.Address{}, fmt.Errorf("%w: %v", ErrInvalidSeal, err)
	}
	return common.BytesToAddress(common.Keccak256(pub.Bytes()).Bytes()[12:]), nil
}

// VerifyHeader checks everything the engine is responsible for: the block's
// position in the chain, its timing, and that the right validator sealed it.
func (p *PoA) VerifyHeader(chain HeaderReader, header, parent *core.Header) error {
	if header.Number == nil {
		return ErrInvalidNumber
	}
	if parent == nil {
		return fmt.Errorf("%w: %s", ErrUnknownParent, header.ParentHash)
	}
	if want := new(big.Int).Add(parent.Number, big.NewInt(1)); header.Number.Cmp(want) != 0 {
		return fmt.Errorf("%w: got %s, want %s", ErrInvalidNumber, header.Number, want)
	}
	if header.ParentHash != parent.Hash() {
		return fmt.Errorf("%w: header points at %s, parent hashes to %s", ErrUnknownParent, header.ParentHash, parent.Hash())
	}
	if len(header.Extra) > MaxExtraDataSize {
		return fmt.Errorf("%w: %d bytes", ErrExtraDataTooLong, len(header.Extra))
	}

	// Timing. A block must respect the block period, and a block claiming a
	// fallback round must additionally have waited out every round before it.
	// That wait is the whole safety argument for the fallback: a validator
	// cannot seize a turn that is not yet forfeit.
	set := p.setFor(header.NumberU64())
	if header.Round > uint64(len(set)) {
		return fmt.Errorf("%w: round %d exceeds the validator count", ErrRoundTooHigh, header.Round)
	}
	earliest := p.earliestTimeFor(parent.Time, header.Round)
	if header.Time < earliest {
		return fmt.Errorf("%w: %d is before round %d opens at %d",
			ErrTimestampTooEarly, header.Time, header.Round, earliest)
	}
	if header.Time > uint64(p.now().Add(AllowedFutureDrift).Unix()) {
		return fmt.Errorf("%w: %d", ErrFutureBlock, header.Time)
	}

	proposer, err := p.Author(header)
	if err != nil {
		return err
	}
	if !p.IsValidatorAt(proposer, header.NumberU64()) {
		return fmt.Errorf("%w: %s", ErrUnauthorizedProposer, proposer)
	}
	expected, err := p.ProposerAtRound(header.Number.Uint64(), header.Round)
	if err != nil {
		return err
	}
	if proposer != expected {
		return fmt.Errorf("%w: %s sealed block %s round %d, expected %s",
			ErrWrongProposerTurn, proposer, header.Number, header.Round, expected)
	}
	// The proposer is also credited as the block's coinbase, so fees go to
	// whoever actually did the work.
	if header.Coinbase != proposer {
		return fmt.Errorf("consensus: coinbase %s does not match proposer %s", header.Coinbase, proposer)
	}
	return nil
}

// Prepare fills in the consensus-controlled fields of a header being built.
func (p *PoA) Prepare(chain HeaderReader, header *core.Header) error {
	parent := chain.GetHeaderByHash(header.ParentHash)
	if parent == nil {
		return fmt.Errorf("%w: %s", ErrUnknownParent, header.ParentHash)
	}
	// The round follows from how long the parent has been unextended, so a
	// proposer only claims a fallback turn once the earlier ones have lapsed.
	round := p.RoundFor(parent.Time, p.now())
	if max := uint64(len(p.setFor(header.NumberU64()))); round > max {
		round = max
	}
	header.Round = round

	proposer, err := p.ProposerAtRound(header.NumberU64(), round)
	if err != nil {
		return err
	}
	header.Coinbase = proposer

	earliest := p.earliestTimeFor(parent.Time, round)
	now := uint64(p.now().Unix())
	if now < earliest {
		header.Time = earliest
	} else {
		header.Time = now
	}
	return nil
}

// Seal signs the block with the proposer's key.
func (p *PoA) Seal(block *core.Block, key *secp256k1.PrivateKey) (*core.Block, error) {
	proposer, err := p.ProposerAtRound(block.NumberU64(), block.Round())
	if err != nil {
		return nil, err
	}
	signer := common.BytesToAddress(common.Keccak256(key.PublicKey().Bytes()).Bytes()[12:])
	if signer != proposer {
		return nil, fmt.Errorf("%w: %s cannot seal block %d round %d, it is %s's turn",
			ErrWrongProposerTurn, signer, block.NumberU64(), block.Round(), proposer)
	}

	digest := block.SealingHash()
	sig, err := secp256k1.Sign(key, digest[:])
	if err != nil {
		return nil, err
	}
	return block.WithSeal(sig.Bytes()), nil
}

// NextProposalTime returns when the validator may seal the next block.
func (p *PoA) NextProposalTime(parent *core.Header) time.Time {
	return time.Unix(int64(parent.Time+p.period), 0)
}

// IsMyTurn reports whether addr may propose the block after parent, taking
// into account any rounds that have already lapsed.
func (p *PoA) IsMyTurn(addr common.Address, nextNumber uint64, parentTime uint64) bool {
	round := p.RoundFor(parentTime, p.now())
	if max := uint64(len(p.setFor(nextNumber))); round > max {
		round = max
	}
	proposer, err := p.ProposerAtRound(nextNumber, round)
	return err == nil && proposer == addr
}
