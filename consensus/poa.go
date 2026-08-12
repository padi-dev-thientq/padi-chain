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
	// ProposerAt returns whose turn it is at the given height.
	ProposerAt(number uint64) (common.Address, error)
	// Validators returns the authorized set.
	Validators() []common.Address
}

// PoA is a round-robin proof-of-authority engine.
type PoA struct {
	validators []common.Address
	period     uint64
	// now is the clock, replaceable in tests.
	now func() time.Time
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
	return &PoA{validators: sorted, period: period, now: time.Now}, nil
}

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

// ProposerAt returns the validator whose turn it is at a height.
func (p *PoA) ProposerAt(number uint64) (common.Address, error) {
	if len(p.validators) == 0 {
		return common.Address{}, ErrNoValidators
	}
	return p.validators[number%uint64(len(p.validators))], nil
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

	// Timing: a block may not precede its parent by the block period, and may
	// not be stamped meaningfully in the future.
	if header.Time < parent.Time+p.period {
		return fmt.Errorf("%w: %d is less than parent %d plus period %d", ErrTimestampTooEarly, header.Time, parent.Time, p.period)
	}
	if header.Time > uint64(p.now().Add(AllowedFutureDrift).Unix()) {
		return fmt.Errorf("%w: %d", ErrFutureBlock, header.Time)
	}

	proposer, err := p.Author(header)
	if err != nil {
		return err
	}
	if !p.IsValidator(proposer) {
		return fmt.Errorf("%w: %s", ErrUnauthorizedProposer, proposer)
	}
	expected, err := p.ProposerAt(header.Number.Uint64())
	if err != nil {
		return err
	}
	if proposer != expected {
		return fmt.Errorf("%w: %s sealed block %s, expected %s", ErrWrongProposerTurn, proposer, header.Number, expected)
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
	proposer, err := p.ProposerAt(header.NumberU64())
	if err != nil {
		return err
	}
	header.Coinbase = proposer

	// Never stamp a block earlier than the period allows.
	earliest := parent.Time + p.period
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
	proposer, err := p.ProposerAt(block.NumberU64())
	if err != nil {
		return nil, err
	}
	signer := common.BytesToAddress(common.Keccak256(key.PublicKey().Bytes()).Bytes()[12:])
	if signer != proposer {
		return nil, fmt.Errorf("%w: %s cannot seal block %d, it is %s's turn", ErrWrongProposerTurn, signer, block.NumberU64(), proposer)
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

// IsMyTurn reports whether addr proposes the block after parent.
func (p *PoA) IsMyTurn(addr common.Address, nextNumber uint64) bool {
	proposer, err := p.ProposerAt(nextNumber)
	return err == nil && proposer == addr
}
