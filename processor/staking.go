package processor

import (
	"errors"
	"fmt"
	"math/big"

	"layer1/common"
	"layer1/core"
	"layer1/rlp"
	"layer1/staking"
	"layer1/state"
)

// Staking operations arrive as ordinary transactions addressed to the staking
// account, the way Ethereum's deposits go to its deposit contract. Handling
// them natively rather than in the EVM keeps the registry's invariants in one
// place, and means a validator's stake cannot be moved by a contract bug.

// Operation selectors, in the first byte of the call data.
const (
	OpDeposit  byte = 0x01 // 0x01 || withdrawalAddress(20)
	OpExit     byte = 0x02 // 0x02
	OpWithdraw byte = 0x03 // 0x03
	OpSlash    byte = 0x04 // 0x04 || RLP equivocation evidence
)

// Gas charged for staking operations, on top of the intrinsic cost. These are
// priced as expensive storage writes because that is what they are.
const (
	GasDeposit  uint64 = 60000
	GasExit     uint64 = 30000
	GasWithdraw uint64 = 30000
	GasSlash    uint64 = 80000
)

var (
	ErrUnknownStakingOp = errors.New("processor: unknown staking operation")
	ErrMalformedStaking = errors.New("processor: malformed staking call data")
	ErrNotTheValidator  = errors.New("processor: only a validator may act on its own stake")
)

// IsStakingCall reports whether a message targets the staking account.
func IsStakingCall(msg *Message) bool {
	return msg.To != nil && *msg.To == staking.StakingAddress
}

// applyStakingCall executes a staking operation and returns the gas it used.
func (st *StateTransition) applyStakingCall(epoch uint64) (uint64, error) {
	data := st.msg.Data
	if len(data) == 0 {
		return 0, fmt.Errorf("%w: no operation selector", ErrMalformedStaking)
	}

	manager := staking.NewManager(st.state)

	switch data[0] {
	case OpDeposit:
		if len(data) < 21 {
			return 0, fmt.Errorf("%w: a deposit needs a withdrawal address", ErrMalformedStaking)
		}
		if st.msg.Value.Sign() <= 0 {
			return 0, fmt.Errorf("%w: a deposit needs value", ErrMalformedStaking)
		}
		withdrawal := common.BytesToAddress(data[1:21])
		// The value has already moved to the staking account; this records the
		// claim on it. A validator stakes for itself: the sender is the key
		// that will sign blocks and attestations.
		if _, err := manager.Deposit(st.msg.From, withdrawal, st.msg.Value, epoch); err != nil {
			return 0, err
		}
		return GasDeposit, nil

	case OpExit:
		if _, err := manager.RequestExit(st.msg.From, epoch); err != nil {
			return 0, err
		}
		return GasExit, nil

	case OpWithdraw:
		if _, err := manager.Withdraw(st.msg.From, epoch); err != nil {
			return 0, err
		}
		return GasWithdraw, nil

	case OpSlash:
		if len(data) < 2 {
			return 0, fmt.Errorf("%w: slashing needs evidence", ErrMalformedStaking)
		}
		var evidence core.Equivocation
		if err := rlp.Decode(data[1:], &evidence); err != nil {
			return 0, fmt.Errorf("%w: %v", ErrMalformedStaking, err)
		}
		// The proof is re-verified from the signatures rather than believed.
		// Anyone may report; nobody may forge.
		if err := evidence.Verify(st.evm.ChainConfig.ChainID); err != nil {
			return 0, fmt.Errorf("processor: equivocation evidence: %w", err)
		}
		if _, _, err := manager.Slash(evidence.Validator, epoch); err != nil {
			return 0, err
		}
		return GasSlash, nil

	default:
		return 0, fmt.Errorf("%w: 0x%02x", ErrUnknownStakingOp, data[0])
	}
}

// EpochParticipation derives who attested during an epoch from the quorum
// certificates its blocks carried.
//
// Participation is read off the chain rather than reported by anyone: a
// validator's reward depends on a signature it actually produced, which is not
// something a proposer can grant or withhold at will.
func EpochParticipation(chain ChainContext, chainID *big.Int, epoch uint64) *staking.Participation {
	participation := staking.NewParticipation()
	if epoch == 0 {
		return participation
	}

	start := staking.EpochStart(epoch)
	end := start + staking.EpochLength

	for number := start; number < end; number++ {
		header := chain.GetHeaderByNumber(number)
		if header == nil {
			continue
		}
		participation.MarkProposed(header.Coinbase)

		qc, err := core.DecodeQuorumCert(header.Justification)
		if err != nil || qc.IsEmpty() {
			continue
		}
		for _, signature := range qc.Signatures {
			attestation := &core.Attestation{
				Number:    qc.Number,
				BlockHash: qc.BlockHash,
				Signature: signature,
			}
			attester, err := attestation.Attester(chainID)
			if err != nil {
				continue
			}
			participation.MarkAttested(attester)
		}
	}
	return participation
}

// ProcessEpochBoundary runs the staking transition when a block starts a new
// epoch. It is part of block execution, so its effects are committed by the
// state root and every node reproduces them exactly.
func (p *Processor) ProcessEpochBoundary(statedb *state.StateDB, header *core.Header, finalizedNumber uint64) (*staking.EpochReport, error) {
	number := header.NumberU64()
	if !staking.IsEpochBoundary(number) {
		return nil, nil
	}
	epoch := staking.EpochOf(number)

	// The epoch that just ended is the one being rewarded.
	participation := EpochParticipation(p.chain, p.config.ChainID, epoch-1)

	manager := staking.NewManager(statedb)
	return manager.ProcessEpoch(epoch, participation, staking.EpochOf(finalizedNumber))
}
