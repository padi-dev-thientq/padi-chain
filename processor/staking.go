package processor

import (
	"errors"
	"fmt"
	"math/big"

	"padi-chain/common"
	"padi-chain/core"
	"padi-chain/crypto/bls12381"
	"padi-chain/rlp"
	"padi-chain/staking"
	"padi-chain/state"
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

// depositWithKeyLength is the call data length of a deposit that registers an
// attestation key: the selector, the withdrawal address, the key and its proof
// of possession.
const depositWithKeyLength = 1 + 20 + staking.BLSPublicKeyLength + 96

// Gas charged for staking operations, on top of the intrinsic cost. These are
// priced as expensive storage writes because that is what they are.
const (
	GasDeposit  uint64 = 60000
	GasExit     uint64 = 30000
	GasWithdraw uint64 = 30000
	GasSlash    uint64 = 80000
	// Registering an attestation key costs far more than a plain deposit: it
	// verifies a proof of possession, which is two pairings.
	GasDepositWithKey uint64 = 250000
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
		if st.msg.Value.Sign() <= 0 {
			return 0, fmt.Errorf("%w: a deposit needs value", ErrMalformedStaking)
		}
		switch {
		case len(data) >= depositWithKeyLength:
			// 0x01 || withdrawal(20) || blsKey(48) || possession(96)
			withdrawal := common.BytesToAddress(data[1:21])
			blsKey := data[21 : 21+staking.BLSPublicKeyLength]
			possession := data[21+staking.BLSPublicKeyLength : depositWithKeyLength]
			if _, err := manager.DepositWithKey(st.msg.From, withdrawal, blsKey, possession, st.msg.Value, epoch); err != nil {
				return 0, err
			}
			return GasDepositWithKey, nil
		case len(data) >= 21:
			// A top-up, which does not carry a key: the validator already has
			// one and changing it silently would let it disown its own votes.
			withdrawal := common.BytesToAddress(data[1:21])
			if _, err := manager.Deposit(st.msg.From, withdrawal, st.msg.Value, epoch); err != nil {
				return 0, err
			}
		default:
			return 0, fmt.Errorf("%w: a deposit needs a withdrawal address", ErrMalformedStaking)
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
		// The proof is re-verified from the signatures rather than believed:
		// anyone may report, nobody may forge. The key comes from the registry
		// so the evidence cannot name a validator it did not implicate.
		accused, err := manager.Registry().Get(evidence.Index)
		if err != nil {
			return 0, fmt.Errorf("processor: equivocation evidence: %w", err)
		}
		key, err := bls12381.PublicKeyFromBytes(accused.BLSPublicKey)
		if err != nil {
			return 0, fmt.Errorf("processor: accused validator has no usable key: %w", err)
		}
		if err := evidence.Verify(st.evm.ChainConfig.ChainID, key); err != nil {
			return 0, fmt.Errorf("processor: equivocation evidence: %w", err)
		}
		if _, _, err := manager.Slash(accused.Address, epoch); err != nil {
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
func EpochParticipation(chain ChainContext, chainID *big.Int, epoch uint64, validators []common.Address) *staking.Participation {
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
		// The bitfield names the signers by their index in the set that
		// governed the certificate's height, so participation is read straight
		// off it — no signature recovery, and nothing a proposer can influence.
		for _, index := range qc.Signers.Indices(len(validators)) {
			if index < len(validators) {
				participation.MarkAttested(validators[index])
			}
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
	validators, err := p.validatorsAt(staking.EpochStart(epoch - 1))
	if err != nil {
		return nil, err
	}
	participation := EpochParticipation(p.chain, p.config.ChainID, epoch-1, validators)

	manager := staking.NewManager(statedb)
	return manager.ProcessEpoch(epoch, participation, staking.EpochOf(finalizedNumber))
}

// validatorsAt returns the ordered validator set governing a height, which is
// what an aggregate's bitfield indexes into.
func (p *Processor) validatorsAt(blockNumber uint64) ([]common.Address, error) {
	provider, ok := p.chain.(interface {
		ValidatorsAt(uint64) ([]common.Address, error)
	})
	if !ok {
		return nil, nil
	}
	return provider.ValidatorsAt(blockNumber)
}
