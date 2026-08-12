// Package staking implements proof-of-stake validator management, following the
// shape Ethereum settled on: stake is deposited through an ordinary
// transaction, the validator set changes only at epoch boundaries and only at a
// bounded rate, exits are delayed before funds can be withdrawn, and
// equivocation is punished by slashing.
//
// The registry lives in the state trie, under the storage of a system account.
// That placement is the point: the state root already commits to it, so every
// node agrees on the validator set for the same reason it agrees on balances,
// and a light client can prove a validator's status with a Merkle proof.
package staking

import (
	"math/big"

	"layer1/common"
)

// Gwei is the accounting unit for stake, as on Ethereum. Balances are held in
// wei but rounded to whole Gwei, which keeps effective-balance arithmetic exact.
var Gwei = big.NewInt(1_000_000_000)

// Ether is one whole unit of the chain's currency.
var Ether = new(big.Int).Mul(Gwei, Gwei)

// StakingAddress is the system account that holds staked funds and the
// registry. It is deliberately not an account anyone holds a key for: the
// protocol is the only thing that moves value out of it.
var StakingAddress = common.BytesToAddress([]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF})

// Protocol parameters. The values mirror Ethereum's where the reasoning carries
// over, and are scaled where this chain's shorter slots make the original
// meaningless.
var (
	// MinDeposit is the stake required to become a validator. A single fixed
	// size keeps the weighting uniform and the accounting simple.
	MinDeposit = new(big.Int).Mul(big.NewInt(32), Ether)

	// MaxEffectiveBalance caps how much stake counts toward influence.
	// Anything above it still belongs to the validator but buys nothing, which
	// removes the incentive to concentrate stake on one key.
	MaxEffectiveBalance = new(big.Int).Mul(big.NewInt(32), Ether)

	// EffectiveBalanceIncrement is the granularity of effective balance.
	// Rounding down to it stops a validator's weight from flickering with
	// every reward.
	EffectiveBalanceIncrement = Ether

	// EjectionBalance is the point below which a validator is removed. A
	// validator that has been penalised down to here is no longer carrying
	// enough stake to be worth trusting.
	EjectionBalance = new(big.Int).Mul(big.NewInt(16), Ether)
)

const (
	// EpochLength is how many blocks make up an epoch. The validator set is
	// constant within one, so every node computes the same set from the same
	// state without needing to agree on timing.
	EpochLength = 32

	// MinActivationDelay is how many epochs a deposit waits before it can be
	// activated. The delay exists so the set a block is verified against was
	// settled well before that block was produced.
	MinActivationDelay = 1

	// WithdrawalDelay is how many epochs an exited validator waits before its
	// stake can be withdrawn. It has to outlast the window in which evidence
	// of misbehaviour could still surface, or a validator could equivocate and
	// walk away before anyone could prove it.
	WithdrawalDelay = 256

	// MinChurnLimit is the floor on how many validators may enter or leave per
	// epoch. Bounding churn is what stops the set from being replaced faster
	// than the rest of the network can follow.
	MinChurnLimit = 4

	// ChurnLimitQuotient makes the churn limit grow with the set, so a large
	// validator set is not throttled by a limit sized for a small one.
	ChurnLimitQuotient = 65536

	// SlashPenaltyQuotient is the fraction of effective balance burned for an
	// initial slashing offence: one thirty-second, as on Ethereum.
	SlashPenaltyQuotient = 32

	// ProposerRewardQuotient is the proposer's share of the rewards it
	// includes, paid for including other validators' attestations.
	ProposerRewardQuotient = 8

	// BaseRewardFactor sets the scale of attestation rewards.
	BaseRewardFactor = 64

	// InactivityLeakThreshold is how many epochs without finality before the
	// chain starts leaking stake from non-participants. Leaking is what lets a
	// chain that has lost a third of its validators eventually finalize again:
	// the absent stake shrinks until the remainder is a two-thirds majority.
	InactivityLeakThreshold = 4

	// InactivityPenaltyQuotient sets how fast the leak drains an absent
	// validator.
	InactivityPenaltyQuotient = 1 << 16
)

// EpochOf returns the epoch a block belongs to.
func EpochOf(blockNumber uint64) uint64 { return blockNumber / EpochLength }

// EpochStart returns the first block number of an epoch.
func EpochStart(epoch uint64) uint64 { return epoch * EpochLength }

// IsEpochBoundary reports whether a block is the first of its epoch. Epoch
// processing runs on exactly these blocks.
func IsEpochBoundary(blockNumber uint64) bool {
	return blockNumber > 0 && blockNumber%EpochLength == 0
}

// ChurnLimit returns how many validators may enter or leave in one epoch,
// given the size of the active set.
func ChurnLimit(activeCount int) int {
	limit := activeCount / ChurnLimitQuotient
	if limit < MinChurnLimit {
		return MinChurnLimit
	}
	return limit
}

// computeEffectiveBalance rounds a balance down to the increment and caps it.
func computeEffectiveBalance(balance *big.Int) *big.Int {
	if balance.Cmp(MaxEffectiveBalance) >= 0 {
		return new(big.Int).Set(MaxEffectiveBalance)
	}
	rounded := new(big.Int).Div(balance, EffectiveBalanceIncrement)
	return rounded.Mul(rounded, EffectiveBalanceIncrement)
}
