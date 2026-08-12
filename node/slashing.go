package node

import (
	"math/big"

	"layer1/core"
	"layer1/keystore"
	"layer1/processor"
	"layer1/rlp"
	"layer1/staking"
)

// Reporting equivocation.
//
// Detecting that a validator signed two conflicting attestations is only half
// the job: the proof has to reach the chain for the stake to be slashed. Any
// node holding a funded key can submit it, and the chain re-derives the proof
// from the signatures, so reporting is permissionless and unforgeable.
//
// Several nodes will usually report the same offence at once. The first one
// included wins and the rest fail as already-slashed, having paid for the
// attempt. That is the same trade Ethereum makes: a little wasted gas is
// cheaper than relying on one designated reporter being online.

// reportEquivocation submits slashing evidence as a transaction.
func (n *Node) reportEquivocation(proof *core.Equivocation) {
	if n.config.Validator == nil {
		return // nothing to sign with
	}
	// Re-verify before spending anything on it.
	if err := proof.Verify(n.ChainID()); err != nil {
		n.log.Debug("not reporting unverifiable evidence", "err", err)
		return
	}

	from := keystore.AddressOf(n.config.Validator)
	statedb, err := n.chain.State()
	if err != nil {
		return
	}
	// Reporting the offence must not be what puts this node out of funds.
	if statedb.GetBalance(from).Sign() == 0 {
		n.log.Warn("cannot report equivocation: the validator key has no funds",
			"validator", proof.Validator, "height", proof.Number)
		return
	}

	encoded, err := rlp.Encode(proof)
	if err != nil {
		return
	}
	nonce, err := n.txpool.Nonce(from)
	if err != nil {
		return
	}

	to := staking.StakingAddress
	baseFee := n.chain.CurrentBlock().BaseFee()
	feeCap := new(big.Int).Add(new(big.Int).Mul(baseFee, big.NewInt(2)), big.NewInt(1_000_000_000))

	tx, err := core.NewSigner(n.ChainID()).SignTx(core.NewTx(&core.DynamicFeeTx{
		Nonce:     nonce,
		GasTipCap: big.NewInt(1_000_000_000),
		GasFeeCap: feeCap,
		Gas:       processor.GasSlash + 100_000,
		To:        &to,
		Value:     new(big.Int),
		Data:      append([]byte{processor.OpSlash}, encoded...),
	}), n.config.Validator)
	if err != nil {
		n.log.Error("signing a slashing report", "err", err)
		return
	}

	if err := n.txpool.Add(tx); err != nil {
		n.log.Debug("slashing report was not pooled", "err", err)
		return
	}
	n.metrics.SlashingReports.Inc()
	n.log.Warn("reported equivocation for slashing",
		"validator", proof.Validator, "height", proof.Number, "tx", tx.Hash())
}
