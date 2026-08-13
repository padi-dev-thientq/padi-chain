package staking

import (
	"fmt"
	"math/big"
	"sort"

	"layer1/common"
	"layer1/crypto/bls12381"
)

// The validator lifecycle.
//
//	deposit -> pending -> active -> exiting -> exited -> withdrawn
//	                        |
//	                        +-----> slashed -> withdrawn
//
// Every transition between those states happens at an epoch boundary and at a
// bounded rate. That is the property the rest of the protocol leans on: the set
// a block is verified against was fixed before that block was produced, and it
// cannot have changed by more than the churn limit since the last one.

// Manager applies staking operations to the state.
type Manager struct {
	registry *Registry
	state    StateAccess
}

// NewManager builds a staking manager over a state view.
func NewManager(state StateAccess) *Manager {
	return &Manager{registry: NewRegistry(state), state: state}
}

// Registry exposes the underlying registry for reads.
func (m *Manager) Registry() *Registry { return m.registry }

// Deposit records staked funds for a validator.
//
// The value itself is expected to have already been transferred to the staking
// account by the surrounding state transition; this records the claim on it.
// A deposit for an address that is already registered tops it up, which is how
// a validator recovers from penalties without needing a second key.
// DepositWithKey records a deposit that also registers an attestation key.
//
// The proof of possession is mandatory. Without it a validator could register a
// key computed from the other validators' keys and then produce aggregate
// signatures nobody agreed to — the rogue key attack, which is the one way an
// aggregation scheme can be broken by a participant rather than by breaking the
// cryptography.
func (m *Manager) DepositWithKey(validator, withdrawal common.Address, blsKey, possession []byte, amount *big.Int, epoch uint64) (*Validator, error) {
	if len(blsKey) != BLSPublicKeyLength {
		return nil, fmt.Errorf("%w: attestation key must be %d bytes, got %d", ErrBadBLSKey, BLSPublicKeyLength, len(blsKey))
	}
	pub, err := bls12381.PublicKeyFromBytes(blsKey)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBadBLSKey, err)
	}
	proof, err := bls12381.SignatureFromBytes(possession)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBadPossession, err)
	}
	if !bls12381.VerifyPossession(pub, proof) {
		return nil, ErrBadPossession
	}

	v, err := m.Deposit(validator, withdrawal, amount, epoch)
	if err != nil {
		return nil, err
	}
	// A top-up must not silently change the key an existing validator attests
	// with; only a first registration sets it.
	if len(v.BLSPublicKey) == 0 {
		v.BLSPublicKey = append([]byte(nil), blsKey...)
		m.registry.Put(v)
	}
	return v, nil
}

func (m *Manager) Deposit(validator, withdrawal common.Address, amount *big.Int, epoch uint64) (*Validator, error) {
	if existing, err := m.registry.ByAddress(validator); err == nil {
		switch existing.Status {
		case StatusExited, StatusSlashed, StatusWithdrawn:
			// Topping up a validator on its way out would let it re-enter the
			// set without waiting out its exit, and a slashed one without
			// consequence.
			return nil, fmt.Errorf("staking: %s has already left the set", validator)
		}
		existing.Balance = new(big.Int).Add(existing.Balance, amount)
		existing.EffectiveBalance = computeEffectiveBalance(existing.Balance)
		m.registry.Put(existing)
		return existing, nil
	}

	if amount.Cmp(MinDeposit) < 0 {
		return nil, fmt.Errorf("%w: %s, need %s", ErrBelowMinimum, amount, MinDeposit)
	}

	v := &Validator{
		Address:           validator,
		WithdrawalAddress: withdrawal,
		Balance:           new(big.Int).Set(amount),
		EffectiveBalance:  computeEffectiveBalance(amount),
		Status:            StatusPending,
		// Activation is scheduled during epoch processing, subject to churn.
		ActivationEpoch:   FarFutureEpoch,
		ExitEpoch:         FarFutureEpoch,
		WithdrawableEpoch: FarFutureEpoch,
	}
	m.registry.Append(v)
	return v, nil
}

// DeriveGenesisBLSKey produces the attestation key of a genesis validator.
//
// A genesis validator has no deposit transaction to carry a key in, so one is
// derived from its address. That is reproducible from the genesis file alone,
// which is what matters for a development chain; a production genesis should
// list real keys, because a derived key is one whose secret is known to anyone
// who can read the address.
func DeriveGenesisBLSKey(validator common.Address) *bls12381.SecretKey {
	return bls12381.DeriveSecretKey(append([]byte("layer1/genesis-validator/v1"), validator[:]...))
}

// RequestExit begins a validator's voluntary departure.
func (m *Manager) RequestExit(validator common.Address, epoch uint64) (*Validator, error) {
	v, err := m.registry.ByAddress(validator)
	if err != nil {
		return nil, err
	}
	switch v.Status {
	case StatusActive:
	case StatusPending:
		// A validator that never activated can leave immediately; it was never
		// responsible for anything.
		v.Status = StatusExited
		v.ExitEpoch = epoch
		v.WithdrawableEpoch = epoch + WithdrawalDelay
		m.registry.Put(v)
		return v, nil
	default:
		return nil, fmt.Errorf("%w: %s is %s", ErrNotActive, validator, v.Status)
	}

	exitEpoch := m.scheduleExit(epoch)
	v.Status = StatusExiting
	v.ExitEpoch = exitEpoch
	// The withdrawal delay runs from the exit, not the request: it has to
	// outlast the window in which evidence of misbehaviour could still appear.
	v.WithdrawableEpoch = exitEpoch + WithdrawalDelay
	m.registry.Put(v)
	return v, nil
}

// scheduleExit places an exit in the queue, spreading departures so no more
// than the churn limit leave in any one epoch.
func (m *Manager) scheduleExit(epoch uint64) uint64 {
	state := m.registry.LoadEpochState()
	active, _ := m.registry.ActiveAt(epoch)
	limit := uint64(ChurnLimit(len(active)))

	earliest := epoch + MinActivationDelay
	if state.ExitQueueEpoch < earliest {
		state.ExitQueueEpoch = earliest
		state.ExitQueueCount = 0
	}
	if state.ExitQueueCount >= limit {
		state.ExitQueueEpoch++
		state.ExitQueueCount = 0
	}
	state.ExitQueueCount++
	m.registry.SaveEpochState(state)
	return state.ExitQueueEpoch
}

// Slash punishes a validator for provable misbehaviour and ejects it.
//
// The penalty is immediate and the ejection is not queued: a validator that has
// demonstrably broken the rules should stop being counted at once, and churn
// limits exist to protect the set from disruption, not to protect an attacker
// from consequences.
func (m *Manager) Slash(validator common.Address, epoch uint64) (*Validator, *big.Int, error) {
	v, err := m.registry.ByAddress(validator)
	if err != nil {
		return nil, nil, err
	}
	if v.Status == StatusSlashed {
		return nil, nil, fmt.Errorf("%w: %s", ErrAlreadySlashed, validator)
	}
	if v.Status == StatusExited || v.Status == StatusWithdrawn {
		return nil, nil, fmt.Errorf("staking: %s has already left the set", validator)
	}

	penalty := new(big.Int).Div(v.EffectiveBalance, big.NewInt(SlashPenaltyQuotient))
	if penalty.Cmp(v.Balance) > 0 {
		penalty = new(big.Int).Set(v.Balance)
	}
	v.Balance = new(big.Int).Sub(v.Balance, penalty)
	v.EffectiveBalance = computeEffectiveBalance(v.Balance)
	v.Status = StatusSlashed
	v.SlashedEpoch = epoch
	v.ExitEpoch = epoch
	v.WithdrawableEpoch = epoch + WithdrawalDelay
	m.registry.Put(v)

	// Record the offence against the epoch, so the correlation penalty applied
	// later can see how much stake misbehaved around the same time.
	m.registry.AddSlashedStake(epoch, v.EffectiveBalance)

	// The slashed stake is destroyed rather than redistributed. Paying it to
	// the reporter would create an incentive to provoke slashable behaviour.
	m.state.SubBalance(StakingAddress, penalty)
	return v, penalty, nil
}

// applyCorrelationPenalties charges the second, larger slashing penalty to
// validators whose offence falls due this epoch.
//
// The size depends on how much stake was slashed in the surrounding window: an
// isolated fault costs a fraction of a percent, while a third of the network
// equivocating together costs nearly everything. That difference is the point.
// A flat penalty either lets a coordinated attack off cheaply or bankrupts an
// operator whose validator ran twice by accident.
func (m *Manager) applyCorrelationPenalties(epoch uint64, report *EpochReport) error {
	all, err := m.registry.All()
	if err != nil {
		return err
	}

	totalStake, err := m.registry.TotalActiveStake(epoch)
	if err != nil {
		return err
	}
	if totalStake.Sign() == 0 {
		return nil
	}
	correlated := m.registry.CorrelatedSlashedStake(epoch)
	// Cap the correlated amount at the whole stake, so the multiplier cannot
	// push the penalty above the balance it applies to.
	if correlated.Cmp(totalStake) > 0 {
		correlated = new(big.Int).Set(totalStake)
	}

	for _, v := range all {
		if v.Status != StatusSlashed || v.Balance.Sign() == 0 {
			continue
		}
		if v.SlashedEpoch+CorrelationPenaltyEpochOffset != epoch {
			continue
		}

		// penalty = effective_balance * min(correlated * multiplier, total) / total
		scaled := new(big.Int).Mul(correlated, big.NewInt(CorrelationPenaltyMultiplier))
		if scaled.Cmp(totalStake) > 0 {
			scaled = new(big.Int).Set(totalStake)
		}
		penalty := new(big.Int).Mul(v.EffectiveBalance, scaled)
		penalty.Div(penalty, totalStake)
		if penalty.Cmp(v.Balance) > 0 {
			penalty = new(big.Int).Set(v.Balance)
		}
		if penalty.Sign() == 0 {
			continue
		}

		v.Balance = new(big.Int).Sub(v.Balance, penalty)
		v.EffectiveBalance = computeEffectiveBalance(v.Balance)
		m.registry.Put(v)

		m.state.SubBalance(StakingAddress, penalty)
		report.Burned.Add(report.Burned, penalty)
		report.Correlated = append(report.Correlated, v.Address)
	}
	return nil
}

// Withdraw returns an exited validator's stake to its withdrawal address.
func (m *Manager) Withdraw(validator common.Address, epoch uint64) (*big.Int, error) {
	v, err := m.registry.ByAddress(validator)
	if err != nil {
		return nil, err
	}
	switch v.Status {
	case StatusExited, StatusSlashed:
	case StatusWithdrawn:
		return nil, fmt.Errorf("staking: %s has already withdrawn", validator)
	default:
		return nil, fmt.Errorf("%w: %s is %s", ErrNotWithdrawable, validator, v.Status)
	}
	if epoch < v.WithdrawableEpoch {
		return nil, fmt.Errorf("%w: withdrawable at epoch %d, now %d", ErrNotWithdrawable, v.WithdrawableEpoch, epoch)
	}

	amount := new(big.Int).Set(v.Balance)
	v.Balance = new(big.Int)
	v.EffectiveBalance = new(big.Int)
	v.Status = StatusWithdrawn
	m.registry.Put(v)

	m.state.SubBalance(StakingAddress, amount)
	m.state.AddBalance(v.WithdrawalAddress, amount)
	return amount, nil
}

// Participation records which validators attested during an epoch, and which
// proposed its blocks. It is derived from the quorum certificates the epoch's
// headers carried, so it is a fact about the chain rather than a claim.
type Participation struct {
	Attested  map[common.Address]struct{}
	Proposers map[common.Address]uint64
}

// NewParticipation returns an empty record.
func NewParticipation() *Participation {
	return &Participation{
		Attested:  make(map[common.Address]struct{}),
		Proposers: make(map[common.Address]uint64),
	}
}

// MarkAttested records that a validator attested.
func (p *Participation) MarkAttested(addr common.Address) { p.Attested[addr] = struct{}{} }

// MarkProposed records a block proposal.
func (p *Participation) MarkProposed(addr common.Address) { p.Proposers[addr]++ }

// EpochReport summarises what an epoch transition did.
type EpochReport struct {
	Epoch     uint64
	Activated []common.Address
	Exited    []common.Address
	Ejected   []common.Address
	Rewarded  int
	Penalised int
	// Correlated lists validators charged the correlation penalty this epoch.
	Correlated []common.Address
	Issued     *big.Int
	Burned     *big.Int
	LeakActive bool
}

// ProcessEpoch applies the end-of-epoch transition: activations, exits,
// rewards, penalties and ejections.
//
// It is deterministic and depends only on the state and the participation
// derived from the chain, so every node computes the same result — which is
// what allows the validator set to be consensus state rather than configuration.
func (m *Manager) ProcessEpoch(epoch uint64, participation *Participation, finalizedEpoch uint64) (*EpochReport, error) {
	state := m.registry.LoadEpochState()
	if epoch <= state.LastProcessedEpoch && state.LastProcessedEpoch != 0 {
		return nil, fmt.Errorf("staking: epoch %d has already been processed", epoch)
	}

	report := &EpochReport{
		Epoch:  epoch,
		Issued: new(big.Int),
		Burned: new(big.Int),
	}

	all, err := m.registry.All()
	if err != nil {
		return nil, err
	}

	// 1. Finish exits whose epoch has arrived.
	for _, v := range all {
		if v.Status == StatusExiting && epoch >= v.ExitEpoch {
			v.Status = StatusExited
			m.registry.Put(v)
			report.Exited = append(report.Exited, v.Address)
		}
	}

	// 2. Reward and penalise the set that was active during the epoch.
	active, err := m.registry.ActiveAt(epoch)
	if err != nil {
		return nil, err
	}
	totalStake := new(big.Int)
	for _, v := range active {
		totalStake.Add(totalStake, v.EffectiveBalance)
	}

	finalityDelay := uint64(0)
	if epoch > finalizedEpoch {
		finalityDelay = epoch - finalizedEpoch
	}
	report.LeakActive = finalityDelay > InactivityLeakThreshold

	if totalStake.Sign() > 0 && participation != nil {
		for _, v := range active {
			base := baseReward(v.EffectiveBalance, totalStake)
			_, attested := participation.Attested[v.Address]

			if attested {
				reward := new(big.Int).Set(base)
				if proposed := participation.Proposers[v.Address]; proposed > 0 {
					// The proposer is paid for the work of collecting and
					// including other validators' attestations.
					bonus := new(big.Int).Div(base, big.NewInt(ProposerRewardQuotient))
					reward.Add(reward, new(big.Int).Mul(bonus, new(big.Int).SetUint64(proposed)))
				}
				v.Balance = new(big.Int).Add(v.Balance, reward)
				report.Issued.Add(report.Issued, reward)
				report.Rewarded++
			} else {
				penalty := new(big.Int).Set(base)
				// While the chain is failing to finalize, absent validators
				// leak stake on top of the ordinary penalty. That is what lets
				// a chain that lost a third of its validators finalize again:
				// the absent stake shrinks until what remains is a two-thirds
				// majority.
				if report.LeakActive {
					leak := new(big.Int).Mul(v.EffectiveBalance, new(big.Int).SetUint64(finalityDelay))
					leak.Div(leak, big.NewInt(InactivityPenaltyQuotient))
					penalty.Add(penalty, leak)
				}
				if penalty.Cmp(v.Balance) > 0 {
					penalty = new(big.Int).Set(v.Balance)
				}
				v.Balance = new(big.Int).Sub(v.Balance, penalty)
				report.Burned.Add(report.Burned, penalty)
				report.Penalised++
			}
			v.EffectiveBalance = computeEffectiveBalance(v.Balance)
			m.registry.Put(v)
		}
	}

	// Rewards are newly issued and penalties are destroyed, so the staking
	// account's balance keeps matching the sum of validator balances.
	if report.Issued.Sign() > 0 {
		m.state.AddBalance(StakingAddress, report.Issued)
	}
	if report.Burned.Sign() > 0 {
		m.state.SubBalance(StakingAddress, report.Burned)
	}

	// 3. Charge correlation penalties that have come due.
	if err := m.applyCorrelationPenalties(epoch, report); err != nil {
		return nil, err
	}

	// Clear the slot this epoch's tally will reuse once the window wraps, so
	// an old total is never mistaken for a recent one.
	m.registry.ResetSlashedStake(epoch + 1)

	// 4. Eject validators that have fallen below the minimum worth trusting.
	for _, v := range active {
		current, err := m.registry.Get(v.Index)
		if err != nil {
			return nil, err
		}
		if current.Status == StatusActive && current.Balance.Cmp(EjectionBalance) < 0 {
			if _, err := m.RequestExit(current.Address, epoch); err == nil {
				report.Ejected = append(report.Ejected, current.Address)
			}
		}
	}

	// 5. Activate pending deposits, oldest first, up to the churn limit.
	activeAfter, err := m.registry.ActiveAt(epoch)
	if err != nil {
		return nil, err
	}
	limit := ChurnLimit(len(activeAfter))

	var pending []*Validator
	for _, v := range all {
		refreshed, err := m.registry.Get(v.Index)
		if err != nil {
			return nil, err
		}
		if refreshed.Status == StatusPending && refreshed.Balance.Cmp(MinDeposit) >= 0 {
			pending = append(pending, refreshed)
		}
	}
	sort.Slice(pending, func(i, j int) bool { return pending[i].Index < pending[j].Index })

	for i, v := range pending {
		if i >= limit {
			break
		}
		v.Status = StatusActive
		v.ActivationEpoch = epoch + MinActivationDelay
		m.registry.Put(v)
		report.Activated = append(report.Activated, v.Address)
	}

	state.LastProcessedEpoch = epoch
	state.FinalizedEpoch = finalizedEpoch
	m.registry.SaveEpochState(state)
	return report, nil
}

// baseReward is the per-epoch reward unit for a validator, scaled so that a
// larger total stake pays each validator proportionally less. Issuance
// therefore grows with the square root of the stake rather than linearly,
// which is what stops the reward rate from being independent of participation.
func baseReward(effectiveBalance, totalStake *big.Int) *big.Int {
	if totalStake.Sign() <= 0 {
		return new(big.Int)
	}
	root := new(big.Int).Sqrt(totalStake)
	if root.Sign() == 0 {
		return new(big.Int)
	}
	reward := new(big.Int).Mul(effectiveBalance, big.NewInt(BaseRewardFactor))
	reward.Div(reward, root)
	// Spread across the epoch's four reward components, as Ethereum does, so
	// the constant means the same thing.
	return reward.Div(reward, big.NewInt(4))
}

// TotalStaked returns the sum of all validator balances, which must equal the
// staking account's balance.
func (m *Manager) TotalStaked() (*big.Int, error) {
	all, err := m.registry.All()
	if err != nil {
		return nil, err
	}
	total := new(big.Int)
	for _, v := range all {
		total.Add(total, v.Balance)
	}
	return total, nil
}
