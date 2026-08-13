package staking

import (
	"errors"
	"fmt"
	"math/big"
	"testing"

	"layer1/common"
	"layer1/db"
	"layer1/state"
)

func newTestState(t *testing.T) *state.StateDB {
	t.Helper()
	sdb, err := state.New(common.Hash{}, db.NewMemoryDB())
	if err != nil {
		t.Fatal(err)
	}
	return sdb
}

func addr(i byte) common.Address { return common.BytesToAddress([]byte{i}) }

func stake(n int64) *big.Int { return new(big.Int).Mul(big.NewInt(n), Ether) }

// deposit records a stake and credits the staking account, as the state
// transition does when a deposit transaction is applied.
func deposit(t *testing.T, m *Manager, sdb *state.StateDB, validator common.Address, amount *big.Int, epoch uint64) *Validator {
	t.Helper()
	sdb.AddBalance(StakingAddress, amount)
	v, err := m.Deposit(validator, validator, amount, epoch)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func TestDepositCreatesPendingValidator(t *testing.T) {
	sdb := newTestState(t)
	m := NewManager(sdb)

	v := deposit(t, m, sdb, addr(1), MinDeposit, 0)
	if v.Status != StatusPending {
		t.Fatalf("status = %s, want pending", v.Status)
	}
	if v.Balance.Cmp(MinDeposit) != 0 {
		t.Fatalf("balance = %s", v.Balance)
	}
	// A pending validator is not part of any set yet.
	if v.IsActiveAt(0) || v.IsActiveAt(100) {
		t.Fatal("a pending validator must not count as active")
	}

	stored, err := m.Registry().ByAddress(addr(1))
	if err != nil {
		t.Fatal(err)
	}
	if stored.Address != addr(1) || stored.Balance.Cmp(MinDeposit) != 0 {
		t.Fatalf("the stored record does not match: %+v", stored)
	}
}

func TestDepositBelowMinimumIsRejected(t *testing.T) {
	sdb := newTestState(t)
	m := NewManager(sdb)

	small := new(big.Int).Sub(MinDeposit, big.NewInt(1))
	if _, err := m.Deposit(addr(1), addr(1), small, 0); !errors.Is(err, ErrBelowMinimum) {
		t.Fatalf("got %v, want ErrBelowMinimum", err)
	}
	if m.Registry().Count() != 0 {
		t.Fatal("a rejected deposit still created a record")
	}
}

func TestDepositTopsUpExistingValidator(t *testing.T) {
	sdb := newTestState(t)
	m := NewManager(sdb)

	deposit(t, m, sdb, addr(1), MinDeposit, 0)
	// A top-up may be any size; the minimum applies to becoming a validator,
	// not to staying one.
	v := deposit(t, m, sdb, addr(1), stake(1), 0)

	want := new(big.Int).Add(MinDeposit, stake(1))
	if v.Balance.Cmp(want) != 0 {
		t.Fatalf("balance after top-up = %s, want %s", v.Balance, want)
	}
	if m.Registry().Count() != 1 {
		t.Fatal("the top-up created a second record")
	}
}

func TestEffectiveBalanceIsCappedAndRounded(t *testing.T) {
	sdb := newTestState(t)
	m := NewManager(sdb)

	// Far above the cap: influence is capped even though the funds are held.
	v := deposit(t, m, sdb, addr(1), stake(100), 0)
	if v.EffectiveBalance.Cmp(MaxEffectiveBalance) != 0 {
		t.Fatalf("effective balance = %s, want the cap %s", v.EffectiveBalance, MaxEffectiveBalance)
	}
	if v.Balance.Cmp(stake(100)) != 0 {
		t.Fatal("capping influence must not confiscate the stake")
	}

	// Below the cap, effective balance rounds down to the increment, so a
	// validator's weight does not flicker with every reward. The minimum
	// deposit equals the cap, so this only becomes observable once penalties
	// have taken a validator below it.
	cases := []struct{ balance, want *big.Int }{
		{new(big.Int).Add(stake(20), big.NewInt(12345)), stake(20)},
		{new(big.Int).Sub(stake(21), big.NewInt(1)), stake(20)},
		{stake(31), stake(31)},
		{stake(100), MaxEffectiveBalance},
		{big.NewInt(0), big.NewInt(0)},
	}
	for _, c := range cases {
		if got := computeEffectiveBalance(c.balance); got.Cmp(c.want) != 0 {
			t.Errorf("effective balance of %s = %s, want %s", c.balance, got, c.want)
		}
	}
}

func TestActivationRespectsChurnLimit(t *testing.T) {
	sdb := newTestState(t)
	m := NewManager(sdb)

	// Ten deposits at once; only the churn limit may enter per epoch.
	for i := 1; i <= 10; i++ {
		deposit(t, m, sdb, addr(byte(i)), MinDeposit, 0)
	}

	report, err := m.ProcessEpoch(1, NewParticipation(), 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Activated) != MinChurnLimit {
		t.Fatalf("activated %d validators in one epoch, the churn limit is %d", len(report.Activated), MinChurnLimit)
	}

	// The rest follow over subsequent epochs.
	total := len(report.Activated)
	for epoch := uint64(2); epoch <= 4; epoch++ {
		report, err := m.ProcessEpoch(epoch, NewParticipation(), 0)
		if err != nil {
			t.Fatal(err)
		}
		total += len(report.Activated)
	}
	if total != 10 {
		t.Fatalf("%d of 10 validators activated after four epochs", total)
	}
}

func TestActivatedValidatorsJoinTheSet(t *testing.T) {
	sdb := newTestState(t)
	m := NewManager(sdb)

	deposit(t, m, sdb, addr(1), MinDeposit, 0)
	if _, err := m.ProcessEpoch(1, NewParticipation(), 0); err != nil {
		t.Fatal(err)
	}

	// Activation takes effect a delay later, so the set a block is verified
	// against was settled before that block existed.
	active, err := m.Registry().ActiveAddressesAt(1)
	if err != nil {
		t.Fatal(err)
	}
	if len(active) != 0 {
		t.Fatalf("validator counted as active in its activation epoch: %v", active)
	}

	active, err = m.Registry().ActiveAddressesAt(1 + MinActivationDelay)
	if err != nil {
		t.Fatal(err)
	}
	if len(active) != 1 || active[0] != addr(1) {
		t.Fatalf("active set = %v, want one validator", active)
	}
}

func TestVoluntaryExit(t *testing.T) {
	sdb := newTestState(t)
	m := NewManager(sdb)

	deposit(t, m, sdb, addr(1), MinDeposit, 0)
	m.ProcessEpoch(1, NewParticipation(), 0)

	v, err := m.RequestExit(addr(1), 5)
	if err != nil {
		t.Fatal(err)
	}
	if v.Status != StatusExiting {
		t.Fatalf("status = %s, want exiting", v.Status)
	}
	// It stays in the set until its exit epoch: it is still expected to
	// attest, and still accountable if it does not.
	if !v.IsActiveAt(5) {
		t.Fatal("a validator that requested exit must remain active until its exit epoch")
	}
	if v.IsActiveAt(v.ExitEpoch) {
		t.Fatal("a validator must leave the set at its exit epoch")
	}
	if v.WithdrawableEpoch != v.ExitEpoch+WithdrawalDelay {
		t.Fatalf("withdrawable at %d, want exit %d plus the delay", v.WithdrawableEpoch, v.ExitEpoch)
	}
}

func TestWithdrawalIsDelayed(t *testing.T) {
	sdb := newTestState(t)
	m := NewManager(sdb)

	deposit(t, m, sdb, addr(1), MinDeposit, 0)
	m.ProcessEpoch(1, NewParticipation(), 0)
	v, _ := m.RequestExit(addr(1), 2)
	m.ProcessEpoch(v.ExitEpoch, NewParticipation(), 0)

	// Before the delay elapses there is nothing to take.
	if _, err := m.Withdraw(addr(1), v.WithdrawableEpoch-1); !errors.Is(err, ErrNotWithdrawable) {
		t.Fatalf("got %v, want ErrNotWithdrawable", err)
	}

	balanceBefore := sdb.GetBalance(addr(1))
	amount, err := m.Withdraw(addr(1), v.WithdrawableEpoch)
	if err != nil {
		t.Fatal(err)
	}
	if amount.Cmp(MinDeposit) != 0 {
		t.Fatalf("withdrew %s, want %s", amount, MinDeposit)
	}
	gained := new(big.Int).Sub(sdb.GetBalance(addr(1)), balanceBefore)
	if gained.Cmp(MinDeposit) != 0 {
		t.Fatalf("the withdrawal address gained %s, want %s", gained, MinDeposit)
	}
	// The staked funds have left the staking account with them.
	if sdb.GetBalance(StakingAddress).Sign() != 0 {
		t.Fatalf("the staking account still holds %s", sdb.GetBalance(StakingAddress))
	}
}

func TestSlashing(t *testing.T) {
	sdb := newTestState(t)
	m := NewManager(sdb)

	deposit(t, m, sdb, addr(1), MinDeposit, 0)
	m.ProcessEpoch(1, NewParticipation(), 0)

	before := sdb.GetBalance(StakingAddress)
	v, penalty, err := m.Slash(addr(1), 3)
	if err != nil {
		t.Fatal(err)
	}

	wantPenalty := new(big.Int).Div(MinDeposit, big.NewInt(SlashPenaltyQuotient))
	if penalty.Cmp(wantPenalty) != 0 {
		t.Fatalf("penalty = %s, want %s", penalty, wantPenalty)
	}
	if v.Status != StatusSlashed {
		t.Fatalf("status = %s, want slashed", v.Status)
	}
	// Ejection is immediate: a validator that has demonstrably broken the
	// rules stops counting at once.
	if v.IsActiveAt(3) {
		t.Fatal("a slashed validator is still in the set")
	}
	// The stake is destroyed, not paid to anyone. Rewarding a reporter would
	// create an incentive to provoke slashable behaviour.
	burned := new(big.Int).Sub(before, sdb.GetBalance(StakingAddress))
	if burned.Cmp(penalty) != 0 {
		t.Fatalf("burned %s, want %s", burned, penalty)
	}
	// And it still cannot withdraw for the full delay.
	if _, err := m.Withdraw(addr(1), 3); err == nil {
		t.Fatal("a slashed validator withdrew immediately")
	}
}

func TestSlashingTwiceIsRejected(t *testing.T) {
	sdb := newTestState(t)
	m := NewManager(sdb)
	deposit(t, m, sdb, addr(1), MinDeposit, 0)
	m.ProcessEpoch(1, NewParticipation(), 0)

	if _, _, err := m.Slash(addr(1), 3); err != nil {
		t.Fatal(err)
	}
	if _, _, err := m.Slash(addr(1), 4); !errors.Is(err, ErrAlreadySlashed) {
		t.Fatalf("got %v, want ErrAlreadySlashed", err)
	}
}

func TestExitedValidatorCannotRejoinByDepositing(t *testing.T) {
	sdb := newTestState(t)
	m := NewManager(sdb)
	deposit(t, m, sdb, addr(1), MinDeposit, 0)
	m.ProcessEpoch(1, NewParticipation(), 0)
	m.Slash(addr(1), 2)

	// Topping up a slashed validator would let it back into the set without
	// consequence.
	if _, err := m.Deposit(addr(1), addr(1), MinDeposit, 3); err == nil {
		t.Fatal("a slashed validator was topped back up")
	}
}

func TestRewardsAndPenalties(t *testing.T) {
	sdb := newTestState(t)
	m := NewManager(sdb)

	for i := 1; i <= 4; i++ {
		deposit(t, m, sdb, addr(byte(i)), MinDeposit, 0)
	}
	m.ProcessEpoch(1, NewParticipation(), 0)
	epoch := uint64(1 + MinActivationDelay)

	// Three of four attest; the fourth is absent.
	participation := NewParticipation()
	for i := 1; i <= 3; i++ {
		participation.MarkAttested(addr(byte(i)))
	}
	participation.MarkProposed(addr(1))

	report, err := m.ProcessEpoch(epoch, participation, epoch)
	if err != nil {
		t.Fatal(err)
	}
	if report.Rewarded != 3 || report.Penalised != 1 {
		t.Fatalf("rewarded %d and penalised %d, want 3 and 1", report.Rewarded, report.Penalised)
	}

	attester, _ := m.Registry().ByAddress(addr(2))
	absent, _ := m.Registry().ByAddress(addr(4))
	if attester.Balance.Cmp(MinDeposit) <= 0 {
		t.Fatalf("an attesting validator was not rewarded: %s", attester.Balance)
	}
	if absent.Balance.Cmp(MinDeposit) >= 0 {
		t.Fatalf("an absent validator was not penalised: %s", absent.Balance)
	}
	// The proposer earns more than a plain attester for the work of including
	// everyone else's attestations.
	proposer, _ := m.Registry().ByAddress(addr(1))
	if proposer.Balance.Cmp(attester.Balance) <= 0 {
		t.Fatal("the proposer was not paid more than a plain attester")
	}
}

func TestInactivityLeak(t *testing.T) {
	sdb := newTestState(t)
	m := NewManager(sdb)

	for i := 1; i <= 4; i++ {
		deposit(t, m, sdb, addr(byte(i)), MinDeposit, 0)
	}
	m.ProcessEpoch(1, NewParticipation(), 0)

	// One validator attests; the rest are absent and the chain stops
	// finalizing.
	participation := NewParticipation()
	participation.MarkAttested(addr(1))

	var lastAbsent *big.Int
	for epoch := uint64(2); epoch < 12; epoch++ {
		report, err := m.ProcessEpoch(epoch, participation, 1)
		if err != nil {
			t.Fatal(err)
		}
		if epoch > 1+InactivityLeakThreshold && !report.LeakActive {
			t.Fatalf("epoch %d: the leak should be active with finality %d epochs behind", epoch, epoch-1)
		}
		absent, _ := m.Registry().ByAddress(addr(4))
		if lastAbsent != nil && absent.Balance.Cmp(lastAbsent) >= 0 {
			t.Fatalf("epoch %d: the absent validator's stake did not shrink", epoch)
		}
		lastAbsent = new(big.Int).Set(absent.Balance)
	}

	// The point of the leak: the participating validator's share of the total
	// grows until it can finalize on its own.
	participant, _ := m.Registry().ByAddress(addr(1))
	absent, _ := m.Registry().ByAddress(addr(4))
	if participant.Balance.Cmp(absent.Balance) <= 0 {
		t.Fatal("the leak did not shift stake toward the participating validator")
	}
}

func TestEjectionBelowMinimum(t *testing.T) {
	sdb := newTestState(t)
	m := NewManager(sdb)

	deposit(t, m, sdb, addr(1), MinDeposit, 0)
	deposit(t, m, sdb, addr(2), MinDeposit, 0)
	m.ProcessEpoch(1, NewParticipation(), 0)

	// Drive one validator below the ejection threshold by hand.
	v, _ := m.Registry().ByAddress(addr(1))
	v.Balance = new(big.Int).Sub(EjectionBalance, big.NewInt(1))
	v.EffectiveBalance = computeEffectiveBalance(v.Balance)
	m.Registry().Put(v)

	report, err := m.ProcessEpoch(2, NewParticipation(), 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Ejected) != 1 || report.Ejected[0] != addr(1) {
		t.Fatalf("ejected %v, want the underfunded validator", report.Ejected)
	}
	ejected, _ := m.Registry().ByAddress(addr(1))
	if ejected.Status != StatusExiting {
		t.Fatalf("status = %s, want exiting", ejected.Status)
	}
}

func TestStakingAccountMatchesTotalStake(t *testing.T) {
	sdb := newTestState(t)
	m := NewManager(sdb)

	// The invariant that makes withdrawals safe: the staking account holds
	// exactly what the registry says validators own, through deposits,
	// rewards, penalties, slashing and withdrawals alike.
	check := func(stage string) {
		t.Helper()
		total, err := m.TotalStaked()
		if err != nil {
			t.Fatal(err)
		}
		if got := sdb.GetBalance(StakingAddress); got.Cmp(total) != 0 {
			t.Fatalf("%s: the staking account holds %s but validators own %s", stage, got, total)
		}
	}

	for i := 1; i <= 5; i++ {
		deposit(t, m, sdb, addr(byte(i)), MinDeposit, 0)
	}
	check("after deposits")

	m.ProcessEpoch(1, NewParticipation(), 0)
	check("after activation")

	participation := NewParticipation()
	participation.MarkAttested(addr(1))
	participation.MarkAttested(addr(2))
	participation.MarkProposed(addr(1))
	m.ProcessEpoch(2, participation, 2)
	check("after rewards and penalties")

	m.Slash(addr(3), 3)
	check("after slashing")

	v, _ := m.RequestExit(addr(4), 3)
	m.ProcessEpoch(v.ExitEpoch, NewParticipation(), 3)
	m.Withdraw(addr(4), v.WithdrawableEpoch)
	check("after a withdrawal")
}

func TestEpochCannotBeProcessedTwice(t *testing.T) {
	sdb := newTestState(t)
	m := NewManager(sdb)
	deposit(t, m, sdb, addr(1), MinDeposit, 0)

	if _, err := m.ProcessEpoch(5, NewParticipation(), 0); err != nil {
		t.Fatal(err)
	}
	// Replaying an epoch would pay its rewards twice.
	if _, err := m.ProcessEpoch(5, NewParticipation(), 0); err == nil {
		t.Fatal("an epoch was processed twice")
	}
}

func TestRegistrySurvivesStateCommit(t *testing.T) {
	store := db.NewMemoryDB()
	sdb, err := state.New(common.Hash{}, store)
	if err != nil {
		t.Fatal(err)
	}
	m := NewManager(sdb)

	for i := 1; i <= 3; i++ {
		sdb.AddBalance(StakingAddress, MinDeposit)
		if _, err := m.Deposit(addr(byte(i)), addr(byte(100+i)), MinDeposit, 0); err != nil {
			t.Fatal(err)
		}
	}
	m.ProcessEpoch(1, NewParticipation(), 0)

	// The registry is ordinary account storage, so the state root commits to
	// it and it reloads with the rest of the state.
	root, err := sdb.Commit(true)
	if err != nil {
		t.Fatal(err)
	}
	reloaded, err := state.New(root, store)
	if err != nil {
		t.Fatal(err)
	}
	m2 := NewManager(reloaded)

	if m2.Registry().Count() != 3 {
		t.Fatalf("%d validators survived the commit, want 3", m2.Registry().Count())
	}
	active, err := m2.Registry().ActiveAddressesAt(1 + MinActivationDelay)
	if err != nil {
		t.Fatal(err)
	}
	if len(active) != 3 {
		t.Fatalf("active set after reload = %v", active)
	}
	v, err := m2.Registry().ByAddress(addr(2))
	if err != nil {
		t.Fatal(err)
	}
	if v.WithdrawalAddress != addr(102) {
		t.Fatalf("withdrawal address after reload = %s", v.WithdrawalAddress)
	}
}

func TestChurnLimitFormula(t *testing.T) {
	// Small sets get the floor; large sets scale with size, so a big validator
	// set is not throttled by a limit chosen for a small one.
	if got := ChurnLimit(0); got != MinChurnLimit {
		t.Errorf("ChurnLimit(0) = %d, want %d", got, MinChurnLimit)
	}
	if got := ChurnLimit(1000); got != MinChurnLimit {
		t.Errorf("ChurnLimit(1000) = %d, want %d", got, MinChurnLimit)
	}
	if got := ChurnLimit(ChurnLimitQuotient * 10); got != 10 {
		t.Errorf("ChurnLimit(%d) = %d, want 10", ChurnLimitQuotient*10, got)
	}
}

func TestEpochArithmetic(t *testing.T) {
	if EpochOf(0) != 0 || EpochOf(EpochLength-1) != 0 || EpochOf(EpochLength) != 1 {
		t.Fatal("EpochOf does not partition blocks into epochs correctly")
	}
	if !IsEpochBoundary(EpochLength) || IsEpochBoundary(EpochLength+1) {
		t.Fatal("IsEpochBoundary is wrong")
	}
	// Genesis is not an epoch boundary: there is no previous epoch to process.
	if IsEpochBoundary(0) {
		t.Fatal("genesis must not trigger epoch processing")
	}
	if EpochStart(3) != 3*EpochLength {
		t.Fatal("EpochStart is wrong")
	}
}

func TestManyValidators(t *testing.T) {
	sdb := newTestState(t)
	m := NewManager(sdb)

	const count = 40
	for i := 0; i < count; i++ {
		v := common.BytesToAddress([]byte(fmt.Sprintf("validator-%d", i)))
		sdb.AddBalance(StakingAddress, MinDeposit)
		if _, err := m.Deposit(v, v, MinDeposit, 0); err != nil {
			t.Fatal(err)
		}
	}

	// Everyone gets in eventually, at the churn limit's pace.
	activated := 0
	for epoch := uint64(1); epoch <= 20 && activated < count; epoch++ {
		report, err := m.ProcessEpoch(epoch, NewParticipation(), epoch)
		if err != nil {
			t.Fatal(err)
		}
		activated += len(report.Activated)
	}
	if activated != count {
		t.Fatalf("%d of %d validators activated", activated, count)
	}
}

// slashAt slashes a validator and advances the registry to the epoch its
// correlation penalty falls due.
func slashAt(t *testing.T, m *Manager, sdb *state.StateDB, victims []common.Address, epoch uint64) {
	t.Helper()
	for _, v := range victims {
		if _, _, err := m.Slash(v, epoch); err != nil {
			t.Fatal(err)
		}
	}
}

func TestCorrelationPenaltyScalesWithTheAttack(t *testing.T) {
	// The same offence, committed alone and committed together, must cost
	// wildly different amounts. That difference is what makes the penalty a
	// deterrent against coordination rather than against running a validator.
	measure := func(t *testing.T, validators, offenders int) *big.Int {
		t.Helper()
		sdb := newTestState(t)
		m := NewManager(sdb)
		for i := 1; i <= validators; i++ {
			deposit(t, m, sdb, addr(byte(i)), MinDeposit, 0)
		}
		// Activate everyone.
		for epoch := uint64(1); epoch <= uint64(validators/MinChurnLimit)+2; epoch++ {
			m.ProcessEpoch(epoch, NewParticipation(), epoch)
		}

		const offenceEpoch = uint64(20)
		var victims []common.Address
		for i := 1; i <= offenders; i++ {
			victims = append(victims, addr(byte(i)))
		}
		slashAt(t, m, sdb, victims, offenceEpoch)

		before, err := m.Registry().ByAddress(addr(1))
		if err != nil {
			t.Fatal(err)
		}

		// Run to the epoch the correlation penalty falls due.
		due := offenceEpoch + CorrelationPenaltyEpochOffset
		for epoch := offenceEpoch + 1; epoch <= due; epoch++ {
			if _, err := m.ProcessEpoch(epoch, NewParticipation(), epoch); err != nil {
				t.Fatal(err)
			}
		}

		after, err := m.Registry().ByAddress(addr(1))
		if err != nil {
			t.Fatal(err)
		}
		return new(big.Int).Sub(before.Balance, after.Balance)
	}

	// The set has to be large enough that one validator is a small share of
	// it. In a set of twelve, a single validator is already eight percent of
	// the stake, and the formula correctly treats that as substantial.
	isolated := measure(t, 40, 1)
	coordinated := measure(t, 40, 14)

	if isolated.Sign() == 0 {
		t.Fatal("an isolated offence was not penalised at all")
	}
	if coordinated.Cmp(isolated) <= 0 {
		t.Fatalf("a coordinated attack cost %s, an isolated fault %s: coordination must cost more",
			coordinated, isolated)
	}
	// A third of the network equivocating together should cost several times
	// what one validator alone does.
	threshold := new(big.Int).Mul(isolated, big.NewInt(5))
	if coordinated.Cmp(threshold) < 0 {
		t.Fatalf("coordinated %s is not meaningfully worse than isolated %s", coordinated, isolated)
	}
	t.Logf("isolated fault: %s wei; coordinated attack: %s wei", isolated, coordinated)
}

func TestCorrelationPenaltyIsChargedOnce(t *testing.T) {
	sdb := newTestState(t)
	m := NewManager(sdb)
	for i := 1; i <= 6; i++ {
		deposit(t, m, sdb, addr(byte(i)), MinDeposit, 0)
	}
	for epoch := uint64(1); epoch <= 3; epoch++ {
		m.ProcessEpoch(epoch, NewParticipation(), epoch)
	}

	const offenceEpoch = uint64(10)
	slashAt(t, m, sdb, []common.Address{addr(1)}, offenceEpoch)

	due := offenceEpoch + CorrelationPenaltyEpochOffset
	var charged int
	var balanceAfterCharge *big.Int
	for epoch := offenceEpoch + 1; epoch <= due+3; epoch++ {
		report, err := m.ProcessEpoch(epoch, NewParticipation(), epoch)
		if err != nil {
			t.Fatal(err)
		}
		if len(report.Correlated) > 0 {
			charged++
			v, _ := m.Registry().ByAddress(addr(1))
			balanceAfterCharge = new(big.Int).Set(v.Balance)
		}
	}
	if charged != 1 {
		t.Fatalf("the correlation penalty was charged %d times, want once", charged)
	}
	// And the balance stops moving afterwards.
	v, _ := m.Registry().ByAddress(addr(1))
	if v.Balance.Cmp(balanceAfterCharge) != 0 {
		t.Fatal("a slashed validator kept losing stake after its penalty was charged")
	}
}

func TestCorrelationPenaltyKeepsTheInvariant(t *testing.T) {
	sdb := newTestState(t)
	m := NewManager(sdb)
	for i := 1; i <= 8; i++ {
		deposit(t, m, sdb, addr(byte(i)), MinDeposit, 0)
	}
	for epoch := uint64(1); epoch <= 3; epoch++ {
		m.ProcessEpoch(epoch, NewParticipation(), epoch)
	}
	slashAt(t, m, sdb, []common.Address{addr(1), addr(2), addr(3)}, 10)

	for epoch := uint64(11); epoch <= 10+CorrelationPenaltyEpochOffset+1; epoch++ {
		if _, err := m.ProcessEpoch(epoch, NewParticipation(), epoch); err != nil {
			t.Fatal(err)
		}
	}

	// The staking account must still hold exactly what validators own, after
	// burning both the immediate and the correlated penalties.
	total, err := m.TotalStaked()
	if err != nil {
		t.Fatal(err)
	}
	if got := sdb.GetBalance(StakingAddress); got.Cmp(total) != 0 {
		t.Fatalf("the staking account holds %s but validators own %s", got, total)
	}
}
