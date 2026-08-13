package staking

import (
	"errors"
	"fmt"
	"math/big"

	"layer1/common"
)

// The registry's storage layout.
//
// Records are laid out the way a Solidity contract would lay them out — one
// value per slot, indexed by hashing — so the whole registry is ordinary
// account storage. Nothing here needs a side channel: `eth_getStorageAt` and a
// Merkle proof work on it exactly as they work on any other contract's state.

var (
	ErrNotFound        = errors.New("staking: no such validator")
	ErrAlreadyExists   = errors.New("staking: address is already a validator")
	ErrBelowMinimum    = errors.New("staking: deposit is below the minimum stake")
	ErrNotActive       = errors.New("staking: validator is not active")
	ErrNotWithdrawable = errors.New("staking: validator's stake is not withdrawable yet")
	ErrAlreadySlashed  = errors.New("staking: validator is already slashed")
	ErrBadBLSKey       = errors.New("staking: invalid attestation key")
	ErrBadPossession   = errors.New("staking: invalid proof of possession")
)

// Status is where a validator sits in its lifecycle.
type Status uint8

const (
	// StatusPending is a deposit accepted but not yet activated.
	StatusPending Status = iota
	// StatusActive is a validator in the set, expected to propose and attest.
	StatusActive
	// StatusExiting has requested to leave and is still in the set until its
	// exit epoch arrives.
	StatusExiting
	// StatusExited is out of the set, with funds locked until withdrawable.
	StatusExited
	// StatusSlashed was ejected for provable misbehaviour.
	StatusSlashed
	// StatusWithdrawn has taken its stake back and holds nothing.
	StatusWithdrawn
)

func (s Status) String() string {
	switch s {
	case StatusPending:
		return "pending"
	case StatusActive:
		return "active"
	case StatusExiting:
		return "exiting"
	case StatusExited:
		return "exited"
	case StatusSlashed:
		return "slashed"
	case StatusWithdrawn:
		return "withdrawn"
	default:
		return "unknown"
	}
}

// Validator is one registry entry.
type Validator struct {
	Index             uint64
	Address           common.Address
	WithdrawalAddress common.Address
	// BLSPublicKey is the key this validator attests with. It is separate from
	// the address key: attestations are aggregated, which needs a pairing-based
	// scheme, while transactions stay on the curve the EVM understands.
	BLSPublicKey      []byte
	Balance           *big.Int
	EffectiveBalance  *big.Int
	Status            Status
	ActivationEpoch   uint64
	ExitEpoch         uint64
	WithdrawableEpoch uint64
	SlashedEpoch      uint64
}

// IsActiveAt reports whether the validator counts toward the set in an epoch.
//
// A validator that has requested to exit still counts until its exit epoch
// arrives: it is still expected to attest, and still slashable if it does not
// behave. Dropping it the moment it asked would let a validator escape
// responsibility for the epoch it is in.
func (v *Validator) IsActiveAt(epoch uint64) bool {
	switch v.Status {
	case StatusActive:
		return epoch >= v.ActivationEpoch
	case StatusExiting:
		return epoch >= v.ActivationEpoch && epoch < v.ExitEpoch
	default:
		return false
	}
}

// FarFutureEpoch marks an epoch that has not been scheduled.
const FarFutureEpoch = ^uint64(0)

// StateAccess is the slice of state the registry reads and writes.
type StateAccess interface {
	GetState(common.Address, common.Hash) common.Hash
	SetState(common.Address, common.Hash, common.Hash)
	GetBalance(common.Address) *big.Int
	AddBalance(common.Address, *big.Int)
	SubBalance(common.Address, *big.Int)
}

// Registry reads and writes validator records in account storage.
type Registry struct {
	state StateAccess
}

// NewRegistry opens the registry over a state view.
func NewRegistry(state StateAccess) *Registry { return &Registry{state: state} }

// Slot keys. Each is derived by hashing a label with the index or address, so
// records cannot collide however many there are.
var (
	slotCount      = common.Keccak256([]byte("staking/count"))
	slotEpochState = common.Keccak256([]byte("staking/epoch-state"))
)

func slotFor(label string, index uint64) common.Hash {
	var buf [8]byte
	for i := 0; i < 8; i++ {
		buf[7-i] = byte(index >> (8 * uint(i)))
	}
	return common.Keccak256([]byte(label), buf[:])
}

func slotForAddress(label string, addr common.Address) common.Hash {
	return common.Keccak256([]byte(label), addr[:])
}

// Count returns how many validators have ever been registered. Indices are
// never reused, so this only grows.
func (r *Registry) Count() uint64 {
	return r.state.GetState(StakingAddress, slotCount).Big().Uint64()
}

func (r *Registry) setCount(n uint64) {
	r.state.SetState(StakingAddress, slotCount, common.BigToHash(new(big.Int).SetUint64(n)))
}

// IndexOf returns a validator's index, and whether it exists. The stored value
// is offset by one so that an absent entry and index zero are distinguishable.
func (r *Registry) IndexOf(addr common.Address) (uint64, bool) {
	raw := r.state.GetState(StakingAddress, slotForAddress("staking/index", addr)).Big()
	if raw.Sign() == 0 {
		return 0, false
	}
	return raw.Uint64() - 1, true
}

func (r *Registry) setIndex(addr common.Address, index uint64) {
	value := new(big.Int).SetUint64(index + 1)
	r.state.SetState(StakingAddress, slotForAddress("staking/index", addr), common.BigToHash(value))
}

// packedCore holds the fields small enough to share one slot: status and the
// three lifecycle epochs. Packing them means a status change costs one storage
// write rather than four.
func packCore(v *Validator) common.Hash {
	var out [32]byte
	out[0] = byte(v.Status)
	putUint64(out[1:9], v.ActivationEpoch)
	putUint64(out[9:17], v.ExitEpoch)
	putUint64(out[17:25], v.WithdrawableEpoch)
	putUint64(out[25:32], v.SlashedEpoch) // seven bytes is ample for an epoch
	return out
}

func unpackCore(h common.Hash, v *Validator) {
	v.Status = Status(h[0])
	v.ActivationEpoch = getUint64(h[1:9])
	v.ExitEpoch = getUint64(h[9:17])
	v.WithdrawableEpoch = getUint64(h[17:25])
	v.SlashedEpoch = getUint64Short(h[25:32])
}

func putUint64(dst []byte, v uint64) {
	for i := 0; i < len(dst) && i < 8; i++ {
		dst[len(dst)-1-i] = byte(v >> (8 * uint(i)))
	}
}

func getUint64(src []byte) uint64 {
	var v uint64
	for _, b := range src {
		v = v<<8 | uint64(b)
	}
	return v
}

func getUint64Short(src []byte) uint64 { return getUint64(src) }

// Get loads a validator by index.
func (r *Registry) Get(index uint64) (*Validator, error) {
	if index >= r.Count() {
		return nil, fmt.Errorf("%w: index %d", ErrNotFound, index)
	}
	v := &Validator{Index: index}
	unpackCore(r.state.GetState(StakingAddress, slotFor("staking/core", index)), v)
	v.Address = common.BytesToAddress(r.state.GetState(StakingAddress, slotFor("staking/addr", index)).Bytes())
	v.WithdrawalAddress = common.BytesToAddress(r.state.GetState(StakingAddress, slotFor("staking/withdrawal", index)).Bytes())
	v.Balance = r.state.GetState(StakingAddress, slotFor("staking/balance", index)).Big()
	v.EffectiveBalance = computeEffectiveBalance(v.Balance)

	// A 48-byte compressed key spans two slots.
	high := r.state.GetState(StakingAddress, slotFor("staking/bls-hi", index))
	low := r.state.GetState(StakingAddress, slotFor("staking/bls-lo", index))
	key := make([]byte, 0, BLSPublicKeyLength)
	key = append(key, high[:]...)
	key = append(key, low[16:]...)
	if !isZeroBytes(key) {
		v.BLSPublicKey = key
	}
	return v, nil
}

// BLSPublicKeyLength is the length of a compressed BLS12-381 public key.
const BLSPublicKeyLength = 48

func isZeroBytes(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}

// ByAddress loads a validator by its signing address.
func (r *Registry) ByAddress(addr common.Address) (*Validator, error) {
	index, ok := r.IndexOf(addr)
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrNotFound, addr)
	}
	return r.Get(index)
}

// Put writes a validator record.
func (r *Registry) Put(v *Validator) {
	r.state.SetState(StakingAddress, slotFor("staking/core", v.Index), packCore(v))
	r.state.SetState(StakingAddress, slotFor("staking/addr", v.Index), v.Address.Hash())
	r.state.SetState(StakingAddress, slotFor("staking/withdrawal", v.Index), v.WithdrawalAddress.Hash())
	r.state.SetState(StakingAddress, slotFor("staking/balance", v.Index), common.BigToHash(v.Balance))

	var high, low common.Hash
	if len(v.BLSPublicKey) == BLSPublicKeyLength {
		copy(high[:], v.BLSPublicKey[:32])
		copy(low[16:], v.BLSPublicKey[32:])
	}
	r.state.SetState(StakingAddress, slotFor("staking/bls-hi", v.Index), high)
	r.state.SetState(StakingAddress, slotFor("staking/bls-lo", v.Index), low)
}

// Append adds a new validator and returns its index.
func (r *Registry) Append(v *Validator) uint64 {
	index := r.Count()
	v.Index = index
	r.Put(v)
	r.setIndex(v.Address, index)
	r.setCount(index + 1)
	return index
}

// All returns every registered validator, in index order.
func (r *Registry) All() ([]*Validator, error) {
	count := r.Count()
	out := make([]*Validator, 0, count)
	for i := uint64(0); i < count; i++ {
		v, err := r.Get(i)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}

// ActiveAt returns the validators that make up the set in an epoch, ordered by
// index so every node derives the same list.
func (r *Registry) ActiveAt(epoch uint64) ([]*Validator, error) {
	all, err := r.All()
	if err != nil {
		return nil, err
	}
	var active []*Validator
	for _, v := range all {
		if v.IsActiveAt(epoch) {
			active = append(active, v)
		}
	}
	return active, nil
}

// ActiveBLSKeysAt returns the attestation keys of the active set, in the same
// order as ActiveAddressesAt.
//
// The order is what an aggregate's bitfield indexes into, so the two must be
// derived the same way on every node — which they are, because both walk the
// registry in index order.
func (r *Registry) ActiveBLSKeysAt(epoch uint64) ([][]byte, error) {
	active, err := r.ActiveAt(epoch)
	if err != nil {
		return nil, err
	}
	out := make([][]byte, 0, len(active))
	for _, v := range active {
		out = append(out, v.BLSPublicKey)
	}
	return out, nil
}

// ActiveAddressesAt returns the signing addresses of the active set.
func (r *Registry) ActiveAddressesAt(epoch uint64) ([]common.Address, error) {
	active, err := r.ActiveAt(epoch)
	if err != nil {
		return nil, err
	}
	out := make([]common.Address, 0, len(active))
	for _, v := range active {
		out = append(out, v.Address)
	}
	return out, nil
}

// TotalActiveStake sums the effective balance of the active set, which is what
// rewards are scaled against.
func (r *Registry) TotalActiveStake(epoch uint64) (*big.Int, error) {
	active, err := r.ActiveAt(epoch)
	if err != nil {
		return nil, err
	}
	total := new(big.Int)
	for _, v := range active {
		total.Add(total, v.EffectiveBalance)
	}
	return total, nil
}

// EpochState is the small amount of bookkeeping the transition needs to carry
// between epochs.
type EpochState struct {
	// LastProcessedEpoch guards against processing an epoch twice.
	LastProcessedEpoch uint64
	// FinalizedEpoch is the most recent epoch known to be final, which the
	// inactivity leak measures its distance from.
	FinalizedEpoch uint64
	// ExitQueueEpoch is the earliest epoch the exit queue has room in, which
	// is how churn is spread rather than bunched.
	ExitQueueEpoch uint64
	// ExitQueueCount is how many exits are already scheduled in that epoch.
	ExitQueueCount uint64
}

// LoadEpochState reads the bookkeeping record.
func (r *Registry) LoadEpochState() EpochState {
	raw := r.state.GetState(StakingAddress, slotEpochState)
	return EpochState{
		LastProcessedEpoch: getUint64(raw[0:8]),
		FinalizedEpoch:     getUint64(raw[8:16]),
		ExitQueueEpoch:     getUint64(raw[16:24]),
		ExitQueueCount:     getUint64(raw[24:32]),
	}
}

// SaveEpochState writes the bookkeeping record.
func (r *Registry) SaveEpochState(s EpochState) {
	var raw [32]byte
	putUint64(raw[0:8], s.LastProcessedEpoch)
	putUint64(raw[8:16], s.FinalizedEpoch)
	putUint64(raw[16:24], s.ExitQueueEpoch)
	putUint64(raw[24:32], s.ExitQueueCount)
	r.state.SetState(StakingAddress, slotEpochState, common.Hash(raw))
}

// The RANDAO mix.
//
// Every block folds its proposer's reveal into a running value held in state.
// Because the reveal is a BLS signature, which is unique per key and message,
// a proposer has no freedom in what it contributes: it can either publish its
// block or withhold it, and nothing in between. That leaves exactly one bit of
// influence per slot, which is the same residual bias Ethereum lives with.

var slotRandaoMix = common.Keccak256([]byte("staking/randao-mix"))

// RandaoMix returns the accumulated randomness.
func (r *Registry) RandaoMix() common.Hash {
	return r.state.GetState(StakingAddress, slotRandaoMix)
}

// SetRandaoMix stores the accumulated randomness.
func (r *Registry) SetRandaoMix(mix common.Hash) {
	r.state.SetState(StakingAddress, slotRandaoMix, mix)
}

// ProposerAt selects the proposer for a slot, weighted by stake.
//
// Selection walks the active set accumulating effective balance until it passes
// a threshold drawn from the seed, so a validator's chance of proposing is its
// share of the stake. The round is mixed in as well, so a fallback round picks
// a different validator rather than the same one twice.
//
// The seed comes from a settled epoch, which means proposers are known for the
// current epoch but not beyond it. That is the same window Ethereum operates
// with: it removes the ability to plan an attack far ahead without claiming to
// make the schedule secret.
func (r *Registry) ProposerAt(epoch uint64, seed common.Hash, slot, round uint64) (common.Address, error) {
	active, err := r.ActiveAt(epoch)
	if err != nil {
		return common.Address{}, err
	}
	if len(active) == 0 {
		return common.Address{}, ErrNotFound
	}

	total := new(big.Int)
	for _, v := range active {
		total.Add(total, v.EffectiveBalance)
	}
	if total.Sign() == 0 {
		// No stake to weight by; fall back to a plain rotation so the chain
		// still makes progress.
		return active[(slot+round)%uint64(len(active))].Address, nil
	}

	var slotBytes, roundBytes [8]byte
	putUint64(slotBytes[:], slot)
	putUint64(roundBytes[:], round)
	draw := common.Keccak256(seed[:], slotBytes[:], roundBytes[:])

	target := new(big.Int).Mod(draw.Big(), total)
	cumulative := new(big.Int)
	for _, v := range active {
		cumulative.Add(cumulative, v.EffectiveBalance)
		if cumulative.Cmp(target) > 0 {
			return v.Address, nil
		}
	}
	return active[len(active)-1].Address, nil
}
