package core

import (
	"errors"
	"fmt"
	"math/big"

	"layer1/common"
	"layer1/crypto/bls12381"
	"layer1/rlp"
)

// Aggregated attestations.
//
// A quorum certificate made of one signature per validator grows with the set
// and costs as much to verify as it does to build. The aggregate form is one
// 96-byte signature plus a bitfield naming who is in it, and verifying it is
// two pairings regardless of how many signed. That is the difference between a
// validator set of hundreds and one of hundreds of thousands.
//
// The bitfield indexes into the ordered validator set for the height, so it
// only means anything alongside that set — which is exactly the state a node
// already needs to verify the block.

var (
	ErrBitfieldLength   = errors.New("core: bitfield does not match the validator set")
	ErrNoSigners        = errors.New("core: aggregate names no signers")
	ErrAggregateInvalid = errors.New("core: aggregate signature is invalid")
)

// Bitfield marks which validators, by index in the ordered set, contributed.
type Bitfield []byte

// NewBitfield returns a bitfield sized for a validator set.
func NewBitfield(validators int) Bitfield {
	return make(Bitfield, (validators+7)/8)
}

// Set marks an index.
func (b Bitfield) Set(index int) {
	if index < 0 || index/8 >= len(b) {
		return
	}
	b[index/8] |= 1 << uint(index%8)
}

// Has reports whether an index is marked.
func (b Bitfield) Has(index int) bool {
	if index < 0 || index/8 >= len(b) {
		return false
	}
	return b[index/8]&(1<<uint(index%8)) != 0
}

// Count returns how many indices are marked.
func (b Bitfield) Count() int {
	n := 0
	for _, by := range b {
		for by != 0 {
			n += int(by & 1)
			by >>= 1
		}
	}
	return n
}

// Indices returns the marked indices in order.
func (b Bitfield) Indices(limit int) []int {
	var out []int
	for i := 0; i < limit; i++ {
		if b.Has(i) {
			out = append(out, i)
		}
	}
	return out
}

// Or merges another bitfield into b, which is how a proposer combines
// aggregates it received from different peers.
func (b Bitfield) Or(other Bitfield) {
	for i := range b {
		if i < len(other) {
			b[i] |= other[i]
		}
	}
}

// Overlaps reports whether two bitfields mark any index in common. Aggregates
// may only be combined when they do not: adding a validator's signature twice
// would produce a signature that verifies against nothing.
func (b Bitfield) Overlaps(other Bitfield) bool {
	for i := range b {
		if i < len(other) && b[i]&other[i] != 0 {
			return true
		}
	}
	return false
}

// fits reports whether the bitfield is sized for a set and marks nothing past
// its end. Trailing bits must be clear, or two encodings could name the same
// signers.
func (b Bitfield) fits(validators int) bool {
	if len(b) != (validators+7)/8 {
		return false
	}
	for i := validators; i < len(b)*8; i++ {
		if b.Has(i) {
			return false
		}
	}
	return true
}

// AggregateAttestation is a set of validators' votes for one block, collapsed
// into a single signature.
type AggregateAttestation struct {
	Number    uint64
	BlockHash common.Hash
	// Signers indexes the ordered validator set for this height.
	Signers Bitfield
	// Signature is the aggregate over all the signers' votes.
	Signature []byte
}

// AttestationMessage is what a validator signs. The chain id is bound in so a
// vote cannot be replayed onto another network, and the domain keeps it
// disjoint from every other signature the protocol produces.
func AttestationMessage(chainID *big.Int, number uint64, blockHash common.Hash) []byte {
	enc, err := rlp.Encode([]any{
		[]byte("layer1/attestation/bls/v1"),
		chainID,
		number,
		blockHash,
	})
	if err != nil {
		panic(fmt.Sprintf("core: encoding attestation message: %v", err))
	}
	return enc
}

// SignAttestationBLS produces a validator's vote.
func SignAttestationBLS(key *bls12381.SecretKey, chainID *big.Int, number uint64, blockHash common.Hash) []byte {
	return key.Sign(AttestationMessage(chainID, number, blockHash)).Bytes()
}

// NewAggregate starts an empty aggregate for a height.
func NewAggregate(number uint64, blockHash common.Hash, validators int) *AggregateAttestation {
	return &AggregateAttestation{
		Number:    number,
		BlockHash: blockHash,
		Signers:   NewBitfield(validators),
	}
}

// Add folds one validator's signature into the aggregate.
//
// A repeat from the same index is ignored rather than added: adding a
// signature twice changes the aggregate into one that verifies against nothing,
// so a duplicate vote must not be allowed to corrupt a certificate in progress.
func (a *AggregateAttestation) Add(index int, signature []byte) error {
	if a.Signers.Has(index) {
		return nil
	}
	sig, err := bls12381.SignatureFromBytes(signature)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrAggregateInvalid, err)
	}

	if len(a.Signature) == 0 {
		a.Signature = append([]byte(nil), signature...)
	} else {
		existing, err := bls12381.SignatureFromBytes(a.Signature)
		if err != nil {
			return fmt.Errorf("%w: %v", ErrAggregateInvalid, err)
		}
		combined, err := bls12381.AggregateSignatures([]*bls12381.Signature{existing, sig})
		if err != nil {
			return err
		}
		a.Signature = combined.Bytes()
	}
	a.Signers.Set(index)
	return nil
}

// Merge folds another aggregate for the same target into this one.
func (a *AggregateAttestation) Merge(other *AggregateAttestation) error {
	if a.Number != other.Number || a.BlockHash != other.BlockHash {
		return fmt.Errorf("%w: aggregates target different blocks", ErrWrongTarget)
	}
	if len(other.Signature) == 0 {
		return nil
	}
	// Overlapping aggregates cannot be combined: the shared signatures would
	// be counted twice and the result would verify against nothing.
	if a.Signers.Overlaps(other.Signers) {
		return errors.New("core: cannot merge aggregates with overlapping signers")
	}
	if len(a.Signature) == 0 {
		a.Signature = append([]byte(nil), other.Signature...)
		a.Signers.Or(other.Signers)
		return nil
	}

	mine, err := bls12381.SignatureFromBytes(a.Signature)
	if err != nil {
		return err
	}
	theirs, err := bls12381.SignatureFromBytes(other.Signature)
	if err != nil {
		return err
	}
	combined, err := bls12381.AggregateSignatures([]*bls12381.Signature{mine, theirs})
	if err != nil {
		return err
	}
	a.Signature = combined.Bytes()
	a.Signers.Or(other.Signers)
	return nil
}

// Count returns how many validators are in the aggregate.
func (a *AggregateAttestation) Count() int { return a.Signers.Count() }

// IsEmpty reports whether the aggregate carries nothing.
func (a *AggregateAttestation) IsEmpty() bool {
	return a == nil || len(a.Signature) == 0 || a.Signers.Count() == 0
}

// Verify checks the aggregate against the ordered validator public keys for its
// height, and returns the indices that signed.
//
// The keys must be in the same order every node derives, since the bitfield
// means nothing otherwise. Each key is assumed to have had its proof of
// possession checked at registration; without that, a rogue key could forge an
// aggregate nobody agreed to.
func (a *AggregateAttestation) Verify(chainID *big.Int, keys []*bls12381.PublicKey) ([]int, error) {
	if a.IsEmpty() {
		return nil, ErrNoSigners
	}
	if !a.Signers.fits(len(keys)) {
		return nil, fmt.Errorf("%w: %d bytes for %d validators", ErrBitfieldLength, len(a.Signers), len(keys))
	}

	indices := a.Signers.Indices(len(keys))
	if len(indices) == 0 {
		return nil, ErrNoSigners
	}

	signers := make([]*bls12381.PublicKey, 0, len(indices))
	for _, i := range indices {
		if keys[i] == nil {
			return nil, fmt.Errorf("%w: validator %d has no key", ErrAggregateInvalid, i)
		}
		signers = append(signers, keys[i])
	}

	sig, err := bls12381.SignatureFromBytes(a.Signature)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrAggregateInvalid, err)
	}
	message := AttestationMessage(chainID, a.Number, a.BlockHash)
	if !bls12381.FastAggregateVerify(signers, message, sig) {
		return nil, ErrAggregateInvalid
	}
	return indices, nil
}

// Encode serializes the aggregate for inclusion in a header.
func (a *AggregateAttestation) Encode() ([]byte, error) {
	if a.IsEmpty() {
		return nil, nil
	}
	return rlp.Encode(a)
}

// DecodeAggregate parses an aggregate from a header.
func DecodeAggregate(data []byte) (*AggregateAttestation, error) {
	if len(data) == 0 {
		return nil, nil
	}
	out := new(AggregateAttestation)
	if err := rlp.Decode(data, out); err != nil {
		return nil, fmt.Errorf("core: decoding aggregate attestation: %w", err)
	}
	return out, nil
}
