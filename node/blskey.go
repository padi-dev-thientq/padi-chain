package node

import (
	"sync"

	"layer1/crypto/bls12381"
	"layer1/keystore"
	"layer1/staking"
)

// The validator's attestation key.
//
// A validator holds two secrets: the secp256k1 key it signs blocks and
// transactions with, and the BLS key it attests with. Managing two secrets is
// worse than managing one, so the BLS key is derived from the first — the node
// never stores it, and an operator who backs up the validator key has both.
//
// Genesis validators are a special case. Their keys have to be in the genesis
// state before any node exists to register one, so a development genesis
// derives them from the validator address. That key's secret is derivable by
// anyone, which is fine for a test network and unacceptable for a real one; the
// node detects which derivation the registry actually holds and uses that.

type blsKeyCache struct {
	once sync.Once
	key  *bls12381.SecretKey
}

// blsKey returns the attestation key matching what the registry holds for this
// validator, or nil if neither derivation matches.
func (n *Node) blsKey() *bls12381.SecretKey {
	n.blsCache.once.Do(func() {
		if n.config.Validator == nil {
			return
		}
		address := keystore.AddressOf(n.config.Validator)

		registry, err := n.chain.StakingRegistry()
		if err != nil {
			return
		}
		validator, err := registry.ByAddress(address)
		if err != nil || len(validator.BLSPublicKey) == 0 {
			// Not registered yet: use the key a deposit would register.
			n.blsCache.key = n.derivedBLSKey()
			return
		}

		registered := string(validator.BLSPublicKey)
		for _, candidate := range []*bls12381.SecretKey{
			n.derivedBLSKey(),
			staking.DeriveGenesisBLSKey(address),
		} {
			if candidate != nil && string(candidate.PublicKey().Bytes()) == registered {
				n.blsCache.key = candidate
				return
			}
		}
		n.log.Error("the registered attestation key does not match any key this node can derive; it cannot attest",
			"validator", address)
	})
	return n.blsCache.key
}

// derivedBLSKey is the attestation key a node derives from its validator
// secret. This is the key a deposit should register.
func (n *Node) derivedBLSKey() *bls12381.SecretKey {
	if n.config.Validator == nil {
		return nil
	}
	return bls12381.DeriveSecretKey(append([]byte("layer1/validator-bls/v1"), n.config.Validator.Bytes()...))
}

// AttestationKey returns this node's attestation public key, for an operator
// building a deposit transaction.
func (n *Node) AttestationKey() *bls12381.PublicKey {
	key := n.derivedBLSKey()
	if key == nil {
		return nil
	}
	return key.PublicKey()
}

// AttestationPossessionProof returns the proof a deposit must carry.
func (n *Node) AttestationPossessionProof() []byte {
	key := n.derivedBLSKey()
	if key == nil {
		return nil
	}
	return key.ProvePossession().Bytes()
}
