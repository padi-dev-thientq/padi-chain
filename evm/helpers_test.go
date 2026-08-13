package evm

import "padi-chain/crypto/secp256k1"

// secp256k1PrivateKey returns a fixed key so tests are reproducible.
func secp256k1PrivateKey() (*secp256k1.PrivateKey, error) {
	return secp256k1.PrivateKeyFromHex("0x4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318")
}

func signHash(key *secp256k1.PrivateKey, hash [32]byte) (*secp256k1.Signature, error) {
	return secp256k1.Sign(key, hash[:])
}
