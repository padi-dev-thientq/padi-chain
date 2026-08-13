package chain

// rawKeysForTest exposes the encoded attestation keys for a height, which tests
// need in order to build a pool with the same ordering the chain derives.
func (bc *BlockChain) RawKeysForTest(blockNumber uint64) ([][]byte, error) {
	return bc.rawBLSKeysAt(blockNumber)
}
