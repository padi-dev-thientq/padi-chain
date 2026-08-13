package chain

import (
	"encoding/json"
	"fmt"
	"math/big"
	"os"

	"layer1/common"
	"layer1/core"
	"layer1/db"
	"layer1/staking"
	"layer1/state"
	"layer1/trie"
)

// GenesisAccount is a pre-funded account in the genesis state.
type GenesisAccount struct {
	Balance *big.Int                    `json:"balance"`
	Nonce   uint64                      `json:"nonce,omitempty"`
	Code    []byte                      `json:"code,omitempty"`
	Storage map[common.Hash]common.Hash `json:"storage,omitempty"`
}

// Genesis describes the first block and the state it starts from.
type Genesis struct {
	ChainID   *big.Int                          `json:"chainId"`
	Timestamp uint64                            `json:"timestamp"`
	GasLimit  uint64                            `json:"gasLimit"`
	BaseFee   *big.Int                          `json:"baseFee"`
	ExtraData []byte                            `json:"extraData,omitempty"`
	Coinbase  common.Address                    `json:"coinbase"`
	Alloc     map[common.Address]GenesisAccount `json:"alloc"`
	// Validators are the addresses allowed to propose blocks.
	Validators []common.Address `json:"validators"`
	// BlockPeriod is the target seconds between blocks.
	BlockPeriod uint64 `json:"blockPeriod"`
	// WithdrawalAddresses maps a genesis validator to where its stake returns
	// if it exits. A validator with no entry withdraws to itself.
	WithdrawalAddresses map[common.Address]common.Address `json:"withdrawalAddresses,omitempty"`
	// BLSKeys maps a genesis validator to the key it attests with. Omitted
	// entries are derived from the validator address, which is convenient for
	// a development chain and wrong for a real one.
	BLSKeys map[common.Address][]byte `json:"blsKeys,omitempty"`
}

// DefaultGenesis returns a development genesis with the given validators.
func DefaultGenesis(chainID *big.Int, validators []common.Address) *Genesis {
	return &Genesis{
		ChainID:     chainID,
		Timestamp:   0,
		GasLimit:    30_000_000,
		BaseFee:     big.NewInt(1_000_000_000),
		ExtraData:   []byte("layer1 genesis"),
		Alloc:       make(map[common.Address]GenesisAccount),
		Validators:  validators,
		BlockPeriod: 2,
	}
}

// LoadGenesis reads a genesis specification from a JSON file.
func LoadGenesis(path string) (*Genesis, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("chain: reading genesis: %w", err)
	}
	var raw genesisJSON
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("chain: parsing genesis: %w", err)
	}
	return raw.toGenesis()
}

// Save writes the genesis specification to a JSON file.
func (g *Genesis) Save(path string) error {
	data, err := json.MarshalIndent(g.toJSON(), "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0o644)
}

// genesisJSON is the on-disk form, with quantities as hex strings so a genesis
// file stays readable and unambiguous about large numbers.
type genesisJSON struct {
	ChainID     string                        `json:"chainId"`
	Timestamp   string                        `json:"timestamp"`
	GasLimit    string                        `json:"gasLimit"`
	BaseFee     string                        `json:"baseFee"`
	ExtraData   string                        `json:"extraData,omitempty"`
	Coinbase    string                        `json:"coinbase,omitempty"`
	Alloc       map[string]genesisAccountJSON `json:"alloc"`
	Validators  []string                      `json:"validators"`
	BlockPeriod uint64                        `json:"blockPeriod"`
}

type genesisAccountJSON struct {
	Balance string            `json:"balance"`
	Nonce   uint64            `json:"nonce,omitempty"`
	Code    string            `json:"code,omitempty"`
	Storage map[string]string `json:"storage,omitempty"`
}

func (g *Genesis) toJSON() *genesisJSON {
	out := &genesisJSON{
		ChainID:     common.EncodeHexBig(g.ChainID),
		Timestamp:   common.EncodeHexUint(g.Timestamp),
		GasLimit:    common.EncodeHexUint(g.GasLimit),
		BaseFee:     common.EncodeHexBig(g.BaseFee),
		ExtraData:   common.EncodeHex(g.ExtraData),
		Coinbase:    g.Coinbase.Hex(),
		Alloc:       make(map[string]genesisAccountJSON, len(g.Alloc)),
		BlockPeriod: g.BlockPeriod,
	}
	for addr, account := range g.Alloc {
		entry := genesisAccountJSON{
			Balance: common.EncodeHexBig(account.Balance),
			Nonce:   account.Nonce,
		}
		if len(account.Code) > 0 {
			entry.Code = common.EncodeHex(account.Code)
		}
		if len(account.Storage) > 0 {
			entry.Storage = make(map[string]string, len(account.Storage))
			for k, v := range account.Storage {
				entry.Storage[k.Hex()] = v.Hex()
			}
		}
		out.Alloc[addr.Hex()] = entry
	}
	for _, v := range g.Validators {
		out.Validators = append(out.Validators, v.Hex())
	}
	return out
}

func (j *genesisJSON) toGenesis() (*Genesis, error) {
	chainID, err := common.DecodeHexBig(j.ChainID)
	if err != nil {
		return nil, fmt.Errorf("chain: chainId: %w", err)
	}
	timestamp, err := common.DecodeHexUint(j.Timestamp)
	if err != nil {
		return nil, fmt.Errorf("chain: timestamp: %w", err)
	}
	gasLimit, err := common.DecodeHexUint(j.GasLimit)
	if err != nil {
		return nil, fmt.Errorf("chain: gasLimit: %w", err)
	}
	baseFee, err := common.DecodeHexBig(j.BaseFee)
	if err != nil {
		return nil, fmt.Errorf("chain: baseFee: %w", err)
	}
	extra, err := common.DecodeHex(j.ExtraData)
	if err != nil {
		return nil, fmt.Errorf("chain: extraData: %w", err)
	}

	g := &Genesis{
		ChainID:     chainID,
		Timestamp:   timestamp,
		GasLimit:    gasLimit,
		BaseFee:     baseFee,
		ExtraData:   extra,
		Alloc:       make(map[common.Address]GenesisAccount, len(j.Alloc)),
		BlockPeriod: j.BlockPeriod,
	}
	if j.Coinbase != "" {
		if g.Coinbase, err = common.HexToAddress(j.Coinbase); err != nil {
			return nil, fmt.Errorf("chain: coinbase: %w", err)
		}
	}
	for addrHex, account := range j.Alloc {
		addr, err := common.HexToAddress(addrHex)
		if err != nil {
			return nil, fmt.Errorf("chain: alloc key %q: %w", addrHex, err)
		}
		balance, err := common.DecodeHexBig(account.Balance)
		if err != nil {
			return nil, fmt.Errorf("chain: alloc %s balance: %w", addrHex, err)
		}
		entry := GenesisAccount{Balance: balance, Nonce: account.Nonce}
		if account.Code != "" {
			if entry.Code, err = common.DecodeHex(account.Code); err != nil {
				return nil, fmt.Errorf("chain: alloc %s code: %w", addrHex, err)
			}
		}
		if len(account.Storage) > 0 {
			entry.Storage = make(map[common.Hash]common.Hash, len(account.Storage))
			for k, v := range account.Storage {
				key, err := common.HexToHash(k)
				if err != nil {
					return nil, fmt.Errorf("chain: alloc %s storage key: %w", addrHex, err)
				}
				value, err := common.HexToHash(v)
				if err != nil {
					return nil, fmt.Errorf("chain: alloc %s storage value: %w", addrHex, err)
				}
				entry.Storage[key] = value
			}
		}
		g.Alloc[addr] = entry
	}
	for _, v := range j.Validators {
		addr, err := common.HexToAddress(v)
		if err != nil {
			return nil, fmt.Errorf("chain: validator %q: %w", v, err)
		}
		g.Validators = append(g.Validators, addr)
	}
	return g, nil
}

// ToBlock builds the genesis block and writes its state into store.
func (g *Genesis) ToBlock(store db.Database) (*core.Block, error) {
	statedb, err := state.New(common.Hash{}, store)
	if err != nil {
		return nil, err
	}
	for addr, account := range g.Alloc {
		if account.Balance != nil {
			statedb.AddBalance(addr, account.Balance)
		}
		if account.Nonce != 0 {
			statedb.SetNonce(addr, account.Nonce)
		}
		if len(account.Code) > 0 {
			statedb.SetCode(addr, account.Code)
		}
		for key, value := range account.Storage {
			statedb.SetState(addr, key, value)
		}
	}
	// Seed the validator registry. The genesis validators are staked by the
	// protocol rather than by a deposit transaction, because there is no chain
	// yet to carry one — the same bootstrapping problem Ethereum solved with a
	// deposit contract pre-populated before the merge.
	if len(g.Validators) > 0 {
		manager := staking.NewManager(statedb)
		for _, validator := range g.Validators {
			withdrawal := validator
			if g.WithdrawalAddresses != nil {
				if w, ok := g.WithdrawalAddresses[validator]; ok {
					withdrawal = w
				}
			}
			statedb.AddBalance(staking.StakingAddress, staking.MinDeposit)

			// Genesis validators need an attestation key like any other, but
			// there is no deposit transaction to carry one. Deriving it from
			// the validator address keeps genesis reproducible from the
			// specification alone; a real deployment would list the keys.
			blsKey := g.BLSKeys[validator]
			if len(blsKey) == 0 {
				blsKey = staking.DeriveGenesisBLSKey(validator).PublicKey().Bytes()
			}

			v, err := manager.Deposit(validator, withdrawal, staking.MinDeposit, 0)
			if err != nil {
				return nil, fmt.Errorf("chain: staking genesis validator %s: %w", validator, err)
			}
			v.BLSPublicKey = blsKey
			// Genesis validators are active from the first block; there is no
			// earlier epoch for them to have queued in.
			v.Status = staking.StatusActive
			v.ActivationEpoch = 0
			manager.Registry().Put(v)
		}
	}

	// Genesis accounts are written as specified, including ones that would
	// otherwise be pruned as empty.
	root, err := statedb.Commit(false)
	if err != nil {
		return nil, fmt.Errorf("chain: committing genesis state: %w", err)
	}

	header := &core.Header{
		ParentHash:  common.Hash{},
		Coinbase:    g.Coinbase,
		StateRoot:   root,
		TxRoot:      common.Hash(trie.EmptyRoot),
		ReceiptRoot: common.Hash(trie.EmptyRoot),
		Number:      new(big.Int),
		GasLimit:    g.GasLimit,
		GasUsed:     0,
		Time:        g.Timestamp,
		Extra:       g.ExtraData,
		BaseFee:     g.BaseFee,
	}
	return core.NewBlock(header, nil, nil), nil
}

// Commit writes the genesis block and its state to store.
func (g *Genesis) Commit(store db.Database) (*core.Block, error) {
	block, err := g.ToBlock(store)
	if err != nil {
		return nil, err
	}
	batch := store.NewBatch()
	if err := WriteBlock(batch, block); err != nil {
		return nil, err
	}
	if err := WriteCanonicalHash(batch, 0, block.Hash()); err != nil {
		return nil, err
	}
	if err := WriteHeadBlockHash(batch, block.Hash()); err != nil {
		return nil, err
	}
	if err := WriteGenesisHash(batch, block.Hash()); err != nil {
		return nil, err
	}
	config, err := json.Marshal(g.toJSON())
	if err != nil {
		return nil, err
	}
	if err := WriteChainConfig(batch, config); err != nil {
		return nil, err
	}
	if err := batch.Write(); err != nil {
		return nil, err
	}
	return block, nil
}
