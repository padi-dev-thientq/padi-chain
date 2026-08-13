package rpc

import (
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"sort"

	"padi-chain/chain"
	"padi-chain/common"
	"padi-chain/core"
	"padi-chain/evm"
	"padi-chain/processor"
	"padi-chain/state"
	"padi-chain/txpool"
)

// Backend is everything the API needs from the node.
type Backend interface {
	Chain() *chain.BlockChain
	TxPool() *txpool.TxPool
	ChainID() *big.Int
	// PeerCount reports how many peers the node is connected to.
	PeerCount() int
	// ClientVersion identifies this software.
	ClientVersion() string
	// Accounts lists the addresses the node holds keys for.
	Accounts() []common.Address
}

// API implements the eth, net and web3 namespaces.
type API struct {
	backend Backend
	filters *filterSet
}

// RegisterAll wires every supported method into a server.
func RegisterAll(s *Server, backend Backend) {
	api := &API{backend: backend, filters: newFilterSet()}

	s.Register("web3_clientVersion", api.clientVersion)
	s.Register("web3_sha3", api.sha3)

	s.Register("net_version", api.netVersion)
	s.Register("net_listening", api.netListening)
	s.Register("net_peerCount", api.peerCount)

	s.Register("eth_chainId", api.chainId)
	s.Register("eth_blockNumber", api.blockNumber)
	s.Register("eth_getBalance", api.getBalance)
	s.Register("eth_getTransactionCount", api.getTransactionCount)
	s.Register("eth_getCode", api.getCode)
	s.Register("eth_getStorageAt", api.getStorageAt)
	s.Register("eth_getBlockByNumber", api.getBlockByNumber)
	s.Register("eth_getBlockByHash", api.getBlockByHash)
	s.Register("eth_getBlockTransactionCountByNumber", api.getBlockTxCountByNumber)
	s.Register("eth_getTransactionByHash", api.getTransactionByHash)
	s.Register("eth_getTransactionReceipt", api.getTransactionReceipt)
	s.Register("eth_sendRawTransaction", api.sendRawTransaction)
	s.Register("eth_call", api.call)
	s.Register("eth_estimateGas", api.estimateGas)
	s.Register("eth_gasPrice", api.gasPrice)
	s.Register("eth_maxPriorityFeePerGas", api.maxPriorityFeePerGas)
	s.Register("eth_getLogs", api.getLogs)
	s.Register("eth_feeHistory", api.feeHistory)

	// Polling filters. Tooling that watches events over plain HTTP installs a
	// filter and asks what has changed, rather than re-scanning ranges.
	s.Register("eth_newFilter", api.newFilter)
	s.Register("eth_newBlockFilter", api.newBlockFilter)
	s.Register("eth_newPendingTransactionFilter", api.newPendingTransactionFilter)
	s.Register("eth_getFilterChanges", api.getFilterChanges)
	s.Register("eth_getFilterLogs", api.getFilterLogs)
	s.Register("eth_uninstallFilter", api.uninstallFilter)

	// Methods with no meaning on this chain, answered rather than refused:
	// tooling probes them and treats an error as a broken node.
	s.Register("eth_protocolVersion", api.protocolVersion)
	s.Register("eth_mining", api.mining)
	s.Register("eth_hashrate", api.hashrate)
	s.Register("eth_coinbase", api.coinbase)
	s.Register("eth_getUncleCountByBlockNumber", api.uncleCount)
	s.Register("eth_getUncleCountByBlockHash", api.uncleCount)
	s.Register("eth_getBlockTransactionCountByHash", api.getBlockTxCountByHash)
	s.Register("eth_getTransactionByBlockNumberAndIndex", api.getTransactionByBlockNumberAndIndex)
	s.Register("eth_getTransactionByBlockHashAndIndex", api.getTransactionByBlockHashAndIndex)
	s.Register("eth_accounts", api.accounts)
	s.Register("eth_syncing", api.syncing)

	s.Register("txpool_status", api.txpoolStatus)
	s.Register("padi_validators", api.validators)
	s.Register("padi_validatorInfo", api.validatorInfo)
	s.Register("padi_nodeInfo", api.nodeInfo)
}

// --- parameter helpers ---

func decodeParam[T any](params []json.RawMessage, index int) (T, error) {
	var out T
	if index >= len(params) {
		return out, NewError(CodeInvalidParams, "missing parameter %d", index)
	}
	if err := json.Unmarshal(params[index], &out); err != nil {
		return out, NewError(CodeInvalidParams, "parameter %d: %v", index, err)
	}
	return out, nil
}

func decodeAddress(params []json.RawMessage, index int) (common.Address, error) {
	raw, err := decodeParam[string](params, index)
	if err != nil {
		return common.Address{}, err
	}
	addr, err := common.HexToAddress(raw)
	if err != nil {
		return common.Address{}, NewError(CodeInvalidParams, "parameter %d is not an address: %v", index, err)
	}
	return addr, nil
}

func decodeHash(params []json.RawMessage, index int) (common.Hash, error) {
	raw, err := decodeParam[string](params, index)
	if err != nil {
		return common.Hash{}, err
	}
	hash, err := common.HexToHash(raw)
	if err != nil {
		return common.Hash{}, NewError(CodeInvalidParams, "parameter %d is not a hash: %v", index, err)
	}
	return hash, nil
}

// resolveBlock turns a block tag or number into a block. Missing parameters
// default to the chain head, which is what the Ethereum API specifies.
func (a *API) resolveBlock(params []json.RawMessage, index int) (*core.Block, error) {
	bc := a.backend.Chain()
	if index >= len(params) {
		return bc.CurrentBlock(), nil
	}
	var tag string
	if err := json.Unmarshal(params[index], &tag); err != nil {
		return nil, NewError(CodeInvalidParams, "block parameter: %v", err)
	}
	switch tag {
	case "", "latest", "pending":
		return bc.CurrentBlock(), nil
	case "safe", "finalized":
		// The finalized head is a real distinction here: blocks above it can
		// still be reorganised, blocks at or below it never can.
		if final := bc.FinalizedBlock(); final != nil {
			return final, nil
		}
		return bc.Genesis(), nil
	case "earliest":
		return bc.Genesis(), nil
	default:
		number, err := common.DecodeHexUint(tag)
		if err != nil {
			return nil, NewError(CodeInvalidParams, "block parameter %q: %v", tag, err)
		}
		block := bc.GetBlockByNumber(number)
		if block == nil {
			return nil, NewError(CodeInvalidParams, "block %d is unknown", number)
		}
		return block, nil
	}
}

func (a *API) stateAt(block *core.Block) (*state.StateDB, error) {
	statedb, err := a.backend.Chain().StateAt(block.StateRoot())
	if err != nil {
		return nil, NewError(CodeInternalError, "state at block %d is unavailable: %v", block.NumberU64(), err)
	}
	return statedb, nil
}

// --- web3 ---

func (a *API) clientVersion(params []json.RawMessage) (any, error) {
	return a.backend.ClientVersion(), nil
}

func (a *API) sha3(params []json.RawMessage) (any, error) {
	raw, err := decodeParam[string](params, 0)
	if err != nil {
		return nil, err
	}
	data, err := common.DecodeHex(raw)
	if err != nil {
		return nil, NewError(CodeInvalidParams, "not hex data: %v", err)
	}
	return common.Keccak256(data).Hex(), nil
}

// --- net ---

func (a *API) netVersion(params []json.RawMessage) (any, error) {
	return a.backend.ChainID().String(), nil
}

func (a *API) netListening(params []json.RawMessage) (any, error) { return true, nil }

func (a *API) peerCount(params []json.RawMessage) (any, error) {
	return common.EncodeHexUint(uint64(a.backend.PeerCount())), nil
}

// --- eth ---

func (a *API) chainId(params []json.RawMessage) (any, error) {
	return common.EncodeHexBig(a.backend.ChainID()), nil
}

func (a *API) blockNumber(params []json.RawMessage) (any, error) {
	return common.EncodeHexUint(a.backend.Chain().CurrentBlock().NumberU64()), nil
}

func (a *API) syncing(params []json.RawMessage) (any, error) {
	// This node imports blocks as they arrive rather than running a separate
	// sync phase, so it is never "syncing" in the API's sense.
	return false, nil
}

func (a *API) accounts(params []json.RawMessage) (any, error) {
	out := []string{}
	for _, addr := range a.backend.Accounts() {
		out = append(out, addr.Hex())
	}
	return out, nil
}

func (a *API) getBalance(params []json.RawMessage) (any, error) {
	addr, err := decodeAddress(params, 0)
	if err != nil {
		return nil, err
	}
	block, err := a.resolveBlock(params, 1)
	if err != nil {
		return nil, err
	}
	statedb, err := a.stateAt(block)
	if err != nil {
		return nil, err
	}
	return common.EncodeHexBig(statedb.GetBalance(addr)), nil
}

func (a *API) getTransactionCount(params []json.RawMessage) (any, error) {
	addr, err := decodeAddress(params, 0)
	if err != nil {
		return nil, err
	}
	// The pending tag must account for transactions still in the pool, or a
	// client sending several transactions in a row would reuse a nonce.
	if len(params) > 1 {
		var tag string
		if json.Unmarshal(params[1], &tag) == nil && tag == "pending" {
			nonce, err := a.backend.TxPool().Nonce(addr)
			if err != nil {
				return nil, NewError(CodeInternalError, "%v", err)
			}
			return common.EncodeHexUint(nonce), nil
		}
	}
	block, err := a.resolveBlock(params, 1)
	if err != nil {
		return nil, err
	}
	statedb, err := a.stateAt(block)
	if err != nil {
		return nil, err
	}
	return common.EncodeHexUint(statedb.GetNonce(addr)), nil
}

func (a *API) getCode(params []json.RawMessage) (any, error) {
	addr, err := decodeAddress(params, 0)
	if err != nil {
		return nil, err
	}
	block, err := a.resolveBlock(params, 1)
	if err != nil {
		return nil, err
	}
	statedb, err := a.stateAt(block)
	if err != nil {
		return nil, err
	}
	return common.EncodeHex(statedb.GetCode(addr)), nil
}

func (a *API) getStorageAt(params []json.RawMessage) (any, error) {
	addr, err := decodeAddress(params, 0)
	if err != nil {
		return nil, err
	}
	slotRaw, err := decodeParam[string](params, 1)
	if err != nil {
		return nil, err
	}
	slotBig, err := common.DecodeHexBig(slotRaw)
	if err != nil {
		return nil, NewError(CodeInvalidParams, "storage slot: %v", err)
	}
	block, err := a.resolveBlock(params, 2)
	if err != nil {
		return nil, err
	}
	statedb, err := a.stateAt(block)
	if err != nil {
		return nil, err
	}
	return statedb.GetState(addr, common.BigToHash(slotBig)).Hex(), nil
}

func (a *API) getBlockByNumber(params []json.RawMessage) (any, error) {
	block, err := a.resolveBlock(params, 0)
	if err != nil {
		return nil, err
	}
	full, _ := decodeParam[bool](params, 1)
	return a.marshalBlock(block, full), nil
}

func (a *API) getBlockByHash(params []json.RawMessage) (any, error) {
	hash, err := decodeHash(params, 0)
	if err != nil {
		return nil, err
	}
	block := a.backend.Chain().GetBlockByHash(hash)
	if block == nil {
		return nil, nil
	}
	full, _ := decodeParam[bool](params, 1)
	return a.marshalBlock(block, full), nil
}

// feeHistory reports recent base fees and how full the blocks were, which is
// what a client uses to choose a priority fee.
//
// The next block's base fee is included as an extra entry, because it is
// already determined by the head — a client that did not know it would have to
// guess how much the fee could move before its transaction lands.
func (a *API) feeHistory(params []json.RawMessage) (any, error) {
	countRaw, err := decodeParam[string](params, 0)
	if err != nil {
		return nil, err
	}
	count, err := common.DecodeHexUint(countRaw)
	if err != nil {
		return nil, NewError(CodeInvalidParams, "block count: %v", err)
	}
	const maxHistory = 1024
	if count > maxHistory {
		count = maxHistory
	}
	head, err := a.resolveBlock(params, 1)
	if err != nil {
		return nil, err
	}

	// Percentiles of the priority fees paid in each block, when asked for.
	var percentiles []float64
	if len(params) > 2 {
		json.Unmarshal(params[2], &percentiles)
	}

	newest := head.NumberU64()
	oldest := uint64(0)
	if newest+1 > count {
		oldest = newest + 1 - count
	}

	bc := a.backend.Chain()
	baseFees := []string{}
	gasUsedRatio := []float64{}
	rewards := [][]string{}

	for n := oldest; n <= newest; n++ {
		block := bc.GetBlockByNumber(n)
		if block == nil {
			continue
		}
		baseFees = append(baseFees, common.EncodeHexBig(block.BaseFee()))
		ratio := 0.0
		if block.GasLimit() > 0 {
			ratio = float64(block.GasUsed()) / float64(block.GasLimit())
		}
		gasUsedRatio = append(gasUsedRatio, ratio)

		if percentiles != nil {
			rewards = append(rewards, blockRewardPercentiles(block, percentiles))
		}
	}

	// The base fee of the block that would come next.
	nextBase := bc.Config().CalcBaseFee(head.Header())
	baseFees = append(baseFees, common.EncodeHexBig(nextBase))

	out := map[string]any{
		"oldestBlock":   common.EncodeHexUint(oldest),
		"baseFeePerGas": baseFees,
		"gasUsedRatio":  gasUsedRatio,
	}
	if percentiles != nil {
		out["reward"] = rewards
	}
	return out, nil
}

// blockRewardPercentiles returns the priority fees at the requested percentiles
// of a block's transactions, ordered by what they actually paid.
func blockRewardPercentiles(block *core.Block, percentiles []float64) []string {
	txs := block.Transactions()
	if len(txs) == 0 {
		out := make([]string, len(percentiles))
		for i := range out {
			out[i] = "0x0"
		}
		return out
	}

	tips := make([]*big.Int, 0, len(txs))
	for _, tx := range txs {
		tips = append(tips, tx.EffectiveTip(block.BaseFee()))
	}
	sort.Slice(tips, func(i, j int) bool { return tips[i].Cmp(tips[j]) < 0 })

	out := make([]string, len(percentiles))
	for i, p := range percentiles {
		idx := int(p / 100 * float64(len(tips)-1))
		if idx < 0 {
			idx = 0
		}
		if idx >= len(tips) {
			idx = len(tips) - 1
		}
		out[i] = common.EncodeHexBig(tips[idx])
	}
	return out
}

// Methods that have no meaning on a proof-of-stake chain with no uncles, but
// which tooling probes and expects an answer to.

func (a *API) protocolVersion(params []json.RawMessage) (any, error) { return "0x41", nil }
func (a *API) mining(params []json.RawMessage) (any, error)          { return false, nil }
func (a *API) hashrate(params []json.RawMessage) (any, error)        { return "0x0", nil }
func (a *API) uncleCount(params []json.RawMessage) (any, error)      { return "0x0", nil }

func (a *API) coinbase(params []json.RawMessage) (any, error) {
	return a.backend.Chain().CurrentBlock().Coinbase().Hex(), nil
}

func (a *API) getBlockTxCountByHash(params []json.RawMessage) (any, error) {
	hash, err := decodeHash(params, 0)
	if err != nil {
		return nil, err
	}
	block := a.backend.Chain().GetBlockByHash(hash)
	if block == nil {
		return nil, nil
	}
	return common.EncodeHexUint(uint64(len(block.Transactions()))), nil
}

func (a *API) getTransactionByBlockNumberAndIndex(params []json.RawMessage) (any, error) {
	block, err := a.resolveBlock(params, 0)
	if err != nil {
		return nil, err
	}
	return a.transactionAt(block, params, 1)
}

func (a *API) getTransactionByBlockHashAndIndex(params []json.RawMessage) (any, error) {
	hash, err := decodeHash(params, 0)
	if err != nil {
		return nil, err
	}
	block := a.backend.Chain().GetBlockByHash(hash)
	if block == nil {
		return nil, nil
	}
	return a.transactionAt(block, params, 1)
}

func (a *API) transactionAt(block *core.Block, params []json.RawMessage, index int) (any, error) {
	raw, err := decodeParam[string](params, index)
	if err != nil {
		return nil, err
	}
	position, err := common.DecodeHexUint(raw)
	if err != nil {
		return nil, NewError(CodeInvalidParams, "index: %v", err)
	}
	txs := block.Transactions()
	if position >= uint64(len(txs)) {
		return nil, nil
	}
	return a.marshalTransaction(txs[position], block.Hash(), block.NumberU64(), position), nil
}

func (a *API) getBlockTxCountByNumber(params []json.RawMessage) (any, error) {
	block, err := a.resolveBlock(params, 0)
	if err != nil {
		return nil, err
	}
	return common.EncodeHexUint(uint64(len(block.Transactions()))), nil
}

func (a *API) getTransactionByHash(params []json.RawMessage) (any, error) {
	hash, err := decodeHash(params, 0)
	if err != nil {
		return nil, err
	}
	bc := a.backend.Chain()
	if tx, entry := bc.GetTransaction(hash); tx != nil {
		return a.marshalTransaction(tx, entry.BlockHash, entry.BlockIndex, entry.Index), nil
	}
	// Not mined yet: it may still be in the pool.
	if tx := a.backend.TxPool().Get(hash); tx != nil {
		return a.marshalTransaction(tx, common.Hash{}, 0, 0), nil
	}
	return nil, nil
}

func (a *API) getTransactionReceipt(params []json.RawMessage) (any, error) {
	hash, err := decodeHash(params, 0)
	if err != nil {
		return nil, err
	}
	bc := a.backend.Chain()
	tx, entry := bc.GetTransaction(hash)
	if tx == nil {
		return nil, nil
	}
	receipts := bc.GetReceipts(entry.BlockHash)
	if entry.Index >= uint64(len(receipts)) {
		return nil, nil
	}
	return a.marshalReceipt(receipts[entry.Index], tx, entry), nil
}

func (a *API) sendRawTransaction(params []json.RawMessage) (any, error) {
	raw, err := decodeParam[string](params, 0)
	if err != nil {
		return nil, err
	}
	data, err := common.DecodeHex(raw)
	if err != nil {
		return nil, NewError(CodeInvalidParams, "not hex data: %v", err)
	}
	tx := new(core.Transaction)
	if err := tx.UnmarshalBinary(data); err != nil {
		return nil, NewError(CodeInvalidParams, "cannot decode transaction: %v", err)
	}
	if err := a.backend.TxPool().Add(tx); err != nil {
		return nil, NewError(CodeExecutionError, "%v", err)
	}
	return tx.Hash().Hex(), nil
}

func (a *API) gasPrice(params []json.RawMessage) (any, error) {
	head := a.backend.Chain().CurrentBlock()
	// Suggest the base fee plus a modest tip, which is what a client needs to
	// be included promptly.
	suggested := new(big.Int).Add(head.BaseFee(), big.NewInt(1_000_000_000))
	return common.EncodeHexBig(suggested), nil
}

func (a *API) maxPriorityFeePerGas(params []json.RawMessage) (any, error) {
	return common.EncodeHexBig(big.NewInt(1_000_000_000)), nil
}

// callArgs is the transaction-shaped object eth_call and eth_estimateGas take.
type callArgs struct {
	From     *string `json:"from"`
	To       *string `json:"to"`
	Gas      *string `json:"gas"`
	GasPrice *string `json:"gasPrice"`
	Value    *string `json:"value"`
	Data     *string `json:"data"`
	Input    *string `json:"input"`
}

func (args *callArgs) toMessage(gasCap uint64, baseFee *big.Int) (*processor.Message, error) {
	msg := &processor.Message{
		Value:      new(big.Int),
		GasLimit:   gasCap,
		GasPrice:   new(big.Int),
		GasFeeCap:  new(big.Int),
		GasTipCap:  new(big.Int),
		SkipChecks: true,
	}
	if args.From != nil {
		from, err := common.HexToAddress(*args.From)
		if err != nil {
			return nil, NewError(CodeInvalidParams, "from: %v", err)
		}
		msg.From = from
	}
	if args.To != nil && *args.To != "" {
		to, err := common.HexToAddress(*args.To)
		if err != nil {
			return nil, NewError(CodeInvalidParams, "to: %v", err)
		}
		msg.To = &to
	}
	if args.Gas != nil {
		gas, err := common.DecodeHexUint(*args.Gas)
		if err != nil {
			return nil, NewError(CodeInvalidParams, "gas: %v", err)
		}
		if gas > 0 && gas < gasCap {
			msg.GasLimit = gas
		}
	}
	if args.Value != nil {
		value, err := common.DecodeHexBig(*args.Value)
		if err != nil {
			return nil, NewError(CodeInvalidParams, "value: %v", err)
		}
		msg.Value = value
	}
	data := args.Data
	if data == nil {
		data = args.Input
	}
	if data != nil {
		decoded, err := common.DecodeHex(*data)
		if err != nil {
			return nil, NewError(CodeInvalidParams, "data: %v", err)
		}
		msg.Data = decoded
	}
	return msg, nil
}

// simulate runs a message against a copy of the state without committing.
func (a *API) simulate(args *callArgs, block *core.Block, gasCap uint64) (*processor.ExecutionResult, error) {
	statedb, err := a.stateAt(block)
	if err != nil {
		return nil, err
	}
	// Work on a copy: a simulation must never affect the node's state.
	statedb = statedb.Copy()

	header := block.Header()
	msg, err := args.toMessage(gasCap, header.BaseFee)
	if err != nil {
		return nil, err
	}

	proc := a.backend.Chain().Processor()
	vm := evm.NewEVM(
		proc.NewBlockContext(header),
		evm.TxContext{Origin: msg.From, GasPrice: msg.GasPrice},
		statedb,
		&evm.ChainConfig{ChainID: a.backend.ChainID()},
		evm.Config{NoBaseFee: true},
	)
	gasPool := new(processor.GasPool).AddGas(gasCap)
	return processor.ApplyMessage(vm, msg, gasPool, statedb)
}

func (a *API) call(params []json.RawMessage) (any, error) {
	args, err := decodeParam[callArgs](params, 0)
	if err != nil {
		return nil, err
	}
	block, err := a.resolveBlock(params, 1)
	if err != nil {
		return nil, err
	}

	result, err := a.simulate(&args, block, block.GasLimit())
	if err != nil {
		return nil, NewError(CodeExecutionError, "%v", err)
	}
	if result.Failed() {
		if revert := result.Revert(); len(revert) > 0 {
			return nil, &Error{
				Code:    CodeExecutionError,
				Message: "execution reverted: " + decodeRevertReason(revert),
				Data:    common.EncodeHex(revert),
			}
		}
		return nil, NewError(CodeExecutionError, "%v", result.Err)
	}
	return common.EncodeHex(result.ReturnData), nil
}

func (a *API) estimateGas(params []json.RawMessage) (any, error) {
	args, err := decodeParam[callArgs](params, 0)
	if err != nil {
		return nil, err
	}
	block, err := a.resolveBlock(params, 1)
	if err != nil {
		return nil, err
	}

	// Binary search for the smallest limit the message succeeds under. Gas
	// use is not always monotonic in the limit, but it is in practice for the
	// contracts this is used on, and the caller can always override.
	var (
		low  = evm.TxGas - 1
		high = block.GasLimit()
	)
	executable := func(gas uint64) bool {
		probe := args
		hexGas := common.EncodeHexUint(gas)
		probe.Gas = &hexGas
		result, err := a.simulate(&probe, block, gas)
		return err == nil && !result.Failed()
	}

	if !executable(high) {
		// Re-run at the cap to report why it fails.
		result, err := a.simulate(&args, block, high)
		if err != nil {
			return nil, NewError(CodeExecutionError, "%v", err)
		}
		if revert := result.Revert(); len(revert) > 0 {
			return nil, &Error{
				Code:    CodeExecutionError,
				Message: "execution reverted: " + decodeRevertReason(revert),
				Data:    common.EncodeHex(revert),
			}
		}
		return nil, NewError(CodeExecutionError, "the transaction cannot succeed at any gas limit: %v", result.Err)
	}

	for low+1 < high {
		mid := (low + high) / 2
		if executable(mid) {
			high = mid
		} else {
			low = mid
		}
	}
	return common.EncodeHexUint(high), nil
}

// filterCriteria is the argument to eth_getLogs.
type filterCriteria struct {
	FromBlock *string `json:"fromBlock"`
	ToBlock   *string `json:"toBlock"`
	Address   any     `json:"address"`
	Topics    []any   `json:"topics"`
	BlockHash *string `json:"blockHash"`
}

func (a *API) getLogs(params []json.RawMessage) (any, error) {
	criteria, err := decodeParam[filterCriteria](params, 0)
	if err != nil {
		return nil, err
	}
	bc := a.backend.Chain()

	addresses, err := parseAddressFilter(criteria.Address)
	if err != nil {
		return nil, err
	}
	topics, err := parseTopicFilter(criteria.Topics)
	if err != nil {
		return nil, err
	}

	var blocks []*core.Block
	if criteria.BlockHash != nil {
		hash, err := common.HexToHash(*criteria.BlockHash)
		if err != nil {
			return nil, NewError(CodeInvalidParams, "blockHash: %v", err)
		}
		block := bc.GetBlockByHash(hash)
		if block == nil {
			return nil, NewError(CodeInvalidParams, "block %s is unknown", hash)
		}
		blocks = append(blocks, block)
	} else {
		from, to, err := a.resolveRange(criteria.FromBlock, criteria.ToBlock)
		if err != nil {
			return nil, err
		}
		const maxRange = 10000
		if to-from > maxRange {
			return nil, NewError(CodeInvalidParams, "the requested range covers %d blocks, the limit is %d", to-from, maxRange)
		}
		for n := from; n <= to; n++ {
			if block := bc.GetBlockByNumber(n); block != nil {
				blocks = append(blocks, block)
			}
		}
	}

	out := []map[string]any{}
	for _, block := range blocks {
		// The header's bloom filter rules most blocks out without touching
		// their receipts at all.
		if !bloomMayContain(block.Bloom(), addresses, topics) {
			continue
		}
		for _, log := range bc.GetLogs(block.Hash()) {
			if matchesFilter(log, addresses, topics) {
				out = append(out, marshalLog(log))
			}
		}
	}
	return out, nil
}

func (a *API) resolveRange(fromTag, toTag *string) (uint64, uint64, error) {
	head := a.backend.Chain().CurrentBlock().NumberU64()
	resolve := func(tag *string, fallback uint64) (uint64, error) {
		if tag == nil {
			return fallback, nil
		}
		switch *tag {
		case "latest", "pending", "safe", "finalized", "":
			return head, nil
		case "earliest":
			return 0, nil
		default:
			return common.DecodeHexUint(*tag)
		}
	}
	from, err := resolve(fromTag, 0)
	if err != nil {
		return 0, 0, NewError(CodeInvalidParams, "fromBlock: %v", err)
	}
	to, err := resolve(toTag, head)
	if err != nil {
		return 0, 0, NewError(CodeInvalidParams, "toBlock: %v", err)
	}
	if to > head {
		to = head
	}
	if from > to {
		return 0, 0, NewError(CodeInvalidParams, "fromBlock %d is after toBlock %d", from, to)
	}
	return from, to, nil
}

// --- txpool and node info ---

func (a *API) txpoolStatus(params []json.RawMessage) (any, error) {
	pending, queued := a.backend.TxPool().Stats()
	return map[string]any{
		"pending": common.EncodeHexUint(uint64(pending)),
		"queued":  common.EncodeHexUint(uint64(queued)),
	}, nil
}

func (a *API) validators(params []json.RawMessage) (any, error) {
	out := []string{}
	for _, addr := range a.backend.Chain().Validators() {
		out = append(out, addr.Hex())
	}
	return out, nil
}

// validatorInfo reports a validator's stake and position in its lifecycle. It
// reads the registry, which is ordinary account storage, so the same answer is
// available to anyone with a Merkle proof of the state root.
func (a *API) validatorInfo(params []json.RawMessage) (any, error) {
	addr, err := decodeAddress(params, 0)
	if err != nil {
		return nil, err
	}
	registry, err := a.backend.Chain().StakingRegistry()
	if err != nil {
		return nil, NewError(CodeInternalError, "%v", err)
	}
	v, err := registry.ByAddress(addr)
	if err != nil {
		return nil, nil // not a validator
	}
	return map[string]any{
		"address":           v.Address.Hex(),
		"withdrawalAddress": v.WithdrawalAddress.Hex(),
		"status":            v.Status.String(),
		"balance":           common.EncodeHexBig(v.Balance),
		"effectiveBalance":  common.EncodeHexBig(v.EffectiveBalance),
		"index":             common.EncodeHexUint(v.Index),
		"activationEpoch":   common.EncodeHexUint(v.ActivationEpoch),
		"exitEpoch":         common.EncodeHexUint(v.ExitEpoch),
		"withdrawableEpoch": common.EncodeHexUint(v.WithdrawableEpoch),
	}, nil
}

func (a *API) nodeInfo(params []json.RawMessage) (any, error) {
	bc := a.backend.Chain()
	head := bc.CurrentBlock()
	pending, queued := a.backend.TxPool().Stats()
	return map[string]any{
		"version":     a.backend.ClientVersion(),
		"chainId":     common.EncodeHexBig(a.backend.ChainID()),
		"genesis":     bc.Genesis().Hash().Hex(),
		"head":        head.Hash().Hex(),
		"blockNumber": common.EncodeHexUint(head.NumberU64()),
		"finalized":   common.EncodeHexUint(bc.FinalizedNumber()),
		"validators":  len(bc.Validators()),
		"quorum":      core.Quorum(len(bc.Validators())),
		"peers":       a.backend.PeerCount(),
		"txpool":      map[string]int{"pending": pending, "queued": queued},
	}, nil
}

// decodeRevertReason extracts the string from a standard Error(string) revert.
func decodeRevertReason(data []byte) string {
	// Layout: 4-byte selector, 32-byte offset, 32-byte length, then the bytes.
	const selectorLen = 4
	if len(data) < selectorLen+64 {
		return common.EncodeHex(data)
	}
	length := new(big.Int).SetBytes(data[selectorLen+32 : selectorLen+64]).Uint64()
	start := selectorLen + 64
	if uint64(len(data)) < uint64(start)+length {
		return common.EncodeHex(data)
	}
	return string(data[start : uint64(start)+length])
}

var errUnsupportedFilter = errors.New("rpc: unsupported filter value")

func parseAddressFilter(value any) ([]common.Address, error) {
	switch v := value.(type) {
	case nil:
		return nil, nil
	case string:
		addr, err := common.HexToAddress(v)
		if err != nil {
			return nil, NewError(CodeInvalidParams, "address: %v", err)
		}
		return []common.Address{addr}, nil
	case []any:
		var out []common.Address
		for _, item := range v {
			s, ok := item.(string)
			if !ok {
				return nil, NewError(CodeInvalidParams, "%v", errUnsupportedFilter)
			}
			addr, err := common.HexToAddress(s)
			if err != nil {
				return nil, NewError(CodeInvalidParams, "address: %v", err)
			}
			out = append(out, addr)
		}
		return out, nil
	default:
		return nil, NewError(CodeInvalidParams, "%v", errUnsupportedFilter)
	}
}

// parseTopicFilter builds the positional topic filter: position i matches any
// of the hashes at topics[i], and a nil entry matches anything.
func parseTopicFilter(topics []any) ([][]common.Hash, error) {
	out := make([][]common.Hash, len(topics))
	for i, entry := range topics {
		switch v := entry.(type) {
		case nil:
			out[i] = nil
		case string:
			hash, err := common.HexToHash(v)
			if err != nil {
				return nil, NewError(CodeInvalidParams, "topic %d: %v", i, err)
			}
			out[i] = []common.Hash{hash}
		case []any:
			for _, item := range v {
				s, ok := item.(string)
				if !ok {
					return nil, NewError(CodeInvalidParams, "topic %d: %v", i, errUnsupportedFilter)
				}
				hash, err := common.HexToHash(s)
				if err != nil {
					return nil, NewError(CodeInvalidParams, "topic %d: %v", i, err)
				}
				out[i] = append(out[i], hash)
			}
		default:
			return nil, NewError(CodeInvalidParams, "topic %d: %v", i, errUnsupportedFilter)
		}
	}
	return out, nil
}

func matchesFilter(log *core.Log, addresses []common.Address, topics [][]common.Hash) bool {
	if len(addresses) > 0 {
		var found bool
		for _, addr := range addresses {
			if log.Address == addr {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	if len(topics) > len(log.Topics) {
		return false
	}
	for i, allowed := range topics {
		if len(allowed) == 0 {
			continue // a wildcard position
		}
		var found bool
		for _, want := range allowed {
			if log.Topics[i] == want {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// bloomMayContain tests a block's filter before its receipts are loaded.
func bloomMayContain(bloom core.Bloom, addresses []common.Address, topics [][]common.Hash) bool {
	if len(addresses) > 0 {
		var possible bool
		for _, addr := range addresses {
			if bloom.Test(addr[:]) {
				possible = true
				break
			}
		}
		if !possible {
			return false
		}
	}
	for _, allowed := range topics {
		if len(allowed) == 0 {
			continue
		}
		var possible bool
		for _, topic := range allowed {
			if bloom.Test(topic[:]) {
				possible = true
				break
			}
		}
		if !possible {
			return false
		}
	}
	return true
}

// --- marshalling ---

// emptyUnclesHash is keccak256(rlp([])), the value Ethereum blocks carry when
// they have no uncles — which here is always.
const emptyUnclesHash = "0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347"

// randaoMixField renders the proposer's reveal as the 32-byte value clients
// expect to find in mixHash.
func randaoMixField(reveal []byte) string {
	if len(reveal) == 0 {
		return common.Hash{}.Hex()
	}
	return common.Keccak256(reveal).Hex()
}

func (a *API) marshalBlock(block *core.Block, fullTxs bool) map[string]any {
	header := block.Header()
	out := map[string]any{
		"number":           common.EncodeHexUint(block.NumberU64()),
		"hash":             block.Hash().Hex(),
		"parentHash":       header.ParentHash.Hex(),
		"stateRoot":        header.StateRoot.Hex(),
		"transactionsRoot": header.TxRoot.Hex(),
		"receiptsRoot":     header.ReceiptRoot.Hex(),
		"miner":            header.Coinbase.Hex(),
		"logsBloom":        header.Bloom.Hex(),
		"gasLimit":         common.EncodeHexUint(header.GasLimit),
		"gasUsed":          common.EncodeHexUint(header.GasUsed),
		"timestamp":        common.EncodeHexUint(header.Time),
		"extraData":        common.EncodeHex(header.Extra),
		"baseFeePerGas":    common.EncodeHexBig(header.BaseFee),
		"size":             common.EncodeHexUint(block.Size()),

		// Fields this chain has no use for, reported anyway because clients
		// parse the block object against Ethereum's shape and reject it
		// outright when one is missing — even one that could only ever hold a
		// constant here.
		"difficulty":      "0x0",
		"totalDifficulty": "0x0",
		"nonce":           "0x0000000000000000",
		"sha3Uncles":      emptyUnclesHash,
		"uncles":          []string{},

		// Post-merge Ethereum reuses mixHash to carry the beacon randomness,
		// and tooling reads prevRandao from it. This chain's randomness belongs
		// in the same place.
		"mixHash": randaoMixField(header.RandaoReveal),

		// This chain's own fields, which no Ethereum client will look at.
		"proposerSeal":  common.EncodeHex(header.ProposerSeal),
		"round":         common.EncodeHexUint(header.Round),
		"justification": common.EncodeHex(header.Justification),
	}

	txs := block.Transactions()
	if fullTxs {
		full := make([]any, len(txs))
		for i, tx := range txs {
			full[i] = a.marshalTransaction(tx, block.Hash(), block.NumberU64(), uint64(i))
		}
		out["transactions"] = full
	} else {
		hashes := make([]string, len(txs))
		for i, tx := range txs {
			hashes[i] = tx.Hash().Hex()
		}
		out["transactions"] = hashes
	}
	return out
}

func (a *API) marshalTransaction(tx *core.Transaction, blockHash common.Hash, blockNumber, index uint64) map[string]any {
	v, r, s := tx.RawSignature()
	out := map[string]any{
		"hash":                 tx.Hash().Hex(),
		"nonce":                common.EncodeHexUint(tx.Nonce()),
		"gas":                  common.EncodeHexUint(tx.Gas()),
		"gasPrice":             common.EncodeHexBig(tx.GasPrice()),
		"maxFeePerGas":         common.EncodeHexBig(tx.GasFeeCap()),
		"maxPriorityFeePerGas": common.EncodeHexBig(tx.GasTipCap()),
		"value":                common.EncodeHexBig(tx.Value()),
		"input":                common.EncodeHex(tx.Data()),
		"type":                 common.EncodeHexUint(uint64(tx.Type())),
		"chainId":              common.EncodeHexBig(a.backend.ChainID()),
		"v":                    common.EncodeHexBig(v),
		"r":                    common.EncodeHexBig(r),
		"s":                    common.EncodeHexBig(s),
		// Typed transactions report the parity bit under its own name; clients
		// prefer it to v, and some require it.
		"yParity": common.EncodeHexUint(parityOf(tx, v)),
	}

	// An access list is part of a typed transaction's shape, so it is reported
	// even when empty rather than left out.
	if tx.Type() != core.LegacyTxType {
		accessList := []map[string]any{}
		for _, tuple := range tx.AccessList() {
			keys := make([]string, 0, len(tuple.StorageKeys))
			for _, key := range tuple.StorageKeys {
				keys = append(keys, key.Hex())
			}
			accessList = append(accessList, map[string]any{
				"address":     tuple.Address.Hex(),
				"storageKeys": keys,
			})
		}
		out["accessList"] = accessList
	}
	if to := tx.To(); to != nil {
		out["to"] = to.Hex()
	} else {
		out["to"] = nil
	}
	if from, err := a.backend.TxPool().Signer().Sender(tx); err == nil {
		out["from"] = from.Hex()
	}
	// A pending transaction has no position in the chain yet.
	if blockHash.IsZero() {
		out["blockHash"] = nil
		out["blockNumber"] = nil
		out["transactionIndex"] = nil
	} else {
		out["blockHash"] = blockHash.Hex()
		out["blockNumber"] = common.EncodeHexUint(blockNumber)
		out["transactionIndex"] = common.EncodeHexUint(index)
	}
	return out
}

func (a *API) marshalReceipt(receipt *core.Receipt, tx *core.Transaction, entry *chain.TxLookupEntry) map[string]any {
	logs := []map[string]any{}
	for _, log := range receipt.Logs {
		logs = append(logs, marshalLog(log))
	}
	out := map[string]any{
		"transactionHash":   tx.Hash().Hex(),
		"transactionIndex":  common.EncodeHexUint(entry.Index),
		"blockHash":         entry.BlockHash.Hex(),
		"blockNumber":       common.EncodeHexUint(entry.BlockIndex),
		"cumulativeGasUsed": common.EncodeHexUint(receipt.CumulativeGasUsed),
		"gasUsed":           common.EncodeHexUint(receipt.GasUsed),
		"effectiveGasPrice": common.EncodeHexBig(receipt.EffectiveGasPrice),
		"status":            common.EncodeHexUint(receipt.Status),
		"logs":              logs,
		"logsBloom":         receipt.Bloom.Hex(),
		"type":              common.EncodeHexUint(uint64(receipt.Type)),
	}
	if from, err := a.backend.TxPool().Signer().Sender(tx); err == nil {
		out["from"] = from.Hex()
	}
	if to := tx.To(); to != nil {
		out["to"] = to.Hex()
		out["contractAddress"] = nil
	} else {
		out["to"] = nil
		out["contractAddress"] = receipt.ContractAddress.Hex()
	}
	return out
}

// parityOf returns the signature's parity bit, which for a legacy transaction
// is buried inside the EIP-155 encoding of v.
func parityOf(tx *core.Transaction, v *big.Int) uint64 {
	if v == nil {
		return 0
	}
	if tx.Type() != core.LegacyTxType {
		return v.Uint64() & 1
	}
	raw := v.Uint64()
	if raw == 27 || raw == 28 {
		return raw - 27
	}
	// v = chainID*2 + 35 + parity
	return (raw - 35) & 1
}

func marshalLog(log *core.Log) map[string]any {
	topics := make([]string, len(log.Topics))
	for i, topic := range log.Topics {
		topics[i] = topic.Hex()
	}
	return map[string]any{
		"address":          log.Address.Hex(),
		"topics":           topics,
		"data":             common.EncodeHex(log.Data),
		"blockNumber":      common.EncodeHexUint(log.BlockNumber),
		"blockHash":        log.BlockHash.Hex(),
		"transactionHash":  log.TxHash.Hex(),
		"transactionIndex": common.EncodeHexUint(uint64(log.TxIndex)),
		"logIndex":         common.EncodeHexUint(uint64(log.Index)),
		"removed":          log.Removed,
	}
}

var _ = fmt.Sprintf
