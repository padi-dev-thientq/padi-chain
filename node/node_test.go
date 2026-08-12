package node_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"os"
	"testing"
	"time"

	"layer1/chain"
	"layer1/common"
	"layer1/core"
	"layer1/crypto/secp256k1"
	"layer1/evm"
	"layer1/keystore"
	"layer1/node"
)

var testChainID = big.NewInt(4242)

func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
}

func devKey(t *testing.T, i byte) (*secp256k1.PrivateKey, common.Address) {
	t.Helper()
	key, err := secp256k1.PrivateKeyFromBytes(common.LeftPadBytes([]byte{i}, 32))
	if err != nil {
		t.Fatal(err)
	}
	return key, keystore.AddressOf(key)
}

// newGenesis builds a one-validator genesis with the given accounts funded.
func newGenesis(validator common.Address, funded ...common.Address) *chain.Genesis {
	genesis := chain.DefaultGenesis(testChainID, []common.Address{validator})
	genesis.BlockPeriod = 1
	genesis.Timestamp = uint64(time.Now().Add(-time.Hour).Unix())
	balance := new(big.Int).Mul(big.NewInt(1000), big.NewInt(1e18))
	genesis.Alloc[validator] = chain.GenesisAccount{Balance: balance}
	for _, addr := range funded {
		genesis.Alloc[addr] = chain.GenesisAccount{Balance: balance}
	}
	return genesis
}

func startNode(t *testing.T, config *node.Config) *node.Node {
	t.Helper()
	n, err := node.New(config)
	if err != nil {
		t.Fatal(err)
	}
	if err := n.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { n.Stop() })
	return n
}

// waitFor polls until the condition holds or the timeout expires.
func waitFor(t *testing.T, timeout time.Duration, what string, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func TestNodeProducesBlocks(t *testing.T) {
	key, addr := devKey(t, 1)
	n := startNode(t, &node.Config{
		DataDir:   t.TempDir(),
		Genesis:   newGenesis(addr),
		Validator: key,
		Mine:      true,
		RPCAddr:   "127.0.0.1:0",
		Logger:    quietLogger(),
	})

	waitFor(t, 10*time.Second, "the node to seal blocks", func() bool {
		return n.Chain().CurrentBlock().NumberU64() >= 2
	})

	head := n.Chain().CurrentBlock()
	if head.Coinbase() != addr {
		t.Fatalf("block coinbase is %s, want the validator %s", head.Coinbase(), addr)
	}
	if len(head.Seal()) == 0 {
		t.Fatal("the produced block carries no proposer seal")
	}
}

func TestNodeRejectsMiningWithoutValidatorKey(t *testing.T) {
	_, addr := devKey(t, 1)
	otherKey, _ := devKey(t, 2)

	n, err := node.New(&node.Config{
		DataDir:   t.TempDir(),
		Genesis:   newGenesis(addr),
		Validator: otherKey, // not in the validator set
		Mine:      true,
		Logger:    quietLogger(),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer n.Stop()

	if err := n.Start(); err == nil {
		t.Fatal("a node whose key is not a validator must refuse to mine")
	}
}

// --- RPC ---

type client struct{ url string }

func (c *client) call(t *testing.T, method string, params ...any) json.RawMessage {
	t.Helper()
	raw, err := c.tryCall(method, params...)
	if err != nil {
		t.Fatalf("%s: %v", method, err)
	}
	return raw
}

func (c *client) tryCall(method string, params ...any) (json.RawMessage, error) {
	if params == nil {
		params = []any{}
	}
	body, _ := json.Marshal(map[string]any{
		"jsonrpc": "2.0", "id": 1, "method": method, "params": params,
	})
	resp, err := http.Post(c.url, "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	data, _ := io.ReadAll(resp.Body)
	var parsed struct {
		Result json.RawMessage `json:"result"`
		Error  *struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(data, &parsed); err != nil {
		return nil, fmt.Errorf("malformed response %q", string(data))
	}
	if parsed.Error != nil {
		return nil, fmt.Errorf("rpc error %d: %s", parsed.Error.Code, parsed.Error.Message)
	}
	return parsed.Result, nil
}

func (c *client) callString(t *testing.T, method string, params ...any) string {
	t.Helper()
	var out string
	if err := json.Unmarshal(c.call(t, method, params...), &out); err != nil {
		t.Fatalf("%s: %v", method, err)
	}
	return out
}

func TestRPCEndToEnd(t *testing.T) {
	validatorKey, validator := devKey(t, 1)
	senderKey, sender := devKey(t, 2)

	n := startNode(t, &node.Config{
		DataDir:   t.TempDir(),
		Genesis:   newGenesis(validator, sender),
		Validator: validatorKey,
		Mine:      true,
		RPCAddr:   "127.0.0.1:0",
		Logger:    quietLogger(),
	})
	c := &client{url: "http://" + n.RPCAddr()}

	t.Run("chain identity", func(t *testing.T) {
		if got := c.callString(t, "eth_chainId"); got != common.EncodeHexBig(testChainID) {
			t.Errorf("eth_chainId = %s", got)
		}
		if got := c.callString(t, "net_version"); got != testChainID.String() {
			t.Errorf("net_version = %s", got)
		}
		if got := c.callString(t, "web3_clientVersion"); got != node.Version {
			t.Errorf("web3_clientVersion = %s", got)
		}
	})

	t.Run("balances from genesis", func(t *testing.T) {
		got := c.callString(t, "eth_getBalance", sender.Hex(), "latest")
		balance, err := common.DecodeHexBig(got)
		if err != nil {
			t.Fatal(err)
		}
		want := new(big.Int).Mul(big.NewInt(1000), big.NewInt(1e18))
		if balance.Cmp(want) != 0 {
			t.Errorf("balance = %s, want %s", balance, want)
		}
	})

	t.Run("keccak", func(t *testing.T) {
		got := c.callString(t, "web3_sha3", "0x68656c6c6f20776f726c64") // "hello world"
		want := "0x47173285a8d7341e5e972fc677286384f802f8ef42a5ec5f03bbfa254cb01fad"
		if got != want {
			t.Errorf("web3_sha3 = %s, want %s", got, want)
		}
	})

	// Send a transfer through the RPC and wait for it to be mined.
	recipient := common.MustHexToAddress("0x5555555555555555555555555555555555555555")
	amount := big.NewInt(123456789)

	signer := core.NewSigner(testChainID)
	tx, err := signer.SignTx(core.NewTx(&core.DynamicFeeTx{
		Nonce:     0,
		GasTipCap: big.NewInt(1_000_000_000),
		GasFeeCap: big.NewInt(20_000_000_000),
		Gas:       21000,
		To:        &recipient,
		Value:     amount,
	}), senderKey)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := tx.MarshalBinary()

	t.Run("send raw transaction", func(t *testing.T) {
		hash := c.callString(t, "eth_sendRawTransaction", common.EncodeHex(raw))
		if hash != tx.Hash().Hex() {
			t.Fatalf("returned hash %s, want %s", hash, tx.Hash().Hex())
		}
	})

	waitFor(t, 15*time.Second, "the transaction to be mined", func() bool {
		found, _ := n.Chain().GetTransaction(tx.Hash())
		return found != nil
	})

	t.Run("receipt", func(t *testing.T) {
		raw := c.call(t, "eth_getTransactionReceipt", tx.Hash().Hex())
		var receipt map[string]any
		if err := json.Unmarshal(raw, &receipt); err != nil {
			t.Fatal(err)
		}
		if receipt["status"] != "0x1" {
			t.Errorf("receipt status = %v, want 0x1", receipt["status"])
		}
		if receipt["gasUsed"] != "0x5208" {
			t.Errorf("gasUsed = %v, want 0x5208 (21000)", receipt["gasUsed"])
		}
		if receipt["from"] != sender.Hex() {
			t.Errorf("receipt from = %v, want %s", receipt["from"], sender.Hex())
		}
	})

	t.Run("recipient balance", func(t *testing.T) {
		got := c.callString(t, "eth_getBalance", recipient.Hex(), "latest")
		balance, _ := common.DecodeHexBig(got)
		if balance.Cmp(amount) != 0 {
			t.Errorf("recipient balance = %s, want %s", balance, amount)
		}
	})

	t.Run("nonce advanced", func(t *testing.T) {
		got := c.callString(t, "eth_getTransactionCount", sender.Hex(), "latest")
		if got != "0x1" {
			t.Errorf("nonce = %s, want 0x1", got)
		}
	})

	t.Run("block by number", func(t *testing.T) {
		raw := c.call(t, "eth_getBlockByNumber", "0x0", false)
		var block map[string]any
		if err := json.Unmarshal(raw, &block); err != nil {
			t.Fatal(err)
		}
		if block["number"] != "0x0" {
			t.Errorf("genesis block number = %v", block["number"])
		}
		if block["hash"] != n.Chain().Genesis().Hash().Hex() {
			t.Errorf("genesis hash mismatch: %v", block["hash"])
		}
	})

	t.Run("transaction by hash", func(t *testing.T) {
		raw := c.call(t, "eth_getTransactionByHash", tx.Hash().Hex())
		var got map[string]any
		if err := json.Unmarshal(raw, &got); err != nil {
			t.Fatal(err)
		}
		if got["to"] != recipient.Hex() {
			t.Errorf("to = %v", got["to"])
		}
		if got["value"] != common.EncodeHexBig(amount) {
			t.Errorf("value = %v", got["value"])
		}
	})

	t.Run("unknown transaction returns null", func(t *testing.T) {
		raw := c.call(t, "eth_getTransactionByHash", common.Keccak256([]byte("nope")).Hex())
		if string(raw) != "null" && len(raw) != 0 {
			t.Errorf("expected null for an unknown transaction, got %s", raw)
		}
	})

	t.Run("unknown method", func(t *testing.T) {
		if _, err := c.tryCall("eth_thisDoesNotExist"); err == nil {
			t.Fatal("an unknown method must produce an error")
		}
	})

	t.Run("bad params", func(t *testing.T) {
		if _, err := c.tryCall("eth_getBalance", "not-an-address", "latest"); err == nil {
			t.Fatal("a malformed address must produce an error")
		}
	})
}

func TestRPCContractLifecycle(t *testing.T) {
	validatorKey, validator := devKey(t, 1)
	senderKey, sender := devKey(t, 2)

	n := startNode(t, &node.Config{
		DataDir:   t.TempDir(),
		Genesis:   newGenesis(validator, sender),
		Validator: validatorKey,
		Mine:      true,
		RPCAddr:   "127.0.0.1:0",
		Logger:    quietLogger(),
	})
	c := &client{url: "http://" + n.RPCAddr()}

	// Runtime: store calldata word 0 in slot 0, emit a log, return the value.
	runtime := []byte{
		byte(evm.PUSH1), 0x00, byte(evm.CALLDATALOAD),
		byte(evm.DUP1),
		byte(evm.PUSH1), 0x00, byte(evm.SSTORE),
		byte(evm.PUSH1), 0x00, byte(evm.MSTORE),
		byte(evm.PUSH1), 0xaa, // topic
		byte(evm.PUSH1), 0x20, byte(evm.PUSH1), 0x00,
		byte(evm.LOG1),
		byte(evm.PUSH1), 0x20, byte(evm.PUSH1), 0x00, byte(evm.RETURN),
	}
	initCode := append([]byte{
		byte(evm.PUSH1), byte(len(runtime)),
		byte(evm.PUSH1), 12,
		byte(evm.PUSH1), 0x00,
		byte(evm.CODECOPY),
		byte(evm.PUSH1), byte(len(runtime)),
		byte(evm.PUSH1), 0x00,
		byte(evm.RETURN),
	}, runtime...)

	signer := core.NewSigner(testChainID)
	send := func(nonce uint64, to *common.Address, data []byte, gas uint64) common.Hash {
		t.Helper()
		tx, err := signer.SignTx(core.NewTx(&core.DynamicFeeTx{
			Nonce:     nonce,
			GasTipCap: big.NewInt(1_000_000_000),
			GasFeeCap: big.NewInt(20_000_000_000),
			Gas:       gas,
			To:        to,
			Value:     new(big.Int),
			Data:      data,
		}), senderKey)
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := tx.MarshalBinary()
		c.callString(t, "eth_sendRawTransaction", common.EncodeHex(raw))
		waitFor(t, 15*time.Second, "the transaction to be mined", func() bool {
			found, _ := n.Chain().GetTransaction(tx.Hash())
			return found != nil
		})
		return tx.Hash()
	}

	deployHash := send(0, nil, initCode, 500_000)

	var receipt map[string]any
	if err := json.Unmarshal(c.call(t, "eth_getTransactionReceipt", deployHash.Hex()), &receipt); err != nil {
		t.Fatal(err)
	}
	if receipt["status"] != "0x1" {
		t.Fatalf("deployment failed: %v", receipt)
	}
	contractAddr, err := common.HexToAddress(fmt.Sprint(receipt["contractAddress"]))
	if err != nil {
		t.Fatal(err)
	}

	t.Run("code is published", func(t *testing.T) {
		got := c.callString(t, "eth_getCode", contractAddr.Hex(), "latest")
		if got != common.EncodeHex(runtime) {
			t.Fatalf("deployed code = %s", got)
		}
	})

	value := common.LeftPadBytes([]byte{0x7b}, 32) // 123
	callHash := send(1, &contractAddr, value, 200_000)

	t.Run("storage was written", func(t *testing.T) {
		got := c.callString(t, "eth_getStorageAt", contractAddr.Hex(), "0x0", "latest")
		if got != common.BytesToHash(value).Hex() {
			t.Fatalf("storage slot 0 = %s, want %s", got, common.BytesToHash(value).Hex())
		}
	})

	t.Run("log was emitted and is filterable", func(t *testing.T) {
		raw := c.call(t, "eth_getLogs", map[string]any{
			"fromBlock": "0x0",
			"toBlock":   "latest",
			"address":   contractAddr.Hex(),
		})
		var logs []map[string]any
		if err := json.Unmarshal(raw, &logs); err != nil {
			t.Fatal(err)
		}
		if len(logs) != 1 {
			t.Fatalf("got %d logs, want 1", len(logs))
		}
		if logs[0]["transactionHash"] != callHash.Hex() {
			t.Errorf("log is attributed to %v", logs[0]["transactionHash"])
		}

		// A filter on a different address must match nothing.
		raw = c.call(t, "eth_getLogs", map[string]any{
			"fromBlock": "0x0",
			"toBlock":   "latest",
			"address":   "0x1111111111111111111111111111111111111111",
		})
		var none []map[string]any
		json.Unmarshal(raw, &none)
		if len(none) != 0 {
			t.Errorf("a filter on an unrelated address returned %d logs", len(none))
		}
	})

	t.Run("eth_call reads without a transaction", func(t *testing.T) {
		probe := common.LeftPadBytes([]byte{0x99}, 32)
		got := c.callString(t, "eth_call", map[string]any{
			"from": sender.Hex(),
			"to":   contractAddr.Hex(),
			"data": common.EncodeHex(probe),
		}, "latest")
		if got != common.EncodeHex(probe) {
			t.Fatalf("eth_call returned %s, want the echoed input", got)
		}
		// The simulated write must not have touched real state.
		stored := c.callString(t, "eth_getStorageAt", contractAddr.Hex(), "0x0", "latest")
		if stored != common.BytesToHash(value).Hex() {
			t.Fatalf("eth_call modified stored state: slot 0 is now %s", stored)
		}
	})

	t.Run("eth_estimateGas", func(t *testing.T) {
		got := c.callString(t, "eth_estimateGas", map[string]any{
			"from": sender.Hex(),
			"to":   contractAddr.Hex(),
			"data": common.EncodeHex(value),
		})
		estimate, err := common.DecodeHexUint(got)
		if err != nil {
			t.Fatal(err)
		}
		if estimate < 21000 {
			t.Fatalf("estimate %d is below the intrinsic cost", estimate)
		}
	})
}

func TestTwoNodesSyncOverNetwork(t *testing.T) {
	if os.Getenv("LAYER1_SKIP_NETWORK_TESTS") != "" {
		t.Skip("network tests disabled")
	}

	validatorKey, validator := devKey(t, 1)
	senderKey, sender := devKey(t, 2)
	genesis := newGenesis(validator, sender)

	// The producer seals blocks; the follower only listens.
	producer := startNode(t, &node.Config{
		DataDir:    t.TempDir(),
		Genesis:    genesis,
		Validator:  validatorKey,
		Mine:       true,
		ListenAddr: "127.0.0.1:0",
		Logger:     quietLogger(),
	})

	waitFor(t, 10*time.Second, "the producer to seal a block", func() bool {
		return producer.Chain().CurrentBlock().NumberU64() >= 1
	})

	follower := startNode(t, &node.Config{
		DataDir:    t.TempDir(),
		Genesis:    genesis,
		ListenAddr: "127.0.0.1:0",
		Bootstrap:  []string{producer.P2PAddr()},
		RPCAddr:    "127.0.0.1:0",
		Logger:     quietLogger(),
	})

	waitFor(t, 15*time.Second, "the peers to connect", func() bool {
		return producer.PeerCount() > 0 && follower.PeerCount() > 0
	})

	// The follower must catch up with blocks it never produced.
	waitFor(t, 30*time.Second, "the follower to sync", func() bool {
		return follower.Chain().CurrentBlock().NumberU64() >= producer.Chain().CurrentBlock().NumberU64()
	})

	if follower.Chain().CurrentBlock().Hash() != producer.Chain().CurrentBlock().Hash() {
		// Heights can differ by one while a block is in flight; compare a
		// height both nodes have.
		height := follower.Chain().CurrentBlock().NumberU64()
		if follower.Chain().GetBlockByNumber(height).Hash() != producer.Chain().GetBlockByNumber(height).Hash() {
			t.Fatalf("the nodes disagree about block %d", height)
		}
	}

	// A transaction submitted to the follower must reach the producer and be
	// mined there.
	recipient := common.MustHexToAddress("0x7777777777777777777777777777777777777777")
	signer := core.NewSigner(testChainID)
	tx, err := signer.SignTx(core.NewTx(&core.DynamicFeeTx{
		Nonce:     0,
		GasTipCap: big.NewInt(1_000_000_000),
		GasFeeCap: big.NewInt(20_000_000_000),
		Gas:       21000,
		To:        &recipient,
		Value:     big.NewInt(555),
	}), senderKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := follower.TxPool().Add(tx); err != nil {
		t.Fatal(err)
	}

	waitFor(t, 30*time.Second, "the gossiped transaction to be mined", func() bool {
		found, _ := producer.Chain().GetTransaction(tx.Hash())
		return found != nil
	})

	waitFor(t, 30*time.Second, "the follower to see the mined transaction", func() bool {
		found, _ := follower.Chain().GetTransaction(tx.Hash())
		return found != nil
	})

	statedb, err := follower.Chain().State()
	if err != nil {
		t.Fatal(err)
	}
	if got := statedb.GetBalance(recipient); got.Cmp(big.NewInt(555)) != 0 {
		t.Fatalf("the follower's state shows %s for the recipient, want 555", got)
	}
	_ = sender
}

func TestNodeRestartResumesChain(t *testing.T) {
	validatorKey, validator := devKey(t, 1)
	dataDir := t.TempDir()
	genesis := newGenesis(validator)

	first, err := node.New(&node.Config{
		DataDir:   dataDir,
		Genesis:   genesis,
		Validator: validatorKey,
		Mine:      true,
		Logger:    quietLogger(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := first.Start(); err != nil {
		t.Fatal(err)
	}
	waitFor(t, 10*time.Second, "blocks to be produced", func() bool {
		return first.Chain().CurrentBlock().NumberU64() >= 2
	})
	height := first.Chain().CurrentBlock().NumberU64()
	hash := first.Chain().GetBlockByNumber(height).Hash()
	if err := first.Stop(); err != nil {
		t.Fatal(err)
	}

	// Restarting against the same data directory must resume the same chain.
	second, err := node.New(&node.Config{
		DataDir: dataDir,
		Genesis: genesis,
		Logger:  quietLogger(),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer second.Stop()

	if got := second.Chain().CurrentBlock().NumberU64(); got < height {
		t.Fatalf("chain height after restart is %d, want at least %d", got, height)
	}
	if got := second.Chain().GetBlockByNumber(height).Hash(); got != hash {
		t.Fatalf("block %d is %s after restart, want %s", height, got, hash)
	}
}
