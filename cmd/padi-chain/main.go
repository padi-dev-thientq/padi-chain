// Command padi-chain runs a node of the padi-chain blockchain and provides the tools
// to set one up.
package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"padi-chain/chain"
	"padi-chain/common"
	"padi-chain/core"
	"padi-chain/crypto/secp256k1"
	"padi-chain/keystore"
	"padi-chain/node"
)

const usage = `padi-chain - a blockchain node

Usage:
  padi-chain <command> [flags]

Commands:
  init       Create a data directory and write a genesis file
  account    Manage keys (new, list, import)
  run        Run a node
  send       Sign and submit a transaction through a node's RPC
  call       Make a read-only contract call through a node's RPC
  balance    Print an account balance
  status     Print a node's chain status
  prune      Ask a running node to prune its state now
  version    Print the version

Run "padi-chain <command> -h" for the flags of a command.
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}

	var err error
	switch os.Args[1] {
	case "init":
		err = cmdInit(os.Args[2:])
	case "account":
		err = cmdAccount(os.Args[2:])
	case "run":
		err = cmdRun(os.Args[2:])
	case "send":
		err = cmdSend(os.Args[2:])
	case "call":
		err = cmdCall(os.Args[2:])
	case "balance":
		err = cmdBalance(os.Args[2:])
	case "status":
		err = cmdStatus(os.Args[2:])
	case "prune":
		err = cmdPrune(os.Args[2:])
	case "version":
		fmt.Println(node.Version)
	case "-h", "--help", "help":
		fmt.Print(usage)
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n%s", os.Args[1], usage)
		os.Exit(2)
	}

	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func newLogger(level string) *slog.Logger {
	var lvl slog.Level
	switch strings.ToLower(level) {
	case "debug":
		lvl = slog.LevelDebug
	case "warn":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	default:
		lvl = slog.LevelInfo
	}
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: lvl}))
}

// --- init ---

func cmdInit(args []string) error {
	fs := flag.NewFlagSet("init", flag.ExitOnError)
	dataDir := fs.String("datadir", "./data", "data directory")
	chainID := fs.Int64("chainid", 1337, "chain id")
	validators := fs.String("validators", "", "comma-separated validator addresses (default: a newly created account)")
	alloc := fs.String("alloc", "", "comma-separated address=balance pairs to pre-fund")
	period := fs.Uint64("period", 2, "seconds between blocks")
	gasLimit := fs.Uint64("gaslimit", 30_000_000, "block gas limit")
	passphrase := fs.String("password", "", "passphrase for a newly created validator account")
	fs.Parse(args)

	if err := os.MkdirAll(*dataDir, 0o755); err != nil {
		return err
	}
	genesisPath := filepath.Join(*dataDir, "genesis.json")
	if _, err := os.Stat(genesisPath); err == nil {
		return fmt.Errorf("%s already exists; remove it to reinitialise", genesisPath)
	}

	var validatorSet []common.Address
	if *validators != "" {
		for _, raw := range strings.Split(*validators, ",") {
			addr, err := common.HexToAddress(strings.TrimSpace(raw))
			if err != nil {
				return fmt.Errorf("validator %q: %w", raw, err)
			}
			validatorSet = append(validatorSet, addr)
		}
	} else {
		// Without an explicit set, create a validator so the chain can
		// actually produce blocks.
		ks, err := keystore.New(filepath.Join(*dataDir, "keystore"))
		if err != nil {
			return err
		}
		pass := *passphrase
		if pass == "" {
			pass, err = promptPassphrase("Passphrase for the new validator account: ", true)
			if err != nil {
				return err
			}
		}
		addr, err := ks.NewAccount(pass)
		if err != nil {
			return err
		}
		validatorSet = append(validatorSet, addr)
		fmt.Printf("Created validator account %s\n", addr)
	}

	genesis := chain.DefaultGenesis(big.NewInt(*chainID), validatorSet)
	genesis.BlockPeriod = *period
	genesis.GasLimit = *gasLimit
	genesis.Timestamp = uint64(time.Now().Unix())

	// Validators start with a balance so they can transact on a fresh chain.
	defaultBalance := new(big.Int).Mul(big.NewInt(1_000_000), big.NewInt(1e18))
	for _, addr := range validatorSet {
		genesis.Alloc[addr] = chain.GenesisAccount{Balance: defaultBalance}
	}
	if *alloc != "" {
		for _, entry := range strings.Split(*alloc, ",") {
			parts := strings.SplitN(strings.TrimSpace(entry), "=", 2)
			if len(parts) != 2 {
				return fmt.Errorf("malformed alloc entry %q, want address=balance", entry)
			}
			addr, err := common.HexToAddress(parts[0])
			if err != nil {
				return fmt.Errorf("alloc address %q: %w", parts[0], err)
			}
			balance, ok := new(big.Int).SetString(parts[1], 10)
			if !ok {
				return fmt.Errorf("alloc balance %q is not a decimal number", parts[1])
			}
			genesis.Alloc[addr] = chain.GenesisAccount{Balance: balance}
		}
	}

	if err := genesis.Save(genesisPath); err != nil {
		return err
	}
	fmt.Printf("Wrote %s\n", genesisPath)
	fmt.Printf("Chain id %d, block period %ds, %d validator(s)\n", *chainID, *period, len(validatorSet))
	fmt.Printf("\nStart the node with:\n  padi-chain run -datadir %s -mine -validator %s\n", *dataDir, validatorSet[0])
	return nil
}

// --- account ---

func cmdAccount(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: padi-chain account <new|list|import> [flags]")
	}
	fs := flag.NewFlagSet("account", flag.ExitOnError)
	dataDir := fs.String("datadir", "./data", "data directory")
	passphrase := fs.String("password", "", "passphrase (prompted for when omitted)")
	keyHex := fs.String("key", "", "hex private key to import")
	fs.Parse(args[1:])

	ks, err := keystore.New(filepath.Join(*dataDir, "keystore"))
	if err != nil {
		return err
	}

	switch args[0] {
	case "new":
		pass := *passphrase
		if pass == "" {
			if pass, err = promptPassphrase("Passphrase: ", true); err != nil {
				return err
			}
		}
		addr, err := ks.NewAccount(pass)
		if err != nil {
			return err
		}
		fmt.Println(addr)
		return nil

	case "list":
		accounts, err := ks.Accounts()
		if err != nil {
			return err
		}
		if len(accounts) == 0 {
			fmt.Println("no accounts")
			return nil
		}
		for _, addr := range accounts {
			fmt.Println(addr)
		}
		return nil

	case "import":
		if *keyHex == "" {
			return errors.New("-key is required")
		}
		key, err := secp256k1.PrivateKeyFromHex(*keyHex)
		if err != nil {
			return err
		}
		pass := *passphrase
		if pass == "" {
			if pass, err = promptPassphrase("Passphrase: ", true); err != nil {
				return err
			}
		}
		addr, err := ks.ImportKey(key, pass)
		if err != nil {
			return err
		}
		fmt.Println(addr)
		return nil

	default:
		return fmt.Errorf("unknown account subcommand %q", args[0])
	}
}

// --- run ---

func cmdRun(args []string) error {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	dataDir := fs.String("datadir", "./data", "data directory")
	listenAddr := fs.String("addr", "0.0.0.0:30303", "p2p listen address (empty to disable)")
	rpcAddr := fs.String("rpc", "127.0.0.1:8545", "JSON-RPC listen address (empty to disable)")
	monitorAddr := fs.String("monitor", "127.0.0.1:6060", "metrics and health listen address (empty to disable)")
	bootstrap := fs.String("peers", "", "comma-separated bootstrap peer addresses")
	mine := fs.Bool("mine", false, "produce blocks when it is this validator's turn")
	validator := fs.String("validator", "", "validator address to seal with")
	passphrase := fs.String("password", "", "passphrase to unlock the validator key")
	nodeName := fs.String("name", "padi-chain", "node name announced to peers")
	logLevel := fs.String("log", "info", "log level: debug, info, warn, error")
	archive := fs.Bool("archive", false, "keep every historical state instead of pruning")
	retain := fs.Uint64("retain", 256, "how many recent blocks' states to keep when pruning")
	fs.Parse(args)

	log := newLogger(*logLevel)

	config := &node.Config{
		DataDir:     *dataDir,
		ListenAddr:  *listenAddr,
		RPCAddr:     *rpcAddr,
		MonitorAddr: *monitorAddr,
		NodeName:    *nodeName,
		Mine:        *mine,
		Logger:      log,
		Prune: chain.PruneConfig{
			Enabled:  !*archive,
			Retain:   *retain,
			Interval: 10 * time.Minute,
		},
	}
	if *bootstrap != "" {
		for _, peer := range strings.Split(*bootstrap, ",") {
			config.Bootstrap = append(config.Bootstrap, strings.TrimSpace(peer))
		}
	}

	if *mine {
		if *validator == "" {
			return errors.New("-mine requires -validator")
		}
		addr, err := common.HexToAddress(*validator)
		if err != nil {
			return fmt.Errorf("validator address: %w", err)
		}
		ks, err := keystore.New(filepath.Join(*dataDir, "keystore"))
		if err != nil {
			return err
		}
		pass := *passphrase
		if pass == "" {
			if pass, err = promptPassphrase(fmt.Sprintf("Passphrase for %s: ", addr), false); err != nil {
				return err
			}
		}
		key, err := ks.Unlock(addr, pass)
		if err != nil {
			return err
		}
		config.Validator = key
	}

	n, err := node.New(config)
	if err != nil {
		return err
	}
	if err := n.Start(); err != nil {
		return err
	}

	// Run until interrupted, then shut down cleanly so the store is flushed.
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	<-stop
	fmt.Fprintln(os.Stderr, "\nshutting down...")
	return n.Stop()
}

// --- RPC client commands ---

type rpcClient struct {
	url string
}

func (c *rpcClient) call(method string, params ...any) (json.RawMessage, error) {
	if params == nil {
		params = []any{}
	}
	body, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  method,
		"params":  params,
	})
	if err != nil {
		return nil, err
	}

	resp, err := http.Post(c.url, "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("calling %s: %w", c.url, err)
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	var parsed struct {
		Result json.RawMessage `json:"result"`
		Error  *struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(data, &parsed); err != nil {
		return nil, fmt.Errorf("malformed response: %s", string(data))
	}
	if parsed.Error != nil {
		return nil, fmt.Errorf("rpc error %d: %s", parsed.Error.Code, parsed.Error.Message)
	}
	return parsed.Result, nil
}

func (c *rpcClient) callString(method string, params ...any) (string, error) {
	raw, err := c.call(method, params...)
	if err != nil {
		return "", err
	}
	var out string
	if err := json.Unmarshal(raw, &out); err != nil {
		return "", err
	}
	return out, nil
}

func cmdSend(args []string) error {
	fs := flag.NewFlagSet("send", flag.ExitOnError)
	rpcURL := fs.String("rpc", "http://127.0.0.1:8545", "node RPC endpoint")
	dataDir := fs.String("datadir", "./data", "data directory holding the keystore")
	from := fs.String("from", "", "sender address")
	to := fs.String("to", "", "recipient address (omit to deploy a contract)")
	value := fs.String("value", "0", "value in wei")
	dataHex := fs.String("data", "", "hex call data")
	gas := fs.Uint64("gas", 0, "gas limit (estimated when omitted)")
	passphrase := fs.String("password", "", "passphrase to unlock the sender")
	fs.Parse(args)

	if *from == "" {
		return errors.New("-from is required")
	}
	fromAddr, err := common.HexToAddress(*from)
	if err != nil {
		return err
	}
	amount, ok := new(big.Int).SetString(*value, 10)
	if !ok {
		return fmt.Errorf("value %q is not a decimal number", *value)
	}
	var callData []byte
	if *dataHex != "" {
		if callData, err = common.DecodeHex(*dataHex); err != nil {
			return fmt.Errorf("data: %w", err)
		}
	}
	var toAddr *common.Address
	if *to != "" {
		addr, err := common.HexToAddress(*to)
		if err != nil {
			return err
		}
		toAddr = &addr
	}

	ks, err := keystore.New(filepath.Join(*dataDir, "keystore"))
	if err != nil {
		return err
	}
	pass := *passphrase
	if pass == "" {
		if pass, err = promptPassphrase(fmt.Sprintf("Passphrase for %s: ", fromAddr), false); err != nil {
			return err
		}
	}
	key, err := ks.Unlock(fromAddr, pass)
	if err != nil {
		return err
	}

	client := &rpcClient{url: *rpcURL}

	chainIDHex, err := client.callString("eth_chainId")
	if err != nil {
		return err
	}
	chainID, err := common.DecodeHexBig(chainIDHex)
	if err != nil {
		return err
	}
	nonceHex, err := client.callString("eth_getTransactionCount", fromAddr.Hex(), "pending")
	if err != nil {
		return err
	}
	nonce, err := common.DecodeHexUint(nonceHex)
	if err != nil {
		return err
	}
	gasPriceHex, err := client.callString("eth_gasPrice")
	if err != nil {
		return err
	}
	feeCap, err := common.DecodeHexBig(gasPriceHex)
	if err != nil {
		return err
	}

	gasLimit := *gas
	if gasLimit == 0 {
		args := map[string]any{
			"from":  fromAddr.Hex(),
			"value": common.EncodeHexBig(amount),
			"data":  common.EncodeHex(callData),
		}
		if toAddr != nil {
			args["to"] = toAddr.Hex()
		}
		estimateHex, err := client.callString("eth_estimateGas", args)
		if err != nil {
			return fmt.Errorf("estimating gas: %w", err)
		}
		if gasLimit, err = common.DecodeHexUint(estimateHex); err != nil {
			return err
		}
		// Leave headroom: state can move between the estimate and inclusion.
		gasLimit = gasLimit * 12 / 10
	}

	signer := core.NewSigner(chainID)
	tx, err := signer.SignTx(core.NewTx(&core.DynamicFeeTx{
		Nonce:     nonce,
		GasTipCap: big.NewInt(1_000_000_000),
		GasFeeCap: feeCap,
		Gas:       gasLimit,
		To:        toAddr,
		Value:     amount,
		Data:      callData,
	}), key)
	if err != nil {
		return err
	}
	raw, err := tx.MarshalBinary()
	if err != nil {
		return err
	}

	hash, err := client.callString("eth_sendRawTransaction", common.EncodeHex(raw))
	if err != nil {
		return err
	}
	fmt.Println(hash)
	return nil
}

func cmdCall(args []string) error {
	fs := flag.NewFlagSet("call", flag.ExitOnError)
	rpcURL := fs.String("rpc", "http://127.0.0.1:8545", "node RPC endpoint")
	to := fs.String("to", "", "contract address")
	from := fs.String("from", "", "caller address")
	dataHex := fs.String("data", "", "hex call data")
	fs.Parse(args)

	if *to == "" {
		return errors.New("-to is required")
	}
	callArgs := map[string]any{"to": *to, "data": *dataHex}
	if *from != "" {
		callArgs["from"] = *from
	}

	client := &rpcClient{url: *rpcURL}
	result, err := client.callString("eth_call", callArgs, "latest")
	if err != nil {
		return err
	}
	fmt.Println(result)
	return nil
}

func cmdBalance(args []string) error {
	fs := flag.NewFlagSet("balance", flag.ExitOnError)
	rpcURL := fs.String("rpc", "http://127.0.0.1:8545", "node RPC endpoint")
	fs.Parse(args)

	if fs.NArg() < 1 {
		return errors.New("usage: padi-chain balance <address>")
	}
	addr, err := common.HexToAddress(fs.Arg(0))
	if err != nil {
		return err
	}

	client := &rpcClient{url: *rpcURL}
	balanceHex, err := client.callString("eth_getBalance", addr.Hex(), "latest")
	if err != nil {
		return err
	}
	balance, err := common.DecodeHexBig(balanceHex)
	if err != nil {
		return err
	}
	fmt.Printf("%s wei (%s)\n", balance, formatEther(balance))
	return nil
}

func cmdStatus(args []string) error {
	fs := flag.NewFlagSet("status", flag.ExitOnError)
	rpcURL := fs.String("rpc", "http://127.0.0.1:8545", "node RPC endpoint")
	fs.Parse(args)

	client := &rpcClient{url: *rpcURL}
	raw, err := client.call("padi_nodeInfo")
	if err != nil {
		return err
	}
	var info map[string]any
	if err := json.Unmarshal(raw, &info); err != nil {
		return err
	}

	number, _ := common.DecodeHexUint(fmt.Sprint(info["blockNumber"]))
	chainID, _ := common.DecodeHexBig(fmt.Sprint(info["chainId"]))
	fmt.Printf("version:  %v\n", info["version"])
	fmt.Printf("chain id: %s\n", chainID)
	fmt.Printf("head:     #%d %v\n", number, info["head"])
	if finalized, err := common.DecodeHexUint(fmt.Sprint(info["finalized"])); err == nil {
		fmt.Printf("final:    #%d\n", finalized)
	}
	fmt.Printf("quorum:   %v of %v validators\n", info["quorum"], info["validators"])
	fmt.Printf("genesis:  %v\n", info["genesis"])
	fmt.Printf("peers:    %v\n", info["peers"])
	if pool, ok := info["txpool"].(map[string]any); ok {
		fmt.Printf("txpool:   %v pending, %v queued\n", pool["pending"], pool["queued"])
	}
	return nil
}

func cmdPrune(args []string) error {
	fs := flag.NewFlagSet("prune", flag.ExitOnError)
	monitor := fs.String("monitor", "http://127.0.0.1:6060", "node monitoring endpoint")
	fs.Parse(args)

	resp, err := http.Post(*monitor+"/admin/prune", "application/json", nil)
	if err != nil {
		return fmt.Errorf("calling %s: %w", *monitor, err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s: %s", resp.Status, strings.TrimSpace(string(body)))
	}

	var stats struct {
		Deleted    int   `json:"deleted"`
		Reachable  int   `json:"reachable"`
		Roots      int   `json:"roots"`
		Skipped    int   `json:"skipped"`
		DurationMs int64 `json:"durationMs"`
	}
	if err := json.Unmarshal(body, &stats); err != nil {
		return err
	}
	fmt.Printf("deleted %d entries, %d reachable across %d roots (%d skipped) in %dms\n",
		stats.Deleted, stats.Reachable, stats.Roots, stats.Skipped, stats.DurationMs)
	return nil
}

// formatEther renders wei as a decimal ether amount.
func formatEther(wei *big.Int) string {
	ether := new(big.Int).Div(wei, big.NewInt(1e18))
	remainder := new(big.Int).Mod(wei, big.NewInt(1e18))
	fraction := fmt.Sprintf("%018d", remainder)
	fraction = strings.TrimRight(fraction, "0")
	if fraction == "" {
		return ether.String() + " ETH"
	}
	return ether.String() + "." + fraction + " ETH"
}

// promptPassphrase reads a passphrase from the terminal. The terminal is not
// put into no-echo mode here, so it warns rather than pretending to hide input.
func promptPassphrase(prompt string, confirm bool) (string, error) {
	reader := bufio.NewReader(os.Stdin)
	fmt.Fprint(os.Stderr, prompt)
	first, err := reader.ReadString('\n')
	if err != nil {
		return "", err
	}
	first = strings.TrimRight(first, "\r\n")
	if first == "" {
		return "", errors.New("the passphrase must not be empty")
	}
	if confirm {
		fmt.Fprint(os.Stderr, "Confirm passphrase: ")
		second, err := reader.ReadString('\n')
		if err != nil {
			return "", err
		}
		if strings.TrimRight(second, "\r\n") != first {
			return "", errors.New("the passphrases do not match")
		}
	}
	return first, nil
}
