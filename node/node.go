// Package node wires the chain, the transaction pool, the network and the RPC
// server into a running process.
package node

import (
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"padi-chain/chain"
	"padi-chain/common"
	"padi-chain/consensus"
	"padi-chain/core"
	"padi-chain/crypto/secp256k1"
	"padi-chain/db"
	"padi-chain/keystore"
	"padi-chain/metrics"
	"padi-chain/miner"
	"padi-chain/p2p"
	"padi-chain/rpc"
	"padi-chain/state"
	"padi-chain/txpool"
)

// Version identifies this software over the wire and in the RPC.
const Version = "padi-chain/v0.1.0"

// Config configures a node.
type Config struct {
	DataDir string
	// GenesisPath points at a genesis JSON file. When empty, the genesis
	// already stored in the data directory is reused.
	GenesisPath string
	Genesis     *chain.Genesis

	ListenAddr string
	RPCAddr    string
	// MonitorAddr serves metrics and health checks, on its own listener so it
	// stays reachable when the RPC port is saturated.
	MonitorAddr string
	Bootstrap   []string
	MaxPeers    int
	NodeName    string

	// Validator is the key this node seals blocks with. Without it the node
	// follows the chain but never proposes.
	Validator *secp256k1.PrivateKey
	Mine      bool

	// Prune controls state pruning. A zero value uses the defaults; set
	// Enabled to false to run as an archive node that keeps every state.
	Prune chain.PruneConfig

	// SnapSyncThreshold is how far behind the node must be before it prefers
	// downloading state to replaying blocks. Zero uses the default.
	SnapSyncThreshold uint64

	Logger *slog.Logger
}

// Node is a running blockchain node.
type Node struct {
	config *Config
	log    *slog.Logger

	store    db.Database
	nodeKey  *secp256k1.PrivateKey
	chain    *chain.BlockChain
	engine   *consensus.PoA
	txpool   *txpool.TxPool
	keystore *keystore.KeyStore

	network         *p2p.Server
	rpc             *rpc.Server
	metrics         *metrics.NodeMetrics
	monitorServer   *http.Server
	monitorListener net.Listener
	builder         *miner.Builder
	attestations    *consensus.AttestationPool
	pruner          *chain.Pruner
	snap            snapSync
	blsCache        blsKeyCache

	quit     chan struct{}
	quitOnce sync.Once
	wg       sync.WaitGroup

	startedAt time.Time
}

// New creates a node from its configuration, opening the data directory and
// initialising the chain.
func New(config *Config) (*Node, error) {
	if config.Logger == nil {
		config.Logger = slog.Default()
	}
	if config.NodeName == "" {
		config.NodeName = "padi-chain"
	}
	if config.MaxPeers == 0 {
		config.MaxPeers = 25
	}

	if err := os.MkdirAll(config.DataDir, 0o755); err != nil {
		return nil, fmt.Errorf("node: creating data directory: %w", err)
	}

	genesis := config.Genesis
	if genesis == nil {
		if config.GenesisPath == "" {
			config.GenesisPath = filepath.Join(config.DataDir, "genesis.json")
		}
		loaded, err := chain.LoadGenesis(config.GenesisPath)
		if err != nil {
			return nil, fmt.Errorf("node: %w (run `padi-chain init` first)", err)
		}
		genesis = loaded
	}

	store, err := db.OpenFile(filepath.Join(config.DataDir, "chaindata", "chain.db"), db.Options{})
	if err != nil {
		return nil, err
	}

	engine, err := consensus.NewPoA(genesis.Validators, genesis.BlockPeriod)
	if err != nil {
		store.Close()
		return nil, err
	}

	bc, err := chain.NewBlockChain(store, genesis, engine)
	if err != nil {
		store.Close()
		return nil, err
	}

	ks, err := keystore.New(filepath.Join(config.DataDir, "keystore"))
	if err != nil {
		store.Close()
		return nil, err
	}

	nodeKey, err := loadOrCreateNodeKey(filepath.Join(config.DataDir, "nodekey"))
	if err != nil {
		store.Close()
		return nil, err
	}

	n := &Node{
		config:   config,
		nodeKey:  nodeKey,
		metrics:  metrics.NewNodeMetrics(),
		log:      config.Logger,
		store:    store,
		chain:    bc,
		engine:   engine,
		keystore: ks,
		quit:     make(chan struct{}),
	}
	n.txpool = txpool.New(txpool.DefaultConfig(), genesis.ChainID, n)
	genesisKeys, err := bc.BLSKeysAt(0)
	if err != nil {
		store.Close()
		return nil, err
	}
	genesisEncoded := make([][]byte, len(genesisKeys))
	for i, key := range genesisKeys {
		if key != nil {
			genesisEncoded[i] = key.Bytes()
		}
	}
	n.attestations = consensus.NewAttestationPool(genesis.ChainID, bc.Validators(), genesisEncoded)

	pruneConfig := config.Prune
	if pruneConfig.Retain == 0 && pruneConfig.Interval == 0 && !pruneConfig.Enabled {
		pruneConfig = *chain.DefaultPruneConfig()
		config.Prune = pruneConfig
	}
	if pruneConfig.Enabled {
		n.pruner = chain.NewPruner(bc, bc.Tracker(), &pruneConfig, config.Logger)
	}

	if config.Validator != nil {
		n.builder = miner.NewBuilder(bc, engine, config.Validator)
		n.builder.SetAttestationPool(n.attestations)
		n.builder.SetBLSKey(n.blsKey())
	}
	return n, nil
}

// --- accessors used by the RPC and network layers ---

func (n *Node) Chain() *chain.BlockChain     { return n.chain }
func (n *Node) TxPool() *txpool.TxPool       { return n.txpool }
func (n *Node) KeyStore() *keystore.KeyStore { return n.keystore }
func (n *Node) ChainID() *big.Int            { return n.chain.Config().ChainID }
func (n *Node) ClientVersion() string        { return Version }

func (n *Node) PeerCount() int {
	if n.network == nil {
		return 0
	}
	return n.network.PeerCount()
}

func (n *Node) Accounts() []common.Address {
	accounts, err := n.keystore.Accounts()
	if err != nil {
		return nil
	}
	return accounts
}

// --- txpool.StateReader ---

func (n *Node) CurrentState() (*state.StateDB, error) { return n.chain.State() }
func (n *Node) CurrentGasLimit() uint64               { return n.chain.CurrentBlock().GasLimit() }
func (n *Node) CurrentBaseFee() *big.Int              { return n.chain.CurrentBlock().BaseFee() }

// --- p2p.Backend ---

func (n *Node) Genesis() common.Hash { return n.chain.Genesis().Hash() }
func (n *Node) NetworkID() *big.Int  { return n.ChainID() }

func (n *Node) Head() (common.Hash, uint64) {
	head := n.chain.CurrentBlock()
	return head.Hash(), head.NumberU64()
}

func (n *Node) BlockByNumber(number uint64) *core.Block {
	return n.chain.GetBlockByNumber(number)
}

func (n *Node) BlockByHash(hash common.Hash) *core.Block {
	return n.chain.GetBlockByHash(hash)
}

// HandleBlock imports a block announced by a peer.
func (n *Node) HandleBlock(block *core.Block) error {
	// While a snapshot sync is running the node has no state to execute
	// against, and adopting the snapshot afterwards requires it to still be at
	// genesis. Blocks are dropped rather than queued; the catch-up request
	// after the sync finishes fetches them again.
	if n.SnapSyncing() {
		return errSnapSyncing
	}
	err := n.chain.InsertBlock(block)
	switch {
	case err == nil:
		n.syncValidatorSet()
		n.metrics.BlocksImported.Inc()
		n.metrics.BlockGasUsed.Observe(float64(block.GasUsed()))
		n.txpool.Reset(block.Transactions())
		n.log.Info("imported block", "number", block.NumberU64(), "hash", block.Hash(), "txs", len(block.Transactions()))
		n.attest(block)
		return nil
	case errors.Is(err, chain.ErrKnownBlock):
		return err
	case errors.Is(err, chain.ErrUnknownAncestor):
		// The block is ahead of us; the peer sync loop will fill the gap.
		return err
	default:
		n.metrics.BlocksRejected.Inc()
		n.log.Warn("rejected block from peer", "number", block.NumberU64(), "hash", block.Hash(), "err", err)
		return err
	}
}

// Attestations exposes the vote pool.
func (n *Node) Attestations() *consensus.AttestationPool { return n.attestations }

// HandleAttestations records validator votes received from a peer and acts on
// any quorum they complete.
func (n *Node) HandleAttestations(attestations []*core.Attestation) {
	for _, attestation := range attestations {
		added, err := n.attestations.Add(attestation)
		if err != nil {
			if errors.Is(err, consensus.ErrEquivocation) {
				// A validator voting two ways is the one fault that can break
				// finality, so it is logged loudly and the proof is spread.
				n.metrics.Equivocations.Inc()
				n.log.Error("equivocation detected", "height", attestation.Number, "err", err)
				evidence := n.attestations.Evidence()
				if n.network != nil {
					n.network.BroadcastEvidence(evidence)
				}
				// Detecting the offence is only half the job; the proof has to
				// reach the chain for the stake to be slashed.
				for _, proof := range evidence {
					n.reportEquivocation(proof)
				}
			}
			continue
		}
		if added {
			n.metrics.AttestationsSeen.Inc()
			n.tryFinalize(attestation.Number, attestation.BlockHash)
		}
	}
}

// HandleEvidence records equivocation proofs received from a peer.
func (n *Node) HandleEvidence(evidence []*core.Equivocation) {
	for _, proof := range evidence {
		if err := n.attestations.AddEvidence(proof); err != nil {
			n.log.Debug("rejected equivocation evidence", "err", err)
			continue
		}
		n.log.Error("validator equivocated", "validator", proof.Validator, "height", proof.Number)
		n.reportEquivocation(proof)
	}
}

// syncValidatorSet keeps the attestation pool aligned with the set the chain
// says is active. Without this a validator that joined after genesis would have
// its votes rejected, and the quorum would be computed for a set that no longer
// exists.
func (n *Node) syncValidatorSet() {
	next := n.chain.CurrentBlock().NumberU64() + 1
	set, err := n.chain.ValidatorsAt(next)
	if err != nil || len(set) == 0 {
		return
	}
	keys, err := n.chain.BLSKeysAt(next)
	if err != nil {
		n.log.Warn("could not read the attestation keys for the next block", "err", err)
		return
	}
	encoded := make([][]byte, len(keys))
	for i, key := range keys {
		if key != nil {
			encoded[i] = key.Bytes()
		}
	}
	n.attestations.UpdateValidators(set, encoded)
}

// tryFinalize promotes a block to final once a quorum has attested to it.
func (n *Node) tryFinalize(number uint64, hash common.Hash) {
	qc := n.attestations.Certificate(number, hash)
	if qc == nil {
		return
	}
	if number <= n.chain.FinalizedNumber() {
		return
	}
	if err := n.chain.Finalize(qc); err != nil {
		n.log.Warn("finalization failed", "number", number, "hash", hash, "err", err)
		return
	}
	n.attestations.MarkFinalized(number)
	n.log.Info("finalized block", "number", number, "hash", hash,
		"votes", qc.Count(), "quorum", n.attestations.Quorum())
}

// attest votes for a block this node has verified and imported. A validator
// only ever attests to a block it executed itself, so a quorum is a statement
// about validity, not just about what was seen first.
func (n *Node) attest(block *core.Block) {
	if n.config.Validator == nil {
		return
	}
	index, ok := n.attestations.IndexOf(keystore.AddressOf(n.config.Validator))
	if !ok {
		return // not in the set that governs this height
	}
	blsKey := n.blsKey()
	if blsKey == nil {
		return
	}
	attestation := n.attestations.Attest(blsKey, uint64(index), block.NumberU64(), block.Hash())
	if _, err := n.attestations.Add(attestation); err != nil {
		n.log.Error("recording own attestation", "err", err)
		return
	}
	// Count our own vote like any other: otherwise the metric reads zero on a
	// node that is attesting perfectly well.
	n.metrics.AttestationsSeen.Inc()
	n.tryFinalize(block.NumberU64(), block.Hash())

	if n.network != nil {
		n.network.BroadcastAttestations([]*core.Attestation{attestation})
	}
}

// errSnapSyncing marks a block dropped because the node is downloading state.
var errSnapSyncing = errors.New("node: snapshot sync in progress")

// HandleTransactions imports transactions announced by a peer.
func (n *Node) HandleTransactions(txs []*core.Transaction) {
	for i, err := range n.txpool.AddBatch(txs) {
		if err == nil {
			n.metrics.TxAccepted.Inc()
			continue
		}
		n.metrics.TxRejected.Inc()
		if !errors.Is(err, txpool.ErrAlreadyKnown) {
			n.log.Debug("rejected transaction from peer", "hash", txs[i].Hash(), "err", err)
		}
	}
}

// Start brings up networking, the RPC server and, if configured, mining.
func (n *Node) Start() error {
	n.startedAt = time.Now()

	if n.config.ListenAddr != "" {
		netConfig := p2p.DefaultConfig(n.config.ListenAddr)
		netConfig.NodeKey = n.nodeKey
		netConfig.Bootstrap = n.config.Bootstrap
		netConfig.MaxPeers = n.config.MaxPeers
		netConfig.NodeName = n.config.NodeName

		n.network = p2p.NewServer(netConfig, n, n.log)
		if err := n.network.Start(); err != nil {
			return err
		}
	}

	if n.config.RPCAddr != "" {
		n.rpc = rpc.NewServer()
		rpc.RegisterAll(n.rpc, n)
		if err := n.rpc.Start(n.config.RPCAddr); err != nil {
			return err
		}
		n.log.Info("rpc listening", "addr", n.rpc.Addr())
	}

	// Relay locally submitted transactions to peers.
	if n.network != nil {
		txCh := make(chan []*core.Transaction, 64)
		n.txpool.Subscribe(txCh)
		n.wg.Add(1)
		go func() {
			defer n.wg.Done()
			for {
				select {
				case <-n.quit:
					return
				case txs := <-txCh:
					n.network.BroadcastTransactions(txs)
				}
			}
		}()
	}

	if n.config.MonitorAddr != "" {
		if err := n.startMonitoring(n.config.MonitorAddr); err != nil {
			return err
		}
	}

	n.wg.Add(1)
	go n.maintenanceLoop()

	if n.config.Mine {
		if n.builder == nil {
			return errors.New("node: mining requires a validator key")
		}
		if !n.engine.IsValidator(n.builder.Coinbase()) {
			return fmt.Errorf("node: %s is not in the validator set", n.builder.Coinbase())
		}
		n.wg.Add(1)
		go n.mineLoop()
		n.log.Info("mining enabled", "validator", n.builder.Coinbase())
	}

	head := n.chain.CurrentBlock()
	n.log.Info("node started",
		"chainId", n.ChainID(),
		"genesis", n.chain.Genesis().Hash(),
		"head", head.NumberU64(),
		"finalized", n.chain.FinalizedNumber(),
		"validators", len(n.engine.Validators()),
		"quorum", n.attestations.Quorum())
	return nil
}

// mineLoop proposes a block whenever it is this validator's turn and the block
// period has elapsed.
func (n *Node) mineLoop() {
	defer n.wg.Done()

	period := time.Duration(n.engine.Period()) * time.Second
	if period <= 0 {
		period = time.Second
	}
	// Poll well inside the block period so a turn is never missed by a whole
	// slot because of scheduling jitter.
	ticker := time.NewTicker(period / 4)
	defer ticker.Stop()

	for {
		select {
		case <-n.quit:
			return
		case <-ticker.C:
			n.tryPropose()
		}
	}
}

func (n *Node) tryPropose() {
	head := n.chain.CurrentBlock()
	next := head.NumberU64() + 1

	// The turn accounts for fallback rounds, so an absent proposer costs one
	// round rather than stalling the chain.
	if !n.engine.IsMyTurn(n.builder.Coinbase(), next, head.Time()) {
		return
	}
	if uint64(time.Now().Unix()) < head.Time()+n.engine.Period() {
		return
	}

	candidates := n.txpool.Ready(0)
	result, err := n.builder.Commit(candidates)
	if err != nil {
		if !errors.Is(err, miner.ErrNotOurTurn) {
			n.log.Error("block production failed", "number", next, "err", err)
		}
		return
	}

	n.syncValidatorSet()
	n.metrics.BlocksProduced.Inc()
	n.metrics.BlockGasUsed.Observe(float64(result.Block.GasUsed()))
	n.txpool.Reset(result.Included)
	n.log.Info("sealed block",
		"number", result.Block.NumberU64(),
		"hash", result.Block.Hash(),
		"txs", len(result.Included),
		"gas", result.Block.GasUsed())

	if n.network != nil {
		n.network.BroadcastBlock(result.Block)
	}
	// The proposer attests to its own block like any other validator; in a
	// single-validator network that vote alone is the quorum.
	n.attest(result.Block)
}

// Stop shuts the node down and closes its store.
func (n *Node) Stop() error {
	var err error
	n.quitOnce.Do(func() {
		close(n.quit)
		if n.monitorServer != nil {
			n.monitorServer.Close()
		}
		if n.rpc != nil {
			n.rpc.Stop()
		}
		if n.network != nil {
			n.network.Stop()
		}
		n.wg.Wait()
		err = n.store.Close()
		n.log.Info("node stopped", "uptime", time.Since(n.startedAt).Truncate(time.Second))
	})
	return err
}

// NodeID returns this node's network identity.
func (n *Node) NodeID() p2p.NodeID { return p2p.NodeIDOf(n.nodeKey) }

// loadOrCreateNodeKey reads the node's long-term network identity, generating
// one on first start. The identity has to persist: peers score and ban by it,
// and a node that regenerates it on every restart would look like a new peer
// each time — which is exactly how a misbehaving node would evade a ban.
func loadOrCreateNodeKey(path string) (*secp256k1.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err == nil {
		key, err := secp256k1.PrivateKeyFromHex(strings.TrimSpace(string(data)))
		if err != nil {
			return nil, fmt.Errorf("node: reading %s: %w", path, err)
		}
		return key, nil
	}
	if !os.IsNotExist(err) {
		return nil, fmt.Errorf("node: reading %s: %w", path, err)
	}

	key, err := secp256k1.GenerateKey()
	if err != nil {
		return nil, err
	}
	encoded := common.EncodeHex(key.Bytes())
	if err := os.WriteFile(path, []byte(encoded+"\n"), 0o600); err != nil {
		return nil, fmt.Errorf("node: writing %s: %w", path, err)
	}
	return key, nil
}

// RPCAddr returns the address the RPC server is listening on.
func (n *Node) RPCAddr() string {
	if n.rpc == nil {
		return ""
	}
	return n.rpc.Addr()
}

// P2PAddr returns the address the network server is listening on.
func (n *Node) P2PAddr() string {
	if n.network == nil {
		return ""
	}
	return n.network.Addr()
}

// RPCServer exposes the RPC server, for in-process calls.
func (n *Node) RPCServer() *rpc.Server { return n.rpc }

// AddPeer connects to another node at runtime.
func (n *Node) AddPeer(addr string) error {
	if n.network == nil {
		return errors.New("node: networking is disabled")
	}
	return n.network.AddPeer(addr)
}
