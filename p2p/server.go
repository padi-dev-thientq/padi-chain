package p2p

import (
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"net"
	"sync"
	"time"

	"layer1/common"
	"layer1/core"
)

// Backend is what the network layer needs from the node.
type Backend interface {
	// Genesis identifies the chain.
	Genesis() common.Hash
	// NetworkID is the chain id peers must agree on.
	NetworkID() *big.Int
	// Head returns the current head hash and height.
	Head() (common.Hash, uint64)
	// BlockByNumber returns a canonical block, or nil.
	BlockByNumber(number uint64) *core.Block
	// BlockByHash returns a stored block, or nil.
	BlockByHash(hash common.Hash) *core.Block
	// HandleBlock imports a block received from a peer.
	HandleBlock(block *core.Block) error
	// HandleTransactions imports transactions received from a peer.
	HandleTransactions(txs []*core.Transaction)
}

// Config tunes the network layer.
type Config struct {
	ListenAddr string
	// Bootstrap peers to dial on start.
	Bootstrap []string
	MaxPeers  int
	NodeName  string
	// PingInterval is how often idle peers are probed.
	PingInterval time.Duration
	// DialRetry is how long to wait before redialling a lost peer.
	DialRetry time.Duration
}

// DefaultConfig returns usable networking defaults.
func DefaultConfig(listenAddr string) *Config {
	return &Config{
		ListenAddr:   listenAddr,
		MaxPeers:     25,
		NodeName:     "layer1",
		PingInterval: 15 * time.Second,
		DialRetry:    10 * time.Second,
	}
}

// Server accepts and dials peer connections.
type Server struct {
	config  *Config
	backend Backend
	log     *slog.Logger

	listener net.Listener

	mu    sync.RWMutex
	peers map[string]*Peer

	quit     chan struct{}
	quitOnce sync.Once
	wg       sync.WaitGroup

	// seenBlocks and seenTxs stop a gossiped item from bouncing between peers
	// forever.
	seen *seenCache
}

// NewServer creates a network server.
func NewServer(config *Config, backend Backend, log *slog.Logger) *Server {
	if log == nil {
		log = slog.Default()
	}
	return &Server{
		config:  config,
		backend: backend,
		log:     log,
		peers:   make(map[string]*Peer),
		quit:    make(chan struct{}),
		seen:    newSeenCache(8192),
	}
}

// Start begins listening and dials the bootstrap peers.
func (s *Server) Start() error {
	if s.config.ListenAddr != "" {
		listener, err := net.Listen("tcp", s.config.ListenAddr)
		if err != nil {
			return fmt.Errorf("p2p: listening on %s: %w", s.config.ListenAddr, err)
		}
		s.listener = listener
		s.wg.Add(1)
		go s.acceptLoop()
		s.log.Info("p2p listening", "addr", listener.Addr().String())
	}

	for _, addr := range s.config.Bootstrap {
		s.wg.Add(1)
		go s.dialLoop(addr)
	}
	return nil
}

// Addr returns the listening address.
func (s *Server) Addr() string {
	if s.listener == nil {
		return ""
	}
	return s.listener.Addr().String()
}

// Stop shuts the server and all peers down.
func (s *Server) Stop() {
	s.quitOnce.Do(func() {
		close(s.quit)
		if s.listener != nil {
			s.listener.Close()
		}
		s.mu.Lock()
		for _, peer := range s.peers {
			peer.Close()
		}
		s.mu.Unlock()
		s.wg.Wait()
	})
}

func (s *Server) acceptLoop() {
	defer s.wg.Done()
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			select {
			case <-s.quit:
				return
			default:
				s.log.Debug("p2p accept failed", "err", err)
				continue
			}
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.handleConnection(conn, true)
		}()
	}
}

// dialLoop keeps trying to reach a peer until the server stops.
func (s *Server) dialLoop(addr string) {
	defer s.wg.Done()
	for {
		select {
		case <-s.quit:
			return
		default:
		}

		if s.PeerCount() < s.config.MaxPeers {
			conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
			if err == nil {
				s.handleConnection(conn, false)
			} else {
				s.log.Debug("p2p dial failed", "addr", addr, "err", err)
			}
		}

		select {
		case <-s.quit:
			return
		case <-time.After(s.config.DialRetry):
		}
	}
}

func (s *Server) handleConnection(conn net.Conn, inbound bool) {
	if s.PeerCount() >= s.config.MaxPeers {
		conn.Close()
		return
	}

	peer := newPeer(conn, s, inbound)
	if err := peer.handshake(); err != nil {
		s.log.Debug("p2p handshake failed", "remote", conn.RemoteAddr().String(), "err", err)
		conn.Close()
		return
	}

	key := peer.ID()
	s.mu.Lock()
	if _, exists := s.peers[key]; exists {
		// Already connected, most likely because both sides dialled at once.
		s.mu.Unlock()
		conn.Close()
		return
	}
	s.peers[key] = peer
	s.mu.Unlock()

	s.log.Info("peer connected", "id", key, "inbound", inbound, "head", peer.HeadNumber())

	// Ask a peer that is ahead of us for the blocks we are missing.
	go s.syncFrom(peer)

	peer.run()

	s.mu.Lock()
	delete(s.peers, key)
	s.mu.Unlock()
	s.log.Info("peer disconnected", "id", key)
}

// syncFrom requests the blocks a peer has that this node does not.
func (s *Server) syncFrom(peer *Peer) {
	_, ourHeight := s.backend.Head()
	theirHeight := peer.HeadNumber()
	if theirHeight <= ourHeight {
		return
	}
	for from := ourHeight + 1; from <= theirHeight; from += MaxBlocksPerRequest {
		count := theirHeight - from + 1
		if count > MaxBlocksPerRequest {
			count = MaxBlocksPerRequest
		}
		if err := peer.Send(MsgGetBlocks, &GetBlocks{From: from, Count: count}); err != nil {
			return
		}
		// Give the peer time to answer before asking for the next batch, so a
		// long sync does not flood the connection.
		time.Sleep(100 * time.Millisecond)
	}
}

// PeerCount returns the number of connected peers.
func (s *Server) PeerCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.peers)
}

// Peers returns the connected peers.
func (s *Server) Peers() []*Peer {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*Peer, 0, len(s.peers))
	for _, peer := range s.peers {
		out = append(out, peer)
	}
	return out
}

// BroadcastBlock announces a block to every peer that has not seen it.
func (s *Server) BroadcastBlock(block *core.Block) {
	enc, err := block.MarshalBinary()
	if err != nil {
		s.log.Error("p2p encoding block for broadcast", "err", err)
		return
	}
	s.seen.add(block.Hash())

	payload, err := encodePayload(&BlocksPayload{Blocks: [][]byte{enc}})
	if err != nil {
		return
	}
	for _, peer := range s.Peers() {
		if peer.hasSeen(block.Hash()) {
			continue
		}
		peer.sendRaw(MsgNewBlock, payload)
	}
}

// BroadcastTransactions announces transactions to peers.
func (s *Server) BroadcastTransactions(txs []*core.Transaction) {
	var fresh []*core.Transaction
	for _, tx := range txs {
		if s.seen.add(tx.Hash()) {
			fresh = append(fresh, tx)
		}
	}
	if len(fresh) == 0 {
		return
	}
	encoded, err := encodeTransactions(fresh)
	if err != nil {
		return
	}
	payload, err := encodePayload(&TransactionsPayload{Transactions: encoded})
	if err != nil {
		return
	}
	for _, peer := range s.Peers() {
		peer.sendRaw(MsgNewTransactions, payload)
	}
}

// AddPeer dials an additional peer at runtime.
func (s *Server) AddPeer(addr string) error {
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return err
	}
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.handleConnection(conn, false)
	}()
	return nil
}

// seenCache remembers recently gossiped hashes, bounded so it cannot grow
// without limit.
type seenCache struct {
	mu    sync.Mutex
	limit int
	items map[common.Hash]struct{}
	order []common.Hash
}

func newSeenCache(limit int) *seenCache {
	return &seenCache{limit: limit, items: make(map[common.Hash]struct{}, limit)}
}

// add records a hash and reports whether it was new.
func (c *seenCache) add(hash common.Hash) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.items[hash]; ok {
		return false
	}
	c.items[hash] = struct{}{}
	c.order = append(c.order, hash)
	if len(c.order) > c.limit {
		oldest := c.order[0]
		c.order = c.order[1:]
		delete(c.items, oldest)
	}
	return true
}

func (c *seenCache) has(hash common.Hash) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	_, ok := c.items[hash]
	return ok
}

var errServerStopped = errors.New("p2p: server stopped")
