package p2p

import (
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"net"
	"strconv"
	"sync"
	"time"

	"padi-chain/common"
	"padi-chain/core"
	"padi-chain/crypto/secp256k1"
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
	// HandleAttestations imports validator votes received from a peer.
	HandleAttestations(attestations []*core.Attestation)
	// HandleEvidence imports equivocation proofs received from a peer.
	HandleEvidence(evidence []*core.Equivocation)
	// LocalSnapshot returns this node's finalized block and the certificate
	// proving it, for a peer that wants to skip replaying the chain.
	LocalSnapshot() (*core.Block, *core.QuorumCert)
	// HandleSnapshot receives a peer's finalized block and certificate.
	HandleSnapshot(block *core.Block, qc *core.QuorumCert)
	// ServeStateNodes returns the state blobs it holds for the given hashes.
	ServeStateNodes(hashes []common.Hash) [][]byte
	// HandleStateNodes receives state blobs requested during a snapshot sync.
	HandleStateNodes(blobs [][]byte)
}

// Config tunes the network layer.
type Config struct {
	ListenAddr string
	// NodeKey is the long-term identity this node authenticates with. It is
	// required: without it there is no way for a peer to know who it is
	// talking to.
	NodeKey *secp256k1.PrivateKey
	// Bootstrap peers to dial on start.
	Bootstrap []string
	MaxPeers  int
	NodeName  string
	// PingInterval is how often idle peers are probed.
	PingInterval time.Duration
	// DialRetry is how long to wait before redialling a lost peer.
	DialRetry time.Duration
	// NAT decides the address this node advertises to peers.
	NAT NATMode
	// DNSSeeds are domains whose TXT records list entry points, consulted only
	// when no bootstrap peers were given.
	DNSSeeds []string
}

// DefaultConfig returns usable networking defaults.
func DefaultConfig(listenAddr string) *Config {
	return &Config{
		ListenAddr:   listenAddr,
		MaxPeers:     25,
		NodeName:     "padi-chain",
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

	// scores tracks peer behaviour so misbehaving nodes can be shed.
	scores *scoreboard

	// addresses is where peers learned from other peers are remembered.
	addresses *addressBook

	// external is the address this node tells peers to dial it on.
	external *externalAddress
}

// NewServer creates a network server.
func NewServer(config *Config, backend Backend, log *slog.Logger) *Server {
	if log == nil {
		log = slog.Default()
	}
	return &Server{
		config:    config,
		backend:   backend,
		log:       log,
		peers:     make(map[string]*Peer),
		quit:      make(chan struct{}),
		seen:      newSeenCache(8192),
		scores:    newScoreboard(),
		addresses: newAddressBook(1024),
		external:  newExternalAddress(),
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

	for _, addr := range s.bootstrapAddresses() {
		s.addresses.add(addr)
		s.wg.Add(1)
		go s.dialLoop(addr)
	}

	s.wg.Add(1)
	go s.discoveryLoop()
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
func (s *Server) dialLoop(raw string) {
	defer s.wg.Done()
	target, err := ParseNodeURL(raw)
	if err != nil {
		s.log.Error("ignoring bootstrap peer", "addr", raw, "err", err)
		return
	}
	addr := target.Addr
	for {
		select {
		case <-s.quit:
			return
		default:
		}

		if s.PeerCount() < s.config.MaxPeers {
			conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
			if err == nil {
				s.handleConnectionAs(conn, false, target)
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
	s.handleConnectionAs(conn, inbound, NodeURL{})
}

// handleConnectionAs is handleConnection with an expectation about who should
// be on the other end. The expectation is empty for inbound connections and for
// addresses given without an identity.
func (s *Server) handleConnectionAs(conn net.Conn, inbound bool, expected NodeURL) {
	if s.PeerCount() >= s.config.MaxPeers {
		conn.Close()
		return
	}

	// Authenticate and establish encryption before a single protocol byte is
	// exchanged, so an unauthenticated peer can never reach the block or
	// transaction handlers.
	sess, err := performHandshake(conn, s.config.NodeKey, !inbound)
	if err != nil {
		s.log.Debug("p2p cryptographic handshake failed", "remote", conn.RemoteAddr().String(), "err", err)
		conn.Close()
		return
	}
	secure := &secureConn{conn: conn, session: sess}

	// The handshake proves who answered; it cannot know who was meant to. When
	// the address named an identity, that is checked here — otherwise dialling
	// a bootstrap node would accept whoever managed to answer at its address,
	// which is the whole attack the identity is there to stop.
	if expected.wantsID() && sess.remoteID != expected.ID {
		s.log.Warn("peer identity does not match the address dialled",
			"addr", expected.Addr, "expected", expected.ID.String(), "got", sess.remoteID.String())
		conn.Close()
		return
	}

	if s.IsBanned(sess.remoteID) {
		s.log.Debug("rejected banned peer", "id", sess.remoteID.String())
		conn.Close()
		return
	}

	peer := newPeer(secure, s, inbound)
	if err := peer.handshake(); err != nil {
		s.log.Debug("p2p protocol handshake failed", "peer", peer.ID(), "err", err)
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

// syncFrom requests what a peer has that this node does not.
func (s *Server) syncFrom(peer *Peer) {
	_, ourHeight := s.backend.Head()
	theirHeight := peer.HeadNumber()
	if theirHeight <= ourHeight {
		return
	}

	// Offer the peer a chance to hand over a finalized snapshot. Whether that
	// is worth taking is the node's decision, not the network layer's.
	peer.Send(MsgGetSnapshot, nil)
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

// backfill asks a peer for the blocks before one that would not connect.
//
// A node whose head sits on a branch the peer abandoned cannot be helped by
// asking for blocks above its own height: every one of them has a parent it
// does not have, and it stays stuck on its own fork for as long as it lives.
// Walking backwards from the block that failed reaches the height where the two
// chains last agreed, and from there the peer's branch imports normally and the
// usual fork choice decides which one wins.
func (s *Server) backfill(peer *Peer, number uint64) {
	if number <= 1 {
		return
	}
	step := peer.nextBackfillStep()
	from := uint64(1)
	if number > step {
		from = number - step
	}
	count := number - from
	if count > MaxBlocksPerRequest {
		count = MaxBlocksPerRequest
		from = number - count
	}
	s.log.Debug("searching for a common ancestor", "peer", peer.ID(), "from", from, "count", count)
	peer.Send(MsgGetBlocks, &GetBlocks{From: from, Count: count})
}

// penalise deducts a peer's score and disconnects it if it runs out.
func (s *Server) penalise(id NodeID, amount int, reason string) {
	if !s.scores.penalise(id, amount) {
		return
	}
	s.log.Warn("banned peer", "id", id.String(), "reason", reason, "duration", banDuration)

	s.mu.Lock()
	defer s.mu.Unlock()
	for key, peer := range s.peers {
		if peer.NodeID() == id {
			peer.Close()
			delete(s.peers, key)
		}
	}
}

// IsBanned reports whether a peer is currently refused.
func (s *Server) IsBanned(id NodeID) bool { return s.scores.isBanned(id) }

// ScoreOf returns a peer's reputation score.
func (s *Server) ScoreOf(id NodeID) int { return s.scores.scoreOf(id) }

// SyncFromPeers re-runs the catch-up request against every peer, for a node
// that has just jumped forward and needs the blocks since.
func (s *Server) SyncFromPeers() {
	for _, peer := range s.Peers() {
		go s.syncFrom(peer)
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

// BroadcastAttestations announces validator votes to peers.
func (s *Server) BroadcastAttestations(attestations []*core.Attestation) {
	var fresh []*core.Attestation
	for _, a := range attestations {
		if s.seen.add(a.Hash()) {
			fresh = append(fresh, a)
		}
	}
	if len(fresh) == 0 {
		return
	}
	payload, err := encodePayload(&AttestationsPayload{Attestations: fresh})
	if err != nil {
		return
	}
	for _, peer := range s.Peers() {
		peer.sendRaw(MsgAttestations, payload)
	}
}

// BroadcastEvidence announces equivocation proofs to peers. Evidence is worth
// propagating aggressively: it is how the network learns that a validator has
// broken the one rule finality depends on.
func (s *Server) BroadcastEvidence(evidence []*core.Equivocation) {
	if len(evidence) == 0 {
		return
	}
	payload, err := encodePayload(&EvidencePayload{Evidence: evidence})
	if err != nil {
		return
	}
	for _, peer := range s.Peers() {
		peer.sendRaw(MsgEvidence, payload)
	}
}

// RequestSnapshot asks peers for a finalized block to sync state from.
func (s *Server) RequestSnapshot() {
	for _, peer := range s.Peers() {
		peer.Send(MsgGetSnapshot, nil)
	}
}

// RequestStateNodes asks a peer for state blobs. Requests go to one peer at a
// time so a slow peer does not multiply into duplicate traffic everywhere.
func (s *Server) RequestStateNodes(hashes []common.Hash) bool {
	if len(hashes) == 0 {
		return false
	}
	peers := s.Peers()
	if len(peers) == 0 {
		return false
	}
	// Spread requests across peers by the first hash, so no single peer
	// carries the whole sync.
	peer := peers[int(hashes[0][0])%len(peers)]
	return peer.Send(MsgGetStateNodes, &StateNodesRequest{Hashes: hashes}) == nil
}

// AddPeer dials an additional peer at runtime.
func (s *Server) AddPeer(raw string) error {
	target, err := ParseNodeURL(raw)
	if err != nil {
		return err
	}
	conn, err := net.DialTimeout("tcp", target.Addr, 5*time.Second)
	if err != nil {
		return err
	}
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.handleConnectionAs(conn, false, target)
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

// listenPort is the port peers should dial to reach this node.
func (s *Server) listenPort() int {
	if s.listener == nil {
		return 0
	}
	if addr, ok := s.listener.Addr().(*net.TCPAddr); ok {
		return addr.Port
	}
	return 0
}

// noteObservedAddress records a peer's report of where it sees this node.
//
// The reporting peer is identified by the key it authenticated with rather than
// by its address, so one machine cannot vote repeatedly by reconnecting from a
// range of ports.
func (s *Server) noteObservedAddress(observed string, from NodeID) {
	if observed == "" || s.config.NAT.disabled || s.config.NAT.fixed != nil {
		return
	}
	if s.external.note(observed, from.String(), s.listenPort()) {
		s.log.Info("learned our external address", "url", s.NodeURL())
	}
}

// ExternalAddr returns the address this node advertises, or empty if it does
// not know one yet.
func (s *Server) ExternalAddr() string {
	if s.config.NAT.disabled {
		return ""
	}
	if ip := s.config.NAT.fixed; ip != nil {
		return net.JoinHostPort(ip.String(), strconv.Itoa(s.listenPort()))
	}
	return s.external.get()
}
