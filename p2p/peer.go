package p2p

import (
	"bufio"
	"fmt"
	"net"
	"sync"
	"time"

	"layer1/common"
	"layer1/core"
)

// Peer is one connected node.
type Peer struct {
	conn    net.Conn
	server  *Server
	inbound bool

	reader *bufio.Reader
	writer *bufio.Writer

	writeMu sync.Mutex

	// status is the peer's handshake, fixed for the life of the connection.
	status Status

	// head tracks the peer's latest announced block.
	headMu     sync.RWMutex
	head       common.Hash
	headNumber uint64

	// seen remembers what this peer already knows, so gossip is not echoed
	// back to its source.
	seen *seenCache

	closeOnce sync.Once
	closed    chan struct{}
}

func newPeer(conn net.Conn, server *Server, inbound bool) *Peer {
	return &Peer{
		conn:    conn,
		server:  server,
		inbound: inbound,
		reader:  bufio.NewReaderSize(conn, 64*1024),
		writer:  bufio.NewWriterSize(conn, 64*1024),
		seen:    newSeenCache(4096),
		closed:  make(chan struct{}),
	}
}

// ID identifies the peer by its remote address and node name.
func (p *Peer) ID() string {
	return fmt.Sprintf("%s@%s", p.status.NodeName, p.conn.RemoteAddr().String())
}

// RemoteAddr returns the peer's address.
func (p *Peer) RemoteAddr() string { return p.conn.RemoteAddr().String() }

// Inbound reports whether the peer dialled us.
func (p *Peer) Inbound() bool { return p.inbound }

// Head returns the peer's latest announced block.
func (p *Peer) Head() (common.Hash, uint64) {
	p.headMu.RLock()
	defer p.headMu.RUnlock()
	return p.head, p.headNumber
}

// HeadNumber returns the peer's announced height.
func (p *Peer) HeadNumber() uint64 {
	_, number := p.Head()
	return number
}

func (p *Peer) setHead(hash common.Hash, number uint64) {
	p.headMu.Lock()
	defer p.headMu.Unlock()
	// Only move forward: a stale announcement must not rewind our view.
	if number >= p.headNumber {
		p.head, p.headNumber = hash, number
	}
}

func (p *Peer) hasSeen(hash common.Hash) bool { return p.seen.has(hash) }

// handshake exchanges status messages and checks the peer is on our chain.
func (p *Peer) handshake() error {
	head, number := p.server.backend.Head()
	ours := &Status{
		Version:    ProtocolVersion,
		NetworkID:  p.server.backend.NetworkID(),
		Genesis:    p.server.backend.Genesis(),
		Head:       head,
		HeadNumber: number,
		NodeName:   p.server.config.NodeName,
	}

	p.conn.SetDeadline(time.Now().Add(10 * time.Second))
	defer p.conn.SetDeadline(time.Time{})

	if err := p.Send(MsgStatus, ours); err != nil {
		return err
	}

	code, payload, err := readMessage(p.reader)
	if err != nil {
		return err
	}
	if code != MsgStatus {
		return fmt.Errorf("p2p: expected a status message, got %s", code)
	}
	var theirs Status
	if err := decodePayload(payload, &theirs); err != nil {
		return err
	}

	if theirs.Version != ProtocolVersion {
		return fmt.Errorf("%w: peer speaks version %d, we speak %d", ErrProtocolMismatch, theirs.Version, ProtocolVersion)
	}
	if theirs.Genesis != ours.Genesis {
		return fmt.Errorf("%w: peer genesis %s, ours %s", ErrGenesisMismatch, theirs.Genesis, ours.Genesis)
	}
	if theirs.NetworkID == nil || ours.NetworkID.Cmp(theirs.NetworkID) != 0 {
		return fmt.Errorf("%w: peer network %v, ours %v", ErrGenesisMismatch, theirs.NetworkID, ours.NetworkID)
	}

	p.status = theirs
	p.setHead(theirs.Head, theirs.HeadNumber)
	return nil
}

// Send encodes and writes a message.
func (p *Peer) Send(code MessageCode, payload any) error {
	var (
		enc []byte
		err error
	)
	if payload != nil {
		if enc, err = encodePayload(payload); err != nil {
			return err
		}
	}
	return p.sendRaw(code, enc)
}

// sendRaw writes an already-encoded payload.
func (p *Peer) sendRaw(code MessageCode, payload []byte) error {
	p.writeMu.Lock()
	defer p.writeMu.Unlock()

	select {
	case <-p.closed:
		return errServerStopped
	default:
	}

	p.conn.SetWriteDeadline(time.Now().Add(30 * time.Second))
	if err := writeMessage(p.writer, code, payload); err != nil {
		p.Close()
		return err
	}
	if err := p.writer.Flush(); err != nil {
		p.Close()
		return err
	}
	return nil
}

// Close disconnects the peer.
func (p *Peer) Close() {
	p.closeOnce.Do(func() {
		close(p.closed)
		p.conn.Close()
	})
}

// run reads and handles messages until the connection ends.
func (p *Peer) run() {
	defer p.Close()

	// Keep the connection warm and detect a peer that has gone away.
	pingDone := make(chan struct{})
	go func() {
		defer close(pingDone)
		ticker := time.NewTicker(p.server.config.PingInterval)
		defer ticker.Stop()
		for {
			select {
			case <-p.closed:
				return
			case <-p.server.quit:
				return
			case <-ticker.C:
				if err := p.Send(MsgPing, nil); err != nil {
					return
				}
			}
		}
	}()

	for {
		select {
		case <-p.closed:
			return
		case <-p.server.quit:
			return
		default:
		}

		// A peer that says nothing for long enough is dropped; the ping loop
		// guarantees a healthy peer always has something to say.
		p.conn.SetReadDeadline(time.Now().Add(3 * p.server.config.PingInterval))
		code, payload, err := readMessage(p.reader)
		if err != nil {
			return
		}
		if err := p.handle(code, payload); err != nil {
			p.server.log.Debug("p2p message handling failed", "peer", p.ID(), "code", code, "err", err)
			return
		}
	}
}

func (p *Peer) handle(code MessageCode, payload []byte) error {
	backend := p.server.backend

	switch code {
	case MsgPing:
		return p.Send(MsgPong, nil)

	case MsgPong:
		return nil

	case MsgStatus:
		// A second status message updates the peer's head.
		var status Status
		if err := decodePayload(payload, &status); err != nil {
			return err
		}
		p.setHead(status.Head, status.HeadNumber)
		return nil

	case MsgNewBlock, MsgBlocks:
		var blocks BlocksPayload
		if err := decodePayload(payload, &blocks); err != nil {
			return err
		}
		decoded, err := decodeBlocks(blocks.Blocks)
		if err != nil {
			return err
		}
		for _, block := range decoded {
			p.seen.add(block.Hash())
			p.setHead(block.Hash(), block.NumberU64())

			if err := backend.HandleBlock(block); err != nil {
				// An invalid or already-known block is not a protocol
				// violation, so the connection stays up.
				p.server.log.Debug("p2p block rejected", "peer", p.ID(), "number", block.NumberU64(), "err", err)
				continue
			}
			// Relay only blocks that were new to us, which keeps gossip from
			// looping.
			if p.server.seen.add(block.Hash()) {
				p.server.BroadcastBlock(block)
			}
		}
		return nil

	case MsgNewTransactions:
		var txs TransactionsPayload
		if err := decodePayload(payload, &txs); err != nil {
			return err
		}
		decoded, err := decodeTransactions(txs.Transactions)
		if err != nil {
			return err
		}
		var fresh []*core.Transaction
		for _, tx := range decoded {
			p.seen.add(tx.Hash())
			if p.server.seen.add(tx.Hash()) {
				fresh = append(fresh, tx)
			}
		}
		if len(fresh) > 0 {
			backend.HandleTransactions(fresh)
			p.server.BroadcastTransactions(fresh)
		}
		return nil

	case MsgGetBlocks:
		var request GetBlocks
		if err := decodePayload(payload, &request); err != nil {
			return err
		}
		count := request.Count
		if count > MaxBlocksPerRequest {
			count = MaxBlocksPerRequest
		}
		var blocks []*core.Block
		for i := uint64(0); i < count; i++ {
			block := backend.BlockByNumber(request.From + i)
			if block == nil {
				break
			}
			blocks = append(blocks, block)
		}
		if len(blocks) == 0 {
			return nil
		}
		encoded, err := encodeBlocks(blocks)
		if err != nil {
			return err
		}
		return p.Send(MsgBlocks, &BlocksPayload{Blocks: encoded})

	case MsgGetBlockByHash:
		var request GetBlockByHash
		if err := decodePayload(payload, &request); err != nil {
			return err
		}
		block := backend.BlockByHash(request.Hash)
		if block == nil {
			return nil
		}
		encoded, err := encodeBlocks([]*core.Block{block})
		if err != nil {
			return err
		}
		return p.Send(MsgBlocks, &BlocksPayload{Blocks: encoded})

	case MsgAttestations:
		var votes AttestationsPayload
		if err := decodePayload(payload, &votes); err != nil {
			return err
		}
		if len(votes.Attestations) > MaxAttestationsPerMessage {
			return fmt.Errorf("p2p: %d attestations exceeds the per-message limit", len(votes.Attestations))
		}
		var fresh []*core.Attestation
		for _, a := range votes.Attestations {
			p.seen.add(a.Hash())
			if p.server.seen.add(a.Hash()) {
				fresh = append(fresh, a)
			}
		}
		if len(fresh) > 0 {
			backend.HandleAttestations(fresh)
			p.server.BroadcastAttestations(fresh)
		}
		return nil

	case MsgEvidence:
		var proofs EvidencePayload
		if err := decodePayload(payload, &proofs); err != nil {
			return err
		}
		if len(proofs.Evidence) > 0 {
			backend.HandleEvidence(proofs.Evidence)
		}
		return nil

	case MsgDisconnect:
		var reason DisconnectReason
		decodePayload(payload, &reason)
		p.server.log.Info("peer disconnecting", "id", p.ID(), "reason", reason.Reason)
		return fmt.Errorf("p2p: peer disconnected: %s", reason.Reason)

	default:
		// Unknown codes are ignored so the protocol can be extended without
		// breaking older nodes.
		return nil
	}
}
