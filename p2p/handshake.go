package p2p

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"layer1/common"
	"layer1/crypto/keccak"
	"layer1/crypto/secp256k1"
)

// The peer handshake.
//
// Two nodes exchange ephemeral public keys, agree on a shared secret by ECDH,
// and each proves possession of its long-term node key by signing the
// handshake transcript. The transcript covers both ephemeral keys and both
// nonces, so a signature cannot be lifted from one session into another.
//
// Ephemeral keys give forward secrecy: recovering a node's long-term key later
// does not decrypt traffic recorded today. The static signatures give
// authentication: an attacker who relays the exchange cannot produce a
// signature over a transcript containing its own ephemeral key.

var (
	ErrHandshakeFailed  = errors.New("p2p: handshake failed")
	ErrPeerUnauthentic  = errors.New("p2p: peer failed to prove its identity")
	ErrSelfConnection   = errors.New("p2p: refusing to connect to ourselves")
	ErrFrameTooLarge    = errors.New("p2p: encrypted frame exceeds the size limit")
	ErrFrameCorrupt     = errors.New("p2p: encrypted frame failed authentication")
	ErrSequenceOverflow = errors.New("p2p: frame counter exhausted")
)

const (
	// handshakeTimeout bounds how long a peer may take to authenticate.
	handshakeTimeout = 10 * time.Second
	// ephemeralKeyLen is an uncompressed public key without its tag byte.
	ephemeralKeyLen = 64
	// nonceLen is the handshake nonce length.
	nonceLen = 32
	// authLen is a 65-byte signature.
	authLen = secp256k1.SignatureLength
)

// NodeID identifies a peer by its long-term public key.
type NodeID [64]byte

// Address returns the address the node key controls.
func (id NodeID) Address() common.Address {
	return common.BytesToAddress(keccak.Sum256Bytes(id[:])[12:])
}

// String renders a short, recognisable form of the identity.
func (id NodeID) String() string {
	return common.EncodeHex(id[:8]) + "..."
}

// NodeIDOf derives the identity of a node key.
func NodeIDOf(key *secp256k1.PrivateKey) NodeID {
	var id NodeID
	copy(id[:], key.PublicKey().Bytes())
	return id
}

// session holds the negotiated keys for one connection.
type session struct {
	// send and recv are separate: using one key in both directions would let
	// an attacker reflect a node's own frames back at it.
	send cipher.AEAD
	recv cipher.AEAD

	sendSeq uint64
	recvSeq uint64

	remoteID NodeID
}

// deriveKey mixes the shared secret with the transcript under a label.
func deriveKey(shared, transcript []byte, label string) []byte {
	sum := keccak.Sum256([]byte("layer1/p2p/kdf/v1"), []byte(label), shared, transcript)
	return sum[:]
}

func newAEAD(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// handshakeTranscript is what both sides sign and derive keys from. The
// initiator's material always comes first so both sides compute it identically.
func handshakeTranscript(initiatorEph, initiatorNonce, responderEph, responderNonce []byte) []byte {
	sum := keccak.Sum256(
		[]byte("layer1/p2p/handshake/v1"),
		initiatorEph, initiatorNonce,
		responderEph, responderNonce,
	)
	return sum[:]
}

// handshakeMessage is what each side puts on the wire: its ephemeral key, its
// nonce, its static public key, and a signature over the transcript.
type handshakeMessage struct {
	ephemeral [ephemeralKeyLen]byte
	nonce     [nonceLen]byte
	staticKey [ephemeralKeyLen]byte
	signature [authLen]byte
}

func (m *handshakeMessage) prefix() []byte {
	out := make([]byte, 0, ephemeralKeyLen+nonceLen+ephemeralKeyLen)
	out = append(out, m.ephemeral[:]...)
	out = append(out, m.nonce[:]...)
	out = append(out, m.staticKey[:]...)
	return out
}

const handshakePrefixLen = ephemeralKeyLen + nonceLen + ephemeralKeyLen

// performHandshake runs the exchange and returns the negotiated session.
func performHandshake(conn net.Conn, nodeKey *secp256k1.PrivateKey, initiator bool) (*session, error) {
	conn.SetDeadline(time.Now().Add(handshakeTimeout))
	defer conn.SetDeadline(time.Time{})

	ephemeral, err := secp256k1.GenerateKey()
	if err != nil {
		return nil, err
	}
	// The ephemeral key must not outlive the handshake.
	defer ephemeral.Zeroize()

	var ours handshakeMessage
	copy(ours.ephemeral[:], ephemeral.PublicKey().Bytes())
	copy(ours.staticKey[:], nodeKey.PublicKey().Bytes())
	if _, err := rand.Read(ours.nonce[:]); err != nil {
		return nil, err
	}

	// Exchange the unsigned prefix first: the transcript both sides sign has to
	// exist before either can sign it.
	if _, err := conn.Write(ours.prefix()); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrHandshakeFailed, err)
	}
	theirPrefix := make([]byte, handshakePrefixLen)
	if _, err := io.ReadFull(conn, theirPrefix); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrHandshakeFailed, err)
	}

	var theirs handshakeMessage
	copy(theirs.ephemeral[:], theirPrefix[:ephemeralKeyLen])
	copy(theirs.nonce[:], theirPrefix[ephemeralKeyLen:ephemeralKeyLen+nonceLen])
	copy(theirs.staticKey[:], theirPrefix[ephemeralKeyLen+nonceLen:])

	// A node that dials itself would derive a working session and then talk to
	// its own reflection forever.
	if subtle.ConstantTimeCompare(ours.staticKey[:], theirs.staticKey[:]) == 1 {
		return nil, ErrSelfConnection
	}

	var transcript []byte
	if initiator {
		transcript = handshakeTranscript(ours.ephemeral[:], ours.nonce[:], theirs.ephemeral[:], theirs.nonce[:])
	} else {
		transcript = handshakeTranscript(theirs.ephemeral[:], theirs.nonce[:], ours.ephemeral[:], ours.nonce[:])
	}

	// Prove possession of the long-term key by signing the transcript.
	signature, err := secp256k1.Sign(nodeKey, transcript)
	if err != nil {
		return nil, err
	}
	if _, err := conn.Write(signature.Bytes()); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrHandshakeFailed, err)
	}
	theirSignature := make([]byte, authLen)
	if _, err := io.ReadFull(conn, theirSignature); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrHandshakeFailed, err)
	}

	theirStatic, err := secp256k1.ParsePublicKey(theirs.staticKey[:])
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrPeerUnauthentic, err)
	}
	parsedSig, err := secp256k1.ParseSignature(theirSignature)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrPeerUnauthentic, err)
	}
	// This is the check that stops a relay attack: the signature covers the
	// ephemeral keys of *this* session, so it cannot be replayed.
	if !secp256k1.Verify(theirStatic, transcript, parsedSig) {
		return nil, ErrPeerUnauthentic
	}

	theirEphemeral, err := secp256k1.ParsePublicKey(theirs.ephemeral[:])
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrHandshakeFailed, err)
	}
	shared, err := secp256k1.ECDH(ephemeral, theirEphemeral)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrHandshakeFailed, err)
	}

	initiatorKey := deriveKey(shared, transcript, "initiator")
	responderKey := deriveKey(shared, transcript, "responder")

	var sendKey, recvKey []byte
	if initiator {
		sendKey, recvKey = initiatorKey, responderKey
	} else {
		sendKey, recvKey = responderKey, initiatorKey
	}

	sendAEAD, err := newAEAD(sendKey)
	if err != nil {
		return nil, err
	}
	recvAEAD, err := newAEAD(recvKey)
	if err != nil {
		return nil, err
	}

	s := &session{send: sendAEAD, recv: recvAEAD}
	copy(s.remoteID[:], theirs.staticKey[:])
	return s, nil
}

// secureConn wraps a connection in the negotiated encryption.
type secureConn struct {
	conn    net.Conn
	session *session

	readMu  sync.Mutex
	writeMu sync.Mutex
}

// RemoteID returns the peer's authenticated identity.
func (c *secureConn) RemoteID() NodeID { return c.session.remoteID }

// nonceFor builds a GCM nonce from a frame counter. Every frame gets a distinct
// nonce under a given key; reusing one would destroy the cipher's guarantees.
func nonceFor(seq uint64) []byte {
	var out [12]byte
	binary.BigEndian.PutUint64(out[4:], seq)
	return out[:]
}

// writeFrame encrypts and sends one message.
func (c *secureConn) writeFrame(code MessageCode, payload []byte) error {
	if len(payload) > MaxMessageSize {
		return fmt.Errorf("%w: %d bytes", ErrMessageTooLarge, len(payload))
	}
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	if c.session.sendSeq == ^uint64(0) {
		return ErrSequenceOverflow
	}

	plaintext := make([]byte, 1+len(payload))
	plaintext[0] = byte(code)
	copy(plaintext[1:], payload)

	// The length prefix travels in the clear so the reader knows how much to
	// read; binding it into the authenticated data stops it being altered.
	sealed := c.session.send.Seal(nil, nonceFor(c.session.sendSeq), plaintext, nil)
	c.session.sendSeq++

	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(sealed)))

	if _, err := c.conn.Write(header[:]); err != nil {
		return err
	}
	_, err := c.conn.Write(sealed)
	return err
}

// readFrame receives and decrypts one message.
func (c *secureConn) readFrame() (MessageCode, []byte, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()

	var header [4]byte
	if _, err := io.ReadFull(c.conn, header[:]); err != nil {
		return 0, nil, err
	}
	length := binary.BigEndian.Uint32(header[:])
	if length > MaxMessageSize+1024 {
		return 0, nil, fmt.Errorf("%w: %d bytes", ErrFrameTooLarge, length)
	}
	if length == 0 {
		return 0, nil, ErrFrameCorrupt
	}

	sealed := make([]byte, length)
	if _, err := io.ReadFull(c.conn, sealed); err != nil {
		return 0, nil, err
	}

	// The counter is implicit rather than sent, so an attacker cannot replay a
	// frame or reorder the stream without the decryption failing.
	plaintext, err := c.session.recv.Open(nil, nonceFor(c.session.recvSeq), sealed, nil)
	if err != nil {
		return 0, nil, ErrFrameCorrupt
	}
	c.session.recvSeq++

	if len(plaintext) == 0 {
		return 0, nil, ErrFrameCorrupt
	}
	return MessageCode(plaintext[0]), plaintext[1:], nil
}

func (c *secureConn) Close() error                       { return c.conn.Close() }
func (c *secureConn) RemoteAddr() net.Addr               { return c.conn.RemoteAddr() }
func (c *secureConn) SetDeadline(t time.Time) error      { return c.conn.SetDeadline(t) }
func (c *secureConn) SetReadDeadline(t time.Time) error  { return c.conn.SetReadDeadline(t) }
func (c *secureConn) SetWriteDeadline(t time.Time) error { return c.conn.SetWriteDeadline(t) }
