// Package p2p connects nodes to each other: block and transaction gossip over
// plain TCP with length-prefixed, RLP-encoded messages.
package p2p

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/big"

	"layer1/common"
	"layer1/core"
	"layer1/rlp"
)

// ProtocolVersion is bumped whenever the wire format changes incompatibly.
const ProtocolVersion = 1

// MessageCode identifies a message type.
type MessageCode uint8

const (
	MsgStatus MessageCode = iota
	MsgPing
	MsgPong
	MsgNewBlock
	MsgNewTransactions
	MsgGetBlocks
	MsgBlocks
	MsgGetBlockByHash
	MsgDisconnect
	MsgAttestations
	MsgEvidence
	MsgGetAddresses
	MsgAddresses
	MsgGetSnapshot
	MsgSnapshot
	MsgGetStateNodes
	MsgStateNodes
)

var messageNames = map[MessageCode]string{
	MsgStatus:          "status",
	MsgPing:            "ping",
	MsgPong:            "pong",
	MsgNewBlock:        "newBlock",
	MsgNewTransactions: "newTransactions",
	MsgGetBlocks:       "getBlocks",
	MsgBlocks:          "blocks",
	MsgGetBlockByHash:  "getBlockByHash",
	MsgDisconnect:      "disconnect",
	MsgAttestations:    "attestations",
	MsgEvidence:        "evidence",
	MsgGetAddresses:    "getAddresses",
	MsgAddresses:       "addresses",
	MsgGetSnapshot:     "getSnapshot",
	MsgSnapshot:        "snapshot",
	MsgGetStateNodes:   "getStateNodes",
	MsgStateNodes:      "stateNodes",
}

func (c MessageCode) String() string {
	if name, ok := messageNames[c]; ok {
		return name
	}
	return fmt.Sprintf("unknown(%d)", uint8(c))
}

// MaxMessageSize caps a single message, so one peer cannot exhaust memory.
const MaxMessageSize = 16 * 1024 * 1024

var (
	ErrMessageTooLarge  = errors.New("p2p: message exceeds the size limit")
	ErrProtocolMismatch = errors.New("p2p: peer speaks a different protocol version")
	ErrGenesisMismatch  = errors.New("p2p: peer is on a different chain")
	ErrHandshakeTimeout = errors.New("p2p: handshake timed out")
)

// Status is exchanged on connect, before anything else. It is what stops two
// nodes on different chains from gossiping incompatible blocks at each other.
type Status struct {
	Version    uint64
	NetworkID  *big.Int
	Genesis    common.Hash
	Head       common.Hash
	HeadNumber uint64
	ListenPort uint64
	NodeName   string
}

// GetBlocks requests a run of blocks by height.
type GetBlocks struct {
	From  uint64
	Count uint64
}

// BlocksPayload carries encoded blocks.
type BlocksPayload struct {
	Blocks [][]byte
}

// TransactionsPayload carries encoded transactions.
type TransactionsPayload struct {
	Transactions [][]byte
}

// GetBlockByHash requests a specific block.
type GetBlockByHash struct {
	Hash common.Hash
}

// DisconnectReason explains why a peer is being dropped.
type DisconnectReason struct {
	Reason string
}

// AttestationsPayload carries validator votes.
type AttestationsPayload struct {
	Attestations []*core.Attestation
}

// EvidencePayload carries proof that a validator equivocated.
type EvidencePayload struct {
	Evidence []*core.Equivocation
}

// SnapshotPayload offers a finalized block together with the certificate that
// proves it final. The certificate is what lets the receiver trust the state
// root without executing a single block.
type SnapshotPayload struct {
	Block       []byte
	Certificate []byte
}

// StateNodesRequest asks for state blobs by hash.
type StateNodesRequest struct {
	Hashes []common.Hash
}

// StateNodesPayload carries state blobs. They are self-verifying: the receiver
// checks each against the hash it asked for.
type StateNodesPayload struct {
	Nodes [][]byte
}

// MaxStateNodesPerMessage bounds a state response.
const MaxStateNodesPerMessage = 256

// MaxAttestationsPerMessage bounds a single votes message.
const MaxAttestationsPerMessage = 512

// MaxBlocksPerRequest bounds how many blocks one request may ask for.
const MaxBlocksPerRequest = 128

// writeMessage frames a message: one code byte, a four-byte big-endian length,
// then the payload.
func writeMessage(w io.Writer, code MessageCode, payload []byte) error {
	if len(payload) > MaxMessageSize {
		return fmt.Errorf("%w: %d bytes", ErrMessageTooLarge, len(payload))
	}
	var header [5]byte
	header[0] = byte(code)
	binary.BigEndian.PutUint32(header[1:], uint32(len(payload)))

	if _, err := w.Write(header[:]); err != nil {
		return err
	}
	if len(payload) == 0 {
		return nil
	}
	_, err := w.Write(payload)
	return err
}

// readMessage reads one framed message.
func readMessage(r io.Reader) (MessageCode, []byte, error) {
	var header [5]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return 0, nil, err
	}
	code := MessageCode(header[0])
	length := binary.BigEndian.Uint32(header[1:])
	if length > MaxMessageSize {
		return 0, nil, fmt.Errorf("%w: %d bytes", ErrMessageTooLarge, length)
	}
	if length == 0 {
		return code, nil, nil
	}
	payload := make([]byte, length)
	if _, err := io.ReadFull(r, payload); err != nil {
		return 0, nil, err
	}
	return code, payload, nil
}

// encodeBlocks renders blocks for the wire.
func encodeBlocks(blocks []*core.Block) ([][]byte, error) {
	out := make([][]byte, 0, len(blocks))
	for _, block := range blocks {
		enc, err := block.MarshalBinary()
		if err != nil {
			return nil, err
		}
		out = append(out, enc)
	}
	return out, nil
}

// decodeBlocks parses blocks from the wire.
func decodeBlocks(encoded [][]byte) ([]*core.Block, error) {
	out := make([]*core.Block, 0, len(encoded))
	for i, enc := range encoded {
		block := new(core.Block)
		if err := block.UnmarshalBinary(enc); err != nil {
			return nil, fmt.Errorf("p2p: block %d: %w", i, err)
		}
		out = append(out, block)
	}
	return out, nil
}

func encodeTransactions(txs []*core.Transaction) ([][]byte, error) {
	out := make([][]byte, 0, len(txs))
	for _, tx := range txs {
		enc, err := tx.MarshalBinary()
		if err != nil {
			return nil, err
		}
		out = append(out, enc)
	}
	return out, nil
}

func decodeTransactions(encoded [][]byte) ([]*core.Transaction, error) {
	out := make([]*core.Transaction, 0, len(encoded))
	for i, enc := range encoded {
		tx := new(core.Transaction)
		if err := tx.UnmarshalBinary(enc); err != nil {
			return nil, fmt.Errorf("p2p: transaction %d: %w", i, err)
		}
		out = append(out, tx)
	}
	return out, nil
}

func encodePayload(v any) ([]byte, error) { return rlp.Encode(v) }

func decodePayload(data []byte, v any) error { return rlp.Decode(data, v) }
