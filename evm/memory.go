package evm

import (
	"sync"

	"layer1/uint256"
)

// Memory is the contract's linear byte-addressed scratch space. It grows in
// 32-byte words and is zero-filled; growth is charged for quadratically, which
// is what keeps a contract from cheaply allocating gigabytes.
type Memory struct {
	store       []byte
	lastGasCost uint64
}

var memoryPool = sync.Pool{
	New: func() any { return &Memory{store: make([]byte, 0, 1024)} },
}

func newMemory() *Memory {
	m := memoryPool.Get().(*Memory)
	m.store = m.store[:0]
	m.lastGasCost = 0
	return m
}

func returnMemory(m *Memory) {
	m.store = m.store[:0]
	m.lastGasCost = 0
	memoryPool.Put(m)
}

// Len returns the current size in bytes.
func (m *Memory) Len() int { return len(m.store) }

// Data exposes the backing bytes. Used for tracing.
func (m *Memory) Data() []byte { return m.store }

// Resize grows memory to at least size bytes.
func (m *Memory) Resize(size uint64) {
	if uint64(len(m.store)) < size {
		m.store = append(m.store, make([]byte, size-uint64(len(m.store)))...)
	}
}

// Set writes value at offset. Memory must already be large enough.
func (m *Memory) Set(offset, size uint64, value []byte) {
	if size == 0 {
		return
	}
	copy(m.store[offset:offset+size], value)
}

// Set32 writes a 256-bit word at offset, left-padded with zeros.
func (m *Memory) Set32(offset uint64, value *uint256.Int) {
	b := value.Bytes32()
	copy(m.store[offset:offset+32], b[:])
}

// GetCopy returns a copy of size bytes at offset, zero-filled past the end.
func (m *Memory) GetCopy(offset, size uint64) []byte {
	if size == 0 {
		return nil
	}
	out := make([]byte, size)
	if offset < uint64(len(m.store)) {
		copy(out, m.store[offset:min64(offset+size, uint64(len(m.store)))])
	}
	return out
}

// GetPtr returns a slice aliasing memory at offset. The caller must not retain
// it across a resize.
func (m *Memory) GetPtr(offset, size uint64) []byte {
	if size == 0 || offset >= uint64(len(m.store)) {
		return nil
	}
	return m.store[offset:min64(offset+size, uint64(len(m.store)))]
}

func min64(a, b uint64) uint64 {
	if a < b {
		return a
	}
	return b
}

// toWordSize returns the number of 32-byte words needed to hold size bytes.
func toWordSize(size uint64) uint64 {
	if size > ^uint64(0)-31 {
		// Saturate rather than wrap: the caller charges gas from this and a
		// wrapped value would under-charge catastrophically.
		return ^uint64(0)/32 + 1
	}
	return (size + 31) / 32
}
