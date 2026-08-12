package evm

import (
	"fmt"
	"sync"

	"layer1/uint256"
)

// StackLimit is the maximum depth of the EVM operand stack.
const StackLimit = 1024

// Stack is the EVM's operand stack. Values are 256-bit words; the top of the
// stack is the end of the slice.
type Stack struct {
	data []uint256.Int
}

var stackPool = sync.Pool{
	New: func() any { return &Stack{data: make([]uint256.Int, 0, 32)} },
}

func newStack() *Stack {
	s := stackPool.Get().(*Stack)
	s.data = s.data[:0]
	return s
}

func returnStack(s *Stack) {
	s.data = s.data[:0]
	stackPool.Put(s)
}

// Len returns the number of items on the stack.
func (s *Stack) Len() int { return len(s.data) }

// Data exposes the raw stack contents, bottom first. Used for tracing.
func (s *Stack) Data() []uint256.Int { return s.data }

// push adds a value to the top.
func (s *Stack) push(v *uint256.Int) {
	s.data = append(s.data, *v)
}

// pop removes and returns the top value.
func (s *Stack) pop() uint256.Int {
	top := s.data[len(s.data)-1]
	s.data = s.data[:len(s.data)-1]
	return top
}

// peek returns a pointer to the top value, which callers may modify in place.
func (s *Stack) peek() *uint256.Int { return &s.data[len(s.data)-1] }

// back returns a pointer to the n-th value from the top (0 is the top).
func (s *Stack) back(n int) *uint256.Int { return &s.data[len(s.data)-n-1] }

// swap exchanges the top with the n-th value below it.
func (s *Stack) swap(n int) {
	top := len(s.data) - 1
	s.data[top], s.data[top-n] = s.data[top-n], s.data[top]
}

// dup pushes a copy of the n-th value from the top (1 is the top).
func (s *Stack) dup(n int) {
	v := s.data[len(s.data)-n]
	s.data = append(s.data, v)
}

// require checks that at least n values are available.
func (s *Stack) require(n int) error {
	if len(s.data) < n {
		return fmt.Errorf("%w: need %d values, have %d", ErrStackUnderflow, n, len(s.data))
	}
	return nil
}

// checkLimits verifies an instruction's stack effect fits within the limit.
func (s *Stack) checkLimits(pops, pushes int) error {
	if len(s.data) < pops {
		return fmt.Errorf("%w: need %d values, have %d", ErrStackUnderflow, pops, len(s.data))
	}
	if len(s.data)-pops+pushes > StackLimit {
		return fmt.Errorf("%w: %d values exceeds the limit of %d", ErrStackOverflow, len(s.data)-pops+pushes, StackLimit)
	}
	return nil
}
