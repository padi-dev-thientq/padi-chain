package evm

import (
	"errors"
	"math/big"
	"testing"

	"layer1/common"
	"layer1/db"
	"layer1/state"
	"layer1/uint256"
)

var (
	sender   = common.MustHexToAddress("0x1111111111111111111111111111111111111111")
	contract = common.MustHexToAddress("0x2222222222222222222222222222222222222222")
	chainID  = big.NewInt(1337)
)

// newTestEVM builds an EVM over fresh state, with the sender pre-funded.
func newTestEVM(t *testing.T) (*EVM, *state.StateDB) {
	t.Helper()
	sdb, err := state.New(common.Hash{}, db.NewMemoryDB())
	if err != nil {
		t.Fatal(err)
	}
	sdb.AddBalance(sender, new(big.Int).Lsh(big.NewInt(1), 64))

	blockCtx := BlockContext{
		CanTransfer: CanTransfer,
		Transfer:    Transfer,
		GetHash:     func(n uint64) common.Hash { return common.Keccak256([]byte{byte(n)}) },
		Coinbase:    common.Address{9},
		GasLimit:    30_000_000,
		BlockNumber: big.NewInt(100),
		Time:        1700000000,
		BaseFee:     big.NewInt(1_000_000_000),
		Random:      common.Keccak256([]byte("randao")),
	}
	txCtx := TxContext{Origin: sender, GasPrice: big.NewInt(2_000_000_000)}
	return NewEVM(blockCtx, txCtx, sdb, &ChainConfig{ChainID: chainID}, Config{}), sdb
}

// run deploys code at the contract address and calls it.
func run(t *testing.T, code []byte, input []byte, gas uint64) ([]byte, uint64, error, *state.StateDB) {
	t.Helper()
	evm, sdb := newTestEVM(t)
	sdb.CreateAccount(contract)
	sdb.SetCode(contract, code)
	ret, left, err := evm.Call(AccountRef(sender), contract, input, gas, new(big.Int))
	return ret, left, err, sdb
}

// asm assembles a byte sequence from opcodes and raw bytes.
func asm(parts ...any) []byte {
	var out []byte
	for _, p := range parts {
		switch v := p.(type) {
		case OpCode:
			out = append(out, byte(v))
		case byte:
			out = append(out, v)
		case int:
			out = append(out, byte(v))
		case []byte:
			out = append(out, v...)
		default:
			panic("asm: unsupported operand")
		}
	}
	return out
}

// push32 emits a PUSH32 of v.
func push32(v *big.Int) []byte {
	word := uint256.FromBig(v).Bytes32()
	return append([]byte{byte(PUSH32)}, word[:]...)
}

// returnTop stores the top stack word at memory 0 and returns it.
func returnTop() []byte {
	return asm(PUSH1, 0, MSTORE, PUSH1, 32, PUSH1, 0, RETURN)
}

func expectWord(t *testing.T, ret []byte, want *big.Int) {
	t.Helper()
	if len(ret) != 32 {
		t.Fatalf("returned %d bytes, want 32: %x", len(ret), ret)
	}
	got := new(big.Int).SetBytes(ret)
	if got.Cmp(want) != 0 {
		t.Fatalf("returned %s, want %s", got, want)
	}
}

func TestArithmetic(t *testing.T) {
	cases := []struct {
		name string
		code []byte
		want *big.Int
	}{
		{"add", asm(PUSH1, 3, PUSH1, 5, ADD, returnTop()), big.NewInt(8)},
		{"sub", asm(PUSH1, 3, PUSH1, 5, SUB, returnTop()), big.NewInt(2)},
		{"mul", asm(PUSH1, 3, PUSH1, 5, MUL, returnTop()), big.NewInt(15)},
		{"div", asm(PUSH1, 3, PUSH1, 15, DIV, returnTop()), big.NewInt(5)},
		{"div by zero", asm(PUSH1, 0, PUSH1, 15, DIV, returnTop()), big.NewInt(0)},
		{"mod", asm(PUSH1, 4, PUSH1, 15, MOD, returnTop()), big.NewInt(3)},
		{"exp", asm(PUSH1, 8, PUSH1, 2, EXP, returnTop()), big.NewInt(256)},
		{"addmod", asm(PUSH1, 7, PUSH1, 5, PUSH1, 10, ADDMOD, returnTop()), big.NewInt(1)},
		{"mulmod", asm(PUSH1, 7, PUSH1, 5, PUSH1, 10, MULMOD, returnTop()), big.NewInt(1)},
		{"lt", asm(PUSH1, 5, PUSH1, 3, LT, returnTop()), big.NewInt(1)},
		{"gt", asm(PUSH1, 5, PUSH1, 3, GT, returnTop()), big.NewInt(0)},
		{"eq", asm(PUSH1, 5, PUSH1, 5, EQ, returnTop()), big.NewInt(1)},
		{"iszero", asm(PUSH1, 0, ISZERO, returnTop()), big.NewInt(1)},
		{"and", asm(PUSH1, 0x0f, PUSH1, 0x3c, AND, returnTop()), big.NewInt(0x0c)},
		{"or", asm(PUSH1, 0x0f, PUSH1, 0x30, OR, returnTop()), big.NewInt(0x3f)},
		{"xor", asm(PUSH1, 0x0f, PUSH1, 0x3c, XOR, returnTop()), big.NewInt(0x33)},
		{"shl", asm(PUSH1, 1, PUSH1, 4, SHL, returnTop()), big.NewInt(16)},
		{"shr", asm(PUSH1, 16, PUSH1, 4, SHR, returnTop()), big.NewInt(1)},
		{"byte", asm(PUSH2, 0xab, 0xcd, PUSH1, 31, BYTE, returnTop()), big.NewInt(0xcd)},
		{"signextend positive", asm(PUSH1, 0x7f, PUSH1, 0, SIGNEXTEND, returnTop()), big.NewInt(0x7f)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ret, _, err, _ := run(t, c.code, nil, 100000)
			if err != nil {
				t.Fatal(err)
			}
			expectWord(t, ret, c.want)
		})
	}
}

func TestSignedArithmetic(t *testing.T) {
	minusOne := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 256), big.NewInt(1))

	// -1 SDIV 1 == -1
	code := asm(PUSH1, 1, push32(minusOne), SDIV, returnTop())
	ret, _, err, _ := run(t, code, nil, 100000)
	if err != nil {
		t.Fatal(err)
	}
	expectWord(t, ret, minusOne)

	// SIGNEXTEND of 0xff from byte 0 is -1.
	code = asm(PUSH1, 0xff, PUSH1, 0, SIGNEXTEND, returnTop())
	ret, _, err, _ = run(t, code, nil, 100000)
	if err != nil {
		t.Fatal(err)
	}
	expectWord(t, ret, minusOne)

	// SAR of -1 by any amount stays -1.
	code = asm(push32(minusOne), PUSH1, 8, SAR, returnTop())
	ret, _, err, _ = run(t, code, nil, 100000)
	if err != nil {
		t.Fatal(err)
	}
	expectWord(t, ret, minusOne)

	// SLT: -1 < 1 as signed, but not as unsigned.
	code = asm(PUSH1, 1, push32(minusOne), SLT, returnTop())
	ret, _, err, _ = run(t, code, nil, 100000)
	if err != nil {
		t.Fatal(err)
	}
	expectWord(t, ret, big.NewInt(1))

	code = asm(PUSH1, 1, push32(minusOne), LT, returnTop())
	ret, _, err, _ = run(t, code, nil, 100000)
	if err != nil {
		t.Fatal(err)
	}
	expectWord(t, ret, big.NewInt(0))
}

func TestKeccak256Opcode(t *testing.T) {
	// Hash the empty string.
	code := asm(PUSH1, 0, PUSH1, 0, KECCAK256, returnTop())
	ret, _, err, _ := run(t, code, nil, 100000)
	if err != nil {
		t.Fatal(err)
	}
	want := common.Keccak256(nil)
	if string(ret) != string(want[:]) {
		t.Fatalf("keccak256('') = %x, want %x", ret, want)
	}
}

func TestMemory(t *testing.T) {
	// Store a value, read it back from a different path.
	code := asm(
		PUSH1, 0x42, PUSH1, 0, MSTORE,
		PUSH1, 0, MLOAD,
		returnTop(),
	)
	ret, _, err, _ := run(t, code, nil, 100000)
	if err != nil {
		t.Fatal(err)
	}
	expectWord(t, ret, big.NewInt(0x42))

	// MSTORE8 writes a single byte at the top of the word.
	code = asm(PUSH1, 0xff, PUSH1, 0, MSTORE8, PUSH1, 0, MLOAD, returnTop())
	ret, _, err, _ = run(t, code, nil, 100000)
	if err != nil {
		t.Fatal(err)
	}
	if ret[0] != 0xff || ret[1] != 0 {
		t.Fatalf("MSTORE8 wrote %x", ret[:2])
	}

	// MSIZE reflects the highest word touched.
	code = asm(PUSH1, 1, PUSH1, 0x40, MSTORE, MSIZE, returnTop())
	ret, _, err, _ = run(t, code, nil, 100000)
	if err != nil {
		t.Fatal(err)
	}
	expectWord(t, ret, big.NewInt(0x60))
}

func TestMemoryCopyOverlapping(t *testing.T) {
	// MCOPY must behave like memmove for overlapping ranges.
	code := asm(
		PUSH1, 0xaa, PUSH1, 0, MSTORE8,
		PUSH1, 0xbb, PUSH1, 1, MSTORE8,
		PUSH1, 2, PUSH1, 0, PUSH1, 1, MCOPY, // copy 2 bytes from 0 to 1
		PUSH1, 0, MLOAD, returnTop(),
	)
	ret, _, err, _ := run(t, code, nil, 100000)
	if err != nil {
		t.Fatal(err)
	}
	if ret[0] != 0xaa || ret[1] != 0xaa || ret[2] != 0xbb {
		t.Fatalf("MCOPY of overlapping ranges gave %x", ret[:3])
	}
}

func TestStorage(t *testing.T) {
	code := asm(
		PUSH1, 0x99, PUSH1, 1, SSTORE,
		PUSH1, 1, SLOAD,
		returnTop(),
	)
	ret, _, err, sdb := run(t, code, nil, 100000)
	if err != nil {
		t.Fatal(err)
	}
	expectWord(t, ret, big.NewInt(0x99))
	if got := sdb.GetState(contract, common.BytesToHash([]byte{1})); got != common.BytesToHash([]byte{0x99}) {
		t.Fatalf("state after SSTORE = %s", got)
	}
}

func TestTransientStorageOpcodes(t *testing.T) {
	code := asm(
		PUSH1, 0x77, PUSH1, 5, TSTORE,
		PUSH1, 5, TLOAD,
		returnTop(),
	)
	ret, _, err, sdb := run(t, code, nil, 100000)
	if err != nil {
		t.Fatal(err)
	}
	expectWord(t, ret, big.NewInt(0x77))
	// Transient storage must never reach persistent storage.
	if got := sdb.GetState(contract, common.BytesToHash([]byte{5})); got != (common.Hash{}) {
		t.Fatalf("TSTORE leaked into persistent storage: %s", got)
	}
}

func TestJumps(t *testing.T) {
	// Jump over an INVALID and return 1.
	code := asm(
		PUSH1, 6, JUMP,
		INVALID,
		JUMPDEST, // offset 4? recompute below
		PUSH1, 1, returnTop(),
	)
	_ = code
	// Build precisely: PUSH1 <dest> JUMP INVALID JUMPDEST PUSH1 1 ...
	prog := []byte{byte(PUSH1), 5, byte(JUMP), byte(INVALID), 0x00, byte(JUMPDEST)}
	prog = append(prog, asm(PUSH1, 1, returnTop())...)
	ret, _, err, _ := run(t, prog, nil, 100000)
	if err != nil {
		t.Fatalf("valid jump failed: %v", err)
	}
	expectWord(t, ret, big.NewInt(1))
}

func TestInvalidJumpDestination(t *testing.T) {
	// Jumping to a non-JUMPDEST byte must fail.
	code := asm(PUSH1, 3, JUMP, STOP, PUSH1, 1, STOP)
	if _, _, err, _ := run(t, code, nil, 100000); !errors.Is(err, ErrInvalidJump) {
		t.Fatalf("got %v, want ErrInvalidJump", err)
	}

	// A 0x5b byte inside push data is data, not a valid destination.
	code = asm(PUSH1, 4, JUMP, PUSH1, byte(JUMPDEST), STOP)
	if _, _, err, _ := run(t, code, nil, 100000); !errors.Is(err, ErrInvalidJump) {
		t.Fatal("a JUMPDEST byte inside push data must not be jumpable")
	}
}

func TestConditionalJump(t *testing.T) {
	// JUMPI with a zero condition falls through.
	prog := []byte{
		byte(PUSH1), 0, // condition
		byte(PUSH1), 9, // destination
		byte(JUMPI),
		byte(PUSH1), 7, // taken when the jump is not
	}
	prog = append(prog, returnTop()...)
	ret, _, err, _ := run(t, prog, nil, 100000)
	if err != nil {
		t.Fatal(err)
	}
	expectWord(t, ret, big.NewInt(7))
}

func TestLoop(t *testing.T) {
	// Sum 1..10 with a counted loop. The stack holds [acc, i] with the
	// counter on top; the loop exits when the counter reaches zero.
	const loopHead = 4
	const exit = 22
	prog := []byte{
		byte(PUSH1), 0, // 0: acc = 0
		byte(PUSH1), 10, // 2: i = 10
		byte(JUMPDEST),    // 4: loop head
		byte(DUP1),        // 5: i i acc
		byte(ISZERO),      // 6:
		byte(PUSH1), exit, // 7:
		byte(JUMPI),    // 9:
		byte(DUP1),     // 10: i i acc
		byte(DUP3),     // 11: acc i i acc
		byte(ADD),      // 12: (acc+i) i acc
		byte(SWAP2),    // 13: acc i (acc+i)
		byte(POP),      // 14: i (acc+i)
		byte(PUSH1), 1, // 15:
		byte(SWAP1),           // 17: i 1 acc
		byte(SUB),             // 18: (i-1) acc
		byte(PUSH1), loopHead, // 19:
		byte(JUMP),     // 21:
		byte(JUMPDEST), // 22: exit
		byte(POP),      // 23: drop the counter
	}
	prog = append(prog, returnTop()...)

	ret, _, err, _ := run(t, prog, nil, 1000000)
	if err != nil {
		t.Fatal(err)
	}
	expectWord(t, ret, big.NewInt(55))
}

func TestCallDataAccess(t *testing.T) {
	input := make([]byte, 64)
	input[31] = 0xaa
	input[63] = 0xbb

	// CALLDATASIZE
	ret, _, err, _ := run(t, asm(CALLDATASIZE, returnTop()), input, 100000)
	if err != nil {
		t.Fatal(err)
	}
	expectWord(t, ret, big.NewInt(64))

	// CALLDATALOAD at offset 32
	ret, _, err, _ = run(t, asm(PUSH1, 32, CALLDATALOAD, returnTop()), input, 100000)
	if err != nil {
		t.Fatal(err)
	}
	expectWord(t, ret, big.NewInt(0xbb))

	// Reading past the end is zero-padded rather than an error.
	ret, _, err, _ = run(t, asm(PUSH1, 100, CALLDATALOAD, returnTop()), input, 100000)
	if err != nil {
		t.Fatal(err)
	}
	expectWord(t, ret, big.NewInt(0))

	// CALLDATACOPY
	code := asm(PUSH1, 32, PUSH1, 0, PUSH1, 0, CALLDATACOPY, PUSH1, 32, PUSH1, 0, RETURN)
	ret, _, err, _ = run(t, code, input, 100000)
	if err != nil {
		t.Fatal(err)
	}
	expectWord(t, ret, big.NewInt(0xaa))
}

func TestEnvironmentOpcodes(t *testing.T) {
	cases := []struct {
		name string
		code []byte
		want *big.Int
	}{
		{"chainid", asm(CHAINID, returnTop()), chainID},
		{"number", asm(NUMBER, returnTop()), big.NewInt(100)},
		{"timestamp", asm(TIMESTAMP, returnTop()), big.NewInt(1700000000)},
		{"gaslimit", asm(GASLIMIT, returnTop()), big.NewInt(30_000_000)},
		{"basefee", asm(BASEFEE, returnTop()), big.NewInt(1_000_000_000)},
		{"gasprice", asm(GASPRICE, returnTop()), big.NewInt(2_000_000_000)},
		{"address", asm(ADDRESS, returnTop()), contract.Big()},
		{"caller", asm(CALLER, returnTop()), sender.Big()},
		{"origin", asm(ORIGIN, returnTop()), sender.Big()},
		{"callvalue", asm(CALLVALUE, returnTop()), big.NewInt(0)},
		{"codesize", asm(CODESIZE, returnTop()), nil}, // checked separately
	}
	for _, c := range cases {
		if c.want == nil {
			continue
		}
		t.Run(c.name, func(t *testing.T) {
			ret, _, err, _ := run(t, c.code, nil, 100000)
			if err != nil {
				t.Fatal(err)
			}
			expectWord(t, ret, c.want)
		})
	}
}

func TestBlockHash(t *testing.T) {
	// A recent block resolves; anything older than 256 blocks is zero.
	ret, _, err, _ := run(t, asm(PUSH1, 99, BLOCKHASH, returnTop()), nil, 100000)
	if err != nil {
		t.Fatal(err)
	}
	want := common.Keccak256([]byte{99})
	if string(ret) != string(want[:]) {
		t.Fatalf("BLOCKHASH(99) = %x, want %x", ret, want)
	}

	// The current block and the future are not addressable.
	ret, _, err, _ = run(t, asm(PUSH1, 100, BLOCKHASH, returnTop()), nil, 100000)
	if err != nil {
		t.Fatal(err)
	}
	expectWord(t, ret, big.NewInt(0))
}

func TestRevertReturnsDataAndGas(t *testing.T) {
	// REVERT with a message.
	code := asm(
		PUSH1, 0xde, PUSH1, 0, MSTORE,
		PUSH1, 32, PUSH1, 0, REVERT,
	)
	ret, left, err, _ := run(t, code, nil, 100000)
	if !errors.Is(err, ErrExecutionReverted) {
		t.Fatalf("got %v, want ErrExecutionReverted", err)
	}
	expectWord(t, ret, big.NewInt(0xde))
	if left == 0 {
		t.Fatal("a revert must return the unused gas")
	}
}

func TestRevertRollsBackState(t *testing.T) {
	code := asm(
		PUSH1, 0x11, PUSH1, 1, SSTORE,
		PUSH1, 0, PUSH1, 0, REVERT,
	)
	_, _, err, sdb := run(t, code, nil, 100000)
	if !errors.Is(err, ErrExecutionReverted) {
		t.Fatal(err)
	}
	if got := sdb.GetState(contract, common.BytesToHash([]byte{1})); got != (common.Hash{}) {
		t.Fatalf("a reverted SSTORE persisted: %s", got)
	}
}

func TestInvalidOpcodeConsumesAllGas(t *testing.T) {
	_, left, err, _ := run(t, asm(INVALID), nil, 100000)
	var invalidOp *ErrInvalidOpCode
	if !errors.As(err, &invalidOp) {
		t.Fatalf("got %v, want an invalid-opcode error", err)
	}
	if left != 0 {
		t.Fatalf("an invalid opcode must consume all gas, %d left", left)
	}
}

func TestOutOfGas(t *testing.T) {
	code := asm(PUSH1, 1, PUSH1, 1, ADD, STOP)
	if _, left, err, _ := run(t, code, nil, 5); !errors.Is(err, ErrOutOfGas) {
		t.Fatalf("got %v (%d gas left), want ErrOutOfGas", err, left)
	}
}

func TestStackUnderflowAndOverflow(t *testing.T) {
	if _, _, err, _ := run(t, asm(ADD), nil, 100000); !errors.Is(err, ErrStackUnderflow) {
		t.Fatalf("got %v, want ErrStackUnderflow", err)
	}
	// Push past the stack limit.
	var code []byte
	for i := 0; i <= StackLimit; i++ {
		code = append(code, byte(PUSH1), 1)
	}
	if _, _, err, _ := run(t, code, nil, 10_000_000); !errors.Is(err, ErrStackOverflow) {
		t.Fatalf("got %v, want ErrStackOverflow", err)
	}
}

func TestLogs(t *testing.T) {
	code := asm(
		PUSH1, 0xff, PUSH1, 0, MSTORE,
		PUSH1, 0xaa, // topic1
		PUSH1, 32, PUSH1, 0, // size, offset
		LOG1,
		STOP,
	)
	_, _, err, sdb := run(t, code, nil, 100000)
	if err != nil {
		t.Fatal(err)
	}
	logs := sdb.Logs()
	if len(logs) != 1 {
		t.Fatalf("emitted %d logs, want 1", len(logs))
	}
	if logs[0].Address != contract {
		t.Errorf("log address = %s", logs[0].Address)
	}
	if len(logs[0].Topics) != 1 || logs[0].Topics[0] != common.BytesToHash([]byte{0xaa}) {
		t.Errorf("log topics = %v", logs[0].Topics)
	}
	if len(logs[0].Data) != 32 || logs[0].Data[31] != 0xff {
		t.Errorf("log data = %x", logs[0].Data)
	}
}

func TestCallBetweenContracts(t *testing.T) {
	evm, sdb := newTestEVM(t)

	// The callee returns 0x2a.
	callee := common.MustHexToAddress("0x3333333333333333333333333333333333333333")
	sdb.CreateAccount(callee)
	sdb.SetCode(callee, asm(PUSH1, 0x2a, returnTop()))

	// The caller calls it and returns whatever came back.
	caller := asm(
		PUSH1, 32, PUSH1, 0, // retSize, retOffset
		PUSH1, 0, PUSH1, 0, // argsSize, argsOffset
		PUSH1, 0, // value
		push32(callee.Big()),
		PUSH2, 0xff, 0xff, // gas
		CALL,
		POP,
		PUSH1, 32, PUSH1, 0, RETURN,
	)
	sdb.CreateAccount(contract)
	sdb.SetCode(contract, caller)

	ret, _, err := evm.Call(AccountRef(sender), contract, nil, 1_000_000, new(big.Int))
	if err != nil {
		t.Fatal(err)
	}
	expectWord(t, ret, big.NewInt(0x2a))
}

func TestCallFailurePushesZero(t *testing.T) {
	evm, sdb := newTestEVM(t)

	// The callee always reverts.
	callee := common.MustHexToAddress("0x3333333333333333333333333333333333333333")
	sdb.CreateAccount(callee)
	sdb.SetCode(callee, asm(PUSH1, 0, PUSH1, 0, REVERT))

	caller := asm(
		PUSH1, 0, PUSH1, 0,
		PUSH1, 0, PUSH1, 0,
		PUSH1, 0,
		push32(callee.Big()),
		PUSH2, 0xff, 0xff,
		CALL,
		returnTop(), // the call's success flag
	)
	sdb.CreateAccount(contract)
	sdb.SetCode(contract, caller)

	ret, _, err := evm.Call(AccountRef(sender), contract, nil, 1_000_000, new(big.Int))
	if err != nil {
		t.Fatalf("the outer call must succeed even when the inner one reverts: %v", err)
	}
	expectWord(t, ret, big.NewInt(0))
}

func TestStaticCallForbidsStateChange(t *testing.T) {
	evm, sdb := newTestEVM(t)

	// The callee tries to write storage.
	callee := common.MustHexToAddress("0x3333333333333333333333333333333333333333")
	sdb.CreateAccount(callee)
	sdb.SetCode(callee, asm(PUSH1, 1, PUSH1, 1, SSTORE, STOP))

	caller := asm(
		PUSH1, 0, PUSH1, 0,
		PUSH1, 0, PUSH1, 0,
		push32(callee.Big()),
		PUSH2, 0xff, 0xff,
		STATICCALL,
		returnTop(),
	)
	sdb.CreateAccount(contract)
	sdb.SetCode(contract, caller)

	ret, _, err := evm.Call(AccountRef(sender), contract, nil, 1_000_000, new(big.Int))
	if err != nil {
		t.Fatal(err)
	}
	// The static call must have failed, so the flag is zero.
	expectWord(t, ret, big.NewInt(0))
	if got := sdb.GetState(callee, common.BytesToHash([]byte{1})); got != (common.Hash{}) {
		t.Fatalf("a static call modified state: %s", got)
	}
}

func TestDelegateCallKeepsContext(t *testing.T) {
	evm, sdb := newTestEVM(t)

	// The library writes to storage slot 1 and returns its own view of ADDRESS.
	library := common.MustHexToAddress("0x3333333333333333333333333333333333333333")
	sdb.CreateAccount(library)
	sdb.SetCode(library, asm(PUSH1, 0x55, PUSH1, 1, SSTORE, ADDRESS, returnTop()))

	caller := asm(
		PUSH1, 32, PUSH1, 0,
		PUSH1, 0, PUSH1, 0,
		push32(library.Big()),
		PUSH3, 0x0f, 0xff, 0xff,
		DELEGATECALL,
		POP,
		PUSH1, 32, PUSH1, 0, RETURN,
	)
	sdb.CreateAccount(contract)
	sdb.SetCode(contract, caller)

	ret, _, err := evm.Call(AccountRef(sender), contract, nil, 1_000_000, new(big.Int))
	if err != nil {
		t.Fatal(err)
	}
	// Inside a delegate call, ADDRESS is the caller's address.
	expectWord(t, ret, contract.Big())
	// And the write landed in the caller's storage, not the library's.
	if got := sdb.GetState(contract, common.BytesToHash([]byte{1})); got != common.BytesToHash([]byte{0x55}) {
		t.Fatalf("delegate call wrote to the wrong storage: caller slot = %s", got)
	}
	if got := sdb.GetState(library, common.BytesToHash([]byte{1})); got != (common.Hash{}) {
		t.Fatalf("delegate call wrote to the library's storage: %s", got)
	}
}

func TestValueTransferThroughCall(t *testing.T) {
	evm, sdb := newTestEVM(t)
	recipient := common.MustHexToAddress("0x4444444444444444444444444444444444444444")

	sdb.CreateAccount(contract)
	sdb.AddBalance(contract, big.NewInt(1000))
	sdb.SetCode(contract, asm(
		PUSH1, 0, PUSH1, 0,
		PUSH1, 0, PUSH1, 0,
		PUSH2, 0x01, 0xf4, // value: 500
		push32(recipient.Big()),
		PUSH2, 0xff, 0xff,
		CALL,
		returnTop(),
	))

	ret, _, err := evm.Call(AccountRef(sender), contract, nil, 1_000_000, new(big.Int))
	if err != nil {
		t.Fatal(err)
	}
	expectWord(t, ret, big.NewInt(1))
	if got := sdb.GetBalance(recipient); got.Cmp(big.NewInt(500)) != 0 {
		t.Fatalf("recipient balance = %s, want 500", got)
	}
	if got := sdb.GetBalance(contract); got.Cmp(big.NewInt(500)) != 0 {
		t.Fatalf("contract balance = %s, want 500", got)
	}
}

func TestCreateContract(t *testing.T) {
	evm, sdb := newTestEVM(t)

	// Init code that returns a one-byte runtime: STOP.
	runtime := []byte{byte(STOP)}
	initCode := asm(
		PUSH1, byte(len(runtime)), PUSH1, 12, PUSH1, 0, CODECOPY,
		PUSH1, byte(len(runtime)), PUSH1, 0, RETURN,
	)
	initCode = append(initCode, runtime...)

	ret, addr, _, err := evm.Create(AccountRef(sender), initCode, 1_000_000, new(big.Int))
	if err != nil {
		t.Fatalf("create failed: %v (returned %x)", err, ret)
	}
	if addr != CreateAddress(sender, 0) {
		t.Fatalf("deployed at %s, want %s", addr, CreateAddress(sender, 0))
	}
	if got := sdb.GetCode(addr); len(got) != 1 || got[0] != byte(STOP) {
		t.Fatalf("deployed code = %x, want %x", got, runtime)
	}
	if sdb.GetNonce(addr) != 1 {
		t.Fatal("a new contract must start at nonce 1")
	}
	if sdb.GetNonce(sender) != 1 {
		t.Fatal("the creator's nonce must be incremented")
	}
}

func TestCreate2IsAddressDeterministic(t *testing.T) {
	evm, _ := newTestEVM(t)
	initCode := asm(PUSH1, 0, PUSH1, 0, RETURN)
	salt := uint256.NewInt(0xcafe)

	_, addr, _, err := evm.Create2(AccountRef(sender), initCode, 1_000_000, new(big.Int), salt)
	if err != nil {
		t.Fatal(err)
	}
	// The address must be predictable from the inputs alone.
	saltBytes := salt.Bytes32()
	if want := CreateAddress2(sender, saltBytes, initCode); addr != want {
		t.Fatalf("CREATE2 deployed at %s, want %s", addr, want)
	}
}

func TestCreateCollisionIsRejected(t *testing.T) {
	evm, sdb := newTestEVM(t)
	initCode := asm(PUSH1, 0, PUSH1, 0, RETURN)
	salt := uint256.NewInt(1)
	saltBytes := salt.Bytes32()

	// Occupy the target address first.
	target := CreateAddress2(sender, saltBytes, initCode)
	sdb.CreateAccount(target)
	sdb.SetCode(target, []byte{byte(STOP)})

	if _, _, _, err := evm.Create2(AccountRef(sender), initCode, 1_000_000, new(big.Int), salt); !errors.Is(err, ErrContractAddressCollision) {
		t.Fatalf("got %v, want ErrContractAddressCollision", err)
	}
}

func TestCodeSizeLimit(t *testing.T) {
	evm, _ := newTestEVM(t)

	// Init code that returns more than MaxCodeSize bytes.
	size := MaxCodeSize + 1
	initCode := asm(
		push32(big.NewInt(int64(size))),
		PUSH1, 0,
		RETURN,
	)
	if _, _, _, err := evm.Create(AccountRef(sender), initCode, 10_000_000, new(big.Int)); !errors.Is(err, ErrMaxCodeSizeExceeded) {
		t.Fatalf("got %v, want ErrMaxCodeSizeExceeded", err)
	}
}

func TestReservedCodePrefixRejected(t *testing.T) {
	evm, _ := newTestEVM(t)
	// Return a single 0xEF byte, which EIP-3541 reserves.
	initCode := asm(
		PUSH1, 0xEF, PUSH1, 0, MSTORE8,
		PUSH1, 1, PUSH1, 0, RETURN,
	)
	if _, _, _, err := evm.Create(AccountRef(sender), initCode, 1_000_000, new(big.Int)); !errors.Is(err, ErrInvalidCode) {
		t.Fatalf("got %v, want ErrInvalidCode", err)
	}
}

func TestInsufficientBalanceForCall(t *testing.T) {
	evm, sdb := newTestEVM(t)
	poor := common.MustHexToAddress("0x5555555555555555555555555555555555555555")
	sdb.CreateAccount(poor)

	_, _, err := evm.Call(AccountRef(poor), contract, nil, 100000, big.NewInt(1))
	if !errors.Is(err, ErrInsufficientBalance) {
		t.Fatalf("got %v, want ErrInsufficientBalance", err)
	}
}

func TestSelfDestruct(t *testing.T) {
	evm, sdb := newTestEVM(t)
	beneficiary := common.MustHexToAddress("0x6666666666666666666666666666666666666666")

	sdb.CreateAccount(contract)
	sdb.AddBalance(contract, big.NewInt(777))
	sdb.SetCode(contract, asm(push32(beneficiary.Big()), SELFDESTRUCT))

	if _, _, err := evm.Call(AccountRef(sender), contract, nil, 1_000_000, new(big.Int)); err != nil {
		t.Fatal(err)
	}
	if got := sdb.GetBalance(beneficiary); got.Cmp(big.NewInt(777)) != 0 {
		t.Fatalf("beneficiary balance = %s, want 777", got)
	}
	if !sdb.HasSelfDestructed(contract) {
		t.Fatal("the contract was not marked for destruction")
	}
}

func TestDepthLimit(t *testing.T) {
	evm, sdb := newTestEVM(t)
	// A contract that calls itself forever; the depth limit must stop it.
	sdb.CreateAccount(contract)
	sdb.SetCode(contract, asm(
		PUSH1, 0, PUSH1, 0,
		PUSH1, 0, PUSH1, 0,
		PUSH1, 0,
		push32(contract.Big()),
		GAS,
		CALL,
		returnTop(),
	))
	ret, _, err := evm.Call(AccountRef(sender), contract, nil, 50_000_000, new(big.Int))
	if err != nil {
		t.Fatal(err)
	}
	// Recursion terminates instead of running away: the frame that hits the
	// limit fails and pushes zero, and every frame above it still succeeds.
	expectWord(t, ret, big.NewInt(1))
}

func TestReturnDataOpcodes(t *testing.T) {
	evm, sdb := newTestEVM(t)
	callee := common.MustHexToAddress("0x3333333333333333333333333333333333333333")
	sdb.CreateAccount(callee)
	sdb.SetCode(callee, asm(PUSH1, 0x5a, returnTop()))

	// Call, then check RETURNDATASIZE.
	sdb.CreateAccount(contract)
	sdb.SetCode(contract, asm(
		PUSH1, 0, PUSH1, 0,
		PUSH1, 0, PUSH1, 0,
		PUSH1, 0,
		push32(callee.Big()),
		PUSH2, 0xff, 0xff,
		CALL, POP,
		RETURNDATASIZE,
		returnTop(),
	))
	ret, _, err := evm.Call(AccountRef(sender), contract, nil, 1_000_000, new(big.Int))
	if err != nil {
		t.Fatal(err)
	}
	expectWord(t, ret, big.NewInt(32))
}

func TestReturnDataOutOfBounds(t *testing.T) {
	evm, sdb := newTestEVM(t)
	callee := common.MustHexToAddress("0x3333333333333333333333333333333333333333")
	sdb.CreateAccount(callee)
	sdb.SetCode(callee, asm(PUSH1, 0, PUSH1, 0, RETURN)) // returns nothing

	sdb.CreateAccount(contract)
	sdb.SetCode(contract, asm(
		PUSH1, 0, PUSH1, 0,
		PUSH1, 0, PUSH1, 0,
		PUSH1, 0,
		push32(callee.Big()),
		PUSH2, 0xff, 0xff,
		CALL, POP,
		PUSH1, 32, PUSH1, 0, PUSH1, 0, RETURNDATACOPY, // read 32 bytes that do not exist
		STOP,
	))
	_, _, err := evm.Call(AccountRef(sender), contract, nil, 1_000_000, new(big.Int))
	if !errors.Is(err, ErrReturnDataOutOfBounds) {
		t.Fatalf("got %v, want ErrReturnDataOutOfBounds", err)
	}
}

func TestEcrecoverPrecompile(t *testing.T) {
	evm, _ := newTestEVM(t)
	key, err := secp256k1PrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	msg := common.Keccak256([]byte("recover me"))
	sig, err := signHash(key, msg)
	if err != nil {
		t.Fatal(err)
	}

	input := make([]byte, 128)
	copy(input[:32], msg[:])
	input[63] = 27 + sig.V
	sig.R.FillBytes(input[64:96])
	sig.S.FillBytes(input[96:128])

	ret, _, err := evm.Call(AccountRef(sender), ecrecoverAddress, input, 100000, new(big.Int))
	if err != nil {
		t.Fatal(err)
	}
	want := common.BytesToAddress(common.Keccak256(key.PublicKey().Bytes()).Bytes()[12:])
	if common.BytesToAddress(ret) != want {
		t.Fatalf("ecrecover returned %s, want %s", common.BytesToAddress(ret), want)
	}

	// A malformed signature yields empty output rather than an error.
	bad := make([]byte, 128)
	ret, _, err = evm.Call(AccountRef(sender), ecrecoverAddress, bad, 100000, new(big.Int))
	if err != nil {
		t.Fatal(err)
	}
	if len(ret) != 0 {
		t.Fatalf("ecrecover on garbage returned %x", ret)
	}
}

func TestSha256AndIdentityPrecompiles(t *testing.T) {
	evm, _ := newTestEVM(t)

	ret, _, err := evm.Call(AccountRef(sender), sha256Address, []byte("abc"), 100000, new(big.Int))
	if err != nil {
		t.Fatal(err)
	}
	// The canonical SHA-256 of "abc".
	want := "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
	if common.EncodeHex(ret) != "0x"+want {
		t.Fatalf("sha256(abc) = %s", common.EncodeHex(ret))
	}

	payload := []byte("echo this back")
	ret, _, err = evm.Call(AccountRef(sender), identityAddress, payload, 100000, new(big.Int))
	if err != nil {
		t.Fatal(err)
	}
	if string(ret) != string(payload) {
		t.Fatalf("identity returned %q", ret)
	}
}

func TestModexpPrecompile(t *testing.T) {
	evm, _ := newTestEVM(t)

	// 3^2 mod 5 == 4
	input := make([]byte, 96+3)
	input[31] = 1 // base length
	input[63] = 1 // exponent length
	input[95] = 1 // modulus length
	input[96] = 3
	input[97] = 2
	input[98] = 5

	ret, _, err := evm.Call(AccountRef(sender), modexpAddress, input, 100000, new(big.Int))
	if err != nil {
		t.Fatal(err)
	}
	if len(ret) != 1 || ret[0] != 4 {
		t.Fatalf("modexp(3, 2, 5) = %x, want 04", ret)
	}
}

func TestCreateAddressVectors(t *testing.T) {
	// The canonical example from the yellow paper's address derivation.
	from := common.MustHexToAddress("0x6ac7ea33f8831ea9dcc53393aaa88b25a785dbf0")
	cases := []struct {
		nonce uint64
		want  string
	}{
		{0, "0xcd234a471b72ba2f1ccf0a70fcaba648a5eecd8d"},
		{1, "0x343c43a37d37dff08ae8c4a11544c718abb4fcf8"},
		{2, "0xf778b86fa74e846c4f0a1fbd1335fe81c00a0c91"},
	}
	for _, c := range cases {
		if got := CreateAddress(from, c.nonce); got.Hex() != c.want {
			t.Errorf("CreateAddress(nonce=%d) = %s, want %s", c.nonce, got.Hex(), c.want)
		}
	}
}

func TestCreate2AddressVectors(t *testing.T) {
	// Vectors from EIP-1014.
	from := common.MustHexToAddress("0x0000000000000000000000000000000000000000")
	var salt [32]byte
	got := CreateAddress2(from, salt, []byte{0x00})
	if got.Hex() != "0x4d1a2e2bb4f88f0250f26ffff098b0b30b26bf38" {
		t.Errorf("CREATE2 = %s, want 0x4d1a2e2bb4f88f0250f26ffff098b0b30b26bf38", got.Hex())
	}
}

func TestGasAccounting(t *testing.T) {
	// Three very-low-cost instructions plus a STOP.
	code := asm(PUSH1, 1, PUSH1, 2, ADD, STOP)
	_, left, err, _ := run(t, code, nil, 100000)
	if err != nil {
		t.Fatal(err)
	}
	used := 100000 - left
	// PUSH1 (3) + PUSH1 (3) + ADD (3) + STOP (0)
	if used != 9 {
		t.Fatalf("gas used = %d, want 9", used)
	}
}

func TestMemoryExpansionIsQuadratic(t *testing.T) {
	// Writing far out in memory must cost much more than writing near zero.
	cheap := asm(PUSH1, 1, PUSH1, 0, MSTORE, STOP)
	_, leftCheap, err, _ := run(t, cheap, nil, 10_000_000)
	if err != nil {
		t.Fatal(err)
	}
	expensive := asm(PUSH1, 1, push32(big.NewInt(100_000)), MSTORE, STOP)
	_, leftExpensive, err, _ := run(t, expensive, nil, 10_000_000)
	if err != nil {
		t.Fatal(err)
	}
	usedCheap := 10_000_000 - leftCheap
	usedExpensive := 10_000_000 - leftExpensive
	if usedExpensive <= usedCheap*100 {
		t.Fatalf("memory growth is not being charged quadratically: %d vs %d", usedCheap, usedExpensive)
	}
}

func TestColdAndWarmAccessCosts(t *testing.T) {
	// Reading the same slot twice: the second read is far cheaper.
	code := asm(PUSH1, 1, SLOAD, POP, STOP)
	_, leftOne, err, _ := run(t, code, nil, 100000)
	if err != nil {
		t.Fatal(err)
	}
	code = asm(PUSH1, 1, SLOAD, POP, PUSH1, 1, SLOAD, POP, STOP)
	_, leftTwo, err, _ := run(t, code, nil, 100000)
	if err != nil {
		t.Fatal(err)
	}
	secondRead := leftOne - leftTwo
	// A warm read is 100 gas plus the 3 for the PUSH1.
	if secondRead > GasWarmStorageRead+GasVeryLow+GasBase {
		t.Fatalf("the second read cost %d gas, expected a warm read", secondRead)
	}
}

func BenchmarkArithmeticLoop(b *testing.B) {
	sdb, _ := state.New(common.Hash{}, db.NewMemoryDB())
	sdb.CreateAccount(contract)
	code := asm(PUSH1, 1, PUSH1, 2, ADD, POP, STOP)
	sdb.SetCode(contract, code)

	evm := NewEVM(BlockContext{
		CanTransfer: CanTransfer, Transfer: Transfer,
		GetHash:     func(uint64) common.Hash { return common.Hash{} },
		BlockNumber: big.NewInt(1), BaseFee: big.NewInt(1),
	}, TxContext{Origin: sender, GasPrice: big.NewInt(1)}, sdb, &ChainConfig{ChainID: chainID}, Config{})

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		evm.Call(AccountRef(sender), contract, nil, 100000, new(big.Int))
	}
}
