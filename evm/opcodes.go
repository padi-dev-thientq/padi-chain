package evm

// OpCode is a single EVM instruction.
type OpCode byte

// Arithmetic and comparison.
const (
	STOP       OpCode = 0x00
	ADD        OpCode = 0x01
	MUL        OpCode = 0x02
	SUB        OpCode = 0x03
	DIV        OpCode = 0x04
	SDIV       OpCode = 0x05
	MOD        OpCode = 0x06
	SMOD       OpCode = 0x07
	ADDMOD     OpCode = 0x08
	MULMOD     OpCode = 0x09
	EXP        OpCode = 0x0a
	SIGNEXTEND OpCode = 0x0b

	LT     OpCode = 0x10
	GT     OpCode = 0x11
	SLT    OpCode = 0x12
	SGT    OpCode = 0x13
	EQ     OpCode = 0x14
	ISZERO OpCode = 0x15
	AND    OpCode = 0x16
	OR     OpCode = 0x17
	XOR    OpCode = 0x18
	NOT    OpCode = 0x19
	BYTE   OpCode = 0x1a
	SHL    OpCode = 0x1b
	SHR    OpCode = 0x1c
	SAR    OpCode = 0x1d

	KECCAK256 OpCode = 0x20
)

// Environment access.
const (
	ADDRESS        OpCode = 0x30
	BALANCE        OpCode = 0x31
	ORIGIN         OpCode = 0x32
	CALLER         OpCode = 0x33
	CALLVALUE      OpCode = 0x34
	CALLDATALOAD   OpCode = 0x35
	CALLDATASIZE   OpCode = 0x36
	CALLDATACOPY   OpCode = 0x37
	CODESIZE       OpCode = 0x38
	CODECOPY       OpCode = 0x39
	GASPRICE       OpCode = 0x3a
	EXTCODESIZE    OpCode = 0x3b
	EXTCODECOPY    OpCode = 0x3c
	RETURNDATASIZE OpCode = 0x3d
	RETURNDATACOPY OpCode = 0x3e
	EXTCODEHASH    OpCode = 0x3f

	BLOCKHASH   OpCode = 0x40
	COINBASE    OpCode = 0x41
	TIMESTAMP   OpCode = 0x42
	NUMBER      OpCode = 0x43
	PREVRANDAO  OpCode = 0x44
	GASLIMIT    OpCode = 0x45
	CHAINID     OpCode = 0x46
	SELFBALANCE OpCode = 0x47
	BASEFEE     OpCode = 0x48
)

// Stack, memory, storage and flow control.
const (
	POP      OpCode = 0x50
	MLOAD    OpCode = 0x51
	MSTORE   OpCode = 0x52
	MSTORE8  OpCode = 0x53
	SLOAD    OpCode = 0x54
	SSTORE   OpCode = 0x55
	JUMP     OpCode = 0x56
	JUMPI    OpCode = 0x57
	PC       OpCode = 0x58
	MSIZE    OpCode = 0x59
	GAS      OpCode = 0x5a
	JUMPDEST OpCode = 0x5b
	TLOAD    OpCode = 0x5c
	TSTORE   OpCode = 0x5d
	MCOPY    OpCode = 0x5e
	PUSH0    OpCode = 0x5f
)

// Push, dup, swap and log families.
const (
	PUSH1  OpCode = 0x60
	PUSH2  OpCode = 0x61
	PUSH3  OpCode = 0x62
	PUSH4  OpCode = 0x63
	PUSH5  OpCode = 0x64
	PUSH6  OpCode = 0x65
	PUSH7  OpCode = 0x66
	PUSH8  OpCode = 0x67
	PUSH9  OpCode = 0x68
	PUSH10 OpCode = 0x69
	PUSH11 OpCode = 0x6a
	PUSH12 OpCode = 0x6b
	PUSH13 OpCode = 0x6c
	PUSH14 OpCode = 0x6d
	PUSH15 OpCode = 0x6e
	PUSH16 OpCode = 0x6f
	PUSH17 OpCode = 0x70
	PUSH18 OpCode = 0x71
	PUSH19 OpCode = 0x72
	PUSH20 OpCode = 0x73
	PUSH21 OpCode = 0x74
	PUSH22 OpCode = 0x75
	PUSH23 OpCode = 0x76
	PUSH24 OpCode = 0x77
	PUSH25 OpCode = 0x78
	PUSH26 OpCode = 0x79
	PUSH27 OpCode = 0x7a
	PUSH28 OpCode = 0x7b
	PUSH29 OpCode = 0x7c
	PUSH30 OpCode = 0x7d
	PUSH31 OpCode = 0x7e
	PUSH32 OpCode = 0x7f
)

const (
	DUP1  OpCode = 0x80
	DUP2  OpCode = 0x81
	DUP3  OpCode = 0x82
	DUP4  OpCode = 0x83
	DUP5  OpCode = 0x84
	DUP6  OpCode = 0x85
	DUP7  OpCode = 0x86
	DUP8  OpCode = 0x87
	DUP9  OpCode = 0x88
	DUP10 OpCode = 0x89
	DUP11 OpCode = 0x8a
	DUP12 OpCode = 0x8b
	DUP13 OpCode = 0x8c
	DUP14 OpCode = 0x8d
	DUP15 OpCode = 0x8e
	DUP16 OpCode = 0x8f
)

const (
	SWAP1  OpCode = 0x90
	SWAP2  OpCode = 0x91
	SWAP3  OpCode = 0x92
	SWAP4  OpCode = 0x93
	SWAP5  OpCode = 0x94
	SWAP6  OpCode = 0x95
	SWAP7  OpCode = 0x96
	SWAP8  OpCode = 0x97
	SWAP9  OpCode = 0x98
	SWAP10 OpCode = 0x99
	SWAP11 OpCode = 0x9a
	SWAP12 OpCode = 0x9b
	SWAP13 OpCode = 0x9c
	SWAP14 OpCode = 0x9d
	SWAP15 OpCode = 0x9e
	SWAP16 OpCode = 0x9f
)

const (
	LOG0 OpCode = 0xa0
	LOG1 OpCode = 0xa1
	LOG2 OpCode = 0xa2
	LOG3 OpCode = 0xa3
	LOG4 OpCode = 0xa4
)

// System operations.
const (
	CREATE       OpCode = 0xf0
	CALL         OpCode = 0xf1
	CALLCODE     OpCode = 0xf2
	RETURN       OpCode = 0xf3
	DELEGATECALL OpCode = 0xf4
	CREATE2      OpCode = 0xf5
	STATICCALL   OpCode = 0xfa
	REVERT       OpCode = 0xfd
	INVALID      OpCode = 0xfe
	SELFDESTRUCT OpCode = 0xff
)

// IsPush reports whether op pushes an immediate value.
func (op OpCode) IsPush() bool { return op >= PUSH1 && op <= PUSH32 }

// PushSize returns the number of immediate bytes a push instruction carries.
func (op OpCode) PushSize() int {
	if !op.IsPush() {
		return 0
	}
	return int(op-PUSH1) + 1
}

var opCodeNames = map[OpCode]string{
	STOP: "STOP", ADD: "ADD", MUL: "MUL", SUB: "SUB", DIV: "DIV", SDIV: "SDIV",
	MOD: "MOD", SMOD: "SMOD", ADDMOD: "ADDMOD", MULMOD: "MULMOD", EXP: "EXP",
	SIGNEXTEND: "SIGNEXTEND", LT: "LT", GT: "GT", SLT: "SLT", SGT: "SGT",
	EQ: "EQ", ISZERO: "ISZERO", AND: "AND", OR: "OR", XOR: "XOR", NOT: "NOT",
	BYTE: "BYTE", SHL: "SHL", SHR: "SHR", SAR: "SAR", KECCAK256: "KECCAK256",
	ADDRESS: "ADDRESS", BALANCE: "BALANCE", ORIGIN: "ORIGIN", CALLER: "CALLER",
	CALLVALUE: "CALLVALUE", CALLDATALOAD: "CALLDATALOAD", CALLDATASIZE: "CALLDATASIZE",
	CALLDATACOPY: "CALLDATACOPY", CODESIZE: "CODESIZE", CODECOPY: "CODECOPY",
	GASPRICE: "GASPRICE", EXTCODESIZE: "EXTCODESIZE", EXTCODECOPY: "EXTCODECOPY",
	RETURNDATASIZE: "RETURNDATASIZE", RETURNDATACOPY: "RETURNDATACOPY",
	EXTCODEHASH: "EXTCODEHASH", BLOCKHASH: "BLOCKHASH", COINBASE: "COINBASE",
	TIMESTAMP: "TIMESTAMP", NUMBER: "NUMBER", PREVRANDAO: "PREVRANDAO",
	GASLIMIT: "GASLIMIT", CHAINID: "CHAINID", SELFBALANCE: "SELFBALANCE",
	BASEFEE: "BASEFEE", POP: "POP", MLOAD: "MLOAD", MSTORE: "MSTORE",
	MSTORE8: "MSTORE8", SLOAD: "SLOAD", SSTORE: "SSTORE", JUMP: "JUMP",
	JUMPI: "JUMPI", PC: "PC", MSIZE: "MSIZE", GAS: "GAS", JUMPDEST: "JUMPDEST",
	TLOAD: "TLOAD", TSTORE: "TSTORE", MCOPY: "MCOPY", PUSH0: "PUSH0",
	CREATE: "CREATE", CALL: "CALL", CALLCODE: "CALLCODE", RETURN: "RETURN",
	DELEGATECALL: "DELEGATECALL", CREATE2: "CREATE2", STATICCALL: "STATICCALL",
	REVERT: "REVERT", INVALID: "INVALID", SELFDESTRUCT: "SELFDESTRUCT",
}

func (op OpCode) String() string {
	if name, ok := opCodeNames[op]; ok {
		return name
	}
	switch {
	case op.IsPush():
		return "PUSH" + itoa(op.PushSize())
	case op >= DUP1 && op <= DUP16:
		return "DUP" + itoa(int(op-DUP1)+1)
	case op >= SWAP1 && op <= SWAP16:
		return "SWAP" + itoa(int(op-SWAP1)+1)
	case op >= LOG0 && op <= LOG4:
		return "LOG" + itoa(int(op-LOG0))
	default:
		return "opcode(0x" + hexByte(byte(op)) + ")"
	}
}

func itoa(v int) string {
	if v == 0 {
		return "0"
	}
	var buf [3]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	return string(buf[i:])
}

func hexByte(b byte) string {
	const digits = "0123456789abcdef"
	return string([]byte{digits[b>>4], digits[b&0xf]})
}
