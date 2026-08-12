# layer1

An Ethereum-style Layer-1 blockchain written from scratch in Go, with **no third-party
dependencies** — the module requires nothing beyond the Go standard library.

That constraint is the point of the project. Keccak-256, secp256k1, ECDSA, RLP, the
Merkle Patricia Trie, the 256-bit integer arithmetic, the EVM, the fee market, the
consensus engine, the peer-to-peer protocol and the JSON-RPC server are all implemented
here rather than imported.

```
$ go build ./cmd/layer1
$ ./layer1 init -datadir ./data
$ ./layer1 run -datadir ./data -mine -validator <address>
```

## What it does

- Executes EVM bytecode with the London gas schedule, so contracts compiled by Solidity
  for Ethereum run unmodified.
- Commits account state, storage, transactions and receipts into Merkle Patricia Tries,
  so a block header is a cryptographic commitment to the entire world state.
- Produces blocks under round-robin proof of authority with signed headers.
- Prices gas with an EIP-1559 fee market: the base fee is burned, the priority fee pays
  the proposer.
- Gossips blocks and transactions between nodes over TCP and answers the standard
  Ethereum JSON-RPC methods, so existing tooling can talk to it.

## Layout

| Package | What lives there |
| --- | --- |
| `crypto/keccak` | Keccak-256 with Ethereum's padding, as a streaming `hash.Hash` |
| `crypto/secp256k1` | Curve arithmetic in Jacobian coordinates, deterministic low-s ECDSA, public key recovery |
| `common` | Addresses and hashes, EIP-55 checksums, hex quantities |
| `uint256` | Four-limb 256-bit integers with the EVM's exact arithmetic semantics |
| `rlp` | Recursive Length Prefix codec with struct tags and canonicality checks |
| `trie` | Merkle Patricia Trie with inclusion and exclusion proofs |
| `db` | Key/value store: in-memory, plus a crash-safe append-only log with compaction |
| `core` | Accounts, transactions, blocks, receipts, log blooms |
| `state` | Journaled world state with snapshots, access lists, transient storage |
| `evm` | The bytecode interpreter, gas metering and precompiles |
| `processor` | Transaction execution, intrinsic gas, the fee market |
| `consensus` | Proof-of-authority block sealing and verification |
| `chain` | Genesis, block storage and indexes, validation, reorganisation |
| `txpool` | Pending and queued transactions with nonce and fee rules |
| `miner` | Block assembly |
| `p2p` | Peer handshake, block and transaction gossip, chain sync |
| `rpc` | JSON-RPC 2.0 server and the `eth`/`net`/`web3` namespaces |
| `keystore` | V3 encrypted key files (PBKDF2-HMAC-SHA256, AES-128-CTR, Keccak MAC) |
| `node` | Wires everything into a running process |
| `cmd/layer1` | Command-line interface |

## Design notes

**Why a hand-written `uint256`.** The EVM's arithmetic wraps at 2^256, divides by zero
to zero, and has signed operations that truncate toward zero. Expressing that with
arbitrary-precision integers means masking after every operation and still getting the
signed cases subtly wrong. A fixed-width type gets the semantics right by construction.
It is checked against `math/big` across 50,000 randomized cases per operation.

**Hashing is not persistence.** The trie tracks "this node's hash is known" separately
from "this node's encoding is on disk". Collapsing them into one flag is an easy mistake
that makes `Commit` silently skip any subtree that `Hash` happened to visit first — the
chain then produces a state root it cannot reload.

**Reverts return gas, everything else burns it.** A revert is a contract deliberately
rejecting its input, so the caller keeps the unspent gas. Any other failure consumes it
all: without that asymmetry, an attacker could probe execution for free.

**The base fee is burned, not paid.** Only the priority fee reaches the proposer. That
removes the incentive for a proposer to stuff blocks with its own transactions to
recycle fees back to itself.

**Signatures are canonical-only.** Every ECDSA signature has a mirrored twin that is
equally valid mathematically. Accepting both would let anyone change a signed
transaction's hash without holding the key, so only the low-s form is admitted.

## Testing

```
$ go test ./...           # 289 tests
$ go test -race ./...
```

Correctness is anchored to published vectors wherever they exist: the Keccak-256 test
vectors, the RLP examples from the yellow paper, the Ethereum reference trie roots, the
EIP-55 checksum cases, the EIP-1014 `CREATE2` addresses and the RFC 6070-style PBKDF2
vectors. Above that sit differential tests against `math/big`, randomized trie workloads
cross-checked against a plain map, and end-to-end tests that mine blocks, deploy and call
contracts, reorganise the chain, restart nodes, and sync two nodes over a real socket.

## Command line

```
layer1 init      -datadir ./data [-chainid N] [-validators ...] [-alloc addr=wei,...]
layer1 account   new | list | import -key <hex>
layer1 run       -datadir ./data [-mine -validator <addr>] [-rpc host:port] [-peers ...]
layer1 send      -from <addr> -to <addr> -value <wei> [-data <hex>]
layer1 call      -to <addr> -data <hex>
layer1 balance   <address>
layer1 status
```

## Scope

This is a complete, working chain, not a production network. Notable omissions, each a
deliberate boundary rather than an oversight:

- Precompiles cover `ecrecover`, `sha256`, `identity` and `modexp`. The BN254 pairing
  and `blake2f` precompiles are absent, so zk-SNARK verifier contracts will not run.
- Peer discovery is static: peers are supplied by address, with no DHT.
- The peer connection is unauthenticated and unencrypted TCP; there is no RLPx handshake.
- Sync fetches full blocks from the head backwards. There is no snap sync, no state
  pruning, and no archive/full distinction — every node keeps everything.
- Proof of authority means the validator set is fixed at genesis. There is no staking,
  no slashing, and no on-chain governance to rotate it.
