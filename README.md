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

Or `make devnet` to do all three at once. `make help` lists every target;
[QUICKSTART.md](QUICKSTART.md) walks through starting a chain, deploying a Solidity
contract and joining as a validator, with output from an actual run.

## What it does

- Executes EVM bytecode with the London gas schedule, so contracts compiled by Solidity
  for Ethereum run unmodified — including the BN254 precompiles a zk-SNARK verifier
  needs.
- Commits account state, storage, transactions and receipts into Merkle Patricia Tries,
  so a block header is a cryptographic commitment to the entire world state.
- Finalizes blocks with validator attestations: once more than two thirds have voted,
  the block can never be reorganised away. One absent validator costs a round, not the
  chain.
- Runs open proof of stake: validators join by depositing, the set changes only at epoch
  boundaries and only at a bounded rate, equivocation is slashed, and an inactivity leak
  lets a network that lost a third of its stake finalize again.
- Aggregates attestations with BLS12-381, so a quorum certificate is one signature and a
  bitfield rather than one signature per validator, and picks proposers by stake from
  randomness the proposers themselves cannot grind.
- Prices gas with an EIP-1559 fee market: the base fee is burned, the priority fee pays
  the proposer.
- Connects peers over authenticated, encrypted links with forward secrecy, scores their
  behaviour, and discovers new ones by peer exchange.
- Starts a new node from a finalized snapshot rather than replaying the chain, and prunes
  the state no retained block still references.
- Answers the standard Ethereum JSON-RPC methods under per-client rate limits, and
  exposes Prometheus metrics and health checks for operators.

## Layout

| Package | What lives there |
| --- | --- |
| `crypto/keccak` | Keccak-256 with Ethereum's padding, as a streaming `hash.Hash` |
| `crypto/secp256k1` | Curve arithmetic in Jacobian coordinates, deterministic low-s ECDSA, public key recovery, ECDH |
| `crypto/ripemd160` | The RIPEMD-160 hash |
| `crypto/blake2b` | The BLAKE2b compression function |
| `crypto/bn254` | The alt_bn128 tower field, both groups, and the optimal ate pairing |
| `crypto/bls12381` | BLS12-381 and aggregate signatures, for attestations |
| `common` | Addresses and hashes, EIP-55 checksums, hex quantities |
| `uint256` | Four-limb 256-bit integers with the EVM's exact arithmetic semantics |
| `rlp` | Recursive Length Prefix codec with struct tags and canonicality checks |
| `trie` | Merkle Patricia Trie with inclusion and exclusion proofs |
| `db` | Key/value store: in-memory, plus a crash-safe append-only log with compaction |
| `core` | Accounts, transactions, blocks, receipts, log blooms |
| `state` | Journaled world state with snapshots, access lists, transient storage |
| `evm` | The bytecode interpreter, gas metering and precompiles |
| `processor` | Transaction execution, intrinsic gas, the fee market |
| `consensus` | Block sealing, round-based proposer fallback, attestations and finality |
| `staking` | The proof-of-stake validator registry and its lifecycle |
| `chain` | Genesis, block storage and indexes, validation, reorganisation |
| `txpool` | Pending and queued transactions with nonce and fee rules |
| `miner` | Block assembly |
| `p2p` | Authenticated encrypted transport, gossip, peer scoring, discovery |
| `rpc` | JSON-RPC 2.0 server, the `eth`/`net`/`web3` namespaces, admission control |
| `metrics` | Counters, gauges and histograms in Prometheus format |
| `keystore` | V3 encrypted key files (PBKDF2-HMAC-SHA256, AES-128-CTR, Keccak MAC) |
| `statesync` | Downloading a state trie from peers instead of replaying blocks |
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

**Finality is a floor, not a freeze.** A quorum certificate makes history permanent:
a longer branch that abandons it is rejected however long it is, which is what closes
the long-range attack. Above the finalized block the longest chain still wins, so
ordinary competition between branches resolves as usual.

**A missing validator costs a round, not the chain.** Proposal falls through to the
next validator after a timeout, and the block's own timestamp has to prove the earlier
rounds actually lapsed — so a validator cannot seize a turn that is not yet forfeit.

**Peers are identified by key, not address.** Reputation follows the node key, so a
misbehaving peer cannot shed its record by reconnecting from somewhere else.

**Synced state is checked, not trusted.** The trie is content-addressed, so a syncing
node asks for a specific hash and discards anything that does not hash to it. A hostile
peer can refuse to answer; it cannot substitute state. The only thing established out of
band is the root, and that comes with a quorum certificate.

**The validator set is state, not configuration.** The registry lives in the state trie
as ordinary account storage, so every node agrees on who may propose for exactly the
reason it agrees on balances. The set for an epoch is read from the state at the end of
the previous one, which is what makes it usable for verification: a node checking a block
already holds the state that decided who was allowed to produce it.

**Slashing has to distinguish a fault from an attack.** An offence is charged twice: a
flat penalty at once, and a second one later that scales with how much stake was slashed
around the same time. An isolated fault costs about 7% of a stake; a third of the network
equivocating together costs all of it. One number cannot span that range.

**A quorum should cost two pairings, not two hundred.** Attestations aggregate, so a
certificate for 256 validators is 167 bytes and verifies in one check. Verifying each
vote as it arrives would have thrown that away, which is a mistake this codebase made
once and its own benchmarks caught.

**Randomness a proposer cannot grind.** The RANDAO reveal is a BLS signature over the
epoch, and a BLS signature is unique per key and message — there is exactly one value a
proposer can contribute. What is left is the choice to publish or withhold, which is one
bit per slot and the same residual bias Ethereum lives with.

**Slashed stake is burned, not paid out.** Rewarding whoever reports an offence would
create an incentive to provoke one.

**Pruning walks, it does not count.** Reference counting would be cheaper, but a single
miscounted reference silently destroys state that is still in use. A mark from the
retained roots cannot be wrong about what is reachable, and a write barrier makes it
safe to run while blocks are still arriving.

## Testing

```
$ go test ./...           # 505 tests
$ go test -race ./...
```

Correctness is anchored to published vectors wherever they exist: the Keccak-256 test
vectors, the RLP examples from the yellow paper, the Ethereum reference trie roots, the
EIP-55 checksum cases, the EIP-1014 `CREATE2` addresses and the RFC 6070-style PBKDF2
vectors, the EIP-152 BLAKE2b vectors and the full RIPEMD-160 specification set. The
pairing is checked by bilinearity and non-degeneracy rather than a single vector, since
those are the properties a verifier actually depends on.

Above that sit differential tests against `math/big`, randomized trie workloads
cross-checked against a plain map, and end-to-end tests that mine blocks, deploy and call
contracts, reorganise the chain, restart nodes, and run a four-validator cluster over
real sockets — including killing a validator mid-run and confirming that both block
production and finality carry on without it.

## Command line

```
layer1 init      -datadir ./data [-chainid N] [-validators ...] [-alloc addr=wei,...]
layer1 account   new | list | import -key <hex>
layer1 run       -datadir ./data [-mine -validator <addr>] [-rpc host:port] [-peers ...]
                 [-archive] [-retain N] [-monitor host:port]
layer1 send      -from <addr> -to <addr> -value <wei> [-data <hex>]
layer1 call      -to <addr> -data <hex>
layer1 balance   <address>
layer1 status
layer1 prune     [-monitor host:port]
```

## Staking

A validator joins by sending its stake to the system account, and leaves the same way:

```
# deposit: 0x01 || withdrawal address, with the stake as the transaction value
layer1 send -from <validator> -to 0x00000000000000000000000000000000000000ff \
            -value 32000000000000000000 -data 0x01<withdrawalAddress>

# request exit
layer1 send -from <validator> -to 0x00000000000000000000000000000000000000ff -data 0x02

# withdraw, once the delay has elapsed
layer1 send -from <validator> -to 0x00000000000000000000000000000000000000ff -data 0x03
```

`layer1_validatorInfo` reports a validator's stake and where it sits in its lifecycle.

## Scope

[ROADMAP.md](ROADMAP.md) tracks the path to production. Eight of its nine phases are
done. What remains, stated plainly:

- **The pairing is still around ten times slower than a production library.** Signature
  verification is 19ms against roughly 1-2ms for an assembly implementation. That caps
  throughput, not correctness, and the remaining gap is allocation in the extension tower
  rather than anything structural.
- **It has not been audited, and it has not been run in public.** Everything here is
  tested against its own author's model of what could go wrong, which is precisely the
  blind spot an independent audit and a long-running testnet exist to cover. Do not put
  value on this chain until both have happened.
