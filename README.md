# padi-chain

An Ethereum-compatible Layer-1 blockchain written from scratch in Go, with **no
third-party dependencies**. The module requires nothing beyond the standard
library.

That constraint is the point of the project. Keccak-256, secp256k1, BLS12-381
and its pairing, RLP, the Merkle Patricia Trie, 256-bit arithmetic, the EVM, the
fee market, proof of stake, the peer-to-peer protocol and the JSON-RPC server
are all implemented here rather than imported.

```
$ make devnet
$ make deploy CONTRACT=Counter.sol ARGS=$(make -s word N=100)
$ make call TO=<contract> DATA=$(make -s selector SIG='count()')
```

Contracts compiled by `solc` for Ethereum run unmodified.

## What it does

- **Runs the EVM** with the London gas schedule and nine of the ten precompiles,
  including the BN254 pairing a zk-SNARK verifier depends on.
- **Commits state** into Merkle Patricia Tries, so a block header is a
  cryptographic commitment to every account, balance and storage slot.
- **Finalizes blocks** with validator attestations. Once more than two thirds
  have voted, a block can never be reorganised away. One absent validator costs
  a round, not the chain.
- **Aggregates those attestations** with BLS12-381: a certificate for 256
  validators is 167 bytes and verifies in two pairings, against 16KB and 256
  signature recoveries for the naive form.
- **Runs open proof of stake**: validators join by depositing, the set changes
  only at epoch boundaries and only at a bounded rate, equivocation is slashed
  in proportion to how many did it together, and an inactivity leak lets a
  network that lost a third of its stake finalize again.
- **Picks proposers by stake** from randomness the proposers themselves cannot
  grind.
- **Prices gas** with an EIP-1559 fee market: the base fee is burned, the
  priority fee pays the proposer.
- **Connects peers** over authenticated, encrypted links with forward secrecy,
  scores their behaviour by key rather than address, and finds new ones by peer
  exchange.
- **Starts fast**: a new node takes a finalized snapshot from a peer instead of
  replaying the chain, and prunes state no retained block references.
- **Answers the standard Ethereum JSON-RPC** under per-client rate limits, and
  exposes Prometheus metrics and health checks.

## Getting started

```
$ make devnet          # build, create a chain, start a mining node
$ make status
$ make stop
```

`make help` lists every target. [QUICKSTART.md](QUICKSTART.md) walks through the
same ground by hand — starting a chain, deploying a Solidity contract, joining
as a validator — with output from an actual run.

## Layout

| Package | What lives there |
| --- | --- |
| `crypto/keccak` | Keccak-256 with Ethereum's padding, as a streaming `hash.Hash` |
| `crypto/secp256k1` | Curve arithmetic, deterministic low-s ECDSA, key recovery, ECDH |
| `crypto/bls12381` | BLS12-381 with Montgomery arithmetic, pairing, aggregate signatures |
| `crypto/bn254` | The alt_bn128 curve behind the SNARK precompiles |
| `crypto/ripemd160`, `crypto/blake2b` | The remaining precompile hashes |
| `common` | Addresses and hashes, EIP-55 checksums, hex quantities |
| `uint256` | Four-limb 256-bit integers with the EVM's exact semantics |
| `rlp` | Recursive Length Prefix codec with struct tags and canonicality checks |
| `trie` | Merkle Patricia Trie with inclusion and exclusion proofs |
| `db` | Key/value store: in-memory, plus a crash-safe append-only log |
| `core` | Accounts, transactions, blocks, receipts, attestations, log blooms |
| `state` | Journaled world state with snapshots and access lists |
| `evm` | The bytecode interpreter, gas metering and precompiles |
| `processor` | Transaction execution, intrinsic gas, the fee market, epochs |
| `staking` | The proof-of-stake validator registry and its lifecycle |
| `consensus` | Block sealing, round fallback, attestation aggregation, finality |
| `chain` | Genesis, block storage, validation, reorganisation, pruning |
| `statesync` | Downloading a state trie from peers instead of replaying blocks |
| `txpool` | Pending and queued transactions with nonce and fee rules |
| `miner` | Block assembly |
| `p2p` | Encrypted transport, gossip, peer scoring, discovery |
| `rpc` | JSON-RPC 2.0 and the `eth`/`net`/`web3` namespaces |
| `metrics` | Counters, gauges and histograms in Prometheus format |
| `keystore` | V3 encrypted key files |
| `node` | Wires everything into a running process |
| `cmd/padi-chain` | Command-line interface |

## Design notes

The reasoning behind the choices that were not obvious.

**Why a hand-written `uint256`.** The EVM's arithmetic wraps at 2^256, divides
by zero to zero, and has signed operations that truncate toward zero. Expressing
that with arbitrary-precision integers means masking after every operation and
still getting the signed cases subtly wrong. A fixed-width type gets the
semantics right by construction, and is checked against `math/big` across 50,000
randomized cases per operation.

**Hashing is not persistence.** The trie tracks "this node's hash is known"
separately from "this node's encoding is on disk". Collapsing them into one flag
makes `Commit` silently skip any subtree that `Hash` happened to visit first —
and the chain then produces a state root it cannot reload.

**Reverts return gas; everything else burns it.** A revert is a contract
deliberately rejecting its input, so the caller keeps the unspent gas. Any other
failure consumes it all. Without that asymmetry, an attacker could probe
execution for free.

**The base fee is burned, not paid.** Only the priority fee reaches the
proposer. That removes the incentive to stuff blocks with one's own transactions
to recycle fees back to oneself.

**Signatures are canonical-only.** Every ECDSA signature has a mirrored twin
that is equally valid mathematically. Accepting both would let anyone change a
signed transaction's hash without holding the key.

**Finality is a floor, not a freeze.** A quorum certificate makes history
permanent: a longer branch that abandons it is rejected however long it is,
which closes the long-range attack. Above the finalized block the longest chain
still wins, so ordinary competition resolves as usual.

**A missing validator costs a round, not the chain.** Proposal falls through to
the next validator after a timeout, and the block's timestamp has to prove the
earlier rounds actually lapsed — so nobody can seize a turn that is not yet
forfeit.

**The validator set is state, not configuration.** The registry lives in the
state trie as ordinary account storage, so every node agrees on who may propose
for exactly the reason it agrees on balances. The set for an epoch is read from
the state at the end of the previous one, so a node checking a block already
holds the state that decided who was allowed to produce it.

**A quorum should cost two pairings, not two hundred.** Attestations aggregate.
Verifying each vote as it arrives would throw that away — a mistake this
codebase made once, and its own benchmarks caught.

**Randomness a proposer cannot grind.** The RANDAO reveal is a BLS signature
over the epoch, and such a signature is unique per key and message: there is
exactly one value a proposer can contribute. What remains is the choice to
publish or withhold, one bit per slot, the same residual bias Ethereum lives
with.

**Slashing must distinguish a fault from an attack.** An offence is charged
twice: a flat penalty at once, and a second later that scales with how much
stake was slashed around the same time. An isolated fault costs about 7% of a
stake; a third of the network equivocating together loses all of it. One number
cannot span that range.

**Slashed stake is burned, not paid out.** Rewarding whoever reports an offence
would create an incentive to provoke one.

**Peers are identified by key, not address.** Reputation follows the node key,
so a misbehaving peer cannot shed its record by reconnecting from elsewhere.

**Synced state is checked, not trusted.** The trie is content-addressed, so a
syncing node asks for a specific hash and discards anything that does not hash
to it. A hostile peer can refuse to answer; it cannot substitute state. The only
thing established out of band is the root, and that arrives with a quorum
certificate.

**Pruning walks, it does not count.** Reference counting would be cheaper, but
one miscounted reference silently destroys live state. A mark from the retained
roots cannot be wrong about what is reachable.

## Testing

```
$ make test        # 505 tests
$ make test-race
$ make check       # formatting, vet and tests, as CI would
```

Correctness is anchored to published vectors wherever they exist: the Keccak-256
vectors, the RLP examples from the yellow paper, the Ethereum reference trie
roots, the EIP-55 checksums, the EIP-1014 `CREATE2` addresses, the EIP-152
BLAKE2b vectors, the RIPEMD-160 specification set, and the published BLS12-381
field prime and group order — which the code derives from the curve parameter
rather than transcribing, so a mistyped digit fails every test at once.

Pairings are checked by bilinearity and non-degeneracy rather than a single
vector, since those are the properties a verifier actually relies on. That
distinction matters: the BLS12-381 twist was implemented backwards at one point
and produced a map that was still non-degenerate and still landed in the right
subgroup — only the bilinearity test noticed.

Above that sit differential tests against `math/big`, randomized trie workloads
cross-checked against a plain map, and end-to-end tests that mine blocks, deploy
and call contracts, reorganise the chain, restart nodes, snapshot-sync a fresh
node, and run a four-validator cluster over real sockets — including killing a
validator mid-run and confirming that both block production and finality carry
on without it.

## Command line

```
padi-chain init      -datadir ./data [-chainid N] [-validators ...] [-alloc addr=wei,...]
padi-chain account   new | list | import -key <hex>
padi-chain run       -datadir ./data [-mine -validator <addr>] [-rpc host:port]
                     [-peers ...] [-archive] [-retain N] [-monitor host:port]
padi-chain send      -from <addr> -to <addr> -value <wei> [-data <hex>]
padi-chain call      -to <addr> -data <hex>
padi-chain balance   <address>
padi-chain status
padi-chain prune     [-monitor host:port]
```

## JSON-RPC

The standard Ethereum methods under their standard names, so existing tooling
works unmodified. Verified against **ethers.js v6**, **web3.js v4** and
**web3.py**: deploying a contract, reading it, sending signed transactions,
decoding events, watching them through polling filters, and decoding a custom
error out of revert data all work with no adaptation.

The `eth_` prefix is kept deliberately. It is not a claim to be Ethereum — it is
the name every client has compiled into it, and renaming it would mean none of
them could talk to this chain.

```
eth_    chainId blockNumber syncing accounts coinbase protocolVersion mining hashrate
        getBalance getTransactionCount getCode getStorageAt
        getBlockByNumber getBlockByHash getBlockTransactionCountByNumber
        getBlockTransactionCountByHash getUncleCountByBlockNumber getUncleCountByBlockHash
        getTransactionByHash getTransactionByBlockNumberAndIndex
        getTransactionByBlockHashAndIndex getTransactionReceipt
        sendRawTransaction call estimateGas gasPrice maxPriorityFeePerGas feeHistory
        getLogs newFilter newBlockFilter newPendingTransactionFilter
        getFilterChanges getFilterLogs uninstallFilter
net_    version listening peerCount
web3_   clientVersion sha3
txpool_ status
padi_   nodeInfo validators validatorInfo
```

The chain's own methods live under `padi_`, spelled without the hyphen because a
JSON-RPC namespace containing one breaks enough tooling not to be worth it — the
same reason the metrics use `padi_`.

Blocks, transactions and receipts carry every field Ethereum defines, including
ones that can only hold a constant here: no proof of work means `difficulty` is
always zero, and there are no uncles. Clients parse these objects against a
fixed shape and reject the whole thing when a field is absent, so a missing
constant is not a small omission — it makes the node unusable from a library.
`mixHash` carries the block's randomness, which is where post-merge Ethereum
puts it and where tooling looks for it.

Not implemented: WebSocket transport, so `eth_subscribe` is unavailable and
events must be watched by polling a filter. There is no `eth_sendTransaction`
either — the node holds keys but will not sign with them over RPC, so signing
stays with the client.

## Staking

A validator joins by sending its stake to the system account at
`0x00000000000000000000000000000000000000ff`:

```
deposit   0x01 || withdrawalAddress(20) || blsPublicKey(48) || proofOfPossession(96)
exit      0x02
withdraw  0x03
report    0x04 || equivocation evidence
```

The proof of possession is mandatory. Without it a validator could register a
key derived from everyone else's and forge aggregate signatures nobody agreed
to — the one way an aggregation scheme is broken by a participant rather than by
breaking the mathematics.

`padi_validatorInfo` reports where a validator sits in its lifecycle.

## Running a cluster

There is no hash rate to add to. Blocks are produced by whichever validator's
turn it is, on a fixed period, and a second machine does not make that turn come
faster. What more machines buy is the thing proof of work buys with hash rate but
proof of stake buys with independence: a chain that keeps finalizing when some of
it goes away.

Finality needs signatures from more than two thirds of the stake, so a set of `n`
validators tolerates `(n-1)/3` of them being lost at once. Four validators
survive one failure; one validator survives nothing, and a single-node devnet has
no fault tolerance at all — it just does not notice, because the one node is
always in the quorum.

To put a validator on another machine:

```sh
# on every machine — the genesis file must be byte-identical everywhere,
# so copy it, do not re-run init
padi-chain account new -datadir ./data -password <pw>
scp node1:~/data/genesis.json ./data/genesis.json

padi-chain run -datadir ./data -mine -validator <address> -password <pw> \
  -addr 0.0.0.0:30303 \
  -peers <bootstrap-host>:30303 \
  -rpc 127.0.0.1:8545
```

`-addr` has to be an interface the other machines can actually reach, and port
30303 has to be open between them; `-rpc` should stay on loopback unless the
endpoint is meant to be public, since it is unauthenticated. Peers only need one
reachable bootstrap address each — peer exchange finds the rest.

A node that has drifted onto its own branch — because it was mining before it
found the network, or because it was partitioned for a while — recovers by
searching backwards for the height at which its chain and its peer's last
agreed, then replaying forward from there. Asking only for blocks above its own
head would never work: every one of them descends from a block it does not have.

Two things bite in practice. Validators must be in the genesis set (or deposit
their stake afterwards and wait out the activation queue) before their
attestations count for anything; and clocks must agree, because a header more
than 15 seconds ahead of a node's own clock is refused, so a machine with a
drifting clock silently has its blocks rejected by everyone else. Run NTP.

`make cluster` starts four validators locally on one machine. That is a
correctness test of the quorum path, not a performance one.

## Scope

[ROADMAP.md](ROADMAP.md) tracks the path to production. Eight of its nine phases
are done: consensus finality and liveness, network security, denial-of-service
resistance, EVM equivalence, operations, state management, validator governance
and validator-set scale.

What remains, stated plainly:

- **There is no WebSocket transport.** Events are watched by polling a filter
  rather than subscribing, which is more work for a client and higher latency.
- **The pairing is around ten times slower than a production library.**
  Verification is 19ms against roughly 1-2ms for an assembly implementation.
  That caps throughput, not correctness, and the remaining gap is allocation in
  the extension tower rather than anything structural.
- **It has not been audited, and it has never run in public.** Everything here
  is tested against its own author's model of what could go wrong, which is
  precisely the blind spot an independent audit and a long-running testnet exist
  to cover. Two of the bugs found late in this project — a Montgomery reduction
  that returned zero while round-tripping perfectly, and a pairing that was
  non-degenerate but not bilinear — were invisible to the obvious tests.

Do not put value on this chain until both have happened.
