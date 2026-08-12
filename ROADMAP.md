# Path to production

The chain in this repository is complete and correct as a protocol implementation.
What follows is what stands between it and a network that can safely hold value.
Ordered by what breaks worst if it is missing.

## Phase 1 — Consensus safety and liveness  (BLOCKING)

*The gap:* round-robin proof of authority has no finality and no fault tolerance.
A single offline validator stalls the chain at its slot forever. Two validators
that disagree produce two chains with no rule to settle them, and any depth of
history can be reorganised away.

- Attestation layer: validators sign each block; a quorum certificate (>2/3) makes
  it final.
- Fork choice anchored to the highest finalized block — finalized history can
  never be reorganised.
- Round-based proposer fallback so one missing validator costs one slot, not the
  chain.
- Equivocation detection producing slashable evidence.

## Phase 2 — Network security  (BLOCKING)

*The gap:* peer connections are plaintext TCP with no peer identity. Anyone on the
path can read, modify or inject blocks and transactions.

- Node identity keys and an authenticated ECDH handshake.
- Encrypted, authenticated framing (AES-256-GCM).
- Peer scoring and banning; per-peer rate limits.
- Peer exchange so the network survives bootstrap nodes going away.

## Phase 3 — Denial of service resistance  (BLOCKING)

*The gap:* a single client can exhaust the node.

- RPC rate limiting, per-method cost accounting, concurrency caps.
- Bounded queues everywhere; backpressure instead of unbounded growth.
- Resource limits on block and transaction validation.

## Phase 4 — EVM equivalence

*The gap:* missing precompiles mean some real contracts cannot run.

- `ripemd160`, `blake2f`, and the BN254 curve precompiles (`ecAdd`, `ecMul`,
  `ecPairing`) that zk-SNARK verifiers depend on.

## Phase 5 — Operations

*The gap:* an operator cannot see what the node is doing or tune it without
recompiling.

- Metrics, health and readiness endpoints.
- Configuration files.
- Structured, sampled logging.

## Phase 6 — Scaling and state management

- State pruning; the node currently keeps every historical state node forever.
- Snapshot sync so a new node does not replay the whole chain.
- Database compaction scheduling.

## Phase 7 — Validator set governance

- On-chain staking, validator set changes, and slashing execution.

## Phase 8 — What code cannot deliver

- Independent security audit.
- A public testnet run long enough to find what tests do not.
- A bug bounty, an incident response plan, and a disclosure policy.
- Reproducible builds and signed releases.
