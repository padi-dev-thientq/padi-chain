# Path to production

The chain in this repository is complete and correct as a protocol implementation.
What follows is what stands between it and a network that can safely hold value.
Ordered by what breaks worst if it is missing.

## Phase 1 — Consensus safety and liveness  — DONE

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

## Phase 2 — Network security  — DONE

*The gap:* peer connections are plaintext TCP with no peer identity. Anyone on the
path can read, modify or inject blocks and transactions.

- Node identity keys and an authenticated ECDH handshake.
- Encrypted, authenticated framing (AES-256-GCM).
- Peer scoring and banning; per-peer rate limits.
- Peer exchange so the network survives bootstrap nodes going away.

## Phase 3 — Denial of service resistance  — DONE

*The gap:* a single client can exhaust the node.

- RPC rate limiting, per-method cost accounting, concurrency caps.
- Bounded queues everywhere; backpressure instead of unbounded growth.
- Resource limits on block and transaction validation.

## Phase 4 — EVM equivalence  — DONE

*The gap:* missing precompiles mean some real contracts cannot run.

- `ripemd160`, `blake2f`, and the BN254 curve precompiles (`ecAdd`, `ecMul`,
  `ecPairing`) that zk-SNARK verifiers depend on.

## Phase 5 — Operations  — DONE

*The gap:* an operator cannot see what the node is doing or tune it without
recompiling.

- Metrics, health and readiness endpoints.
- Configuration files.
- Structured, sampled logging.

## Phase 6 — Scaling and state management  — DONE

- State pruning by mark and sweep from the roots worth keeping. Reference
  counting would be cheaper, but one miscounted reference silently destroys
  live state; a walk from the roots cannot be wrong about what is reachable.
  A write barrier keeps it safe to run while blocks are still being imported.
- Snapshot sync: a new node takes a finalized block from a peer and downloads
  the state it commits to. Safe because of finality, not trust — the block
  carries a quorum certificate, and every state node is checked against the
  hash that referenced it.
- Scheduled compaction, which is what actually returns disk after pruning
  deletes records from an append-only log.

Still open here: the pruner holds the reachable set in memory, which is fine
at present scale and will not be for a very large state.

## Phase 7 — Validator set governance  — NOT DONE

*Why it is still open:* the right answer depends on what the network is for,
and picking one unilaterally would be the wrong call.

The validator set is fixed at genesis. Equivocation is detected, proved and
gossiped, but nothing acts on the proof — there is no stake to slash and no
mechanism to remove a validator. Adding one means choosing between a
permissioned set with governance-controlled membership and an open
proof-of-stake set, which is a decision about the network, not about the code.

## Phase 8 — What code cannot deliver  — NOT DONE

No amount of implementation substitutes for these.

- An independent security audit. Everything above is tested against its own
  author's understanding of what could go wrong, which is exactly the blind
  spot an audit exists to cover.
- A public testnet run long enough to surface what tests do not: clock skew,
  partitions, disk exhaustion, the failure that only happens at 3am on day 40.
- A bug bounty, an incident response plan, and a disclosure policy.
- Reproducible builds and signed releases.
