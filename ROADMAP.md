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

## Phase 7 — Validator set governance  — DONE

Open proof of stake, following the shape Ethereum settled on.

- Stake is deposited by an ordinary transaction to a system account, the way
  Ethereum's deposits go to its deposit contract.
- The registry lives in the state trie, so the state root already commits to
  it: every node agrees on the validator set for the same reason it agrees on
  balances, and a light client can prove a validator's status.
- The set changes only at epoch boundaries and only at the churn limit's pace,
  so the set a block is verified against was settled before that block existed.
- Effective balance is capped and rounded, removing the incentive to
  concentrate stake on one key and stopping weights from flickering.
- Exits are queued and withdrawals delayed past the window in which evidence
  could still surface.
- Equivocation is slashed: the stake is burned rather than paid to the
  reporter, which would otherwise create an incentive to provoke it.
- Attestation rewards and penalties are derived from the quorum certificates
  the chain carries, so participation is a fact about the chain rather than a
  claim anyone makes.
- An inactivity leak drains absent validators while the chain fails to
  finalize, so a network that has lost a third of its stake can recover.

Still open here: Ethereum's correlation penalty, which scales a slashing with
how many validators were slashed near the same time, is not implemented — a
coordinated attack is currently punished no harder than an isolated fault.

## Phase 8 — Validator set scale  — DONE

*The gap:* attestations were one secp256k1 signature per validator, so a quorum
certificate grew with the set and cost as much to verify as to build. And
proposal was round-robin, so the next proposer was known indefinitely far ahead
and trivial to attack.

- BLS12-381 with signature aggregation: a certificate is one signature plus a
  bitfield, and verifying it is two pairings whatever the number of signers.
  Measured, a certificate for 256 validators is 167 bytes against 16KB for the
  equivalent in recoverable signatures.
- Proofs of possession at registration, without which a validator could forge
  aggregates from a key derived from everyone else's.
- RANDAO: each block carries the proposer's signature over the epoch, mixed
  into state. Proposers are drawn from it weighted by stake, so the schedule is
  unpredictable beyond the current epoch while staying verifiable.

Still open here: the pairing implementation uses math/big rather than Montgomery
arithmetic over fixed limbs, which leaves it roughly two orders of magnitude
slower than a production library. That is a throughput ceiling, not a
correctness one.

## Phase 9 — What code cannot deliver  — NOT DONE

No amount of implementation substitutes for these.

- An independent security audit. Everything above is tested against its own
  author's understanding of what could go wrong, which is exactly the blind
  spot an audit exists to cover.
- A public testnet run long enough to surface what tests do not: clock skew,
  partitions, disk exhaustion, the failure that only happens at 3am on day 40.
- A bug bounty, an incident response plan, and a disclosure policy.
- Reproducible builds and signed releases.
