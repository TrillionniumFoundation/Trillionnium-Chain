# TRNM Native Consensus — Binding Architecture Decision

Date: 2026-09-07  
Status: **binding**

## Decision

Trillionnium Chain develops, operates, tests, and releases only its native Rust consensus implementation.

The canonical path is:

```text
client / signed command
  -> trnm-chain-node ingress and mempool
  -> native proposer selection and proposal construction
  -> authenticated validator execution and voting
  -> quorum certificate / commit decision
  -> deterministic state transition
  -> durable state, receipts, and AppHash
```

Canonical binaries:

- `trnm-chain-node` — ingress, mempool, proposal coordination, block/state commit, RPC, and receipt publication;
- `trnm-chain-validator` — independent validation, voting, anti-equivocation, and recovery state;
- `trnm-chain-cli` — key, transaction, query, benchmark, and operator interface;
- `trnm-sim` — deterministic simulation and fault/regression harness.

`trnm-node` is the consensus authority. `trnm-runtime`, `trnm-state`, `trnm-executor`, `trnm-mempool`, `trnm-protocol`, `trnm-types`, and finality crates are internal reusable boundaries, not alternative consensus implementations.

## Prohibited architecture

The following are forbidden unless this decision is explicitly replaced by a separately approved binding decision:

- external consensus-engine runtime dependencies;
- adapter processes that own block ordering or finality;
- compatibility fallbacks that can become consensus authority;
- CI, release, packaging, or operations paths requiring an external engine;
- documentation that presents an external engine as current, fallback, reference, migration, or production candidate.

## Safety invariants

1. **Determinism** — identical ordered inputs and prior state produce identical receipts, mutations, and AppHash.
2. **Quorum** — finality requires at least `2/3 + 1` of configured voting power under the frozen validator-set semantics.
3. **Anti-equivocation** — a validator cannot sign conflicting votes for the same height and round after restart, restore, or key rotation.
4. **Lock discipline** — proposal locks, unlock proofs, and round changes are explicit, durable, and independently verifiable.
5. **Authenticated messages** — proposal, vote, commit, and validator-lifecycle messages are domain-separated, chain-bound, versioned, signed, and replay-resistant.
6. **Fail-closed recovery** — gaps, corruption, identity drift, chain mismatch, or conflicting roots stop progress instead of being repaired silently.
7. **State commitment** — consensus identity, validator-set state, replay state, economic state, and application objects are committed consistently.
8. **Bounded resources** — ingress, mempool, proposal, validation, proof, snapshot, and recovery work have deterministic limits.

## Required protocol specification

The native consensus specification must define:

- heights, rounds, proposer selection, proposal validity, and timeout progression;
- vote types, signing bytes, quorum calculation, lock/unlock, and commit proof;
- message deduplication, replay windows, and peer penalties;
- validator-set activation height, overlap rules, rotation, removal, and recovery;
- crash points and WAL/checkpoint semantics;
- state sync, snapshot authentication, fast catch-up, and rollback boundaries;
- safety/liveness assumptions for Byzantine power, network synchrony, clock skew, and storage faults;
- version negotiation and mixed-version upgrade constraints.

## Acceptance gates

A capability is production-candidate only when all applicable gates pass:

1. deterministic replay across independent processes;
2. four-node and larger quorum tests with offline and Byzantine participants;
3. asymmetric partition, packet loss, duplication, delay, reordering, and healing;
4. crash injection before/after proposal, vote, durable state commit, and response publication;
5. validator add/remove/rotate and compromised-key recovery;
6. authenticated fresh-node sync and corrupt-snapshot rejection;
7. sequential versus parallel execution root equivalence;
8. sustained multi-host throughput and finality latency with complete raw evidence;
9. independent security review and long fuzz campaigns.

## Current posture

The native implementation already has local BFT, recovery, message-authentication, round-change, and fault-matrix assets. These are development foundations, not public-network proof. The unresolved items in `RELEASE_READINESS.md` remain blocking.
