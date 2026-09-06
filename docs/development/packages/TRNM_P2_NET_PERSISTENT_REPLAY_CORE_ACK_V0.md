# TRNM P2-NET persistent replay and Core acknowledgement candidate v0

## Scope

This package records the repository-owned persistence boundary between an authenticated peer frame and the canonical Core `Prepared` receipt.

The candidate flow is deliberately ordered as follows:

1. authenticate and verify the exact peer frame through `CandidateP2pAdmissionV0`;
2. bind the frame to one validated `BoundIngressV0`;
3. atomically persist the pending frame, peer-session identity, node identity, replay nonce and ingress operation binding before invoking Core;
4. invoke the canonical authority coordinator with the bound ingress;
5. accept only an exact `AuthorityStageV0::Prepared` receipt whose operation binding and facts digest match the persisted ingress;
6. atomically persist the advanced replay floor and the exact Prepared receipt before acknowledging the peer.

A crash after step 3 but before step 6 reopens with the same pending frame. The caller must replay that exact frame to Core. Core's idempotent complete receipt can then be checked and the replay floor can advance without inventing a new nonce or operation.

## Repository mechanisms

The feature-gated `CandidatePeerReplayJournalV0` provides:

- process exclusion through an exclusive lock file;
- node, chain, peer, protocol, session, profile and generation binding;
- checksum-protected canonical snapshots;
- write, file sync, rename and parent-directory sync before success is returned;
- complete temporary-snapshot promotion after response loss;
- rejection of conflicting temporary recovery, tampering, session substitution, stale tokens, conflicting replay and non-Prepared Core receipts;
- an integrated `CandidatePersistentPeerAdmissionV0` wrapper that keeps the in-memory admission state equal to the durable replay state.

The exact-source runtime fault matrix permanently runs the feature tests and strict Clippy checks.

## Explicit non-claims

This candidate does **not** provide or claim:

- a production socket, TLS implementation, peer discovery or network scheduler;
- a production multi-peer database or cross-platform filesystem qualification;
- rollback resistance against replacement of the whole state directory by an operator;
- an independent monotonic anchor, HSM, physical power-loss result, multi-host campaign or long soak;
- production consensus activation, public-testnet readiness or release readiness.

Those facts remain separate fail-closed blockers. Repository tests may establish ordering, exact binding, restart semantics and corruption rejection, but cannot synthesize external hardware, operational or independent-review evidence.
