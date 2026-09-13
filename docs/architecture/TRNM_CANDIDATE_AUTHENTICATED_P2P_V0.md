# Candidate Authenticated P2P Admission v0

Status: pure feature-gated candidate; no listener, socket, consensus or production activation authority.

Related contracts:

- [Authenticated Authority Input Ports v0](TRNM_AUTHENTICATED_STAGE_FACT_PORT_V0.md)
- [Production Authority Session v0](TRNM_PRODUCTION_AUTHORITY_SESSION_V0.md)
- [Candidate Pacemaker I/O v0](TRNM_CANDIDATE_PACEMAKER_IO_V0.md)

## Purpose

A live transport must not convert an arbitrary peer identifier, profile digest, nonce or payload hash into `Prepared` authority. The candidate in `trnm-poco-node-io` defines the replay and response-loss state machine that a real authenticated transport and durable replay store must satisfy.

The default node I/O runtime remains completely inert. The candidate is available only under `candidate-authenticated-p2p`.

## Session identity

`PeerSessionIdentityV0` binds non-zero identifiers for:

- chain;
- protocol/profile;
- peer;
- authenticated session;
- validator/session generation.

A frame is bound to one exact session, a non-zero replay nonce, a non-zero payload digest and a bounded payload length. The mechanism deliberately does not hash or authenticate payload bytes itself; `PeerFrameSourceV0` owns that trust decision.

## Replay state and response loss

`PeerReplayStateV0` contains the exact authenticated session, highest acknowledged nonce and at most one pending frame. A pending frame must be the exact successor of the acknowledged nonce. This creates a closed one-frame authority window:

1. `PeerFrameSourceV0` authenticates the complete frame against fresh transport state;
2. `verify_frame` mints a non-cloneable token bound to the exact replay state;
3. `admit_verified` installs one pending frame or exactly replays the same pending frame;
4. `acknowledge` advances only for the exact pending frame.

A response lost after admission is recovered through `PeerReplayRecoverySourceV0`; the exact pending frame can be replayed without nonce movement. A different payload at the same nonce, a later nonce while one is pending, a stale nonce, a gap, a wrong session, a stale token or a wrong acknowledgement fails closed before state movement.

## Authenticated recovery

`PeerReplayRecoverySourceV0` must authenticate the durable replay record, namespace, session generation and fresh readback. Structural validity alone is insufficient. Recovery-source rejection creates no admission state.

The candidate does not provide a filesystem, database, remote peer or cryptographic handshake implementation.

## Exact-source compile qualification

The feature graph is no longer source-only. Fixed-toolchain run `34005399117`, bound to Rust 1.95.0 and the exact candidate predecessor, executed formatting, all-target tests and strict Clippy for both:

```text
trnm-poco-node-io --features candidate-pacemaker,candidate-authenticated-p2p
trnm-poco-node-host --features candidate-networked-authority
```

The guarded run then created commit `ee72c648603198e3540f11f3e27aa699dc404155` with source tree `56ece5f05f1d326c41f963847dfef7ab64f7eaa1`. The change only moved a test-only digest import, made three readback function-pointer boundaries explicit and removed a test helper shadow. The temporary write-enabled workflow removed itself in the same commit.

This establishes that the pure admission state machine and P2P-to-authority bridge compile, execute and lint together on that exact tree. It does not establish durable replay storage, a listener, a live peer, production activation or full-workspace/prospective-merge acceptance. Every later source movement requires fresh qualification.

## Required live integration

A production candidate still requires:

- cross-platform listener/connect lifecycle;
- mutually authenticated handshake and session-key/profile binding;
- durable atomic replay state across process and host restart;
- body-byte retrieval and digest verification;
- peer lease/revocation recheck;
- bounded connection, queue, memory, rate and file-descriptor resources;
- exact mapping to `BoundIngressV0` and `AuthorityIngressSourceV0`;
- durable Core acknowledgement and outbox response-loss handling;
- partition, churn, slow-peer, malformed-frame and multi-host campaigns.

## Non-claims

Unit tests and test source implementations prove only the pure candidate state machine. They are not live network, multi-host, throughput, liveness, independent review, HSM, physical-fault, audit, soak or activation evidence.
