# TRNM PoCO-BFT v0 Architecture Freeze — 2026-08-04

Status: **P0 normative architecture target**

This document is not an implementation, deployment, audit, or release-readiness claim.

## 1. Decision

Trillionnium Chain will target a deterministic PoCO-BFT v0 consensus path whose safety-critical state machine is independent of networking, storage engines, wall clocks, and application side effects. The existing deterministic runtime and authenticated state tree remain reusable execution components. Consensus, persistence, networking, state sync, signer isolation, and economic activation are layered around them.

The target data path is:

```text
authenticated P2P / local ingress
              |
              v
PoCO-BFT node shell (WAL, sign journal, pacemaker, sync)
              |
              v
deterministic consensus core
              |
              v
deterministic execution adapter
              |
              v
trnm-runtime -> JMT / committed state -> state root
```

The current Comet-based path remains a differential oracle during development. It is not the production PoCO-BFT finality authority. Legacy coordinator/simulator code is not promoted into the v0 safety kernel merely because it shares BFT terminology.

## 2. Non-negotiable boundaries

The deterministic consensus core MUST NOT directly read:

- sockets or peer identity databases;
- a system clock or random-number generator;
- a database, filesystem, or signer device;
- application-global mutable state.

It consumes explicit events and returns deterministic actions plus a safety-state update that the node shell must persist before emitting signatures.

The execution adapter MUST deterministically validate and execute the complete proposed payload before an honest validator votes. It MUST compare the computed state root and all other consensus-committed execution roots against the block header.

The node shell owns authenticated P2P, message admission, WAL and snapshot I/O, remote-signer calls, local timers, retries, peer scoring, and state sync. Local time may guide admission and liveness, but it MUST NOT change deterministic consensus validity except through the parent-relative timestamp rule frozen by the protocol.

## 3. Delivery phases

### P0 — protocol freeze

P0 produces the normative documents in `docs/protocol/poco-bft-v0`, the Consumption Certificate schema, reference parameters, a threat model, and formal/conformance obligations. P0 is complete only when consensus-affecting ambiguities are eliminated or explicitly fail closed.

### P1 — pure consensus kernel

P1 implements a network/DB/clock-free deterministic core with chained QCs, locks, timeout certificates, pacemaker transitions, epoch transition, double-sign evidence, crash-state transitions, and a deterministic fault simulator. TLA+/Quint models MUST cover the frozen invariants before the implementation is treated as a candidate safety kernel.

### P2 — real node

P2 adds authenticated P2P, WAL and sign journal, catch-up/state sync, remote signer, and the adapter to the existing runtime/JMT. It must survive reproducible 4- and 7-node crash, equivocation, partition, heal, restart, disk-full, and stale-state scenarios without violating safety.

### P3 — PoCO and economic safety

P3 implements Consumption Certificates, bond/unbond/jail/slash, maturity/decay/caps, snapshot construction, anti-reciprocal-consumption simulation, and rollout controls. Weight calculation begins in `shadow` and advances only through finalized epoch-boundary governance after the required observation gates. Mainnet economics require a separate freeze and audit.

### P4 — public validation

P4 expands from 7 to 20 geographically distributed validators; exercises data availability, disk, OOM, network, signer, and resource attacks; performs a 7–30 day soak; commissions external consensus, cryptography, and economic reviews; and validates an independently implemented light client.

No phase label implies completion of a later phase.

## 4. Architecture contracts

### 4.1 Consensus core contract

Given the same initial safety state, validator set, parameters, and ordered event stream, all conforming cores MUST return byte-identical logical actions and state. The core emits unsigned sign requests identified by exact canonical digests. It never emits network bytes itself.

### 4.2 Persistence and signer contract

Before a vote, timeout, or handoff signature leaves the validator boundary, the corresponding decision and resulting monotonic safety state MUST be committed durably. The signer MUST reject a request that conflicts with its journal even if the node process asks for it. Failure to persist or validate the journal causes fail-stop behavior, not best-effort signing.

### 4.3 Execution contract

The application boundary returns deterministic validity, post-state root, receipts/events commitment if enabled, and deterministic resource/accounting results. Application settlement records, including PoCO consumption records, do not become consensus votes and cannot independently finalize blocks.

### 4.4 State and proof contract

The committed header authenticates the execution state root. JMT/ICS23-style proofs establish membership or non-membership relative to that root only after the header itself has been finalized and verified. Application proofs do not replace consensus finality proofs.

### 4.5 Versioning contract

Every signed consensus message binds genesis, chain, protocol version, epoch, active validator-set hash, view, and message kind. Protocol upgrades activate only at epoch boundaries through the joint handoff procedure. Unknown versions fail closed.

## 5. Deployment and validation boundary

Local developer machines may edit, compile, and run isolated tests. Persistent node services, LAN validation, and public-network validation are intentionally outside P0 and must be performed on the designated remote validation host(s) through the approved SSH workflow. P0 documentation work MUST NOT install services, open ports, alter host networking, or mutate persistent node state.

## 6. Reuse and replacement posture

- Reuse the deterministic runtime where its transition semantics are stable and covered by vectors.
- Reuse the JMT/authenticated-tree proof machinery behind a narrow committed-state interface.
- Keep Comet execution available as a differential oracle until equivalence is demonstrated.
- Replace simulated signatures, centralized HTTP coordination, implicit round state, and unweighted or cardinality-only quorum logic in the production path.
- Do not reinterpret existing application-level consumption settlement as a Consumption Certificate or voting-power source without the P3 rules.

## 7. Claims deliberately not made

This freeze does not claim:

- a machine-checked safety or liveness proof;
- a production P2P, WAL, state-sync, or signer implementation;
- secure mainnet economic parameters;
- resistance to every adaptive-corruption, DoS, or data-availability attack;
- compatibility with a particular transport encoding;
- audit completion or permissionless launch readiness.

Those claims require evidence from the later phases and the conformance gates in the protocol freeze.
