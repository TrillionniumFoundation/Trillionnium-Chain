# Authenticated Authority Stage-Fact Port v0

Status: candidate contract; no production activation authority.

## Purpose

A durable authority journal proves ordering, recovery, replay and hash-chain continuity. It does not prove that a caller-supplied digest represents a real Application, Safety, signer, finality, checkpoint or publication operation. This contract removes the public naked-digest advancement seam from `ProductionAuthoritySessionV0`.

A stage transition now has three boundaries:

1. an authoritative domain owner emits an `AuthorityFactClaimV0` bound to the exact node identity, operation binding, stage, source identity, source sequence and payload digest;
2. an `AuthorityFactSourceV0` implementation authenticates fresh owner readback and compares every claim field;
3. the session mints a non-cloneable `VerifiedAuthorityFactV0` bound to the current durable record and consumes it in `advance_verified`.

The token is rejected after any identity, operation, predecessor-record, stage or payload movement. Exact response-loss replay requires the source to reverify the identical claim and the recomputed fact digest to equal the recovered durable receipt.

## Dependency and authority boundary

The production-composition crate remains wiring-only. It does not import Application, Safety, signer, finality, checkpoint or networking implementations. Real bounded adapters implement `AuthorityFactSourceV0` outside the composition root and remain responsible for cryptographic authentication, source-specific invariants and fresh readback.

A verifier returning success is an explicit trust decision by the caller's composition. Reference or test verifiers are not production evidence. The port transfers no signing, voting, finality, persistence, networking or activation authority.

## Required producer bindings

A production candidate must provide separate accepted sources for:

- `ApplicationSealed`: executed block, application state root and receipt commitment;
- `SafetyPersisted`: exact Safety revision and durable readback;
- `SignIntentPersisted`: exact sign bytes, domain and anti-double-sign intent;
- `SignatureConfirmed`: non-exportable signer result and monotonic watermark;
- `FinalityApplied`: finalized proof and exact application/Safety join;
- `CheckpointConfirmed`: predecessor-bound whole-node checkpoint CAS and readback;
- `OutboundPublished`: authenticated publication acknowledgement and replay identity.

Each source must reject stale, substituted, cross-operation, cross-identity and zero evidence. Source errors leave the session and durable predecessor unchanged.

## Acceptance

Repository acceptance requires fixed-toolchain formatting, all-target tests, strict Clippy, exact-head and prospective-merge replay, negative token-reuse/source-substitution tests and independent M03/M06/M07/M08/M15 review.

This source increment does not establish any of the listed producer bindings, a live validator, a network campaign, HSM custody, an external monotonic anchor, physical power-loss evidence, an independent audit, soak completion or governance activation.
