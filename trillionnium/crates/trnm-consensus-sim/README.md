# trnm-consensus-sim

Deterministic, in-memory fault simulator for the current epoch-0 PoCO-BFT core
prototype. It drives `Effect`/`Input` boundaries without opening sockets,
starting services, reading a wall clock, writing a database, or owning a real
signing key.

This crate is **not wire-conforming yet**. Its bootstrap fixture follows the
current prototype API: a signed genesis QC over an independent `0x42…` block
identifier. Frozen PoCO-BFT v0 instead requires
`synthetic_genesis_block_id = genesis_hash` and an empty-signature genesis QC.
Until the core and simulator replace this prototype fixture with the
already-implemented trusted `GenesisQcV0` path, simulator results do not close
P1 genesis or production-readiness gates.

Finalization currently follows the core's obsolete internal `CommitProof`
compatibility witness. It is not the frozen `FinalityProofV0`, does not prove
the exact signed proposal justification/TC/handoff relationships required by
the protocol, and must not be exported or treated as light-client evidence.

The simulator is also epoch-0 only. Epoch transitions, a rollback-resistant
sign journal/remote-signer watermark, authenticated networking, durable WAL,
and real runtime execution remain outside this crate.

`Trace` is a deterministic diagnostic transcript, not yet a self-contained
replay input format. Scenario code must still recreate the configuration and
external fault actions. Trace entries retain full object identifiers,
signatures, signing roots, and safety-state digests so repeated-run comparison
does not rely on display prefixes, but a canonical trace decoder/replay API
remains a P1 blocker.

## Current regression evidence

As of 2026-08-05, the crate passes 11 tests: 3 focused unit tests and 8
deterministic scenarios. They cover applied-chain prefix comparison, key-bound
mock signatures, 4-/7-validator quorum-loss boundaries, 2+2 partition/heal,
persistence-before-sign rollback, durable conflicting-QC halt/restart,
consumed drop/duplicate/delay/reorder faults, and a running crash from nonzero
durable state through safety replay and synced-payload validation.

Progress assertions use applied finality plus a durable cleared-outbox
watermark; they do not treat a volatile in-core finalized tip as completed
application finality.

Additional P1 blockers remain: all simulated validators currently have equal
weight; payload validation always succeeds; recovery and TC aggregation use
global in-memory object availability; the complete persist/sign/broadcast
crash matrix is absent; and no invalid/unavailable-payload, stale-disk/signer,
epoch-transition, or heterogeneous-certificate campaign exists. The key-aware
deterministic signature scheme is test-only and is not Ed25519 or
authenticated-network evidence.
