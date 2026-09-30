# M04 Bounded peer ingress and propagation

Revision: invariant-driven revision3. Selected target: `pon-nakamoto-v1`.
[Sole development plan](../development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md); [exact invariant registry](../../config/pon/invariants-v2.json).

## Scope and ownership

Native admission components and the bounded development loopback endpoint; neither is an authenticated public network service.

The claims below apply to their named component and tests, not to an independently accepted full native node.

## PoN State machine

### M04.ReadFrame

Read four bytes with10-second timeout; require 1..2097152 before allocating; read exactly length and reject duplicate JSON keys. Submit payload goes through full M02 validation, never through an accept flag.

**Atomic/commit boundary:** Transport has no chain authority; each child owns a different ledger.

### M04.PropagateVerifiedBlock

Send identical block to separate processes; each rechecks full work and state before ack. Retain failed/unavailable outcomes. Native peer identity/replay comes from retained authenticated frame components, not the test TCP wrapper.

**Atomic/commit boundary:** M07/M08 own receipt persistence; transport never writes ledger tables.

## M04.RecoveryCapacity

**Invariant:** Public verification cannot consume or duplicate-pin a local recovery slot; stopped generations retain live accounting until every permit drops.

**Scope:** Native admission components and the bounded development loopback endpoint; neither is an authenticated public network service.

**Atomic boundary:** One mutex owns counts and per-lane duplicate identities; only the local recovery capability can select its lane; RAII releases each live permit.

**Failure schedule:** Fill public capacity with changing identities; Acquire recovery permit; Stop/resume while old jobs live; Panic unwind; Public caller holds the same certificate identity requested for local recovery.

**Expected result:** Public verification cannot consume or duplicate-pin a local recovery slot; stopped generations retain live accounting until every permit drops.

**Resource and retention rule:** Three public jobs, one recovery job, two jobs per peer; no unbounded queue.

## Concrete regression selectors

`trillionnium/crates/trnm-transport/src/proof_admission.rs::public_flood_cannot_consume_reserved_recovery_capacity`

`trillionnium/crates/trnm-transport/src/proof_admission.rs::stop_resume_does_not_erase_outstanding_work`

`trillionnium/crates/trnm-transport/src/proof_admission.rs::panic_unwind_releases_capacity`

`trillionnium/crates/trnm-transport/src/proof_admission.rs::public_duplicate_cannot_pin_a_locally_requested_recovery_digest`

These exact functions contain executable assertions. The registry only checks binding; actual outcomes and source/input identities belong to the separate qualification report.

## Module-specific threat and residual work

Sybil connection churn, eclipse, validation starvation and forged recovery priority.

Global public fairness and cheap-proof defense are unresolved; local recovery capability is never selected by packet fields.

## Current source and verification

- [`trillionnium/crates/trnm-pon-node/src/ingress.rs`](../../trillionnium/crates/trnm-pon-node/src/ingress.rs).
- [`trillionnium/crates/trnm-transport/src/proof_admission.rs`](../../trillionnium/crates/trnm-transport/src/proof_admission.rs).

No test binding or local campaign grants independent acceptance, ordinary Hepta execution or production activation. Preserve the exact source, profile and environment of every outcome.

## Executed evidence and scope

[Responsibility-level evidence navigation](README.md#responsibility-and-evidence) reads
measured commits from immutable receipts. The module's entries in
[module-maturity-v1.json](../../config/pon/module-maturity-v1.json) identify actual callable
owners, controlled entrypoints, backends, persistence and exact observed test selectors.
Run `python3 scripts/ci/report_module_evidence.py --module M04` from the repository
root to see subject-byte and complete recorded-runtime matches separately, plus scenarios
not observed in each package. A byte match is not a new test run or product acceptance.
Historical v1/v3/v4 results are never repinned. The sole plan selects further work.

## Native development continuation and remaining scope

The native development server now consumes actual bounded socket frames through the existing proof-admission component and Rust Node. It restricts loopback, fixed workers and absolute frame deadlines. It is not authenticated public P2P, Sybil fairness or a public recovery service.

The current callable mappings remain in `config/pon/module-maturity-v1.json`.
Exact native entry, storage and work behavior is specified by N3 in NETWORK_CLIENT,
the native continuation in STATE_RECOVERY and the prepared-producer section in WORK_PROFILE.
No historical receipt is relabelled as executing this source.

The native development Submit path releases the Node mutex for transcript replay,
then consumes an opaque exact-packet verification result through the same Node owner.
Context/clock/state checks are repeated before commit; lock waiting and post-work
cancellation are bounded. The exact remaining public-service limits and executed
counterexamples are in [A2](../protocol/pon-nakamoto-v1/details/ADMISSION_SECURITY.md).
