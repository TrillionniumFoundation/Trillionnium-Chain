# M04 Bounded peer ingress and propagation

Revision: invariant-driven revision2. The selected target remains `pon-nakamoto-v1`.
[Sole development plan](../development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md); [precise invariant/test registry](../../config/pon/invariants-v2.json).

## Scope and ownership

Native transport admission component, not an already deployed public network service.

This is an implementation boundary, not a claim of a complete native node or independent acceptance.

## PoN State machine

### M04.ReadFrame

Read four bytes with10-second timeout; require 1..2097152 before allocating; read exactly length and reject duplicate JSON keys. Submit payload goes through full M02 validation, never through an accept flag.

**Atomic/commit boundary:** Transport has no chain authority; each child owns a different ledger.

### M04.PropagateVerifiedBlock

Send identical block to separate processes; each rechecks full work and state before ack. Retain failed/unavailable outcomes. Native peer identity/replay comes from retained authenticated frame components, not the test TCP wrapper.

**Atomic/commit boundary:** M07/M08 own receipt persistence; transport never writes ledger tables.

## M04.RecoveryCapacity

**Invariant:** Public proof permits cannot consume the local-only reserved recovery slot; stop/resume does not erase live jobs.

**Preconditions:** Exact installed revision2 context; current local owner and immutable task/evidence identities. Storage-only and controlled-attestation premises are explicitly labelled in their tests.

**Atomic boundary:** One mutex owns global/per-peer counts and duplicate identities; RAII releases every permit on success, failure or unwind.

**Failure schedule:** Fill public capacity with changing identities; Acquire recovery permit; Stop/resume while old jobs live; Panic unwind.

**Expected result:** Public proof permits cannot consume the local-only reserved recovery slot; stop/resume does not erase live jobs.

**Resource and retention rule:** Three public jobs, one recovery job, two jobs per peer; no unbounded queue.

## Concrete regression selectors

`trillionnium/crates/trnm-transport/src/proof_admission.rs::public_flood_cannot_consume_reserved_recovery_capacity`

`trillionnium/crates/trnm-transport/src/proof_admission.rs::stop_resume_does_not_erase_outstanding_work`

`trillionnium/crates/trnm-transport/src/proof_admission.rs::panic_unwind_releases_capacity`

These selectors identify actual test functions, not a class-name count. A binding checker cannot label a test passed; the separate exact-source command receipt must show execution and outcome.

## Module-specific threat and residual work

Sybil connection churn, eclipse, validation starvation and forged recovery priority.

Global public fairness and cheap-proof defense are unresolved; local recovery capability is never selected by packet fields.

No assertion of independent operators, physical durability, ordinary Hepta execution or future model efficacy follows from local fixtures.

## Current source and verification

- [`trillionnium/crates/trnm-transport/src/proof_admission.rs`](../../trillionnium/crates/trnm-transport/src/proof_admission.rs).

Run the relevant native package and exact Python test selectors through the protocol CI lane. Preserve source hashes, failures, backend, filesystem and process/host scope. Historical evidence is never relabelled as current.
