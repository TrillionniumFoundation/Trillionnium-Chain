# M17 Reproducible evidence and semantic contract checks

Revision: invariant-driven revision2. The selected target remains `pon-nakamoto-v1`.
[Sole development plan](../development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md); [precise invariant/test registry](../../config/pon/invariants-v2.json).

## Scope and ownership

Immutable evidence/pon-v1 plus separate current-source receipts.

This is an implementation boundary, not a claim of a complete native node or independent acceptance.

## PoN State machine

### M17.CheckDetailedContracts

Old reports remain tied to their measured source; newer source is never called tested by rehashing an old pass. Verify original artifacts and measured ancestor bytes; report current-source match separately from historical consistency.

**Atomic/commit boundary:** Verify original artifacts and measured ancestor bytes; report current-source match separately from historical consistency.

### M17.QualifyExecutedCampaign

Keep workcost, invalidproofamplification, diskprocesscrashes, localhostnetwork, actuallearning andreward evidence separate. Retainfailedobservations; requireexternal revieweridentity for independentacceptance, never substitute authoredsubprocesses.

**Atomic/commit boundary:** Immutable evidence artifact manifest; cannot enableproduction.

## M17.HistoricalEvidence

**Invariant:** Old reports remain tied to their measured source; newer source is never called tested by rehashing an old pass.

**Preconditions:** Exact installed revision2 context; current local owner and immutable task/evidence identities. Storage-only and controlled-attestation premises are explicitly labelled in their tests.

**Atomic boundary:** Verify original artifacts and measured ancestor bytes; report current-source match separately from historical consistency.

**Failure schedule:** Stale digest; Dropped failure; Hidden strongest control; Forged independent or future acceptance.

**Expected result:** Old reports remain tied to their measured source; newer source is never called tested by rehashing an old pass.

**Resource and retention rule:** Binding validation is read-only and does not execute tests or award deployment authority.

## Concrete regression selectors

`scripts/ci/test_pon_evidence.py::EvidenceRejectionTests.test_source_digest_cannot_be_stale`

`scripts/ci/test_pon_evidence.py::EvidenceRejectionTests.test_future_window_claim_rejected_even_after_rehash`

These selectors identify actual test functions, not a class-name count. A binding checker cannot label a test passed; the separate exact-source command receipt must show execution and outcome.

## Module-specific threat and residual work

Heading/class-count theatre, stale measurements, omitted failures and same-operator processes called independent.

Every final result needs actual source, command, filesystem, backend and honest unexecuted scope.

No assertion of independent operators, physical durability, ordinary Hepta execution or future model efficacy follows from local fixtures.

## Current source and verification

- [`scripts/ci/check_pon_evidence.py`](../../scripts/ci/check_pon_evidence.py).

Run the relevant native package and exact Python test selectors through the protocol CI lane. Preserve source hashes, failures, backend, filesystem and process/host scope. Historical evidence is never relabelled as current.
