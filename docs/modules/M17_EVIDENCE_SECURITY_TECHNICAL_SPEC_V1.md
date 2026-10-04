# M17 Reproducible evidence and semantic contract checks

Revision: invariant-driven revision3. Selected target: `pon-nakamoto-v1`.
[Sole development plan](../development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md); [exact invariant registry](../../config/pon/invariants-v2.json).

## Scope and ownership

Immutable evidence/pon-v1 plus separate current-source receipts.

The claims below apply to their named component and tests, not to an independently accepted full native node.

## PoN State machine

### M17.CheckDetailedContracts

Old reports remain tied to their measured source; newer source is never called tested by rehashing an old pass. Verify original artifacts and measured ancestor bytes; report current-source match separately from historical consistency.

**Atomic/commit boundary:** Verify original artifacts and measured ancestor bytes; report current-source match separately from historical consistency.

### M17.QualifyExecutedCampaign

Keep workcost, invalidproofamplification, diskprocesscrashes, localhostnetwork, actuallearning andreward evidence separate. Retainfailedobservations; requireexternal revieweridentity for independentacceptance, never substitute authoredsubprocesses.

**Atomic/commit boundary:** Immutable evidence artifact manifest; cannot enableproduction.

## M17.HistoricalEvidence

**Invariant:** Old reports remain tied to their measured source; newer source is never called tested by rehashing an old pass.

**Scope:** Immutable evidence/pon-v1 plus separate current-source receipts.

**Atomic boundary:** Verify original artifacts and measured ancestor bytes; report current-source match separately from historical consistency.

**Failure schedule:** Stale digest; Dropped failure; Hidden strongest control; Forged independent or future acceptance.

**Expected result:** Old reports remain tied to their measured source; newer source is never called tested by rehashing an old pass.

**Resource and retention rule:** Binding validation is read-only and does not execute tests or award deployment authority.

## Concrete regression selectors

`scripts/ci/test_pon_evidence.py::EvidenceRejectionTests.test_source_digest_cannot_be_stale`

`scripts/ci/test_pon_evidence.py::EvidenceRejectionTests.test_future_window_claim_rejected_even_after_rehash`

These exact functions contain executable assertions. The registry only checks binding; actual outcomes and source/input identities belong to the separate qualification report.

## Module-specific threat and residual work

Heading/class-count theatre, stale measurements, omitted failures and same-operator processes called independent.

Every final result needs actual source, command, filesystem, backend and honest unexecuted scope.

## Current source and verification

- [`scripts/ci/check_pon_evidence.py`](../../scripts/ci/check_pon_evidence.py).

No test binding or local campaign grants independent acceptance, ordinary Hepta execution or production activation. Preserve the exact source, profile and environment of every outcome.

## Executed evidence and scope

[Responsibility-level evidence navigation](README.md#responsibility-and-evidence) reads
measured commits from immutable receipts. The module's entries in
[module-maturity-v1.json](../../config/pon/module-maturity-v1.json) identify actual callable
owners, controlled entrypoints, backends, persistence and exact observed test selectors.
Run `python3 scripts/ci/report_module_evidence.py --module M17` from the repository
root to see subject-byte and complete recorded-runtime matches separately, plus scenarios
not observed in each package. A byte match is not a new test run or product acceptance.
Historical v1/v3/v4 results are never repinned. The sole plan selects further work.

## Repository delivery versus local files

The current client/session evidence checker requires every declared artifact in an
in-repository package to be tracked by Git, including globally ignored raw logs.
Presence and matching hashes in the author's directory do not establish a complete
checkout. The publication tests exercise actual Git index omission and byte-preserving
addition. Externally supplied historical packages remain explicitly separate from
claims about which files existed in their original measured source tree.

## Executed CI and current navigation

The [CI execution contract](../architecture/CI_EXECUTION_CONTRACT.md) pins real libFuzzer and dependency tools, retains failed receipts/corpora and verifies exact head or prospective-merge identities. The [current implementation table](../architecture/CURRENT_IMPLEMENTATION.md) is regenerated from existing authorities. Source checks still do not establish independent work hardness or model/public-service qualification.

The same workflow adds two native release cost jobs on explicitly identified x64
and ARM64 hosted runners and compares their actual retained artifacts. Complete
challenge/proof/ticket streams, attempts, setup counts and source identities must
agree; measured speeds need not. Missing/failed architectures remain failures.
An explicitly labelled local preflight cannot satisfy the hosted comparison.
Runner/compiler/ELF observations and artifact hashes are retained, without
promoting physical independence, GPU coverage, resource fairness or work hardness.
