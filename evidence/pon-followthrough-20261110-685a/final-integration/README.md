# Merged checks and retained failed observations

Status: **draft review only; security HOLD; native full-suite success is false**.

This evidence-only child preserves every existing blob and mode in M1
`8ab052065ae8307b1ab2c9d42b0dca229a5a3b9d` (tree `218f49c3a4b1495f90c0d885433c0ec9ad51fb3c`). It adds this directory only. The E1 commit identity
and its own repository/source checks are recorded by the publication recorder
after the commit exists; this document does not anticipate those outcomes.

## Separate source and execution scopes

* **C2 `8d8c0e64e7a301fc111a6720721a14816639e5aa`** retains the original full node-library result: exit **101**,
  **1,285 passed / 2 failed / 39 original ignored**. Its original-v3 files remain
  in [the original command directory](../native/original-v3/commands.json).
  No nonexistent v3 summary or source-after record is manufactured. The
  [independent v4 followup](../native/followup-v4/summary.json) retains two exact
  original test failures (exit 101), while its other twelve commands exited 0.
  Its source-before/source-after bytes equal the original v3 before record.
  Limited focused successes, fresh-probe observations and Clippy remain C2
  observations; they do not replace the failed full suite.
* **C3 `a715b2c8e89732ce356ebae67f978ef232156c04`** actually completed 29 source-bracketed checks: **25 zero exits,
  4 nonzero exits**. The [original summary](historical-orchestration/attempt-03/controller-output/validation-01-summary.json)
  and [all original commands](historical-orchestration/attempt-03/controller-output/commands.json)
  retain the CI-contract/repository failures caused by the stale inline store
  pin, and the ledger negative-control failure caused by a missing historical
  Cargo.lock blob. Driver03 failed and did **not execute its native child**.
  Its unexecuted runner is retained as source, without execution credit.
* **M1 `8ab052065ae8307b1ab2c9d42b0dca229a5a3b9d`** is the normal two-parent merge of C3 and upstream `df927b6ffaecff293b9e9428e3ba516f47cd101a`.
  [Source-only merge receipts](merged-source/summary.json) record that merge
  and its exact corpus/parent binding. They claim no tests. The independently
  executed [38-command validation](merged-validation/summary.json) and
  [raw command list](merged-validation/commands.json) have all required exits
  zero and an identical M1 source bracket. This includes the retained 18 CI
  names and 19 ledger names, corpus/CI/repository/source/report checks, locked
  offline metadata, format, the MVCC library, the nine quorum integration
  tests, the exact cancellation test, four confirmation controls, and strict
  Clippy for four owners with default features and all targets. The full node
  library suite was **not repeated**. Neither parent contributes test credit
  to this cohort, and no hosted Actions completion is claimed.
* **E1** adds original receipts only under `evidence/pon-followthrough-20261110-685a/final-integration/`. Every pre-existing
  M1 blob and mode remains identical. Its separately recorded source and
  repository checks do not rerun or upgrade C2, C3, baseline or M1 tests.

## Retained independent controls and prior attempts

The [initial baseline attempt](baseline-controls/initial/failure.json) stopped
before tests because an orchestration guard refused shallow history. The
[baseline followup](baseline-controls/followup-02/summary.json) ran only two
unchanged selected tests: large-parent passed; inactive-page failed with
`PUBLIC_MUTATION_CPU_BUDGET`. Its full-library success remains null. This is
different from the `OWNER_PUBLIC_SERVICE_UNCLEAN_EPOCH` diagnostic failure in
C2's full run. C2's separate exact reruns both reported CPU-budget failures.
These controls establish neither identical causes nor absence of regression.

Historical orchestration attempts 01, 02 and 03 have separate original output
and bundle directories. Attempt01 stopped at the failed C2 native gate;
attempt02 stopped at its test-count parser refusal; attempt03 created C3 but
failed its own checks. No later observation rewrites any of those outcomes.
The [read-only observer audit](observer-audit-03/summary.json) inspected the
39 original plus 14 followup commands and 121 raw members. It executed no
native tests and created no C3. The original publisher v2 is retained under
`orchestration/unused-publisher-v2/`; its completion path was never invoked.
This publisher loads only its pinned read-only helpers.

[Historical object preparation](historical-lock-materialization/summary.json)
retains the exact 40,365-byte Cargo.lock from its existing selected Git commit
and tree. It restored only that authenticated blob, left HEAD/tree/index/status
and shallow state identical, and ran no native tests. Its original failed C3
read remains recorded. M1 independently passed the unchanged 19 ledger controls.

## Byte preservation and limits

[members.json](members.json) identifies each copied byte count, SHA-256, Git
blob, original source and representation. [sources.json](sources.json) records
command-stream closure, every already-retained C2 member, exact orchestration
identities, and explicit temporary-index/lock exclusions. Historical Markdown
bytes use `.md.txt` names. The source-merge compressed archive is retained as
base64 with an explicit decoded original identity; each old driver's archive
also remains exactly embedded in its pinned source. Two NUL-delimited original
Git index-flag logs are preserved as raw logs, not as executable binaries.

Global shallow history is disclosed; complete global history is not claimed.
Required selected objects, parent paths and materialized source remain checked.
This evidence establishes no cheapest legal work-cost bound, QROM reduction,
public-prefix/chain-growth/chain-quality bound, confirmation failure probability,
model benefit or production qualification. All qualifications remain
**HOLD/false/null**. The candidate remains a draft for review.
