# PQ workflow continuation: fixes, receipts and open gates

Status: **HOLD — bounded engineering progress; no whole-chain acceptance or activation.**

The publication code checkpoint uses Chain input `38cf428103f48879fcc6b7dc0fc523d5c58ff2e0` plus [publication-source-files.json](publication-source-files.json). Its immutable Git commit is the selected code identity. The earlier validated input `38543c96cabb0d63a4a99d149a30a270d0c2c107` and exact changed files are retained in [source-files.json](final-composition/source-files.json). See [PUBLICATION_SCOPE.md](PUBLICATION_SCOPE.md): validation of the newer Growth composition is pending at checkpoint creation. The paired runtime candidate is **`484ce165522026d915c4cf526cd7df2effab632c`** in [runtime Draft #4812](https://github.com/TrillionniumFoundation/hepta-private-ci/pull/4812). The pair is fixed for review; a complete ordinary deployment profile and a real task/multi-node run on this pair remain unqualified.

The existing [Chain Draft #688](https://github.com/TrillionniumFoundation/Trillionnium-Chain/pull/688), sole [development plan](../../docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md), original 4-second/16-hostile-producer criteria and negative activation assertions remain the owners of acceptance. This is an evidence record, not a parallel plan.

## Changes and why they are needed

1. **Prospective source composition.** Two correctly ordered parents do not prove that a merge commit contains their reviewed composition: an arbitrary tree can be attached with `commit-tree`. The CI source guard now independently reproduces the canonical tree and compares it to the supplied merge. The divergent case uses an empty-template bare repository, object alternates and a controlled Git environment. Local/global configuration, untracked attributes and external merge drivers must not inject, omit or silently resolve source. New controls cover fabricated trees, real conflicts, external drivers and union/binary attribute overrides.
2. **Exclusive cache ownership.** PublicServer could accept rejection-cache setup before arithmetic-cache setup, or replace a rejection-cache owner by repeated setup. Both cache selection orders now reject mixed ownership, and repeat setup is rejected. Four real native integration tests verify refusal and preservation of the cold CPU budget/profile for either valid single-cache choice.
3. **Quantum candidate-check accounting.** In upward-rounding mode, nearest-rounded sums could start a candidate check before exact readout completion or omit a check already in progress. The simulator now uses the same exact Fraction stage boundaries as the resource clock. Six controls cover cancellation, the horizon, exact boundaries, nonzero start time and full per-processor checking cost. The existing domain-setup fixes are preserved.
4. **Runtime clock/frontier separation.** The companion runtime commit rejects identical canonical clock/frontier paths before trust clients or local owner creation. It includes both configuration directions and a pre-service constructor control. [Runtime evidence](https://github.com/TrillionniumFoundation/hepta-private-ci/blob/484ce165522026d915c4cf526cd7df2effab632c/evidence/pq-final-use-endpoint-separation-20261104/README.md) records the separate native-test limitation.

The source inventory includes the new native test and the concurrently added W1 artifact module. CI includes the new quantum test module. Corpus pins were refreshed for the exact changed inputs without changing any acceptance assertion. Concurrent Cell storage, W1 v2/QROM candidate and migration records through `38543c96` are retained. The final composition was rerun rather than inheriting the earlier `44ebe1a` results; [pin changes](final-composition/pin-refresh.json) preserve the exact adjustment.

## Actual verification on the recorded 38543c96 composition

| Check | Result | Receipt |
| --- | --- | --- |
| Source integrity plus native-command recorder controls | 47 passed: 43 source controls and 4 recorder controls | [log](final-composition/source-integrity.log), [command](final-composition/checks.json) |
| Quantum candidate/network/resource-clock controls | 63 passed | [log](final-composition/quantum-clock.log), [command](final-composition/checks.json) |
| PQ source-coverage and claim controls | 57 passed | [log](final-composition/pq-controls.log), [commands](final-composition/checks.json) |
| Actual PublicServer cache integration tests | 4 passed, 0 failed/ignored/filtered; Cargo exit 0 | [log](final-composition/native-cache-modes/cargo.log), [receipt](final-composition/native-cache-modes/result.json) |
| Fixed source corpus | 460 exact blobs checked, exit 0, status remains HOLD_NO_GO | [log](final-composition/pq-corpus.log), [command](final-composition/checks.json) |
| CI structural contract, distributed source inventory, shell syntax, workspace Rust format, whitespace | PASS | [commands](final-composition/checks.json) |
| Runtime repository formatting | PASS on exact runtime input plus its two-file patch | [runtime receipt](https://github.com/TrillionniumFoundation/hepta-private-ci/blob/484ce165522026d915c4cf526cd7df2effab632c/evidence/pq-final-use-endpoint-separation-20261104/repository-format-receipt.json) |
| Runtime host native tests; complete native workspace tests and strict workspace Clippy; original performance campaign; actual paired task/multi-node campaign | NOT RUN in this continuation | These remain required gates |

The final native run took 82.612371 seconds including incremental recompilation with Rust/Cargo 1.95.0, default features, locked offline dependencies, one build job, disabled incremental, debug information disabled and Node test optimization set to zero. These are recorded local build settings, not a change to production criteria. The actual HEAD, eight explicit file/lock bindings and an aggregate of 1,210 native/config inputs were unchanged before and after execution. The four tests take the real public constructor path; they do not exercise the original state/SQLite business baseline or hostile network campaign.

The build retained `trnm SQLite I/O boundary UNQUALIFIED: RUSTC must be absolute`. That warning is not hidden or converted into SQLite/host qualification. The actual test executable's hash is in the native receipt. The initial `44ebe1a` native run remains separately recorded at [its original receipt](native-cache-modes/result.json); its SHA-256 was unchanged during the final rerun.

## Retained failures and provenance limits

- The initial private native attempt was interrupted by executor loss. It has no exit result and remains **UNKNOWN**. Recovery also found an actual checkout of `a9b8602706b66adba82655c3c2ce90bde88620a2` where the initial attempt had declared `7a88207db3c50d2789787ff3af6f3b8ff7620ac5`. The patch-file hashes agreed, but that did not establish the whole-tree identity. [The recovery record](native-cache-prior-unknown.json) preserves this error. The later successful run verifies the actual `44ebe1a` HEAD and does not inherit any result from the interrupted attempt.
- The first corpus check refused missing pinned evidence in the sparse checkout; after 17 pinned inputs were materialized, it correctly refused a further missing qualification README. Both failures remain in [pq-corpus.log](pq-corpus.log) and [pq-corpus-materialized.log](pq-corpus-materialized.log). The final pass followed exact-object materialization recorded in [materialized-pins.json](materialized-pins.json). A corpus pass is not a complete raw-checkout qualification.
- The six new quantum controls initially had four failures. [The original red output](quantum-before-fix.log) is retained with its [original source identity](quantum-baseline-source.json). The final 63-test result above is the re-execution on the integrated candidate.
- The runtime's earlier isolated harness outcome is UNKNOWN/INCOMPLETE. Repository formatting later passed, but host native tests were not run. A fresh Unix socket probe returned EPERM. No native success is inferred from formatting or source inspection.
- GitHub's prospective merges, previously published executables and old V8 runs are separate identities. No earlier result is transferred to this pair. Remote CI was not awaited and is not claimed as passed.

## Workstream disposition

| Workstream | What this record advances | Remaining closure condition |
| --- | --- | --- |
| P0 | Exact source input/patch identities, stronger composition verification, source asset/owner inventory and partial call map | Complete deployed profile, exhaustive authority map, final-binary provenance and paired execution |
| A1 | Explicit runtime clock/frontier path separation | Ordinary tasks, payments, CURRENT and FinalUse under one qualified PQ policy; GrowthV2/PQ entry composition |
| A2 | Existing account-inventory/migration history retained | Full source-state conservation, debt/nonce/task/generation migration and cross-activation reorg/recovery acceptance |
| A3 | External clock/frontier configuration constraint strengthened | Provider-effect/consumption/revocation coordination; directory rollback, clone and crash recovery with independently operated witnesses |
| B1 | Real constructor cache-owner regressions now execute | No-attack full business baseline, native GrowthV2 calls and state-scaling costs |
| B2 | Cache setup preserves the original cold CPU domain/profile | End-to-end budgets, actual cancellation, service/Cell/sync isolation and all original 4-second/16-producer subconditions |
| C1 | Existing actual-cost research retained | Cheapest legal solver set, task selection and cross-attempt reuse; honest FLOPs are not an attacker-cost lower bound |
| C2 | Candidate-check accounting corrected and regressed | Actual marked-domain assumptions, calibrated costs, private branches/DAA, deployment-specific chain-growth and reorg conclusions |
| D | Incoming W1 v2 candidate and QROM budget records retained; no promotion | Complete W1 relation, security conditions and an end-to-end benefit over additional proving/verification/transport cost |
| E | Reviewable paired source and reproducible narrow checks | Real task/multi-node records, A/B engineering acceptance, explicit treatment of C assumptions and independent acceptance |

See [P0 baseline](P0_BASELINE.md) and [machine-readable reproduction record](reproduction.json). Issues [#629](https://github.com/TrillionniumFoundation/Trillionnium-Chain/issues/629) and [#639](https://github.com/TrillionniumFoundation/Trillionnium-Chain/issues/639) remain open.
