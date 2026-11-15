# Committed-source recheck after composing concurrent PoN work

## Result

The native journal continuation has been composed with the latest observed integration candidate, `df927b6ffaecff293b9e9428e3ba516f47cd101a`, using the ordinary two-parent merge `f5e836c2b88f7fe0f7cb3f1992601c6943df733e`. Both lines of development and their original evidence remain in ancestry. The continuation branch was published through the authenticated local GitHub channel and read back at the same merge commit and tree.

On that exact merged source, the two affected journal suites passed 23 top-level methods, the selected Public V3 test subtree passed 59 methods, the recovered MVCC run passed **259** methods with **9** top-level ignored entries, and nine Python control suites passed 395 methods with zero skips. The actual binding/consistency inspectors, locked/offline workspace and fuzz dependency graphs, formatting and recovered strict all-target/all-feature Clippy completed successfully.

The original combined validation contains **23 successful commands and two failed commands**, not 25 passes. A separate recovery preflight and the two unchanged build commands then succeeded. The packet retains **28 guarded observations: 26 successful and two failed**. The first MVCC build failed during linking, before executing any test method; the first Clippy command reported disk exhaustion. Their raw logs and source receipts are preserved alongside the separate successful recoveries.

**Overall qualification remains HOLD / NO-GO.** These are observed source, component, mechanism and integration checks. They do not prove minimum legal work cost, useful model gain, open-consensus security, independent governance, public-service liveness, external-effect safety or whole-chain post-quantum security.

## Execution identities and composition

| Role | Exact source |
| --- | --- |
| Original native cost experiment and first fixed journal suites | `39336622c63df1ae746d83a76bb53202cd01ba17`; tree `42fbd7d5a7f00b75000cb4aa242e578a8f941d59` |
| Earlier source-binding repair and its executed inspectors | `be24e0be2ddf7dfef7e902f6b879cad1f2005ebc`; tree `23dadad580311dba14c6407123d998876a9d5acb` |
| First merge parent, carrying our preceding evidence supplement | `bf010229a877eb7baf162830abf23bb515ac3a36` |
| Second merge parent, current integration candidate at composition | `df927b6ffaecff293b9e9428e3ba516f47cd101a` |
| Newly executed combined source | `f5e836c2b88f7fe0f7cb3f1992601c6943df733e` |
| Newly executed combined tree | `6866639dce1132a1e716505ab4156c43b3ca01b3` |
| Complete tracked source observed before and after every combined command | 27,867 entries; 2,552,906,464 bytes; clean and verified |
| Delivery of this supplement | A subsequent evidence-only child; it is not a new native execution identity |

The original draft-creation precondition correctly refused the stale `da1374a2` integration head before creating a PR. The two newly observed integration commits were imported and reviewed without editing the other workspace. Ordinary merge resolution affected only the shared development-plan appendices and corpus pins. Both plans' additions and a composition note were retained. The merged corpus preserves the 1,079 pinned-path and 987 required-path sets, with the reviewed union of 17 changed existing pin values relative to the common source. All current pin values were checked against actual Git blobs.

The distributed inventory remains 1,573 paths. The current QROM declaration remains 138 local inputs and 16 selected project inputs, with the previously reviewed contract and profile descriptor unchanged by this merge. Its crate-root/literal-data roster is not a complete recursive Rust include/build graph; the cross-root `#[path]` helper limitation described in the [binding supplement](INTEGRATION-RECHECK.md) remains.

The continuation retains the incoming evaluation-quorum validation and lifecycle/gate changes. The incoming Public V3 source change is test ordering; it does not alter the production listener or its budgets. The MVCC change validates stored close-record contents during ordinary and PQ hydration and rejects adoption before the stored close height while retaining current conflict checks. The incoming lifecycle reader checks complete material/producer combinations and proof identities, including losing attempts, and the native workflow gates retain the actual required control rosters. Existing signed domains, stored schemas and Cargo lockfiles are unchanged by the composition.

These incoming changes and their historical failures retain their own record in the [parallel continuation packet](../pon-open-consensus-continuation-20261110-2334/README.md). This supplement adds executions on the combined source; it does not rename those earlier observations. Validation of stored quorum data does not establish evaluator independence, real demand, clean holdouts or model benefit. Reconstruction of some growing historical conflict subsets remains limited by the stored history information.

## Actual combined-source observations

| Command or cohort | Terminal observation | Scope |
| --- | --- | --- |
| Original preflights and separate recovery preflight | All exited zero | Preconditions and source checks |
| `native_owner_journal` | 11 passed; 0 failed; 2 ignored helper entrypoints | Complete affected integration harness |
| `native_risk_ledger` | 12 passed; 0 failed; 2 ignored helper entrypoints | Complete affected integration harness |
| `ingress::public_v3::tests::` | 59 passed; 0 failed; 0 ignored; 1,263 filtered out | Selected subtree only; other Public V3 modules and the complete node harness were not executed by this filter |
| First `trnm-mvcc-fee --tests` command | Exit 101; linker signal 7 / Bus error | No test method executed in that failed command |
| Recovered `trnm-mvcc-fee --tests` command | 259 passed; 0 failed; 9 top-level ignored; 0 filtered out | Package library/integration harnesses with default features; includes all nine evaluation-quorum methods |
| Corpus inspector and its controls | 1,079 pinned blobs consistent; `HOLD_NO_GO`; 59/59 controls | Consistency and refusal mechanics |
| Current QROM inspector and its controls | 138 declared inputs; `CURRENT_MAPPING_REPRODUCED_SECURITY_HOLD`; 14/14 controls | Declared mapping, not a security reduction |
| Proof-profile inspector and its controls | Exact descriptor matched; `PROFILE_BOUND_SECURITY_HOLD`; 26/26 controls | Descriptor binding, not proof-system qualification |
| Authority-effect inspector | Seven routes and 44 source records consistent; security HOLD | Curated declaration scope |
| Source-integrity controls | 43/43 passed | Negative source checks |
| CI-contract inspector and controls | Inspector PASS with `tests_executed=false`; 177/177 controls | Inspection does not execute all workflows |
| Lifecycle V4 controls | 15/15 passed | Retained reader/control suite |
| Factorial native-gate controls | 9/9 passed | Retained workflow-gate suite |
| Shared material-reader controls | 32/32 passed | Retained reader/control suite |
| From-zero controls with the retained actual native stream | 20/20 passed; zero skips | Reader execution on this merge; native measurements remain at `39336622` |
| Repository check | PASS; 6,618 local links; 26 packages and 1,471 Rust files | Pre-supplement merged source |
| Distributed source inventory | PASS; 1,573 embedded paths | Declared inventory consistency |
| Workspace formatting | Exit zero | Original `cargo fmt --all ... -- --check` |
| Locked/offline workspace and fuzz graphs | Both exited zero | Metadata resolution; no fuzz campaign was executed |
| First strict workspace Clippy | Exit 101; explicit `No space left on device` creating temporary rmeta directories | Build-environment failure; no successful lint conclusion |
| Recovered strict workspace Clippy | Exit zero | Original workspace/all-target/all-feature command with `-D warnings` |

The four ignored journal entries are owned subprocess helpers explicitly invoked by their parent controls and are not added again to the 23-method denominator. MVCC's 9 top-level ignored entries are reported as ignored, not silently promoted to passing tests. Its 17 top-level harnesses include the feature-gated `pq_account_owner` harness with zero tests under this default-feature command. The separate Clippy command selects all features; it does not supply all-feature runtime execution. Rust harness rows and Python method denominators are preserved in the raw logs; the [summary](composition-summary.json) lists them separately. No grand total is used to imply broader coverage.

All nine Python suites require terminal `OK`, exact method counts and zero skips. Expected negative-case diagnostics inside a successful control suite remain visible. The source-guard wrappers observe the complete tracked bytes before and after each actual command; those observations are not physical host attestation or proof against every same-privilege change-and-restore between observations.

## Preserved build failure and bounded recovery

The original MVCC command failed while linking the `pq3_quota_authority` test binary and the library test binary. Its log contains linker signal 7 / Bus error and no test execution summaries. The immediately following Clippy log explicitly reports ENOSPC. The MVCC log alone does not establish ENOSPC as the cause of its Bus error, so the two observed error classes remain distinct.

The filesystem subsequently had 151,863,296 free bytes. Recovery removed only this task's generated Rust incremental cache under `target-journal/debug/incremental`, freeing enough space to observe 6,259,265,536 available bytes immediately afterward. Source, lockfiles, observations, the measured cost executable and other workspaces were preserved. The recovery record hashes both original failed receipts and logs before removal and confirms those bytes afterward.

A new guarded preflight passed. MVCC and Clippy then ran with exactly the same original argv, captured environment, source commit and tree. Both completed successfully. These are separate recovery observations; the original exit-101 outcomes remain in the archive. The strict-warning setting, package selection, feature/target selections and original timeouts were not relaxed.

## Original cost experiment remains separate

The six finite construction-versus-rejection CPU cells, 96 constructions, 576 stage observations, 48 preliminary false-transcript hits and all full `Transcript` rejections belong to the [original native report](README.md) at source `39336622`. This composition did not rerun that native experiment.

The 20 actual-stream controls did execute on `f5e836c2`. Their binding record verifies the original stream's SHA-256 `953ef816f391839d1bae8b7c3cb2c6653b2bfad2eb611968288167afcf2d3f7d` before and after the controls. It explicitly records `native_execution_repeated=false` and `native_execution_identity_transferred=false`.

The observed approximately 5.00x to 15.73x ratios compare separately measured preliminary-plus-full-rejection component CPU against per-sample construction CPU including every completed search attempt. Public fixture/task setup is separately recorded. Those finite diagnostic-target measurements are not an admitted-node service amplification factor, an adversarial worst-case bound, or the minimum cost of every legal mining strategy. No forged work was accepted by the full verifier.

## Publication and retained preparation observations

The merge publication's first attempt stopped on a failed GitHub tree GET before a merge commit/ref was published. Its original terminal output is retained. A read-only retry of that tree succeeded, and the unchanged publication helper then verified the parent blobs, target tree and exact two-parent commit, advanced the continuation branch without force, and read it back at `f5e836c2` / `6866639d`. That successful terminal stream is included separately from the failure.

The merge's first-parent whitespace check also remains visible: exit 2 with 1,079 warnings confined to inherited raw evidence. Those original log bytes were retained. The change check relative to the latest integration base `df927b6f` exited zero. Preparation checks, publication observations and independent read-only reviews are archive members but are not included in the 28 guarded execution-command denominator.

This supplement does not claim a hosted workflow pass. A draft PR's current hosted status is a later, separate observation, and creating a draft does not merge or activate the candidate.

## Raw records and remaining obligations

The [composition archive](composition-records.tar.xz) contains **70 regular files**, totaling **2,205,260 uncompressed member bytes**. The [manifest](composition-records-manifest.json) binds every relative path, size and SHA-256. The [summary](composition-summary.json) records all 28 guarded outcomes, exact source identities, actual Rust harness rows, Python cohorts and the retained-stream binding.

Archive bytes: **127,944**. SHA-256:

```text
caf93d3596c53d0131bd9289033d7837e8e5b928b42b0bc360cd6b34513bdc41
```

The archive groups are `committed-f5e836c2` and `composition-preparation`. The original [48-member native packet](raw-records-manifest.json), [66-member binding supplement](integration-records-manifest.json), and imported parallel packet remain unchanged. The complete failure record therefore includes the original FIFO controls, initial offline dependency failures, introduced binding failures, incoming quorum/lifecycle/workflow/service failures, current build failures and their separately scoped repairs or recoveries.

The remaining obligations include minimum legal cost under setup/cache/nonce/task/multi-target/hardware and classical/quantum strategies; complete useful-work delivery and independent future-task model benefit; joint DAA, timestamp, chainwork and network analysis; public prefix, growth, quality and confirmation probabilities; original public-service deadlines and persistent resource responsibility; evaluator independence; and target-side idempotency, durable journals, reconciliation and `Unknown` recovery for external actions. Same-inode/same-length live journal mutation and lifetime PQ-authentication budget exhaustion/recovery remain open. None is closed merely by this composition or these test counts.

All qualification and activation flags remain false. The new evidence narrows concrete implementation and integration defects while keeping the broader open-consensus claims unqualified.
