# Recovery floors and native provider readback V4: retained evidence

Status: **HOLD / RESEARCH ONLY**. [Draft PR #837](https://github.com/TrillionniumFoundation/Trillionnium-Chain/pull/837) continues [PR #826](https://github.com/TrillionniumFoundation/Trillionnium-Chain/pull/826). All five whole-chain blockers remain open. No production root, key, service, effect or algorithm migration was activated.

## Corrected frozen-source local execution

The executed source is `0d99924005b70b1308bf3e62c53e9300fbb4aac4`, tree `9358521d635df532d71b807fab8cc3029ff83912`. Its local campaign completed **42/42** recorded commands with exit 0. The packager verifies their exact names, order, argv and raw-log hashes against the fixed 42-command plan before producing this document.

The [before](attempt-0d999240/source-before.json) and [after](attempt-0d999240/source-after.json) receipts record identical **11541 tracked entries / 1119133792 bytes**. This is observed endpoint consistency. Continuous immutability and independent executor authentication are not established. A later evidence delivery commit is not relabeled as the executed source.

Retained inputs include the [qualification record](qualification-record.json), [commands](attempt-0d999240/commands.json), [parent summary](attempt-0d999240/summary.json), [fixed command plan](exact-command-plan.json), [V4 summary](attempt-0d999240/native-v4/summary.json), and [V3 summary](attempt-0d999240/native-v3/summary.json). Native selectors and summaries are reparsed from raw logs and compared with inventories in the frozen runner source.

| Native component | Passed tests |
| --- | ---: |
| V4 / recovery-floor | 8 |
| V4 / provider-readback | 12 |
| V4 / callback-budget | 6 |
| V3 / crypto-structure | 10 |
| V3 / crypto-native | 8 |
| V3 / root-kernel | 12 |
| V3 / root-owner | 20 |

| Python suite | Observed tests |
| --- | ---: |
| custody-controls | 20 |
| migration-controls | 33 |
| continuation-runner-controls | 3 |
| feature-and-registry-controls | 15 |
| dependency-controls | 42 |
| native-runner-controls | 11 |
| ci-contract-controls | 108 |
| source-integrity-controls | 43 |
| pq-source-controls | 55 |
| lifetime-controls | 58 |
| claim-controls | 49 |
| authority-controls | 18 |
| v2-policy | 26 |
| v2-signature-structure | 17 |
| v2-provider-structure | 15 |
| v2-signature-native | 14 |
| v2-provider-native | 6 |
| v2-journal-native | 14 |

The retained default crypto and release-library runs report **175 / 43** passed tests. Strict workspace, all-target, all-feature Clippy completed with `-D warnings`. The default/all-feature/fuzz dependency-graph commands, formatting, repository links, inventory, implementation summary and **771-pin** source-corpus checker also returned exit 0. The feature/registry suite contains 15 actual tests.

Default crypto already includes the ten V3 structural tests. Counts overlap and do not count independent security properties. **The local campaign did not execute the full protocol lane or all workspace tests.**

The V2 durable-journal suite also records SQLite connection `ResourceWarning` messages and still reports 14 tests with exit 0. The raw warnings are retained. Source review identifies transaction context managers without explicit connection closure in its fixture; the owner's regular database path closes in `finally`, while initialization PRAGMAs precede that protection. No allocation tracebacks were collected to uniquely attribute every warning. No zero-warning, data-corruption or resource-exhaustion conclusion is made. The [runtime readback](runtime-after-campaign.json) is explicitly observed after the campaign.

## Corrected source still fails the original hosted native campaign

The corrected source's [original native campaign result](hosted-corrected-details/native-campaign-result-0d999240.json) records a successful release build followed by **0/3 successful runs**, each returning **101**, with `ORIGINAL_THREE_RUN_CAMPAIGN_FAILED`. Its source-after receipt binds the same corrected commit and tree. The underlying cause has not been established. The [retained job-log archive](hosted-corrected-details/archive-index.json) includes job 129060656332 from run 42587477765.

This failure remains a failed acceptance requirement. Passing local components and successful diagnostic/source-matrix workflows do not supersede it, establish full-chain qualification or authorize a workload/budget change.

The [selected artifact readback](hosted-corrected-details/native-artifact-selected/artifact-readback.json) preserves 40 raw members checked against the artifact index and explicit projections of the three large reports. The complete downloaded ZIP matched GitHub's SHA-256, and each full report matched its recorded hash before projection. The full ZIP and large reports are not included in this repository subset; their provider URL and expiry are recorded. All nine projected phases report unmet finite criteria, incomplete signed-round confirmation and unequal receiver/client state. These are observed failed predicates, not an established underlying cause.

The [corrected-source hosted snapshot](hosted-source-0d999240.json) is dated **2026-11-09 09:04:24 UTC** and reports: **completed/failure: 3, completed/success: 6, in_progress/None: 4**. Workflow association with a head does not prove every job ran that exact head; jobs may use prospective merges. Pending states remain pending. Snapshots retain run IDs, status, conclusion, attempt and URLs and do not predict later results.

## Initial local attempt: incomplete parent, complete child observations

The initial source was `db48af79b9686f2c7bb50ff7dde9b2233fe32fb8`. Its [commands](attempt-db48af79/commands.json) retain **39 completed commands with exit 0** out of the retained harness's 41 planned commands. There is **no original parent summary or source-after receipt**. These missing records remain missing. The separately generated [recovery observation](initial-attempt-recovery-observation.json) does not impersonate an original completion record.

The initial Clippy log records the Node compiler subprocess receiving **signal 9 / SIGKILL**. The outer command return code and termination cause are unrecorded. No diff-check execution record is present. An empty list of recorded nonzero exits therefore does not mean the parent campaign passed.

Its V4 child completed 26 tests and V3 child completed 50 tests. Each has matching own source-before/after receipts, command hashes and summaries. Those child endpoints do not supply the missing parent endpoint.

Separate hosted observations at db48 diagnose an unused `RootStateV3` import, and a workspace build with **build exit 0 / artifact-check exit 1** caused by an outdated exact feature list. The observed Node list was `default,pq-native-openssl,pq-root-v3`; M06 retained `default,pq-native-openssl`. The [hosted artifact archive](hosted-source-details/archive-index.json) preserves the full ZIP, diagnostic job logs and member/hash verification. The hosted unused-import diagnosis does not explain the local SIGKILL.

Corrections include the unused import, exact per-crate and ancestry feature checks, report fields, AST refusal controls, mandatory repository-truth execution and reviewed pins. Native test bodies, protocol parameters and original CPU workload/budget requirements were not changed by these CI fixes. Added Python controls are not described as an unchanged test count.

## Execution environments differ

The initial local execution used **OpenSSL 3.5.7** from `/usr`, with its [recorded environment](attempt-db48af79/environment.json) and version log retained. The corrected execution uses a prepared static **OpenSSL 3.5.9** installation, a different configured host/check-out environment and isolated dependency/target directories. These are **not the same environment**, and this evidence makes no isolated causal or performance comparison between them.

The [corrected environment](attempt-0d999240/environment.json), [provider selectors](provider.env) and [preparation archive](preparation/archive-index.json) retain the actual provider receipt, source-archive digest, preparation-script hash and five native-input hashes. The CLI SHA-256 is `d4c13f27791f214bc9ea80acb1ed51fa1fbc7c17db72b9a7c54e24bf0accc171`. The packager checks those five existing input files against the receipt. Preparation smoke checks are not the target ML87/SLH native tests; those results come from the native runners. `upstream_full_tests_run=false` and `independent_cryptographic_implementation_claim=false` remain recorded.

The [fetch receipt](fetch-ready.json), preparation/fetch/control logs and [development archive](development/archive-index.json) retain setup and pre-freeze observations separately. They are not substituted for the frozen-source campaign.

## Engineering additions and retained boundaries

The [external recovery floor](../../docs/security/PQ_ROOT_RECOVERY_FLOOR_V4.md) binds complete enrollment and an exact signed ancestor. Pending recovery still requires signed replay, a fresh exact-target anchor observation and explicit completion. Its conditional guarantee requires a sufficiently fresh authenticated pin surviving outside restored state. Original unpinned V3 APIs and the owner-plus-all-anchor common-restore boundary remain. An old valid floor cannot prove absence of later revocation.

Writer and anchor callbacks recheck original budget identity, deadlines and cancellation on error and successful returns. Observed external cancellation is latched; a signal set and cleared entirely between observations is outside that guarantee.

The [provider readback](../../docs/security/PQ_ROOT_EFFECT_READBACK_NATIVE_V4.md) binds both signature families to original operation/material/provider identity, durably records lookup requests, retains pending/Unknown states and revalidates root history around callbacks. It grants no M15/FinalUse permission, execution, redispatch or compensation authority. All retained orphan declarations remain visible; a newer notification refused while an older epoch remains unresolved must be retained by the caller. There is no automatic reorg feed or multi-epoch pending queue.

Custody and [migration review](../../docs/security/PQ_ROOT_MIGRATION_REVIEW_V1.md) check finite declarations and referenced bytes. The default custody review retains **11 missing items**; migration remains `proposal:null`. Distinct labels and matching bytes do not authenticate operators, devices, backups, complete key populations, current authority or successor proofs.

All native tests use research keys and same-process fixtures. Provider signatures authenticate declarations, not real payments, APIs, resource consumption or compensation. A supplied floor creates neither independent storage nor trustworthy jointly restored currentness.

## Whole-chain qualification stays HOLD

The finite dependency register reports **37 source files and 16 hash-use groups**, snapshot `d3bd30198f56d855bbae4644e0a1f31e8ea9d0df13644b6589f6a01e25e3a4a1`. Shared SHA-512 use remains in the same primitive accounting. All eight actual domain failure bounds are `null`; splitting the target into eight shares only allocates a target.

| Open gate | Material still required |
| --- | --- |
| Independent custody and recovery | Authenticated operator/device/backup/recovery relationships, complete current/historical rosters, and independent operational review |
| Common restore and currentness | Authenticated sufficiently fresh state surviving the common restore set, pin acquisition, age/clock policy and recovery procedures |
| Actual external effects | Current effect admission, provider lifecycle and request authentication, real payment/API/resource evidence and actual reorg/liability/compensation reconciliation |
| Algorithm replacement | Explicit versioned implementation, verified current authority and successor possession, complete history/liability continuity and applicable new-profile security arguments |
| Lifetime and composition | Complete key/epoch population, shared online/offline query scope including preprocessing/advice, concrete reductions and whole-chain bad-event coverage |

The [earlier-source hosted snapshot](hosted-prior-a44344b2.json), [db48 hosted snapshot](hosted-source-db48af79.json) and older [V3 qualification record](../pq-root-native-v3-20261109/qualification-record.json) retain prior failures. The db48 and corrected-source original campaigns each remain 0/3; neither is rewritten by this local component result.

## Retention and reproduction

The [actual recovered harness](run_campaign_v4_recovered.py) preserves the session-bound commands; the [initial harness](run_campaign_v4.py) is retained separately. Portable component invocations remain in the [V4 runner](../../scripts/ci/run_pq_root_continuation_v4.py) and [V3 runner](../../scripts/ci/run_pq_root_native_v3.py), with explicitly configured prerequisites.

Each archived directory has an `archive-index.json` mapping original files to identity or deterministic gzip retention, with original and retained sizes and SHA-256 values. [Packaging checks](packaging-observation.json) identify checked command logs and scope. The [retained-byte manifest](archive-verification.json) excludes itself and authenticates no executor or security property. The unrecorded initial Clippy log has a post-recovery byte hash, not a fabricated command-end receipt.

All `.log` files are retained as deterministic gzip, including small or empty logs. Decompression is checked against the original bytes; trailing newlines and warnings are preserved. The [delivery preparation record](delivery-packaging-review.json) retains the pre-publication omitted-log and raw-log whitespace findings. The final exporter requires the full byte manifest, filesystem and Git index to name the same evidence files.

```text
status = HOLD
actual_lifetime_failure_bound = null
whole_chain_pq_qualified = false
independent_custody_verified = false
actual_external_effects_verified = false
native_m15_production_integration_complete = false
migration_authorized = false
production_activation = false
```
