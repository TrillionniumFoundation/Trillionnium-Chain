# Native demand acceptance — 2026-11-07

This record separates implemented native mechanisms, actual execution observations, and business acceptance that still needs independent material. The implementation is published in [draft PR #779](https://github.com/TrillionniumFoundation/Trillionnium-Chain/pull/779), stacked on [#777](https://github.com/TrillionniumFoundation/Trillionnium-Chain/pull/777). The existing integration candidate remains #688.

## Exact implementation and publication boundary

| Item | Identity |
| --- | --- |
| Chain implementation actually compiled and tested | `690f710c1b6808787996e86aa4c36bd53e1f3939` |
| Implementation tree | `b9ff2e5c4ca6e465b86cb4b2bd466ad831147899` |
| Parent demand/evaluation implementation | `ce9b9f734b99c0c7d0c0264e2819020e0bb9a5db` |
| H execution source canonical SHA-256 | `f9b57e33935e7c767accd80b193b88bc51d42ff1e1e6d33d9da4d5f60725ee98` |
| Hepta implementation actually tested | `e0a3bd2bde77c58a0ae7d211214f326371a72a4a` |
| Hepta published evidence head | `9c352c77d21923eb7c2022c96496228ee428d278` |

The H execution checkout materializes all runtime, test, configuration, script and documentation files: 2,254 entries / 35,472,819 bytes. Its original source manifests explicitly list 8,457 unmaterialized historical archive entries. The separate publication worktree restored all 10,711 tracked paths / 1,028,138,715 bytes, including 9,501 unique blobs. Its actual bytes, Git blob identities and executable modes were verified, with zero missing objects and a clean index/worktree. It did not change the execution checkout. Each new run verifies the exact implementation HEAD, tree, clean state, tracked bytes and modes before and after execution.

The cloud executor disconnected after two local evidence-only commits, `478eae32749be622a4b94ce1b8573842f8370ff5` and `2995df5eeee3d18bc1b857874e5bcdd914a8b4dc`. The original task directory was absent when the executor reconnected. Those unpublished commits and raw logs were not retrieved. Their reported prior passes are not substituted for the new H receipts archived here. The implementation had already been pushed and verified before that loss. The new H runs, the failed original H Node attempt, and all recovery failures remain separate observations.

## Implemented native mechanisms

### Funded task admission and arbitration

[Funded Service Task V1](../../docs/development/specs/pon/FUNDED_SERVICE_TASK_V1.md) introduces the explicit classical `funded-service-contract-dev-v1` profile before genesis/bootstrap. The TSC1 task freezes the request, provider, model, input, output specification, qualified-work reference, evaluation protocol, fee schedule, dispute policy, arbitrator, escrow and deadlines. Original provider delivery, ordinary payer acceptance, TSD1 arbitration and expiry all use the native monetary owner.

Arbitration can pay the original provider or refund the original payer from the original whole escrow. It cannot invent a recipient, payment amount or new balance. Refunds are not provider service revenue. A committed qualified-work reference is not native registry membership or an independently established useful-work claim. A separate arbitrator key is not proof of independent control.

This is a new Legacy/Authenticated development profile. Unsupported permanent-growth and PQ combinations reject explicitly. Existing ordinary Task acceptance semantics are not silently migrated.

### Native evidence and durable reconciliation

[Native Task Evidence V1](../../docs/development/specs/pon/NATIVE_TASK_EVIDENCE_V1.md) uses sealed M12 readback and actual Node replay of funding, provider receipt and payment. JSON exported to a caller cannot become authority merely by being imported again.

The reconciliation journal retains checked prefixes across restart, reorganization and caller consumer epochs. Exact replay does not append another record; truncation, forks and exhausted bounded capacity reject. A consumer epoch is not a network epoch proof. Reorganization retains historical work/cost while recalculating current payment membership. Only the typed native payment-not-confirmed outcome denotes absence; unrelated errors remain errors.

The historical active-anchor check also rejects a real admitted branch that was never the active branch at the claimed generation. Genesis generation zero has its own exact rule. Growth evidence uses its original metadata transaction owner; that does not enable the unsupported TSC1 Growth profile.

### Prospective operation before the output exists

[Native Task Operation V2](../../docs/development/specs/pon/NATIVE_TASK_OPERATION_V2.md) adds a fresh journal/application namespace. Reserve and begin bind an immutable claim/task/contract/operation/provider/target scope and resource cap without predicting an output or accepting a caller-selected payment amount.

The original Node grants begin once and retains its protocol/operation fence before returning `New`. Reopen, a second journal or a lost acknowledgement cannot create a second dispatch grant. Actual output and provider receipt are bound only after separately authorized work. The first delivery remains pinned across reorganization and cannot be replaced by another output or receipt. Historical costs and completed NoGain work survive later branch changes; a NoGain service fee never becomes an improvement bonus.

The four cost fields remain owner declarations, not independent physical meters. The generic Rust owner callback remains a trusted boundary. Target permission, authentic external receipts and global deduplication across independent Node databases still belong to the target owner. Restoring every local and external fence from old copies is outside the local guarantee. Historical V2 payment observations do not assert present-branch finality.

## Actual H execution

User-requested compute preference was HeptaRuntime Colab/Kaggle. No configured callable entry was found in the available tools and scoped tracked metadata. These CPU checks used the existing HeptaRuntime desktop host; no Colab/Kaggle allocation, external training run or model-efficacy measurement is claimed.

Rust/Cargo 1.95.0 and the original package profiles were used. No CARGO_PROFILE override, RUSTFLAGS, encoded flags or compiler wrapper was introduced. Cargo build jobs are two and libtest threads one. OpenSSL 3.5.9 was prepared from the pinned source and its actual executable/libraries were hashed, with a real ML-DSA-65 sign/verify and wrong-message refusal. The Python oracle receives the explicit executable/version/SHA binding.

| Exact-source gate | Actual result |
| --- | --- |
| M06/M00/M12 core suites, all targets and features | 32 targets; **388 passed, 0 failed, 10 ignored** |
| Workspace Clippy, all targets/features, `-D warnings` | Exit 0 |
| Workspace formatting check | Exit 0 |
| Locked/offline root Cargo metadata | 26 workspace members / 180 resolved packages |
| Locked/offline fuzz Cargo metadata | 1 workspace member / 147 resolved packages |

The [core receipts](core/summary.json) preserve each exact command, actual exit, stdout/stderr hashes and unchanged source identity. [Per-target count verification](node/audit/core-target-counts-690f-v1.json) keeps zero-test examples and ignored cases separate. No nested harness summary or benchmark is added to the pass count.

The three newly executed Python groups are 52 demand/upgrade checks, 131 retained model/evaluation/reward checks and 103 CI-contract checks: all passed, with no skipped, failed or error results. These results bind the implementation above, not a later documentation commit. The [full-worktree static receipts](publication/static-implementation/summary.json) additionally record 43 source-integrity, 37 research-integration and 50 repository negative tests, all passing. The source checker verified 580 exact blobs while retaining `HOLD_NO_GO` and all unsupported activation flags. Repository links and whitespace checks passed. Publication-tree checks are independently repeated after the evidence commit; their exact head and receipt digest are recorded in the PR publication readback.

## Complete Node inventory: coverage and failures

The actual locked Cargo metadata contains 91 Node targets: one library, one binary, 69 integration targets and 20 examples. The original command was:

```text
cargo test --locked --offline --manifest-path trillionnium/Cargo.toml \
  -p trnm-pon-node --all-targets --all-features --no-fail-fast \
  -- --test-threads=1
```

Compilation completed in 21m49s. The original H job then reached its 7,200-second process limit and ended with exit 124. It did not emit an original closing `result.json` or `source-after.json`. The authoritative H terminal status and actual retained bytes are archived; a subsequent observation is never relabeled as the missing original closing receipt.

The failed-attempt auditor verifies the 91-target metadata, original recorder identity and source/input hashes. It excludes nested libtest summaries, keeps ignored cases separate, and refuses ambiguous attribution. In the original attempt, 30 targets completed (26 passing targets and four failing targets), one was interrupted and 60 had not started. Completed-target totals were 1,254 passed, eight failed and 40 ignored. These totals do not describe the unstarted or interrupted targets.

The independent continuation selected exactly the 61 unfinished targets: 41 integration targets and 20 example harnesses. It ended normally as a failed test run, native Cargo exit **101**, without a process timeout. Its source-before and source-after snapshots are present and identical. The original 30 completed targets were not rerun or replaced.

| Counted complete target summaries | Targets | Passed | Failed | Ignored |
| --- | ---: | ---: | ---: | ---: |
| Original attempt | 30 | 1,254 | 8 | 40 |
| Independent continuation | 61 | 294 | 7 | 15 |
| Cross-run inventory coverage | **91** | **1,548** | **15** | **55** |

All 91 metadata targets now have an unambiguous complete summary. There are no measured or filtered counts. The original partial `model_composition_v4` segment is retained and excluded from sums; only its preassigned continuation target contributes. The [91-target report](node/audit/node-91-target-report-v1/node-coverage-report.md), [structured summary](node/audit/node-union-finalization-v1/coverage-summary.json) and [complete attribution audit](node/audit/node-cross-run-coverage-v1.json) bind every counted summary to its source run, target identity and exact raw-log byte interval. **This is complete counting coverage across two invocations, not a single successful complete Node gate. Qualification remains false.**

The five native targets have observed complete passing summaries: `no_gain_fees` 2, `funded_service_contract` 4, `native_demand_evidence` 2, `native_task_operation_v2` 3 and `native_active_anchor` 2, totaling **13 passed, no failed or ignored cases**. The funded-contract target belongs to the original attempt; the other four belong to the continuation. These observations do not replace the original missing source-after receipt or any of the 15 failures.

The continuation's seven failing cases are distributed across `native_node` (2), `public_cli` (1), `public_intake_v2` (2) and `public_pool_cli` (2). The [refined continuation diagnosis](node/audit/remainder-failure-diagnosis-v2.md) records five direct primary-panic `PUBLIC_HOST_KERNEL_PARENT` failures and one distinct `PUBLIC_MUTATION_CPU_BUDGET` refusal during complete-page import. The seventh case receives EOF before its receiver readiness line and then `Disconnected`; its own test progress line also contains the kernel-parent marker, but inherited stderr lacks the child identity needed to prove which child emitted it or that it was the sole cause. The earlier conservative extraction remains archived. Across both runs, this gives eight direct fixed-parent failures, three CPU refusals, three PQ witness failures and one readiness/channel failure with the stated attribution limit.

### Diagnosed original failures

The original library target completed with 1,139 passed, five failed and 31 ignored in 5,106.26 seconds. Two 65,536-key continuity/reorganization tests passed. The five failures are retained:

| Failure | Evidence and limit |
| --- | --- |
| Large Legacy genesis / held admission | The 8,625,548-byte state used 2,686,699,580 ns paid CPU in 2.718308382 s wall time. The original 2 s credit plus actual refill was exhausted; final balance was −10,647,018 ns. Active state remained unchanged on refusal. This was a CPU refusal inside the original 10 s deadline. |
| Final authenticated history page | Pages 0–5 succeeded; page 6 returned `PUBLIC_MUTATION_CPU_BUDGET` and kept the seed active. The 13,429,683 ns final positive balance does not prove sufficient headroom at an earlier checkpoint/reserve. The same operation owns the 25 ms termination reserve. Existing observations do not identify the unique internal rejection point. |
| NPQ6 invalid-signature/restart case | The retained parent trace records `PQ_WITNESS_DEADLINE` at the original 250 ms exchange limit; a later request sees the same owner unavailable. The request-order inference is distinguished from a directly observed signature-recovery success. |
| NPQ6 cleanup-sentinel case | External witness CAS committed, then response write hit broken pipe. The child handle took about 276 ms, including about 160 ms commit and 108 ms reply signing. Parent phase details reached the original log cap, so the precise parent refusal is not asserted. |
| NPQ6 replay/restart case | First legal submit returned `FRAME_EOF`. Detailed phase observations were unavailable after the original log cap. Replay/restart success was not reached or certified. |

All three NPQ6 cleanup records confirm child exit, successful cleanup and preservation of the primary error. They are not evidence of child crashes. Transport failures do not justify reusing a fail-closed witness connection or replaying an uncertain CAS.

The original run also found failures in architecture delivery comparison, evaluation-sync CLI and mining-service CLI. All three retain `PUBLIC_HOST_KERNEL_PARENT` diagnostics. In architecture comparison, all 18 samples had that error and passed cold-reopen equality; the original assertion failed because it also requires an empty error array. These samples do not establish the required complete native state or delivery result. A later read-only check confirmed that `/sys/fs/cgroup/trnmponpublic.slice` is absent and the job runs under the ordinary user slice. The source requires the one administrator-provisioned parent, with aggregate CPU ≤25%, memory ≤2 GiB, zero swap/burst and ≤256 tasks, plus actual calling-thread membership. A user-created substitute or a per-job quota is not that parent. This run does not alter host-wide policy or relax the checker. That later probe is not a reconstruction of each earlier sample's instantaneous membership. The [diagnosis](node/audit/node-690f-diagnosis-v1.md) and its structured inputs preserve the distinction.

## Hepta product-owner continuation

[Hepta draft PR #5318](https://github.com/TrillionniumFoundation/hepta-private-ci/pull/5318) continues the existing #5315/#5316 path, based on exact `b8d12ad02a2d8311581a4aa69e6cdf07d18f9758`. It adds 19 production lines to compare the complete request bundle digest with the verified selection manifest after the existing authentication/source checks. Four-stage evaluated NoUpdate, expected head, signature/trust/time checks, owner-checkpoint receipt semantics, operation domains and independent FinalUse/Control boundaries remain.

The actual `e0a3bd2bde77c58a0ae7d211214f326371a72a4a` source passed the original 60-test selector; 662 tests were outside that selector. Crate Clippy fixer and actual helper build also exited zero with source bytes unchanged. Clippy retains two existing vendored warnings and is not described as a warnings-as-errors result. The published head contains 130 evidence files, including 128 raw files / 4,974,975 bytes and 54 native fixture exports / 146,271 bytes. The remote head/tree, manifest and native log were read back and checked.

The duplicate exploratory `34060ab` bridge was not selected; its patch, bundle, failures and independent pass remain historical evidence in Hepta. Its result is not transferred to the selected source. Chain stores only the [interop provenance](interop/hepta/README.md), its manifest and publication receipt; Hepta source and raw logs remain in that repository.

These are deterministic engineering fixtures, including a memory-backed learning checkpoint and test keys. Terminal STOP/ACK and the separate drain assertion are distinguished. Historical readback remains `DENY_ALL`. This is not production installation, independent external adoption or a qualified Chain/Hepta combined deployment.

## Five acceptance obligations

| Obligation | Delivered mechanism/evidence | Still required for real business acceptance |
| --- | --- | --- |
| Native owner evidence and reconciliation | Actual native funding, provider receipt, payment and reorganization observations; V1/V2 journals and chronology/anchor checks | Authorized production owners and durable target receipts; external control/restore assumptions and actual operational deployment |
| Full funded contract and dispute execution | New TSC1/TSD1 development profile with original escrow, owners, deadlines, payout/refund and expiry | Funded real customer contracts and independent dispute operation; ordinary legacy Task migration is not implied |
| Independent customers, funds and evaluation | Fail-closed separation of signed declarations, funding origin and independent acceptance | Auditable control relationships, external budgets and independent data/evaluators; different keys or self-payment do not suffice |
| Prospective cost-matched evaluation | Frozen operation and evaluation references, bounded resource records and separate NoGain fees | Actual measured training, evaluation, retention and service costs, prospective matched controls and independent net benefit |
| Ordinary Hepta loop and Node qualification | Same-source native owner fixtures and full-inventory execution/coverage records | Passing original gates on the required host, real canary/install/next-task/withdrawal/rollback and qualified cross-repository composition |

No external business reuse ratio, independent customer count, real adoption rate or model improvement is fabricated. No improvement bonus is qualified. No production activation, main merge, force push or self-approval occurs. The source contract and evidence checks remain distinct from whole-chain security, economics and model efficacy.

## Reading the evidence

The [acceptance status](ACCEPTANCE_STATUS.json) keeps implementation, target coverage, actual gate outcomes and external business acceptance in separate fields. The [artifact index](ARTIFACT_INDEX.json) records the byte length and SHA-256 of each archived artifact, excluding itself. Copied raw files retain their exact bytes; extraction reports and later diagnosis never replace missing original records.
