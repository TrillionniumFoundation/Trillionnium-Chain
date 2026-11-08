# C6 later CI failures and base96 History readback

This is read-only evidence from existing GitHub jobs. It preserves the 18 newly observed failures in the frozen 08:10 UTC C6 snapshot, plus the existing base96 History diagnostic run. No CI was rerun or dispatched, no source changed, no operation was created, and no budget was extended.

## Snapshot and identities

The unchanged snapshot has SHA256 `1e65f320701a9f1e948a8b4930f97835ee9c02d926446e081ecd07d9ca028f3e`. Independent reads span 2026-11-08 08:10:27.088242–08:10:46.546382 UTC; this is not an atomic snapshot. Exact C6 is `2bdd252aa6c300b7431b9ee897b254b7953cf562`, tree `ac3cb7171c429fa5e12e29ee16839fa6f49f1b81`.

That snapshot contains 105 checks: 58 failed, 42 succeeded, 3 skipped, and 2 still in progress. This bundle does not refresh the global count or claim all CI is terminal. 'New' means newly present in the failed-check set, not necessarily a later wall-clock failure.

## All 18 newly observed failures

Every row has its original complete job metadata. Ten first failures are source identity or ordered-parent preconditions; their business steps were skipped. Exact new logs from three of these jobs show `ValueError: merge parents differ from the event base and candidate`. The other seven are classified from their own metadata, without inventing an unobserved error string.

| Job | Name | First failing stage | Category |
| --- | --- | --- | --- |
| 128662532819 | prospective-merge (rust-baseline) | Verify immutable source identity | pre_execution_source_guard |
| 128662229998 | prospective-merge (external-evidence-contract) | Verify merge identity and exact ordered parents | pre_execution_source_guard |
| 128662229957 | prospective-merge (fuzz-smoke) | Verify merge identity and exact ordered parents | pre_execution_source_guard |
| 128662229947 | prospective-merge (protocol-contract) | Verify merge identity and exact ordered parents | pre_execution_source_guard |
| 128662229937 | W1 actual reuse V3 (arm64, prospective-merge) | Verify V3 exact source and ordered merge before execution | pre_execution_source_guard |
| 128662229935 | prospective Rust shard (quality) | Verify immutable source identity | pre_execution_source_guard |
| 128662229865 | cross-arch-cost (x64) | Execute exact native from-zero service controls | executed_target_failure |
| 128662229854 | prospective-merge (repository-truth) | Verify merge identity and exact ordered parents | pre_execution_source_guard |
| 128662229829 | W1 actual reuse V3 (x64, prospective-merge) | Verify V3 exact source and ordered merge before execution | pre_execution_source_guard |
| 128662229758 | cross-arch-cost (arm64) | Execute exact native from-zero service controls | executed_target_failure |
| 128662229746 | prospective Rust shard (runtime) | Verify immutable source identity | pre_execution_source_guard |
| 128662229491 | protocol-contract | Run actual protocol-contract checks | executed_target_failure |
| 128660702010 | W1 factorial legal strategies v3 (x64, prospective-merge) | Reserve observations and verify ordered source identity | pre_execution_source_guard |
| 128660701948 | W1 fresh challenge service (x64, head) | Execute original and fresh service with original Host resources | executed_target_failure |
| 128660701711 | native priorities (ubuntu-24.04-arm, head, service-model) | Execute original release from-zero controls | executed_target_failure |
| 128660701637 | native priorities (ubuntu-24.04, head, history) | Execute 4105 real work blocks and paid public full sync | executed_target_failure |
| 128660701605 | native priorities (ubuntu-24.04, head, service-model) | Execute original release from-zero controls | executed_target_failure |
| 128660701377 | original native campaign (x64, head, release) | Run three original campaigns under verified actual limits | executed_target_failure |

Together with the earlier 39 source-bound refusals and one missing historical-artifact failure, the 58 observed failures divide into 49 source-bound preconditions, 1 artifact-availability failure, and 8 actual execution failures. This is not a claim of 58 business regressions. The strict source guard was not changed, and these reads do not establish whether an executed failure is a new code regression.

## Actual C6 execution failures

### Five original from-zero gates

The two cross-architecture jobs, protocol-contract, and the two service-model head jobs each completed all five named native controls. Their original report nevertheless has `finite_target_met=false`, while protocol invariants remain true. The original acceptance error is `CONFIRMATION_TARGET`.

Each retains the original 4-second window, 0/16 hostile-worker comparison, and fixed public parent limits: 0.25 CPU, 2 GiB, no swap, and 256 PIDs. Baseline confirms 1/1; pressure confirms 0/1 and retains `PUBLIC_REQUEST_DEADLINE`. Failure is censored at the original window and receives no successful latency.

| Job | Baseline successful business latency, seconds | Pressure result |
| --- | ---: | --- |
| 128662229865 | 2.291778440 | 0/1 in 4 seconds |
| 128662229758 | 1.814360555 | 0/1 in 4 seconds |
| 128662229491 | 2.824878643 | 0/1 in 4 seconds |
| 128660701711 | 1.786019790 | 0/1 in 4 seconds |
| 128660701605 | 3.085104124 | 0/1 in 4 seconds |

These are per-job observations, not additional independent trials, a p99 estimate, a WAN result, or positive resource qualification. Each retained confirmation report matches its original observer SHA256.

### W1 fresh service, job 128660701948

Both retained original and fresh-challenge reports use 4 seconds and 16 hostile workers. Both baselines confirm 1/1 (3.098021827 and 3.091566631 seconds); both pressure phases confirm 0/1 with `PUBLIC_REQUEST_DEADLINE`. The original native invocation exits 0 but its reader refuses `CONFIRMATION_TARGET`. The fresh invocation exits 101 after the actual assertion at `fresh_challenge.rs:244`: the original four-second/six-depth target failed. Its adapter records `FRESH_NATIVE_PROCESS_REQUIRED`. Native test durations are 8.89 and 8.70 seconds for the paired phases; wrapper elapsed values include source checks and must not replace the 4-second business windows.

### Three original campaigns, job 128660701377

The retained workload uses 21 business blocks, baseline/from-zero/late-product modes, 30 seconds per phase, and 0/24/24 attacker processes. The outer controller has 4 CPU / 16 GiB / nice 10; receiver and verifier use the original 0.25 CPU / 2 GiB public domain. These resource domains are not interchangeable.

All three complete attempts return 101 and retain `finite_experiment_criteria_met=false`, with overall `ORIGINAL_THREE_RUN_CAMPAIGN_FAILED`. Their outer elapsed times are 113.106867917, 112.896625855, and 112.692097277 seconds; none reaches the original 600-second cap. Each baseline confirms only observed round 0 (phase times 16.111312958 / 16.206307183 / 16.416152516 seconds); observed round 1 fails at the 30-second boundary. Each pressure mode has an observed round-0 result only, and it is false. Unobserved later rounds are not credited; observed-list length does not replace the planned denominator.

All phases retain `genuine_budget_depletion_observed=false`. Run 1 late-product also has `observer_complete=false`, which is not repaired. Full raw reports and stderr/stdout plus selected actual Host records are retained. Report and stderr hashes match the original attempt pins.

### Original History, job 128660701637

The exact C6 original History test executes and exits 101. Its server records the original 1,800-second lifetime expiring at 1,800.000502746 seconds. Independent synchronization records 3,853 successful-return import calls, then fails at `history-rpc` with `IO: Connection refused (os error 111)`. Durable committed-block count is null. Native test duration is 2,812.31 seconds; GNU time is 46:52.30. These include generation plus synchronization and are not the server lifetime.

Source/build checks succeeded and Host provisioning reports no failure. The observed sequence is incomplete synchronization followed by connection refusal after the original server lifetime. This is not an install or source-binding failure and does not prove a unique hardware or code-regression cause.

## Separate base96 History diagnostic

Existing run 42456320219 is bound to `96a241bf43f6a46d35dfb3d4ced9594ed8ceca75`. Both replicas pass source binding and preparation. Replica 1 (128655993256) fails in execution. Replica 2 (128655993533) has completed/success metadata and its complete public job log.

Replica 1 retains 4,105 configured blocks and the original 1,800-second server lifetime. The loop expires at 1,800.000008599 seconds; replay has 2,759 successful-return imports and fails at `history-rpc` with connection refused 111. Durable committed blocks remain null. Native test duration is 3,215.89 seconds; GNU time is 53:36.09; the distinct failure-record monotonic interval is 3,214.405739726 seconds. Its complete 27,093,638-byte native log is retained as lossless gzip, raw SHA256 `0f1af76ec902e6cd3c06b4df99589508650a525a25897a9513404fb4dd470c80`.

The diagnostic source includes buffering and observer overhead inside the service lifetime. Nested phase and Host CPU cannot be added. This replica split and comparison with C6 establish no causal speedup, tail latency, resource qualification, WAN readiness, or production safety.

Replica 2's 64,440,198-byte artifact download hit the reader's declared 120-second bound after 21,413,888 bytes. Partial SHA256 is `f5660018a142121dba4ac92dbe4021d89fc2d76337626a8c5e921c5d24cbd0b7`. It remains in the non-public sibling download cache. There was no retry, no inner summary was invented, and this read failure does not change the observed CI success.

## Evidence handling and limits

54 read-only GitHub API invocations comprise identity plus 20 metadata calls, 13 complete job logs, 10 artifact metadata calls, and 10 archive downloads. Nine archives match both API size and digest; one download is incomplete. Reader failures and helper transport timeout remain recorded. No private operator environment, credentials, ELF, packet binary, or SQLite file is copied into this public bundle.

`new-failure-classification.json` retains every original first-failure step. `summary.json` holds the budget and boundary readback. Each `selected-artifact-manifest.json` binds original ZIP-member bytes to retained plain text or lossless gzip. Original archive caches stay outside this bundle. `read-scripts/` and `helper-witnesses/` preserve bounded read/derivation procedures and their actual completed process evidence.

C7 local qualification and later operations remain separate evidence. These reads create zero full proofs and zero operations. They do not qualify C7, a newer base, the actual merge tree, provider payment, historical whole-process reclamation, or production activation.
