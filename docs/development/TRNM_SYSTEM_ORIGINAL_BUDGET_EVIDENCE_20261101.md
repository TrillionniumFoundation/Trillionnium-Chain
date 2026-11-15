# Original-budget system service evidence — 2026-11-01

## Decision and scope

**HOLD / no system-service acceptance.** PR #678 contains candidate implementation changes and source-bound evidence. The original four-second hostile business-confirmation gate and the complete original 30-second campaign have actual failures. The original large-state selectors and 4,105-block full History acceptance require their own completed native results. ACK counts, reader tests, an arithmetic speedup, or a successful compilation do not substitute for those results.

This is an immutable observation snapshot. See [the structured evidence](TRNM_SYSTEM_ORIGINAL_BUDGET_EVIDENCE_20261101.json) for observation times, source identities, jobs, artifacts and limitations. Subsequent CI results belong to their own exact source and run.

## Exact source identities

| Identity | Commit | Tree / purpose |
| --- | --- | --- |
| Latest #559 parent | `0e9eac5d2a8cdb0a6f0cc7920f84e290e0d5d0d0` | Preserves the existing integration candidate and its changes |
| #674 parent | `605af09da34ca72665f822200a2f3e75573e6052` | Original long-History diagnostic candidate |
| Runtime candidate | `b97f63254df260243186f14c6e177ab96fffdcd8` | `a61aa2029758386a6278bc6d58debc0f590e6d15`; ordered parents are the two commits above |
| Explicit original CPU selectors added to priority CI | `bb84d3ded8acc8b33ddbf32e1c8defae76900a0e` | `8802deea926665ecb05d5c943c22c00814877cb7`; runtime source unchanged |

The workflow and evidence additions accompanying this document also leave the runtime code and original test budgets unchanged. Their new Git commit must still receive its own source verification; old run results are not relabelled as acceptance of a later head.

## Four-second independently confirmed business: actual failure

[Run 41293784189](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/41293784189) tested the runtime candidate. These are four actual execution artifacts, **not** a claim that this particular table is a complete head/merge × x64/ARM matrix:

| Execution / job | Unattacked independent confirmation | Last of seven honest ACKs under pressure | Independent confirmation under 16 hostile W1 producers |
| --- | --- | --- | --- |
| Protocol x64 head / `124810273570` | 1/1 in 2.897804531 s | 1.951356475 s | **0/1**; second History page reaches request deadline |
| Protocol x64 prospective merge / `124810273577` | 1/1 in 2.817577638 s | 1.974011406 s | **0/1**; second page reaches request deadline |
| Cost x64 head / `124810273556` | 1/1 in 3.476350205 s | 2.446005365 s | **0/1**; first page reaches request deadline |
| Cost ARM head / `124810273572` | 1/1 in 2.196132609 s | 2.244766954 s | **0/1**; second page reaches request deadline |

The five named Rust executions in each report passed their own assertions, but the required report aggregate failed `CONFIRMATION_TARGET`. Invariants were retained. Actual Host observations recorded `cpu.max=25000 100000`, `cpu.max.burst=0`, `memory.max=2147483648`, `memory.swap.max=0`, and `pids.max=256`; no Host-validation error or OOM explains away the missing confirmation.

For protocol x64 head, pressure page one took 1.400063213 s wall time and 75.215510 ms caller CPU. Page two started 3.556821763 s after the phase start and returned `PUBLIC_REQUEST_DEADLINE` at 4.051780044 s. Seven timely ACKs therefore remain insufficient for the original business target.

The denominator is one offered business confirmation per four-second phase. A value such as 1/4 s is a finite-offer completion rate, not a measured saturation TPS. Zero or one successful observation does not support p50/p95/p99 latency claims.

## Complete original 30-second campaign: actual failure

[Runtime-candidate run 41293783904, job 124810272193](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/41293783904/job/124810272193) retained the original 1,024 seed transfers, four seed blocks, 21 business blocks, three business rounds, 30-second phases, and 0 / 24 / 24 attack processes for baseline / from-zero / late-product.

All three complete predefined runs produced the same business-round counts:

| Phase | Independently confirmed rounds | Original criteria |
| --- | --- | --- |
| Baseline | 1/3 | Failed |
| From-zero pressure | 0/3 | Failed |
| Late-product pressure | 0/3 | Failed |

`phase_startup_errors` was empty; `report_validation_failure` was null; actor and observer reports were present. This is a measured business failure, not a missing executable or a report-parser success substituted for execution. `genuine_budget_depletion_observed` was false and does not turn the failed business gate into a pass.

[The later bb84 run 41294743084](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/41294743084) also completed with failure. Its job log reports three `original_criteria_met=false` results, no startup errors, no report-validation failure, and verified exact bb84 source after execution. At this snapshot its individual phase JSON files had not been re-extracted, so the b97 phase counts above are not copied into bb84 records.

### What the measured stages show

For runtime-candidate baseline run one:

| Measured client stage | Calls | CPU | Wall time |
| --- | --- | --- | --- |
| `account_graph` | 69 | 5.0461 s | 21.6738 s |
| `verify_state` | 84 | 5.1439 s | 21.9236 s |
| `complete_state_root` | 36 | 0.0080 s | 0.0851 s |

These are nested stages and **must not be added together**. Across the three baseline runs, client `account_graph` CPU was approximately 4.92–5.05 s. The account graph and its control/checkpoint path therefore warrant investigation before attributing the complete campaign's cost to state-root arithmetic.

The current source calls progress while traversing graph nodes; that path reaches operation controls and fresh Host checks. This is a source-correlated cost diagnosis, not a function-level measurement proving that every CPU difference is caused by a particular syscall.

## Original large-state CPU policy

The two exact nonignored release selectors are:

```text
store::detached_admission::tests::admitted_custom_genesis_over_eight_mib_keeps_original_held_schedule_and_cpu_owner
store::detached_admission::tests::authenticated_large_parent_original_schedule_supplementary_denominator
```

The fixture contains 2,100 strings of 4,080 bytes and 8,625,548 bytes of complete key/canonical-value material. The original standalone policy remains a 2,000,000,000 ns CPU burst with 250,000,000 ns/s refill, a 100,000,000 ns start reserve, two workers, and the original ten-second absolute deadline. This is not a newly invented assertion that total CPU must always be at most two seconds despite refill.

The original `unwrap` acceptance, independently computed complete state, packet equality, and reopen-state checks remain. The fixture starts from a custom large genesis; it does not certify default-genesis state growth or the separate full-capacity test.

bb84 adds both original selectors explicitly before the original capacity test in the existing priority matrix. At the observation snapshot that workflow was pending behind the executing predecessor. Existing b97 full-workspace runtime shards were still running; lack of a completed log does not prove whether they had reached these selectors.

The accompanying independent workflow is configured to run these exact two release tests and the two actual reactor-exit regressions on x64 and ARM, for both head and actual prospective merge. It records exact source before/after, toolchain, default release build metadata, executable hash, original package working directory, each process exit and each named test. It does not provision a substitute public-service cgroup or change test policy. A queued or running workflow remains unaccepted until actual results arrive.

## Original 4,105-block History

[Priority run 41293784074](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/41293784074) had four active original full-History executions at this snapshot:

| Architecture / source | Job |
| --- | --- |
| x64 head | `124810272811` |
| x64 prospective merge | `124810272766` |
| ARM head | `124810272977` |
| ARM prospective merge | `124810272833` |

Each passed its separate build and entered `Execute 4105 real work blocks and paid public full sync`. There was no completed native result or current-height artifact available. The original 1,800-second service lifetime, actual installed 25%-CPU/2-GiB parent, 4,105-block count, paid public import, reopen and corruption refusal remain unchanged.

The previous #674 evidence recorded exit near 1,800 seconds. However, server cleanup itself sets `stop=true`, so the after-return stop flag cannot distinguish external cancellation from lifetime expiry. The runtime candidate records `StopRequested`, `LifetimeExpired`, or `LoopError` at the actual reactor exit condition, before internal shutdown. The new native tests exercise a real lifetime expiry and an external stop after a real signed Head read. This diagnostic change must be executed and observed; it does not itself prove the long-History root cause or pass the original performance gate.

## Implementation boundaries

The candidate retains checked pure-arithmetic reuse with complete current-input encoding/hashing; it does not reuse a verdict across changed inputs. Native ancestry queries reuse prepared SQLite statements while still reading each current row and charging original SQL/control work. General historical verification still walks toward genesis: this is a constant-factor change, not removal of chain-length growth.

Bounded serialization avoids a redundant encode for inputs already known to exceed the cache's size bound, preserving original encoded bytes and error precedence. Host limit paths and small buffers avoid repeated allocation; every actual Host check still obtains fresh observations. Existing transaction-scoped post-write reuse continues to bind the same connection, transaction, schema/context and write epoch.

Business reporting keeps failed confirmations in the original denominator. It requires at least two actual successful observations for p50, 20 for p95 and 100 for p99; min/max and available sample counts remain explicit. No seven-sample maximum is relabelled p99.

## Verification completed and verification interrupted

A clean local default-release, locked/offline build completed in 10m02s on local commit `b40cfffa4c6525ba2ed947130d7667082fd5b512`, whose tree was exactly `a61aa2029758386a6278bc6d58debc0f590e6d15`. Before/after verification covered 6,771 tracked entries and 781,023,099 bytes. Its source receipts retain that actual local commit; they are not retroactively relabelled b97. No native tests were executed by the no-run build.

Local confirmation-reader tests passed 98 cases; CI-contract tests passed 95; source-integrity negatives passed 34; public-readiness reader tests passed 51. Formatting, project boundary, exact corpus pins and source inventory checks passed in the observed local work. These are bounded source/reader checks.

The final-source bb84 rebuild was still compiling when the managed local executor became unavailable (`exec-server: No such file or directory`). No completed final-build receipt, local native execution result or new strict-Clippy result was observed. A premature runner attempt failed because the required final build provenance did not exist and ran no native test.

[Recent-batch run 41293784173](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/41293784173) did complete its four x64/ARM head/merge jobs, with actual named native tests and exact final source verification, including native owner/transaction controls and the rotating false-work confirmation regression. Those narrower passes do not override the separate original four-second or complete 30-second failures.

## Next safe implementation boundary

[The reorganization readback review](TRNM_REORG_POSTWRITE_READBACK_REVIEW_20261101.md) identifies a bounded possible extension inside existing WRITE transactions after their final SQL writes. It was reviewed against bb84 but was **not implemented or measured** in this candidate.

For a seven-block import from genesis, the source-derived estimate is ten fewer duplicate graph traversals in the reorganization tail; it is not evidence that 69 total calls can become a handful. Existing admission scope cannot simply move ahead of legitimate account writes. The review specifies write-epoch, transaction identity, schema, callback and crash-recovery counterexamples that any later implementation must satisfy.

Original acceptance remains tied to independently completed business, original CPU-policy success, and completed full-History/recovery results. Complete PQ configuration, public-network capacity, physical crash behavior, independent operators and production activation remain outside the results obtained here.
