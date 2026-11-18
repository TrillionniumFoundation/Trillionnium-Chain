# Original F0 after parent Frontier preservation — 2026-11-18

**The business gate remains failed: 1/6 confirmations inside the original 30-second phases, and 0/6 within four seconds of their scheduled starts.** This directory preserves the complete negative observation for [source PR #964](https://github.com/TrillionniumFoundation/Trillionnium-Chain/pull/964), immutable head `d95239eda6a666458aa264ddeaf993d6d9fbf37d` and tree `a738dbba92df0d7ffa3f6dd257b4106b9c783603`.

This is the one original [F0 run 44376853052](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/44376853052), attempt 1, job `135058186221`, on the recorded provider runner `GitHub Actions 1000191204`. Its native test exited 101. No second dispatch, reduced workload, renewed deadline, changed resource allowance, omitted planned round, or replacement success oracle is used.

## Original outcome and denominator

The original test retains 1,024 seed transfers across four seed blocks, separate baseline and valid-work ROOT pressure phases, 24 ROOT actors, the actual public 0.25-CPU/2-GiB parent, all six scheduled confirmation rounds, all 42 planned business-packet exposures, 30-second phase deadlines and four-second scheduled confirmation targets.

| Original condition | Actual observation |
| --- | --- |
| Baseline confirmations inside its 30-second phase | 1/3 |
| ROOT confirmations inside its 30-second phase | 0/3 |
| All planned confirmations inside original phases | 1/6 |
| All planned confirmations within four seconds of scheduled start | 0/6 |
| Planned business-packet exposures | 42 |
| Timely acknowledged exposures | 19 |
| Entirely unattempted exposures | 22 |
| Exposure attempted without timely acknowledgement | 1 |
| Actual Submit attempts, including retries | 29: 14 baseline and 15 ROOT |
| ROOT History requests and client imports | 0 and 0 |
| Original preparation controls | All seven passed |
| Original receiver observations | Complete; no omitted records or measurement failures |
| Final service cleanup | All services known empty |

The 29 actual attempts do not replace the 42 planned exposures. Unattempted rounds remain failures. Baseline's first round was scheduled at 1,000,000,000 ns, started at 1,000,558,069 ns and ended at 19,608,161,919 ns: **18.608161919 seconds from scheduled start**. Baseline's next round reached its original phase deadline; its third round was not reached. ROOT's first round started at 1,031,353,229 ns and ended at 30,032,925,689 ns without a confirmed round.

The original business reader refuses `BASELINE_MUST_PASS`. The original scheduled-target reader refuses `F0_ALL_SIX_SCHEDULED_FOUR_SECOND_TARGETS_REQUIRED`. A successfully executed independent evidence reader does not convert either refusal into a service pass.

## ROOT stopped before History

[The additional boundary reader](root-boundary-readback.py) checks the same original archive and the existing independent result, imports the pinned original readers, and records the actual ROOT call sequence and receiver observations in [root-boundary-readback.json](root-boundary-readback.json).

The frozen caller is `trillionnium/crates/trnm-pon-node/tests/support/multiprocess_root_phase_host.rs` at the source head above. Its first loop advances `next` only after an on-time Submit acknowledgement. Its following History loop requires `next == final_index`; the first round's `final_index` is 7. The actual 15 attempts had packet indices:

`0, 0, 1, 1, 1, 2, 2, 2, 3, 3, 4, 4, 4, 5, 5`.

Only five packet exposures received timely acknowledgements. The seventh packet was never attempted. Consequently, the History guard was never reached. **ROOT's zero client-import cost measures no observed client import, not inexpensive successful History service.**

All 410 receiver records are retained. Of these, 395 match the exact original hostile wire-body digests. The remaining 15 records are reported separately without attributing an unverified participant identity. Their complete bodies and source evidence remain in the original archive.

For the first body also present in the actual Submit sequence, the receiver observed a 1,314,645,895-ns grant wait and a 486,538,681-ns paid-task queue wait. Its worker then incurred 59,348,191 ns of actual dispatch-owner CPU before observing peer cancellation. The successful retry of that same body still waited 1,302,303,886 ns for a grant and 408,074,638 ns in the paid-task queue. These are actual receiver-local intervals, not a claim that independent clock domains share an origin. Waiting and nested CPU measurements must not be summed as disjoint costs.

The exact hostile-body records account for 6,029,512,501 ns of dispatch-owner CPU; the other observed records account for 400,308,680 ns. Their total, **6,429,821,181 ns**, exactly matches the actual paid debit, settled full CPU, ROOT supplement and service-outcome mutation CPU. Unknown nested phase measurements remain unknown.

## The original depletion condition also failed

The original budget is unchanged: 2,000,000,000 ns burst, 250,000,000 ns of refill per second, 100,000,000 ns start reservation and two workers.

All 417 discrete actual paid-credit observations satisfy their balance identities. None meets the original depletion predicate. The smallest sampled remaining actual paid credit is **1,982,201,160 ns**. The original `checked_depletion_samples` reader explicitly refuses `NUMERIC_DEPLETION_REQUIRED`.

The boundary adapter records this exact original refusal and uses `null` for checked depletion intervals. It does not replace a rejected result with an empty successful result or modify the original reader. Its first invocation failed on that original refusal; the adapter revision and both actual invocation records are preserved in [root-boundary-audit-originals.tar.xz](root-boundary-audit-originals.tar.xz). This was read-only evidence analysis, not another F0 execution.

These are discrete measurements. They do not establish a continuous-time minimum or prove impossibility under every schedule. They do distinguish this observed ROOT failure from a claim that paid credit was actually exhausted. Further investigation must preserve actual CPU accounting, paid-reservation ownership, cancellation and the original fixed test conditions.

## Actual cost and its scope

[The cost reader](cost-profile.py) re-reads all five retained original F0 archives. [cost-profile.json](cost-profile.json) retains per-request, per-stage and resource observations with their missing values and scope. Nested measurements overlap their parents and are not additive.

| Actual measurement | Baseline | ROOT |
| --- | ---: | ---: |
| Observed client History imports | 13 | 0 |
| Client caller CPU, ns | 5,627,627,485 | 0 observed |
| Nested client Host checkpoint CPU, ns | 4,664,420,943 | 0 observed |
| Client Host checkpoint calls | 97,284 | 0 |
| Whole public-phase process CPU, ns | 8,190,303,081 | 8,563,349,246 |
| Whole public-phase process wall interval, ns | 33,910,023,853 | 34,505,809,050 |
| Actual paid dispatch-owner CPU, ns | 839,099,420 | 6,429,821,181 |
| Receiver application bytes read | 1,395,370 | 39,165,219 |
| Receiver application bytes written | 1,354,363 | 809,415 |
| Retained receiver observation records | 27 | 410 |
| Retained client database bytes | 3,993,600 | 2,002,944 |
| Retained receiver database bytes | 4,317,184 | 2,834,432 |
| Controller cgroup CPU delta, microseconds | 2,040,834 | 3,448,427 |

The first baseline History import took 467,803,422 ns of caller CPU over a 2,385,746,747-ns wall interval, including 8,245 Host checkpoints and 395,883,820 ns of nested Host CPU. Its last observed import ended with `PUBLIC_REQUEST_DEADLINE`; that failed work remains included.

ROOT's nested receiver account-graph observations total 3,940,704,362 ns of CPU across 388 calls. Its nested admission stage totals 5,267,113,225 ns across 366 calls. These are overlapping views of the actual work, not extra charges to add to paid owner CPU. There were six receiver publish-stage observations, although only five distinct exposures received timely client acknowledgements.

The controller cgroup explicitly excludes the separately systemd-owned public phase. Controller memory peaks include preparation and earlier lifetime activity; their difference is not a per-phase allocation or concurrent whole-system peak. Baseline's observed controller peak was 80,371,712 bytes and ROOT's was 128,020,480 bytes. Public procfs RSS diagnostics were 77,029,376 and 119,136,256 bytes respectively; separate rusage peaks were 76,910,592 and 118,960,128 bytes. These are named observation scopes, not a complete physical memory bill.

[provider-timing.json](provider-timing.json) is the original provider API response: `billable.UBUNTU.total_ms=0`, one job with `duration_ms=0`, and `run_duration_ms=466000`. Zero reported billable milliseconds does not establish zero physical consumption or a known monetary price. Provider run duration includes elapsed scheduling/run time and is not CPU time.

Complete physical energy, physical network bytes, device I/O, concurrent whole-system memory, storage byte-seconds, monetary charges and full research overhead remain **UNKNOWN**. Application byte counts and retained database sizes do not replace those dimensions.

## Source, original readers and archive custody

The original provider artifact is `14462800092`, named `pon-fixed-host-root-f0-x64-head-d95239eda6a666458aa264ddeaf993d6d9fbf37d-1`. [f0-original.zip](f0-original.zip) is exactly 18,089,290 bytes with SHA-256:

`b4457d8062f6f5068286c8b597668b09065a5eb2f12c85759517037cb386be93`.

The original report SHA-256 is `2d7041b82c29226a56300f7e0a52c6262d76175226d7a77309ed20459508318b`; the actual executed ELF SHA-256 is `d9cc26a91ba9ce4d966c4d9ee52cb1093078d4f229305a957a215bf2684807a7`. The archive contains its inventory plus 443 verified entries. The actual execution, preparation, before/after source manifests and binary bindings all resolve to the frozen source head and tree above.

[f0-readback.py](f0-readback.py) preserves the prior strict independent reader with only this run's immutable identity constants updated. It verifies all twelve original reader SHA-256 pins, all inventory entries, the source and ELF binding, all original preparation controls, original refusals, all planned rounds and exposures, and final cleanup. It does not edit the original workload or assertions.

[f0-independent-readback.json](f0-independent-readback.json) is 20,995 bytes, SHA-256 `694877da3535471c04a048a9e6bec4d4aa63557309d0c7698a909daa9c5607d0`. The separate boundary result is 29,325 bytes, SHA-256 `45188111f4d02a3476567519edc12b4bc986358a78948d6d192fa96baad57c07`. The [provider artifact](provider-artifact.json) and [provider job](provider-job.json) records are retained alongside the original provider timing response.

The source candidate's native controls and their exact source archive remain in [the preceding native evidence](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/d95239eda6a666458aa264ddeaf993d6d9fbf37d/docs/development/evidence/chain-native-record-frontier-20261118-2e9b/README.md): 224 unique passing native cases, seven existing ignored cases, all current source pins, original mutation/omission negative controls, strict Clippy and formatting. The original regression first failed at 164/164 callbacks on unchanged production and then passed at 164/68. Those controls justify the source boundary; they do not override this failed business window.

## Earlier negative windows remain available

| Original source window | Confirmed in 30-second phases | Within four seconds |
| --- | ---: | ---: |
| 44315121617, original fixed-host F0 | 1/6 | 0/6 |
| 44328450170, Host syscall candidate | 0/6 | 0/6 |
| 44335832525, actual execution-delta candidate | 2/6 | 0/6 |
| 44356270247, parent whole-Root through one INSERT | 1/6 | 0/6 |
| 44376853052, original sealed parent Frontier retained | 1/6 | 0/6 |

These archives use different provider runners and complete different amounts of work. In particular, 18.608 seconds here versus the prior 24.508 seconds is **not a controlled causal speedup**. No prior negative observation is deleted or reinterpreted. This evidence-only continuation does not dispatch another workload, qualify a four-second service result, establish independent-operator robustness, close full physical cost, or activate production.
