# Responsive PoN quantum research: frozen execution and complete evidence

**Research result: the declared validation and observation campaigns passed. All four general quantum safety gates remain HOLD.** This record extends the preceding [competing-schedule evidence](../pon-quantum-competing-gates-20261107/README.md). It does not certify a calibrated quantum miner, a minimum-cost attacker, a profitable QPU attack, or general settlement security.

Executable implementation: `bab83768b7c794b0127dc63d633f3e37a1be025a`; tree `21afda717e4f6aaf6a119bbcdeee6f3c397d0d7e`; predecessor `bef17d632d1e40014167dba2a1089b85366b67b8`. The subsequent publication commit adds evidence and the sole development-plan outcome. The full executable suites ran on the frozen implementation, not on a falsely relabelled later source SHA.

The freeze receipt preserves its original pre-validation pending flag; the later completion and audit establish the outcome without rewriting that historical receipt.

The [implementation freeze](implementation-source.json), [final validation result](validation-result.json), [completion receipt](validation-completion.json), [independent validation audit](validation-audit.json), and [machine-readable outcome](summary.json) bind this record to retained bytes. Dates in the directory identify the campaign start; final validation and publication preparation continued on 2026-11-08 UTC.

**Operational item still open:** the owned Colab allocation is `ACTIVE_RELEASE_BLOCKED`. Two normal guarded release attempts were refused with `RELEASE_BLOCKED_BY_FOREIGN_OR_BUSY_KERNEL` before any unassign call. Read-only inventory still showed the endpoint at **2026-11-08T00:55:36.835049+00:00**. All scientific tasks and verified downloads are complete, but actual release time remains null. The [release receipt](allocation-release.json) and [Colab timeline](colab-final-summary.json) retain this state; the allocation interval is only known through the confirmed cutoff and may continue beyond it.

## Four gates

| Gate | Added verifiable evidence | Missing general evidence | Status |
| --- | --- | --- | --- |
| Complete machine cost and error | Numerical calibration admissibility, all active-event gap accounting, preserved source/architecture bindings, actual Colab CPU reconstruction and independent replay | Measured quantum hardware, compiled physical layout, controller/decoder services, energy/capital costs, conditional execution guarantees | **HOLD** |
| Cheapest legal implementation and amortization | Four complete proof producers, four bounded payload capacities, full and deadline-limited fresh children; all 896 planned slots retained | Exhaustive algorithms/preprocessing/cache coverage, a global lower bound, unbiased performance comparison and equal total physical resources | **HOLD** |
| Native-valid adversarial quantum execution | Twelve real native CPU runs, receiver-following honest cancellation/rebinding, all attempts and admissions, independent fresh-node replays | QPU execution, calibrated quantum clock, arbitrary mutually responsive strategies and a continuously operating public network | **HOLD** |
| Hybrid quantum/classical consensus | Two additional exact responsive finite-state certificates, independent checks and forward fixed-policy calculations; ancestry separated from final tip ownership | Arbitrary quantum algorithms/timestamps, native DAA probability calibration, unbounded horizons and a full settlement theorem | **HOLD** |

## 1. Numerical calibration is checked, and missing measurements stay missing

The [calibration observation](calibration-observation.json) is reconstructed from the frozen native-derived allocation. The original total fault budget is `1/100`; nine active physical-event classes receive confidence allocation `1/1800` each. No physical sample record was admitted. The report therefore returns an uninformative worst-case risk upper bound of one and `OBSERVED_HOLD`. One is not a measured failure probability.

For illustrative declared per-event rates near `1e-30`, `1e-32` (finite factory exhaustion), and `1e-25` (live data patch-cycles), the checker reports conservative sufficient direct zero-fault sample counts of approximately `1.1e31`, `1.1e33`, and `1.1e26`, respectively. Those counts apply only to the specified fixed-size IID direct-sampling route. They are not physical lower bounds or a statement that direct sampling is the only route. Valid error-correction/decoder transformations could support logical bounds, but the necessary calibrated inputs and proofs are absent here.

For an admitted class, confidence is allocated once and event counts multiply its failure-rate bound. Missing active classes receive the conservative unit bound. Summing the declared event contributions and confidence allocations, then clipping to one, does not create an execution guarantee. In particular, a fixed-sample IID statement has not been lifted to the required adaptive, history-conditional runtime statement.

The actual Colab hardware probe observed a CPU runtime with two visible logical CPUs and an AMD EPYC 7B12 model string. It did not establish exclusive cores, QPU execution, reliable energy counters, a machine price, or complete dependency/firmware authentication. The complete available task/management timeline and allocated interval through the last confirmed cutoff, including preparation and idle periods, are retained separately from child CPU timings. Since guarded release remains blocked, the allocation lifetime and cost after that cutoff are not closed. See [the final Colab record](colab-final-summary.json) and raw receipts.

## 2. Four proof producers, bounded reuse and deadline accounting

The [portfolio outcome and audit bindings](portfolio/portfolio-public-outcome-bab83768.json) check the complete [matrix summary](portfolio-summary.json). The frozen portable input contains 28 planned slots: 16 original native candidates and 12 explicitly relation-only controls. There are 25 distinct headers, three repeated slots and five exact AB cache keys. The original 16 include two admitted native winners and fourteen target misses. The twelve controls do not acquire native admission merely by satisfying the W1 relation.

Four producers are compared: `direct-ab`, `trace-correction-ab`, `sparse-ab`, and `rank-aware-ab`. Each builds a complete proof and undergoes independent verification. The trace-correction identity

```text
AB = C' - (A Fl) Fr - El (Er B')
```

is used only after retaining the complete ordered trace. At N=64 and R=8 the correction requires 131072 multiply-accumulate pairs versus 262144 for dense AB. The complete 262144-pair trace, noise, ticket, hashes and independent checks remain charged. Rank-aware handling proves its rank-zero/rank-one condition and uses a dense fallback otherwise; no approximate arithmetic substitutes for the legal relation.

Payload capacities are 0, 4096, 65536 and 262144 bytes. These are cache payload limits, not total process or machine-memory bounds. Four producers × four capacities × two modes gives **32 fresh-child runs and 896 planned slots**. The sixteen full runs each generate and independently check 28 complete proofs, yielding 448 full-run proofs. The original-candidate and relation-only planned denominators are 512 and 384 across both modes.

| Observation group | Planned slots | Completely verified | Partially completed | Never started |
| --- | ---: | ---: | ---: | ---: |
| Sixteen full runs | 448 | 448 | 0 | 0 |
| Sixteen four-second runs | 448 | 146 | 10 | 292 |
| **Total** | **896** | **594** | **10** | **292** |

Only **140** budgeted completions finished independent verification by four seconds; **six** later completions receive no timely credit. The full runs retain 32 target hits and 416 misses; the budgeted runs retain sixteen hits and 130 misses. The 594 verified slots represent 25 distinct proof identities and two distinct target-hit challenges. These are repeated scheduled proof constructions, without an independent-mining-query or block denominator. Target hits in this source-declared candidate schedule are not a blind-mining probability estimate.

For each payload cap, the following is the lowest *single observed whole-child process CPU* among the four complete 28-slot producers:

| Payload cap | Lowest observed producer | Whole-child CPU seconds | Full-run AB computations / reuses |
| --- | --- | ---: | ---: |
| 0 B | trace-correction-ab | 8.910238 | 28 / 0 |
| 4096 B | trace-correction-ab | 8.790328 | 28 / 0 |
| 65536 B | trace-correction-ab | 8.318015 | 9 / 19 |
| 262144 B | rank-aware-ab | 8.109524 | 5 / 23 |

At 65536 B, rank-aware-ab measured 8.319462 CPU seconds, only 1.447 ms above the listed value. This one observation supports no statistical ranking or general speedup conclusion. All four full producers have the shown per-cap AB computation/reuse counts.

All 32 children consumed 193.081908 CPU seconds. The surrounding portfolio envelope consumed 197.702050 CPU seconds and 258.937060113 wall seconds, retaining 4.620142 CPU seconds outside the children. The envelope already includes the children and must not be added to them again. It does not include the whole Colab allocation or the later independent replay.

The greatest observed admitted-stage overrun was 155.534050 ms; the greatest whole-child overrun was 188.023549 ms. One already admitted stage actually began after the four-second point, with its full cost retained. Observed peak RSS ranged from 30859264 to 32276480 bytes, illustrating why payload caps cannot stand for total memory.

The four-second admission clock begins in the parent before argument preparation, the flushed start receipt and spawning the child. Imports, source checks, plan loading and empty-cache initialization consume that budget. A stage admitted before the deadline is non-preemptive and may finish after it; the excess is retained. Timely credit requires full verification to finish by the deadline. Final serialization, source recheck, process exit and controller reconciliation remain in outer receipts rather than being silently forced into the four-second window. Accordingly, `hard_wall_deadline_guaranteed=false`.

The shared native export is separately charged once: 1.578401403 process-CPU seconds and 1.585308175 wall seconds inside the export function, with its surrounding startup/serialization in outer receipts. It is not treated as free per-child work. Management, transfer, replay and allocated idle time are separately visible and cannot be replaced by the fastest child CPU value.

Per-attempt records retain proof SHA-256/length, complete input/trace/ticket bindings and stage ledgers; the independent replay regenerates and verifies the proofs. Separate raw proof binaries for every portfolio attempt are not retained. Original native packet fixtures do retain their packet/proof bytes. A repeated timing is not substituted for a slow, failed or censored observation.

## 3. Native receivers now drive bounded honest reactions

The [native execution audit](native-responsive-audit.json) checks 76 retained files, including 55 packet files and twelve complete event journals. It binds the original Python reader stdout to independent native replay and checks the native/Python source inventory. Each run uses three independent Node database instances within one native process: an honest producer, private producer and receiver. This is not three physical machines or a live public network.

The receiver applies real native proof, DAA, timestamp and cumulative-work checks. Selected-tip notices can cancel an unfinished honest attempt and bind its replacement to the receiver's new tip. Completed stale delivery is supported by the implementation and controls. **The actual twelve-run native campaign contains zero completed stale honest deliveries**, so it does not claim empirical coverage of that case.

| Native ledger | Retained count |
| --- | ---: |
| Fresh runs and matching fresh receiver replays | 12 |
| Attempts started | 93 |
| Honest / private starts | 72 / 21 |
| Completed attempts, including target misses | 72 |
| Cancelled attempts | 9 |
| Deadline-censored attempts | 12 |
| Actual eagerly generated candidate proofs | 90 |
| Opaque private attempts without a generated candidate | 3 |
| Receiver block admissions | 16 |
| Receiver selection changes | 9 |
| Private replacement and honest rebind onto its tip | 1 / 1 |

The single private replacement is the predeclared `classical-observer-advice-seed9` control. It uses a known winning path and must not be interpreted as a blind-search success rate, quantum advantage or attack probability. The remaining eight cancellations follow honest selection changes. The three opaque attempts are both positive-q cases and the serial q0 lifecycle; they reach the horizon before a candidate check.

The four recorded risks are ever replacing the public branch, a private-owned tip at the horizon, a private block on the horizon ancestor chain (including the tip), and orphaning the initial public block at the horizon. Only the seed9 advice control triggers any of them; it triggers all four. These twelve samples do not themselves distinguish the four events.

Native CPU proofs are computed eagerly. The controller exposes modeled outcomes at the declared completion time and retains actual CPU cost even when a modeled attempt is subsequently cancelled or censored. This is not literal interruption of CPU proof computation or execution of Grover search.

The twelve inner run CPU ledgers close exactly:

```text
5,542,772,874 ns
= 127,914,011 ns  attempt preparation / proof / checking
+ 429,181,689 ns  native producer/receiver admission and notification events
+ 4,985,677,174 ns  remaining process work
```

This inner sample excludes the surrounding source census, final report serialization, and subsequent Node/temporary-directory teardown; outer command receipts retain those process costs separately. It must not be labelled complete pipeline CPU, calibrated physical cost or the modeled quantum execution time.

## 4. Responsive finite certificates separate private ancestry from tip ownership

The original eight prescribed-arrival finite certificates are retained. This continuation adds two complete responsive reduced models, each with an independent certificate check, a separate forward fixed-policy calculation and five checked samples (seeds 9, 17, 41, 73 and 401).

| Declared winner-proof duration | States | Edges | Maximum ever replacement / private ancestry / initial-public orphan | Maximum private-owned tip at horizon |
| --- | ---: | ---: | --- | --- |
| Four ticks | 3361 | 5236 | 343/32768 | 343/32768 |
| One illustrative tick | 2828 | 5101 | 7/512 | 343/32768 |

Each risk has its own Bellman optimization; the maxima need not share one policy. The one-tick seed401 sample has an honest-owned final tip descending from a private block. It also retains two cancellations charged for one and two ticks and an already completed stale honest packet. **That contrast is a reduced-model result; it did not occur in the twelve native samples.**

The model declares success law 1/8, sixteen quarter-second ticks, at most six honest and two private starts, constant-work layers and explicit observer visibility. It does not prove these probabilities for native DAA, calibrate a hardware clock or cover arbitrary timestamp/release/quantum algorithms. The default zero fault-union assumption is an idealized parameter, not a measured whole-network fault guarantee. Any perturbation bound requires its explicitly stated coupling assumptions.

Actual Colab CPU independently produced and checked the same two certificates and ten samples. A read-only comparison found byte-identical contents in all **26** existing certificate, sample, checker and forward-probability files (2 + 10 + 14). The [cross-environment receipt](cross-environment-reduced.json) excludes timing-bearing summaries from the byte-equality claim. Agreement of the same frozen algorithm across these two CPU environments is not an independent proof of the model assumptions.

See [the reduced-model summary](reduced-summary.json), the complete archived certificates/samples, and the [finite contract](../../formal/pon-nakamoto-v1/FINITE_QUANTUM_CONSENSUS.md).

## 5. Frozen-source regression, including exact test inventories

The full ROG driver completed 62 required commands; no required command failed and no optional command remained incomplete. It checked all 11073 tracked files before and after, with unchanged source inventory digest `32df826245ec145f0b70f5421f70451a3e71c3b0bfb06ef9aa981bb9dd483f0b`.

| Verification | Result |
| --- | --- |
| Twelve Python suite groups | **861 passed**, no skipped summaries |
| Complete Node outer libtest inventory | **1251 passed / 0 failed / 39 ignored / 0 filtered** |
| Explicit ignored native quantum tests | **6 separately executed and passed** |
| Whole-workspace Clippy, all targets and features, warnings denied | PASS |
| Formatting; main and fuzz locked/offline graphs | PASS |
| Current source pins, distributed inventory, negative integrity/CI/PQ/readiness controls and repository links | PASS |
| Old native baseline/competition, 18 construction cells, 54 service cells, three cache capacities and full historical CPU ledger replay | PASS |
| New native responsive execute / reader verify / fresh replay | PASS |
| Two new exact reduced certificates and ten samples on ROG | PASS |
| Frozen added-suite subset on actual Colab CPU | **85 passed**, counted separately from the 861 |
| Exact publisher offline controls on ROG and Mac | **16 passed on each**, no API effects |

The 1251 count excludes nested child-test successes. The independent outer checker recognizes the known nested parents/children and accounts for every nonempty output line against the same current ELF's full inventory; six negative parser controls pass. Thirty-nine tests are still ignored by the default outer suite. Only the six explicitly selected quantum native tests are claimed as additionally executed here.

The ELF `32b7931f7dfc93fe785a0228f7245919807ea648a07b2f655597c5697ed2b4ba` was selected from this successful Cargo JSON build's exact artifact record, not from a filename glob. The existing build target cache was reused. This was not a clean reproducible build, complete transitive toolchain attestation, exclusive calibration or calibrated equal-resource benchmark. Compiler/provider/environment identities and boundaries remain in the raw declaration.

Three CI fixes preserve the intended acceptance conditions: enumerate the actual original plus newly added ignored selectors; test the pinned malformed-null JSON rejection with nonzero exit and unchanged databases; and follow exact `SelectedOpen` forwarding/dispatch while preserving schema, namespace, no-fallback and rebinding guards.

## 6. Failures and limits are retained

Development failures remain in the raw archive: the rejected unsafe Rust process-clock call and safe pinned `rustix` replacement; an incorrect SHA-256 source-pin refresh rejected by the Git-blob checker and then corrected; a generated bytecode-cache file rejected by the freeze guard and quarantined; initial sparse-publisher local-control failure; and refused/failed Colab control/readback attempts. Their corrected checks do not overwrite the initial receipts.

The prior GitHub head `bef17d6` produced **1249 passed / 1 failed / 37 ignored** in its PQ network job. The first legitimate TCP submit returned `ECONNRESET(104)` in `guarded_npq6_valid_submit_exact_replay_and_independent_process_restart`. The [prior CI audit](prior-ci-audit.json) and complete raw log remain retained. A witness idle-deadline interaction is plausible, but the causal phase is not identified by the retained job log and the cause remains unresolved. Passing the present ROG suite does not establish that this prior CI failure is fixed. Those PQ transport sources were not changed to obtain this result.

The old CodeQL deadline failure and public-service resource/artifact failures are not relabelled as repaired. No deadline, resource cap or original acceptance test was relaxed for this continuation. GitHub CI at the eventual evidence head is a separate observation; pending or unobserved jobs are not PASS.

## 7. Read or reproduce the retained evidence

The [raw index](raw-index.json) pins ordered gzip archive parts, the [complete file manifest](raw-manifest.json) and every archived member. The full raw archive includes command stdout/stderr and receipts, source snapshots, native packets/journals/replays, old and new certificates, portable exports, full Colab observations and independent verification, retained preparation failures, hardware/allocation receipts, and the exact helper sources. Only explicitly reviewed public files from the runtime lane are included; private credentials, profiles and session capabilities are excluded.

From this directory, verify without extraction:

```bash
python3 -B verify_raw.py
```

To also extract into an absent destination:

```bash
python3 -B verify_raw.py --extract /tmp/pon-responsive-evidence
```

[The archive readback receipt](raw-verification.json) records the same verification. Original member hashes and sizes are checked before, during and after packaging; extraction rejects duplicate/nonregular/unsafe paths. Public hash inventories establish byte identity and completeness of the selected archive, not hardware truth.

For a fresh execution, use a separate checkout of the frozen implementation, the retained validation/reduced/outer-check helpers, the recorded compiler and OpenSSL provider, and newly empty output directories. The validation driver is invoked with explicit `--repo`, `--head`, `--out` and `--env-file` arguments; the archived environment contains actual observed paths that must be consciously provisioned on a different host. Portable Colab input exports explicitly delegate native provenance; they are not a substitute for native admission.

[The service/reuse contract](../../formal/pon-nakamoto-v1/MACHINE_SERVICE_AND_REUSE.md) states the algorithm, cost and calibration assumptions. [The sole development plan](../../docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md) records the final outcome. Publication uses the authorized HeptaRuntime local Mac GitHub channel and an exact linear source/evidence object stack, with one final non-force ref update and subsequent readback. No merge, protected-main bypass, release approval or production activation is part of this result.
