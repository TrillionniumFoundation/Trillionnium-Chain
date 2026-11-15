# Completed b5bb F0 campaign: failure evidence readback

This is a read-only analysis of the completed [GitHub run 41964674522](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/41964674522), [job 127038806677](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/41964674522/job/127038806677). No native executable was run during this analysis. No CI run, source change, budget change or revised acceptance criterion was introduced.

The actual business campaign failed, starting with its no-attack baseline. The pair runner recorded `NATIVE_F0_FAILED` and `BASELINE_MUST_PASS`. The finalizer retained all six confirmations and all 42 business packet exposures and correctly returned failure: the native pair failed and **0/6** scheduled four-second SLOs passed. Its report/resource observations were complete; all three owned services were observed empty, with no cleanup failure.

## Immutable inputs and original bytes

- Head: `b5bb7bc8d7ffe79d46c6a58fd5189e2bb9e4550c`.
- Tree: `8be28a72673ce318d60a464898ab610d9ba39216`.
- Original [artifact 13386124417](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/41964674522/artifacts/13386124417): 18,263,423 ZIP bytes, SHA256 `c39004a545404871bc04a58edd769d339319a8ec41ee1e806f3507e54317832d`.
- The ZIP contained 444 entries. The readback extracted 433 JSON/log/text/CSV members, 40,292,779 bytes; it did not extract or execute the native binaries. Every original member is listed in `artifact-inventory.json`; extracted members include their hashes.
- Prepared release ELF SHA256: `68de7e28779aca7bf0f6738906cf9edb1e50afc387e3c508f26df721ec86b227`, 11,676,080 bytes. Its original preparation and source-before/source-after records are retained under `artifact/`.
- `artifact/` contains byte-for-byte copies of the selected original members. The large raw combined report remains bound by SHA256 `e56674a91e022b7b1a234f0b0ab67fed77aa581c482f6c87d8cd5dc261932872` and by the original downloadable ZIP.
- `workflow-job-127038806677.log` preserves the GitHub connector's decoded job-log text encoded as UTF-8, without line editing. This is not a claim about the bytes of a separate original log ZIP.

## Actual results

All times below are phase-relative. SLO elapsed time starts at the scheduled offset and includes delay before the round actually began; it is not execution duration.

| Phase / round | Scheduled s | Actual start s | Actual end s | Elapsed from schedule s | Confirmed within 30 s phase | 4 s SLO |
| --- | ---: | ---: | ---: | ---: | --- | --- |
| baseline / 0 | 1 | 1.001387691 | 15.102383267 | 14.102383267 | yes | failed |
| baseline / 1 | 5 | 15.102405166 | 28.812108308 | 23.812108308 | yes | failed |
| baseline / 2 | 9 | 28.812126962 | 30.004374319 | 21.004374319 | no | failed |
| ROOT / 0 | 1 | 1.050950036 | 30.053569951 | 29.053569951 | no | failed |
| ROOT / 1 | 5 | unobserved | unobserved | unobserved | no | failed |
| ROOT / 2 | 9 | unobserved | unobserved | unobserved | no | failed |

Baseline retained 21 planned packet exposures: 18 observed attempts, 17 timely network ACKs and 3 unobserved packets. ROOT retained 21 planned exposures: 7 observed attempts/ACKs and 14 unobserved packets. An ACK is not a confirmation.

The original native selector reported one failed test, zero passed, zero ignored and 24 filtered out, finishing in 75.46 s. It panicked on the actual F0-criteria assertion at `tests/support/multiprocess_root_phase_host.rs:1423`. The controller exited status 1; the original systemd record reports an exit-code result rather than a kill/OOM.

`scripts/run_fixed_host_root_f0.py:215–224` requires the baseline's original `finite_phase_criteria_met` predicate. Its failure is retained alongside the native failure. `scripts/ci/finalize_fixed_root_f0.py:283–288` requires successful native execution, complete observations, empty owned services and all six SLOs. Step 9's failure therefore does not mean that the denominator or cleanup was lost.

## Measured replay and Host costs

| Actual observation | Baseline | ROOT |
| --- | ---: | ---: |
| History network calls | 14 | 5 |
| Sum of History network wall seconds | 0.308889425 | 0.328417233 |
| Ordinary client imports | 14 | 5 |
| Sum of client import wall seconds | 23.368586812 | 15.374301136 |
| Sum of client import calling-thread CPU seconds | 5.401201965 | 1.585730854 |
| Successful client imports | 14 | 4 |
| Observed Host checkpoint calls | 166,743 | 43,310 |
| Host checkpoint calling-thread CPU seconds | 4.038066182 | 1.236897535 |
| Host checkpoint wall seconds | 6.612842651 | 3.296422510 |

ROOT's fifth client import returned `PUBLIC_REQUEST_DEADLINE`. Every counted Host checkpoint completed and was accepted; unknown-clock and unfinished-call counts were zero. `phase-client-import-extracts.json` preserves each selected original `client_import` object and identifies the original raw phase file/hash. These are exact JSON-value copies reserialized into a smaller document, not the original phase-file bytes.

The baseline client account-graph stage measured 124 calls, 3.738849684 CPU seconds and 15.396977190 wall seconds. These stage and Host intervals are nested within larger operations. **Do not add them**, or infer the cost of a particular statement from a stage total. The observations support inspecting the actual ordinary replay path; they do not justify dropping independent state, SQL-graph or Host validation.

Original public Host declarations and actual before/after observations agree: `cpu.max = 25000 100000` (one quarter of one CPU), `memory.max = 2147483648`, no swap, and `pids.max = 256`. CPU throttling occurred. The original CI memory-event counters show no OOM or OOM kill. The current local executor's unrelated shared-cgroup OOM is not an explanation for this completed GitHub run. Controller limits and actual resource observations are separately retained.

## Scope boundaries

This F0 campaign explicitly selects **AuthenticatedV1 / RawR14**. The selector constructs that configuration at `tests/support/multiprocess_root_phase_host.rs:415–443`, and the backend's opener routes to `Node::open_with_authenticated_state`. GrowthV2 uses its separate `open_growth_selected` path. These observations are not validation of the new GrowthV2 admission/cancellation or B1 account-prefix tests.

This pair has 24 hostile producers, two 30-second phases, and six four-second SLOs scheduled at offsets 1/5/9 seconds in each phase. It is distinct from [issue #639](https://github.com/TrillionniumFoundation/Trillionnium-Chain/issues/639)'s unchanged from-zero **4-second / 16-hostile-producer** gate. The original issue definition/history is preserved in `issue-639-observation.json`; this F0 failure neither reruns nor closes that gate.

The observations do not qualify prospective-merge native behavior, independent operators, a WAN campaign, production/F1, PQ or quantum security. Work-verification-stage acceptance counts are not counts of admitted invalid-root hostile packets; the retained ROOT checks report hostile packets absent live and after cold reopen.

## Files and derivation

`analysis.json` is the bounded machine-readable review, with exact inputs, all six round rows, per-phase denominator/resource data and immutable source blobs/URLs. `client-import-summary.json` and `phase-performance-summary.json` are derived summaries, not additional native executions. `extract_analysis.py` shows the read-only extraction/aggregation from the prepared download directory; that directory also contains the two derived summary files and complete artifact inventory. Its default paths identify this review's workspace and are not CI selectors.

No wrapper/parser bug has been established by this readback. Any follow-up optimization must preserve the actual backend, independent checks, original deadlines, Host policy and complete denominator, and must be validated by the relevant native gate before a performance claim is made.
