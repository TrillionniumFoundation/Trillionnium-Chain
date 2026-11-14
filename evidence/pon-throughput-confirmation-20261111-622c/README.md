# Independent original 3×30-second native confirmation campaign readback — source 622c402c (HOLD)

This source-locked analysis is an independently verified **failure**, not a successful campaign, throughput improvement, new runtime execution, source-level regression fix, or production qualification. It does **not** inherit observations from prior source `aaa3c539` (6/27 planned) or `5bbc5cff` (3/27 planned).

## Exact original provenance

- Original workflow: [run 42945301519](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42945301519), [job 130276541117](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42945301519/job/130276541117).
- Original complete [artifact 13824444138](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42945301519/artifacts/13824444138): **84,012,013 ZIP bytes**, SHA-256 `8187420dda147ac19833936ed7b21f5955f1ff7b7c703783461be761f42f5e71`. This digest was independently computed from the connector-downloaded original archive, not merely copied from the uploader.
- Actual tested head `622c402c273f6a9f433eb8b63cd501fd1db486e5`, tree `24f41830d3db91862f0289d55e2c29380f2e23f5`, release compiler artifact `d9ae93196ca537afd93bdd42cf87cca88deac8d3f36afbe73b2c228414dc04ec` (identical before/after all three original runs).
- Exact **1,766 unique ZIP entries** and **1,765/1,765** pinned manifest member files, size, SHA-256 and stream CRC verified without extraction or trusting path aliases; **674,031,436** total uncompressed manifest bytes. The three original raw report digests, runner result identities and native exit codes were independently cross-checked.
- The `build` succeeded, original campaigns 1, 2, 3 each returned **exit 101**, with no reported phase-startup errors or report-validation failure. These native failures were preserved. This analysis changes neither original workload nor acceptance predicate.

## Exact fixed denominator and end-to-end failure

| Run | Phase | Confirmed / observed / planned | Timely honest ACK / attempts | Receiver honest work accepted | Hostile attempts / work rejected | History imports | Host checkpoints | Checkpoint CPU / import CPU (nested, seconds) |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | baseline | 1 / 2 / 3 | 14 / 14 | 14 | 0 / 0 | 13 | 131,980 | 5.398 / 6.082 |
| 1 | from-zero | 0 / 1 / 3 | 7 / 7 | 7 | 3,283 / 3,259 | 7 | 74,328 | 3.274 / 3.761 |
| 1 | late-product | 0 / 1 / 3 | 7 / 7 | 7 | 3,184 / 3,161 | 7 | 71,988 | 3.176 / 3.660 |
| 2 | baseline | 1 / 2 / 3 | 14 / 14 | 14 | 0 / 0 | 13 | 129,636 | 5.319 / 6.045 |
| 2 | from-zero | 0 / 1 / 3 | 7 / 7 | 7 | 3,283 / 3,261 | 7 | 74,157 | 3.274 / 3.761 |
| 2 | late-product | 0 / 1 / 3 | 7 / 7 | 7 | 3,243 / 3,220 | 7 | 72,466 | 3.219 / 3.696 |
| 3 | baseline | 1 / 2 / 3 | 14 / 14 | 14 | 0 / 0 | 13 | 128,527 | 5.259 / 6.003 |
| 3 | from-zero | 0 / 1 / 3 | 7 / 7 | 7 | 3,230 / 3,209 | 7 | 73,189 | 3.230 / 3.711 |
| 3 | late-product | 0 / 1 / 3 | 7 / 7 | 7 | 3,137 / 3,118 | 7 | 70,818 | 3.208 / 3.678 |

Fixed original aggregate: **0/3 complete campaigns, 0/9 complete phases, 3/27 planned in-window confirmations**, 12 observed and 15 unreached. All three baseline phases fail even without malicious traffic. The original nine final client/receiver comparisons are **all unequal**. All nine original native phase verifier-error lists include `PUBLIC_REQUEST_DEADLINE`; the original depletion criteria do not hold.

- Honest original Submit: **84/84 timely client success responses**; original receiver reports **84 honest work accepts**. Neither metric is an independent client-confirmed business result. Exact recognized successful confirmation events across the three repeated fixtures refer to **one transaction identifier**; the same fixture must not be claimed as three independent business transactions.
- Hostile calls: **19,360 attempted**, **19,228 work rejections**. These counts are *different* from non-work failures or process-level errors; their difference must not be silently called accepted hostile work. This source lacks the required resource-depletion evidence.
- History: **81** observed import instances, **827,089** completed Host checkpoint calls, **35.355980223 seconds** checkpoint-calling-thread CPU nested inside **40.397126971 seconds** importer-calling-thread CPU (87.52%). **Do not add the nested CPU totals**, equate them to complete worker/host CPU, or assume they can be removed without affecting the original fresh Host checks. Extra checkpoint work suggests a diagnostic priority, not a measured speedup or unique causal explanation.
- The original Host's fixed 0.25 CPU / 2 GiB / zero swap / PID and complete 4-second hostile gate, qualified WAN and long-term cold recovery remain separate; loopback release-profile evidence does not qualify any of them. No unique confirmed business TPS can be reported.

## Reproduction instructions and strict limits

The original ZIP is at the artifact URL above; it is not rehosted in git. Verify its full SHA-256 before processing. Use the ZIP central directory without unrestricted extraction, reject duplicate/nonregular/traversal member names, and require exact equality between the 1,765 `artifact-files.json` paths and all ZIP members besides the manifest itself. Independently stream-hash every member and check its length and CRC.

Parse `results.json`, the three `run-N-raw/report.json` and the three `run-N-phase-readback.json`. Require tested head/tree, successful release build, identical native binary before/after, all three original exit 101 records, and absence of missing startup/report validation. For each original phase, recompute observed/positive/unreached from `confirmations`, positive flags and real `observation.confirmed`, actual `submissions` success/time fences, receiver `full_work_accepted`, hostile process requests/receiver full-work rejected, and compare exact derived phase readback. For each `client_import.native_import_observation`, count complete `history_import` thread CPU separately from `host_checks.phase=checkpoint` calling-thread CPU; these scopes overlap and are never additive. Reject any lost phase or positive evidence promotion.

**No novel native run was started by this independent readback.** The evidence-only child PR commit must not inherit the native runner's pass/fail as its own execution. Further real W1/M06/Host, capacity/churn, receipt-level ambiguous Submit reconciliation, independent History/WAN, production real-customer business and model-throughput acceptance remain **HOLD_NO_GO / Draft**.
