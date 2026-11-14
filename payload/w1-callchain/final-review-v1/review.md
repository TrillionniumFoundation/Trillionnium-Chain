# H5DF / R1 W1 replay call-chain review

## Conclusion

The failing History Work interval runs the native FullLimb verifier synchronously on the independent-import caller thread. It does not launch or join W1 worker threads. The observed caller-thread CPU therefore does not omit a hidden W1 parallel computation. Other server/attacker threads remain outside this clock by design.

There is no evidence-backed non-Host arithmetic change that can currently be claimed to close the original 4 s / 16-worker / 0.25-CPU acceptance failure. Two small source-level repetitions exist; neither has a measured benefit. No implementation, build, native run, API call, source/ref change or frozen-payload modification was performed.

## Exact source and call path

All ten runtime/fixture files listed in summary.json have identical Git blobs at H5DF 5df7ae6f482157c5f7fdcbcd52222117a965053f and R1 2a86462a1ab20c68151719ba4635e3c294391e64. Captured Git blob identities and SHA256 are independently checked.

1. public_v3_from_zero.rs 1285–1286 creates distinct independent-client and receiver Nodes. The receiver is moved to the serving thread (1299–1325); attacker and reader threads use that network service (1338–1392). The independent verifier remains on the calling thread. Its successful on-time History response enters receive_public_page_from_before_observed synchronously at 1444–1463. Replay CPU/ended timestamps are taken before observer.snapshot() (1464–1479).
2. ingress.rs 2670–2711 selects Owner::Exclusive, performs original fixed-parent resolve/initial observations, installs a fresh kernel.verify callback, and retains the mandatory final Host observation.
3. history_import.rs 392–394 surrounds exactly one verify_history_work call with SubmitPhase::Work. That calls WorkCheckedPacket::verify_with_progress at 316–337. store.rs 1200–1221 invokes pon_work::verify_with_progress once.
4. pon_work.rs 481–495 selects FullLimb. Its private checked-input continuation (709–819,824–905) checks current canonical proof/statement, replays the complete transcript using evaluate_transcript_kernel_with_progress::<true,false,true> (859–865,1017–1137), checks the transcript (870), performs the product corrections (873–885,1229–1259), compares the claimed product and performs the final callback (886–899) before constructing VerifiedWork.
5. Actual arithmetic uses maintenance_limb::dot8 / dot_bounded (18–62), synchronous local loops plus SHA256 updates. There is no spawn, rayon, join, async handoff, mutex acquisition or explicit sleep in this active arithmetic chain. The whole fixture has other threads; the statement applies specifically to the W1 verification call.
6. M06 ExecutionControl and scoped-worker accounting are connected only after W1 returns (history_import.rs 398–409). The failed second replay never entered Admission or Execution.

## Reachable waits and meter boundaries

- Each W1 progress callback performs control.alive and history_checkpoint; the latter calls control.check, which checks the original absolute deadline, freshly invokes Host, then checks the same deadline again. The former adjacent duplicate Host read is already removed. No boundary may be cached, skipped or weakened (history_import.rs 29–38,316–337).
- LiveRequestCpu::observe_sample acquires request then global budget mutex (scalar_cpu.rs 787–879). They are released before returning to arithmetic; Host is called before these locks in observe_with_control (678–709). This is not a claim that all code is lock-free.
- Its 5 ms refill wait requires observe_sample to return a deadline, which occurs only with verified_completion=true (855–856). New operations start false (499–513); production promotion is after NativeAdmissionCompletion (1224–1250). Consequently unfinished W1 cannot receive that wait. Neither the 5 ms writer-preparation wait nor M06 joins explain this second Work interval.
- Owner::Exclusive does not enter the shared Node try_lock/1 ms retry loop (history_import.rs 58–84). The fixture's fresh verifier gets its own Node-owned cold account (operator_continuous_owner.rs 543–574; scalar_cpu.rs 1033–1041). The attack receiver has a distinct service domain. These sources expose no competing attacker owner of the verifier's two scalar locks during W1.
- Phase/Host diagnostic updates use try_lock (request_observation.rs 1383–1387; history_import/observation.rs 398/466); snapshot's blocking locks run after synchronous import. They cannot be reclassified as a blocking phase-observer wait.
- The earlier cold-reserve 2 ms polling is real and separately recorded as CpuWait. For pressure replay 1, the page reserve had 56 refusals/56 completed sleeps; replay 2 page and packet reserves each succeeded on the first attempt with zero sleeps. This does not describe an in-Work 5 ms wait.

## Exact existing H5DF x64 measurements

Source is artifact 14124189121, confirmation/report.json SHA256 8b222dc0c57d1995dc2b33332d42cd7686078e5defa7e847abdd62816b40aaee. Selected members were CRC/SHA verified; the full ZIP and ELF were not independently downloaded/hashed. No result is inherited from R1's head/prospective protocol failures.

| Pressure replay | Work wall ms | Work caller CPU ms | Work-attributed Host calls | Host CPU ms | Host summed wall ms |
|---|---:|---:|---:|---:|---:|
| 1, accepted | 1297.461326 | 66.412397 | 1099 | 63.274464 | 164.267306 |
| 2, PUBLIC_REQUEST_DEADLINE | 400.483119 | 19.988815 | 338 | 19.052498 | 22.169405 |

These are the Work buckets, not the entire page's 1221/350 checkpoint counts. All these Host calls were accepted; measurement_failures=0. The counts describe these packets and do not define a universal checkpoint constant.

The recorded CPU residual outside the nested Work-attributed Host spans is 3.137933 ms and 0.936317 ms respectively. This includes arithmetic, scalar accounting and observation overhead; it is not an isolated arithmetic measurement. Host CPU is about 95.28% / 95.32% of recorded Work CPU. Do not add Host CPU to Work CPU.

The last second-replay Work Host call ended at observer-local 398.209377 ms; Work returned at 495.181944 ms, a 96.972567 ms gap. There is no per-TID scheduler state/wakeup or phase-aligned cgroup trace to identify that gap as runnable delay, throttling, blocking, or any specific resource cause. Its proximity to 100 ms is not proof of a throttling period.

ThreadCpuStamp checks the same ThreadId and CLOCK_THREAD_CPUTIME_ID; a different thread or invalid clock becomes unknown rather than zero (request_observation.rs 1562–1609). Phase stamps surround action() (ingress.rs 1326–1336; request_observation.rs 1430–1516), including synchronous callbacks. They exclude other threads, while the wider native Admission stage can have separately accounted M06 workers. That latter fact does not create missing worker CPU in the W1 Work stage.

## Small source-level candidates, not a demonstrated 4-second repair

1. Reuse this invocation's FR transpose. FullLimb noise F=FL*FR computes the 512-word FR transpose via 1038→939–954. Product correction 1 transposes the same unchanged FR again via 1239→1187–1201. Keeping exactly that 2 KiB operation-local transpose can avoid one allocation/permutation, preserving every dot product, transcript byte and original callback. The larger B' transpose is already retained at 1048–1055/1123–1126/1249–1250; proposing that old optimization again would be incorrect.
2. Avoid only the private already-validated A/B rescan. Current proof validation scans C/A/B field words (727–735), decodes immutable A/B (769–774), then the optimized evaluator validates A/B again (1030–1031): 8192 repeated word checks. Any future change must make current-call checked-input provenance explicit, retain original C/A/B error precedence and all callbacks, and preserve all generic evaluator callers (reference/research/arithmetic_facts/legal_attempt/rejection_cache). Unconditionally deleting generic validate calls would be wrong.

Both are source-level repetition claims; generated-code elimination and performance benefit have not been measured. No full transcript is repeated within a single successful call, no completed native fact can substitute for current proof work, and cross-request/challenge reuse is not proposed. Even all recorded non-Host CPU is small in the measured Work scope; that is insufficient evidence to predict a nonlinear deadline outcome.

## Measurement needed before attributing the remaining wall gap

A future separately authorized diagnostic would need the actual importer TID and Work/Host interval markers on one monotonic clock; that TID's running/runnable/sleep state and wakeups; phase-aligned same-cgroup cpu.stat/throttling data; and separately identified attacker/server CPU. Fresh Host cost would need bounded sub-operation attribution without caching any observation. Existing whole-lane cpu.stat snapshots cannot supply this. No such diagnostic was run here.

## Evidence correction

The initial external measurement-excerpts-v1/exact-work-host-attribution.json had a projection-variable shadowing error in original_report.path, and a missing-key worker_count projection. It was preserved, never used as the conclusion's source, and superseded by attribution-corrected-v2/exact-work-host-attribution.json with the fixed original raw pin. Its numerical underlying raw source was unchanged. An empty initial store-history-domain excerpt was a search miss, not proof of no domain; domain-source-v1 contains the actual implementation.
