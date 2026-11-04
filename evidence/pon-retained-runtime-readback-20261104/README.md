# Retained runtime failures, native follow-up and complete cost readback

> **Dated source/status observation, 2026-11-04 10:44:39 UTC:** integration results below remain bound to 93e207c8. Its four original Node/PQ lanes each pass 992/0/27. Original F0, campaign, W1 and priority workflows fail; the required-baseline run remains in progress. [Complete Node/PQ scope](93e-pq-four-lane-terminal-readback.json), [current business outer failures](original-93e-business-outer-terminal-readback.json), [complete current History failures](original-93e-four-lane-history-failures.json), [the original generic-bound DB refusal](original-69d-arm-retained-database-readback.json) and [the separate successful fixed-DB query](original-69d-arm-fixed-database-snapshot.json) preserve their own source/time boundaries. Overall HOLD remains.


This directory records already executed work on exact frozen sources. It is evidence under the sole development plan, not a new plan or a release qualification. The integration branch has continued to advance; each section below names its exact measured source and observation time. Later revisions do not inherit earlier results.

## Latest retained results and current diagnostic source

Integration has advanced concurrently to [93e207c8](https://github.com/TrillionniumFoundation/Trillionnium-Chain/commit/93e207c8d2ccb8509f78566223abc371b9d8118b), an ordinary child of 69d2, with actual merge 5afe5dd2 and tree 1066c679. The completed [69d2 diagnostic source](https://github.com/TrillionniumFoundation/Trillionnium-Chain/commit/69d2e06c48bbbd1e22432f9b557727b140aba361) retains its own four-lane format/strict-Clippy, complete-workspace no-run build, 60 selected tests per lane and 987/0/27 complete Node-library results. All four original 69d long-History executions failed; their new inner diagnostics are now fully retained. These results and the older 73ab costs do not qualify 93e.

| Frozen measured scope | Actual result | Evidence |
| --- | --- | --- |
| 69d original formatting and strict Node Clippy, x64/ARM head/actual merge | All four original lanes succeed | [Current format/lint and queue evidence](69d-format-lint-and-baseline-queue-readback.json) |
| 69d original workspace test profile, four lanes | Full workspace/all-targets/all-features no-run build succeeds; each lane executes 60 distinct selected tests, all PASS | [Current workspace terminal evidence](69d-original-workspace-four-lane-terminal-readback.json) |
| 69d complete original Node library, four lanes | Each 987 PASS / 0 FAIL / 27 ignored; 49 explicit controls and four separate cost selectors succeed per lane | [Current Node/PQ component terminal evidence](69d-pq-four-lane-terminal-readback.json) |
| 69d original 4,105-block History, four lanes | All four 0 PASS / 1 FAIL, exit 101; x64 next-RPC failures after 2,162/2,844 successful imports, ARM final-page import deadlines after 4,104 | [Complete current diagnostic source](original-69d-four-lane-history-failures.json) |
| 73ab original release, x64/ARM head/actual merge | All four lanes pass original four selectors and three pipelines | [Release terminal record](73ab-release-finality-four-lane-terminal.json) |
| 73ab original stable/nightly locked-fetch contexts | Four actual executions, exit 0, no timeout | [Fetch terminal record](73ab-locked-fetch-four-context-terminal-readback.json) |
| 73ab complete Node library, four lanes | Each 985 PASS / 0 FAIL / 27 ignored; original 49 explicit controls and strict Clippy pass | [PQ/native terminal record](73ab-pq-four-lane-terminal-readback.json) |
| 73ab original F0 | 1/6 original-window confirmations; 0/6 original scheduled four-second target | [Complete native cost record](original-73ab-native-cost-readback.json) |
| 73ab original three-run campaign | 6/27 confirmed, 9 observed unconfirmed, 12 unobserved; all nine phase criteria fail | [Complete native cost record](original-73ab-native-cost-readback.json) |
| 73ab W1 fresh-service and service-model | Both fresh native assertions fail; all four service-model business validators reject CONFIRMATION_TARGET | [Six original failures](original-73ab-service-w1-failures.json) |

Overall HOLD remains. Passing native controls and archive readers do not close the failing public confirmation, long-sync or independent qualification gates. The [earlier owned PR section](pr-688-runtime-section-before-20261104-0810.md) and [the section before the latest consolidation](pr-688-runtime-section-before-20261104-094909.md) are retained verbatim; their pending/current statements describe their own observation times.

## Two concrete engineering closures

[Repair 00099642](https://github.com/TrillionniumFoundation/Trillionnium-Chain/commit/00099642bb4d3d9bb7f0f428a65f401c1c1a2c47) writes and closes a same-directory temporary SIGKILL marker, then renames it before the existing parent's exact check. The original five cuts, deadlines, debt and durable-block assertions remain. The original [f35 ARM failure](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/41752900431/job/126322034210) remains 967 passed / 1 failed / 25 ignored: the admitted marker was visible while its payload was still empty.

The [actual ARM follow-up](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/41763088481/job/126355064041) measured 00099642, tree `158f55c4676da3b05fefd6abda207e7946fc6298`. Source guards before/after matched all 7,986 files / 929,288,390 bytes, and both project audits passed. All five cuts received signal 9; all preserved the unreconciled debt fence and refused a new CPU account. The admitted and activated blocks survived reopen.

The same job executed the two original native authenticated-storage/migration export selectors, all 29 independent storage-oracle controls, and both original reconstruction CLIs on the actual exported databases. All passed. Locked graph, formatting, source/claim controls and strict Node Clippy also passed. These are three existing exact Rust selectors, not three new tests or a complete Node/workspace run. The original C3 oracle 28-control result (15 failures / 9 errors from NATIVE_STORAGE_TABLE_NAME) is preserved separately.

Rust 1.95.0 used the original test profile: the Node compiler artifact records opt-level 3 with debug assertions and overflow checks enabled. Python 3.12.3 used numpy 1.26.4 and cryptography 50.0.2. No separate ELF digest was recorded. A process kill does not establish physical power-loss durability.

## Original failures and costs remain failed

The [nine-artifact reader](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/41766300448/job/126365358821) checked exact original ZIP sizes/hashes, all selected member read lengths, and six pinned raw campaign report hashes. All nine archives completed with no omitted members under the original bounds. The reader did not execute archived code or grant acceptance.

The 016271 campaign has its own **3/27** confirmations: 3 confirmed, 9 observed unconfirmed, 15 unobserved. Every original phase lasted 30 seconds and failed its native criterion; all three native commands returned 101. All three baseline phases had an empty verifier-error list; six pressure phases reported PUBLIC_REQUEST_DEADLINE. First baseline confirmations ended at 28.719374647 / 28.811780496 / 28.594533451 seconds from each original phase epoch. These are actual timestamps, not a scheduled four-second pass.

The same source's F0 command returned 101 with NATIVE_F0_FAILED and BASELINE_MUST_PASS. Its fixed denominator remains six. Its complete confirmation count is intentionally null in this record because the initial bounded console did not display all six original planned rows; the complete small reports and ZIP remain in the reader artifact.

Both frozen campaign cohorts retain all 9 phases × 2 roles × 16 native stages. All stage counters were observed; calling-thread CPU unknown and unwinding calls were zero. Six client pressure activation rows in each cohort were not entered, with complete CPU null. AccountGraph includes both complete and partial scoped-frontier verification, so its calls cannot be called full traversal counts. Its costs overlap verify_state, admission and publication; do not add them or infer isolated SQL COMMIT/fsync cost. The attached projections retain exact raw member identities and per-phase values.

## Reproducible records

- [Native closure and failure ledger](native-closure-and-failures.json)
- [Original native-cost projections](native-cost-projections.json)
- [Native artifact](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/41763088481/artifacts/13292622407): 1,000,976 bytes, SHA-256 `2eb6ab671e9ea76a4df9b3340db753f0c545c02a60ab650ed05cb6f1c5c3f314`.
- [Reader artifact](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/41766300448/artifacts/13292893021): 316,377,415 bytes, SHA-256 `402ed0c016d369062628e44c3a03123de745e41622632baa6ba830f366e18cf4`. This retains original ZIPs, member indexes and full selected excerpts, including fields omitted from console display.

Complete service targets, increasing-account/history costs, long-history fault recovery, independent operator/security review, whole-chain PQ and production eligibility remain open. No activation, merge or independent approval is implied.

## Supplement: complete F0 and fresh-process failure readback

The [eleven-artifact reader](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/41768377123/job/126372027338) completed on exact reader source `e1ef368ab304d9bb8ef177184b98b8d2d29ed835`, tree `3eb26dec9a647be74a57f515715e42e15e94d39b`. Both source guards verified 7,963 files / 926,973,975 bytes; the project audit passed. All eleven original archives completed with zero omitted selected members under the unchanged reader bounds. It executed no archived native code.

Both original small 016271 F0 reports now supply all six planned rows: **0/6 confirmed and 0/6 scheduled four-second SLO**. Two rounds were observed and unconfirmed; four were unobserved, with null actual timestamps and latencies. The observed baseline and ROOT rounds ended 29.001996243 and 29.059899379 seconds after their scheduled starts. The original command returned 101, with NATIVE_F0_FAILED and BASELINE_MUST_PASS. All three owned services were validated and observed empty, and finalization recorded all_services_known_empty=true while complete_success=false. This was not a cleanup failure. The earlier v4 null count is kept as the initial incomplete readback, not silently rewritten.

The same source's [original W1 fresh-service run](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/41760812907) failed on both head and actual prospective merge `554a76fb8e21f160806692c753ca3ea6ad53a42f`, sharing tree `e0a48a52802852a08bf80ffc564c23e20bc91358`. In each lane, the original selector returned 0 with one native test passed, but finite_target_met=false and the runner reported CONFIRMATION_TARGET. The fresh-process selector returned 101 with one native test failed, finite_target_met=false and FRESH_NATIVE_PROCESS_REQUIRED. All four last replay diagnostics were history_call_index=0, replay_accepted=false and PUBLIC_REQUEST_DEADLINE in from-zero-pressure. The original four-second window and 16 attack workers remain. A native test exit of zero does not turn a false business criterion into a pass.

[Complete supplementary observations](v5-confirmation-and-fresh-readback.json) retain both F0 reports' exact member hashes, the W1 manifest/Host/source fields, selected original native log lines, all eleven archive identities and the before/after reader source guards. The [reader artifact](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/41768377123/artifacts/13293922589) is 326,730,178 bytes, SHA-256 `5f4d53f210040fd9c870b17ba88bc7d2631ac80243675064c63210427adf3a0c`; it contains original ZIPs, indexes and full selected excerpts. These frozen failures are not qualifications of later implementation sources.

## Formatter gate and source-bound follow-up

The frozen `41dd661222285728720b97519da1f5a024c7716b` source passed its actual project audit, source/claim checks, repository checks and locked graph, then failed Rust 1.95 formatting. The original PQ x64 HEAD, recent ARM HEAD and branch ARM prospective-merge logs contain the same thirteen formatter hunks in three files. This did not execute the planned Node test-binary build or downstream Node tests.

The [frozen supplemental job](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/41770745958/job/126379603657) also stopped at that formatting gate. Its before/after guards matched all 8,026 files / 931,949,909 bytes and both project audits passed. The retained [artifact](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/41770745958/artifacts/13295465583) is 127,332 bytes, SHA-256 `cbd3fab7fed312bc0e110b6fd187147d54f30d1f2250b863a6afd3e5ad361fe2`. Its requested Node selectors, storage-oracle execution and strict Node Clippy were not reached; the separately pinned provider preparation remains a separate executed step.

[Follow-up `6f458c4f`](https://github.com/TrillionniumFoundation/Trillionnium-Chain/commit/6f458c4fbf07a0a44d7d7a6f451aa960c1b0a029) applies those exact formatter changes and skips mathematical-cache work when a node is already at its requested depth. The original lift returns the current digest for that empty range. Every original test line remains; added controls compare 8,193 real one-level lifts against the original function and check both the 8,192-entry boundary and original overflow clearing. All 384 corpus keys, 296 required paths and original test selectors remain; all twenty inline source hashes match the new tree. Actual gains are unmeasured.

[The complete failed-format and follow-up record](41dd-format-gate-and-followup.json) binds the original diff, source guards, command receipts, archive and seven changed leaf entries. Current native validation is pending on its own exact source. The supplemental workflow now includes nineteen existing exact state/transaction/cache selectors, plus the original SIGKILL, Rust exports, independent oracle and strict lint scopes. Repetition does not increase the unique-test denominator.

## Completed v6 readback and preserved business failures

The [v6 reader job](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/41772202892/job/126384242458) completed all eighteen frozen archives, with zero selected members omitted. Its source guards matched `c94557593bd858c8622be3af959b6e9331452c90` / tree `c96a81b3d7364f8ac1a6734ef368edfd1b8c4a39` and all 7,966 files / 927,198,646 bytes; its actual project audit passed. The [reader artifact](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/41772202892/artifacts/13294939185) is 369,411,999 bytes, SHA-256 `bc8c4904e5dd94412466193fcd8ed9e317e9442a92aae487fb0221918f638010`.

In all six original `01627151` from-zero lanes, all five native selectors returned 0 with one test passed per selector. Both service and sustained reports passed; the original confirmation report failed with `CONFIRMATION_TARGET`. The recorded terminal says all five native commands and finalization completed, no native test or acceptance stage was unexecuted, and acceptance remained false. The older top-level `execution_finished: false` value is retained alongside those distinct terminal fields. These repetitions add no unique tests, and native test success does not override a failed business criterion.

The original `41dd6612` F0 archive reports `FORMAT_FAILED`, `prepared: false`, and `selector_invocation_attempted: false`. Arm and execution were skipped. Its six planned confirmation slots describe the unexecuted plan; actual native business confirmation measurement remains null. This preparation refusal is not measured zero of six.

[The complete v6 observations](v6-from-zero-and-preparation-readback.json) retain fixed archive identities, hashes, actual manifests and source guards.

## Frozen 6f native commands and composite-parent checker correction

The [frozen 6f supplemental job](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/41772202866/job/126384242062) returned 0 for all 42 recorded commands. It ran nineteen original exact state/transaction/cache selectors, the separate original five-cut SIGKILL parent, two original Rust export selectors, all 29 independent storage-oracle controls, both actual-export oracle CLI reconstructions and strict Node Clippy. Both source guards matched `6f458c4fbf07a0a44d7d7a6f451aa960c1b0a029` / tree `76d3b416eccc6a810634062e036f646f22bffc76`, with all 8,026 files / 931,951,117 bytes; both actual project audits passed.

The job itself failed. The generic one-invocation checker rejected the three legitimate killed child harness invocations of `three_actual_sigkill_cuts_keep_active_state_replay_and_unknown_cpu_fence`, even though that original parent returned 0 with one test passed. [The failed job and exact command receipts](6f-scoped-native-checker-failure.json) retain this distinction. Its [original artifact](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/41772202866/artifacts/13296192102) is 1,062,125 bytes, SHA-256 `4054f91f330b2d819c9cb4fea1857ad2cae992aa42a0cd539b2a286f8c2b7854`.

The auxiliary workflow now handles only that existing composite parent with a dedicated output validator: require its three ordered cuts, actual signal 9, original recovery/debt observations and sole passing parent terminal before invoking the original single-parent validator. Eighteen ordinary selector validators and all native commands, assertions, profiles and timeouts are unchanged. One positive and eighteen negative reader controls are required; they add no native tests. The corrected [frozen 6f job](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/41775481816/job/126394717519) has now completed successfully. [Its exact readback](6f-scoped-native-success.json) preserves all 42 original zero-exit command receipts, the 22 passing parent/export summaries, all three reorg and five History signal-9 cuts, 29 oracle controls, both actual-export reconstructions, strict Node Clippy and both original source/audit checks. The one positive and eighteen negative composite-checker controls are supported by the actual fail-closed step's successful execution; their redirected JSON body was not downloaded. This closes this auxiliary composite-output checker failure for the exact x64 focused job. It does not qualify a full Node run, ARM, performance or another source.

## Separate current cost readback

A separate read-only workflow binds the two original failed `6f458c4f` F0 and three-run campaign archives. It authenticates archive metadata, complete ZIP hashes and original source guards before reading their four raw phase reports. Original snapshots and sixteen stages remain intact. Additive SQL commit-call and exact node-decode differences retain missing, saturated, failed, abandoned, in-flight and unknown observations. A zero or missing cost is never substituted for an unentered or unobserved interval.

The reader requires seventeen SQL controls and five decode-control groups. It preserves the original member, archive, JSON-node and console limits, executes no archived source and grants no native or performance acceptance. The first actual readback is now complete; the original failed native outcomes and measured cost observations are recorded below.

## Actual 6f cost readback and next failed-archive cohort

The [current-cost reader](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/41775481853/job/126394717589) completed successfully on auxiliary source `8102335d91db9a2bfe2cc7c65a2aed7d6f5881b2` / tree `3d8620899228d3023ed5d29a6a240e87b7a1832b`. Both source guards verified 7,972 files / 927,427,337 bytes and both project audits passed. Seventeen SQL reader controls and five decode-control groups passed. Both fixed original archives and all four required raw reports were read, with zero selected-member omissions. Some optional console lines were bounded; their full excerpts and original members remain retained.

[Complete current observations](6f-native-cost-and-confirmation-readback.json) preserve the original source guards, exact ZIP/member hashes, all four native cost projections and both F0 terminal reports. The [reader artifact](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/41775481853/artifacts/13296772091) is 72,766,949 bytes, SHA-256 `823ca76ca1bce34608f7890317e8866260ecfdf9e3f2790b4be7155c4e65b779`, and retains the complete raw snapshots.

| Original current-source cohort | Actual result |
| --- | --- |
| F0, six planned confirmations | 1 confirmed, 2 observed unconfirmed, 3 unobserved; 1/6 |
| F0, original scheduled four-second window | 0/6 |
| Three-run campaign, 27 planned confirmations | 3 confirmed, 9 observed unconfirmed, 15 unobserved; 3/27 |
| Three baseline client graph intervals | 62 calls each; 17.861–18.213 seconds wall |
| Same baseline client SQL commit calls | 7 admission and 9 reorg-step calls each; 18.669–20.306 milliseconds total wall |
| Same baseline exact node decode counts | 68,002 calls; 67,874 exact hits; 128 original decodes; 108 bounded probe refusals; no borrow conflicts |

All 22 receiver/client observations preserve the original sixteen stages: 352 rows, including seven not-entered rows. The additive SQL child has 88 closed site intervals, 37 entered and 51 unentered. Entered SQL calls in these intervals show no failures, abandoned/unwinding calls or CPU-unknown calls; unentered complete wall/CPU values stay null. All 22 decode differences are observed. These are observations of these intervals, not a claim that no failing or cancelled request exists.

Account-graph work remains the measured investigation priority. The interval includes actual SQL reads, exact byte/cache comparisons, lift/path arithmetic, graph containers and the original progress callbacks. Those callbacks also perform live Host resource checks. These aggregate measurements do not isolate the constituents; exact decode counts are not SQL-read counts. Nested stage costs cannot be added, and Host CPU includes each actual invoking thread while enclosing phase CPU excludes scoped workers.

A separate bounded reader now freezes the four original `01627151` long-history failures and both current `6f458c4f` W1 fresh-service failures. It reads only the original native logs, manifests, source identities and Host records. It does not rerun their tests or reuse an older native error label. All six ZIP identities were independently checked against original job/API records. The [actual six-archive reader](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/41776513691/job/126398047214) has completed successfully. All six archives were read with zero selected-member omissions, source mismatches or unknown source bindings. [The preserved failures](original-long-history-and-current-w1-failures.json) retain original JSON lines verbatim, including integer timestamps that must not be rounded through JavaScript numbers. The four old long-history runs each failed the original selector with `IO: Connection refused (os error 111)` after the service's original 1,800-second lifetime expired. The last reported progress was 3,000 / 2,000 / 2,500 / 2,500 blocks, not a completed 4,105-block import. Both current W1 fresh lanes preserve `PUBLIC_REQUEST_DEADLINE`, `finite_target_met: false` and the original 4-second / 16-worker / six-depth requirements. The named original selector's exit 0 does not override its failed confirmation criterion. These are diagnosed native failures, not closed performance gates.

## Exact current-source core and workspace receipts

[Ten original core lanes](6f-ten-lane-core-evidence.json) bind the four Recent, four Branch and two ARM W1-factorial logs to `6f458c4f` or actual merge `4d0bcfb7`, with the same tree `76d3b416`. [The two x64 W1-factorial lanes](6f-w1-two-x64-factorial-terminal-readback.json) are preserved separately. Each original W1 History group reports 28 passed / 0 failed / 1 original child fixture ignored. The 29 registered names include the concurrent codec selector. All original five-cut recovery and debt qualifications remain explicit. Runs across architectures and repeated selectors do not add unique tests.

[Four original workspace lane logs](6f-workspace-four-lane-terminal-readback.json) each contain the same 49 distinct selected tests with actual one-pass terminals. The original whole-workspace command is `--no-run`, so it establishes compilation of that graph, not execution of every workspace test. Each lane's original growth reader reports nine cohorts, 72 measured blocks, nine cancellations and nine cold reopens. The redirected native growth log and exit file were not downloaded during that readback; p99 remains null, and throughput, public-network readiness and production activation remain false.

## Full Node regression retains the ARM merge failure

[All four full Node/PQ lanes](6f-pq-four-lane-terminal-readback.json) are now terminal. The x64 head, x64 actual merge and ARM head each report 975 passed / 0 failed / 25 ignored. The ARM actual merge reports 974 passed / 1 failed / 25 ignored. Its original failing selector is `guarded_npq6_valid_submit_cleanup_preserves_primary_error_and_child_diagnostics`, which returned `FRAME_EOF` during the initial valid submit. The original cleanup subsequently completed, the child was reaped and the primary error was preserved.

The child diagnostic records a committed witness CAS with a 381,040,169 ns COMMIT-call wall interval and 517,760 ns caller CPU, followed by a broken pipe. The client keeps its original 250 ms exchange cap. This supports investigating late durable completion; it does not by itself prove a journal-mode cause. The failed parent's detailed observer output was unavailable because the original process log limit had already been reached. That missing observation remains explicit. All original 43 separately invoked PQ controls exited zero, but their selector inventory does not include this failing combined selector; they do not close its failure. The failed full-suite result is retained without a timeout increase or successful-rerun substitution.

## Existing Host-observer evidence readback

A new bounded reader reads only the same two original current-source F0/campaign ZIPs and four raw reports already authenticated above. It binds every retained History response, tip/after request context and supplied packet count before interpreting existing client import and Host observations. It retains all four Host phases, all nineteen original page/packet phase slots, failures, unfinished calls, missing observations and raw timestamps. Host CPU includes each invoking thread and is not an exclusive fraction of the caller-only import or account-graph CPU.

The reader requires 22 synthetic consistency controls and preserves the original 2 MiB metadata, 32 MiB member, 160 MiB selected-member, 25,000-member, 200,000-JSON-node and 70,000-character console bounds. Full projections and original ZIP bytes remain in the artifact. It changes no instrumentation, source test, Host check frequency, resource budget or deadline. [The first actual reader job](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/41778445413/job/126404171308) failed at Python module parsing: a closing parenthesis was missing from the retained response-packet-count expression. Its before/after source guards and both project audits passed. [The complete failure receipt](host-reader-original-syntax-failure.json) preserves the SyntaxError and the two-file, 752-byte source-only artifact; the 22 controls, two ZIP downloads and four Host projections did not execute, so Host results remain null. The follow-up changes exactly one character, adding the missing parenthesis. All binding checks, original targets, bounds and native sources remain unchanged. The corrected [reader job](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/41778879626/job/126405579251) completed successfully on auxiliary source `2f2f53d3` / tree `51211a40`; both source guards verified 7,984 files / 928,659,678 bytes and both actual audits passed. All 22 reader controls, both exact original ZIPs and four raw reports completed with zero selected-member omissions. [The actual Host readback](6f-host-readback-success.json) preserves the complete compact projections and their limits. This closes the reader parse failure; it does not change any original native failure.

[The remaining-gate inventory](existing-plan-remaining-blockers.json) is a source-bound readback of the existing sole development plan and original acceptance contracts. It is not a new roadmap or an acceptance grant. Current native failures and external independent-review, hardware, WAN, model and activation requirements remain open where no corresponding original evidence exists.

The integration branch subsequently advanced concurrently to `44d3def32f515b98fc41f074fe1b88e97f046191`, a child of the measured `6f458c4f`. All frozen `6f` native observations in this directory retain their original source scope. They do not qualify the later recovery, retention, cache or SHA-2 backend changes.

## Measured Host checkpoint cost in the same frozen 6f reports

The successful Host readback authenticates the same four raw member hashes as the preceding SQL/decode readback. It does not select a new performance sample or rerun native code.

| Original campaign phase | Accepted checkpoint calls | Recorded checkpoint CPU, seconds | Recorded checkpoint wall, seconds |
| --- | ---: | ---: | ---: |
| Run 1 baseline | 82,935 | 4.580288960 | 6.592916204 |
| Run 2 baseline | 82,934 | 4.563092387 | 6.185134145 |
| Run 3 baseline | 82,925 | 4.585642696 | 6.834905309 |

The eleven phases contain 59 History rows: 57 valid native observers and two missing-or-invalid rows. Outer import results are 51 succeeded, six failed and two unknown. The two unknown rows are F0 baseline `history[11]` and campaign run 2 from-zero `history[3]`; those phases keep their complete cost totals null. Their detailed validation reasons remain in the full artifact and were not emitted in the compact console. All 59 compact History rows were emitted without display cropping.

The valid observers retain 561,421 Host invocations, including 561,250 checkpoints, with zero recorded Host rejections, unfinished calls or clock-unknown calls. Six outer imports nevertheless failed. These Host outcomes do not establish import or business success. Checkpoint CPU includes each actual calling thread, including workers that call the wrapper; graph/import caller CPU has a different scope. Their totals cannot be subtracted or treated as exclusive percentages.

The original `KernelBudget::verify` performs fresh path/metadata/thread-membership/limits checks at each checkpoint. The observer does not separately time the file operations, parsing or metadata work, so this readback does not establish which subcomponent dominates. No descriptor reuse, authorization cache, reduced checkpoint frequency or unmeasured numeric-parser change is adopted from these aggregate observations.

The [full Host readback artifact](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/41778879626/artifacts/13297928663) is 72,695,546 bytes, SHA-256 `19b417590069612a932840c8a245d7db2871e259af14ce307b67d33148c600a4`. It retains both original ZIPs and the full client-import, four-Host-phase and nineteen-phase page/packet projections.

## Historical 016 state-lane terminals

[All four original state lanes](016-four-lane-state-terminal-readback.json) are now terminal and their original logs have been read. Each x64/ARM head/actual-merge lane executed the same 42 distinct named selectors across seven top-level invocations: two large-state controls, the explicitly selected original ignored capacity control, the 36-test migration group and three range/reorganization controls. Each selected top-level result reports zero failed and zero ignored. Nested migration children and grep reprints do not add tests.

The two ARM capacity invocations took 6,591.58 and 6,581.54 seconds under their original release commands and limits. These results bind `01627151` / actual merge `554a76fb`, tree `e0a48a52`. They do not qualify a later source, close the touched-set complexity gate or establish the public confirmation SLO. The old history and service failures remain separate.

## Exact 44d branch-count failure and a10 follow-up

[Four original 44d Branch failures](44d-branch-count-guard-failure.json) retain the actual module terminal: six passed, zero failed, two explicitly ignored. The original workflow still required five passed and one ignored, so its following grep exited one. The newly retained collision control passed; the newly retained complete-graph cost diagnostic remained explicitly ignored. The old ignored constant-table diagnostic also remained. Later commands in that failed shell and subsequent skipped steps were not executed.

[Integration follow-up a10c3902](https://github.com/TrillionniumFoundation/Trillionnium-Chain/commit/a10c39025cdc03d3265b031d6547b11e0350da2c) changes only that exact result count to six/two and the workflow's existing corpus pin. Recursive tree readback verified exactly two modified leaves, 8,095 files / 932,581,466 bytes, and no native-source changes. All 384 pinned keys and 296 required paths remain. Its tree is `f82a65891b8c5d094ad9a67450751253ec150910`; actual merge `0dac3ffa4513860c9c063b9f8ffb6a022d22ba64` has the same tree and ordered parents `dd6e1c3c`, `a10c3902`. [Its own Branch execution](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/41780585786) now completes all four original lanes; the source-bound terminal evidence is recorded below.

## Actual 44d native terminal evidence and a10 Branch closure

The four original x64/ARM head/actual-merge cohorts remain separate. All observations bind their own source; a later source does not inherit full native qualification.

| Evidence | Original observed result | Scope |
| --- | --- | --- |
| [44d complete Node and PQ](44d-pq-four-lane-terminal-readback.json) | Each of four original Node library runs: 980 PASS, 0 FAIL, 26 ignored; each lane also executes its original 47 explicit controls and strict Node Clippy successfully | Original test profile and four exact-source lanes; 1,006 registered per library run. Repeated controls and subprocess 1-PASS rows are not added to the unique denominator. |
| [44d Recent](44d-recent-four-lane-terminal-readback.json) | All four original lanes pass; History group 6/0/3 and authenticated group 91/0/0 | Original source, formatter and lint evidence retained. The separate default library registry is 990. |
| [44d workspace CPU selections](44d-workspace-four-lane-terminal-readback.json) | The same 49 selected native tests pass in each lane; whole workspace compiles with --no-run | This is not a whole-workspace test run. Nine growth cohorts retain 72 measured blocks, nine cancellations and nine cold reopens, with unresolved p99 and qualification fields. |
| [44d W1 factorial selections](44d-w1-factorial-four-lane-terminal-readback.json) | Each lane retains History 28 PASS / 0 FAIL / 1 original ignored and the original 6/6/1/5/11-test groups | Five original actual SIGKILL cuts remain separate. These component controls do not establish the failing fresh-service business gate. |
| [44d state and capacity](44d-four-lane-state-terminal-readback.json) | All four original lanes pass the same 42 distinct named tests across seven top-level groups, including the explicitly selected original ignored capacity control and 36-test migration group | Original release profile, before/after source guards and audits retained. Nested children and repeated summaries are not additional tests; no touched-set or service-SLO qualification. |
| [a10 Branch](a10-branch-four-lane-terminal-readback.json) | All four original lanes complete the corrected exact 6/0/2 guard, later original tests and strict Node Clippy | Source before/after and actual audits bind a10 / actual merge 0dac3ffa, tree f82a6589. Only the workflow count and its existing corpus pin changed. |

The original 6f ARM merge failure in `guarded_npq6_valid_submit_cleanup_preserves_primary_error_and_child_diagnostics` remains in its earlier evidence. The 44d 47-name selected registry does not contain that selector. A complete-suite 980/0/26 terminal is a different observation, not a separately read positive control for that one name and not proof that the earlier 381 ms durable-commit tail now meets the original 250 ms client exchange bound. All original whole-chain quantum-security qualification flags remain false.

## Completed frozen 44d native cost and Host readback

[The cost and confirmation record](44d-native-cost-and-confirmation-readback.json) binds the original F0 ZIP 13298581298 and original three-run campaign ZIP 13297768757, not an auxiliary-branch native execution. Reader run 41781610161 / job 126414205574 actually succeeds after the original 17 SQL controls and five decode-control groups. Both exact ZIPs and all four raw report bytes/hashes are verified; zero selected archive members are omitted. Before/after diagnostic source guards and audits bind 62b6bf2a, tree 3d5d9ff8, 7,992 entries / 929,073,543 bytes.

The original native/business results remain failed:

- F0 confirms 1 of 6 planned rounds inside its original windows, with two observed unconfirmed and three unobserved. Its original scheduled four-second result is **0/6**. The first confirmed round ends at phase epoch 28.297656297 s, or 27.297656297 s after its scheduled start; it is 23.297656297 s beyond the four-second deadline. Original native exit 101, NATIVE_F0_FAILED and BASELINE_MUST_PASS remain.
- The three original campaign runs confirm **3/27**, with nine observed unconfirmed and 15 unobserved rounds. All nine phase criteria fail. Five of six pressure phases report PUBLIC_REQUEST_DEADLINE; run-2 late-product has an empty verifier-errors array and still fails its criteria. Both F0 verifier-errors arrays are also empty; no deadline error is invented for them.
- All 16 original stages remain in every receiver/client role: 22 roles, 352 stage rows, 330 entered and 22 unentered. SQL has 88 rows, 36 entered and 52 unentered. Unentered SQL wall/CPU values remain null. The original native-stage records retain their different unentered representation (wall_ns=0 and complete_cpu_ns=null). The observed SQL rows have zero failed, abandoned, unwinding or CPU-unknown calls; this does not erase the public-operation failures.

| Original campaign baseline | Client account-graph calls | Account-graph wall / caller CPU, seconds | Measured SQL commit wall, milliseconds |
| --- | ---: | --- | ---: |
| run 1 | 62 | 18.310584629 / 4.107554154 | 19.166675 |
| run 2 | 62 | 17.936598560 / 4.052001681 | 96.232610 |
| run 3 | 62 | 18.159630625 / 4.038814428 | 17.709296 |

Each baseline also retains 68,002 native node-decode calls: 67,874 exact node-ID-and-byte hits, 128 original decodes, 20 retention operations during the interval and 108 probe refusals. Hits bind the freshly selected SQL blob bytes and expected node ID; no graph membership or authority verdict is retained. This corrects the earlier ed566 prose label, which confused this arithmetic cache with the separate CurrentAccounts projection. The original counters and literal evidence are unchanged; the retention delta is not the number of occupied slots.

[The independent Host record](44d-host-readback-success.json), run 41781610174 / job 126414205777, actually passes 22 reader controls and reads the same four original raw reports. Its complete compact projections contain 11 phases and 52 History records: 51 valid observer records, comprising 46 successful and five failed imports, plus one unknown record. Run-2 late-product history[3] remains unknown, so that phase's complete totals remain null. F0 valid-work-root has an empty History array; its Host/import costs also remain null, not measured zero.

The known checkpoint subtotal is 496,411 completed/accepted calls; it does not fill either missing denominator. The three baseline checkpoint CPU values are 4.602467924, 4.569368482 and 4.546044413 seconds, from 82,936, 82,935 and 82,904 calls. Corresponding original client import wall times are 24.935915725, 24.505508223 and 24.355024741 seconds. Host CPU spans all actual invoking threads, while caller CPU has its original narrower scope. These nested intervals cannot be added or divided to claim an exclusive fraction, and there is no fresh-I/O substage timing to assign that cost to a particular syscall.

Output artifacts are [cost 13299865878](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/41781610161/artifacts/13299865878), 71,973,539 bytes, SHA-256 976a53d410366fca69474f066c88fb013dc9f4b245caa6c7396d5f2ff2e86892, and [Host 13299103868](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/41781610174/artifacts/13299103868), 71,886,609 bytes, SHA-256 1abee3916a016540831ca5b214edd576a9af728a0af73ce68304ac7353505c7c. Raw console JSON strings preserve exact integer tokens; original ZIPs and selected complete report bytes remain in those artifacts. Reader success grants no native, ABBA, p99, throughput or production acceptance.

## Completed old baseline and current W1 failure readback

[Four original failure archives](original-baseline-016-and-w1-44d-failures.json) are now actually read by run 41781610159 / job 126414206007: four completed archives, 78 selected records, 667,906 selected small-member bytes, zero missing, omitted, mismatched or source-unknown entries. Before/after diagnostic source and both audits agree.

The old 016 head/merge baseline lanes each execute all five named native selectors successfully, but only service and sustained validators pass; the original confirmation validator fails with CONFIRMATION_TARGET. Original `execution_finished=false`, `native_execution_completed=true` and `acceptance_passed=false` remain distinct.

The two 44d W1 fresh lanes retain an original selector PASS followed by failed business confirmation, then a fresh selector native failure, exit 101 / FRESH_NATIVE_PROCESS_REQUIRED. Original-selector last replay is accepted=true/error=null at indices 0 and 2 respectively; the fresh-selector last replay fails with PUBLIC_REQUEST_DEADLINE at those indices. The original failure-diagnostic field finite_target_met=false is retained as an observed report field; it is not described as successful gate validation. Unprovided business-confirmation counts and manifest named_execution remain null. Normal Host cleanup does not replace these failures.

The [complete retained output](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/41781610159/artifacts/13299726571) is artifact 13299726571, 21,267,512 bytes, SHA-256 795484075d76c8c0f24576c14f69de11969f8e430705451b476090e13674e1bf. Literal console JSON and original native/Host excerpts retain their source archive/member/line identity.

## Completed four-lane priority service-model failure readback

[Four source-bound original service-model failures](original-44d-priority-service-model-failures.json) have now been read by actual SUCCESS run 41783972276 / job 126421721724. The fixed original artifacts are 13298344954, 13298993182, 13299476462 and 13299640686 from run 41778472816. The reader verifies 108 selected records / 1,212,245 small-member bytes and all 40 original selector log digests, with zero missing, omitted, mismatched or source-unknown members. Before/after source guards and actual audits agree on ed566d78, tree 4ef90dd2, 8,001 entries / 930,436,863 bytes.

Each of the four original lanes executes all five named native tests successfully with exit 0 and no timeout. Original service and sustained validators pass; the original confirmation validator fails with CONFIRMATION_TARGET. Their original confirmation stdout reports finite_target_met=false. Manifest execution_finished=false, terminal native_execution_completed=true, finalization_completed=true and acceptance_passed=false remain distinct. Original unexecuted-native and unexecuted-acceptance arrays are empty. Actual business-confirmation counts remain null because this small-member readback does not extract those large report bodies. Host failure=null, empty final errors and already-collected cleanup do not alter the business failure.

The [retained output artifact](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/41783972276/artifacts/13300122097) is 13300122097, 27,832,105 bytes, SHA-256 2525d97026c6437df1db2f936ca257723f159c813a12d7b72895ea50025d485f. The JSON retains 43 original console JSON strings and 147 native/Host excerpt lines with exact source archive/member/line identity. Complete selected original members and ZIP bytes remain in that artifact.

The reader is a ten-line identity/name/path/scope-only clone of the four-archive implementation that actually passed above. All execution/verification logic, 27 fixed from-zero members, five original selectors, four-target guard and original resource bounds remain byte-identical: ten-minute job cap, 2 MiB metadata, 32 MiB/member, 160 MiB selected bytes/target, 25,000 ZIP members, 200,000 JSON nodes and 70,000 console characters/target. It executes no archived native code.

## Source review of the remaining graph and Host boundary

[The fixed-source static review](44d-account-graph-and-host-static-boundaries.md) records the original RESET/table-mapping counterexample, the four-role/sixteen-slot/4-KiB limits, the foreign-writer-after-COMMIT control, and the distinct fresh Host reads. It explains why an insert counter cannot yet carry parent graph authority across publication writes, and why the existing checkpoint reads cannot be coalesced without changing their observation/error order. This is a source review only; it creates no native result or performance acceptance.

The four 44d capacity invocations took 2,001.78 s (x64 head), 2,637.73 s (x64 actual merge), 2,089.60 s (ARM head) and 2,067.67 s (ARM actual merge). These are their own original finite runtime observations, not a controlled source-pair speedup or a replacement for the separate 4,105-block History result. All four 44d state/capacity terminal logs are now read. The four separate 44d History jobs ended in failure; their original native outcomes have now been read from all four fixed archives, as recorded below.

## Completed original 44d long-History failure readback

[The four original outer terminal records](44d-history-four-lane-outer-terminal-readback.json) retain their earlier observation scope: native exit/counts and internal cause were not exposed in those outer logs and remain null in that record. [The completed four-archive native readback](original-44d-four-lane-history-failures.json) now supplies the actual internal outcomes from the original artifacts, without retroactively filling or rewriting the outer-only observation.

The original selector is `actual_v3_long_chain_public_full_sync_reopen_and_corrupt_index_refusal` in all four lanes. Each original invocation exits 101 with **0 passed / 1 failed / 0 ignored**:

| Original 44d lane | Native elapsed, seconds | Actual failure | Last printed full-sync milestone | Actual server exit |
| --- | ---: | --- | ---: | --- |
| x64 head | 3243.28 | IO: Connection refused (os error 111) | 2000 | lifetime_expired; original 1800 s reached; prior stop flag false |
| x64 actual merge | 3267.49 | IO: Connection refused (os error 111) | 2000 | lifetime_expired; original 1800 s reached; prior stop flag false |
| ARM head | 3161.00 | PUBLIC_REQUEST_DEADLINE | 4000 | stop_requested; lifetime not reached; 1723.402629880 s |
| ARM actual merge | 3229.50 | PUBLIC_REQUEST_DEADLINE | 4000 | stop_requested; lifetime not reached; 1752.986352332 s |

The printed milestones are not exact final imported or committed counts. Those counts, the failing page/checkpoint, the precise ARM deadline origin and whether a durable commit preceded its failure remain null. Original manifest `completed`, `named_execution` and `native_tests_executed` were null and remain so; observed libtest outcomes are recorded separately.

Exact 44d source retains the original 4,105-block scope and 1,800-second server lifetime. Each Public V2 RPC starts its original 30-second overall budget; this selector supplies no outer deadline. The server task uses the earlier of that overall deadline and now plus 10 seconds, with the original five-second output budget. The History page import after the RPC starts a separate original 30-second PAGE_BUDGET. This selector does not invoke the separate shared SYNC_BUDGET=300-second interface. Several original checks can return PUBLIC_REQUEST_DEADLINE; no page/stage attribution is invented for ARM, and its subsequent stop-requested cleanup is not mislabeled as lifetime expiry.

[Reader run 41787024926](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/41787024926), job 126431400722, actually succeeds. It reads four fixed original ZIPs, 48 selected small members / 107,684 bytes, with zero missing, omitted, source-unknown or mismatched members and no console truncation. All original native log lines are retained: 1-37, 1-37, 1-41 and 1-41. Before/after actual audits both PASS with 26 packages. Both source receipts bind `72a6206bf1b0d4d83cc1c1907c2a74ef34dc593e`, tree `619cee0358a6c1d5e48530cad44292fb2486564d`, 8,007 entries / 930,890,238 bytes.

The [complete retained output](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/41787024926/artifacts/13302175606) is artifact 13302175606, 195,379,215 bytes, SHA-256 `25c0803ff1ac4e6c4271a559ffa2b36d41efdccd24ca8733002d2d28e1c1d9f7`. The JSON preserves 42 original console JSON strings and 284 original log excerpts. The bounded reader is the reviewed eleven-line identity/name/path/count/scope-only adaptation of the actual-success six-failure reader: four History targets and zero fresh targets. Original parsing, verification and resource limits remain unchanged. It executes no archived native code; reader success does not close the original History failure.

## Concurrent 40a5 source and static boundary review

[The complete recursive Git-tree comparison](40a5-concurrent-source-static-review.json) binds concurrent integration `40a5ba25e40fd5eda5b04fc1c3811320d438de11`, parent `a10c39025cdc03d3265b031d6547b11e0350da2c`, tree `75fe3367c4896a4f2d5f5dd561914613ec999343`. Actual merge `720606ee3ed65c943bda395c923e4d5b9bc0560c` has ordered parents `dd6e1c3cbeacbdc532b0679297835b3a0aac78f0` and 40a5, with that same tree. There are 8,113 tracked files / 932,942,579 bytes, 30 changed leaves, 18 additions and no deletions. All previous 384 pins / 296 required paths are retained; the new corpus has 389 pins / 301 required paths, and every pin matches its actual Git blob. This is Git-object verification, not an executed worktree receipt or native acceptance.

[RootDigest review](40a5-root-digest-static-review.json) verifies the production commitment-only path against its exact prior source. Full account input ordering, collision checks, owner/balance/nonce binding, fork guards, left/right order and full path/digest/depth cache key remain. Stored record construction, SQL publication and the native-store tail after lift extraction are unchanged. The new production root path avoids unused record IDs and encoding and the duplicate owner-path hash; it still visits the complete account input. Its production path-to-owner relationship comes from the same private `ordered_accounts` call. This finding does not claim equivalence for arbitrary forged private tuples.

[M06 unchanged-snapshot review](40a5-unchanged-snapshot-static-review.json) verifies full current key/value canonical-byte comparison before sharing the immutable prior map. The old fallback, canonical error order, budget behavior, empty-delta tree check, damaged-tree repair and final expected-root check remain. The retained-capacity argument is limited to snapshots constructible through the current public production constructors; it is not generalized to arbitrarily reallocated private vectors or a future encoder. Full-input comparison still scales with total input size.

The two source reviews found no reachable semantic violation in their stated scopes. Three ordinary RootDigest controls plus one ignored cost diagnostic and six ordinary M06 controls plus one ignored diagnostic are identified in source; these reviews execute none of them. They grant no native PASS, speedup, touched-set complexity, p99 or business acceptance. Both paths retain full-input work; account/history scaling and original confirmation deadlines remain open.

## First terminal 40a5 F0 outer observation

[The exact 40a5 F0 outer record](40a5-f0-outer-terminal-readback.json) binds original run 41785836093 / job 126427664011. Source/parser preparation, compiler/graph preparation, source-bound ELF and original controls, and the service-arm step succeed. Original pair execution and finalization fail. Final source verification/retention and artifact upload succeed.

This outer-only readback does not expose the internal native counts, exit/cause or four-second confirmation denominator. All such fields remain null; no earlier 44d or a10 internal outcome is assigned to 40a5. The retained original archive is [artifact 13301461139](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/41785836093/artifacts/13301461139), 15,940,628 bytes, SHA-256 `dba913975f1941d874bdb7d5c82258d69f0c74aa7c1ce2adbd1e11056fb5ea90`. API metadata and the original upload receipt agree. Full original job metadata and terminal log text are retained in the JSON. This observation leaves current-source native/business qualification unresolved.

## Completed frozen 40a native cost and confirmation readback

[The complete 40a cost record](40a5-native-cost-and-confirmation-readback.json) now supplies the inner evidence that was unavailable in the earlier outer-only F0 record. Actual SUCCESS reader [41791107191](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/41791107191), job 126444441307, retains the original 17 SQL controls and five decode-control groups. Both fixed ZIPs and all four complete native report bytes/hashes verify. There are 33 selected members / 105,080,075 bytes and zero omitted members. The two actual audit PASS records and before/after source receipts bind diagnostic b68bf403 / tree c3cbc67d, 8,015 entries / 931,600,847 bytes.

The measured native source remains 40a5ba25 / tree 75fe3367, not the later faa or 73ab revisions:

- Original F0 confirms **0/6** in its original windows and **0/6** against its scheduled four-second bound. Two rounds are observed but unconfirmed; four are unobserved. The first baseline attempt ends at phase epoch 30.002199940 s, 29.002199940 s after its scheduled start, without confirmation. Original exit 101, NATIVE_F0_FAILED and BASELINE_MUST_PASS remain. Its baseline error is PUBLIC_REQUEST_DEADLINE; the root phase error list is empty and its criteria still fail.
- The original three-run campaign confirms **6/27**: six confirmed, nine observed unconfirmed and twelve unobserved. Each baseline confirms two of its three planned rounds; none of the six pressure phases confirms a round. All nine phase criteria fail and all nine report PUBLIC_REQUEST_DEADLINE. These are original-window counts, not a four-second acceptance result.
- Coverage remains all 16 native stages across 11 phases / 22 roles: 352 rows, comprising 336 entered and 16 unentered. SQL has 88 rows, comprising 49 observed and 39 unentered. Unentered SQL wall/CPU stays null; original unentered native-stage wall zero / complete CPU null remains a separate producer representation. No public failure is erased by the observed SQL intervals' zero failure/abandonment/unwinding/CPU-unknown counts.

| 40a original campaign baseline | Client account-graph calls | Account-graph wall / caller CPU, seconds | Observed SQL commit wall subtotal, milliseconds |
| --- | ---: | --- | ---: |
| run 1 | 136 | 15.857839091 / 3.636439891 | 181.769102 |
| run 2 | 137 | 15.881182848 / 3.686882949 | 35.918052 |
| run 3 | 138 | 15.198865829 / 3.714934025 | 108.640015 |

The first confirmed baseline rounds end at phase epochs 13.408139979, 13.308585511 and 13.103585269 seconds. Different completed-round and call counts across sources prevent a controlled speedup or throughput claim from these aggregates. Account-graph, commitment, SQL and end-to-end intervals remain nested, not additive. Node-decode reuse still binds expected node ID plus freshly read complete SQL bytes; it grants no authority and does not imply fewer SQL reads. No new Host projection was run here, so the old 44d checkpoint values are not assigned to 40a.

The [retained output artifact](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/41791107191/artifacts/13302619351) is 13302619351, 83,233,432 bytes, SHA-256 ea4b12aee04bfc2791536d6d934b8881ec32bd452caae1b4a314ae249a0dc877. The durable JSON preserves 24 original console JSON records as strings and the complete reader terminal log. Original selected report members and ZIP bytes remain in that artifact.

## 73ab release toolchain failure repaired and verified

[The original 40a ARM failure](40a5-release-finality-toolchain-failure.json) retains the actual partial-toolchain recovery and cargo-clippy installation conflict. Compilation did not start; the original certificate and pipeline steps were skipped. The origin of the pre-existing partial installation remains unknown.

The repair is ordinary integration commit [73ab6e9a](https://github.com/TrillionniumFoundation/Trillionnium-Chain/commit/73ab6e9a83bcc836e261d93f9bb23ceafe556758), directly after concurrent faa36 recovery/cache/confirmation/fuzz-lock work. Recursive readback verifies exactly one changed leaf, the original release-finality workflow: 7,450 to 7,852 bytes. Tree 65a2100f has 8,120 files / 933,034,956 bytes. All 389 corpus pins / 301 required paths are preserved and match their actual blobs. The pre-change faa source's actual preflight and both source receipts were read from run 41790379662 / job 126442122973.

Build and certificate steps now share one fresh RUSTUP_HOME per run, attempt, runner and lane. The source-pinned minimal Rust 1.95.0 and required clippy/rustfmt components remain. Original Cargo/rustc commands, four exact selectors including the original explicit ignored-test selection, three pipelines, release profile, 30-minute job cap, 300-second per-pipeline cap, final counters and source/artifact checks are unchanged. The repair deletes no shared installation and swallows no failure.

[The four original release lanes](73ab-release-finality-four-lane-terminal.json), [run 41791243030](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/41791243030), now actually succeed:

| Exact 73ab lane | Original job | Actual original selector results |
| --- | ---: | --- |
| x64 head | 126444877220 | Four distinct selectors, each 1 PASS / 0 FAIL / 0 ignored |
| ARM head | 126444877344 | Four distinct selectors, each 1 PASS / 0 FAIL / 0 ignored |
| ARM actual merge | 126444877500 | Four distinct selectors, each 1 PASS / 0 FAIL / 0 ignored |
| x64 actual merge | 126444877622 | Four distinct selectors, each 1 PASS / 0 FAIL / 0 ignored |

Actual merge 88f89924 has ordered parents dd6e1c3c and 73ab6e9a and the same tree. Every lane retains exact before/after source equality, actual audit PASS, successful pinned installation, the same unique Rust home in both relevant steps, original native build and all four named invocations. The three-pattern collect-all pipeline step and original counter reader also succeed in every lane. The complete native result excerpts retain interleaved output and separate-line ok results; repeated printed command text is not extra execution.

This closes the original toolchain-installation blocker on 73ab. Individual pipeline report counters and the actual ELF digest file content were not extracted; they remain null. No four-second public-service, saturation, full-Node, complete-workspace or whole-chain PQ acceptance follows.

## Unexecuted 40a priority cohort and Legacy History boundary

[The exact original 40a priority cancellation](40a5-priority-prejob-cancellation.json) retains run 41785836221, attempt 1, completed/cancelled, with total_count=0 and jobs=[]. No job was instantiated, so it supplies no History/capacity/service native result. Its cancellation initiator and native results remain null. Earlier 44d results are not inherited, and this unexecuted cohort is not removed from the record.

[The fixed-source Legacy operation review](40a5-legacy-history-operation-boundaries.md) explains why authenticated campaign costs cannot directly identify the original 4,105-block selector's bottleneck. That selector uses Legacy storage. For its ordinary successful new-packet path with a stable epoch, there is one W1 verification entry, one canonical M06 execution entry and three historical State constructions; state reconstruction between 128-block snapshots checks actual stored deltas and roots without re-executing old W1 or transactions.

The intended final page has a separate deep activation from genesis. Each attach step checks staging State and the still-active genesis State before commit; actual entered/completed step counts remain unknown after failure. A single arithmetic material entry can alternate between these inputs, so continuous staging-cache reuse cannot be assumed. No speculative wrapper was applied. Fresh PQ-state validation, growth dispatch, original independent roots, actual readbacks, cancellation and publication boundaries remain. Source topology supplies no measured stage shares or exact ARM deadline location.

## Original quality/fuzz fetch failures identified

[The four original 40a fetch failures](original-40a-quality-fuzz-fetch-failures.json) have been read by actual SUCCESS [reader 41792928140](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/41792928140), job 126450249569. All four complete original fetch logs are byte-identical, 301 bytes each, and report that tests/fuzz/Cargo.lock cannot be updated while --locked is supplied. Both quality lanes and both fuzz lanes fail on that same independent manifest. The four original jobs remain failures.

Four source.json members exactly verify 40a head / 720606 actual merge / tree 75fe3367, 8,113 entries / 932,942,579 bytes. The original archives did not contain source-before.json or source-after.json; those two missing members remain null, distinct from the diagnostic reader's own successful before/after receipts. Eight complete selected members total 3,066 bytes. Their fetch text contains no numeric exit code or named missing package, so those original-text observations are not invented.

The source comparison identifies the missing sha2-to-sha2-asm edge and sha2-asm 0.6.4 package in the independent fuzz lock. Concurrent faa36 adds exactly those ten lines while retaining the original --locked commands. That package-level correspondence is an inference from the frozen manifests and full before/after lock comparison; the Cargo error itself only names the lock file. The later 73ab release pass does not prove the independent fetch repair.

Reader source 5c09e132 / tree 71f5328e has 8,019 files / 931,985,269 bytes, with both actual audits PASS. [Output artifact 13303794145](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/41792928140/artifacts/13303794145) is 117,038 bytes, SHA-256 189d42f44310dbae8fd98c158da676631f6dfa6c096c0af68da70509e5e321ba. It preserves all four complete original ZIPs and selected members; the durable JSON retains all 14 original console JSON lines.

## Original locked-fetch subgate repaired and verified in all four contexts

[The complete four-context terminal readback](73ab-locked-fetch-four-context-terminal-readback.json) records actual SUCCESS [run 41795067492](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/41795067492), attempt 1. The workflow originates from diagnostic commit 6e016e7e; measured code is fixed 73ab head and actual merge 88f899, both tree 65a2100f, 8,120 files / 933,034,956 bytes.

| Measured context | Original job | Original command result |
| --- | ---: | --- |
| head / quality, Rust 1.95.0 | 126457112337 | Executed, exit 0, process exit 0, no timeout |
| head / fuzz, nightly-2026-10-01 | 126457112575 | Executed, exit 0, process exit 0, no timeout |
| actual merge / fuzz, nightly-2026-10-01 | 126457112594 | Executed, exit 0, process exit 0, no timeout |
| actual merge / quality, Rust 1.95.0 | 126457112672 | Executed, exit 0, process exit 0, no timeout |

Every lane actually runs the unchanged `cargo fetch --locked --manifest-path tests/fuzz/Cargo.toml` under the original 900-second command owner, ten-second TERM grace and owned-process-group cleanup. No retry or native test is introduced. Requested stable/nightly compilers and their original required components remain. Each context has fresh distinct RUSTUP_HOME and CARGO_HOME. Inner source-before/after/verified and source-consistency flags are all true; every outer before/after pair exactly agrees, and each lane has one actual preflight audit PASS with 26 packages.

All four original lock-file observations equal SHA-256 `8a76c46560cea2f973f1a40cbbaf32f12e542f3b6c963a1061fb01dce045de4d`, matching the fixed source lock. The durable document retains all four complete original manifest strings, eight source receipts and 32 complete original members, including all four fetch logs. Root independently matched every manifest/source/audit literal to its full original job log and rehashed all 32 members plus all four complete job logs, 584,456 bytes. All four artifact identities, byte sizes and SHA-256 upload receipts agree with the API.

This closes the shared locked-fetch refusal on the measured 73ab source. The four original 40a failures remain failed. Full quality checks, fuzz targets, native suites, public-business and performance qualifications are not executed or granted by this fetch-only observation. Later source revisions do not inherit its result.

## Frozen 73ab workflow and open acceptance snapshot

[The timestamped 07:51:22 UTC snapshot](73ab-workflow-and-open-acceptance-status.json) retains all 16 original 73ab workflow observations: nine success, three failure, three in progress and one pending. F0 run 41791243013 fails in original pair execution/finalization; campaign run 41791242816 fails its original three-campaign step; W1 run 41791242629 has two failed fresh-service jobs. Their inner native counts and failure causes were unread in that snapshot and remain null there. The detailed 40a results above are not assigned to 73ab.

The snapshot preserves the then-running PQ, priority and workspace jobs and the pending required baseline. Later terminal results require separate source-bound evidence. At 08:05 UTC the integration branch and PR had advanced concurrently to b8116f65789a85148254f870c678a44f895316de, actual merge 91e2363714964709206f595787b32c55547ec729. That advance does not modify any frozen observation here.

Issues [#639](https://github.com/TrillionniumFoundation/Trillionnium-Chain/issues/639) and [#629](https://github.com/TrillionniumFoundation/Trillionnium-Chain/issues/629) remain open in the recorded snapshot. Original public confirmation under pressure and independently evaluated PQ/W1/economic, recovery, WAN and governed-activation requirements still need their own evidence. Diagnostic reader success, source review and narrow CI repair grant none of those qualifications.


## Completed frozen 73ab native and PQ component cohort

[The four-lane terminal record](73ab-pq-four-lane-terminal-readback.json) binds original [run 41791242683](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/41791242683), head 73ab6e9a and actual merge 88f89924, tree 65a2100f, 8,120 files / 933,034,956 bytes. Each full Node-library invocation reports 985 PASS / 0 FAIL / 27 ignored, 1,012 registered tests. Two nested child-process one-test outputs are not added to the outer result.

Every lane completes the same 49 distinct required component controls and their original named-test checks, with the child-process helper excluded from that roster. The four separate explicitly selected cost diagnostics each pass once; their repeated measurements are not extra tests or a public performance qualification. Original formatting and strict Node Clippy also return zero. Full Node elapsed seconds are 1,323.63 / 1,323.24 on ARM merge/head and 1,376.59 / 1,374.55 on x64 merge/head; these independent jobs are not a controlled architecture comparison.

Root independently rehashed all four full job logs, matched 76 retained literal blocks and all 16 complete cost-output segment hashes, and cross-checked all eight artifact identities with original upload receipts. The complete 49-name source roster, original recorder and named-test checker were separately read by Git blob.

Evidence layers stay explicit: the initial source JSON is directly retained from console; the original successful command recorder requires before/after source equality for every command. Those per-command raw source files remain inside the retained ZIPs and were not separately extracted here. The printed authentication-cost binary digest belongs to that test-profile cost invocation; the full Node build-record ELF digest is unread/null. No ignored test is relabeled PASS and no later source inherits this result.

## Completed frozen 73ab full cost and confirmation readback

[The complete cost evidence](original-73ab-native-cost-readback.json) comes from actual SUCCESS [reader 41797728826](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/41797728826), job 126465723652, on diagnostic 1736ade2 / tree ba4fa0de. Both actual audits PASS with 26 packages and both source receipts agree on 8,028 files / 932,451,482 bytes. The exact 17 SQL controls and five decode-control groups pass.

The reader verifies two original ZIPs, four complete original reports, 33 selected members / 94,965,976 bytes and zero omitted archive members. All 24 original compact JSON strings and 78 original member-log excerpts are preserved. The original console budget still clips some unrelated fields/logs; zero omitted archive members does not mean all full native stdout was printed. Campaign run 2/3 libtest summary counts remain null where the console did not expose them.

- F0: original native exit 101, NATIVE_F0_FAILED and BASELINE_MUST_PASS. Its planned six confirmations contain one confirmed, two observed unconfirmed and three unobserved. The original scheduled four-second result remains 0/6. The one confirmed baseline round ends at phase epoch 27.400817764 seconds, 26.400817764 seconds after its scheduled start; that is not a four-second success. The baseline has PUBLIC_REQUEST_DEADLINE. The root phase has an empty verifier-error list and no entered client native-stage counters, yet its original criterion remains false. No claim that the entire client/RPC process did not run follows.
- Campaign: all three original invocations return 101. Each baseline confirms 2/3 and each pressure phase confirms 0/3, giving 6 confirmed, 9 observed unconfirmed and 12 unobserved across the planned 27. All nine original phase criteria fail. All six pressure phases report PUBLIC_REQUEST_DEADLINE; the three baseline error arrays are empty and still do not pass the original criterion.
- Coverage: all 11 phases, 22 roles and 16 native stages per role remain: 352 rows, 330 entered and 22 not entered. SQL has 88 rows: 36 observed and 52 unentered. The observed SQL intervals contain 357 started/returned/successful calls and no observed SQL failures/abandonments/unknown CPU; this does not erase pre-commit refusals or public failures. Unentered SQL durations remain null.

| 73ab original campaign baseline | Client account-graph calls | Account-graph wall / caller CPU, seconds | Observed SQL commit wall subtotal, milliseconds |
| --- | ---: | --- | ---: |
| run 1 | 124 | 16.133378564 / 3.844399840 | 128.574152 |
| run 2 | 124 | 16.189713331 / 3.837764770 | 44.359511 |
| run 3 | 124 | 16.373165976 / 3.841085166 | 43.258633 |

F0 baseline has 62 account-graph calls, 17.648002309 seconds wall and 3.910179334 seconds caller CPU. Six pressure phases have 31–33 such calls each, approximately 15.50–15.72 seconds wall. These nested intervals do not isolate SQL reads, hashing, allocation, scheduling or Host work. They cannot be added into latency or compared across different completed cohorts as a speedup.

Each campaign baseline's client decode record has 136,004 calls, 135,721 exact hits, 283 original decodes, 39 interval retentions, 244 bounded-probe refusals and zero borrow conflicts. The exact-input decoder does not establish fewer SQL reads or a latency gain. Retained values are gauges, not RSS. No new Host projection was run for this cohort.

The retained output is [artifact 13305684438](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/41797728826/artifacts/13305684438), 79,467,304 bytes, SHA-256 91c6de7bb46439cc97955fdca9560c0649e7a32986f0dacfc9679b55b3f2e035. The measured native source remains 73ab, independently of the reader and current integration.

## Six frozen 73ab original service failures narrowed

[The original six failures](original-73ab-service-w1-failures.json) were read by actual SUCCESS [reader 41798208532](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/41798208532), job 126467281621. Both actual audits PASS with 26 packages; exact before/after source receipts bind diagnostic 8cdd1da9 / tree 43564b4d, 8,029 files / 932,494,839 bytes.

Both original W1 fresh-service jobs run two selectors. The original selector passes its native assertion (1 PASS, exit 0), then its original business validator rejects CONFIRMATION_TARGET. The fresh selector reports 0 PASS / 1 FAIL, exit 101, at the existing aggregate assertion in fresh_challenge.rs:220; the runner records FRESH_NATIVE_PROCESS_REQUIRED. All four process timed_out fields are false. The raw aggregate assertion includes construction validity and baseline/pressure invariants and targets; the precise first or unique failing conjunct remains unknown.

The four service-model jobs each pass all five original named native selectors, exit 0 without timeout. Service and sustained validators pass, while the confirmation validator rejects CONFIRMATION_TARGET in all four contexts. Original execution_finished=false and terminal native_execution_completed=true describe different scopes and are both retained. Confirmation counts not exposed by the bounded small-member read stay null.

The two fresh selectors' last observed pressure replay records include PUBLIC_REQUEST_DEADLINE. This does not identify the internal History deadline checkpoint or prove that this last replay is the sole cause of the aggregate assertion. Authenticated service failures are not assigned the Legacy 4,105-block selector's topology or 1,800-second lifetime cause.

Six fixed original ZIPs contain 132 selected small members / 1,268,655 bytes, with zero missing, omitted, source-unknown or mismatched members. The document preserves all 63 literal JSON records and 531 original member-console lines. Twenty complete short native logs were independently reconstructed and rehashed; four long trace lines remain clipped by the original reader and are not called complete. The complete original member bytes remain in [output artifact 13305189878](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/41798208532/artifacts/13305189878), 38,436,065 bytes, SHA-256 6aec53203cc97ad85ee18ace57e36ad2a91d739471aeacd130f1bcfc53564d93.

## Original long-sync failure-location observation

Integration [69d2e06c](https://github.com/TrillionniumFoundation/Trillionnium-Chain/commit/69d2e06c48bbbd1e22432f9b557727b140aba361) is an ordinary child of concurrent b8116f65. Root's full recursive readback verifies exactly one changed leaf: the original ancestry_long_sync.rs selector file, 16,780 to 19,849 bytes. New tree d9327a58 has 8,127 files / 933,472,602 bytes. Every existing corpus entry remains: 389 pins / 301 required paths, all matching their actual blobs. The exact parent b811's original cloud-input audit and both source receipts were read before editing.

The change fills the specific gap demonstrated by the frozen History failures: an overall error plus 500-page milestones could not identify the current page or whether RPC, decoding, import or later state checks failed. It keeps only fixed-size location/timing state while the original calls run and adds a separate failure_location object to the existing exit JSON. It records the completed successful import-call count, last successful/requested cursors, original unvalidated reply-completion value, operation name and the durations of the original returning head/history RPC and import call expressions.

Each measured call retains its original arguments, then records elapsed time before the original Result is propagated. The import expression includes the existing clock argument preparation; if that argument exits early, its duration stays null. Each new page clears fields that could otherwise be inherited from the previous page. Call durations are captured before confirmer cleanup; no extra Node, SQL, file, network or per-page output operation is added.

The original exact selector, 4,105 blocks, 1,800-second server lifetime, separate original RPC/import deadlines, complete verification, assertion texts, reopened-state checks and shutdown/join/error precedence remain. No observed-import API, retry, larger budget or weaker acceptance rule is introduced. Successful import returns do not prove a final durable commit count after an error; durable_committed_blocks and activation_cursor remain null. Two independent static reviews found no semantic/formatting/type issue in this scope. The current source now passes its original four-lane formatting/strict Clippy, full workspace all-targets/all-features no-run compilation, and 60 distinct selected tests per lane. The original 4,105-block History jobs returned four failure terminals, with successful original builds and matching source-after checks. Complete archived-log readback now locates the x64 errors at the next History RPC and both ARM errors at the attempted 4,105th single-page import expression. No deadline repair or acceptance is claimed from this observation-only change.

## Current 69d build and selected-control terminal evidence

[The four-lane terminal record](69d-original-workspace-four-lane-terminal-readback.json) binds original run 41799271299 to head 69d2e06c and actual merge bfdfc2bf. All eight before/after source receipts agree with tree d9327a58, 8,127 files / 933,472,602 bytes; each actual project audit passes. The original Rust 1.95.0 command builds --workspace --all-targets --all-features --no-run in the unchanged test profile. Its strict shell gate and original compiler-artifact reader both succeed in all four lanes.

Each lane then actually executes 60 different selected test names: 42 Node and 18 M06. All 60 pass, with zero failures or ignored tests within that selected scope. The roster includes four CPU/reactor controls and 56 semantic controls for full-root arithmetic, unchanged canonical maps, independent root-digest references, error/cancellation return observations, ASCII encoding, reorganization tails, current SQL, prepared historical reads and post-write verification. The root independently matched all 240 result segments, every complete libtest terminal, source/audit literals, 36 large-observation fragments and all four upload/API artifact identities. Full workflow text is bound to the actual source blob.

This is full-workspace compilation plus the explicitly selected executions. It is not complete-workspace test execution, a complete Node/M06 suite, original long-sync success or public-service qualification. The growth step succeeded, but its internal report was not read here and growth figures remain null. Redirected compiler-artifact JSON, raw build.exit and executable digest bodies are also unread/null. The separate [format/strict-Clippy record](69d-format-lint-and-baseline-queue-readback.json) retains its actual four successful lanes; its older workspace snapshot remains dated, not silently rewritten.

## Complete original 73ab long-History failures

[The original four-lane History readback](original-73ab-four-lane-history-failures.json) retains the actual unchanged 4,105-block selector from run 41791242964. The successful reader 41801401067 checks four original ZIPs totaling 226,757,308 bytes and 48 selected members / 107,731 bytes, with zero missing or omitted members. Both reader audits and exact source pairs pass. Root independently reconstructed all eight complete native/GNU-resource members and matched their hashes, 42 original JSON lines, 285 member excerpt lines and the original outer receipts.

| Original 73ab lane | Native result and elapsed time | Last printed milestone | Retained error / server exit |
| --- | --- | ---: | --- |
| x64 head | 0 PASS / 1 FAIL / 0 ignored; 3,262.40 s | 2,000 | IO111; original 1,800-second lifetime expired, prior stop false |
| x64 actual merge | 0 PASS / 1 FAIL / 0 ignored; 3,195.67 s | 2,500 | IO111; original 1,800-second lifetime expired, prior stop false |
| ARM head | 0 PASS / 1 FAIL / 0 ignored; 3,289.76 s | 4,000 | PUBLIC_REQUEST_DEADLINE; stop_requested at 1,781.596945188 s, lifetime not expired |
| ARM actual merge | 0 PASS / 1 FAIL / 0 ignored; 3,269.38 s | 4,000 | PUBLIC_REQUEST_DEADLINE; stop_requested at 1,766.083925624 s, lifetime not expired |

Every original native invocation exits 101. The printed milestones are not exact successful-import, committed-block or activation-cursor counts. Failed page, operation boundary, deadline origin, exact durable count and complete 4,105-block confirmation remain null. In particular, this source's x64-merge 2,500 milestone must not inherit the older 44d source's 2,000. The new 69d observer does not fill older unknowns retroactively.

## Same-source 73ab Host costs and graph-stage boundary

[The retained Host projection](original-73ab-native-host-cost-readback.json) reads the same two original ZIPs and four raw reports as [the complete cost projection](original-73ab-native-cost-readback.json). Actual reader 41803235636 succeeds on source 46df7c60: all 22 original reader controls pass, both audits pass, the source pair is byte-identical, and all 8 selected members / 91,600,775 bytes are retained with zero omissions. This reader executes no archived native code and adds no runtime measurement.

All 11 phases and 92 History rows remain: 85 successful imports, seven failed imports and zero unknown import outcomes. Every retained import has a valid observer, with zero measurement-failure observers. Seven failures are F0 baseline index 7 and index 6 in each of six campaign pressure phases. The console preserves all 92 compact import/checkpoint records and 44 per-phase Host slots. F0 ROOT has no History rows; its four slots remain unknown with complete time/call totals null. These are not measured zero-cost observations.

| Original baseline scope | History rows: success / failure | Host checkpoint calls | Checkpoint wall, seconds | Sum of actual invoking-thread CPU, seconds |
| --- | --- | ---: | ---: | ---: |
| F0 baseline | 7 / 1 | 83,581 | 6.233690200 | 4.399011445 |
| Campaign run 1 baseline | 14 / 0 | 166,367 | 6.837774672 | 4.159873526 |
| Campaign run 2 baseline | 14 / 0 | 166,344 | 7.515145033 | 4.155183110 |
| Campaign run 3 baseline | 14 / 0 | 166,367 | 6.467027246 | 4.158917758 |

Across observed records the known checkpoint subtotal is 914,503 calls. All recorded Host calls finish and accept; this does not change the seven failed imports or original F0 1/6, campaign 6/27 and F0 four-second 0/6 outcomes. The empty ROOT phase prevents a complete all-phase Host total. Per-import resolve/initial/final fields are retained in the output artifact, while their per-phase summaries are directly visible in console; that output ZIP's complete projection was not independently downloaded. Host CPU sums the actual invoking threads, whereas client-import CPU is the caller-thread measurement. Neither is an exclusive graph cost; no subtraction, CPU-share percentage or cross-source gain is inferred.

[The exact-source graph boundary review](account-graph-cost-source-boundary-69d2.json) separately binds 13 current code blobs. The measured account_graph interval includes current writer/schema checks, optional current-account parsing, fresh SQL reads, complete-input decoding/lift math, graph traversal/collections/equality checks and progress callbacks. Those callbacks can perform the original deadline/Host checks and, under the original exclusive ownership path, bounded refill waiting. Existing decoder/lift caches bind mathematical inputs; they do not authorize current state. The stage counter can include partial or failed traversals. Independent SQL/decode/hash/allocation/callback/refill timing is not available in these reports, so deleting a check, reusing stale SQL or asserting a causal speedup is unsupported.

## Dated current workflow and queue state

[The 09:10:57 UTC metadata snapshot](69d-workflow-status-20261104-091057.json) contains all 16 original 69d PR workflows: 11 success, three failure, one in progress and one pending. F0 41799271331, campaign 41799271249 and W1 41799271243 remain failures; their detailed current-source native/business counts are unread/null in that snapshot. PQ 41799271168 has actual workflow success at 09:04:23, but its internal test counts require separate exact-source log readback. The original priority/History run 41799271270 is still running and required baseline 41799271178 is pending.

[The queue evidence](69d-format-lint-and-baseline-queue-readback.json) preserves the 08:38:29 snapshot: current baseline pending with zero jobs, while older 40a run 41785836318 remains active. Both exact workflows share the same PR concurrency group and cancel-in-progress=false. This supports queue blocking as an inference from configuration and concurrent metadata; the API does not name an explicit blocking_run. No cancellation, concurrency change or budget change was performed. [Both b811 baseline and priority cancellations](b811-prejob-cancelled-baseline-priority.json) instead have actual cancelled terminal states and total_count=0/jobs=[]; no native outcome or cancellation initiator is invented.

All still-failing public confirmation, fresh-service, original long-History and independent PQ/W1/economics/recovery/WAN/model/governed-acceptance boundaries remain open. The records above close only their named engineering, build or evidence subgates.

## Current 69d complete Node-library and PQ-component terminal scope

[The original four-lane terminal record](69d-pq-four-lane-terminal-readback.json) binds run 41799271168 to the current head 69d2e06c / actual merge bfdfc2bf and common tree d9327a58. The outer full Node-library terminal in every lane is 987 PASS / 0 FAIL / 27 ignored, with zero filtered tests. The inferred registered scope is 1,014; two printed filtered one-test child summaries are retained separately and are not added to 987.

| Original current-source lane | Job | Full Node elapsed, seconds | Outer result |
| --- | --- | ---: | --- |
| ARM actual merge | 126470754088 | 1,328.15 | 987 / 0 / 27 |
| ARM head | 126470754395 | 1,328.38 | 987 / 0 / 27 |
| x64 actual merge | 126470754526 | 1,363.67 | 987 / 0 / 27 |
| x64 head | 126470754671 | 1,390.54 | 987 / 0 / 27 |

All 49 distinct original native-00 through native-48 controls execute and the unchanged named-test checker loop succeeds. Each lane has 68 distinct successful command receipts, including the original locked graph, format, build, strict Node Clippy and four separate original cost selectors. Each cost selector has its own 1 PASS / 0 FAIL / 0 ignored result; these are not added to the full Node denominator. Root independently matched 104 hash-bound log ranges, all 272 distinct command receipts, all outer Node and 16 cost terminals, all four exact source files and all eight artifact upload/API identities.

Each console directly prints its initial source receipt and actual audit PASS. Per-command complete-source equality follows from the exact included recorder and actual command_succeeded records; the raw before/after receipt bodies are retained in unread ZIPs and remain null here. Individual native/checker logs, redirected compiler-artifact records, complete Node ELF identity and ignored individual names were not read. The authentication-cost executable digest applies only to that printed cost scope. No source qualification is inherited from 73ab; whole-chain PQ security, original public confirmation, original long-History, WAN readiness and activation remain unqualified.

## 69d original History outer-terminal observation before inner readback

At 09:31:41 UTC, root read all four completed original History jobs in [run 41799271270](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/41799271270). Jobs 126471217600, 126471217634, 126471217803 and 126471218057 each retain successful original release builds, failed original execution, successful source-after verification and successful artifact upload. All four complete before/after source pairs match the current 69d/bfdf tree; each actual audit passes. The outer Host controller reports systemd_run_exit=1 and passed=false, with failure=null and final_host_errors=[].

The outer console does not print history-native/history.log, the libtest terminal or the new failure_location object, so internal failure cause and counts remain unknown at this boundary. A reader using the already successful fixed 12-member History projection is rebound only to these four actual source/artifact identities. It reads the archived originals without executing their contents; all native selectors, budgets, deadlines and complete failure denominators remain unchanged.

## Complete 69d failure-location readback

[The four original History failure records](original-69d-four-lane-history-failures.json) bind the actual head 69d2e06c and merge bfdfc2bf, common tree d9327a58. Actual reader 41808704638 / job 126502124623 succeeds on auxiliary source 63b3e205; both audits pass and its complete source pair is identical. It checks four original ZIPs / 226,135,726 bytes and 48 original selected members / 111,452 bytes with zero omissions, missing members, unknown source bindings or source mismatches. Root independently matched all 42 original JSON literals, 285 numbered member excerpts, all eight complete native/GNU-resource member hashes, four original outer logs and the output artifact API/upload identity.

| Original 69d lane | Failing call boundary | Successful import returns before error | Returned History RPC, ms | Returned import expression, s | Native outcome |
| --- | --- | ---: | ---: | ---: | --- |
| x64 head | history-rpc; IO111 after original server lifetime | 2,162 | 0.129582 | null | 0 PASS / 1 FAIL; exit 101 |
| x64 actual merge | history-rpc; IO111 after original server lifetime | 2,844 | 0.113220 | null | 0 PASS / 1 FAIL; exit 101 |
| ARM head | import-call-expression; PUBLIC_REQUEST_DEADLINE | 4,104 | 7.754563 | 30.000693324 | 0 PASS / 1 FAIL; exit 101 |
| ARM actual merge | import-call-expression; PUBLIC_REQUEST_DEADLINE | 4,104 | 8.627527 | 30.069217869 | 0 PASS / 1 FAIL; exit 101 |

The unchanged selector checks one packet per page before importing, and increments its counter only after a successful import return. Both ARM replies advertise complete=true; the error therefore occurs in the attempted 4,105th single-page import expression, after that History RPC and page checks returned. The expression includes the existing clock argument preparation. This directly observed boundary closes the outer-call diagnostic gap; it does not identify an importer substage, an exact internal cancellation checkpoint, activation entry or publication.

The ARM server exits are stop_requested at 1,752.624871422 and 1,768.281957021 seconds, before its original 1,800-second lifetime. The two x64 loops instead record lifetime_expired with prior stop=false. Coarse printed import milestones remain 2,000/2,500/4,000/4,000, separate from the new exact successful-return counters. All original after digests and pinned tips are retained. activation_cursor and durable_committed_blocks remain null in the original diagnostic, and manifest completed/named_execution/native_tests_executed remain their original nulls. Successful-return counters are not durable block counts.

[The fixed 69d Legacy source review](69d-legacy-final-page-source-boundary.json) preserves 11 exact source bindings and 17 complete source excerpts, independently checked against the actual Git blobs. The final-page call includes admission and, if admission succeeds, activation under the same original absolute deadline. Each deep attach can perform fresh staging-State validation and a separate fresh active-State validation before its own commit; the complete step sequence is checked at resume entry, not once per attach. These code paths have not been assigned measured cost shares.

Existing FullRootArithmetic reuse is bounded pure mathematics, not an authorization result. A naked arithmetic root is not a replacement for the original fresh PQ-state validation, profile dispatch and root/error order. Its single retained material can alternate between staging and genesis, while full SQL, JSON, canonical bytes, metadata and ancestry work remain. No new runtime optimization or safe-and-measured deadline repair is claimed by that source review.

A separate bounded reader is prepared for the two original ARM post-cleanup confirmer databases. It first checks the original fixed ZIP/source identities and exact database/WAL/SHM/journal inventory, retains the original size limits, and reads fixed SQL only from a complete frozen read-only set. Missing, excessive, inconsistent or write/recovery-requiring snapshots remain unavailable. Any resulting SQL cursor is a new post-cleanup observation and does not replace the original failure-time nulls.

## Later terminal queue status and concurrent integration

[The dated terminal/source snapshot](69d-terminal-and-concurrent-93e-status.json) retains all 16 original 69d workflow terminals as observed at 09:48:10 UTC: 11 success, four failure and one cancellation. Required-baseline run 41799271178 is actually cancelled, with total_count=0/jobs=[]; there was no instantiated native baseline job. Its initiator and cause are unknown in these readbacks. The older 40a baseline runtime jobs 126429599608 and 126429599819 also have actual cancelled conclusions, at 09:37:09 and 09:47:12, with original source-after and artifact steps successful. Their inner native result counts and cancellation cause were not read; elapsed time is not promoted into an observed timeout cause.

At 09:49:09 UTC the concurrent integration head is 93e207c8, whose sole parent is 69d2. Root verifies actual merge 5afe5dd2 has ordered parents dd6e1c3c and 93e207c8 and the same complete tree: 8,761 files / 940,655,430 bytes, with no truncated recursive listing. The 93e workflow snapshot contains 10 success, three failure and three in progress. Its own F0 41806693160, campaign 41806693023 and W1 41806693679 already fail; inner causes/counts remain unread in this metadata record. PQ, priority and required baseline remain in progress at that observation time.

All older source-bound results are preserved without assigning them to 93e. The concurrent source changes and its separately published evidence are preserved; this update does not review or overwrite their runtime implementation. Overall public-service, long-History and independent qualification HOLD remains.

## 93e complete Node/PQ terminal and current business outer failures

[The original 93e four-lane Node/PQ record](93e-pq-four-lane-terminal-readback.json) binds run 41806692746 to head 93e207c8 and actual merge 5afe5dd2, common tree 1066c679. Every lane directly prints the outer result 992 PASS / 0 FAIL / 27 ignored, zero filtered. Its inferred registered scope is 1,019; two nested one-test child summaries are not added. Every lane separately executes the 49 original PQ controls, 13 distinct transaction-scope controls and four original cost selectors. The four costs each have their own 1/0/0 terminal. The original fail-accumulating named-test checker loops and steps pass; raw individual logs/checker JSON remain unread inside ZIPs.

| Original 93e lane | Job | Full Node elapsed, seconds | Outer result |
| --- | --- | ---: | --- |
| x64 actual merge | 126495360050 | 894.53 | 992 / 0 / 27 |
| x64 head | 126495360276 | 1,364.35 | 992 / 0 / 27 |
| ARM actual merge | 126495360520 | 1,324.77 | 992 / 0 / 27 |
| ARM head | 126495360593 | 1,324.56 | 992 / 0 / 27 |

Root independently reads all four full original console logs, all four exact source files and original job/artifact metadata. It matches 116 hash-bound ranges, 88 literal ranges, 324 distinct successful command receipts and all eight artifact upload/API identities. The exact source guards and actual audits pass. Format, original build, locked graph and strict Node Clippy receipts succeed. Raw per-command before/after source files, full Node compiler-artifact/ELF records and the ignored individual roster remain null/unread; per-command equality is supported by the exact recorder and actual success receipts. Unequal lane durations are not a controlled speedup comparison.

[The dated 93e status snapshot](93e-current-source-workflow-status.json) is first observed at 10:13:06 UTC. Its 16 pull_request runs contain 11 success, three failure and two in progress; one additional dynamic CodeQL success makes 17 all-event runs. Root's later 10:25:54 source/run read confirms the same head/main and coarse counts. F0, campaign and W1 remain failures. Priority and required baseline remain in progress; priority's four service-model jobs are already metadata failures at original step 6, while their inner native results remain unread in that status record.

[Four original failed business outer logs](original-93e-business-outer-terminal-readback.json) add a separate direct terminal readback. All four actual audits pass and all four uploaded artifact identities match the original-run API:

- F0 job 126495361302 fails original execution step 8 and finalization step 9, each with outer exit 1. The redirected actual execution/finalization manifests, native exit and confirmation counts remain unread/null. Two console rows under /tmp/fixed-root-f0-source-controls-* are parser fixtures and are explicitly excluded from actual F0 results.
- Campaign job 126495362295 directly prints all three actual native return codes 101 and original_criteria_met=false, with 112.132358638 / 111.891432002 / 112.005188221 seconds elapsed. The original outer cap remains 600 seconds. Phase startup errors and finalization failures are empty; empty errors do not make the original criteria pass. Build exits 0, the original binary before/after digest agrees and source-before equals the nested source-after. The original confirmation report bodies and counts remain unread/null.
- W1 fresh-service jobs 126495364919 and 126495365320 directly report systemd_run_exit=1, passed=false, failure=null, final_host_errors=[] and identical complete before/after source receipts. Their inner native summaries and exact business-failure cause remain unread/null at this outer boundary.

These current-source failures are not assigned the historical 73ab denominators. The 992 component PASS and 13 separate transaction controls close their measured engineering scopes only; original public confirmation and independent qualification remain open.

## Original 69d retained databases: actual generic-bound refusal and fixed-member follow-up

[The first original two-ARM database readback](original-69d-arm-retained-database-readback.json) preserves actual reader run 41812595146 / job 126515293786, source 7a85995c / tree 8175c1e9 / 8,050 entries / 935,110,411 bytes. The job succeeds, both actual audits pass and complete source-before/source-after are identical. Both snapshot outcomes are nevertheless unavailable, with snapshot=null and no SQLite query executed.

The original ZIP indexes list the exact confirmer/native.sqlite members: head 220,749,824 bytes (compressed 22,920,177), merge 220,811,264 bytes (compressed 22,931,478). Both exceed the reader's existing 32 MiB/member and 160 MiB/selected bounds. Both original outcomes retain BOUNDED_SIZE:history-native/long-history/confirmer/native.sqlite and DATABASE_MEMBER_UNREAD. Fixed WAL, SHM and rollback-journal names are absent in the original ZIP directories. That archive-index fact does not establish database integrity, activation entry or any cursor.

The reader authenticates both original ZIPs / 122,282,461 bytes and all 12 small binding members / 21,763 bytes, with unchanged before/after input hashes. Root independently verifies the full 40,268-byte original console, its literal result/source/audit records, original failure-location objects and output artifact API/upload identity. Original failure-time activation_cursor and durable_committed_blocks remain null. The main database's individual digest, SQL schema and rows have not yet been observed in this original bounded run.

A separate diagnostic revision adds only a fixed main-database allocation for these two already authenticated original archives and their exact path/observed sizes: 220,749,824 and 220,811,264 bytes, 441,561,088 combined. It streams at most 1 MiB per read, checks complete length/EOF/CRC and hashes every copied byte. Generic 32 MiB/member and 160 MiB/selected bounds continue to cover all non-main-DB members, including sidecars; database and non-database totals are reported separately. No generic 256 MiB allowance is introduced.

The revision keeps all original source/ZIP checks, fixed read-only SQL/schema/authorizer checks, immutable handling only for sidecar-free frozen copies, input and directory rechecks, the approximate five-second/200k callback thresholds and ten-minute diagnostic workflow. This is a separately declared evidence-reading allocation, not a changed native performance budget or an accepted speedup. The original bound refusal above remains unchanged. The follow-up's SQL availability and any post-cleanup cursor require its own actual terminal evidence.

## Fixed 69d ARM database snapshots now expose partial staging cancellation

[The separately budgeted fixed-main-database reader](original-69d-arm-fixed-database-snapshot.json) completes actual run 41814841999 / job 126522878902 on source 2fab1611, tree 0febfbbb, 8,054 entries / 935,565,979 bytes. Both complete source receipts are identical and both actual audits pass. Both snapshots are observed, with no unavailable reason. Each of the two already pinned main files is streamed under its own exact limit, then queried with the unchanged read-only/schema/authorizer constraints.

| Retained original 69d state | ARM head | ARM actual merge |
| --- | --- | --- |
| Original artifact | 13311000045 | 13311101182 |
| reorg.cursor / lifecycle.cancelled_cursor | 3427 / 3427 | 3393 / 3393 |
| reorg.done / lifecycle.outcome | 2 / 2 | 2 / 2 |
| cancellation reason | PUBLIC_REQUEST_DEADLINE | PUBLIC_REQUEST_DEADLINE |
| new_tip | Matches the original pinned tip | Matches the original pinned tip |
| active tip / generation / state_slot | Original genesis / 0 / 0 | Original genesis / 0 / 0 |
| planned steps | 4105 attach rows, ordinal 0..4104 | 4105 attach rows, ordinal 0..4104 |

The queried height-4105 target block exists in each archive and its parent is the queried original height-4104 last successful import. Exact 69d Store and cancellation source excerpts show that each staging delta/cursor increment commits together; cancellation reads the committed cursor, records it with outcome=2 and done=2, and requires the old active generation/slot. Together, these directly read rows and source semantics support partial committed staging progress followed by cancellation before final active publication.

The row snapshots were retained after the original call returned, Node drop and Host cleanup. They do not identify the precise last failing checkpoint, uncommitted step phase or original SQL/JSON/root/COMMIT cost share. Original failure-time activation_cursor and durable_committed_blocks remain null, separate from 4104 successful import returns and these staging cursor observations. The reader does not rerun Node recovery, recompute roots, revalidate every block or qualify physical-fault durability.

Both main-file SHA256 values match the stream, before-query and after-query hashes: head 5f677fe67ea3bab3fae678e1e1a7c763e7da0e01aa3a5441bb4ba6d594a69fb6; merge e2ea1627ac06ac711cb1586baae1e1557d93c5ea77123e033a4bb9b5c497407d. All 14 selected files total 441,582,851 bytes: the two fixed databases total 441,561,088 and the original 12 small members total 21,763. The latter match the earlier generic-bound readback byte-for-byte by their complete digests. Both original ZIP digests and retained directory contents remain unchanged.

The two fixed query sets each complete seven statements in the diagnostic SQLite process, with 82,000 approximate progress-callback units. Its roughly two-millisecond SQL time measures this later readback only. It does not measure or explain the original 30-second import. Root independently checks the complete 55,385-byte log, four original JSON literals, complete rows/queries/schema, all fourteen before/after digests, original diagnostics, six exact source excerpts and output artifact API/upload identity. The original 32 MiB refusal remains its separate unavailable result.

## Later 93e priority terminal, before inner current-source readback

At 10:38:30 UTC root reads the actual terminal of [original 93e priority run 41806693207](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/41806693207): completed/failure, original terminal update 10:27:36. All 13 jobs are terminal. Four History jobs fail only original step 20; four service-model jobs fail original step 6; four state jobs and the retained-pressure job have successful metadata conclusions. Native scope/counts for the state and service jobs are not inferred from that metadata.

Root reads all four complete original History outer logs. The head/actual-merge source pairs are identical, all actual audits pass and all original builds, source-after checks and artifact uploads succeed; original execution fails. Those outer logs do not print the inner failure-location object or native terminal. They bind four original ZIPs totaling 224,077,518 bytes. A clone of the already successful twelve-member History reader is changed only in nine name/identity lines for these four 93e archives; the other 543 lines, selected members, generic 32/160 MiB bounds and ten-minute workflow remain unchanged. It does not execute archived code or SQL.

The new reader is needed to report 93e's own internal failure results. The 69d page counts, cancellation cursors and causes are not assigned to 93e. The separate original required-baseline run 41806693078 remains in progress at root's 10:44:39 metadata observation; no terminal or native counts are invented.

## Complete original 93e four-lane History failure-location readback

[The current-source inner record](original-93e-four-lane-history-failures.json) now binds all four original failures directly to 93e207c8 / actual merge 5afe5dd2 / tree 1066c679. Actual reader 41816366204 / job 126528009299 succeeds on source 29173740 / tree 90c23106 / 8,056 entries / 935,770,842 bytes. Both source receipts are identical and both actual audits pass. It authenticates the four original ZIPs / 224,077,518 bytes and 48 selected members / 111,310 bytes with zero missing, omitted, unknown or mismatched source members.

| Original 93e lane | Successful import returns | Failing boundary | Last returned History RPC | Last returned import expression | Native terminal |
| --- | ---: | --- | ---: | ---: | --- |
| x64 head | 2345 | history-rpc; IO111 after original lifetime | 0.111838 ms | null | 0 PASS / 1 FAIL / exit 101 |
| x64 actual merge | 2292 | history-rpc; IO111 after original lifetime | 0.107732 ms | null | 0 PASS / 1 FAIL / exit 101 |
| ARM head | 4104 | import-call-expression; PUBLIC_REQUEST_DEADLINE | 9.159184 ms | 30.000860172 s | 0 PASS / 1 FAIL / exit 101 |
| ARM actual merge | 4104 | import-call-expression; PUBLIC_REQUEST_DEADLINE | 8.218462 ms | 30.001312998 s | 0 PASS / 1 FAIL / exit 101 |

Both ARM replies have complete=true, with the unchanged original one-packet checks and success-only counter. The attempt therefore fails in the final 4,105th import expression after its RPC returned; argument preparation remains included. Their servers stop_requested at 1,771.103365931 / 1,771.205134298 seconds before the original 1,800-second lifetime. Both x64 servers instead record lifetime_expired. Coarse milestones remain 2000/2000/4000/4000, distinct from exact returned-call counts. Whole native harness durations are 3315.81 / 3274.08 / 3278.59 / 3264.94 seconds; these are not exclusive final-import or Host/SQL/root costs.

The reader retains 42 original JSON strings, 284 numbered member lines and all eight complete native/GNU resource files. Root independently reconstructs each complete member in original line order and verifies its exact bytes/SHA256 against the original manifest, checks every literal/member line against the full actual 181,650-byte reader log, source/audit guards, original outer identities and output artifact API/upload digest. Original binary/preparation/native/process distinctions remain separate.

All four original activation_cursor and durable_committed_blocks remain null. No 93e database was queried here, so its internal activation cursor/checkpoint remains unknown; the 69d post-cleanup 3427/3393 values are not inherited. This reader completion closes the current-source evidence gap and preserves four native failures. It does not close original long-History acceptance or any public-business gate.

## Legacy profiling candidate: original formatter failure retained (2026-11-04 11:29 UTC)

[The complete original 9eba formatter failure](legacy-profile-9eba-format-failure.json) preserves run [41820573105](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/41820573105), controls job 126542375546, both literal source receipts and actual PASS/26 audits, the full original 162,457-byte console (SHA256 f6983cca4d25c83af30d103df74fb8dda468044c27cc37da2195cda5925f42d9), terminal job metadata and the matching 20,109-byte artifact identity. The exact candidate is 9eba82312a584c41ddfc9ca60d8e8d299a60fa97 / tree e64fd2b1e89f6f799674a1d7c1c99d9ca6334b1d, 8,764 tracked files / 940,778,773 bytes.

All nine actual source/control commands return zero; their five Python suites report 34/4/34/22/11 cases and OK. Four nested /tmp/trnm-pq-command-control fixture return rows are preserved in the original log and excluded from that command denominator. The original Rust 1.95 formatter returns 1 with exactly four whitespace hunks in two Rust files. Provider preparation, the locked build graph, whole-workspace compilation, all seven named native controls, strict Clippy and the dependent original History diagnostic are skipped. This is a formatting failure, with no compiler or native result inferred.

The exact four formatter hunks are subsequently applied in isolated child 1b25374bc7cd0af01882eb85b4d4b9398d0e8116 / tree c640b9f56b98523ca6661732f9a2145d3aaa0e4a, with 8,764 files / 940,778,862 bytes. Only the two formatted Rust files and their Recent/corpus pins change. Run [41821540586](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/41821540586) is in progress at 11:31:29 UTC; this dated state supplies no passing build, native, Clippy or performance result.

## Exact 93e inner-business report readback prepared for execution

Two new isolated read-only workflows bind the original 93e F0/campaign archives and the two original 93e W1 fresh-service archives. Their unchanged parsers keep the existing fixed member lists, 32 MiB member / 160 MiB selected-byte / 70k console / ten-minute limits, SQL/decoder controls and unknown semantics. Four original ZIP names, sizes, full digests, run/head/job bindings and the three original campaign report digests match the [preserved original outer evidence](original-93e-business-outer-terminal-readback.json). F0 has no separately published member digest; its expected field remains null, with the exact full ZIP checked first.

These are additive identity-bound readers; no 73ab result is rewritten or transferred to 93e. Their new diagnostic source must execute its actual before/after source checks and project audits. No new reader result, native rerun, business acceptance or resource-budget change is claimed by this preparation.


## Original 93e business denominators and native cost read back (2026-11-04)

[The complete current-source cost and confirmation record](original-93e-native-cost-readback.json) binds actual read-only run [41821892261](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/41821892261) / job 126546814496 to original F0 41806693160 and campaign 41806693023. [The current-source W1 failure record](original-93e-w1-fresh-service-failures.json) binds actual reader [41821892252](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/41821892252) / job 126546813209 to original W1 run 41806693679, both head and actual-merge lanes. Both readers succeed on c3e8351493d78ba119c201dd458373a246edb9e7 / tree 68f7ff9dbe64e8f03a94fd4122351e46c9c08fcb, 8,061 tracked files / 936,296,362 bytes. Actual before/after source receipts are byte-identical and both actual audits pass per reader. The full original consoles, literal member projections, complete native-member digests, terminal API records and matching output artifact identities are retained in the two records.

| Original 93e experiment | Planned rounds | Observed rounds | Confirmed | Observed unconfirmed | Unobserved |
| --- | ---: | ---: | ---: | ---: | ---: |
| Fixed Host ROOT F0 | 6 | 3 | 1 | 2 | 3 |
| Three-run native campaign | 27 | 12 | 3 | 9 | 15 |

F0's original four-second criterion is 0/6. Its baseline first scheduled confirmation latency is 26.903826437 seconds; that scheduled latency is distinct from the 26.903408830-second actual round-call duration. ROOT pressure has zero confirmations. The original F0 native test fails with exit 101 and BASELINE_MUST_PASS; finalization nevertheless records all three service groups known-empty. Each campaign baseline confirms one of three planned rounds; all six pressure phases confirm zero, all nine original criteria are false, and all three original native processes exit 101. The third campaign harness counts remain unknown because the unchanged reader console bound does not expose that summary; its actual exit code is retained.

The eleven measured phases retain 22 role projections and 352 stage rows: 330 entered and 22 unentered. SQL COMMIT observations contain 36 observed and 52 unentered site rows; their 267 started calls all returned successfully, with no failed, abandoned or in-flight calls. An unentered stage's complete duration remains null. These are nested stages and current-thread CPU measurements, not exclusive stage attribution or disk-fsync measurements.

Across the three campaign baselines, the client account-graph stage records 62 calls and 18.493288429 / 17.898739787 / 17.975575889 seconds of wall time, with 4.060883486 / 4.076259371 / 4.076451178 seconds of current-thread CPU. The entered SQL COMMIT subtotals are 97.087741 / 18.946513 / 18.215496 milliseconds. Each decoder projection records 68,002 calls, 67,874 exact hits and 128 original decodes. Decoder counters do not measure decoder elapsed time or avoided SQL. Host contribution is not extracted by this cost reader, and these AuthV1 observations do not characterize the separate Legacy 4,105th-import failure.

For both original W1 lanes, the retained-packet selector reports 1 PASS / exit 0 but the unchanged business validator reports CONFIRMATION_TARGET. Both fresh selectors report 0 PASS / 1 FAIL / exit 101 at the original composite business assertion, with FRESH_NATIVE_PROCESS_REQUIRED in the original manifest. All four processes have timed_out=false. Complete W1 business denominators and the exact failed fresh-assertion conjunct remain unknown because this fixed-member reader does not select the four raw report.json files. The record does not infer them from the last replay or a libtest result.

## Same-source 93e Host cost reader prepared

The added frozen_93e_native_host_readback.py and its isolated workflow reuse the already executed Host parser and 22 negative/positive controls. Only source/target names and exact input identities change. The same two original 93e ZIPs and four complete raw-report member sizes/SHA256 values are fixed to the completed current-source cost readback above. Existing 32 MiB per-member, 160 MiB selected-byte, 70k console and ten-minute limits remain unchanged.

The new reader will project the original client-import Host observations without executing native code, changing Host budgets, claiming exclusive nested costs, or assigning old 73ab numbers to 93e. Its source must pass the actual before/after source checks and project audits. No result is claimed by this preparation; all original F0, campaign, W1 and long-History business failures remain open.


## Original 93e Host cost is now observed

[The complete same-source Host record](original-93e-native-host-cost-readback.json) binds successful read-only run [41824848332](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/41824848332) / job 126556843009 to diagnostic source 29160a58 / tree 85a3f714. Both literal source receipts match and both original audits pass. Its 22 reader controls pass; both original ZIPs and all four raw-report sizes/digests match the already completed cost readback. The complete 65,811-byte log, 13 original JSON strings and matching output artifact 13318637072 are retained.

Across eleven original phases, the 50 retained History imports contain 44 successes and six failures, with zero unknown import outcomes. Forty of the 44 Host phase summaries are observed; the four empty F0 ROOT summaries retain null counts and complete durations. No compact History row is omitted.

| Original campaign baseline | Checkpoint calls | Recorded wall seconds | Invoking-thread CPU seconds |
| --- | ---: | ---: | ---: |
| Run 1 | 82,913 | 6.601991452 | 4.556264853 |
| Run 2 | 82,930 | 5.964185337 | 4.570351415 |
| Run 3 | 82,936 | 6.962409772 | 4.570681824 |

The checkpoint count over known records is 493,629. These measurements cover the observed History imports in each phase; they are not graph-only or exclusive stage costs. They cannot be subtracted from account-graph timing or added to nested import/stage totals. Successful entered Host checks inside six failed imports do not turn the enclosing import or business criterion into success. All F0/campaign/W1/History acceptance failures remain.

## Concurrent Cell inventory source-control repair prepared

The concurrent integration change 5c070abe adds three native Rust files but leaves the embedded distributed inventory at 1,172 paths. Actual original PQ run 41824885864 stops all four lanes at the inventory source check before native execution. Root reads the exact x64-head source receipt and actual PASS/26 preflight, eight successful preceding source commands and the original inventory exit 1.

Candidate [a4a0e2b5](https://github.com/TrillionniumFoundation/Trillionnium-Chain/commit/a4a0e2b561f057cfa3189979c5bf11f3a0eb2353) changes only the existing generated inventory: 1,175 paths, adding cell_residency_observer.rs, cell/residency.rs and cell/residency_tests.rs in generator order. The original generator reproduces the entire prior 1,172-path file byte-for-byte from the exact parent tree; the candidate has exactly one changed leaf and retains all 393 existing source pins. No implementation bytes or validation rule change.

The added isolated workflow checks out this exact candidate, verifies its ordered parent and one-file delta, executes the original inventory --check, source-pin checker and repository checker, and repeats exact source and audit checks. The candidate is held on its own branch until this actual validation returns; no current integration pass is claimed by preparing it.
