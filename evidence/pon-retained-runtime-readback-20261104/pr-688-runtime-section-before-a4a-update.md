<!-- runtime-fixture-b28098c-begin -->
## Runtime continuation — verified scopes and remaining blockers

**Overall HOLD remains.** At the 11:56 UTC readback, concurrent integration head is 5c070abeb61d0ea8702fa94fffe9330d1699119c (parent 93e207c8); actual merge fd606c6c has ordered parents dd6e1c3c / 5c070abe and the same tree 40e5b643: 8,766 files / 940,774,052 bytes. Its eleven changed paths preserve the separate Cell residency work. All measured 93e and isolated Legacy results below retain their original source; no current-head CI result is inherited. [The complete evidence index](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/29160a58cd98018b791feefb374a8238965bfcf9/evidence/pon-retained-runtime-readback-20261104/README.md) preserves failures, repairs, raw literals and unknowns; [the previous owned PR section](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/ecb8a99774c9e5f5c1ad3dc59f12cac3a087c52e/evidence/pon-retained-runtime-readback-20261104/pr-688-runtime-section-before-20261104-094909.md) is archived verbatim.

### Closed engineering and component scopes

| Measured scope | Actual outcome |
| --- | --- |
| 73ab original release/finality, four x64/ARM head/merge lanes | Original four distinct selectors each pass 1/0/0; collect-all pipelines and counter readers pass. A fresh run/attempt/runner/lane RUSTUP_HOME repairs the original installation conflict, preserving pinned Rust 1.95.0, compiler arguments, release profile and original budgets. |
| 73ab original four locked-fetch contexts | Stable quality and pinned-nightly fuzz on head/merge each execute unchanged cargo fetch --locked --manifest-path tests/fuzz/Cargo.toml and exit 0 without timeout. Concurrent faa36 repairs the missing lock edge/package. This closes fetch only, not full quality or fuzz execution. |
| 69d original format/strict lint and workspace | All four format/strict-Node-Clippy lanes pass. Four original complete-workspace/all-target/all-feature --no-run builds succeed; each separately executes 60 unique selected tests, 42 Node / 18 M06, all passing. Complete workspace execution is not claimed. |
| 69d original full Node/PQ | Four lanes each print outer 987 PASS / 0 FAIL / 27 ignored, with 49 distinct original controls and four separate costs passing. |
| **93e original full Node/PQ** | **Four lanes each print outer 992 PASS / 0 FAIL / 27 ignored**, zero filtered. Each separately passes 49 original PQ controls, 13 transaction-scope controls, four cost selectors and original format/build/strict-Clippy commands. All 81 distinct command receipts per lane succeed. |

Evidence: [release](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/ecb8a99774c9e5f5c1ad3dc59f12cac3a087c52e/evidence/pon-retained-runtime-readback-20261104/73ab-release-finality-four-lane-terminal.json), [locked fetch](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/ecb8a99774c9e5f5c1ad3dc59f12cac3a087c52e/evidence/pon-retained-runtime-readback-20261104/73ab-locked-fetch-four-context-terminal-readback.json), [69d format/lint](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/ecb8a99774c9e5f5c1ad3dc59f12cac3a087c52e/evidence/pon-retained-runtime-readback-20261104/69d-format-lint-and-baseline-queue-readback.json), [69d workspace](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/ecb8a99774c9e5f5c1ad3dc59f12cac3a087c52e/evidence/pon-retained-runtime-readback-20261104/69d-original-workspace-four-lane-terminal-readback.json), [69d Node/PQ](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/ecb8a99774c9e5f5c1ad3dc59f12cac3a087c52e/evidence/pon-retained-runtime-readback-20261104/69d-pq-four-lane-terminal-readback.json) and [93e Node/PQ](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/ecb8a99774c9e5f5c1ad3dc59f12cac3a087c52e/evidence/pon-retained-runtime-readback-20261104/93e-pq-four-lane-terminal-readback.json).

Root independently reads the four complete 93e logs and four exact source files, matches 116 hash-bound ranges / 88 literal ranges / 324 successful receipts, and checks all eight artifact upload/API identities. Each cost selector has its own 1/0/0 terminal; costs, the 13 separate transaction controls and nested one-test child summaries are not added to 992. Full Node elapsed seconds are 894.53 / 1,364.35 for x64 merge/head and 1,324.77 / 1,324.56 for ARM merge/head; these unequal lanes are not a controlled speedup comparison.

Initial source receipts and actual audits are directly read. Per-command source equality follows from the exact recorder plus actual success receipts; raw command source-pair bodies remain unread in ZIPs. Individual selected-test/checker logs, complete Node compiler-artifact/ELF records and the ignored name roster remain unread/null. The separately printed authentication-cost ELF binds only that cost invocation. Whole-chain PQ/public-service qualification remains open.

### 69d original long-History: exact outer failure locations

[Diagnostic commit 69d2e06c](https://github.com/TrillionniumFoundation/Trillionnium-Chain/commit/69d2e06c48bbbd1e22432f9b557727b140aba361) changes only ancestry_long_sync.rs: eight local observations and one nested failure-location object in the existing exit record. Original call expressions and argument/error order, one-packet checks, selector, 4,105-block workload, 1,800-second server lifetime, separate 30-second RPC/import deadlines, assertions and cleanup precedence remain.

[Four complete original failures](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/ecb8a99774c9e5f5c1ad3dc59f12cac3a087c52e/evidence/pon-retained-runtime-readback-20261104/original-69d-four-lane-history-failures.json) now locate the returned call boundary:

| Original 69d lane | Failing call and error | Successful import returns | Last RPC | Last import expression |
| --- | --- | ---: | ---: | ---: |
| x64 head | history-rpc; lifetime expiry then IO111 | 2,162 | 0.129582 ms | null |
| x64 actual merge | history-rpc; lifetime expiry then IO111 | 2,844 | 0.113220 ms | null |
| ARM head | import-call-expression; PUBLIC_REQUEST_DEADLINE | 4,104 | 7.754563 ms | 30.000693324 s |
| ARM actual merge | import-call-expression; PUBLIC_REQUEST_DEADLINE | 4,104 | 8.627527 ms | 30.069217869 s |

All four original native selectors fail 0 PASS / 1 FAIL, exit 101. ARM's final replies advertise complete=true: after the unchanged one-packet checks, the attempted 4,105th import expression fails. It includes original clock-argument preparation. ARM stops its server at 1,752.624871422 / 1,768.281957021 seconds, before lifetime; x64 records lifetime_expired with no prior stop.

Original failure-time activation_cursor and durable_committed_blocks remain null. Successful return counts are not durable block counts; coarse milestones remain 2,000/2,500/4,000/4,000. Manifest completed/named_execution/native_tests_executed remain original nulls, while process/libtest directly retain failed execution. Reader 41808704638 verifies four original ZIPs and 48 selected members without omissions; root matches all 42 JSON literals, 285 numbered excerpts, eight complete native/resource member hashes, source/audit pairs and artifact identity.

[The exact Legacy source review](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/ecb8a99774c9e5f5c1ad3dc59f12cac3a087c52e/evidence/pon-retained-runtime-readback-20261104/69d-legacy-final-page-source-boundary.json) checks 11 bindings / 17 excerpts. The final call can include admission then activation under one original deadline. Deep attaches can freshly validate both staging and active State before committing; whole-step validation occurs at resume entry. SQL, canonical decode, PQ validation, arithmetic, Host and commit cost shares within this failure remain unmeasured. Bounded mathematical reuse cannot replace fresh state/current-authority validation, profile dispatch or original root/error order.

### Original 69d retained database state closes the staging-location gap

[The first generic-bound reader](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/ecb8a99774c9e5f5c1ad3dc59f12cac3a087c52e/evidence/pon-retained-runtime-readback-20261104/original-69d-arm-retained-database-readback.json) correctly reports both snapshots unavailable: each original main database is about 221 MB, exceeding its 32 MiB/member and 160 MiB/selected caps. No SQL was executed in that run. This historical refusal is retained.

[The separately declared fixed-file reader](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/ecb8a99774c9e5f5c1ad3dc59f12cac3a087c52e/evidence/pon-retained-runtime-readback-20261104/original-69d-arm-fixed-database-snapshot.json), actual run 41814841999, streams only those two exact pinned ZIP/path/size identities in at most 1 MiB chunks. Other members retain their original limits. Both read-only snapshots are now observed, with exact input hashes unchanged:

| Original 69d snapshot after call return and cleanup | ARM head | ARM actual merge |
| --- | ---: | ---: |
| reorg.cursor / lifecycle.cancelled_cursor | 3427 / 3427 | 3393 / 3393 |
| reorg.done / lifecycle.outcome | 2 / 2 | 2 / 2 |
| reason | PUBLIC_REQUEST_DEADLINE | PUBLIC_REQUEST_DEADLINE |
| active generation / slot | 0 / 0, original genesis | 0 / 0, original genesis |
| planned attach steps | 4105, ordinal 0..4104 | 4105, ordinal 0..4104 |

Both cancellation targets match their original pinned tips; height-4105 records exist with the original height-4104 parents. Six exact source excerpts show staging delta/cursor commit together and cancellation preserve the committed cursor while requiring old active generation/slot. Thus the retained rows support partial committed staging and cancellation before final active publication.

This is a post-cleanup, source-supported inference. Original failure-time cursor/durable-block fields stay null; the exact failing checkpoint and SQL/JSON/root/commit cost split remain unknown. No full database/root revalidation, recovery execution or physical-fault qualification is claimed. Fourteen retained files total 441,582,851 bytes; stream/before/after hashes and original ZIP digests agree. Root verifies the full original log, all SQL rows/queries/schema, source/audit pair and artifact identity. The roughly two-millisecond read-only query measures this later diagnostic only.

### Original current-source History failures are also fully read

[The independent 93e four-lane inner readback](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/ecb8a99774c9e5f5c1ad3dc59f12cac3a087c52e/evidence/pon-retained-runtime-readback-20261104/original-93e-four-lane-history-failures.json), actual reader 41816366204, preserves four original native 0 PASS / 1 FAIL / exit 101 results.

| Original 93e lane | Successful import returns | Failing boundary | Returned final import expression |
| --- | ---: | --- | ---: |
| x64 head | 2345 | history-rpc; IO111 after original 1800-second server lifetime | null |
| x64 actual merge | 2292 | history-rpc; same original lifetime boundary | null |
| ARM head | 4104 | last-page import-call-expression; PUBLIC_REQUEST_DEADLINE | 30.000860172 s |
| ARM actual merge | 4104 | last-page import-call-expression; PUBLIC_REQUEST_DEADLINE | 30.001312998 s |

ARM's prior RPCs are 9.159184 / 8.218462 ms, both replies advertise complete=true, and servers stop before lifetime. The unchanged page checks identify the final attempted 4105th import expression. Coarse milestones are 2000/2000/4000/4000. All current-source cursor/durable-block fields remain null; no 93e DB is queried and 69d's retained 3427/3393 cursors are not transferred.

Root matches all 42 original JSON strings, 284 numbered excerpts and eight full native/GNU-resource files against the complete original log and manifest hashes. All 48 selected members / 111,310 bytes and four original ZIPs are source-bound without omissions. Reader source 29173740/tree90c23106, actual audits and artifact upload/API identity are checked separately from the failed original native run.

### Original costs and failures remain in the denominator

[The frozen 73ab full-cost record](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/ecb8a99774c9e5f5c1ad3dc59f12cac3a087c52e/evidence/pon-retained-runtime-readback-20261104/original-73ab-native-cost-readback.json) retains F0 **1/6 original-window confirmations and 0/6 scheduled-four-second confirmations**: one confirmed, two observed unconfirmed, three unobserved. Its three-run campaign remains **6/27**: six confirmed, nine observed unconfirmed and twelve unobserved. Every baseline is 2/3; all six pressure phases are 0/3; all nine criteria fail. Current 93e counts are not inferred from these historical results.

That record includes 11 phases / 22 roles / 352 stage slots (330 entered, 22 not entered), plus 36 observed and 52 unentered SQL slots. Three baseline account-graph totals are 16.133378564 / 16.189713331 / 16.373165976 seconds wall; corresponding SQL-commit observed subtotals are 128.574152 / 44.359511 / 43.258633 milliseconds. Graph includes fresh reads, decode/canonical checks, traversal and progress callbacks, not an isolated query timer.

[The same-source Host record](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/ecb8a99774c9e5f5c1ad3dc59f12cac3a087c52e/evidence/pon-retained-runtime-readback-20261104/original-73ab-native-host-cost-readback.json) retains **92 History imports: 85 successful, seven failed, zero unknown**, all with valid observer records. Of 44 Host phase slots, 40 are observed and four unknown; an empty F0 ROOT History array leaves Host totals null. Known checkpoint calls total 914,503. The F0 baseline records 83,581 calls / 6.233690200 seconds wall / 4.399011445 seconds Host invoking-thread CPU; three campaign baselines record 166,367 / 166,344 / 166,367 calls with 6.837774672 / 7.515145033 / 6.467027246 seconds wall.

Host invoking-thread CPU, client caller CPU, nested spans and full command time differ in scope. No subtraction is presented as exclusive cost or accepted speedup. [The exact graph source boundary](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/ecb8a99774c9e5f5c1ad3dc59f12cac3a087c52e/evidence/pon-retained-runtime-readback-20261104/account-graph-cost-source-boundary-69d2.json) keeps mathematical full-input reuse separate from fresh authorization. [Original W1/service evidence](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/ecb8a99774c9e5f5c1ad3dc59f12cac3a087c52e/evidence/pon-retained-runtime-readback-20261104/original-73ab-service-w1-failures.json) preserves passing component selectors alongside failed CONFIRMATION_TARGET business validation and the unknown exact fresh-service assertion conjunct.

### Original 93e business failures: inner evidence now complete within reader scope

[The dated 93e source/status snapshot](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/ecb8a99774c9e5f5c1ad3dc59f12cac3a087c52e/evidence/pon-retained-runtime-readback-20261104/93e-current-source-workflow-status.json) retains its original 10:13:06 state. Priority run 41806693207 subsequently finishes failure: four original History and four service-model jobs fail, while four state jobs and retained-pressure have successful metadata conclusions. Those metadata conclusions do not supply unread native counts. Required-baseline 41806693078 is still in progress at the 11:56 UTC readback; no terminal is inferred.

The [original outer failures](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/29160a58cd98018b791feefb374a8238965bfcf9/evidence/pon-retained-runtime-readback-20261104/original-93e-business-outer-terminal-readback.json) remain preserved. Actual read-only runs [41821892261](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/41821892261) and [41821892252](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/41821892252) now succeed on exact auxiliary c3e83514, with identical before/after source receipts, two actual audits each, full original consoles and matching artifact API/upload identities.

[The original 93e F0/campaign record](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/29160a58cd98018b791feefb374a8238965bfcf9/evidence/pon-retained-runtime-readback-20261104/original-93e-native-cost-readback.json) establishes:

| Original experiment | Planned | Confirmed | Observed unconfirmed | Unobserved |
| --- | ---: | ---: | ---: | ---: |
| F0 | 6 | 1 | 2 | 3 |
| Three-run campaign | 27 | 3 | 9 | 15 |

F0's original four-second SLO is 0/6; its first scheduled confirmation latency is 26.903826437 seconds. Its native selector fails 0 PASS / 1 FAIL / exit 101 and the business validator reports BASELINE_MUST_PASS. Finalization does report all three service groups known-empty. All nine campaign phase criteria fail and all three original processes exit 101. Run 3's harness counts remain unknown under the unchanged console bound.

The current-source cost record retains 11 phases / 22 roles / 352 stage rows, with 330 entered and 22 unentered. Its 36 observed SQL site rows contain 267 successful returned COMMIT calls; 52 unentered rows retain unknown complete durations. Three campaign baseline account-graph observations each have 62 calls, wall 18.493288429 / 17.898739787 / 17.975575889 seconds and current-thread CPU 4.060883486 / 4.076259371 / 4.076451178 seconds. Decoder counters each show 68,002 calls / 67,874 exact hits / 128 original decodes. These are nested stages, not exclusive CPU or avoided-SQL attribution; AuthV1 costs do not characterize Legacy activation. A separate same-source [Host reader 41824848332](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/41824848332) completes successfully on 29160a58; its original log is still under review, so Host totals are not yet claimed.

[Both original 93e W1 lanes](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/29160a58cd98018b791feefb374a8238965bfcf9/evidence/pon-retained-runtime-readback-20261104/original-93e-w1-fresh-service-failures.json) have retained-packet libtest 1 PASS / exit 0 but CONFIRMATION_TARGET in the unchanged business validator. Both fresh selectors fail 0 PASS / 1 FAIL / exit 101 at the composite business assertion; original manifests report FRESH_NATIVE_PROCESS_REQUIRED. All four process timed_out values are false. Complete W1 business denominators and the exact failed assertion conjunct remain unknown because the fixed reader does not select the four raw reports. Last replay success is not treated as confirmation.

[All 16 frozen 69d workflow terminals](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/ecb8a99774c9e5f5c1ad3dc59f12cac3a087c52e/evidence/pon-retained-runtime-readback-20261104/69d-terminal-and-concurrent-93e-status.json) remain 11 success / four failure / one cancellation. Its required baseline cancels with zero jobs and no native result; older 40a runtime jobs also cancel. Causes remain unknown. Earlier queue blocking is a configuration-supported inference, not a named API blocking_run.

### Legacy activation-cost instrumentation: exact candidate executing

The default-off, owner-local Legacy observation change is now in isolated candidate [1b25374](https://github.com/TrillionniumFoundation/Trillionnium-Chain/commit/1b25374bc7cd0af01882eb85b4d4b9398d0e8116), a child of the first candidate 9eba823 based on exact 93e. It reuses the existing fixed 16-stage/four-SQL-site accounting for Legacy staging, active-tail validation and actual reorg commit calls, retaining one before/after pair around the original replay. Three signed enabled/disabled reorg controls compare full state/root/nonce, original progress/cuts, cancellation, damaged stored roots and cold default-off behavior. Original calls, validation, atomic publication, deadlines and cleanup are preserved.

[The complete first formatter failure](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/c3e8351493d78ba119c201dd458373a246edb9e7/evidence/pon-retained-runtime-readback-20261104/legacy-profile-9eba-format-failure.json) retains run 41820573105: nine real source/control commands return zero and five Python suites total 105 OK cases; fmt returns 1 with four whitespace hunks in two files. The build, seven named native controls, Clippy and History are skipped. Nested negative fixture return rows remain in the raw log and are excluded from the actual command denominator.

Those exact four formatting hunks and corresponding pins are applied in 1b25374. [Run 41821540586](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/41821540586), read at 11:56 UTC, has completed source/negative controls, Rust 1.95 formatting, original provider preparation, the locked graph, complete-workspace test-profile compilation and all seven selector registration checks successfully. The seven behavior/native controls are executing; strict Clippy is pending. Compiler-artifact details and native counts are not inferred from step metadata. The original ARM 4,105-page History diagnostic can start only after all controls succeed. No completed native validation or performance gain is claimed.

### Independent acceptance remains open

[Issue #639](https://github.com/TrillionniumFoundation/Trillionnium-Chain/issues/639) still requires original four-second/depth-six signed confirmation under hostile W1 pressure, with complete resource, failed/cancelled/unobserved outcomes and independent review. [Issue #629](https://github.com/TrillionniumFoundation/Trillionnium-Chain/issues/629) still requires independent authority/revocation, complete PQ/W1/compiler/backend/composition security, equal-cost classical/quantum economics, non-rewinding recovery, real-network costs and governed activation.

The sole development plan additionally requires real model lineage/independent consumption, funded economic effects and rollback behavior, and at least three independent administrators/fault domains over at least 72 hours of the specified WAN/fault cohorts. Same-agent/source checks and component PASS cannot supply that independence.

The index keeps earlier narrow repairs, original syntax/cleanup failures, cancelled zero-job cohorts and every failed/unknown denominator. Full W1/state validation, nonce/debt floors, immutable parent/current-authority separation, original Host budgets, deep-reorg recovery and atomic publication remain mandatory.
<!-- runtime-fixture-b28098c-end -->