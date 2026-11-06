# Throughput continuation: bounded hot work and unchanged acceptance

**Status: implementation candidate; performance acceptance remains open.**
There is no credible production TPS conclusion from this work. Original failed
business gates remain failed. The finite local observations do not establish
independent WAN capacity, production work hardness, whole-chain PQ readiness or
activation. Documentation publication never changes a measurement's source.

This record retains the original-CI snapshot of **2026-11-06 08:13:54 UTC**,
the complete terminal `285982d7` CI snapshot of **09:28:59 UTC**, and the
separately executed static/native checks on final implementation `7586d3e2`.
Original business failures, ignored controls, interrupted builds and source
identities remain visible. A later evidence-only publication is not a new
performance measurement, and completed 285 CI is not relabeled as 7586 CI.

## 1. Source identity and composition

| Source / role | Exact commit | Exact tree |
| --- | --- | --- |
| Original performance parent, PR #688 | `b173c1f52d927522af67df30dd08ecfb2e3a1bb0` | `6fcdb1aca01da0f2495fea1c74802af05119c77f` |
| PQ parent, PR #723 | `cad4c18fe146b7d742ac7fa8872044cd4136c22b` | `1e753c4641f6108f50b356182f8b4e81fa941e31` |
| Initial explicit composition | `3e676aa230b8888c83a56fe37a70b4ceaec82964` | `51fd2b87858f7c08be25574f84d119312029a178` |
| Actual restored ROG baseline identity | `a93f906d9b31da98c22ff1b8581ea2990f101352` | `51fd2b87858f7c08be25574f84d119312029a178` |
| First published throughput candidate | `9e50ca8e1ce655ef2f4686bd0ab58120b30c4632` | `8d67d4812661393cfc9dba2474c279d8285d6dee` |
| Test-only SQLite counter correction | `1986fa080b69bbab3a44f270ab8477adc5a01ea4` | `d905995bebe371972d5efed5ad95ba7461d7f87d` |
| Concurrent Cell integration base | `1f723bba961ec5f8d7e25e7b33db222dac7ef50c` | `1e6b82410a9adebab710b275d9f5cf211fb380ec` |
| First Cell composition, PR #736 | `285982d78a4f62a064841cb0f106d18c865e19c5` | `ce074eb1857a92c9b47ea317b841777fcfc63c04` |
| Concurrent six-workpackage integration base | `56897f125df27994efa1dda935f2c62eceb36de9` | `dc6efc584b2506edda43a2cce318edc95dd117ad` |
| Final composed implementation source | `7586d3e209b38246402e34cf73a27aa9b907bc9c` | `fc0e51b1235470b972de41f2d677f6d5948f4868` |

[PR #736](https://github.com/TrillionniumFoundation/Trillionnium-Chain/pull/736)
retains the history of the original parents. The
[first Cell merge](https://github.com/TrillionniumFoundation/Trillionnium-Chain/commit/285982d78a4f62a064841cb0f106d18c865e19c5)
has ordered parents `1986fa08` and `1f723bba`. The restored ROG baseline has the
same recorded tree as the initial composition; its unpublished commit identity
comes from the actual ROG build/execution receipts, not a fabricated GitHub run.
CI matrices include x64/arm64 and head/prospective-merge lanes. The submitted
candidate SHA labels the run; each actual synthetic merge commit/tree remains
in its own source receipt and is not replaced by the candidate's head identity.

The Cell base adds explicit persistent rarest-first transport composition and
single-Cell custody-window preflight/recovery controls. Its runtime files are
retained unchanged from that parent. Only corpus, checker, embedded inventory
and the sole development plan required composition. This first Cell composition
on `285982d7` contains
**582 pins, 501 required paths and 1,268 embedded inventory entries**; no parent
entries were dropped. All capability assertions and `HOLD_NO_GO` remain intact.
[Cell parent evidence](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/1f723bba961ec5f8d7e25e7b33db222dac7ef50c/evidence/cell-bt-composition-20261106/README.md)
and [composition receipts](reports/base-sync/summary.json) retain separate scope.

## 2. Original b173 failures remain failures

| Original run | Actual result | Interpretation |
| --- | --- | --- |
| [Three native campaigns](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42165737862) | All three fail; first no-attack confirmations 14.585549165 / 14.998208439 / 14.811700851 s; attack phases have none | Original business acceptance fails; no conversion to production TPS |
| [Fixed Host F0](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42165737677) | First late confirmation 27.299782829 s; 0/6 planned slots meet the four-second SLO | Late and unobserved slots remain in the denominator |
| [Large-state CPU](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42165737753) | Original four matrix jobs succeed | That CPU experiment only |
| [Workspace](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42165737656) | Actual registry 25, expected 23; selection fails before its TSV exists | Scheduling mismatch, not 25 executed semantic failures |
| [PQ](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42165737716) | Required roster 52, hardcoded expectation 49; required-control construction fails | Missing required execution, not a cryptographic algorithm failure |

The separate [original complete Node library job](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42165737716/job/127721689346)
records **1,136 passed, 0 failed, 31 ignored**. It does not replace the required
controls that were not executed. Raw profiles, field paths, archive identities,
denominators and the classification are retained in the [original CI bundle](reports/original-ci/README-20261106T081354Z.md).

The b173 profiles show Host-check CPU at 75.05%–75.78% of baseline import thread
CPU across the three campaigns and 84.08% in F0 baseline, including failed
imports. These are nested costs, not additive stages. F0 ROOT has no observed
import rows; its ratio is unknown, not a zero-cost success.

## 3. All five original 9e50 CI runs reached terminal outcomes

| Original run on 9e50 | Terminal result | Actual observation |
| --- | --- | --- |
| [Three native campaigns](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42179336010) | FAIL, all three | First no-attack confirmations 21.592711199 / 21.412403030 / 21.705995884 s; no attack-phase confirmation |
| [Fixed Host F0](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42179336118) | FAIL | 0/6 meet four seconds; two baseline confirmations are late at 14.306255781 and 24.407486459 s from scheduled slots; ROOT has none |
| [Large-state CPU](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42179335866) | PASS, four matrices | Four exact controls per matrix; original 8,625,548-byte seeded fixture and CPU settlement |
| [Workspace](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42179336034) | FAIL, four matrices | All select 80 actual controls; each records 79 passed and the same one counter assertion failed |
| [PQ](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42179335849) | FAIL, four matrix regressions | Each complete Node library records 1,169 passed, 1 failed, 32 ignored; the same counter test fails |

All four PQ pre-regression archives retain **52/52 required native controls,
14 TLS/ordinary-binary controls and 13 original transaction-scope controls passed**.
Twelve ancillary jobs also pass. Those results remain distinct from the failed
complete library/workflow; overlapping controls are not added as unique tests.
The [immutable PQ summary](reports/original-ci/pq-system-original-artifact-summary.json)
binds actual job/artifact identifiers and every original terminal library log.

F0 reports `BASELINE_MUST_PASS`: its baseline service criterion failed. Verified
cleanup reports all services known empty; a real business failure is not an
infrastructure error. Campaign hardware differs between the b173 and 9e50 runs
(Intel Xeon Platinum 8370C versus AMD EPYC 9V74). F0 CPU model is absent from its
retained hardware record. These cross-run times cannot isolate a code regression.

The original campaign keeps three attempts, 30-second phases, 1,024 seed transfers/four
seed blocks and 21 business blocks. F0 keeps six planned slots and its four-second
deadline including queue and final-observer time.
The public parent remains 0.25 CPU (`25000 100000`), CPU burst 0, 2 GiB memory,
swap 0 and 256 tasks; the external controller remains 4 CPUs, 16 GiB and nice 10.
No timeout, difficulty, workload, resource cap or failure denominator was relaxed.
Development-fixture depth-six latency is not real-difficulty WAN confirmation.

## 4. What changed in the candidate

### Required controls and routing

Preserve the original 25 post-write controls and correct the PQ roster to 52.
Add 12 separately named history controls and eight Host identity/file controls.
The actual inline workflow builders are exercised by source-registry fixtures
and reject stale counts, duplicates, missing/extra entries and empty selections.
These Python fixtures are not native libtest execution. F0 routing includes
production runtime, configuration and toolchain changes; budgets stay unchanged.

### Completed history reuse inside one original writer

Only four nominated records can retain completed suffix verification: child,
genesis, the fully verified child's parent and the original reader's active tip.
The receipt starts after the final write and binds the original connection,
writer, no-new-write epoch, schema, complete Record and same immutable Settings.
Every ancestor plus canonical genesis snapshot/initial State and genesis graph
must pass before a receipt is sealed. Partial, cancelled or failed work seals none.
[Scope and matching](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/285982d78a4f62a064841cb0f106d18c865e19c5/trillionnium/crates/trnm-pon-node/src/store/native_authenticated/post_write_readback.rs#L86-L328).

Hits freshly verify the starting record/block/parent/deltas and retain entry/exit
progress and final fences. A first-use callback write disables reuse and repeats
the original full verifier; changes after consumption are refused. Early errors
also check transaction identity. A fifth un-nominated block traverses its full
history even if it reaches a nominated ancestor. There is no new ledger or
Node-global verdict. Skipped ancestors also skip their associated progress;
unchanged whole-operation callback counts are not claimed for successful reuse.
[Original history and publication paths](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/285982d78a4f62a064841cb0f106d18c865e19c5/trillionnium/crates/trnm-pon-node/src/store/native_authenticated.rs#L807-L1026).

### Fresh Host limit reads through the original directory

An O_PATH handle retains only the identity-checked parent directory. Each Host
check still freshly reads boot identity, actual thread cgroup membership and all
five limit files through EOF, with original parsing/error order. NOFOLLOW opens
are fresh; no resource bytes or successful verdict are cached. Absolute identity
and permission checks bracket the reads; the final fence rejects replacement.
Host-check frequency and resource budgets are unchanged by this Host change.
[Host implementation](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/285982d78a4f62a064841cb0f106d18c865e19c5/trillionnium/crates/trnm-pon-node/src/host_kernel_parent.rs).

## 5. Counter correction and actual 1986 results

The failed selector is
`history_tests::writes_restoration_and_prepare_only_schema_changes_disable_completed_history`.
On 9e50, reversed DDL observed RUN `[3,3,0,3,2]` while expecting `[2,2,0,2,1]`.
That original failure remains failure. The old assertion stopped before its
later invalidation assertions; those later assertions were not proven by that log.

Pinned SQLite 3.51.3 increments RUN at OP_Init. After CREATE/DROP, the old VM can
reach its stale schema-cookie check, reprepare/reset, and execute again. RUN
therefore counts VM attempts, not logical queries or rows. Another expired-VM
path reprepares before OP_Init, so subtracting REPREPARE would be unsound.
The [test-only correction](https://github.com/TrillionniumFoundation/Trillionnium-Chain/commit/1986fa080b69bbab3a44f270ab8477adc5a01ea4)
retains raw RUN and independently records REPREPARE; no production logic changes.

The actual 1986 ROG build uses the unchanged test profile and all features.
Its original selected-control runner executes **80/80 exact controls successfully**,
including all 12 history and eight Host controls. The corrected control's raw
log records the following values, with no post-DDL cache flush or warm-up:
Vector order is state record, block, parent block, delta rows, genesis snapshot.

| Scenario | Actual RUN | Actual REPREPARE |
| --- | --- | --- |
| Reversed DDL, first/cold call | `[3,3,0,3,2]` | `[1,1,0,1,1]` |
| Reversed DDL, second/warm call | `[2,2,0,2,1]` | `[0,0,0,0,0]` |
| No-row write, restored bytes, prepare-only writable_schema; both calls each | `[2,2,0,2,1]` | `[0,0,0,0,0]` |

All eight observations have **16 callbacks, equal to the original full verifier;
one actual account_graph call; zero history hits; reuse disabled**. The assertions
also require all history slots empty. Native/reader execution passes with one
exact test, zero ignored. This proves the retained fallback control on 1986;
it does not turn old 9e50 results or the newer Cell composition into a pass.
[80-control summary](reports/rog-counter/summary.json),
[raw counter control](reports/rog-counter/history-counter.log) and
[SQLite source/correction receipt](reports/history-sqlite-reprepare-counter-fix.json).

## 6. Finite ROG cost observations do not demonstrate end-to-end gain

These are release/default-feature component executions on the restored baseline
tree and 9e50 candidate, not the original test-profile CPU gate or fixed Host.
The declared baseline/candidate/candidate/baseline sequence ran once per slot,
with **n=2 per arm**, 1,024 signed transfers and identical packet identities.
All four correctness observations pass: wrong-root refusals preserve durable
state, and a legal call after cold reopen has the expected live/cold state.

| Paid component CPU | Baseline mean, ns | Candidate mean, ns | Change |
| --- | ---: | ---: | ---: |
| Legal call after reopen | 29,293,638.5 | 30,048,942.5 | **+2.578%** |
| Refusals | 22,887,104 | 22,448,150.5 | −1.918% |

The legal mean is higher. This finite shared-host sample demonstrates no
end-to-end gain and does not isolate a persistent regression from either change.
All four samples, CPU/wall values, state assertions and identities are retained;
there is no repeat-to-select-best or conversion of component time into TPS.

The complete three-arm Host observation retains 192 samples and 12,288 checks
(4,096 per arm). Mean thread CPU/check is 7,105.361 ns for original absolute
reads, 7,331.078 ns with the extra absolute-path fence, and 7,033.223 ns for fresh
relative reads plus the fence. Relative versus original is **−1.015%**; versus
the refenced arm it is −4.063%. Actual proc context is read, but limit files are
ordinary temporary files, not cgroup kernfs. This does not qualify fixed Host F0.
[Declared plan and raw component analysis](reports/rog-components/analysis.json).

The old 9e50 ROG release control run remains **79/80**. Its later all-feature
full Node run remains **1,169 passed / 1 failed / 32 ignored**, followed by
**52/52 required controls passed**. Strict workspace/all-target/all-feature
Clippy on 9e50 exits zero; it does not erase the native failure. A prior PQ
collector attempt rejected a relative provider-receipt path before any registry
or test execution; both that zero-execution attempt and the corrected collector
run remain separate. [ROG source-bound summaries](reports/rog-pq-counter/summary.json).

## 7. Completed 285982d7 static and native results

The completed local source lane executes **292 Python controls**: CI contract
105, authority 15, claims 22, corpus 37, command recorder 4, project boundary 16,
repository mutants 50 and source-integrity negatives 43. Actual exits are zero.
Source-before/after agree on `ce074eb1`; inventory, Markdown, formatting and
main default/all-feature locked Cargo graphs pass. Fuzz metadata also passes
in its separately source-bound second attempt; both lockfiles remain unchanged.
[Final static summary](reports/static-285982d7/final-summary.json).

Preserved failures include a collector that misread buffered negative-fixture
stdout after unittest's successful stderr summary, and an original offline fuzz
metadata exit 101 for missing libfuzzer-sys cache. The collector was corrected
without rerunning its tests; a bounded normal metadata request then populated
the missing dependency with the locked graph unchanged. This is not the full
repository-truth lane, native testing, Clippy, fuzz execution or release acceptance.

| Combined-source item on 285982d7 | Actual result | Retained scope and evidence |
| --- | --- | --- |
| 285982d7 ROG workspace build, attempt 1 | CANCELLED, recorded SIGTERM/−15; cause UNKNOWN | [Original interruption record](reports/rog-composed-285982d7/rog-composed-2859-build-interruption.json); no OOM/deadline cause inferred |
| 285982d7 ROG workspace build, attempt 2 | CANCELLED, SIGTERM; actual lld SIGBUS diagnostic also retained | Unchanged task_archive_store_recovery link; no successful build-finished; [retained attempt index](reports/rog-composed-285982d7/index.json) |
| 285982d7 ROG Node+M06 library component build, ext4 attempt 1 | FAIL; GCC temporary-file EDQUOT reported after 6.7 s | Compiler still used /tmp; [original exit-101 receipt](reports/rog-composed-285982d7/rog-composed-2859-component-build.json) and [raw stderr](reports/rog-composed-285982d7/rog-composed-2859-component-build.stderr) |
| 285982d7 ROG Node+M06 library component build, explicit ext4 TMPDIR | PASS, actual build exit 0 | Unchanged all-feature/test profile; [original build receipt](reports/rog-composed-285982d7/rog-composed-2859-component-build-attempt2.json); component scope only |
| Combined-source ROG semantic controls | PASS, 80/80 exact registered controls | Actual native/reader exits zero and identical source receipts; [gate receipt](reports/rog-composed-285982d7/controls-80.gate.json) |
| Combined-source ROG full Node library | PASS; 1,172 passed / 0 failed / 32 ignored | Actual registry 1,204; original full harness 884.43 s; source/native/reader checks pass; [gate receipt](reports/rog-composed-285982d7/pq-full-and-required.gate.json) |
| Combined-source ROG required PQ controls | PASS, 52/52 actual named executions | All 52 dispatched and individually confirmed; native/reader exits zero; separate from the full library and not added as unique tests |
| Combined-source ROG M09 all-targets/all-features | PASS; 387 passed / 0 failed / 0 ignored | Fifteen outer harnesses, including five zero-test targets; nested child output is not added; [original Cell summary](reports/rog-composed-285982d7/cell-summary.json) |
| Combined-source ROG M09 documentation | PASS; 10 passed / 0 failed / 0 ignored | Separate original documentation command |
| Combined-source ROG M12 native_budget | PASS; 35 passed / 0 failed / 0 ignored, 11 filtered | Original selected budget command; [independent count review](reports/rog-composed-285982d7/cell-counts-review.json) |
| Combined-source ROG strict Clippy | PASS, actual exit 0 | Original workspace/all-target/all-feature command with -D warnings; [command receipt](reports/rog-composed-285982d7/strict-workspace-clippy-command.json) |
| [285982d7 original campaign](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42185197057) | FAIL; all three native exits 101 | First no-attack confirmations 21.205759120 / 21.203138983 / 21.305650019 s; each baseline 1/3 confirmed, both attack phases 0/3; [raw-derived summary](reports/current-ci-285982d7/campaign-business-summary.json) |
| [285982d7 original large-state CPU](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42185197106) | PASS, four matrices | Four original controls per matrix actually pass; original 8,625,548-byte fixture; [raw-derived summary](reports/current-ci-285982d7/large-cpu-all-matrices-summary.json) |
| [285982d7 original F0](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42185197083) | FAIL; 0/6 planned slots meet four seconds | Only one baseline confirmation, late at 24.901798841 s from its scheduled slot; ROOT has none; [raw-derived summary](reports/current-ci-285982d7/f0-business-summary.json) |
| [285982d7 original Workspace](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42185197125) | PASS, four matrices | Each executes 80 passed / 0 failed / 0 ignored; original CPU/public-loop controls and finite Growth observations retained; [original artifact summary](reports/current-ci-285982d7/workspace-original-artifact-summary.json) |
| [285982d7 original PQ](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42185197027) | PASS, 16/16 jobs | All four main matrices record 1,172 passed / 0 failed / 32 ignored; each required 52 native, 14 TLS/ordinary, 13 scope and 25 public-recovery controls passes; [actual terminal counts](reports/current-ci-285982d7/pq-terminal-counts-4-matrices.json) |

The ROG /tmp target was on tmpfs; its own partial output reached 17.53 GB while
the ext4 root had 24.59 GB free. The first ext4 component build still used /tmp
for GCC temporary files and reported EDQUOT after 6.7 s. Its successor explicitly
sets an owned ext4 TMPDIR, keeping source, flags, two CPUs and 10 GiB unchanged.
The explicit-TMPDIR component build exits zero after 254.37 s; the original
receipt retains the actual source, argv, provider reference and two CPU/10 GiB
execution envelope. Earlier interrupted/failed attempts remain separate. Their
complete raw records accompany the [terminal native suite](records/rog-composed-2859-native-evidence.tar.xz). No component
build qualifies the full workspace; the four original GitHub Workspace matrices
retain that scope. SIGBUS and filesystem observations do not prove OOM as the
cause of either cancelled attempt.

The new campaign retains all 36 public-parent and six controller budget records;
F0 retains eight public-parent and two controller records, all matching the
original envelope. F0 baseline import records contain 90,604 Host checks:
4.611268166 s nested Host thread CPU within 5.454671059 s caller CPU (84.54%).
ROOT has no observed import rows, so that ratio remains unknown. This aggregate
is not a per-confirmation lower bound and does not isolate either optimization.
[Campaign budget readback](reports/current-ci-285982d7/campaign-budget-readback.json)
and [F0 budget readback](reports/current-ci-285982d7/f0-budget-readback.json).

All five original 285 runs are terminal in the **2026-11-06 09:28:59 UTC**
snapshot. Their [bundle index](reports/current-ci-285982d7/bundle-index.json),
[report](reports/current-ci-285982d7/bundle-README.md) and
[raw records](records/current-ci-285982d7.tar.xz) retain 30 original artifact
identities and 26 complete terminal job logs. Those observations retain their
actual head/prospective-merge sources; overlapping suites are not added as
unique tests. The later source below requires separate execution records.

### 7.1 Final composition with the concurrent six-workpackage source

The integration branch advanced again to `56897f12` during final publication.
The [resulting merge](https://github.com/TrillionniumFoundation/Trillionnium-Chain/commit/7586d3e209b38246402e34cf73a27aa9b907bc9c)
has ordered parents `285982d7` and `56897f12`, with tree `fc0e51b1`.
It preserves both complete histories, all W1 observations and the Cell replay
owner controls. The existing production `storage_service.rs` differs from 285
only in two comment blocks; its executable guard statements were already present.
The 16 reviewed history/Host files retain their exact 285 bytes. New Rust work
consists of test registration, replay-owner tests, the observation example and
the composed inventory. The parent sampler observations retain their own source.

The source union contains **593 pins, 512 required paths and 1,271 inventory
entries**. Every non-source corpus field, capability assertion and HOLD remains
unchanged. The Workspace builder retains all 80 controls and the PQ workflow
retains its 52 controls plus the composed CPQ1/TLS/ordinary-binary work.

The incoming roster regression used a frozen b173 registry covering the original
60 selected controls. Its unextended registry correctly fails the current
80-control builder because the later history/Host entries are absent. A separate,
explicitly **synthetic source fixture** adds the 20 current Rust test declarations
and exercises the complete builder without skipping any groups. The original
ZIP/registry bytes and the stale-count refusal remain. This Python fixture is
registration checking; actual execution is independently read from compiled ELFs.

On the exact committed 7586 source, **334 Python controls** actually pass across
11 suites, including 106 CI-contract, six roster, eleven proof-reader and 24
strategy-reader controls. Source-before/after match the clean 10,740-entry,
1,031,948,736-byte tree. Corpus, inventory, authority/claim guards, 3,507 Markdown
links, formatting and all three first-attempt offline locked Cargo graphs pass.
Main default/all-feature graphs contain 175/180 packages, 26 members and 389
declared workspace targets; fuzz contains 147 packages and one member. Both
lockfiles are unchanged. The [static summary](reports/static-7586d3e2/final-summary.json)
retains exact command scope; authority tracing remains incomplete and no whole-chain
qualification follows from these source checks. The [source and merge archive](records/final-source-7586d3e2.tar.xz)
retains 225 original files, its [verified index](reports/static-7586d3e2/index.json),
[composition summary](reports/base-sync-7586/summary.json) and
[unchanged original source review](reports/base-sync-7586/source-review.json).

| Native item on 7586d3e2 | Actual status | Scope |
| --- | --- | --- |
| Node/M06 all-feature library build | PASS, exit 0, 219.48 s | Original test profile; source-bound component build, not the complete workspace build |
| Exact semantic controls | PASS, 80/80 | Fresh compiled-ELF execution; original selector and per-control native/readback results |
| Complete Node library | PASS; 1,177 passed / 0 failed / 32 ignored | Actual registry 1,209; the five additional replay-owner controls belong to this source |
| Required PQ controls | PASS, 52/52 actual named executions | Separate from full Node --lib; overlapping controls are not added as unique tests |
| Original M09 all-targets/all-features | PASS; 387 passed / 0 failed / 0 ignored | Fifteen outer harnesses including five zero-test targets; nested child output is not counted again |
| Original M09 documentation | PASS; 10 passed / 0 failed / 0 ignored | Separate original documentation command |
| Original M12 native_budget | PASS; 35 passed / 0 failed / 0 ignored, 11 filtered | Original selected budget command; filtered entries are not credited as executed |
| Strict workspace Clippy | PASS, actual exit 0 | Workspace/all-target/all-feature command with -D warnings |
| V4 sampler release/default controls | PASS; 9 passed / 0 failed / 0 ignored | Original nine named controls and actual Cargo-announced ELF registry; separate from Node --lib |

All four original native gates and the separate sampler have terminal source-bound
records. Build, gate and sampler source-before/after match `7586d3e2` / `fc0e51b1`.
The [native suite](reports/rog-composed-7586d3e2/summary.json),
[Cell count review](reports/rog-composed-7586d3e2/cell-counts-review.json),
[sampler result](reports/rog-composed-7586d3e2/sampler-summary.json) and
[complete original records](records/rog-composed-7586-native-evidence.tar.xz)
retain actual commands, receipts, logs, ELF identities and provider evidence.
The sampler's SQLite status is **UNKNOWN_SELECTED_RELEASE_UNIT_BINDING**:
the original plain Cargo command does not bind a selected SQLite build-script
OUT_DIR to its ELF. Cached or fresh candidate outputs and absent warnings do not
grant qualification. Sampler correctness does not establish SQLite boundary,
production throughput or service-SLO acceptance.

## 8. Practical storage and capacity limits remain

Each new scope still pays its first full history walk. Public read_active and
state_at use no history receipt: actual complete KV reads, snapshot decoding,
delta replay and state/graph checks remain. Complete-commitment cache hits still
compare current full input; misses parse accounts and construct the non-account
partition. Cold open explicitly verifies active state and complete history.
Existing recovery unchanged checks have their own contracts; this receipt grants
no recovery authority. Observed-time ancestry also remains a separate full walk.
[Read/query/replay paths](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/285982d78a4f62a064841cb0f106d18c865e19c5/trillionnium/crates/trnm-pon-node/src/store.rs#L3332-L3805).

PermanentAccountGrowthV2 is a separate backend; existing copy-on-write and local
witness work is preserved. Nine finite Growth cohorts vary N=64/1,024/16,384 and
H=0/16/128. Their local point-read/witness observations do not remove cold-reopen
cost or establish public throughput; raw records retain unavailable stage CPU,
null p99, throughput_qualified=false and production_activation=false.
The 12 new history controls use classical fixtures; their result alone is not
PQ configuration, provider or public-service acceptance.

Useful-work economics remains separate: the retained small integer-router
[same-material experiment](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/b173c1f52d927522af67df30dd08ecfb2e3a1bb0/evidence/pon-shared-material-cost-v2-20261105/README.md)
reports 7.53% useful logical MACs and 101–376× counted CPU versus ordinary warm
execution. It is not a result for arbitrary large GPU workloads. Likewise,
ML-DSA-65's 3,309-byte signature makes a hypothetical 10,000 independent-signed
TPS about 33.09 MB/s of signatures alone, before payloads, proofs, replication
and verification CPU; that quantity is not an achieved rate.
[Current signature parameters](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/285982d78a4f62a064841cb0f106d18c865e19c5/trillionnium/crates/trnm-crypto-primitives/src/pq_auth.rs).

## 9. Next work follows the original five priorities

1. Reduce mandatory business work: carry existing Growth/COW/witness improvements
   into ordinary admission, query, recovery and PQ paths while keeping explicit
   verifiable recovery/audit. The current receipt removes only bounded repetition.
2. Prepare stateless work in parallel, then deterministically commit balances,
   nonces, tasks and authorization generations. No unchecked parallel-state
   shortcut or broader parallel-preparation result is claimed here.
3. Give model payload transfer and consensus control separate resource treatment.
   Retaining Cell's bounded persistent transport does not prove confirmation,
   withdrawal or recovery fairness while large weights are downloaded.
4. Measure honest completion under invalid traces, new challenges, cold caches
   and recovery load, with all planned attempts and failures in denominators.
   Passing a primitive or aggregate-throughput test cannot replace that target.
5. Report confirmed transaction TPS, useful-work rate, Cell GB/s, model-load
   latency and quality gain per actual cost separately, with source, hardware,
   profile, budget and sample count attached to each measurement.

## 10. Reproduction and evidence layout

Run the original project preflight; use Rust 1.95.0 through the normal rustup
Cargo proxy, absolute RUSTC/RUSTDOC, original profiles and locked dependencies.
Use the original pinned OpenSSL 3.5.9 provider and real sign/verify/wrong-message
controls. An UNQUALIFIED SQLite-layout build is not a qualified native artifact.
Original GitHub campaign/F0 workflows provision the real fixed Host; invoking
their ignored test function bare is not equivalent. Do not change budgets.

[The inventory](manifest.json) and [SHA-256 list](SHA256SUMS) bind the packaged
bytes. New tar.xz carriers contain per-file manifests and safe regular members;
the original 08:13:54 ZIP stays unchanged, with its hash and exact 3,257-member
equivalence in [carrier provenance](reports/archive-provenance.json).
The two earlier ROG gzip archives use smaller xz carriers with the **identical
uncompressed tar bytes**, including every original member and manifest;
[carrier identities](reports/rog-archive-carrier-provenance.json) retain both
original gzip hashes and the actual replacement hashes.

The first final-inventory collector wrote its manifest/checksums, then failed
to write its own receipt because a local path variable was shadowed. Its
[actual failure record](reports/publication-finalization-attempt1/result.json),
original script and intermediate metadata are retained. The receipt-path fix
changes evidence assembly only; the 125 frozen inputs remain byte-identical.

| Bundle | Summary / raw records |
| --- | --- |
| Original b173/9e50 CI | [Immutable report](reports/original-ci/README-20261106T081354Z.md), [records](records/original-ci-20261106T081354Z.tar.xz) |
| Finite ROG components / original release controls | [Analysis](reports/rog-components/analysis.json), [records](records/rog-default-evidence.tar.xz) |
| Old ROG PQ and actual corrected 1986 controls | [Summary](reports/rog-pq-counter/summary.json), [records](records/rog-pq-and-counter-evidence.tar.xz) |
| Combined-source static/source checks | [Final summary](reports/static-285982d7/final-summary.json), [records](records/ci-source-evidence.tar.gz), [original package index](records/ci-source-evidence.index.json) |
| Exact parent composition | [Summary](reports/base-sync/summary.json), [review message record](reports/base-sync/independent-review-message-record.json), [records](records/base-sync.tar.xz) |
| Development/source/failed-build history | [Source map](reports/source-map/remaining-throughput-source-map.md), [66 original staged records and provenance](records/development-records.tar.xz) |
| Completed 285 native execution | [Full source-bound summary](reports/rog-composed-285982d7/summary.json), [index](reports/rog-composed-285982d7/index.json), [raw records](records/rog-composed-2859-native-evidence.tar.xz); both cancelled workspace attempts retained |
| Completed 285 original CI | [Terminal bundle](reports/current-ci-285982d7/bundle-index.json), [four-matrix PQ counts](reports/current-ci-285982d7/pq-terminal-counts-4-matrices.json), [records](records/current-ci-285982d7.tar.xz) |
| Final 7586 static and parent composition | [Static summary](reports/static-7586d3e2/final-summary.json), [composition](reports/base-sync-7586/summary.json), [verified index](reports/static-7586d3e2/index.json), [records](records/final-source-7586d3e2.tar.xz) |
| Final 7586 native gates and separate release sampler | [Suite](reports/rog-composed-7586d3e2/summary.json), [sampler](reports/rog-composed-7586d3e2/sampler-summary.json), [records](records/rog-composed-7586-native-evidence.tar.xz) |

Every new terminal observation is added under its measured source and attempt.
No later success overwrites an earlier failure, no source check is native test
execution, and no component result grants production performance acceptance.
