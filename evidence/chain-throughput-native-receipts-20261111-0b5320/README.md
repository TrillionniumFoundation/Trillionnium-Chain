# Throughput continuation: exact-source native receipts

This evidence records the current component candidate
`11e242dbaaae14a9d16282fe8deaf36827e98395`, tree
`1f42f41923d7761c02fc68b478df5b019c7d83e8`. The evidence commit has that
candidate as its sole parent and changes only explicitly listed `evidence/`
paths. The candidate branch and Draft PR #895 continue to name the measured
source. Recording these observations does not make the evidence commit a new
tested production candidate.

**The recorded fixed-lane 21 named controls and 10 pool integrations passed.
Complete business liveness, sustained throughput and release remain unqualified.**
Current-source hosted confirmation has failed its original acceptance target;
passing Rust test processes do not replace that acceptance result.

## Changes under test

Shared History retains its original paid CPU account while detached. After
workers join, it waits for that account's available headroom before reacquiring
the writer. Original cancellation, deadline, reserves, measured debits and
worker accounting remain. Held preparation, fallback and commit keep their
nonwaiting refusal semantics. Waiting does not guarantee capacity after later
concurrent spending.

Ordinary mining carries the same stop signal and deadline through parent
reads, preparation, post-search revalidation and retained-pool reconciliation.
The scan controls use six real signed transfers and require a stop or deadline
after row two to prevent later preview and admission. Each corrected test
covers initial-batch and post-search paths with both Legacy and AuthenticatedV1
state. The original completion and recovery semantics after durable packet
admission remain in force.

The lightweight scan check does not replace the existing public-owner Host
checks. It cannot hard-preempt an indivisible SQLite or native call. Cancellation
after reconciliation's own SQL classification commit may retain that completed
metadata. The row-two tests observe cancellation before that commit; they are
not a universal rollback or post-classification retry proof.

## Exact source lanes

| Lane | Immutable subject | Recorded native result |
| --- | --- | --- |
| Fixed | `11e242dbaaae14a9d16282fe8deaf36827e98395` | 21/21 named controls and the original 10/10 pool integration tests, including the actual CLI, passed. |
| Budget before v2 | `89fb2269b0dd306fbd32c36f464842c3d7daee2b` | Six exact expected assertion failures and one positive control; official reader accepted the seven-control comparison. |
| Pool before v2 | `84e68b4f7a9b2f48f9c47ed05c9a44229d186e30` | Five exact expected assertion failures and two positive controls; official reader accepted the seven-control comparison. |
| Pool scan before | `ae657e262278ae4a058220f66a6a0495721eb9ad` | Two exact expected native assertion failures; the frozen official reader and independent transcript readback both accepted the comparison. |

All four official lanes use the frozen M driver. Its reader SHA-256 is
`c7604dcf0bb9f533902e368a44b170c927d98c46080570673f268391fd9dc479`.
The old-source lanes must fail the exact intended native assertions; compiler
errors, process signals, setup failures, wrong test threads or additional
unrelated panics cannot satisfy those controls. Passing a negative comparison
does not mean the old implementation passed the corrected behavior.

The four frozen-driver desktop component lanes use Rust/Cargo 1.95.0, the original release profile,
one build job, disabled incremental compilation, and separately recorded
two-CPU/16-GiB operator job limits. They do not impersonate a hosted CI job or
establish a fixed public Host campaign.

## Current-source verification

| Check | Result and boundary |
| --- | --- |
| Complete source identity | Before/after receipts agree on M, its tree, 28,058 tracked entries and 2,592,587,811 tracked bytes. |
| Clean source and readers | All 14 recorded commands passed: preflight, 39 reader tests, 43 source-integrity tests, 179 CI-contract tests, retained inspectors/inventory/links, original-toolchain formatting and locked offline Cargo graph. These commands do not execute native controls. |
| Fixed native lane | 21 named controls plus the original ten pool integrations passed. Recorded source, input bytes and three executable guards agree. |
| Whole default node library | The top-level unfiltered libtest process exited zero: **1,313 passed, 0 failed, 39 ignored, 0 measured, 0 filtered out**, 4,283.75 seconds. The total is 1,352, matching the retained inventory. Whole-source guards before and after the library agree. |
| Strict all-target/all-feature Clippy | `cargo +1.95.0 clippy --locked --manifest-path trillionnium/Cargo.toml -p trnm-pon-node --all-targets --all-features -- -D warnings` exited zero in 277.704520546 seconds. Final source, five pinned-provider files and all three recorded built/retained executable guards agree. The original outer job ended succeeded, exit zero, with complete durable output and no timeout/cancellation. |
| Hosted exact-head repository truth | Job `130324695517` in run `42960214277` succeeded. Its original source member and the two source-check log observations agree on M. |
| Hosted four-source comparison | All four jobs in run `42960214402` succeeded. The four original reports retain the same exact subjects and required positive/negative rosters; their frozen-reader, process-stream, source/input and ZIP-contained binary checks passed. Independent local text readback is recorded separately. |
| Hosted exact-head protocol contract | Job `130324695713` failed before its five from-zero native invocations. The original 60-second `cargo fmt --all -- --check` process timed out: exit -9, 60.002692917 seconds, empty stdout/stderr. All five native invocations and the three report-acceptance stages are explicitly unexecuted. |
| Hosted original 30-second campaign | Run `42960214803`, job `130324697559`, executed all three original campaigns on M. All returned exit 101, with no startup or report-format errors: **0/3 complete campaigns, 0/9 complete phases, 3/27 timely planned confirmation rounds**. |

Nested one-test libtest summaries are not the whole-library result. The latter
requires the top-level process exit and the final unfiltered suite summary.
Strict Clippy also requires its own terminal result and unchanged source and
pinned-provider guards; a completed component build is insufficient.

The dated hosted status snapshot at 2026-11-11 07:03 UTC still observes the
exact-head workspace runtime and quality shards running. Their complete result
is not inferred from the narrower completed desktop node validation. No complete
required-baseline or release pass is claimed.

The protocol-contract formatter timeout is retained separately from the short
business comparison's `CONFIRMATION_TARGET` failures. Artifact `13834081764`
has ZIP SHA-256
`28c7ad48d1b39e2380e7cafb11894e3652390be3d4ddfea460338822dd62e840`.
Its unchanged exact-M source receipts and original manifest record
`NATIVE_TIMEOUT_STOPS_CAMPAIGN` and `NATIVE_FORMAT_CHECK_FAILED`. The captured
output contains no formatting diff or native panic, and does not establish
the formatter's underlying wait cause. A passing format check in another
recorded environment does not turn this job into a pass. The prospective-merge
protocol job is a separate source observation.

### Retained desktop fixed-lane executables

| Executable | Bytes | SHA-256 |
| --- | ---: | --- |
| Library tests | 102,339,856 | `97b219b88db96705cdd297427f408674fd8d1705f27990b72b6de2aea9ae3e4a` |
| Pool integration | 10,150,744 | `ed9d6a7db469bf2c164e1f69d8b9655682df1ff7bf61ad7925ab412fd19469b8` |
| Actual CLI | 17,187,680 | `4b0ed0d62e4c56af7e030737ef2b95e57744c539d0832d95554d66fbd91bb6f9` |

These are recorded built/retained binary guards. The text archives below do
not contain the ELF files, and the independent transcript readback is not an
independent ELF download or another native execution.

## Business acceptance is separate

### Current-source original three-campaign experiment

[Run 42960214803](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42960214803)
uses M, AuthenticatedV1, 1,024 seed transfers in four seed blocks, 21 business
blocks, and the original baseline/from-zero/late-product 30-second phases.
There are zero/24/24 requested attackers. The controller retains four CPUs,
16 GiB and nice 10; the receiver and independent verifier remain in the
quarter-core, 2-GiB phase parent. All three predeclared native invocations ran
and returned exit 101. Build, final source checks and report-format checks
completed without errors.

| Current M campaign observation | Result |
| --- | ---: |
| Complete campaigns | **0/3** |
| Complete phases | **0/9** |
| Timely planned confirmation rounds | **3/27** |
| Actually entered round rows | 12 |
| Planned rounds not reached after earlier failure | 15 |
| Honest submit attempts / client `ok` responses | 84 / 84 |
| Honest ACKs in the original caller window | 84 |
| Exact-digest-matched receiver full-work and dispatch acceptances | 84 |
| History calls / successful independent imports / deadline errors | 77 / 68 / 9 |
| Observed History page owners | 77 exclusive |

Each baseline completed its first round and failed its second; each pressure
phase failed its first round. Thus baseline itself is incomplete. Every phase
records one `PUBLIC_REQUEST_DEADLINE` import error. These observations do not
assign all failure to the attacker or turn submit responses into confirmations.
The separate original-report auditor confirms all 84 one-to-one phase-local
digest joins. Caller ACKs use the caller's original window. Receiver observer
timestamps have their own local epoch and are not subtracted from caller times;
an ACK is not substituted for independent business confirmation. All 77 observed
History page owners are exclusive. The three successful round events contain
one distinct transaction identity.

The auditor independently recomputed all 4,061 receiver `actual_flow` samples.
None meets the original depletion predicate; 790 samples exceed 1.9 CPU-seconds
of cumulative debit while failing the full depletion condition. Minimum sampled
remaining paid credit is 1,972,524,106 ns. There are no missing/unknown flows,
same-flow equation mismatches, unavailable accounting or clock failures, and
the independently computed predicate agrees with all reported flags. Thirty-three
ordinary meter snapshots differ from the separately captured actual-flow
snapshot; this is recorded separately from same-flow ledger equations.

After excluding the 84 matched honest Submit records, 18,361 receiver records
remain: 18,158 have `full_work_accepted=false`, zero have true, and 203 are
unknown. This remainder includes History and unknown records and is not an
individually attributed attacker population. The audit rereads original report
bytes and does not rerun the node, redownload the ZIP/ELF or establish a unique
CPU bottleneck or depletion impossibility.

Official artifact `13833660378` is 81,779,634 bytes, ZIP SHA-256
`96b801074e063222a807a75a012da57f3255f95f3cc0301b7eb012f8188aec78`.
Its three combined report hashes are
`20b0610468fa9b781e69f80a1210442cbfc8536a99b28c567ed6ee2b0b0bc08f`,
`5d56f8557c165a8ed326c54f329767ad60d28b2c366ba17b1dff404042cace86`,
and `4866a9ed85a261de4b7d4fa427b719e40009dd9b930fb62cfde8aaa22dc49327`.
The complete selected original text is retained in a 42,958,086-byte archive,
SHA-256 `bc65c57bf9692fdfb4d5ec2470711562af3a23243b496aa0813ad30634b7d3fb`.

### Current-source four-second comparisons

The required-baseline 4-second comparison at M ran on both x64 and ARM64. Each
phase requires one signed business confirmation. Five named native processes
returned exit zero on each architecture, while the original aggregate business
acceptance failed with `CONFIRMATION_TARGET`.

| M four-second phase observation | x64 | ARM64 |
| --- | ---: | ---: |
| Baseline timely confirmations | 1/1 | 1/1 |
| Baseline observed success latency | 2.836576073 s | 1.777403587 s |
| 16-worker pressure timely confirmations | 0/1 | 0/1 |
| Pressure submit ACKs | 7/7 | 7/7 |
| Pressure History responses | 4/4 | 7/7 |
| Pressure accepted History page-import calls | 3/4 | 6/7 |
| Final replay error | `PUBLIC_REQUEST_DEADLINE` | `PUBLIC_REQUEST_DEADLINE` |
| Attacker client attempts | 383 | 431 |
| Client refused / error / ok | 367 / 16 / 0 | 415 / 16 / 0 |

The x64 observation belongs to [job 130324695723](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42960214277/job/130324695723)
and artifact `13831493931`, ZIP SHA-256
`7899f7639483fa67030f348f26fc0520fd63727377a3ce1948e62354e737dc29`.
The ARM64 observation belongs to [job 130324695802](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42960214277/job/130324695802)
and artifact `13831414961`, ZIP SHA-256
`d32856170ad787b01d924b50a74274abb2af72f8fac142db793e1bc3e76acd44`.
Client dispositions, receiver acceptance and independent confirmation remain
different metrics. These are short local-host comparisons, not saturated TPS
or WAN measurements.

The test constructs one target transaction in a seven-block sequence. Seven
ACKs therefore do not mean seven target transactions. Replay counts are History
page-import calls; a returned error does not by itself prove the absence of a
durable effect. This four-second test uses the ordinary Legacy opener and the
exclusive verifier History entry. It is not the 30-second AuthenticatedV1
campaign or a direct measurement of its account-graph performance.

### Earlier cohort, retained separately

The older original 30-second, three-campaign observation belongs to
`7d6567b92575d1d84766afd49d0720b6f197b0e0` and
[run 42938943169](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42938943169).
It recorded 0/3 complete campaigns, 0/9 complete phases and 3/27 timely planned
confirmation rounds. All three were baseline, with one distinct transaction
identity. All 84 honest attempts had ACKs and exact-digest-matched full-work
receiver acceptance. Every phase ended in a History deadline failure. All
observed History owners were exclusive, so the shared-writer repair alone
cannot close that failure. This cohort is neither the older `aaa3c539` 6/27
observation nor a run of M.

## Preserved failures and environmental observations

- The first `5ec9b449` native execution passed 20/21 named controls. The positive
  durability test left its instrumentation counter table after dropping its
  trigger, and cold reopen correctly refused the extra schema with `SCHEMA`.
  The test-only correction drops both fixture objects. It changes no production
  schema policy, assertions or original deadline. M and the old-pool subject
  use identical corrected test bytes. The initial failed transcript remains.
- The older `5ec9b449` full-library continuation was deliberately cancelled
  after the corrected M run was started. Its authoritative result is cancelled,
  exit -15, not timed out. It has no complete-library or integration pass claim.
- The earlier LLVM attempt exhausted disk space before tests. Its truncated
  raw stderr and unknown/finalizing supervisor observation remain; no native
  result is inferred from them.
- The earlier ad hoc `ae657e26` comparison executed both intended failures at
  the exact line-181 assertion, six decoded rows versus two required. Its own
  wrapper failed because of an overescaped summary regex. A separate frozen
  reader accepts the raw native failures; the wrapper failure is still retained.
  Each old test exits in its first Legacy/initial-batch case, not all four
  corrected internal cases.
- The first official old-scan continuation refused its reused checkout before
  compilation because six evidence archive entries were marked skip-worktree
  and absent. Its native case list is empty. The index metadata was later than
  the earlier ad hoc run's validated source window; actor and cause are unknown.
  The earlier checker contained the same refusal. The second official attempt
  uses a new complete checkout and target, preserving the earlier source and
  every failure record.
- Cloud disk/transport interruptions and Hepta read timeouts are environmental
  observations. They are not fabricated compiler, test or job termination
  outcomes. Existing durable native jobs were not restarted because a read
  timed out.
- The first hosted-artifact readback script rejected a successful test's
  multiline `--nocapture` output because of an extra single-line assumption.
  Its failure belongs to the derived reader. Re-reading the unchanged original
  artifacts with the frozen M parser accepted all four required rosters; the
  first readback failure remains preserved.

## Follow-up findings and remaining work

The original receiver's 3,996 retained actual-flow samples contain no unknown
flow, no recomputation mismatch and no sample satisfying the original depletion
predicate. Although 667 samples exceed 1.9 CPU-seconds of cumulative paid debit,
the minimum remaining paid credit is 1,976,183,348 ns. The identity includes
credited refill and settlement discard. Equal quarter-core quota and scalar
refill rates raise a reachability question, not an impossibility proof; the
samples cannot exclude changes between observations.

Receiver and independent verifier are separate Node/state owners within the
same phase process, with the service on another thread. The verifier's
exclusive History work does not debit the receiver's sampled paid account.
CPU intervals with different thread scopes cannot be used as an exact removable
cost fraction.

The relevant graph/cache files are unchanged between 7d and M. Existing
transaction-scoped record/subtree reuse, current-SQL BLOB checks and projection
reuse are retained. Removing additional readback across callbacks or writes
would need proofs for actual connection and transaction identity, mutation and
savepoint/transaction ABA, schema/trigger effects, cancellation and cold
recovery. No unmeasured graph optimization was added to the frozen candidate.

The delivered work addresses specific shared History and ordinary mining
control gaps. Complete exclusive History confirmation, timeout/retry effects,
full-state copy and repeated verification reduction, deterministic parallel
conflict handling, persistence batching and recovery, and total retained-history
bounds remain open. No PQ capacity, block interval, paid-resource policy,
confirmation criterion or consensus parameter was raised to manufacture a pass.
Higher block rates, DAG and parallel-chain comparisons still require matched
complete-business evidence.

## Retained package

[MANIFEST.json](MANIFEST.json) lists each retained file's bytes, SHA-256 and Git
blob identity; the manifest excludes its own recursive identity. The original
archive member maps remain with the raw packages.

| Evidence | Readback |
| --- | --- |
| Complete M native continuation and final guards | [Final native readback](readbacks/root-native-M-final-evidence-readback.json) |
| Four desktop source lanes | [Desktop comparison](readbacks/root-four-native-lane-readback.json) |
| Four hosted source lanes | [Hosted comparison](readbacks/root-four-hosted-lane-readback.json) |
| Current M original campaign, recomputed from all three original reports | [Independent report audit](readbacks/independent-report-audit-v1.json) |
| Exact-head protocol formatter timeout | [Protocol failure readback](readbacks/root-protocol-M-failure-readback.json) |
| Earlier 7d depletion and graph/cache source review | [Earlier follow-up](NATIVE_FOLLOWUP.md) |

The current campaign's complete selected original text is retained at
[original-text.tar.gz](hosted/original-campaign/original-text.tar.gz).
Other original native/hosted archives, source/reader receipts, failed attempts,
executed analysis scripts and dated CI observations are indexed by the manifest.

Raw archives, source receipts and reader output have different roles. The
package manifest lists exact bytes and hashes. Derived readbacks identify the
original archive/report and do not replace raw failures. Qualification flags
for production activation, network capacity and tail-latency claims remain false.
