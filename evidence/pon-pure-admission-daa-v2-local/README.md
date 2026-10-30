# Pure PoN admission and DAA local observations

These are local development observations, not production or public-network
qualification. The pressure process inherited an 8-CPU / 8-GiB cgroup with nice
0 and shared hardware. It did not run in the separate CI experiment's 4-CPU /
16-GiB unit, or in the fixed 25%-CPU public receiver parent. No administrator
limits, service or production activation were changed.

## Original failed observation

The [manifest](local-observation-01.json) records SHA-256 values for every member
of the [unaltered raw archive](local-observation-01.tar.gz), plus its archive
digest. The 22 files include original packet preparation, all three complete
phase reports (including child reports), native and independent-reader streams
and exits, source identity, binary hashes and actual inherited resource samples.

The measured staged source tree was
`85ea5e6e5df64a40117f81aeaab23ae216c7078a`, now preserved by commit
[`fd6e466dbc13e8aef63f0677e2d1df9be5e4eab2`](https://github.com/TrillionniumFoundation/Trillionnium-Chain/commit/fd6e466dbc13e8aef63f0677e2d1df9be5e4eab2).
The commit was created after measurement; the original receipts truthfully
identify an uncommitted staged candidate, not an exact-head CI execution.

| Phase | Native business confirmations inside the original 30 s | Last round ended |
| --- | --- | --- |
| Baseline | 3 / 3 | 13.452362 s |
| From-zero false transcript | 2 / 3 | 30.068334 s, not confirmed |
| Correct product / fresh header / false trace | 3 / 3 | 20.057870 s |

The native process returned failure. The independent reader also refused the
reports with `native height type`: the initial collector used tuple element 2
(State) as height. Element 1 is activation generation, also not height.
Separately, its old depletion predicate
omitted unbooked refill. Those samples contain no refill-watermark age and
cannot be retrospectively certified as current depletion. Neither defect
removes the observed from-zero service failure.

The main from-zero delay was packet index 3, listener 1, body digest
`74afc2b1478bdc181740db2e633cf4cd33c0c8b7a70a6daba973e2c4feabd08f`.
It began at 3.244333453 s with the original absolute deadline 5.244333453 s,
but returned `IO: Resource temporarily unavailable (os error 11)` at
14.993572449 s. Receiver connection 74 reached solution validation but no
Ready, body or dispatch. Its retry succeeded at 15.360472438 s. All 21 business
submissions completed by 29.385359 s; the last round had only enough time for
five of seven History pages. The fifth local page import finished after 30 s.

The independent 50-ms sampler also showed gaps of 5.011785 s, 1.859751 s,
1.129759 s and 2.436054 s during that physical tail, while its largest sampling
operation was about 4.47 ms. This supports a scheduling or host-pause explanation
but does not establish its precise cause. Inspection found no phase timeout
reset or unbounded cleanup on the client path. Deadline checks correctly deny
success qualification after expiry; they are not scheduler preemption.

## Second captured observation

The separate [manifest](local-observation-02.json) and
[unaltered raw archive](local-observation-02.tar.gz) preserve 20 files from
source tree `6feff931ecf914588e6c5e9876367b3e303826ca`, subsequently committed as
[`19212da4100796c39f1e71fd33f6c0778414dbae`](https://github.com/TrillionniumFoundation/Trillionnium-Chain/commit/19212da4100796c39f1e71fd33f6c0778414dbae).
It corrected the freshness capture without changing runtime resource supply,
the actor workload or any deadline. Native business confirmations were 3 / 3,
3 / 3 and 2 / 3 for the three phases. The native process and qualification
command both failed.

This observation recorded 2,486 from-zero calls; none had completed transcript
arithmetic, consistent with rejection before that stage. The fresh-header arm
recorded 728 calls and 598 distinct challenges with completed and published
arithmetic facts. Its 64-slot churn condition and actual attack/CPU/depletion
overlap were observed, but its third honest round did not complete. This is
not a successful finite service qualification.

In that fresh-header phase, the last History page of round two returned at
15.032377 s, but local `receive_page` ran from 15.032403 to 20.998290 s
(5.965887 s wall / 2.733908 s thread CPU). Round three's first business Submit
started at 21.052818 s. Only that packet completed; the next packet's four calls ended
with `EAGAIN`, the last at 30.011240 s, and no round-three History replay ran.
The prepared packet IDs map the final receiver/client tips to real heights
19/18, so this is an actual unfinished round independent of the labeling bug.

All 23 fresh-depletion samples in round three are wholly inside an honest
Submit call's original deadline and at least one attack call's original
deadline. For example, the sample at 21.193731683--21.193735083 s overlaps the
first honest packet and 24 attackers. Its same-lock paid CPU was 5.214592902 s;
the conservative end-of-sample paid-credit upper bound was 83.633319 ms,
strictly below the unchanged 100-ms reserve. The round additionally recorded
1.388703381 s of hostile receiver dispatch CPU. This establishes a concrete
overlapping failure, not continuous exhaustion or unrestricted-network fairness.
The 2-s deadline applies to a network call; subsequent local History replay
must finish within the original 30-s phase, not within that 2-s network deadline.

The measurement's reader reported structural consistency while refusing service
qualification. A subsequent semantic check found that its integer height fields
still contained **activation generations**: the baseline receiver reported 25
and the independently importing client reported 7, despite sharing the same
height-25 tip. Those mislabeled fields are preserved, not repaired in the
archive. Their presence cannot hide the independently observed last-round
service failure in the fresh-header arm.

## Corrections and interpretation

The final collector obtains height from `parent_height(active_tip)` and records
activation generation separately. A real native regression admits three complete
blocks and activates them once: producer and receiver both have block height 3,
while their generations are respectively 3 and 1. The independent reader binds
reported height to the prepared block identified by the actual tip; it rejects
using generation as height. The stored observation and verdict namespaces are
now v3, so old v2 data cannot receive the new qualification. The signed pure-v2
transport namespace is unchanged.

The collector also captures the
existing same-lock credit-freshness projection and conservatively includes
possible refill through the end of each sampling interval. The independent
reader recalculates these values and preserves all original ceilings, request
deadlines, 30-s phases, 24 actors and 480-call actor caps. These are telemetry
corrections, not a change to the resource policy or a retrospective edit.

The short height/generation regression passed locally; the final v3 90-second
campaign remains subject to its exact-head CI observation. There is no third
local pressure retry to replace the two failures above.

Any later observation is a separate source/binary/stream record. A finite pass
cannot erase this failure, certify unrestricted Sybil fairness, prove PoN
hardness, authenticate hardware counters or grant consensus/model installation
authority. Existing failed r13 observations also remain separate and unchanged.

## Local source and regression validation

The [validation manifest](local-validation.json) inventories all 124 unmodified
members of the [validation log archive](local-validation-logs.tar.gz), including
source-file hashes, compiler build records, binary hashes, process receipts,
native verdicts and the actual conditional-model output. These are local
uncommitted-source records, not substitutes for final committed head/merge CI.

The original release profile on Rust 1.95.0 passed 127 crypto library tests,
181 public-runtime/host tests, three CLI integration tests, two native
DAA/reorganization tests and the final height/generation regression. The crypto
library's one ignored child entry is explicitly launched by its ambient-mode
parent. The final reader, runner, source-integrity and model controls passed
31, 14, 34 and 20 tests respectively. All 2,048 conditional model trials were
evaluated; their cost inputs and quantum parameters remain synthetic premises.

The archive also keeps the first strict Clippy failure caused by a temporary
mistaken edit to the original r13 test; that edit was restored exactly before
the measured source trees. Final full-workspace/all-target/all-feature strict
release Clippy passed. The final validation orchestration also used a wrong
fuzz manifest path once. Its exit 101 is retained; a separate receipt records
the successful locked graph for the actual `tests/fuzz/Cargo.toml`. Neither
invocation mistake is presented as a native protocol vulnerability or a pass.

The locked main graph adds 101 packages without replacing or removing any old
package version. The fuzz lock remains unchanged. Source inventory, Markdown
links, repository checks and formatting passed on the locally recorded source.
None of these regression results overrules the two failed service observations.

## Subsequent exact-head failure and timed-close accounting

The [exact-head manifest](exact-head-c2364a5-validation.json) and
[66-file raw archive](exact-head-c2364a5-validation.tar.gz) preserve a later
local validation on commit `c2364a5864face5e828140e557915f4380f97512`, tree
`765ba4aa64625f26378bd3847f7a827bd6d7d436`. Source identity before and after,
release build records, binary hashes, every process receipt and original
stdout/stderr are included. Its runtime/host filter returned **180 passed,
one failed**, exit 101 without an outer timeout. The earlier 181-pass result
does not replace this exact-head failure. Crypto 127, CLI three, native
confirmation two, height/generation one and the recorded static/model gates
passed in this separate observation; its overall result remains failure.

The failed original TCP case was
`r4_paid_pending_eof_original_expiry_and_shutdown_never_create_body_or_work`.
It first observed EOF and the expected pending-close count, but the assertion
for at least one expired `solution` failed. The exact closing error was not
recorded, so that connection's precise cause remains unknown.

Source review found a reachable baseline classification gap: a deadline can
elapse after the reactor's outer time check. A subsequent stage check can then
return `PublicRequestDeadline` or `PublicCookieExpired`; the generic error
path closed the request but did not add expiry counters. This explains how
the observed combination can occur, not a captured trace proving that it was
the specific failed connection's cause. It is not an expiry bypass.

The correction captures time at the stage-error entry, before observer/metrics
locks, and counts expiry only when **both** a precise time-related error code
and the original connection deadline establish elapsed time. Stop before the
deadline, malformed future intervals, cancellation, EOF, unrelated refusals
and forged error display suffixes cannot claim expiry. The same metrics lock
performs one pending close and retains the original error/refusal counters.
Wire fields, signed profile identities, limits, deadlines and the original TCP
test's conditions are unchanged.

Two deterministic classification controls and that original TCP case passed
locally in the declared test profile. Their
[validation manifest](expiry-correction-validation.json) and
[original log archive](expiry-correction-validation.tar.gz) preserve the exact
source-file/diff hashes, binary identity, commands, profile and verdict. These
controls do not force a real reactor scheduling race or qualify honest service.
The full public-runtime/host compatibility filter then passed all 183 tests
in the same declared test profile. Full-workspace/all-target/all-feature strict
release Clippy also passed. The focused three tests are a subset of those 183,
not additional distinct test coverage.
The corrected committed source still needs its own release/head/merge CI.

## Exact-head CI observations at c2364a5

[Run 40748929769](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/40748929769)
completed its first x64 and ARM64 attempts successfully on the exact `c2364a5`
source. Both original ZIP SHA-256 digests were checked. The independent reader
was rerun locally on the unmodified prepared inputs and full phase reports;
both recomputations exactly matched their recorded v3 qualifications.

| Observation | Native confirmed rounds (baseline / from-zero / fresh-header) | Hostile rounds with both pressure and observed paid depletion | Actual fresh challenges published |
| --- | --- | --- | --- |
| [x64 manifest](ci-c2364a5-x64.json), [raw archive](ci-c2364a5-x64.tar.gz) | 3/3 / 3/3 / 3/3 | 4 of 6 | 1,731 |
| [ARM64 manifest](ci-c2364a5-arm64.json), [raw archive](ci-c2364a5-arm64.tar.gz) | 3/3 / 3/3 / 3/3 | 4 of 6 | 1,736 |

All six hostile rounds per architecture had actual attack and receiver-CPU
overlap. In each hostile phase, rounds two and three additionally contained
fresh paid-credit depletion observations; round one did not. Do not describe
these samples as continuous exhaustion or as depletion in every round. Both
fresh-header phases had zero arithmetic cache hits and exceeded the 64-slot
churn requirement with actual completed/published facts.

These runs used the declared 4-CPU / 16-GiB / nice-10 experimental parent,
two local listeners and 24 actors with the original caps and deadlines. The
six native gates and process/source/binary/resource checks passed. This is
finite service evidence for that source and envelope. It does not certify the
fixed 25%-CPU public receiver parent, hardware authenticity, unrestricted Sybil
fairness, WAN throughput, PoN hardness, PQ-128 or production activation. The
different shared local hardware cannot be used as a controlled throughput
comparison. Both local pressure failures and the exact-head 180/1 regression
remain preserved; these CI passes do not erase them or cover the later
timed-close correction.

## Exact-head CI at 75d52b6: x64 pass, ARM64 evidence failure

[Run 40752790789](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/40752790789)
tested commit `75d52b60b179c7695661afb34d00be9bcdcabbf1`, tree
`0f640c03eaa551d69f8b3a2c0d722a904beef3c0`, once per architecture. The
[x64 manifest](ci-75d52b6-x64.json) and [raw archive](ci-75d52b6-x64.tar.gz)
retain its pass. The [ARM64 manifest](ci-75d52b6-arm64.json) and
[raw archive](ci-75d52b6-arm64.tar.gz) retain its **failure**. Both original
ZIP sizes and SHA-256 digests, step stream digests, source identities and
before/after resource envelopes were checked. Local independent reads of the
five unmodified raw inputs exactly reproduced both recorded verdicts.

The x64 reader qualified 3/3 rounds in each phase; all six hostile rounds had
actual pressure overlap and four also contained fresh paid-depletion samples.
Its fresh-header phase completed and published 1,903 distinct facts, with
zero arithmetic hits. Both architectures passed the six native gates, including
183 runtime tests, 7 transparent-proof tests, 3 CLI tests, 2 native confirmation
tests and the height and pressure gates. The ARM native workload reported nine
confirmed rounds, but its independent reader returned exit 1,
`input_consistent: false`, `finite_qualification: false`, `error: "call clock"`.
Native success cannot override this failed evidence contract.

The violating row is `from-zero/actors/2/report/result/calls/135` (sequence 135):
`started_ns=30000102720`, `ended_ns=30000156365`,
`deadline_ns=30000102720`, status `error`, `PUBLIC_CLIENT_DEADLINE`.
It entered the client API 102,720 ns after the original 30 s phase cutoff.
The client failed in construction before challenge/solution work. The actor's
preceding loop check happened before argument encoding and possible scheduling;
it could not guarantee the captured call start remained inside the window.
The old helper also added a remaining allowance derived from the earlier
monotonic sample to a later `Instant::now()`, needlessly shifting the actual
deadline. This does not establish a production transport deadline bypass.

The forward collector correction refuses a closed phase at the call helper's
captured entry, **before invoking any client API**. All three callers stop
their loop on this no-call outcome. An issued call keeps its entire real row,
including late errors and physical tails; no historical row is filtered or
repaired. An Instant anchor captured before the monotonic sample conservatively
maps the original allowance without granting time for later construction or
scheduling. The sampler now gates and records the same captured start, closing
the analogous between-two-clock-reads race; an already started late-ending
sample remains visible. Existing v3 fields and meanings, reader code, 30 s
windows, 2 s deadlines, actor counts and all resource limits are unchanged.

A new mandatory native call-window gate covers exact cutoff, one nanosecond
on either side, this actual late offset, conservative absolute deadlines and
retention of an issued late error. A reader regression requires the old ARM
row to remain invalid and unchanged. The seven-gate successor requires its own
exact-source campaign; these observations do not qualify it, and the ARM run
is never relabelled a pass.

The [correction validation manifest](phase-entry-correction-validation.json)
and [117-file raw archive](phase-entry-correction-validation.tar.gz) retain the
first strict-Clippy failure (its required equivalent `while let` form), a later
session that ended without a formatter terminal result, and the final complete
release verification. The incomplete session's cause is unknown and it is not
counted as a test pass. Final release call-window and height regressions each
passed one actual test, including the real client construction-deadline negative.
The 32 reader, 14 runner and 34 source-integrity controls, locked main/fuzz graphs,
repository links/inventory, formatting and full-workspace/all-target/all-feature
strict release Clippy passed. Included source snapshots match their original
pre-run SHA-256 digests. No new local 90-second pressure campaign was run.
