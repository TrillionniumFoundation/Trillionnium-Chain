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
