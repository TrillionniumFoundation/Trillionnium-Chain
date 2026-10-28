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
(State) instead of element 1 (height). Separately, its old depletion predicate
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

## Corrections and interpretation

The corrected collector uses explicitly typed u64 heights. It captures the
existing same-lock credit-freshness projection and conservatively includes
possible refill through the end of each sampling interval. The independent
reader recalculates these values and preserves all original ceilings, request
deadlines, 30-s phases, 24 actors and 480-call actor caps. These are telemetry
corrections, not a change to the resource policy or a retrospective edit.

Any later observation is a separate source/binary/stream record. A finite pass
cannot erase this failure, certify unrestricted Sybil fairness, prove PoN
hardness, authenticate hardware counters or grant consensus/model installation
authority. Existing failed r13 observations also remain separate and unchanged.
