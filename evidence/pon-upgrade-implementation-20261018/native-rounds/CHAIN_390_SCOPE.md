# Source390: actual finite native measurements

All native observations on this page identify source
`390617cbe7b169843f60c5622ec26d2531f385d3`, tree
`f2817209ce22b41fdffda284d37c9381edcd6dae`. They ran on the controlled `main`
Linux host using local TCP. Separate processes and generated signing keys do
not establish independent operators. WAN qualification, production activation,
model training, future model utility and independent economic work hardness
remain unproved.

The [original-file manifest](transport-manifest.json) adds 333 byte-verified
files, totalling 29,758,583 bytes. The source transfer manifest has SHA-256
`8c5d6484a50cc60589f4a20a28c20d0b5e3554a01787671329bc3e62a6e5fb75`;
only its three Chain390 directory prefixes were selected. Earlier raw files,
including failed runs, remain unchanged. The
[derived JSON](chain-390-observations.json) is a reading of the retained native
outputs, not another native execution, consensus receipt or qualification.

## Six development metrics

| Metric | Actual observation and limit |
| --- | --- |
| Unique valid confirmed transactions per second | Successful paced run: 800 / 1052.985140773 = **0.7597448140746955**. Failed faster run: 640 / 168.083421769 = **3.807633098281181**, censored by `WORK_BUDGET`. Sustainable public capacity remains null. |
| Proof verification and state commit rates | Complete pipeline stage counts, 106/86 receiver work verification calls, their wall times, and public V3 mutation CPU are retained. These are finite run counts; isolated verification capacity and isolated state commit capacity remain null. |
| Candidate to actual install p50/p95/p99 | **null**. Transaction confirmation latency is not model installation latency. |
| Installed and subsequently qualified updates | **null**. These Chain runs do not observe a model installed through its original owner and qualified on later tasks. |
| Honest completion during attack | Original public V3 baseline, from-zero and late-product phases each confirmed **0/3 planned signed rounds** inside their pressure window. Baseline had no attackers. The separate narrow network-only success has a different completion boundary. |
| Loss/reorg/restart/new-node cost | **null** for calibrated recovery/sync cost. Functional process restart, submission recovery, process-cut and DA commands passed; their command durations are retained and are not recovery throughput or WAN measurements. |

## Continuous transaction pipeline

Commands and exit status are retained in the
[operational results](chain-390-operational/results.json) and
[measured followup results](chain-390-measured-followup/results.json).
Both runs requested 100 business blocks, 8 transactions per block, `growth`,
and `protected` admission. The offered block paces were explicitly 1,000 ms and
10,000 ms. The runs use the same source, but distinct fresh network, parameter
and genesis identities and evolving work targets. They are not a paired
same-task cost experiment or a saturation measurement.

| Quantity | Successful 10-second pace | Failed 1-second pace |
| --- | ---: | ---: |
| Planned transactions | 800 | 800 |
| Constructed transactions | 800 | 696 |
| Execution/work complete, locally admitted/active, remote acknowledged and membership checked | 800 at each boundary | 688 at each boundary |
| Unique confirmed transaction IDs | 800 | 640 |
| Membership checked but pending confirmation | 0 | 48 in 6 blocks |
| Constructed without completed execution/work | 0 | 8 |
| Planned but never constructed | 0 | 104 |
| Whole campaign seconds | 1052.985140773 | 168.083421769 |
| Unique confirmed transactions / whole campaign second | 0.7597448140746955 | 3.807633098281181, failed/censored |
| Membership checked inclusion-window transactions / second | 0.8062369857499755 | 4.286737244589775 |
| Confirmation block samples | 100 | 80 completed blocks |
| Confirmation p50 | 61.791226089 s | 8.802688286 s |
| Confirmation p95 | 62.723588513 s | 26.365319492 s |
| Confirmation p99 | 63.384339129 s | null |
| Final campaign directory apparent bytes | 20,264,742 | 16,558,105 |
| Final producer + validator ledger apparent bytes | 13,139,968 | 10,739,712 |
| Net growth of these two ledger files from initial 362,192 bytes | 12,777,776 | 10,377,520 |
| Outcome | Passed, heads agree | `WORK_BUDGET`, heads agree at the observed partial state |

The full [slow summary](chain-390-measured-followup/continuous-growth-protocol-pace/summary.json)
and [fast summary](chain-390-operational/continuous-growth/summary.json) contain
every retained membership and confirmation observation. The derived report
checks all business transaction IDs for uniqueness, exact included block/height,
network/parameters/genesis and matching initial membership. It checks confirmed
observations have at least six descendants and the required work delta, no
reorg flag, no deterministic-finality flag and no execution authority. It
reconstructs the pending cohort and compares counts and nearest-rank quantiles
against the raw summary. Sorted-ID SHA-256 values bind the extracted cohorts;
the encoding is stated in the derived report.

The [original pipeline implementation](../../../trillionnium/crates/trnm-pon-node/examples/continuous_pipeline.rs)
defines the time boundaries. Whole campaign time starts after setup and listener
preparation, includes business production, confirmation polling, empty descendant
drain and closing, and excludes final summary serialization. The slow run's six
empty descendants contribute time, work and storage, but no business transactions
or latency samples. External command elapsed time also contains wrapper overhead
and is not the TPS denominator. The inclusion window ends at the last business
Submit acknowledgement whose membership is checked; it does not wait for all
confirmations and is reported separately.

Latency uses empirical block samples, conditional on completed observations.
The nearest-rank index is `ceil(n * percentile / 100) - 1`. p95 needs at least 20
samples and p99 at least 100; these are sample resolution rules, not confidence
bounds. Eight transactions in a block do not provide eight independent latency
samples. Shared confirmation RPC measurements can be repeated in several block
records and must not be summed as separate RPC work.

Receiver `work_verification_ns` records elapsed wall time: 510,528,993 ns over
106 calls in the slow run and 407,954,032 ns over 86 calls in the failed run.
Those calls include the empty descendants when present. They are not process
CPU time or independently measured service capacity. The slow socket metrics
also retain one reserved read-only refusal; successful business confirmation
does not imply every transport attempt succeeded.

Disk values are apparent file lengths. The ledger sum includes both producer
and validator copies after closing, and may be lower than a live WAL-inclusive
sample. Neither its net growth nor command duration measures physical disk
writes, single-node storage amplification or fresh-node synchronization cost.

## Original public V3 sustained phases: all fail

The [original multiprocess report](chain-390-operational/public-v3-multiprocess/report.json)
uses `legacy-v2` local state, the original development settings, 1,024 signed seed
transfers, 21 business blocks, three planned signed rounds per phase and a
30-second phase window. Attack phases request 24 separate attacker processes;
the baseline requests zero. All original thresholds and failure criteria remain
unchanged. There is no authenticated-backend comparison result in this archive.

| Phase | Confirmed / planned signed rounds | Started rounds | Accepted full-work calls | Completed Submit calls | Metered mutation CPU | W1 CPU within mutation | Remaining dispatch/execution CPU |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| [Baseline, no attackers](chain-390-operational/public-v3-multiprocess/baseline.json) | 0/3 | 1 | 36 | 4 | 9.475382602 s | 0.239863877 s | 9.235518725 s |
| [From-zero](chain-390-operational/public-v3-multiprocess/from-zero.json) | 0/3 | 1 | 14 | 2 | 9.394589367 s | 0.998983851 s | 8.395605516 s |
| [Late-product](chain-390-operational/public-v3-multiprocess/late-product.json) | 0/3 | 1 | 14 | 4 | 9.514946622 s | 0.964163890 s | 8.550782732 s |

Only the first planned round starts in each phase; no confirmation observation
is returned inside its window. The remaining planned rounds stay in the
denominator. Receiver/client full states do not converge in any phase. A
successful full-work check is not a unique transaction, completed Submit,
confirmed signed round or model installation. Baseline failure means this
evidence cannot attribute the overall service failure solely to hostile work.

The original CPU budget remains a 2-second burst, 0.25 CPU seconds per wall
second refill, two workers and a 100 ms start reserve. The derived report checks
the final identity `initial + credited_refill - paid_CPU - settlement_discard =
remaining_credit`, including negative debt. Refill discarded at the burst cap
is already excluded from credited refill. Baseline finishes with 181,873,620 ns
debt; from-zero retains 85,530,063 ns credit, below the start reserve; late-product
finishes with 132,284,069 ns debt. Original body/output/grant/CPU in-flight owners
and booked reservations are zero after shutdown. This accounting and cleanup
success coexists with the confirmation failures.

The 9.235518725 baseline seconds are mutation dispatch/execution CPU excluding
W1, not a measured breakdown by SQLite, history function or state-root function.
History is a read lane outside this mutation CPU bucket. Isolating those causes
requires additional actual profiling; this archive does not invent that result.

## Separate narrow network-only followup

The original mixed target's network-only test failed because its report parent
directory did not exist; the adjacent mixed-call test passed. Both outcomes are
preserved in the [original log](chain-390-operational/public-v3-mixed.log).
The followup created that original parent and reran the exact network-only test,
with no change to policy, budget or window. Its
[raw report](chain-390-measured-followup/receipts/network-only-business/report.json)
contains 24 unique confirmed transactions, equal consumer state and equal reopened
state, with 88 overlapping false calls in the finite six-second setup.

The supplied blocks use prebuilt fixtures and logical timestamps; all actors
share one host and controller. Formal final confirmation is checked after the
hostile worker threads join. This shows the bounded network/reexecution/reopen
path, and cannot replace the continuous-pressure 0/3 results or establish
anonymous-flood fairness, guaranteed exhaustion recovery or public TPS.

## Other native results and unresolved boundaries

The [native result list](chain-390-native/results.json) records the corrected
quorum/observer/membership, shared-64 and pinned-peer tests as passing, together
with the original public-pool/from-zero target and strict Clippy. Earlier
source54 failures are unchanged. The source390
[applicability-negative log](chain-390-native/applicability-negative.log) still
fails the expected profile-count assertion: 18 expected, 19 observed. No claim
that this native batch passed every gate is made.

The four functional [restart](chain-390-operational/public-roles-restart.log),
[submission recovery](chain-390-operational/submit-recovery.log),
[process cuts](chain-390-operational/native-process-cuts.log) and
[data availability](chain-390-operational/data-availability.log) commands passed.
Their exact commands, return codes and elapsed durations remain in operational
`results.json`. Setup and compilation can be part of those durations. They do
not provide calibrated partition/reorg recovery cost, new-node sync throughput,
physical power-loss evidence, WAN performance or an independently administered
operator cohort.
