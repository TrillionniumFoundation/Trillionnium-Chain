# Business throughput accounting and component observations

**Status: HOLD_NO_GO.** This continuation starts from
`f2d14f9ebd25e054fe17c880331ae0d0c7df46e3` (PR #819). It adds observation
contracts and retains actual diagnostic results. It does not qualify public
throughput, useful computation, complete model service or activation.

The original 511-to-256 state-application result remains an operation count.
All 256 signatures and full canonical state, receipt and root comparisons remain
required. The complete-block measurements below do not show a uniform wall-time
improvement and cannot establish a CPU or TPS doubling.

## Four separate business denominators

| Axis | Required denominator and boundary | Current result |
| --- | --- | --- |
| Confirmed business throughput | Unique business transactions confirmed under the same depth-and-work rule and original observation interval | `null`; no newly qualified confirmation campaign |
| Effective computation | Unique useful tasks accepted by an independent evaluator, with complete training, failure, proof and propagation costs | `null`; historical commands and stage costs are not independent task acceptance |
| Weight access | Complete version acquisition with declared cold/hot cache conditions, loading latency, failures and repair traffic | Historical complete-release records retained; complete cold/hot service rate, loading, global failure denominator and physical repair traffic remain `null` |
| Actual model service | Actual inference/learning throughput, independently evaluated future tasks, old-capability retention and net value | Historical action scoring and training retained; useful service rate, adoption and net value remain `null` |

ACKs, block height, signatures, successor maintenance blocks and test counts do
not replace any numerator above. Unknown is not zero or PASS. Source consistency,
a successful parser or a complete component observation is not business acceptance.

## Complete M06 block: one retained diagnostic experiment

The release libtest binary was compiled with Rust 1.95.0. The native experiment
uses 256 signed transfers to a common recipient, four workers and three sender
distributions. Each distribution has two warmup pairs followed by twelve measured
pairs, alternating reference/candidate order. All 84 original rows are retained:
12 warmup rows and 72 measured rows. Full assertions follow every timed call.

| Distinct senders | Reference wall median, ms | Candidate wall median, ms | Candidate change, ratio of medians | Candidate faster pairs | Median of paired candidate/reference ratios |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 2 | 21.674229 | 19.240576 | -11.23% | 7/12 | 0.961951 |
| 64 | 18.794282 | 19.150353 | +1.89% | 5/12 | 1.063119 |
| 256 | 25.348153 | 27.420416 | +8.18% | 4/12 | 1.131277 |

The two ratio columns are different descriptive statistics. No pair is dropped
and distributions are not pooled. This shared development host was not the
original 0.25-CPU service profile. There is no confidence, tail-latency or
sustained-traffic claim from this experiment.

Each timed call includes decode, all signatures, canonical state execution, root
construction and worker startup/join. Input generation/signing and the assertions
after each call are outside that timed region. Ingress, proof work, consensus
confirmation, SQLite commit/fsync, network and recovery are also outside it.
Per-arm CPU was not measured and remains `null`. The complete child process used
2.838366 user CPU seconds and 0.118162 system CPU seconds over 2.153874387 wall
seconds; those totals include both arms, warmups, setup and assertions and cannot
be assigned to either implementation.

The [original raw run](native-mvcc/run4/commands.json),
[strict complete-block readback](native-mvcc/run4/complete-block-readback.json)
and [independent recomputation](native-mvcc/run4/independent-readback.json) retain
the distinction. The executed binary SHA-256 is
`53bb65f632402701b4d2f8eb25e4e4fb090cc4d11dd01d86af1bbb82dd0483b6`.
The 213-file M06 dependency/include source closure matched before and after;
this is a scoped file identity, not an attestation of every repository file.

## Complete root encoding: memory benefit, limited timing evidence

The fixed root experiment uses 16,384 synthetic keys and 4,096-byte encoded
values. Four fresh processes execute original, streamed, streamed, original.
All return the same full root:
`0a2398d9d2b2862a6eccbb96b4e1127c028c4bc0958af7053b251a8bab8c38e3`.

| Median of two processes per arm | Original | Streamed | Change |
| --- | ---: | ---: | ---: |
| Root-call wall seconds | 1.090859 | 1.079422 | -1.05% |
| Whole-process wall seconds | 1.162697 | 1.178384 | +1.35% |
| Whole-process CPU seconds | 1.155388 | 1.153317 | -0.18% |
| Process peak RSS, KiB | 205,704 | 72,416 | -64.80% |

This supports a memory reduction on the declared fixed input. Two processes per
arm do not establish a general CPU, latency-tail or complete business-path gain.
The whole-process measurements include state construction and cleanup. This is
not an incremental-root or cold-recovery qualification.

## Cancellation: observe the flag transition and the real worker boundary

The new optional nested `public-v3-request-cancellation-observation-v1` records
the first observed false-to-true request-flag transition as a before/after clock
bracket. It distinguishes signal sources, including normal connection cleanup.
An observer worker guard closes after task cleanup, CPU settlement and output
handoff/disposal. A worker return is not a process exit or durable rollback.

Readers preserve missing old extensions, unobserved transitions, failures and
ambiguous signal/return ordering as unknown. A worker returned before the bracket
is reported separately. An overlapping bracket has unknown ordering. Only a
return after the bracket yields lower/upper elapsed bounds; an exact transition
instant is not invented. Original whole-effect reconciliation and signal-to-stop
fields remain null. Small samples cannot supply p95/p99.

Local Node compilation did **not** finish: Cargo exited 101 after
1005.264911621 seconds when `trnm-data-availability` rustc received SIGKILL.
No Node libtest binary, cancellation test execution or native snapshot resulted.
The cause is not uniquely established as OOM. The 900-file dependency/include
closure matched before/after the failed build. The optional SQLite I/O boundary
also emitted its original `RUSTC must be absolute` / UNQUALIFIED warning; this
attempt does not qualify that boundary. See the
[failed build record](native-node/run1/failure-summary.json).

The [component runner](../../formal/throughput-v1/run_component_observations.py)
and dedicated CI job now select actual binary inventories, retain seven planned
native processes, all exit statuses and whole-process rusage, and bind raw files
and endpoint binary hashes. CI uses a separately named development profile.
Its results must be assessed at their actual commit; wiring and static review
are not execution results or substitutes for the original business gate.

## Historical useful-compute cost projection

The [new projection](useful-task-report.json) reads the original 44-file pinned
model corpus. The external manifest SHA-256 is
`9e3c64afcd03bb17ac8746d1146a98c78d214000ccaf71ed2aed0ea96a6a3d25`.
This is historical readback, with no fresh training or inference execution.

It retains 18 command slots (16 zero exits, two nonzero exits), three training
receipts and 25 reported stages. Reported stage CPU totals 130,011,484,774 ns.
That is not complete process-family or task CPU: interval overlap and full cost
coverage are unavailable, and enclosing process times are not added to stages.
The failed 2.049700966999808-second transfer and controlled refusal remain in
the record. Missing CPU, proof or physical network cost stays null.

There are 64 action-scoring forward records on 32 shared fixture labels, with
16/32 correct in each arm and `NoUpdate`. These are not generated tokens,
independently accepted useful tasks or evidence of future learning and retention.
Each cost retains its original path, SHA-256, Git blob and JSON pointer. The
projection exits 1 with HOLD when the corpus is valid but unqualified.

## Validation and failure preservation

The [Python validation record](validation/python-validation-summary.json)
retains the original 246-test batch as **245 passed, one failed**. The failed
source-fence control reached a HEAD-change assertion without the expected
commit switch; its cleaned-up child receipt is unavailable and the cause remains
unknown. One separate retry of that exact test passed with the original five
second child budget. It does not rewrite the first batch to 246/246.

An earlier phase-reader attempt was 72/73 with one missing historical fixture;
the later original suite passed 73/73. Missing sparse-checkout inputs caused
initial report, CI-contract and PQ-source checks to fail; exact original files
were restored, then the four historical reports reproduced byte-for-byte,
the CI contract passed and all 586 pinned source blobs passed. Original report
HOLD exits remain HOLD. The original 43 source-integrity controls and failed
attempts are retained without weakening their tests.

Formatting and locked default/all-feature/fuzz Cargo graphs passed after a
separate attempt could not even create its output directory because of ENOSPC.
The successful graph check retained all 55 Cargo input hashes before/after;
it did not execute Rust tests or Clippy. Strict native compilation/Clippy must
still be assessed from their actual CI run.

M06 build attempts 1, 2 and 3 respectively failed with ENOSPC, a missing original
include file and SIGKILL before the retained successful run 4. Attempt 1 raw logs
survive. Attempts 2/3 were under `/tmp` and were lost on environment restart;
the [failure history](native-mvcc/prior-attempts-after-restart.json) explicitly
marks their original raw bytes unavailable. Tool observations are not fabricated
replacement process logs. Intermittent executor disconnections and shared-disk
pressure are not evidence of a specific kernel kill cause.

The [artifact index](artifact-manifest.json) binds retained bytes, not their
independent origin, host enforcement or business acceptance. Native source
closures, publication source, historical input and CI execution identities are
kept distinct. No deployed data, keys or running service is changed.

## Original acceptance remains unexecuted and HOLD

The [fresh prerequisite observation](host-prerequisites/observation.json)
could not observe the required root-owned parent, reviewed unit or kernel
limits. The original four-second, 16-hostile-input profile remains 0.25 CPU,
2 GiB, zero swap and 256 PIDs under the same depth/work rule. It is `NOT_RUN`,
not passed under a different profile. No new original thirty-second campaign
was executed either. Valid admissions and qualified confirmed/WAN TPS remain
null. Physical network bytes, complete lock wait, cold recovery, independent
useful-task acceptance and complete model value still require their own actual
observations. No merge or runtime activation is included.
