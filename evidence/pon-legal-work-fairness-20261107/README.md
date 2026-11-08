# Legal work, input choice and fresh-ticket fairness — retained evidence

Result: **implemented, independently checked research audit; HOLD on PoW qualification**.
The new grouped lottery wrapper admits a concrete cached-work counterexample:
the model/input arithmetic is independent of the challenge, so one correct
product can be rebound to fresh candidate contexts without new neural matrix
contractions. Canonical encoding closes the tested carrier-reticket freedom;
it does not make each fresh ticket computationally expensive. All audit
chainwork, business credit and model reward remain zero.

## Source and evidence identity

- Tested source commit: `a4302cbf401d59391bcd38978ce3e2c68f60e49e`.
- Tested tree: `e7ddee5ecf6f9844b728a34c0fe6d6e06bb4ee56`.
- Parent: `adebe0bd78e6e1bdb55a599179ffe2313997170e`, preserving the concurrent
  standalone CodeQL lockfile repair on the existing integration candidate #688.
- The later evidence commit is an artifact attachment, not a relabelling of
  the source under which these experiments and tests ran.
- [Protocol and measurement contract](../../docs/development/specs/pon/GROUPED_WORK_FAIRNESS_AUDIT_V0.md),
  [strategy source](../../formal/pon-nakamoto-v1/grouped_legal_strategy_v0.py),
  [lottery source](../../formal/pon-nakamoto-v1/grouped_work_lottery_v0.py), and
  [GPU harness](../../formal/pon-nakamoto-v1/experiments/grouped_gpu_legal_v0.py).

Both final local campaigns independently checked the source before and after
execution. The official CI source guard also verified the complete tracked tree
before and after the final validation suite. No production consensus, target
policy, fork choice, W1 wire format or activation code changed.

The retained material is the historical source-routing model with artifact
`d6ac3f24a43045dda6af862344918688b5fbb047599d423e27c567cf670ccfc2` and evaluation
bundle `485d1ddac3f10b859599297ede15c5703517952d3f507cdc3efea7f14214429e`.
The original source commit is `9fedf7ecbbe07177069c030592b4e03dcffebb81`.
The full original consumer partition was reproduced; the preselected first
16 rows were used. This is a retained historical fixture, not newly trained
model efficacy or authenticated new application demand. Fifteen unavailable
historical Git blobs were recovered and verified against their exact Git object
identities; [hydration provenance](corpus-hydration.json) and the original failed
development observation remain.

## Legal producer campaign

The [frozen plan](strategies/final-source-run/plan.json),
[complete report](strategies/final-source-run/report.json),
[attempt ledger](strategies/final-source-run/attempts.ndjson), and
[independent ledger review](strategies/independent-final-ledger-review.json)
cover **151 observations and all 453 planned rounds**. There were 447 exact
verified rounds and six expected input rejections; no round was silently
omitted. The six rejected rounds retain wall/CPU cost and explicitly unknown
incomplete operation counters. Consequently `round_accounting_complete=true`
and `instrumented_counts_complete=false` are both intentional and consistent.

The campaign includes five real-model arms, 144 controlled observations and
two negative observations, each with three rounds. The controlled cases vary
legal input structure and explicitly synthetic model rank/width. They do not
invent a low-rank factorization of the trained model. Every admitted output
matches a complete independent original-coefficient reference, including router,
tie rule, selected expert, stable grouping and scatter/output ordering.

Real retained batch of 16, exact multiplication/addition positions:

| Lawful producer | First execution MAC | Warm repeated-batch MAC | Other charged work |
| --- | ---: | ---: | --- |
| Original base + selected delta + router | 37,008 | 37,008 | 48 output additions |
| Cached merged, direct selected expert | 24,672 | 24,672 | 2,313 preparation additions once |
| Cached merged, stable grouped | 24,672 | 24,672 | 4,112 gather and 48 scatter elements per round |
| Sparse cached merged | 2,160 | 2,160 | 4,112 input elements scanned per round |
| Exact repeated-input cache | 24,672 | 0 | 16 lookups and 4,112 key elements per round |

Every successful round additionally pays **37,008 MAC in the independent full
reference**, plus the retained validation, key, serialization and hash costs.
The ratio `24672 / 2160 = 514 / 45`, approximately 11.4222, is an operation-count
comparison, not a measured latency advantage or a fresh-ticket cost bound.
Legal bias-only input reduces the dense-position convention by a factor of 257
under the sparse strategy; an all-zero vector including its required bias is
rejected. Cache hits are repeated requests, not new demand or rewarded work.

For the controlled rank-one model, full router + base + factor execution costs
28,832 MAC at batch 16, exceeding the 24,672 cached-merged baseline. The ordinary
baseline must allow exact merged weights as well as factors. This profile has
three outputs; it cannot support an extrapolated 128-fold full-LLM claim.

## Lottery binding, full denominators and native cross-check

The [lottery report](lottery/final-source-run/report.json),
[pre-execution plan](lottery/final-source-run/preregistered-plan.json), and
[independent review](lottery/independent-final-review.json) retain fixed targets,
all misses and repeated/expired attempts. The target is `2^252 - 1`, so the
ideal uniform-ticket probability is 1/16 and nominal diagnostic weight is 16.
Observed hit counts are finite observations, not a fitted claim about SHA-256.

| Group | Attempts | Distinct ticket inputs within group | New inputs across the full run | Result |
| --- | ---: | ---: | ---: | --- |
| Nonces 0 through 63, then repeated 0 | 65 | 64 | 64 | 2 hits; 63 misses including the duplicate |
| 64 carrier/auxiliary encodings of nonce 0 | 64 | 1 | 0 | Same ticket; all arithmetic relations verified |
| Changed parent, batch, task, payee, parameters | 5 | 5 | 5 | Same arithmetic product; all five relations verified |
| Expired versions of nonces 0 through 7 | 8 | 8 | 0 | All eight refused after their ticket queries were counted |

There are **69 globally distinct ticket inputs** and 142 total producer attempts.
The expired queries overlap the original prefix; their costs remain, without
inventing eight additional oracle inputs. The implementation records a query
before later semantic rejection. Repeated internal verifier hashes are also
duplicates, not independently new lottery queries.

The raw expired tickets contain one threshold hit and seven misses, but all
eight requests fail the deadline check and receive no accepted-result hit/miss
flag or credit. This distinction is retained in the independent review; the
report's zero accepted hits/misses for this group does not mean uncomputed
ticket values. In total, 134 attempts passed the current correct research
relation and eight were refused; 73 evaluations duplicated existing inputs.

The native Rust grouped example accepted the exact nonce-zero statement and
matched the Python and NumPy products, every commitment, routes, logits, groups
and scatter order. Its release binary SHA-256 is
`31cd335301d3f4c2898ea3633f7f0e4b76a234f779fbeb4258e5dc016a586acd`.
The retained native process includes startup, model preparation, warmups, all
three producer implementations, full verification, IPC and exit. Its complete
process wall time was 4.910859 ms. Native warm medians were 16.595 us ordinary,
17.852 us direct selected, and 29.7095 us packed; the packed implementation has
three extra internal phase-clock probes. This is a concrete implementation
observation, not a general kernel speed theorem. Python reticket timing and
native kernel timing have different scopes and are not divided into an attack
factor.

The header uses one new, fixed 414-byte wire encoding with strict types and
domain separation. Candidate fields precede challenge; statement, ticket and
receipt follow it. Unknown output/proof/challenge/shape/dtype fields, duplicate
keys and alternate numeric encodings are refused. A bounded transport auxiliary
field is excluded from the ticket; it is not a succinct proof. A caller must
supply an independently established expected candidate. This audit does not
authenticate task authority or externally witness when a candidate was chosen.

The tested cached producer performs **zero new matrix contractions after
preparation**, while still paying fresh serialization, hashes and full verifier
cost. Correctness therefore cannot be promoted into a fresh-work assertion.
The verdict is `HOLD_CHALLENGE_INVARIANT_ARITHMETIC` with no positive chainwork
path. Inspection and tests of native W1 did not establish a free 64-encoding
attack on W1. Its challenge-dependent noisy transcript is a separate relation.

## Actual Colab T4 measurement

The [GPU report](gpu/README.md), [unaltered result](gpu/result.json),
[machine summary](gpu/summary.json) and [cloud lifecycle](gpu/cloud-lifecycle.json)
bind the exact frozen model/input payload, standalone submitted source, actual
Tesla T4, task outcomes, artifact hashes and owned-resource release.
The cloud ran the frozen standalone script, not a remote checkout of the final
commit. Independent byte comparison confirms that the executed script is the
committed GPU harness with only the declared embedded payload substitution.
The GPU `source_commit` field identifies the historical corpus source; it must
not be mistaken for the later audit implementation commit.

All 480 first-call/warmup/warm samples plus 12 fresh-input samples passed exact
product checks; the separate tie control also passed. The 444 warm samples are
150 real-model samples and 294 synthetic rank-one control samples. Real-model
arms each have 30 warm samples. These repeats reuse fixed data and do not count
as independent business requests or lottery tickets.

Real model, batch 16, same Colab process, milliseconds:

| Implementation | Warm synchronized compute median | Warm whole-sample median |
| --- | ---: | ---: |
| CPU cached merged int64 | 0.140261 | 0.300196 |
| CPU cached merged exact FP64 | 0.161600 | 0.352024 |
| CUDA cached direct selected FP64 | 0.411432 | 0.837090 |
| CUDA original direct selected FP64 | 0.702305 | 1.118157 |
| CUDA cached grouped FP64 | 1.437210 | 1.845617 |

Warm whole-sample timing includes output normalization/transfer and comparison
against an already computed independent scalar reference; it does **not**
recompute that reference every warm sample. The 12 fresh-input samples separately
include new conversion, H2D where applicable, compute, D2H, a new scalar reference
and comparison. GPU kernel-only cycles are not reported. The observed cached
direct and grouped CUDA compute times are approximately 2.93 and 10.25 times the
CPU int64 control, respectively. These are implementation-level slowdowns at
this small shape, not a lower bound on optimized or larger GPU workloads.

FP64 implements the same exact bounded integer relation here: every admitted
integer product and absolute partial sum lies below `2^53`. The actual retained
merged bound is 44,748 and the conservative profile bound is 134,737,904.
No tolerance, FP32, TF32, changed quantization or silently changed profile was
used to pass correctness.

Two actual cloud jobs were attempted. The first exited 2 in 0.120032 seconds
before computation because the deployed `runpy` launcher retained an unexpected
CLI argument. Its original source, freeze, stderr and stopped-task receipt are
retained. Only after observing that terminal state did the corrected frozen
no-CLI entrypoint run once, exit 0, and report a stopped process group.

The successful child took 17.474959 seconds. The workload clock retains
14.246770 seconds, including 988 atomic checkpoints costing 4.839262 seconds
outside hot clocks. First H2D was 50.383106 ms and GPU merged preparation was
64.042100 ms. The one owned T4 allocation lasted 650.278609 seconds from
allocation to release, including preparation, waits, observation and download.
The later 11:37:44 UTC resource observation shows no assignments and zero
consumption count/rate. The earlier inconsistent post-release counter is also
preserved. Per-job billing and GPU energy remain unknown, not zero.

## Validation and retained failures

The [validation commands](validation/final-source/commands.json) and
[original suite result](validation/final-source/summary.json) are immutable.
At the exact tested commit, the suite passed 17 of 18 commands. Its one failure
was the offline fuzz graph: the selected local Cargo cache lacked the locked
`libfuzzer-sys` package. A separately retained local-cache repair/follow-up is
reported in the [acceptance record](acceptance.json); the first failure is not
rewritten as a pass.

The [follow-up graph check](validation/fuzz-cache-followup/result.json) passed
on the same unchanged commit and lockfiles. It used an isolated directory source
restored from 135 existing local crate archives whose checksums match the lock,
without network access or shared-cache mutation. All 147 selected packages and
resolve nodes match the locked name/version/source identities. No dependency
upgrade, fuzz execution or extra success claim is inferred from metadata alone.

Passing tests/checks include 78 grouped Python/native tests (46 new adversarial
and strategy tests), 21 conditional query-bound tests, 238 crypto tests across
all targets/features, the native header-binding integration test, 43 source
integrity controls, and 101 CI-contract controls. Locked workspace resolution,
release native build, workspace formatting, strict workspace/all-target/all-feature
Clippy with `-D warnings`, source inventory and repository Markdown-link checks
passed. This is not a claim to have run every workspace unit test, the original
hostile-service campaign, or a production qualification gate.

Development observations before the source freeze remain separately named.
The missing-corpus failure, diagnostic retained-byte run, source-replay
development run, initial GPU failure, local missing-torch entrypoint probe,
and first offline dependency failure are all retained. They are not presented
as the final committed-source experiment. The initial compute-readiness file
is a timestamped pre-allocation snapshot; later cloud lifecycle observations
provide the actual allocation/execution/release evidence. Previous Kaggle
acceptance tasks remained ERROR; this task did not launch a replacement Kaggle
job or treat those older failures as resolved.

## Evidence packaging and reproduction

Small raw per-attempt lottery receipts, the three development strategy runs and
the two native test stdout logs are stored byte-for-byte in
`supporting-observations.tar.gz`, preserving their original relative paths.
The native logs retain Cargo's trailing blank lines without rewriting raw
output to satisfy a source whitespace check. `supporting-observations-manifest.json`
records every archived file's length and SHA-256. Final reports, plans, ledgers,
GPU source and results, other validation logs and independent reviews remain
directly readable.
To restore the original full evidence tree for manifest checks, extract the
archive in this directory. No archived file overlaps a directly retained file.

The top-level `evidence-manifest.json` covers the published files other than
itself. The [retained validation driver](validation/run_final_validation.py)
and the protocol contract give reproduction commands. Experiments should write
to a new directory outside a clean source checkout while source guards run.
Original historical Git objects are required; substituting a new corpus is not
a replay.

## Unresolved qualification

This closes executable audits and specific canonicalization/accounting gaps.
It does not prove a minimum lawful resource cost for a new independent ticket.
A successor needs a challenge-dependent work relation that survives the lawful
factor/merged/sparse/cache/context strategies, explicit computational assumptions,
independently established candidate/target authority, and complete proof,
verification, availability and propagation costs. Numerical or model/profile
changes require their own exact contracts and comparisons. Quantum coherent
queries, cross-parent amortization, bulk-precommit economics, real demand and
model benefit remain separate questions. No benchmark here authorizes activation.
