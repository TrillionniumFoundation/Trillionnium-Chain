# W1 complete legal-search factors and separate false-trace rejection

Measured source: `2b250859e7c07088e6c3c01f75006372c684de61`, tree
`12c414a565f58fde6e98ec6eba503d9389ddd06f`. The complete V3 legal-search
capture and the separate FullLimb false-trace capture both returned **PASS**.
Work-security and public-service qualification remain **HOLD**. Exact-source selected native controls completed **198 passing tests**, with the
two existing ignored entries described below. Strict all-target/all-feature
crypto/Node Clippy, locked metadata and formatting passed. The earlier interrupted
validation attempt remains a separately retained failure.

The [manifest](manifest.json) binds the original execution manifests, binaries,
raw stdout/stderr, analysis and validation records. Publication of this bundle
does not relabel a later documentation commit as the measured code revision.

## Problem and changes under observation

Correct W1 verification establishes the submitted relation. It does not establish
the cheapest legal producer's cost or the receiver's economic cost of rejecting
an invalid trace. A comparison that changes both arithmetic and losing-proof
serialization also cannot identify which change accounts for a measured
difference. These are separate questions under the
[work-security model](../../docs/protocol/pon-nakamoto-v1/details/PURE_PON_WORK_SECURITY_MODEL_V1.md).

V3 separates two factors: eager versus lazy PNW1 proof materialization, and
Transposed versus FullLimb arithmetic. Every cell pays its actual setup and all
complete legal attempts, including losing tickets. Lazy materialization avoids
serializing losing proofs; it does not replace complete attempts with a hash-only
search. The four cells use matched challenge streams. Separate native calls
check each winning proof and its final-product mutation.

V1 retains its two-sample evidence identity. The concurrent V2 retains its
eight-sample identity and FullLimb dispatcher. V3 has its own example, selector
and reader schema. The runner keeps all 30 original shards, the 300-second
per-shard limit and the 900-second build limit. Modes are mutually exclusive;
an incomplete prefix, missing final shard or failed capture cannot satisfy the
complete-grid check.

The measured source also retains the History removal of redundant Host reads,
the complete original cancellation/resource checks, and upstream nonblocking
optional rejection-cache access. Cache contention or poison produces a miss or
skipped publication; complete native verification remains the fallback. The Host
parser removes temporary allocations while preserving current-file reads and
refusal rules. This bundle does not attribute a service improvement to those
changes.

## Source, binary and environment scope

Both execution manifests record the same committed-clean source before and after
execution, unchanged Cargo configuration, and matching executable and retained
binary-copy SHA-256 values before and after capture. The native examples use
Rust 1.95.0, the locked workspace graph, the default release profile and
`x86_64-unknown-linux-gnu`. The execution context is `local-native-preflight`.

The diagnostic host snapshot records `cpu.max = 800000 100000` and
`memory.max = 8589934592`: an eight-CPU-equivalent quota and an 8-GiB memory cap.
It is one locally provisioned environment. It supplies no independent physical
hardware attestation or ARM observation. The original public Host contract is
0.25 CPU / 2 GiB, with the original four-second, sixteen-hostile-producer,
six-depth business criterion. That contract was not exercised by these captures
and has not been enlarged or replaced.

## Complete V3 factorial capture

The retained grid contains **30/30 shards**: five material classes, two fixed
targets, and reuse horizons 1/8/64, with eight sample IDs and all four cells in
each shard. The classes are full-rank-field, zero, continuity-maintenance-v1,
one-zero-left-rank-one and one-zero-right-rank-one.

Actual execution paid **960 setups, 23,360 searches and 389,788 complete
attempts**. There were 23,360 target hits and no exhausted searches, capture
errors or semantic alerts. The four native verifier paths produced **93,440
`Accepted` legal results and 93,440 `Product` refusals** for the separate
final-product mutations. These are actual invocation counts; repeated cells and
horizon prefixes are not independent challenges or credited chainwork. After
cell/horizon deduplication there are 5,120 indexed search streams.

| Fixed cell | Producer CPU (s) | Producer + measured evidence CPU (s) | Paid attempts | PNW1 bytes materialized |
| --- | ---: | ---: | ---: | ---: |
| eager-transposed | 46.269654 | 46.594242 | 97,447 | 4,793,223,036 |
| lazy-transposed | 46.051049 | 46.386532 | 97,447 | 287,257,920 |
| eager-full-limb | 34.886637 | 35.217719 | 97,447 | 4,793,223,036 |
| lazy-full-limb | 35.389193 | 35.713853 | 97,447 | 287,257,920 |

Each cell pays 240 setups and 5,840 searches. Eager cells materialize all 97,447
attempted proofs; lazy cells materialize the 5,840 winners. Common material
generation costs a separately retained 0.021745635 CPU seconds over the 30
actual shards. It is not divided by a hypothetical winner count or charged four
times to the same shared material.

Inclusive producer CPU contains each actual setup, complete attempts/tickets,
winning proof serialization, eager losing-proof destruction, retained binary
trials and timing/container overhead through cohort completion. The second CPU
column adds a separate, non-overlapping interval for complete-attempt digests
and attempt-record JSON Value construction. It is a measured subtotal. Outer
record construction, further proof hashes, JSON serialization/write, later
retained-object destruction, receiver verification, transfer and business
settlement remain outside that subtotal.

In this run, FullLimb producer CPU is 24.60% lower than Transposed in the eager
cell and 23.15% lower in the lazy cell. The materialization effect is smaller
and changes sign: lazy versus eager is -0.472458% with Transposed and
**+1.440539% with FullLimb**. For the zero / target-index 0 / reuse-64 shard,
lazy FullLimb producer CPU is **+105.0876%** relative to eager FullLimb
(+100.4703% for producer plus measured evidence). The observation remains in
every aggregate and denominator. Its cause has not been established. Neither
the aggregate increase nor that shard establishes a stable regression, and the
run does not support a claim that lazy materialization is uniformly faster.

The [eight-sample diagnostic](analysis/completed/zero-target0-reuse64-sample-diagnostic.md)
locates a +411.604441 ms lazy-versus-eager FullLimb difference in sample 5,
against a +408.883176 ms net difference for the whole shard. Each cell paid
the same 133 complete attempts and 64 hits for that sample. This locates the
concentration without explaining its cause or providing a filtered estimate.
All eight samples remain in the reported totals.

The [complete factorial report](analysis/completed/REPORT.md),
[machine-readable analysis](analysis/completed/analysis.json) and accompanying
sample/shard CSVs retain all paired effects and 61 descriptive timing flags.
Those flags do not remove samples. Eight samples satisfy the selected experiment's
sample-count condition; they do not prove the full material/target policy or a
lower bound on the cheapest legal strategy.

## Separate FullLimb false-trace capture

This experiment has its own attack generator, timing intervals and denominator.
It does not borrow V3 legal-producer timings or the Product-mutation calls above.
The fixed capture contains **nine classes, 72 actual setups, 288 searches,
573 paid hash attempts and 288 candidates**. All **1,440 native verifier calls**
across five paths returned `Transcript`; there were no exhausted searches or
semantic alerts, and no valid-proof acquisition was used.

Measured attacker-cohort CPU is **0.005807667 seconds**. The default production
receiver spends **0.120374555 CPU seconds** on complete primitive refusal.
The ratio of these campaign sums is **20.726834889**, with per-class ratios
**18.339781–27.212225** (approximately 18.34–27.21). This is a ratio of actual
summed CPU intervals, not an unweighted average of class ratios. The separately
invoked explicit FullLimb path records 0.119886695 receiver CPU seconds and a
20.642832139 ratio. Production and explicit FullLimb share an arithmetic kernel;
their independently timed calls remain separate observations.

The attacker denominator includes each actual prefix setup and all four
independent false-trace searches using that setup, including misses, challenge
hashes, trial retention and winning clone within the declared interval. Common
public-material generation, JSON/output, receiver work and later retained-buffer
destruction are excluded and remain explicit. The receiver interval measures
the complete native verification call with no mathematical fact cache. The
[false-trace report](analysis/false-trace/REPORT.md) and
[analysis](analysis/false-trace/analysis.json) preserve every class and path.

Correct refusal is observed; the unchanged local receiver/attacker `<= 1`
economic condition remains unsatisfied. These are finite primitive measurements,
not a cheapest-attacker lower bound or a public-network amplification coefficient.
The historical 6.86–7.90 observations used different fixed source, campaign,
instrumentation and environment conditions. They do not form a controlled
before/after comparison with this capture; a performance-regression claim from
those two ranges is unsupported.

## Validation and preserved failures

| Observation | Retained result and scope |
| --- | --- |
| Complete V3 capture on `2b250859` | PASS: all 30 shards and four cells; counts and refusals above |
| Separate FullLimb false-trace capture on `2b250859` | PASS capture; local rejection-economics condition unsatisfied |
| Pre-publication integration Python controls on the identical merged tree | 250 passed: runner 49; CI contract 95; V1/V2/V3 readers 12/11/15; source/PQ-source negatives 34/34 |
| Exact-source native regression suites and strict Clippy | PASS selected controls: W1 113 plus retry 85; 198 passing tests, 2 existing ignored entries; strict all-target/all-feature lint passed |
| SQLite I/O boundary qualification | UNQUALIFIED observation retained in native validation output |
| Original-budget public Host service acceptance | Not established by this bundle; previous source-specific failures remain failures |

The [native validation summary](native-validation-summary.json) maps every passing
command to its source-guarded receipt. The initial Host lib-test compiler exited
with SIGKILL; its Host tests did not run. The initial driver was later stopped,
and the remaining controls passed with Cargo build concurrency reduced from four
to one. Release optimization, selectors, assertions and 900-second command limits
were unchanged. All partial output and the managed interruption record remain in
[the initial attempt](validation/native-initial/); the completed retry is in
[the jobs-one attempt](validation/native-jobs-one/). The initial driver traceback
was emitted after its finally-written manifest: the summary records that final
log-hash difference without rewriting the original manifest.

The two existing ignored entries are the History subprocess fixture, exercised by
its parent SIGKILL-cut control, and a separate explicit protocol paired-cost
observation. Neither is counted among the 198 passing controls.

The native Host validation output reports SQLite I/O boundary `UNQUALIFIED`
because of an unknown or duplicate Cargo loader directory. The original warning
and environment are retained in [validation](validation/). Passing selected
module tests cannot override that observation or qualify the I/O boundary.

The earlier source `d78b67d7bd2b1e194e7679c46dc77ac1ffed286c` attempt remains
**FAIL**. Only 18 of its planned 30 shards completed; the remaining captures
could not launch the build-output executable. The underlying disappearance was
not causally established. Its successful prefix, original failed captures,
runner observations and source guards are preserved together in
`failed-d78-full-observation.tar.zst.part-*`. No prefix from that source is
spliced into the 30/30 `2b250859` capture, and no rebuild relabels its failures.

## Retained artifacts and remaining gates

The manifest inventories the successful raw compressed archive parts and the
complete failed-`d78` archive parts, including assembly order and hashes. The
original per-command stdout/stderr and execution manifests remain authoritative;
derived reports do not replace them. Analysis readers are pinned to the measured
source. Validation logs remain separate from cost records.

The following claims remain unqualified: the cheapest legal work-cost lower
bound; complete work-profile acceptance; fresh-identity rejection economics;
resource fairness and original-budget independent confirmation; physical and
cross-architecture hardware qualification; model improvement or utility; whole
chain quantum/post-quantum cost security; public-network readiness; and
production activation. No work relation, target, chainwork rule, proof-acceptance
predicate, deadline, Host budget or business acceptance threshold is relaxed by
this evidence publication.

## Reproduce the byte checks

Run `python3 evidence/pon-w1-factorial-v3-20261102/verify_archives.py` from a checkout
containing this bundle. Python and `zstd` are required. The helper verifies every
part, assembled archive and original member without extracting or executing it.
[The archive index](archive-index.json) preserves the exact part order and hashes.
For independent record readback, assemble/extract the successful archive, check
out measured commit `2b250859e7c07088e6c3c01f75006372c684de61`, then apply its
V3 reader to all thirty `campaign-*.stdout` files. The analysis scripts and all
input identities are retained in [analysis](analysis/). Byte/readback consistency
does not authenticate clocks or establish an adversarial cost lower bound.
