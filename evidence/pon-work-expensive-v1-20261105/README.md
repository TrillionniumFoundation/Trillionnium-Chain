# Finite cheapest-work and verifier-cost observations, 2026-11-05

This record reports a finite, executed W1 strategy census, a freeze-before-challenge
Mode A experiment, and native verifier cache costs. All attempted work, losing
trials, unsupported constructors, preparation and actual cache lifetimes are
retained. It provides no work-hardness lower bound, protocol-level Gamma bound,
Node admission qualification or production activation.

Read [summary.json](summary.json) for the compact results and
[reproduction.json](reproduction.json) for commands, source/binary/raw digests,
process receipts and retained observations. The research contract is
[WORK_EXPENSIVE_RESEARCH_V1.md](../../docs/development/specs/pon/WORK_EXPENSIVE_RESEARCH_V1.md);
the [single development plan](../../docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md)
continues to own completion gates.

## Current fifteen-arm continuation

The separately frozen continuation executed commit
[`dd10f0aee7de54cbbf6e67c78bf85a5e1d59244d`](https://github.com/TrillionniumFoundation/Trillionnium-Chain/commit/dd10f0aee7de54cbbf6e67c78bf85a5e1d59244d),
tree `21eec0a14631db0de94cabad07a1d4c14bfe0388`. Its before/after whole-tree
checks cover 10,075 tracked entries / 967,116,079 bytes. Later integration
commits preserve these observations; they are not silently substituted for the
executed commit. This section and `summary.json` report the current observation;
the later historical sections and `historical-v1.json` retain the prior run.

Concurrent development added a real sparse preparation implementation and
separate grouped, low-rank and request-batching research components. The census
therefore adds `lazy-full-limb-sparse`, while the original `lazy-full-limb`
continues to mean dense preparation. The sparse arm uses the existing
`Task::with_preparation(..., Arithmetic::FullLimb, Preparation::Sparse)` and
still computes the entire original W1 transcript. Native records use v2; the
reader accepts the exact v1 fourteen-arm and v2 fifteen-arm registries and
rejects relabeling or mixed versions. The CLI selector stays `--work-expensive-v1`.

### Current counts and complete costs

The same declared schedule was used: nine synthetic classes, five exact model
tiles, two targets, eight samples, 64 attempts per applicable cell and actual
reuse of 16. Samples 0--1 select one arm; samples 2--7 evaluate it. Every hit
undergoes native and independent scalar verification.

| Current census item | Observed |
| --- | ---: |
| Complete / unsupported / failed cells | 1,808 / 1,552 / 0 |
| All completed attempts | 115,712 |
| Verified hit records / misses | 30,867 / 84,845 |
| Actual setup calls, including refusals | 8,784 |
| Completed and destroyed cache epochs | 7,232 |
| Actual attempts per completed epoch | 16 |
| All setup CPU, already inside producer CPU | 1,272.852061 ms |
| All producer component CPU | 51,063.556782 ms |
| Separate material creation / identity CPU | 2.231073 / 8.819925 ms |
| Complete external driver wall, including interpreter startup and exit | 97.080716174 s |
| Complete external child user + system CPU | 97.520428 s |
| Observed external maximum RSS | 326,856 KiB |

The producer subtotal contains setup, every attempt, cleanup and actual
destruction. It excludes verifier/evidence work and global material preparation,
which remain separately measured. Continuous cell, native child, parent driver
and complete external-process clocks are nested and must not be summed. The RSS
observation is not an enforced Host quota. Repeated arms and target cohorts do
not turn 30,867 hit records into 30,867 distinct chain-work credits.

Mode A completed **8 first-hit search attempts, including 3 misses**, producing
five fully replayed primitive statements and **one complete 64-request model
batch**. Its actual cutoff wait was 235.615527 ms. The candidate set, route,
numeric/output contract and complete bounded search schedule were saved before
the OS entropy request. No external clock, beacon, owner or Node ancestry was
authenticated by this local observation.

### Honest baseline changes when a cheaper legal implementation appears

Seven of the ten real tile/target combinations select the new sparse arm on
calibration samples. Their held-out producer CPU savings versus dense are
approximately 2.4--9.1%. The other three select dense. This is a finite selection
rule over the explicitly observed algorithms, not the global best algorithm.

| Real material | Target | Calibration-selected arm | Held-out dense / selected CPU |
| --- | --- | --- | ---: |
| Tile 0 | 0 | sparse | 1.0524 |
| Tile 1 | 0 | dense | 1.0000 |
| Tile 2 | 0 | dense | 1.0000 |
| Tile 3 | 0 | dense | 1.0000 |
| Tile 4 | 0 | sparse | 1.0243 |
| Tile 0 | 1 | sparse | 1.0321 |
| Tile 1 | 1 | sparse | 1.0826 |
| Tile 2 | 1 | sparse | 1.1002 |
| Tile 3 | 1 | sparse | 1.0424 |
| Tile 4 | 1 | sparse | 1.0591 |

The all-zero selected arm remains `blocked-zero`, with dense/selected CPU ratios
1.0538 and 1.0531. At target 0, the six held-out repetitions yield 138 dense and
165 selected hits under **20 ms per repetition of producer component CPU**, only
at actually destroyed epoch boundaries. The aggregate budget ceiling is 120 ms;
this is not one 20 ms budget for all six repetitions or a complete mining budget.
At target 1 the counts are 4 and 5. Zero denominators at smaller budgets remain
undefined comparisons, not an infinite security advantage.

Negative selection results also remain: for rank-one/target-1, calibration picks
sparse but held-out dense/selected CPU is 0.9461, so that choice costs about 5.7%
more CPU. Evaluation data never reselects a more favorable winner. All 28 choices,
420 cohort/arm cost summaries and original counts are in `summary.json`.
Legal savings belong in the honest implementation set. `gamma`, a universal
upper bound and live Node accepted work remain null.

### Current verifier rerun

This is a separate synthetic-public-matrix native cache experiment, not a real
Hepta request-stream or Node stress test. Each row submits eight candidates to
three actual verifier paths. The denominator below is actual preparation plus
all completed search/construction/clone CPU, including misses; diagnostic-inclusive
and cache-setup-inclusive alternatives are also retained in `summary.json`.

| Scenario | Raw amplification | Negative cache | Arithmetic facts | Replayed tiles: raw / negative / arithmetic |
| --- | ---: | ---: | ---: | --- |
| Different materials, cold | 2.835x | 3.022x | 3.006x | 4096 / 4096 / 4096 |
| Exact retransmission | 29.234x | 5.957x | 5.389x | 4096 / 512 / 512 |
| Same input, new false traces | 32.053x | 35.061x | 7.257x | 4096 / 4096 / 512 |
| New challenge | 29.061x | 31.976x | 30.790x | 4096 / 4096 / 4096 |
| One-slot forced eviction | 19.548x | 27.232x | 20.394x | 4096 / 4096 / 4096 |
| Owner recreation | 9.956x | 5.901x | 6.564x | 4096 / 2048 / 2048 |
| Actual negative-cache TTL expiry | 37.151x | 44.857x | 8.453x | 4096 / 4096 / 512 |
| Legal cold/warm control | 5.404x | 5.680x | 1.008x | 4096 / 4096 / 512 |
| Cheap malformed input | 0.629x | 1.449x | 0.615x | 0 / 0 / 0 |

All 216 calls match the expected verdict and lifecycle. All 81 completed search
trials, including 51 misses, remain. The 24 accepts are repeated validation of
the legal control, not new consensus work. Current legal negative/raw CPU is
1.0509895449. The three earlier values 1.0494347657, 1.2456976196 and
1.4827579828, and the earlier raw TTL amplification of 88.6160753235x, are
preserved rather than replaced by this lower observation. These small, noisy
component samples do not establish stable throughput or an amplification bound.

The concrete cache repair rejects malformed version, zero target and field
encodings before its optional full-proof key hash while retaining the native
error ordering. The additional canonical scan is paid on ordinary misses too.
Default Node verification still does not enable this negative cache; no default
Node flood-throughput gain is claimed.

### Current validation and reproduction boundary

On the executed `dd10f0ae` source: **150 crypto library + 10 native example tests,
29 Mode-A tests, 19 current-fixture reader controls, 14 verifier reader controls,
12 shared-material parser tests, 43 source-integrity negatives and 98 CI-contract
tests pass**. Whole-workspace/all-target/all-feature strict Clippy, formatting,
locked Cargo graph and repository links also pass. The legacy v1 fixture passes
the new reader's 19 controls separately. The recorded SQLite build-script warning
about an absolute RUSTC path remains an unqualified provider observation; these
checks do not provide SQLite/Host, PQ-release or whole-workspace runtime acceptance.

Use the reproduction sequence below at `dd10f0ae` for the current fifteen-arm
source, with a new output directory and the same explicit model source/bundle.
`reproduction.json` contains the actual current native argv and derived seed;
`reproduction-v1.json` retains the historical argv. New entropy or a new timestamped
freeze changes the mathematical stream. A stored derived seed reproduces the
native stream, but timings do not reproduce exactly and replaying the external
seed alone does not recreate the original time-bound Mode-A journal.

## Historical v1 source and input scope

| Identity | Value |
| --- | --- |
| Executed local source commit | `57b3968753b1d4ae0f6b98e1c7ce8f288e700a97` |
| Executed source tree | `4240037a0901e70ef05e9edbc17641ee1382ae1f` |
| Public source anchor preserving that tree | `96ae5fb7d599368366672f97e7401e075a65dd85` |
| Input model/corpus source commit | `dda4cc47362065819e9591f11f713933e7a853bf` |
| Input model artifact | `88f1ec69fbc2f5aa68661f63a10bff431123bc3229184426a9d37a1438bfd91f` |
| Input evaluation bundle | `49b71ce23df8fc1d938e36df6ddb66d179852cca97c98e8df75335effc78b1f6` |
| Primary derived native seed | `4a43620dc873245eddb9143f74db4dcff0a5a6c9c89f04e9a698ea56f66b86cf` |

The local execution commit is an observation identity, not a claim that the same
commit object exists on GitHub. The [public source anchor](https://github.com/TrillionniumFoundation/Trillionnium-Chain/tree/96ae5fb7d599368366672f97e7401e075a65dd85)
is a separate publication commit with exactly the executed tree; publication
does not constitute another execution or measurement.
The clean primary source manifest, all 134 tracked input hashes in that
manifest, and native executable bytes were unchanged across the run. Frozen
input copies were individually checked against generated task, A/B and material
hashes. Read-only file permissions are not an adversarial immutability claim.

The workload is an existing trained integer source-routing model: one batch of
64 source-derived requests, 257 input coordinates, base/router/three expert
delta operators, and five complete 64-by-64 W1 tiles. It is not a production
Hepta LLM or an independently administered future-demand benchmark. All 257
coordinates are consumed; padding and unselected-expert work are recorded rather
than credited as useful demand. Ordinary cached selected-expert arithmetic is
98,688 multiply-adds, all five model operators require 246,720, and the five
padded W1 products contain 1,310,720.

Results below belong to this frozen source tree. This Mode A implementation
admits its fixed W1 profile only. Separate or later grouped/low-rank/request
prototypes are outside this experiment; this report neither denies their
existence nor grants them its cost observations or a security qualification.

## Historical v1 fixed-attempt census

The primary campaign used 14 existing legal producers, nine synthetic material
classes, the five actual model tiles, two targets, eight samples, 64 attempts per
cell and a reuse horizon of 16. Targets are the exact 256-bit values beginning
`7f` and `07` followed by 31 `ff` bytes. The synthetic classes cover periodic
dense, full-rank field, all-zero, identity, rank-one, sparse diagonal, continuity,
left-zero/right-rank-one and right-zero/left-rank-one materials. Arms include
lazy FullLimb, generic/structured prepared, classical/Strassen tiled, paired,
blocked-zero, one-zero and maintenance producers plus the original scalar.

Unsupported construction is an explicitly measured refusal, with no fallback.
Arm order rotates by sample. A hit never stops this census. Every hit is checked
by the complete native and separate scalar verifier, and every applicable arm
must yield the same trace/ticket stream for the same input and challenge.

| Primary census item | Observed count |
| --- | ---: |
| Complete cells | 1,584 |
| Unsupported cells | 1,552 |
| Failed cells | 0 |
| Completed attempts | 101,376 |
| Native and scalar verified hits | 26,555 |
| Losing attempts | 74,821 |
| Actually closed and destroyed epochs | 6,336 |
| Setup calls including unsupported constructors | 7,888 |

Every complete cell has four actual epochs, each used for 16 attempts and then
destroyed, with boundaries `[16,32,48,64]`. These counts were checked against the
reported lifetimes and boundaries, not inferred solely from the requested
horizon. Unsupported constructors have no completed reuse epoch. The separate
five Mode A searches below are excluded from this census.

The 26,555 hits are execution records, not additive chain weight. Repeated arms,
targets, cached results, packaging and branches cannot be summed into new
accepted opportunities. The v2 work identity excludes trace and proof bytes.
The two census targets intentionally share a mathematical challenge stream;
cross-target arithmetic reuse is therefore explicit.

### Calibration and fixed component budgets

Only samples 0 and 1 select an arm by total producer CPU, with a fixed tie order.
Samples 2 through 7 evaluate that frozen choice. All 28 selections use that
split. All ten actual-tile/target selections chose `lazy-full-limb`. All-zero
selected `blocked-zero` under both targets.

Unfavorable held-out outcomes remain in the report:

| Synthetic class / target | Selected arm | Evaluation producer CPU ms | Lazy FullLimb CPU ms | Baseline / selected |
| --- | --- | ---: | ---: | ---: |
| periodic-dense / 0 | prepared-generic | 154.156782 | 143.219311 | 0.929050 |
| sparse-diagonal / 1 | prepared-structured | 156.198863 | 134.783991 | 0.862900 |
| zero / 0 | blocked-zero | 128.358173 | 142.882201 | 1.113152 |
| zero / 1 | blocked-zero | 126.086665 | 135.898178 | 1.077816 |

An observed legal improvement is available to honest implementations too; it is
not itself an adversarial security advantage. Calibration did not identify the
best held-out implementation in the first two rows, and those rows were not
reselected or dropped.

Fixed-budget prefixes count only actually completed and destroyed epochs.
For all-zero, selected/baseline hits across the six evaluation replicates were:

| Per-replicate producer CPU budget | Target 0 selected / baseline | Target 1 selected / baseline |
| --- | ---: | ---: |
| 1 ms | 0 / 0 | 0 / 0 |
| 5 ms | 33 / 0 | 4 / 2 |
| 20 ms | 174 / 144 | 14 / 11 |

These are six separate budgets, with aggregate ceilings of 6, 30 and 120 ms,
respectively, not one miner receiving a single 1/5/20-ms budget. They are
postprocessed observations of component cost at closed epochs; an early-stop
miner was not executed. A zero baseline count makes a ratio undefined. Neither
these counts nor total-throughput ratios estimate the supremum in Gamma(B).
`gamma`, its upper bound and native-branch accepted work remain null.

### Preparation and actual cache lifetime

The following totals use all eight samples of the selected arm, therefore
512 attempts and 32 actual epochs per row. All values are milliseconds.
Actual model rows use `lazy-full-limb`; zero rows use `blocked-zero`.

| Material / target | Setup CPU | Complete producer CPU | Cache lifetime CPU range | Cache lifetime wall range |
| --- | ---: | ---: | ---: | ---: |
| tile 0 / 0 | 9.835230 | 221.535198 | 10.975419–26.139037 | 10.975614–26.139493 |
| tile 1 / 0 | 7.902724 | 192.856111 | 8.074889–27.902154 | 8.075009–27.902664 |
| tile 2 / 0 | 7.940751 | 187.786323 | 9.882081–24.523231 | 9.882224–24.523676 |
| tile 3 / 0 | 7.436588 | 175.462235 | 10.341415–22.656464 | 10.341487–22.656816 |
| tile 4 / 0 | 7.357597 | 194.939063 | 9.755031–26.099673 | 9.755203–26.110590 |
| tile 0 / 1 | 7.437239 | 188.191333 | 4.828753–11.828390 | 4.828833–11.828550 |
| tile 1 / 1 | 8.280263 | 196.451086 | 4.761192–12.351679 | 4.761281–12.351909 |
| tile 2 / 1 | 8.917451 | 201.871274 | 4.908712–10.659519 | 4.908793–10.659637 |
| tile 3 / 1 | 7.820259 | 184.125288 | 4.709545–10.439631 | 4.709623–10.440106 |
| tile 4 / 1 | 8.553541 | 194.412982 | 4.702075–10.853312 | 4.702152–10.853384 |
| zero / 0 | 0.269689 | 169.185519 | 8.888891–20.807435 | 8.889046–20.807709 |
| zero / 1 | 0.249211 | 166.843658 | 5.068360–10.109129 | 5.068444–10.109286 |

The ten actual-tile rows total 320 epochs, 81.481643 ms setup CPU and
1,937.630893 ms producer CPU. The two zero rows total 64 epochs, 0.518900 ms
setup CPU and 336.029177 ms producer CPU. Restricting to the six evaluation
samples gives 240 actual-tile epochs, 61.613233 ms setup and 1,463.821593 ms
producer CPU; zero gives 48 epochs, 0.400676 ms setup and 254.444838 ms producer
CPU. No preparation is divided by unobserved future requests.

Setup is `phase_timing.setup.cpu_ns`. Producer is setup + all attempt work +
proof cleanup + actual destruction. Cache lifetime starts after construction
and ends after destruction; it includes intervening verifier/audit/output work.
It therefore overlaps producer and instrumented clocks and must not be added
to either. Its observed duration is not a pure arithmetic latency.

Across the entire census, all arms and unsupported constructors cost
1,311.895763 ms setup CPU and 50,928.592300 ms producer CPU. Material creation
(2.886310 ms) and identity/rank preparation (8.280166 ms) are separate startup
observations, not silently amortized into selected-arm prefixes.

### Complete observation envelopes

The host was an uncontrolled shared AMD EPYC 9V74 Linux x86-64 environment,
Rust 1.95.0, Python 3.12.14 and NumPy 2.3.5, with OpenBLAS/OMP thread settings
of one. The outer driver receipt observed 96.014625 s wall, 93.970695 s child
user CPU, 2.836838 s child system CPU and a 293,516-KiB high-water RSS. That
outer child accounting includes the driver and waited-for descendants.

The driver-internal continuous scope observed 95.873814 s wall and 8.527137 s
parent-process CPU, excluding interpreter startup/imports/argument parsing and
final summary emission. Its 17 native experiment exchanges observed 88.239212 s
wall and 88.049998 s CPU. Nested process, cell and component clocks are separate
views, never additive. RSS high-water observations are not enforced quotas or
isolated per-task measurements.

## Historical v1 Mode A chronology and useful output

The exact model, tasks, request order, routes, five tile shapes and arithmetic
contracts were reconstructed and frozen before the driver requested OS entropy.
The frozen journal was written and fsynced first. Configuration binds the
first-hit-or-exhaustion rule, five declared searches, one cycle and 4,096 attempts
per search. Normal worst-case capacity is 20,495 events within the configured
32,768-event limit. This is a local chronology observation, not an authenticated
external randomness service.

The primary run completed **six attempts: five hits and one loser**. All five
declared searches terminated, no hit was withheld, and no search was unfinished.
All five proofs passed native verification and independent scalar replay before
recording five primitive tile outcomes. Consuming their products yielded
**one complete 64-request model batch**, equal to the original integer operator,
NumPy route/logit output and scalar predictions. The state machine's five
`unique_application_outcomes` are explicitly tile-level contracts, not five
complete model batches or five independent useful requests.

Pre-freeze material reconstruction/copy/fsync/routes cost 27.328195 ms CPU and
36.879412 ms wall. Registration preparation cost 15.700817 ms CPU; waiting
after freeze was 233.220252 ms wall. The state-machine attempt subtotal was
2.205084 ms CPU, while native preparation, full-search retention, verification,
journal/recovery and process costs are separately retained. This small subtotal
is not a complete budget B. The saved 21-event journal was restored using an
externally retained exact checkpoint and the resulting summary matched.

The Mode A shared-material challenge domain and the fourteen-arm census domain
are distinct. The driver never treats a census hit as a Mode A admission.
Local clocks, owner labels and OS entropy do not establish external ownership,
unpredictability, absence of bias, Sybil resistance or absence of undisclosed
preparation. Primitive outcomes remain separate from native Node chain weight.

## Historical frozen-v1 verifier observation: all nine scenarios

The final native run executes nine scenarios, eight submitted candidates each,
through raw verification, optional negative cache and arithmetic-fact cache:
216 verifier calls. All complete construction trials and losing searches remain
in the denominator. The fixtures here are synthetic matrix proofs, separate
from the actual model workload above.

D is operational preparation plus every completed construction/search trial and
proof clone. It excludes separately measured proof-hex/hash diagnostics. The
table gives CPU in milliseconds; verifier columns exclude their separately
reported cache-owner setup.

| Scenario | Search trials / losers | D CPU | Raw verifier CPU | Negative-cache CPU | Arithmetic-facts CPU |
| --- | ---: | ---: | ---: | ---: | ---: |
| distinct-material-cold | 23 / 15 | 0.893061 | 4.232956 | 4.212025 | 3.566091 |
| exact-retransmission | 5 / 4 | 0.238945 | 3.202370 | 0.676529 | 0.571622 |
| same-input-new-forgeries | 13 / 5 | 0.129875 | 2.953088 | 3.493044 | 0.528678 |
| new-challenge | 23 / 15 | 0.109725 | 3.676367 | 3.388999 | 3.962562 |
| one-slot-eviction | 7 / 5 | 0.151485 | 3.767412 | 3.402988 | 3.369008 |
| owner-restart | 7 / 6 | 0.090916 | 3.636076 | 2.012335 | 1.870687 |
| negative-ttl-expiry | 2 / 1 | 0.082524 | 7.312953 | 3.364261 | 0.569106 |
| legal-cold-warm | 1 / 0 | 0.631210 | 4.000489 | 5.931757 | 0.968201 |
| cheap-malformed | 0 / 0 | 0.082433 | 0.047540 | 0.132516 | 0.047100 |

For completeness, ratios below include cache-owner setup in each receiver's
numerator. They describe these streams and this host, not an optimal attack
cost or universal amplification bound.

| Scenario | Raw / D | Negative incl. setup / D | Facts incl. setup / D | Actual negative / facts arithmetic reuses |
| --- | ---: | ---: | ---: | ---: |
| distinct-material-cold | 4.739829 | 4.717603 | 4.070645 | 0 / 0 |
| exact-retransmission | 13.402122 | 2.839155 | 2.810023 | 7 / 7 |
| same-input-new-forgeries | 22.737925 | 26.902368 | 4.084936 | 0 / 7 |
| new-challenge | 33.505281 | 30.894974 | 36.138583 | 0 / 0 |
| one-slot-eviction | 24.869868 | 22.468225 | 22.245298 | 0 / 0 |
| owner-restart | 39.993796 | 22.173215 | 22.636126 | 4 / 4 |
| negative-ttl-expiry | 88.616075 | 40.783566 | 7.878023 | 0 / 7 |
| legal-cold-warm | 6.337810 | 9.398946 | 1.540625 | 0 / 7 |
| cheap-malformed | 0.576711 | 1.623233 | 0.618514 | 0 / 0 |

Diagnostic-inclusive construction costs remain separately available:
D plus proof-hex/hash recording ranges from 2.650611 to 3.994472 ms among the
eight non-malformed scenarios, and is 3.567414 ms for cheap malformed input.
Those larger nested totals are not substituted for operational attack cost.
TTL expiry includes actual elapsed waiting; owner restart recreates cache owners,
and one-slot eviction causes the measured cold misses.

Exact retransmission benefits from both caches. New challenges and sustained
different-material requests do not get that benefit. New forged traces over
the same input can reuse arithmetic facts but do not hit the full-proof negative
cache. These distinctions are retained rather than summarized as one warm-cache
speedup.

The concrete optional-cache repair performs length, version, zero-target and
canonical-field checks before hashing all 49,188 proof bytes. Tests retain the
original rejection ordering and check zero proof-digest bytes on those cheap
refusals. It does not make the optional cache free on valid traffic: final
`legal-cold-warm` negative-cache/raw verification CPU is **1.482758**
(5.931757 / 4.000489 ms). Both paths still do 4,096 transcript tiles in that
scenario; the negative cache has no successful-proof arithmetic reuse.

Earlier observations are preserved separately:

| Observation | Legal negative-cache/raw CPU | Interpretation |
| --- | ---: | --- |
| verifier-observation-01 | 1.049435 | Earlier executable/observation, retained |
| verifier-observation-02 | 1.245698 | Same final verifier executable, earlier observation |
| verifier-observation-final | 1.482758 | Final report above |

The final observation is not replaced by the most favorable run. Earlier
observations are not pooled across binary identities. The measured valid-traffic
overhead and cheap-malformed wrapper overhead remain costs; the repair only
establishes the intended cheap-check ordering, not a general verifier speedup.
Default public verification and the cache's opt-in status are unchanged.

## Subsequent census harness revision

The tables above remain the frozen fourteen-arm `pon-work-expensive-native-v1`
history. After integrating the independently developed sparse preparation,
the census adds `lazy-full-limb-sparse` as arm fifteen, using
`Task::with_preparation(..., Arithmetic::FullLimb, Preparation::Sparse)`.
The original `lazy-full-limb` arm remains dense and the original fourteen names
retain their list prefix. Both lazy arms still produce complete transcripts
and materialize proof bytes only on target hits.

That extended record schema is `pon-work-expensive-native-v2`; the executable
name and `--work-expensive-v1` CLI selector remain stable. The v2 arm must be
included in a newly frozen comparison because it is a legal implementation
available to honest miners. This revision does not retrofit a sparse-arm result
into the v1 measurements or turn later combined source into the executed tree
identified above. Reproducing the historical tables requires the historical
source anchor; evaluating the extended set requires its own source receipt.

## Reproduction of the historical source and shared inputs

Use an isolated checkout of the published source anchor whose tree equals the
executed tree above, Rust 1.95.0 and Python with NumPy. Keep default Cargo release
settings; do not supply RUSTFLAGS or profile overrides. Fetch the locked
dependencies before the offline build. The following commands produce new
directories outside the checkout; they do not overwrite the original evidence.

~~~sh
bash scripts/project-preflight.sh
PON_REPRO_OUT="$(mktemp -d /tmp/pon-work-expensive-v1.XXXXXX)"
export CARGO_TARGET_DIR="$PON_REPRO_OUT/target"
export OPENBLAS_NUM_THREADS=1
export OMP_NUM_THREADS=1

cargo fetch --locked --manifest-path trillionnium/Cargo.toml
cargo build --offline --locked --release \
  --manifest-path trillionnium/Cargo.toml \
  -p trnm-crypto-primitives --jobs 2 \
  --example pon_work_expensive_v1 --example pon_shared_material_v1

python3 formal/pon-nakamoto-v1/experiments/shared_cell_operator_v1.py \
  --material-only --replay-source \
  --bundle-hash 49b71ce23df8fc1d938e36df6ddb66d179852cca97c98e8df75335effc78b1f6 \
  --out "$PON_REPRO_OUT/material"

python3 scripts/ci/run_work_expensive_campaign_v1.py \
  --native "$CARGO_TARGET_DIR/release/examples/pon_work_expensive_v1" \
  --shared-native "$CARGO_TARGET_DIR/release/examples/pon_shared_material_v1" \
  --material-dir "$PON_REPRO_OUT/material" \
  --out "$PON_REPRO_OUT/campaign" \
  --attempts 64 --samples 8 --reuse 16 --targets 0 1 \
  --calibration-samples 2 --budgets-ns 1000000 5000000 20000000

python3 scripts/ci/run_work_expensive_verifier_v1.py \
  --out "$PON_REPRO_OUT/verifier"
~~~

A fresh Mode A freeze has new observed times and new entropy, so it yields a new
native stream. Reusing only the historical external `--replay-seed` is not exact
stream replay: the derived seed also binds frozen chronology/configuration.
For exact mathematical census replay, use the stored derived seed above, the
exact canonical material, the original flags and the recorded executable.
For example:

~~~sh
"$CARGO_TARGET_DIR/release/examples/pon_work_expensive_v1" \
  --work-expensive-v1 --attempts 64 --samples 8 --reuse 16 --target-index 0 \
  --seed 4a43620dc873245eddb9143f74db4dcff0a5a6c9c89f04e9a698ea56f66b86cf \
  --material "$PON_REPRO_OUT/material/tile-0/material.bin" \
  > "$PON_REPRO_OUT/replayed-tile-0.jsonl"

python3 scripts/pon_work_expensive_reader_v1.py \
  "$PON_REPRO_OUT/replayed-tile-0.jsonl" \
  --out "$PON_REPRO_OUT/replayed-tile-0-reader.json" \
  --calibration-samples 2 --budgets-ns 1000000 5000000 20000000
~~~

Exact chronology replay uses the saved Mode A journal and external checkpoint;
new execution does not reproduce old wall/CPU observations. Source, material
and process boundaries are detailed in [reproduction.json](reproduction.json).
The small git evidence directory carries compact results and hashes; the large
complete JSONL streams remain in their recorded observation directories rather
than being duplicated here. Inspect those streams or regenerate them for a
full row-by-row audit.

### Preserved failure and tooling observations

An initial offline workspace Clippy attempt refused a missing locked
`foreign-types v0.3.2` dependency. That is a dependency/setup failure, not a
successful lint run; the later dependency-complete checks have separate logs.
A first outer timing launch failed because `/usr/bin/time` was absent and did
not execute the campaign. Its stderr is retained separately from the successful
Python process receipt. Development-01 and Development-02 are retained tiny
driver observations, not substitutes for the primary campaign.

Negative tests intentionally reject altered raw evidence: deleted losers,
setup/teardown/epochs, changed costs or work identities, numeric boolean aliases,
duplicate rows, truncated streams and sample-window manipulation. The latest
reader suite has 17 tests, Mode A has 29, and verifier reader controls have 14.
Separate negative source-integrity and workflow tests retain intentional FAIL
receipts as expected negative controls; these are not erased or reclassified
as successful native work. A failed child with parseable output retains its
parsed failed report; process failure and reader rejection are distinct reasons.

## Remaining scientific and operational boundaries

The finite implementation set provides measured cost witnesses. It cannot
establish the cheapest algorithm, a computational lower bound, the supremum
over miner strategies, an expected accepted-vote rate or a confidence bound
over untested hardware/input distributions. Faster legal algorithms belong in
the honest comparison set. Setup and lifetime accounting do not prove hidden
attacker preparation absent.

These exact W1/source-model observations do not qualify adaptive online input
selection, grouped shape/padding freedom, approximation/rounding variants,
large precommit sets, challenge-owner bias, competitive cross-Cell shared
execution or private-fork economics. An independent grouped profile must have
its own relation, chronology and finite cost study. This Mode A prototype does
not admit that separate profile.

Native primitive verification is not Node ancestry/fork-choice admission,
external-beacon authentication, task-origin authority or live reward eligibility.
The chronology log requires an external rollback anchor, and per-actor caps are
not a Sybil defence. No public-chain work value is reported.

Finally, cache component tests do not qualify the complete Node service:
bounded scheduling, CPU/RSS enforcement, fairness between tasks, honest-task
tail latency under sustained distinct invalid inputs, restart/eviction effects
at service scale, network cost and private branches remain separate accepting
owners. The final cache slowdown and cold/churn observations are reasons to
keep those gates open. All hardness, fairness and production activation flags
remain false.

