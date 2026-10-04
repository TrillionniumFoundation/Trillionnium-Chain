# Head, prospective merge and security execution

The existing five required check names remain unchanged. Their source is the exact
pull-request head (or the exact pushed main commit). A separate PR-only
`prospective-merge` matrix runs the same five lane commands on the event's synthetic
merge commit. Before and after execution, the identity checker verifies a clean
checkout and ordered parents equal to the event's exact base and candidate.
An old base is never reported as the current base; a later base change needs a new
corresponding merge run. These jobs change no repository protections or approvals.

All jobs use ephemeral hosted runners, read-only repository permissions and a
credential-free checkout. Tool installations and output directories are isolated
after runner allocation. Source observations are retained on success and failure.
The source checker validates the workflow wiring, while the hosted lanes execute
the actual tests. A source-check result cannot stand in for a lane outcome.

The same workflow also runs two exact-head `cross-arch-cost` jobs and one
`cross-arch-cost-consistency` job. These three jobs do not rename, replace or add
branch-protection requirements to the original five head and five merge checks.

## Tracked-byte source identity

`verify_ci_source.py` checks the actual tracked worktree against the raw committed
Git tree, including blob bytes, executable modes and symlink target bytes. It does
not accept cached `git status` as evidence that a compiler read those bytes. Both
head and prospective-merge jobs run this guard before and after their lane.

The guard disables object replacement during object reads and rejects replacement
refs, graft files, assume-unchanged and skip-worktree entries. It explicitly asks
for all untracked entries even when local Git configuration suppresses their
display. Every supported tracked blob is read through no-follow Unix directory
and file descriptors, streamed with the committed length, and checked for path or
file changes during hashing. A directory-symlink substitution or nonregular file
is refused without reading an external tree or waiting on a FIFO. Submodules need
a separate recursive source contract and are refused rather than skipped.

The source receipt adds `tracked_worktree_verified`, `tracked_entries` and
`tracked_bytes` to the existing observation schema. Fuzz and supply-chain receipts
reuse the same predicate through `ci_observation.source`; a hidden source change
is retained as `dirty-candidate` with a verification error, not `committed-clean`.
The existing `test_ci_execution.py` entry point imports the raw-worktree regressions,
so they run in both required repository-truth lanes. Real Git fixtures reproduce
hidden index flags, suppressed untracked files, mode changes and replacement
commits; a separate controlled status result proves the byte-hash path is necessary.

These are Unix checkout snapshots, not continuous execution attestation. They do
not certify ignored/generated output, tool binaries, symlink referents, dependencies
or code modified and restored between guards. Existing isolated tool/output,
lockfile, executable-hash and execution checks remain necessary. Protocol bytes,
production flags, required check names and repository protections are unchanged.

## Native x64 and ARM64 repeated-search costs

The cost matrix actually builds and executes `pon_reused_cost` on
`ubuntu-24.04` (x64) and `ubuntu-24.04-arm` (ARM64), using Rust 1.95.0, a locked
release build and the native target triple. GitHub's
[official hosted-runner reference](https://docs.github.com/en/actions/reference/runners/github-hosted-runners)
lists both labels for public repositories; the labels were checked on 2026-10-04.
The workflow uses explicit labels, not a floating `-latest` architecture alias.
The same-run artifact download is pinned to
[download-artifact v5's verified commit](https://github.com/actions/download-artifact/tree/634f93cb2916e3fdff6788551b99b062d0335ce0),
with separate directories so that one architecture cannot overwrite the other.

`scripts/ci/run_cross_arch_cost.py` retains the actual uname and `/proc/cpuinfo`,
verbose rustc and Cargo versions, runner/run/attempt context, exact commands and
return codes, separate complete stdout and stderr, source snapshots before and
after, input hashes, the actual measured executable and its ELF architecture and
before/after SHA-256. Compiler/target/profile environment overrides are refused.
A matrix label by itself is insufficient: observed uname, rustc host, runner
architecture and the retained native ELF must agree. No emulator is invoked.

Each architecture executes both fixed campaigns:

| Campaign | Samples per material and target | Searches per cohort | Attempts per search | Seed |
| --- | ---: | ---: | ---: | ---: |
| 0 | 4 | 4 | 64 | 0 |
| 1 | 2 | 4 | 8 | 1 |

The release build has a 900-second subprocess budget; each campaign has a
300-second budget. Each architecture job has a 135-minute cap, and the comparison
has a 10-minute cap. Matrix fail-fast is disabled. Both campaigns are attempted
after a successful build even if the first campaign returns a failure. Timeout,
nonzero status, malformed output and validation failures remain failed observations
with their captured output. Artifact upload and final source checks run on failure.
The architecture cap covers four separate suites. Each has up to 900 seconds of
build, 600 seconds of campaigns and 90 seconds of identity commands. Each of those
six commands also receives five seconds of termination grace. The complete bounded
capture allowance is therefore `4 * (900 + 600 + 90 + 6 * 5) = 6480` seconds, or
108 minutes. The remaining 27 minutes are reserved for checkout, compiler setup,
source guards, raw-file hashing/copying and artifact handling. The runner and
artifact checker share explicit capture-budget constants; the CI contract checks
their sum against the workflow cap and its overhead allowance. A former 90-minute
cap cannot cover all four suites' bounded failure paths and is rejected. The
27-minute margin is an engineering allowance, not a bound on external downloads.
These caps are execution limits, not measured performance or a promised completion
time. Runner loss or platform-forced termination remains outside the subprocess
capture guarantee.

The native schema is `pon-w1-reused-search-v1`. Its seven explicit diagnostic
materials include rank-checked full-field matrices, the existing structured cases,
and the exact continuity-maintenance fixture. Both target bytes, seeds, samples
and challenge order are identical across architectures. Scalar, generic prepared,
structured prepared, tiled classical and one-level Strassen producers each run in
two modes: prepare once per search, or prepare once and reuse for all searches in
the cohort. Actual setup observations remain an array: zero for scalar, four for
cold prepared searches, one for reused prepared searches. Unsupported structured
inputs retain their actual preparation costs and explicit unsupported outcomes.

Every requested search retains its attempt count, success/exhaustion/unsupported
outcome, complete attempted-ticket and complete-proof stream commitments, winning
challenge/proof commitment when present, and both verifier timings/order. The
native program compares full winning proof bytes and complete attempted streams
between supported implementations and runs both exact verifiers on winners.
Strategy/mode order rotates with the sample and verifier order alternates with
sample plus search index. Setup, all target misses and common challenge/stream
hashing are included; material generation, rank checks and comparison are excluded.
Verification is measured separately after generation. Nanosecond values are
monotonic wall-clock observations, not process CPU accounting.

`scripts/ci/check_cross_arch_cost.py` independently binds fixed material task/rank
identities and winning challenges, checks the complete cohort/search grid and
setup/search sums, replays retained file hashes and source/compiler/binary bindings,
then compares deterministic projections from both actual current-run artifacts.
The projection removes only measured clock values; setup counts, outcomes and all
stream commitments remain. A missing architecture, earlier attempt, changed source,
changed output or producer mismatch fails. A slower producer, reversed speed ratio,
target-budget exhaustion or honestly unsupported optimization is not a failure.
No expected speedup or mining-to-verification ratio is an acceptance condition.
Both repository-truth lanes execute negative tests for these distinctions.

All native artifact schemas require the exact successful capture shape. A
manifest or campaign containing an `error` field, or a command containing a
`launch_error` field, is refused even when that field is null or empty: the real
runner emits those fields only on failed paths. Command exits must be integer
zero, timeouts must be boolean false, and elapsed clocks must be nonnegative
integers; Python's boolean/integer equality cannot supply execution evidence.
The reused checker also retains the native material/target/sample/invocation
array order documented by the producer, in addition to checking every paired
grid position. These checks do not change any native schema, transform old
receipts, or discard their original output. Parser fixtures exercise rejection
only; independently replaying an old hosted artifact remains an observation of
that old source and run.

This is one hosted cost campaign within the existing CI authority. Its manifests
and comparison result do not grant protocol, hardware or release acceptance.
GitHub's two virtual-machine runner types do not establish independent physical
operators, dedicated hardware isolation, GPU coverage or resource fairness. CPU,
compiler, virtualization and scheduling differences all affect the measurements;
an observed difference between machines cannot be attributed to ISA alone. Actual
outcomes belong to their exact run, source, binary and input stream, and must be
collected after execution before any current result is reported.

For a native local preflight after committing source, use
`python3 scripts/ci/run_cross_arch_cost.py --arch x64 --local` (or `arm64` on that
actual host), with fresh isolated Cargo target and receipt paths. This runs the
same bounded program and labels its context `local-native-preflight`. The hosted
artifact checker explicitly refuses that context; setting runner-like environment
names is not the local execution interface.

### Separate zero-material locality suite

The same two architecture jobs also invoke `run_cross_arch_cost.py` with
`--suite zero-locality`. It builds and executes the separate `pon_zero_locality_cost`
example under `pon-w1-zero-locality-v1`, retaining its own raw files and manifest.
The same comparison job checks that suite separately. The old seven-material
reused-search schema, artifact and comparison keep their original interpretation;
the workflow still has thirteen jobs. Both fixed campaigns above run for the exact
zero task, with three producers and two real setup modes. All six producer/mode
positions are present at each target/sample, with starting order rotated by sample.

The dedicated zero checker binds its independent challenge/stream domains, exact
strategy/mode grid, canonical zero task, every search outcome and setup call, timing
sums, winning challenge/proof commitments and complete attempted streams. Unsupported
rows cannot replace one of these three zero-capable producers. Cross-architecture
comparison removes only clocks; it cannot discard exhausted or slower observations.
There is no speed threshold, work qualification or permission to compare absolute
timings against the different old harness schema. Original failed output remains
retained even when the later separate suite executes successfully.

### Separate one-zero/rank-one locality suite

The same architecture jobs then invoke `--suite one-zero-locality`, including
after either preceding suite failed. The comparison likewise runs in its own
always-executed step and writes a separate result. The workflow still has thirteen
jobs for a PR event. This suite owns `pon_one_zero_locality_cost`, raw schema
`pon-w1-one-zero-locality-v1`, artifact directory
`cross-arch-one-zero-locality-cost` and separate execution/comparison schemas.
The two preceding suites retain their original schemas and interpretation.

Its complete grid contains two synthetic matrix pairs: one zero left matrix with
rank-one right matrix, then the reverse. The nonzero matrix has entries
`M[i,j] = (i+1)*(j+3)` for zero-based indices 0 through 63; both exact task digests and
asymmetric ranks are independently encoded and bound by the Python checker.
Both fixed campaigns run generic prepared, structural zero-product and blocked
one-zero/rank-one full-transcript producers, each in cold and reused modes.
There are 96 and 48 cohorts per architecture for campaigns 0 and 1, respectively,
with four retained searches per cohort. The scope flag stays
`one_zero_rank_one_structure_only: true`.

The new challenge domain is `one-zero-locality-cost-v1`. The native program uses
separate ticket/proof-stream and winner-commitment domains and retains complete
proof/ticket stream equality across all six producer/mode positions. The checker
binds the challenge stream, material order, exact method names, full-proof length,
setup counts, every winner and exhaustion, both verifier timings/order and all
timing sums. Unsupported rows cannot replace one of these required capable
constructors. Raw/source/executable hashes and unchanged source identities are
checked through the same strict successful receipt contract. The new negative
suite runs once in both repository-truth lanes and tests schema substitutions,
swapped zero sides, task/rank changes, missing searches, unrecorded setup, old
challenge domains, output changes and cross-architecture stream disagreement.

These are two fixed synthetic materials with unchanged W1 proof bytes. They do
not qualify arbitrary one-sided-zero matrices, general low-rank tasks, model
inputs, maintenance cost, fastest-adversary cost or hardness. No relative speed
threshold is applied; slower and fully exhausted runs remain valid measured
observations, and a native failure retains its own error and raw output.

### Fixed maintenance producer and preparation suite

The same architecture jobs finally execute `--suite maintenance-paired` in a
separate always-executed step; the comparison job checks its own retained artifact
after the earlier comparisons even when one has failed. There are still thirteen
jobs for a PR event. This fourth suite owns `pon_maintenance_cost`, current raw
schema `pon-w1-maintenance-preprocessing-v2`, artifact directory
`cross-arch-maintenance-cost`, and separate
`trnm-cross-arch-maintenance-cost-execution-v2` and
`trnm-cross-arch-maintenance-cost-comparison-v2` schemas. The preceding three raw
schemas and challenge streams remain separate and cannot be substituted.
Historical four-strategy `pon-w1-maintenance-paired-v1` artifacts retain their
original execution/comparison-v1 identities. Read-only artifact comparison can
select them explicitly with `--maintenance-version 1`; the current runner and
default comparator select version2 and cannot accept a v1 artifact as that run.

This experiment uses the fixed public genesis-policy material of
`consensus-maintenance-continuity-dev-v1`: flattened matrix entries are
`A[i] = (13*i + 17) % 257` and `B[i] = (29*i + 31) % 263`, for `0 <= i < 4096`.
The exact task digest is
`c982eea0545c228d0bf48d6d06e623020b4031f2ba79da56cc6bdccde2c63496`.
Python separately encodes those matrices and independently computes their ranks,
56 and 32, over the W1 field. The report keeps
`genesis_maintenance_material_only: true`, its exact task profile, and
`input_source: genesis-policy-public-deterministic-fixture`. These labels establish
which deterministic bytes were studied; they do not establish task utility,
resource fairness, an independent input provider or a lowest possible cost.

Both fixed campaigns run generic prepared, tiled classical, one-level Strassen,
paired-product and `maintenance-periodic-setup` complete producers in both cold
and reused modes. The periodic constructor checks both exact policy operands and
computes their actual fixed product with row-prefix and sawtooth suffix sums;
its per-challenge work is the ordinary complete transcript. All validation, plan,
sum, product and proof-prefix construction inside each setup call is timed.
The campaigns require 80 and 40 cohorts respectively, each retaining four searches,
for 120 cohorts and 480 searches per architecture. Adjacent samples use the same rotated
sequence forwards and backwards: with emitted offset `0..9`, the selected arm is
`(sample // 2 + (offset if sample is even else 9-offset)) % 10`. Thus each arm's
positions sum to nine in every complete sample pair, including the two/four-sample
campaigns. This balances mean invocation position before measurement; it does not
isolate CPU scheduling, caches, thermal effects or supply independent random tasks.

The challenge tag is `maintenance-paired-cost-v1`; the native program also has
separate complete ticket/proof-stream and winner-commitment domains. These retain
their original v1 bytes to preserve the identity of the deterministic searches;
the expanded strategy grid still requires the explicit v2 experiment schema. Every target
miss, exhausted budget, constructor call and full proof stream is retained. The
current checker requires the exact task/profile, all ten invocation positions,
complete 49,188-byte certificate length, identical attempted streams across all
five producers and both modes, the full deterministic winning challenge, both
post-generation verifier timings and all setup/search sums. Unsupported is not a
successful result for one of these five required constructors. It preserves the
same strict source, native ELF, command, failure and original-file hash contracts.

`test_maintenance_cost.py` runs once in both repository-truth lanes. Its synthetic
parser fixtures exercise cross-suite substitution and explicit v1/v2 identities,
wrong challenge domains,
material/rank/profile changes, reordered or missing searches, omitted preparation,
fabricated exhausted winners, hidden command failures, stale attempts, original
file changes and cross-architecture stream disagreement. The tests separately
verify balanced sample-pair positions and the fixed material's bytes and ranks.
Fixture clocks and ELF header stubs are not measured evidence. A slower
producer arm or an all-exhausted campaign remains a valid finite observation;
no speed threshold or mining-to-verification ratio grants acceptance.

## Independent native transition and model observations

`protocol-contract` builds the bounded M06 continuity transition example and supplies
its actual absolute executable to `test_continuity_transitions.py`. Python constructs
the small input states and expected complete state/root/receipt/capacity rows; Rust
performs actual execution. The old continuity vector bridge still runs. Absence of a
binary or a full required row is a failure, not a skip or an imported historical pass.

The same release build also supplies `pon_paired_io` to `test_paired_work.py`.
The existing independent Python W1 oracle constructs complete expected proofs;
the test compares all 49,188 bytes against actual native output for 20
canonical input/challenge cases and checks 18 length, field, argument or
unsupported-material rejections. Eight successful cases use the fixed
genesis-maintenance material: four through the ordinary paired selector and four
through the explicit `maintenance-periodic` selector. Its successor report schema
is `pon-w1-paired-maintenance-python-native-v2`; all 38 native invocations and their
original observations are required. Earlier 22-invocation receipts remain historical.
Each invocation retains its actual input, Python proof where applicable, original
native stdout/stderr and status under a fresh current-lane `paired-work` directory.
Missing binary/output selectors fail explicitly. This comparison is separate from
the cost suite's full-stream commitments and does not measure hardware costs or
prove irreducible work.

`test_model_window_history.py` also executes once in `protocol-contract`. Its
model-window history and evidence consistency checks do not grant future model
utility or change consensus weight. The sole development plan documents its exact
scope and remaining external acceptance requirements.

After its existing Node release example build, `protocol-contract` runs the pure
`test_account_archive_oracle.py` checks and then
`scripts/ci/run_account_archive_conformance.py`. The latter executes the actual
`account_archive_vectors` program with a fresh `account-archive/native` output and
a separate fresh sibling `account-archive/native-working` directory. The latter
retains the original working archive, its SQLite sidecars and the native Node
store. SQLite `VACUUM main INTO ?1` creates the standalone export; the export
directory contains exactly `archive.sqlite`, `observation.json` and
`finalization.json`. The snapshot receipt records the actual SQL operation,
read-only export opening and DELETE journal mode, page counts, header, close and
sidecar observations. The runner then invokes the separate Python oracle with
explicit export JSON/database paths.
Python does not execute native recovery again or use the native status label as
the expected root; it independently recomputes the account/root/witness relation
and reads the closed database. The runner verifies native JSON/database identity,
the complete six-snapshot/thirteen-query/seventeen-operation small fixture, exact
scope, and that every standalone export byte remains unchanged by the oracle.
After its final source and executable checks, it enumerates all retained files
and requires the complete three-file export map to match the original map before
assigning success. A late export sidecar, missing file or changed hash is failure.
Working-file maps before and after the oracle and at final retention remain
separate observations; their changes are recorded without claiming working-file
immutability or treating them as changes to the standalone oracle input.

Both native generation and independent checking have a separate 300-second
capture budget. Missing executable, earlier-source input, partial output, original
export-file changes or an oracle failure remain failed observations with original output.
The actual prebuilt executable, its before/after hashes, exact source guards and
all retained-file hashes remain in the CI artifact. Pure receipt-shape fixtures
exercise refusal only. This small conformance set establishes no large-account
acceptance, consensus-capacity change or public data availability. The separate
65,537-account research fixture and its independent replay, when run, retain their
own source-bound observations and are not inferred from these CI results.

The same `protocol-contract` lane then runs the pure
`test_account_execution_oracle.py -v` suite and
`scripts/ci/run_account_execution_conformance.py`. The existing Node release build
supplies `account_execution_vectors`; no second workspace test execution or new
job is introduced. Its separate `account-execution` artifact requires the complete
43-packet/20-signed-transaction fixture, two native reorganizations, three reopens
and 29 original negative cases. The research wrapper requires full State and one
worker with exact parent-proof account-access coverage; it grants no ordinary
Node admission or archive publication capability.

The native observation schema is `pon-account-execution-native-observation-v1`;
the independent JSON report is `pon-account-execution-oracle-observation-v1`.
Python derives the exact genesis and the supported tag1–5/10/11 signed application
transitions, full State/account roots and witness coverage, then compares the
native States, receipts, errors and recorded branch/reopen identities. It does
not reexecute W1, difficulty, fork choice, native recovery or SQLite operations.
The existing full SQLite archive oracle remains a separate observation scope.

The new wrapper's `trnm-account-execution-conformance-execution-v1` receipt keeps
`oracle_reads_sqlite=false` and `sqlite_rows_independently_checked=false`. Native
generation and JSON checking each have their own 300-second capture budget.
The fresh `native` directory contains exactly `observation.json`, `archive.sqlite`
and `finalization.json`, using the existing standalone snapshot helper; the source
archive, original Node and their sidecars remain under `native-working`. The
wrapper checks the actual export header/page geometry and complete receipt without
opening SQL, and requires every export byte and the exact file inventory to remain
unchanged through final retention. Working-file maps remain separate observations.
All actual native sources/configurations, Python imports and wrapper inputs,
source guards, executable identity, Python dependency identity, commands and
failures are retained. Success is assigned only after final source, binary and
export checks. `test_run_account_execution_conformance.py` executes receipt-shape
and raw-file refusal fixtures in both repository-truth lanes; these synthetic
checks are never labelled native account execution evidence.

`rust-baseline` creates a fresh exclusive `model-composition` directory under its
current receipt and a unique run identifier in a subshell. Its existing single full
workspace all-targets/all-features test execution exports exactly thirteen native
model observation files. Immediately afterwards, the two Python suites recompute
integer model arithmetic, inference, complete records, parent lineage, allocation
and payouts from those observations. The export environment ends with that subshell,
before documentation tests and Clippy. It neither repeats the two long native chains
nor allows later checks to overwrite or supplement the observation set.

The source contract and negative tests reject removed commands, `true` substitutions,
wrong lanes/order, absent native selectors, reused directories, environment leakage
and duplicate or skipped workspace tests. These checks establish executable wiring
only; actual lane output must separately show the required native observations and
successful independent comparisons. Neither oracle establishes work hardness, full
independent ledger verification or future model efficacy.

## Mixed public-service execution

`protocol-contract` runs the source-bound
[V3 local service campaign](../protocol/pon-nakamoto-v1/details/PUBLIC_V3_SERVICE_CAMPAIGN.md)
and its strict report validator and negative checks. Its retained observation includes
every request outcome, honest-service gaps, native work counters, submitted packet
bytes and both closed owner stores across the local server/owner restart. The same
command runs in the head and prospective-merge lanes. The finite development target
does not qualify independent public operators, WAN service or resource fairness.

## Actual fuzz execution

`fuzz-smoke` retains its negative/regression tests and additionally runs the two
[libFuzzer targets](../../tests/fuzz/README.md) with pinned cargo-fuzz, a dated nightly,
ASan, real mutation feedback, fixed duration and retained raw outputs. Its independent
lockfile is checked against every shared dependency version in the normal workspace.
The routine CI budget is finite and does not establish exhaustive parser or work security.
The runner records sanitizer environment overrides and executable hashes. A local
container that blocks LeakSanitizer's process inspection must report that failed
attempt. An explicitly separate local run using `ASAN_OPTIONS=detect_leaks=0` tests
address safety and mutation feedback only; it does not establish leak safety or
replace the hosted lane, whose sanitizer settings remain at their defaults.

## Actual Rust supply-chain execution

`rust-baseline` additionally runs `scripts/ci/run_supply_chain.py` with pinned
cargo-deny. It checks the real locked normal workspace and the isolated fuzz graph,
including development dependencies and all features, against the existing advisory,
license, ban and source policy. No finding is automatically ignored or downgraded.

The runner fetches RustSec into the isolated Cargo directory, records its actual
commit, tree and timestamp, and archives that exact advisory tree. The subsequent
checks are frozen: they cannot update the recorded database or either lockfile.
Raw JSON diagnostics, actual command/exit status and artifact hashes remain in the
receipt, including a nonzero refusal. Both graph checks run even if the first is
denied. A tooling or database-fetch failure is also a failed observation.

This gate reports the tested Rust dependency graphs and recorded database. Python
conformance dependencies retain their separately pinned requirements and recorded
environment; this Rust gate does not claim to audit PyPI, operating-system packages
or advisories published after the recorded database. Current findings require a
dependency repair and rerun, not an acceptance flag or an unreviewed ignore entry.

For a local run, first install the pinned auditor with
`bash scripts/ci/install_ci_tools.sh supply-chain`, then execute
`python3 scripts/ci/run_supply_chain.py` with isolated Cargo/tool paths and a fresh
`TRNM_CI_RECEIPT_DIR`. Inspect the manifest, JSON diagnostics and archived advisory
tree together. Current hosted results remain associated with their exact source,
base, binaries and inputs; no local receipt is relabelled as hosted execution.

Primary references: [cargo-deny command options](https://embarkstudios.github.io/cargo-deny/cli/common.html),
[check categories](https://embarkstudios.github.io/cargo-deny/checks/index.html),
[0.20.2 release](https://github.com/EmbarkStudios/cargo-deny/releases/tag/0.20.2).

## Current implementation navigation

[Current implementation and profiles](CURRENT_IMPLEMENTATION.md) is generated from
the existing source, maturity, applicability and consensus registries. It is checked
for exact regeneration and has no independent status fields. Update the original
owner registry and regenerate the view; do not add a second progress ledger.
