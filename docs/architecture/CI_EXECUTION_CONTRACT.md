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
300-second budget. Each architecture job has a 30-minute cap, and the comparison
has a 10-minute cap. Matrix fail-fast is disabled. Both campaigns are attempted
after a successful build even if the first campaign returns a failure. Timeout,
nonzero status, malformed output and validation failures remain failed observations
with their captured output. Artifact upload and final source checks run on failure.

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
