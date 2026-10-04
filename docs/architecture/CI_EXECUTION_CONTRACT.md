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
