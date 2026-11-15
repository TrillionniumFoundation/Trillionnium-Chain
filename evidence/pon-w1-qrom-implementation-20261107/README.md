# W1 v2 implementation and conditional QROM observations

Date: 2026-11-07. Result: **MAPPING REPRODUCED / SECURITY HOLD**.

This packet continues `cb114b13bf848a77634e40a08b31b30c7c758e7b`. It preserves
the existing proof, source-snapshot and real-receipt-control evidence. The
[technical review](../../docs/security/W1_QROM_IMPLEMENTATION_MAP_20261107.md)
explains the concrete findings and unresolved proof obligations.

## What the packet contains

- `upstream-sources.json.gz`: fixed selected source bytes from
  `risc0/risc0@8c215e2f4ccdd935f0517bf05d90f1ae032840a9`, with SHA-256, Git blob
  identities and exact source URLs. `RISC0-LICENSE` is the accompanying
  Apache-2.0 license. This is selected source, not a complete SDK archive.
- `implementation-map.json`: independently reconstructed 27-program control
  tree and parameter digest, fixed historical v2 public bindings, exact seal
  geometry, dependency selections, input identities and unresolved obligations.
- `transcript-source-review.json`: the independently reviewed native
  commit/challenge order, Merkle auxiliary parameters, RNG sampling and
  grinding scope. Reproducible geometry is also part of the implementation map.
- `theorem-review.json`: exact reviewed manuscript date, selected formal
  statements, latest-version retrieval limitation, and corrected literature
  roles.
- `conditional-unknown.json`, `conditional-example-384.json` and
  `conditional-example-256.json`: unknown and wholly hypothetical theorem
  component calculations. The examples are not this project's security
  parameters, a combined theorem application, or an attack estimate.
- `validation.json`, `validation/` and `file-manifest.json`: actual local
  commands, logs, successful checks, failed attempts and file identities.

## Reproduce the mapping

Use Python 3.11 or newer in the exact checked-out candidate. The audit imports
only the standard library and needs no Rust build or network access. It reads
the fixed historical v2 fixtures already tracked in the repository.

```bash
bash scripts/project-preflight.sh --audit
python3 scripts/w1_qrom_implementation_audit.py --output /tmp/w1-qrom-map.json
python3 scripts/w1_qrom_conditional_budget.py > /tmp/w1-qrom-unknown.json
python3 scripts/w1_qrom_conditional_budget.py --example > /tmp/w1-qrom-example.json
python3 -m unittest discover -s scripts/ci -p 'test_w1_control_tree_audit.py' -v
python3 -m unittest discover -s scripts/ci -p 'test_w1_fri_transcript_audit.py' -v
python3 -m unittest discover -s scripts/ci -p 'test_w1_qrom_implementation_audit.py' -v
python3 -m unittest discover -s scripts/ci -p 'test_w1_qrom_conditional_budget.py' -v
python3 -m unittest discover -s scripts/ci -p 'test_w1_qrom_workflow_gate.py' -v
```

The implementation output is create-only; choose a fresh output path on a
second run. The [CI workflow](../../.github/workflows/pon-w1-qrom-implementation.yml)
requires the exact registered and executed names in the
[fixed test roster](../../config/pon/w1-qrom-required-tests-v1.json), preserves
all outcomes and verifies source identity both before and after execution.

## Scope of the observations

The saved v2 outer seal has raw `po2=18`, 55,667 canonical base-field words,
three FRI folding rounds and the exact geometry `4717 + 50 * 1019 = 55667`.
The default lift-name maximum is 22; the generic parser's explicit maximum is
24. These are different facts. The set of all feasible accepting recursive
trace sizes is not proved here.

The control root and all 27 named inclusion paths are independently recomputed.
This does not reconstruct every generated program from bytecode or prove its
relation, compiler correctness or RBR knowledge soundness. Receipt metadata
and public input reconstruction are not a new STARK verification or a fresh
native work replay. Existing original positive and negative receipt controls
remain separate evidence.

Every project quantum security-bit count is null. Full Theorem 11.3, recursive
Theorem 10.6 composition, the concrete shared-hash/sponge quantum model and the
system-lifetime budget remain unresolved. No complete W1 attack is established
by a conditional expression exceeding a target. No production, consensus,
quantum-work or authorization qualification is granted by this packet.

## Validation record

The final local W1 discovery run passed **209 tests**: the 128 retained controls
and 81 new controls. The new roster consists of 28 control-tree, 13 conditional
budget, 19 implementation, seven transcript and 14 CI-gate tests. Separately,
43 source-integrity controls, 104 existing CI-contract tests, Rust formatting,
and the repository check passed. The latter covered 26 packages, 1,275 Rust
source files and 3,601 local Markdown links on the recorded candidate worktree.

The actual six non-source workflow stages were also executed from the final
workflow text. All 81 registered/started/successful IDs matched, with no skips,
and the 14 recorded execution-input files had identical before/after hashes.
This is a local stage trial, not hosted head/merge CI or a complete local
tracked-source check.

Independent review found and repaired two defects in the new CI draft before
publication: a `load_tests()` hook could exit successfully without producing a
completion record, and incomplete or incorrect budget reports could pass a
scope-only check. The final status now independently validates the named
completion record, while the budget gate fixes field sets and independently
recomputes exact component fractions. Ordinary import-time `SystemExit(0)`
was already rejected by unittest; the retained probes explicitly distinguish
it from the actual `load_tests()` case. A bounded deeply nested JSON input also
now receives a structured calculator rejection instead of an uncaught traceback.

Locked Cargo metadata, native Rust tests and strict Clippy did not complete:
the offline dependency cache lacked `nix` for the chain and `bincode` for the
v2 verifier. The initial Clippy invocation also selected an incomplete rustup
environment; the corrected invocation reached the dependency failure. No Rust
source or lockfile is changed by this continuation. Initial Python attempts
with missing historical fixtures, the later successful replays, and every
Rust failure are retained independently.

The source recovery verified all newly inspected inputs, but 29 large older
binary archive fragments remained unavailable locally. Empty connector
responses were rejected by their Git blob identities and never substituted
for those archives. The repository/link check passed after restoring the
other historical inputs; the complete tracked-source identity still requires
the hosted checkout. This limitation does not relax either CI source gate.

The machine-readable record distinguishes these local successes, environment
blocks and hosted CI. `validation/raw-observations.tar.gz` preserves complete
logs, failed probes and prior local trials; `validation/index.json` identifies
every member. The evidence manifest binds the actual scripts and outputs.
Hosted jobs must be read back for the exact published candidate; local results
do not stand in for those jobs.
