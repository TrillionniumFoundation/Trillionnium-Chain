# Local frozen-input continuation, 2026-11-03

Base: `cca911b47731c9c6f6b61e39758ca3ad17a33555`, verified against the existing
`feature/chain-m02-branch-core` remote before work. The older local checkout at
`df67501f` was not modified. This continuation fixes a real source-check blocker:
the owner-cleared root README is zero bytes, while the checker accepted only one
newline. Both empty representations now pass; content, spaces and extra blank
lines still fail. The root README itself remains unchanged. New positive and
negative cases prevent the entire mutant suite from passing behind this unrelated
precondition failure. The original 57-pass/1-error log remains in this directory.

## Executed results

- Repository boundary and Markdown/source checker: PASS.
- `repository-truth`: 60 repository tests and 12 invariant-registry tests PASS.
- Frozen evaluation/settlement counterexamples: 37 PASS.
- Scalar/NumPy model contracts: 4 PASS.
- Original sealed bundle replay: all three partition predictions and gate results
  exactly match the original stored results. Evaluation A: 130/170 candidate vs
  127/170 locked control; B: 126/184 vs 125/184; consumer: 125/213 vs 129/213.
- All statistical gates remain false. Original settlement caller recomputed both
  evaluator outputs and returned `not_adopted`, model reward 0.

This is a regression/replay on original public fixtures, not new training,
new independent tasks, improved model efficacy or a new accepted generation.
No data, thresholds, budgets, model parameters or historical evidence changed.
No deployment, runtime activation, external payments or public rewards occurred.

## Environment and unrun work

Python 3.12.14, NumPy 2.3.5 and cryptography 50.0.0 were installed. The repository
pins NumPy 1.26.4 and cryptography 41.0.7, so this is explicitly an available-host
regression, not pinned-environment qualification. Cargo was not available: Cargo
graph/lock verification, Rust tests, formatting and strict Clippy were not run.
No claim is made about full native CI, WAN, physical hosts or independent owners.
The timestamped directory is a local execution receipt, not release evidence.

## Reproduction

From repository root, run the commands in `commands.txt`. Settlement requires a
fresh output directory. `replay.py` prints its exact input hashes and asserts
prediction and gate parity; it does not overwrite original inputs. The manifest
binds changed checker source and experiment runtime/configuration/input bytes.
