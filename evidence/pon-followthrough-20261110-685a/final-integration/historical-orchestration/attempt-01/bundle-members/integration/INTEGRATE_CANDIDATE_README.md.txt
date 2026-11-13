# PoN follow-through integration controller

This external controller prepares and validates a child of the actual completed
native-v3 source. It does not contact the desktop, fetch, push, open a PR, rerun
the native owner suites, or promote a security/production qualification.

## Required inputs and checkpoint boundary

`--root` must be the full, non-shallow, non-sparse checkout whose clean HEAD is
the exact commit in the original native `summary-v3.json`. The summary must say
`complete: true`; its C2 source/tree, original before/after source-verifier
records, every command stdout/stderr digest, complete v3 command roster and C1
failure prefix are verified. C2 must be the real single child of C1
`11c9562252d3cf56b423c7756569be0c669d9606`, with only the corrected node test and
verified-reference reader changes. No C2 value is supplied by a caller flag.

The native input directory is the original completed runner OUT, normally:

`/home/qian-qi/chain-pon-followthrough-20261110-685a-inputs/validation`

Every original `.json`, `.log` and `.patch` file in this flat directory is copied
after bounded regular-file reads. Unknown files, directories, symbolic links,
FIFOs and an output directory that changes while being copied are refused.
Target binaries and ZIPs are not evidence inputs. Original C1 failures and the
initial offline dependency failure remain in the command array and original
streams. The corrected v3 red node run explicitly remains an owner
counterfactual over C1 dependencies, not a complete baseline-checkout rerun.

`--inputs` is an external directory retaining the relative paths in the
controller's literal `INPUT_SHA256` mapping. Each helper and patch must match its
fixed SHA256. The controller also records its own SHA256 and requires it on a
later phase. Input updates require a separately reviewed controller version;
there is no accept-current-hashes mode.

## Phases

Use distinct variables for the real checkout, the external input bundle, native
OUT and external controller receipts. The controller does not create missing
parent directories for its output.

```sh
PON_ROOT=/home/qian-qi/chain-pon-followthrough-20261110-685a
PON_INPUTS=/home/qian-qi/chain-pon-followthrough-20261110-685a-inputs/integration-bundle-01
PON_NATIVE=/home/qian-qi/chain-pon-followthrough-20261110-685a-inputs/validation
PON_OUT=/home/qian-qi/chain-pon-followthrough-20261110-685a-inputs/integration-01

python3 -B "$PON_INPUTS/integration/integrate_candidate.py" \
  --phase prepare --root "$PON_ROOT" --inputs "$PON_INPUTS" \
  --native-validation "$PON_NATIVE" --output "$PON_OUT"

python3 -B "$PON_INPUTS/integration/integrate_candidate.py" \
  --phase commit --root "$PON_ROOT" --inputs "$PON_INPUTS" \
  --native-validation "$PON_NATIVE" --output "$PON_OUT"

python3 -B "$PON_INPUTS/integration/integrate_candidate.py" \
  --phase validate --root "$PON_ROOT" --inputs "$PON_INPUTS" \
  --native-validation "$PON_NATIVE" --output "$PON_OUT"
```

`--phase all` runs these three phases in order with one invocation. The initial
OUT must not exist. `commit` and `validate` use the same OUT and verify the exact
saved state. A failed preparation keeps its partial mutations and original
logs; it does not reset or overwrite independent changes. Inspect those bytes
before a targeted recovery. Repeated commit/validation attempts use new
command/result names and preserve previous failed observations.

### Prepare

The controller first executes project preflight. It predicts the five ordered
patch results in a separate Git index outside the checkout, then applies each
patch and compares the resulting complete file blobs with that prediction:

1. W1 exact native rosters and artifact-safe upload preparation.
2. Historical/current QROM CI separation.
3. Three CI control registrations.
4. The 26-test fresh rejection reader registration.
5. The expanded corpus double-deletion guard.

Authority/PQ128, W1 ledger and QROM successor source bindings use the real C2
checkpoint. Their independent review/old-refusal receipts remain in OUT. New
native evidence receives a member manifest with raw file bytes, SHA256 and Git
blob IDs. The sole development plan receives an append-only actual C2 note with
HOLD. The distributed source inventory is refreshed with its original generator.

Only enumerated implementation and evidence paths are staged. Evidence uses
`git add -f --` with the exact member list because `*.log` is ignored by the
repository. Each staged evidence blob is checked with `git ls-tree` and
`git show`; committing a manifest without its raw members is refused.

The staged F tree is passed to the corpus inventory/update helper. All 987 old
required paths and 1,079 old pin paths remain; the 24 new required inputs give
1,011 required paths and 1,103 pins. Only changed existing blob pins and the new
required inputs change. Corpus status, parent/source composition, historical
objects and all false/null claims remain unchanged. The original corpus stays
unchanged until the external updater has produced and validated a replacement.

Source whitespace checks enumerate exact original native log/patch member
exclusions. They use literal paths, never a directory wildcard. Every JSON,
source file, document and generated manifest remains in the check. Original
native logs retain the Rust harness's trailing blank line and any original
spaces; their bytes are checked against their manifest and Git blobs.

### Commit

After another preflight, `commit` creates one ordinary child C3. It verifies the
actual parent C2, exact prepared tree, clean checkout, and every evidence member.
It neither changes the selected C2 source identities to C3 nor credits C3 with
C2's already-run native suites. No push is performed.

### Validate

The unmodified original `scripts/ci/verify_ci_source.py --kind head` brackets all
checks on the actual committed C3. Results go outside the worktree. The checks
include the corpus/source-integrity/CI contract controls, W1 native roster and
artifact controls, storage/discovery controls, all 26 reader controls,
authority/PQ128/W1 controls and audits, and exact reproduction of the new W1
ledger report. The current QROM helper executes its exact 75 named controls;
the original historical audit is executed for its required refusal; the current
auditor reads the actual source closure. These are actual commands. The
workflow-only `verify` subcommand and synthetic stage-outcome environment values
are not used.

The final checks include:

```sh
python3 -B scripts/refresh_distributed_source_inventory.py --check
python3 -B scripts/ci/check_repository.py
cargo fmt --manifest-path trillionnium/Cargo.toml --all -- --check
```

`check_repository.py` is the repository's source/Markdown/local-link check. The
full command list and each command's original stdout/stderr, exit code, start
and end times are written to OUT. No failure is replaced with an assumed pass.
The source verifier must be byte-identical to its baseline. The controller
refuses hidden/assume-unchanged/skip-worktree index flags before each guarded
operation and does not clear them automatically.

C2's full native suites are not repeated. The controller compares actual C2/C3
Git entries and records `native-source-delta.json`: Rust changes must be limited
to the generated distributed inventory, all Cargo graph/config inputs must be
unchanged, and every other path in the three changed owners must retain its Git
mode/blob. Under that condition root runs the original three-crate `--all-targets`
strict Clippy, a locked offline graph and the actual C3 source bracket. It does
not repeat the 4/8/3 focused controls or full owner suites. An unexpected native
input difference is refused for separate review.

## Stable small progress files

The following fixed paths support background observation without enumerating
jobs:

| File | Meaning |
|---|---|
| `OUT/status.json` | Current stage/phase, start/end times, last exit, actual current HEAD. Replaced atomically at command and phase boundaries. |
| `OUT/failure.json` | Latest actual refusal/failure; unique timestamped copies retain earlier failures. |
| `OUT/summary.json` | Successful requested phase, actual C2/C3/tree, whether the full integration validation completed, and HOLD/false qualifications. |
| `OUT/state.json` | Exact phase state, hashes and file/index guards used for continuation. |
| `OUT/commands.json` | Original command array with stdout/stderr member digests and exit codes. |

A `prepare` or `commit` summary explicitly has `integration_complete: false`.
Successful source-only or fixture tests are not reported as native execution or
hosted CI completion. The last failure file is retained after a later success;
use timestamps and the current status/summary to distinguish those observations.

## Local component verification boundary

`test_integrate_candidate.py` uses real temporary Git repositories and Linux
file primitives to check explicit ignored-log staging, exact blob retention,
external index prediction, refusal of independent file/index changes and hidden
flags, FIFO/link rejection, incomplete native rejection, progress files and
source whitespace coverage. These fixtures are not a complete project checkout
or C2/C3 execution. The corpus helper's seven component controls and 48 targeted
checker mutations have the same limited scope. Full integration requires the
actual completed native OUT and complete Git worktree described above.
