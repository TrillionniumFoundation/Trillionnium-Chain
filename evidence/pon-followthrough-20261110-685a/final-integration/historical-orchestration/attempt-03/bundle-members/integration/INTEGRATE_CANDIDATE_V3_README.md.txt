# V3 observer correction

The frozen v2 observer actually refused before source mutation because it expected only one node harness summary. The complete original 203,044-byte stdout, SHA256 `022eabf9dba4c26fda5ab75d9d9b53df76f209e19b2af9b3f4ce256ebf4f0b6b`, also contains three nested 1/0/0 results. V3 verifies all four complete summaries, the main 1,326 unique-name roster and its 1,285 ok / 2 failed / 39 ignored rows. It separately retains the three child successes and 13 interleaved running announcements, without imposing stack pairing or adding child successes to the main denominator. The terminal main result remains FAILED.

Only this observer interpretation changes. All nine runtime inputs and all C3 gates remain fixed; controller/state/check/native-observation schemas intentionally remain v2. The original v2 bundle and driver/controller 02 refusal are retained. The actual original 39-command and followup 14-command artifacts are checked directly by the independent read-only `native-observer-audit-03` before this bundle is frozen. That audit neither constructs Controller nor changes source, executes native tests or creates C3. The later C4 publication must include this audit's original command/streams/summary and the earlier 02 refusal as distinct observations.

# PoN follow-through: draft integration of retained failures

This independent v3 observer with the v2 integration contract integrates reviewed source and evidence while
retaining the actual failed C2 native suite. It does not change project CI gates,
test assertions, service budgets, deadlines, the 39 ignored tests, historical
evidence, or any qualification. It performs no native rerun, fetch, push or PR.
The frozen v1 controller, helpers, bundle, driver and failed observations remain
separate original artifacts.

## Exact input observations

The only code checkpoint is C2 `8d8c0e64e7a301fc111a6720721a14816639e5aa`, tree
`7c003a3d183ad33ff4f3349cbcce61564f73a2ba`. The original native directory must
retain its 39-command array, ending in `node-library-v3`, exit 101. Its complete
stdout records **1285 passed / 2 failed / 39 retained ignored**. Original command
bytes and this full stdout have fixed reviewed SHA256 pins. Earlier offline
dependency failures, C1's 3/1 node result, the 0/4 red observations and the 2/6
settlement counterfactual remain intact.

V3 has no completion summary or source-after record. V2 rejects additions with
those names. The distinct `native-followup-04` directory must contain the actual
completed 14-command observation: the two individually selected original tests
each fail 0/1, exit 101; the other twelve commands exit zero. Its pinned original
summary explicitly keeps `all_followup_checks_passed: false` and
`original_full_node_suite_passed: false`. Every command's argv, cwd, timestamps,
stdout/stderr length and SHA256 are checked. The release probe executes three
tests; the reader executes all 26 tests.

The followup's original source-before and source-after bytes must equal the old
v3 source-before bytes. This closes the unchanged C2 observation interval. It
does not manufacture a successful original suite. The controller's new schema
always separates `native_observation_complete: true` from
`native_full_suite_passed: false`, with `draft_only: true` and security HOLD.

The separately executed exact-BASE two-test control observed large-parent 1/0,
with both internal backends passing, and inactive-page 0/1, exit 101, with
`PUBLIC_MUTATION_CPU_BUDGET`. The latter differs from C2 full-suite's diagnostic
`OWNER_PUBLIC_SERVICE_UNCLEAN_EPOCH`. Its original build path, environment and
time-based refill observations are separate evidence. This mixed result cannot
substitute for the full C2 result or establish one exclusive cause.

## Source and history boundary

The real ROOT must be clean, completely materialized and non-sparse, with every
index entry marked `H`. Hidden index flags are refused, never automatically
cleared. The unmodified original head source verifier reads all actual tracked
bytes before any integration mutation and again around the eventual C3 checks.

Global Git history may be shallow. That fact is recorded explicitly. Raw commit
objects must verify to the selected SHA1 identities, their trees must equal the
fixed BASE/C1/C2 trees, C1 must have only BASE as its raw and visible parent, and
C2 must have only C1. Every blob in these three selected trees must be locally
available. C2 must be a real ancestor of the current HEAD. The older parents of
BASE are not traversed, and completeness of global history is not claimed. No
fetch or shared Git-history change occurs.

The selected C1 is `11c9562252d3cf56b423c7756569be0c669d9606`, and BASE is
`da1374a200022bc14dc2bd325cc9ba29dbcd24ab`. The recorded C1-to-C2 and BASE-to-C2
path sets must match the actual Git changes. The sole C2 correction paths are
the four-test confirmation fixture and the verified-reference reader.

## Invocation and known progress files

The controller accepts the same stage model as v1, adding one explicit followup
directory. `prepare` or `all` requires a fresh external OUT. All inputs are
outside ROOT and must match the nine literal SHA256 pins.

```sh
PON_ROOT=/home/qian-qi/chain-pon-followthrough-20261110-685a
PON_INPUTS=/home/qian-qi/chain-pon-followthrough-20261110-685a-inputs/integration-bundle-03
PON_NATIVE=/home/qian-qi/chain-pon-followthrough-20261110-685a-inputs/validation
PON_FOLLOWUP=/home/qian-qi/chain-pon-followthrough-20261110-685a-inputs/native-followup-04
PON_OUT=/home/qian-qi/chain-pon-followthrough-20261110-685a-inputs/integration-03

python3 -B "$PON_INPUTS/integration/integrate_candidate_v3.py" \
  --phase all --root "$PON_ROOT" --inputs "$PON_INPUTS" \
  --native-validation "$PON_NATIVE" --native-followup "$PON_FOLLOWUP" \
  --output "$PON_OUT"
```

Alternatively, run `prepare`, then `commit`, then `validate` with the same
arguments and OUT. Saved state, controller hash, input hashes, source/index
identity and raw native members are checked before continuation. A refusal
preserves partial changes and original failures; no automatic reset, overwrite,
input repinning or relaxed retry is performed.

| Small file | Meaning |
|---|---|
| `OUT/status.json` | Stage, phase, start/end, last exit, current HEAD and failure-observation flags; atomic updates. |
| `OUT/failure.json` | Latest actual refusal; timestamped files preserve earlier ones. |
| `OUT/summary.json` | Requested phase completion and actual C3 identity; the native full-suite flag stays false. |
| `OUT/state.json` | Exact phase state and owned file/index guards. |
| `OUT/commands.json` | Actual controller argv, streams, digests and exit records. |
| `OUT/native-preflight.json` | Derived index of the original C2 failures and followup observations. |
| `OUT/selected-history.json` | Actual selected chain/object checks and global shallow-history fact. |

## Mutation and validation scope

The five existing ordered patches remain unchanged: native roster/artifact
controls, QROM historical/current CI separation, three control registrations,
the 26-test reader registration, and the corpus double-deletion guard. Each is
first predicted in an external Git index, then compared to the actual applied
file blobs. Three separately pinned v2 binding helpers use the real C2 source.
Their output path sets are identical to v1: seven authority/PQ128 outputs, six
W1 outputs and fourteen QROM outputs including the same ten new evidence files.

Original native files are copied verbatim into distinct directories:

- `evidence/pon-followthrough-20261110-685a/native/original-v3/`
- `evidence/pon-followthrough-20261110-685a/native/followup-v4/`

The one-to-one member manifest retains lengths, SHA256, Git blob IDs and original
modes. Only enumerated members are staged with `git add -f --`, including ignored
`.log` files. Every final Git member is read back and compared. No binary, target
directory, ZIP or unreviewed file type is copied. Only explicitly manifested raw
log/patch paths are exempted from whitespace checks; JSON, code, documentation
and manifests remain checked. Historical evidence is not edited.

The development plan receives an append-only HOLD entry with the actual failed
suite and successful individual gates. The original inventory generator runs.
The staged F tree then drives the unchanged corpus updater: all 987 historical
required paths and 1,079 historical pin paths remain; exactly 24 required inputs
produce totals of 1,011 required paths and 1,103 pins. These extra native raw
members do not add required-path qualifications or alter those denominators.

`commit` makes one ordinary child C3. `validate` retains every original v1 C3
gate: corpus/source-integrity/CI contract and related Python controls, exact
75-name QROM current controls, the historical QROM refusal, current source audit,
authority/PQ128/W1 checks, exact W1 report reproduction, generated inventory,
repository/Markdown links, whitespace and format. Each actual command must exit
zero inside the original source-verifier bracket. Failure of any C3 gate is a
real refusal, with original outputs retained.

The native source delta from C2 may contain only the generated distributed
inventory. All Cargo inputs and every other path under the three native owner
crates must retain their Git modes and blobs. Root then runs the separately
recorded, unchanged three-crate `--all-targets` strict Clippy and locked offline
graph inside an actual C3 source bracket. Full suites and 4/8/3 focused suites
are not repeated or credited to C3.

Local verification exercised 17 Git/Linux component controls: the original
15 controls adapted to the new explicit observation interface, plus selected
shallow-boundary and original-stream closure controls. These are component
fixtures. They do not assert that real C3 integration, native tests or hosted CI
have completed.
