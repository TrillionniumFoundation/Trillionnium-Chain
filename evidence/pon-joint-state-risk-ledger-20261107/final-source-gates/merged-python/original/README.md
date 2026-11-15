# Exact merged Python and source gates

Commit: `2d46d8682201bc0619f5b156af50e77fb399322e`. Tree: `5ae5317304588cca8295a19dd512c8e853f1ef5b`. Parents are the reviewed `b66e66d2465258d808c0f56ff851123306d4bdb4` and `cb314bb4656e5da4844325cd83994ab4764fe8e9`, in that order. All logs in this directory are outside the repository. No commit or push was performed by this work.

## Completed requested gates

All six requested Python suites passed, for **309 tests**. Each raw stdout/stderr stream and command receipt is retained.

| Suite | Tests passed | Command receipt | Raw stderr |
| --- | ---: | --- | --- |
| finite-joint-state | 34 | [receipt](attempt-01/finite-joint-state.command.json) | [stderr](attempt-01/finite-joint-state.stderr.log) |
| event-coverage | 21 | [receipt](attempt-01/event-coverage.command.json) | [stderr](attempt-01/event-coverage.stderr.log) |
| lifecycle-query | 26 | [receipt](attempt-01/lifecycle-query.command.json) | [stderr](attempt-01/lifecycle-query.stderr.log) |
| source-integrity | 43 | [receipt](attempt-01/source-integrity.command.json) | [stderr](attempt-01/source-integrity.stderr.log) |
| ci-execution | 77 | [receipt](attempt-01/ci-execution.command.json) | [stderr](attempt-01/ci-execution.stderr.log) |
| ci-contract-negative | 108 | [receipt](attempt-01/ci-contract-negative.command.json) | [stderr](attempt-01/ci-contract-negative.stderr.log) |

The preflight, CI static contract, distributed source inventory, invariant registry and current-implementation validators also passed. The first detailed-contracts/applicability attempts rejected missing `evidence/pon-v1/manifest.json`; those exact failures remain in `attempt-01/summary.json` and its original streams.

The fixed committed module-maturity declarations require 13 manifest/qualification files. Their actual Git objects were obtained through a normal promisor fetch, each Git blob ID was recomputed, and the exact bytes were placed at their tracked paths. Together they contain **965,044 bytes**. No placeholder, changed guard, changed source, index rewrite or ref update was used. With these inputs present, both detailed-contracts and applicability passed. `report_current_implementation.py --check` also passed. All 13 fixture byte hashes and blob IDs were rechecked at close.

- [Initial complete command receipts and original failures](attempt-01/summary.json)
- [Exact fixture materialization and blob bindings](module-fixtures-attempt-01/materialization.json)
- [Successful source-validator follow-up](module-fixtures-attempt-01/summary.json)
- [Final coverage summary](coverage-summary.json)
- [Durable process identities, terminal states and raw-stream hashes](runtime-jobs.json)

The 13 native/formal files reviewed during automatic merge were rebound to this exact committed tree, with matching reviewed Git blob IDs, SHA-256 values, index entries and working files. The root source snapshot contained all 2,415 non-evidence tracked files; their bytes matched at the initial execution endpoints and were rehashed again at close. HEAD/tree remained fixed and Git status remained clean.

- [Native merge-source binding](attempt-01/native-reviewed-commit-binding.json)
- [Source hashes before](attempt-01/non-evidence-source-before.json)
- [Source hashes after](attempt-01/non-evidence-source-after.json)

## Full repository-truth lane remains uncovered

The canonical lane contains 69 shell commands. Static discovery followed 71 Python entry sources and 165 local import sources. The fixed command-line fixture roots include `evidence/pon-upgrade-implementation-20261018/native-rounds/chain-p0-native-54` (21 tracked files) and `.../chain-pr327-original-campaign-39694587963` (54 tracked files); neither subtree is materialized. The module-maturity manifest/qualification dependencies above are now complete. Additional visible fixture dependencies include the `pon-v3` historical package (77 tracked files, 75 still absent), the four-file `pon-six-workpackages-20261106/ci` directory including its original workspace ZIP, the retained `run_reorg_abba.py`, and the chain-390 public-V3 report.

The static referenced-fixture superset contains 169 distinct tracked paths; 156 remain absent. It is explicitly **not a complete dynamic fixture closure**: conditional paths, JSON-indirect records and historical source-archive objects may require additional inputs. The original v1 package also declares a historical source commit/tree, recorded separately.

The canonical workflow first runs `verify_ci_source.py`. That checker rejects skip-worktree or assume-unchanged index entries and then opens/hashes every tracked blob. This checkout still has 12646 such rejecting index entries. Its immutable tree contains 16,313 tracked blob paths, while **12,646 historical evidence paths remain unmaterialized**. Of those missing paths, cached objects account for 4,383,117 bytes; another 10,862 paths refer to 9,425 distinct uncached objects whose sizes have not been fetched. These cached byte counts are lower bounds, not a total download estimate. A clean sparse Git status does not satisfy the stronger canonical raw-worktree guard.

The full repository-truth lane and merged-tree `check_repository.py` were therefore not run or reported as passing. The separate Git-tree Markdown check belongs to another observation and does not replace either guard. No fake fixture or source-verifier exception was introduced.

- [Canonical source-identity boundary and every rejecting index path](canonical-source-identity-boundary.json)
- [Actual lane commands](repository-truth-static-dependencies-attempt-02/commands.json)
- [Explicit command/config fixture dependencies](repository-truth-static-dependencies-attempt-02/fixed-explicit-fixtures.json)
- [Static fixture prefix footprints](repository-truth-static-dependencies-attempt-02/static-fixture-footprints.json)
- [Every unmaterialized tracked blob and object ID](repository-truth-static-dependencies-attempt-02/missing-tracked-blobs.json)
- [Historical source-archive commit/tree declarations](repository-truth-static-dependencies-attempt-02/declared-historical-source-archives.json)
- [Static-analysis summary and limits](repository-truth-static-dependencies-attempt-02/summary.json)

The first static dependency attempt treated a historical source-archive dictionary as a path and failed before producing a coverage report. Its exact stdout/stderr and job identity are retained in `repository-truth-static-dependencies/`; the second analysis uses the declared commit/tree type. This was an auxiliary analysis error, not a changed repository guard.

## Interpretation and file completeness

These observations bind the reported model/source checks to the identified source and retained inputs. They do not authenticate physical execution costs, establish the actual joint probability law, cover all world execution, or promote production qualification.

[artifact-manifest.json](artifact-manifest.json) enumerates every physical retained file with its byte count and SHA-256, excluding only that self-describing manifest. Inventory uses physical traversal and includes all ignored log files and failed attempts. The process transport keeps raw text streams and omits duplicate `bytes_hex` encoding.
