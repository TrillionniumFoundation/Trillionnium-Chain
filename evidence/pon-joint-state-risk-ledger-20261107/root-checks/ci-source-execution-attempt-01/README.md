# Independent source-integrity and execution gate observation

Preflight, both requested test suites, and the retained transfer verifier completed with exit code 0. All stdout and stderr bytes are retained in separate files, including expected negative-case child failures emitted by the tests. Individual command JSON records retain command arguments, current working directory, UTC start time, elapsed duration, exit status, stream lengths, and stream SHA-256 values.

| Command | Retained result | Stdout | Stderr | Command record |
| --- | --- | --- | --- | --- |
| `bash scripts/project-preflight.sh` | PASS, exit 0 | [stdout](preflight.stdout.log) | [stderr](preflight.stderr.log) | [record](preflight.command.json) |
| `python3 scripts/ci/test_ci_source_integrity.py -v` | 43 tests passed, 2.851 seconds | [stdout](source-integrity.stdout.log) | [stderr](source-integrity.stderr.log) | [record](source-integrity.command.json) |
| `python3 scripts/ci/test_ci_execution.py -v` | 77 tests passed, 23.665 seconds | [stdout](ci-execution.stdout.log) | [stderr](ci-execution.stderr.log) | [record](ci-execution.command.json) |
| `python3 evidence/pon-joint-state-risk-ledger-20261107/recovered-source-gates/transport/verify-transfer.py` | PASS; 208 original files, 27 directories, 14 version-pinned chunks | [stdout](transfer-verification.stdout.log) | [stderr](transfer-verification.stderr.log) | [record](transfer-verification.command.json) |

The two requested suites ran concurrently. The transfer verifier ran after both completed. `check_repository.py` was not invoked by this attempt. Temporary Git repositories and process fixtures belong to the test suites; the shared repository sources were read only.

## Exact source scope and the concurrent documentation update

[source-before.json](source-before.json) and [source-after.json](source-after.json) retain SHA-256, length, type and mode for all 2,376 Git-visible non-evidence files, including tracked files and nonignored untracked files. This selection excludes evidence generation and ignored untracked files; it does not claim to hash every build cache or every physical file on the host. Both endpoint HEAD observations were `6615ffa37a0d8f6451bf3e49c2500b4626ffae6c`; the actual working tree and its uncommitted sources are represented by the full manifests, not by HEAD alone.

The only differing entry was `docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md`: the root agent concurrently appended the actual acceptance results and current integration route. The summary correctly retains `same_non_evidence_source_at_endpoints: false`. No test, implementation, or CI source changed. [gate-source-stability.json](gate-source-stability.json) separately enumerates all `scripts/ci/` entries and the preflight script and records that those exact files matched at both endpoints. This supplementary statement does not replace or weaken the full-tree mismatch record.

- Plan before: 579,300 bytes, SHA-256 `22b8adf1193061f59af035f575802f2f68cec24682386ecfe3f5848b6e290aa2`.
- Plan after: 580,758 bytes, SHA-256 `36dd2dbeba12910a18505744608728b59384bd22bad47f19f20e425cd7a1db37`.
- Full selected-entry digest before: `464497d52441320ffa29b59a3e887b1f9fcbeee442f1d20828ef1b31d8daa4e3`.
- Full selected-entry digest after: `137a13f6bea69e65548fd5f6fc495993df37b1ea41b8e720ad34813287d6bddc`.

[summary.json](summary.json) is the original aggregate result, and [environment.json](environment.json) records the Python executable/version, platform, Git version, and the sole environment override (`PYTHONDONTWRITEBYTECODE=1`). Source equality at observed endpoints is not loaded-module execution attestation or a physical-resource security certificate. `production_qualified` remains false.

All log files are physical retained evidence even when repository ignore patterns omit them; publication must add the full attempt directory explicitly.
