# Evidence lineage review — quantum cost closure

## Conclusion and review scope

**No additional evidence-consistency blocker found in the reviewed final batch. The first frozen attempt failed and remains failed; the final source checks pass with all qualification holds retained.**

This is an internal, read-only review of existing sources, logs, hashes, script lineage and result scope. No tests, builds, campaigns or native executables were rerun for this review, and no repository file was changed. This document is the only output of the review. It is not independent operator, provider, runtime, hardware or security qualification.

The final tested source is `acafa39a507632b6a8947915124a5e9f680f3448`, tree `03c13a4c900b379a87a1fc359d1a82f093218c8e`. The three final summaries agree on that identity, report unchanged tracked source before/after execution and contain only zero command exit codes. Their command arrays agree with `commands.json`. I recomputed every recorded log SHA-256 and byte length: all 32 command logs in the final batch match their receipts. This is a log-integrity count, not a test count.

## Failed attempt and final attempt must remain separate

| Batch | Source/tree | Quantum | Repository | Rust |
| --- | --- | --- | --- | --- |
| `attempt-c7f0918/frozen-*` | `c7f0918da82041de62e693b4e6a814b4ca16fe4c` / `67f496b0aefc140039dcc23e3496fb2b7f107a85` | PASS for its selected checks | **FAIL** | PASS for its lint/metadata checks |
| `frozen-*` | `acafa39a507632b6a8947915124a5e9f680f3448` / `03c13a4c900b379a87a1fc359d1a82f093218c8e` | PASS | PASS for source/contract checks | PASS for lint/metadata checks |

The original failure was exit 1 from `pq-integration-check`: `HOLD_NO_GO: changed source: scripts/ci/ci_job.sh`. The new preprocessing test entry changed that script, but the existing `pinned_blobs` entry still named its old Git blob. The gate correctly refused it. `attempt-c7f0918/pin-correction.json` preserves this explanation.

The commit difference from c7 to acafa is exactly one existing pin replacement in `config/pon/pq-cross-branch-corpus-v1.json`: `69c4a085886dcc91e497db4eb3871ad83f28442f` to `a564e9ed82e6bfb73229d6ab9978920cc3333e62` for `scripts/ci/ci_job.sh`. No source or test logic changed between these two commits. These are Git blob object IDs, not the SHA-256 hashes used for raw logs and files.

The archived c7 command logs also pass all 32 recorded size/hash comparisons, and their before/after source identities match their own commit/tree. Moving the directory did not change those log contents. Absolute command paths in the receipts describe their original execution locations; the later archive location does not relabel the executed source.

Do not present c7 as an all-pass source, erase its refusal, add its successful tests to final totals, or transfer its outcomes to a new source without the separate final records.

## Final counts and overlap

The final logs support the following separate categories:

| Final record | Observed result | Correct interpretation |
| --- | --- | --- |
| `frozen-quantum/quantum-retained-tests.log` | 210 test methods, OK | The ten modules explicitly listed in the recorded command; not every Python or native Rust test in the repository. |
| `frozen-quantum/network-independent.log` | 7 test methods, OK | Separate bounded network controls; not external operator or hardware independence. |
| `frozen-repository/source-integrity-negative-tests.log` | 43 test methods, OK | Source-integrity negative controls. |
| `frozen-repository/ci-contract-tests.log` | 105 test methods, OK | CI command/contract controls. |
| `frozen-repository/pq-integration-tests.log` | 38 test methods, OK | Corpus/source-gate controls. |
| `frozen-quantum/literal-32-controls.log` | 32 arithmetic cases, PASS | Exact rational accounting cases, not 32 finite-horizon work-production experiments. |
| `frozen-quantum/preprocessing-eight-controls.log` | 8 reduced byte-change cases, PASS | An explicit replay of the same case family covered by the preprocessing unit tests. |

The seven `test_w1_preprocessing_reuse` methods and the resource/clock/candidate-check methods are already within the 210-method selected suite. The earlier 54/55-method local resource runs must not be added to it. The eight byte-change cases are subcases, not eight extra test methods. The five intentionally stale-checkpoint examples are a subset of those byte changes, not five newly discovered oracle defects. The two preprocessing JSON presentations describe the same eight cases, not sixteen. The five malformed physical-count cases and five malformed width cases are repeatable diagnostic controls, not additional independent validation populations.

The four portability invocations, historical working-tree runs and repeated c7/acafa runs are repeated executions, not independent replications. Report category-specific counts rather than an inflated aggregate.

## Parent-offset 66 correction is traceable

I read the native `Header::encode` order and the corrected independent field decoder. PNH1 is four magic bytes, two version bytes, then three 32-byte hashes. Therefore parameters occupy `[38,70)` and parent occupies `[70,102)`. Offset 66 changes `parameters[28]`; offset 70 changes `parent[0]`.

`literal-budget/parent-offset-correction.json` correctly classifies the old case as a fixture-label/coverage error, not an oracle implementation vulnerability. The nine listed historical artifacts are preserved under `parent-offset66-history/`; every listed hash matches. The five-block-prefix count did not change, but that numerical agreement did not establish parent-field coverage.

`parent-field-label-before-fix.log` retains the failing assertion showing `parameters` changed instead of `parent`. The corrected test mutates offset 70 and decodes the changed wire fields independently of the mutation offsets inside the original eight-case test. The current seven-method local log and the final selected suite use the corrected test source. I verified the seven regenerated artifact hashes and both corrected source hashes against the manifest.

The 32 literal-accounting cases are unaffected. The old offset-66 logs remain historical local observations and must not be represented as passing parent-field controls or counted as new final-source tests. The helper status wording about a frozen corrected checkpoint is local provenance; the final commit/tree qualification comes from the acafa source receipts.

## Driver and source lineage

- `network-timeout/driver-lineage.json` binds historical before/after observations to `*.py.original.txt` drivers. Both original-driver hashes match. The saved pre-fix simulator file matches its recorded hash and the simulator blob at the original PR #750 base `2d4ff4b6c0af18f324e056b4e0d5343c97850b85`. The current replay uses explicit `--repo`; original hard-coded paths remain only in retained historical snapshots. The fixed outcome reports one publication at `0.6000000000000001`, and its source hash matches the final simulator source.
- `physical-cost/control_script_provenance.json` correctly distinguishes original drivers, portable drivers and historical logs. Both original and current driver hashes, all five historical log hashes and all four portability-log hashes match. The direct-count pre-fix log matches the original base module. Later working-tree checkpoints, including the width pre-fix observation, retain their own module hashes; they must not be called frozen c7/acafa executions.
- The corrected preprocessing and literal-accounting replay artifacts include control-script and dependency hashes. I checked the recorded four-file literal dependency set and both seven-file preprocessing dependency sets, plus their driver hashes; all match the retained files. These checks identify inputs and implementation bytes, not a measured quantum execution.
- `run_frozen_validation.py` hashes to `bf9eda874ccfff3f3231b4ce77d6f21861cc932ce5e7cf6133979b535d9407d7`, matching the batch summaries. Its `--repo`, `--head` and validation-directory arguments make source selection explicit. The source guard verifies tracked repository bytes; standalone evidence drivers are outside that tracked-source guard and have the separate lineage records above.

Final source SHA-256 values relevant to this review:

| Source | SHA-256 |
| --- | --- |
| `quantum_network_sim.py` | `da012e601ab3f79144db6d63044836eb2005c88e78ea41b1108d14ad4d8eb2d9` |
| `quantum_oracle_resources.py` | `0ac636241697c728d64fc4a4f1bb77c53d52a625a6532dfb32631b3f33f20902` |
| `w1_preprocessing_reuse.py` | `660cac37d0f3048f2a809b06e48fa3b24f171968cebf8f3493f3e2dc0ce17c3a` |
| `test_w1_preprocessing_reuse.py` | `d056548a1b217db06b1ece21595f107187ed9a9afeefd15aae97dc2770e2082c` |

## Rust, provider and SQLite limits

The recorded Rust work is `cargo fmt --check`, locked/offline main and fuzz metadata, and workspace/all-target/all-feature Clippy with `-D warnings`. It is not a native Rust test run, production binary execution, provider functional test or performance benchmark.

The environment records `CARGO_PROFILE_DEV_DEBUG=0`, `CARGO_PROFILE_TEST_DEBUG=0`, `CARGO_INCREMENTAL=0`, two build jobs and offline resolution. Thus this is the declared zero-debug-info local lint configuration, not evidence of default-debug CI/provider parity. The logs report unoptimized dev-profile checking; no optimized production or same-budget runtime comparison follows.

Both the OpenSSL CLI and pkg-config report 3.5.7. Version agreement is not execution of provider algorithms or proof of CI environment parity. The final Clippy log still contains the Cargo build-script warning:

> trnm SQLite I/O boundary UNQUALIFIED: normal Cargo loader directory set incomplete

A zero Clippy exit with `-D warnings` does not mean every build-script/environment warning vanished. The warning must remain visible, and SQLite I/O-boundary or native-provider qualification must not be inferred from the lint PASS. The summaries correctly keep `native_runtime_qualification` and `ci_provider_parity` false.

The final `pq-integration-check` now exits zero after checking 688 exact source blobs, but its semantic status remains **HOLD_NO_GO**. It explicitly leaves cryptographic acceptance, continuous combination acceptance, production confidentiality, complete native authorization migration and activation false. A successful contract check is not PQ or whole-chain acceptance.

## Packaging conclusion

Keeping the original c7 failure batch and raw historical evidence separate from the final acafa batch is appropriate. Retain the parent-offset correction manifest and original driver snapshots with the historical material, and include the exact final summaries/commands/logs with the final batch. Archive hashes demonstrate archive integrity; they do not promote lint/source/conditional arithmetic evidence into hardware, equal-budget work production, profitable fork attacks or consensus-security proof.

The final evidence supports the scoped repairs and checks above. **Draft/HOLD and all hardware, same-real-budget advantage, whole-chain quantum-security and activation limits remain in force.**
