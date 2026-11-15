# Useful Cell V2 public Chain evidence — local verification

This is the retained local verification evidence for the bounded integer source-routing Cell relation. `retained-runs.tar.gz` contains the selected original run bytes plus this README and the manifest/review/checksum indexes. Each archive member is checked against its expected SHA256 after compression. This is not a release, a native consensus activation, or an ordinary Hepta owner-use certificate.

## Current result

The final committed-source focused run reports **143 tests, OK, exit 0** on clean commit `837ab80d2b0454a3b226d13ac270f9496f8d7f96`. Its before/after source fences are identical and cover **10692 tracked entries / 1026980219 bytes**. The earlier post-fix focused run is also retained without counting the same tests twice. The final seven-case experiment reports **7/7 complete**, with a new-process verification exit of 0 and **five complete W1 transcripts in every case**. The experiment wrapper ran for **42.877128810 seconds** with `--batch-size 64`.

The collector checked the focused log hash, both final experiment stream hashes, all **77 declared final case payload hashes**, all **77 declared retained pre-fix payload hashes**, and the common attack script/stream hashes. It also compared the three executed V2 source-file hashes shared by the focused receipt and experiment identity. These are read-only consistency checks of retained artifacts, not another execution of the relation.

| Case | Input rows | Actions | RNG counter | Training | Cold exit |
| --- | ---: | --- | --- | --- | ---: |
| emit | 64 | emit=64 | 0 → 0 | no | 0 |
| masked-sampling-training | 64 | emit=64 | 0 → 64 | yes; optimizer step 1 | 0 |
| tool-proposal | 64 | propose_tool=64 | 0 → 0 | no | 0 |
| abstain | 64 | abstain=64 | 0 → 0 | no | 0 |
| stopped | 64 | stop=64 | 0 → 0 | no | 0 |
| exhausted-prefix | 64 | emit=1, stop=63 | 0 → 0 | no | 0 |
| successor-model-task | 64 | emit=64 | 64 → 64 | no | 0 |

All proof targets are maximal (`ff` repeated 32 times), and every case records one attempt per W1 tile. This is a correctness control; it does not establish mining cost or work hardness. The successor case uses the trained artifact on disjoint reference inputs and reaches sequence 2 in this local fixture. It does not establish later ordinary-product adoption.

## Source identity and publication status

- Local code commit: `837ab80d2b0454a3b226d13ac270f9496f8d7f96`.
- Local code tree: `46a355fd6117093bc1d0deb9f3dfb81270a0b8cb`.
- Final relation program SHA256: `5793725462241da591438a3322bfc818e197778b9454831edc7be6ae036dcec5`.
- Final parameter SHA256: `d5cb070af92c18f354b72a2379cea5fadb83eb80e2665f615b8c3c69d6fb3549`.
- Runtime/source closure: `postfix-validation/experiment-postfix-attempt2/source-identity.json`.
- Focused before/after file pins: `postfix-validation/focused-postfix-attempt2.json`.

The exact local commit/tree were read from local Git during preparation. `postfix-validation/committed-source-final.json` now retains a complete source-before → 143-test run → source-after sequence on that commit. The collector checked all three log hashes and equality of the before/after source records. The separate experiment still exposes its complete runtime/program source manifest. Focused/source checks do not imply that every repository gate or any native product qualification has passed.

The publication receipt records a GitHub HTTP 403 account-suspension error, `ref_update_called=false` and `remote_commit_created=false` for this work. This statement does not describe other concurrent writers. The retained `postfix-validation/publication-blocked.json` records the HTTP 403 failure. This package makes **no published-commit, merged-PR, or successful hosted-CI claim**. An earlier unreferenced remote tree is not a published commit and is not used as a release identity here.

## Final repository checks

`postfix-validation/light-gates-final.json` records clean before/after Git status on the same local commit. All six recorded log hashes were checked.

| Check | Observed result |
| --- | --- |
| Project preflight | PASS |
| Repository graph / current links | PASS: 26 workspace packages, 1169 Rust files, 3467 local links, 25 normal dependency edges |
| Distributed source inventory | PASS |
| Project-boundary controls | 16 tests, OK |
| Source-integrity controls | 43 tests, OK |
| CI execution controls | 77 tests, OK; includes the preceding 43 source-integrity tests |
| CI contract controls, including six explicit Cell test files | 102 tests, OK on clean committed source |
| Repository mutation controls | 50 tests, OK on clean committed source |
| Rust toolchain | Rust 1.95.0 |
| Locked, offline, all-features Cargo graph | 26 workspace members; 180 resolved nodes |
| Cargo formatting | `cargo fmt --all -- --check`, exit 0 |
| Strict workspace/all-targets/all-features Clippy | `-- -D warnings`, exit 0 in 119.185103351 s with the reused pinned OpenSSL 3.5.9 provider |
| Source fence after all listed gates | exit 0; same 10,692 entries / 1,026,980,219 bytes, commit and tree |

Do not add 43 and 77 as unique test coverage. The expected `FAIL` receipts emitted by negative source-integrity controls are counterexamples under a passing suite, not an overall gate failure. The earlier failed and truncated runs remain in the package.

The final copy-fixture receipts are in `postfix-validation/heavy-gates-final.json`; the Rust/graph/formatting commands and all six stream hashes are in `postfix-validation/cargo-graph-fmt-final.json`. They bind the same local source commit and a clean final status. The strict Clippy sequence is now complete and retained below; its success is limited to compilation/lint with the recorded provider.

## Strict Clippy attempts, provider reuse and qualification limits

All three attempts used `--locked --offline --workspace --all-targets --all-features -- -D warnings` on the recorded clean source. The suffix `final` in a filename does not mean the command passed.

| Attempt | Exit | Interpretation |
| --- | ---: | --- |
| `strict-clippy-committed-final.*` | 101 | OpenSSL discovery failed because the `pkg-config` executable was missing. |
| `strict-clippy-openssl-paths-final.*` | 101 | Explicit system OpenSSL 3.0 paths could not provide the PQ `private_key_from_seed` API; Rust reported E0599. |
| `strict-clippy-pinned-provider-final.*` | 0 | Strict compilation/lint passed in 119.185103351 s with the existing repository-pinned OpenSSL 3.5.9 provider. |

The original logs, terminal receipts and `returncode=null` start snapshots remain separate and unchanged. The collector checked each terminal log hash, command scope and clean-source fields. Start snapshots have no success verdict.

`reused-pq-provider-original.json` is the historical preparation receipt. `reused-pq-provider-current.json` records five input digests matching that receipt and an unchanged preparation-script hash (`ccdcf7e8bb9871607c73adc78624a607b616c227b7fe581b96c48761a3805bfa`). The collector checked that the current receipt names the exact original-receipt bytes, all five recorded digest/size pairs agree, and the version stdout hash matches. It did not open or copy the installed provider binaries. This is **reuse of an existing provider**, not a new provider build or a new native PQ runtime test. Historical smoke-test fields in the original receipt must not be presented as tests executed by this work.

The successful Clippy log still contains the build-script warning:

> `trnm SQLite I/O boundary UNQUALIFIED: loader directory must be absolute`

Clippy exit 0 does not satisfy that SQLite I/O boundary, establish PQ runtime behavior, or qualify whole-chain production/security. Those flags remain false. Compiler/lint completion and a dependency's build-script qualification report have different meanings.

`source-after-all-gates-final.*` provides one more complete source check after these attempts. Its stdout is identical to the previous recorded source fences. Source-clean statements apply to the gate times; later temporary storage housekeeping is not classified here as a source deletion or a failed gate. Any subsequent evidence commit is a separate source state and must follow restoration of its exact tracked bytes.

## Retained source-rebinding counterexample and repair

`validation-v2/source_guard_rebinding_attack.py` has SHA256 `394ab0af1a4265f79c66f03dce766e8de672dd4b55b055330b33d7caa8c4a7af`. The pre-fix stdout records a replacement function from `__main__`, unchanged claimed identity, five W1 transcripts, and an accepted incorrect memory transition:

- Correct memory: `[3593, -3602, -3580]`.
- Accepted forged memory: `[3594, -3602, -3580]`.

This is a correctness failure. It must not be described as a successful relation qualification merely because the attack process produced output or because the W1 certificates were valid.

The retained same-script post-fix attempt has expected/actual exit 1 and fails with `V2_LOADED_BINDING_MISMATCH`. Its stdout, stderr and receipt are `postfix-validation/source-rebinding-postfix-attempt2.*`. Their hashes and the script hash were checked. The narrow `postfix-validation/pre-fix-program/` directory contains exactly two preserved public source snapshots and their preservation receipt, not a checkout or build cache.

The corrected guard covers source-defined names, imported bindings, defaults, upstream repository functions, class methods, derived schema constants, builtin shadowing and function builtins. It is a local source-consistency check in a trusted interpreter. It does not attest an operating system or protect a checker against arbitrary same-privilege replacement of the checker itself.

## Earlier failures and incomplete observations remain visible

| Retained observation | Classification | Interpretation |
| --- | --- | --- |
| Initial V1 baseline and attempt 2 | failure | Source replay could not obtain frozen historical blobs. Both original logs and receipts remain. |
| Frozen source repair and V1 rehydrated baseline | success, earlier scope | 261 required blobs checked; 15 verified blobs restored; V1 numeric + relation 67 tests passed. |
| Pre-fix seven-case experiment | success, superseded | Original outputs are retained for comparison. They are never used as final qualification. |
| Pre-fix rebinding attack | failure | An invalid state transition was accepted under an unchanged program identity. |
| `source-guard-tests-final.log` | failure | Despite the filename, it records setUpClass failure, `Ran 0 tests`, and `V2_BUILTIN_BINDING_MISMATCH`. |
| `source-guard-tests.log` | unknown | Empty log; no recoverable suite result. |
| `inventory-sourceguard-postfix-attempt1.*` | unknown suite; known writer failure | Both files are zero bytes. The tool record observed outer exit 1 / ENOSPC. No test PASS is inferred. |
| Earlier `source_guard_rebinding_attack.post_fix.*` | unknown | Empty streams without a complete receipt; use the complete attempt 2 for the repaired result. |
| Prior repository gates | mixed, aggregate failure | `check_repository` exit 2 and `test_repository` exit 1 are retained; inventory and boundary checks passed. The new final repository/light/copy-fixture gates pass; these earlier failures remain unchanged. |
| Prior CI contract/execution | earlier PASS | 102 and 77 tests passed on the previous five-test registration; these are not relabelled as final six-test registration validation. |
| `cargo-fmt.log` | unknown | Empty output without a retained exit receipt does not establish success; the later cargo graph/fmt receipt supplies a separate actual PASS. |
| First two strict Clippy attempts | failure | Both retain exit 101 and their distinct causes; neither is converted to PASS by the successful pinned-provider retry. |

The original failures and truncations are not rewritten or removed. When the final repository gates run, add new attempt-specific receipts and preserve these files.

## Scope and authority

The experiment's admission authority is `local-fixture`. Historical validation uses the supplied parent context and protocol time; the pure live verifier checks its time window. Neither verifier authenticates a real owner's current authorization, consumes a one-time operation, installs a checkpoint, grants FinalUse, executes a proposed tool, proves external delivery, or demonstrates later actual model use.

The retained reports keep owner authorization, request consumption, checkpoint commit, FinalUse, actual model use, native node admission, ordinary Hepta use, work-security qualification and production qualification false. Strict Clippy adds no SQLite I/O, native PQ runtime, or whole-chain quantum-security qualification. Real owner integration and any private Hepta work are outside this public Chain package.

## Retained package

`MANIFEST.json` records each source-relative path, byte size, SHA256, success/failure/unknown classification, phase and inclusion decision. `PACKAGE.sha256` lists the relative payload archive paths and checksums. `REVIEW.json` holds the compact derived checks and the explicit remaining limits.

The retained payload contains **264 files, 17,153,945 bytes (16.359 MiB)**, before archive compression and before the four small index files included in the archive.

| Phase | Files | Bytes |
| --- | ---: | ---: |
| baseline-or-pre-fix | 18 | 135515 |
| current-committed-focused | 4 | 28728 |
| current-final-cargo-graph-fmt | 7 | 844869 |
| current-final-experiment | 91 | 7563330 |
| current-final-focused | 2 | 28828 |
| current-final-heavy-gates | 3 | 23111 |
| current-final-light-gates | 7 | 26000 |
| current-final-refusal | 3 | 1815 |
| current-final-source-fence | 3 | 812 |
| current-final-strict-clippy | 3 | 5668 |
| current-provider-input-reuse | 3 | 3093 |
| failed-strict-clippy-attempts | 6 | 23064 |
| intermediate | 15 | 837841 |
| publication-blocked | 1 | 1098 |
| retained-original-provider-reference | 1 | 2834 |
| retained-v1-baseline | 2 | 12518 |
| superseded-pre-fix | 95 | 7614821 |

The retained payload includes both full seven-case runs so that the pre-fix evidence remains auditable, the source-rebinding reproducer and its before/after observations, all original failures/truncations, and available graph/gate receipts. The 297,201-byte duplicate fetched Git-blob JSON is inventoried but excluded from the package: the frozen source inventory, exact blob hashes and repair receipt are retained.

Temporary eviction/restoration inventories, `temporary-*` housekeeping, `own-clippy-cache-cleanup`, publication-elements, temporary test trees, source checkouts, build caches and private Hepta directories are excluded. No GitHub publication action was performed by this collector.

## Archive verification and publication boundary

The listed local validation sequence is complete, with the two failed Clippy attempts retained beside the successful pinned-provider attempt. This archive refresh incorporates those final records. Native full-system, runtime PQ, SQLite I/O and production qualification are not established by this sequence.

The archive includes only `include=true` payload entries plus `MANIFEST.json`, `PACKAGE.sha256`, `README.md` and `REVIEW.json`. Member names must be relative canonical paths without parent traversal, duplicate names, links or nonregular entries. The collector reads every compressed member back and compares its size and SHA256 to the original selected bytes. `ARCHIVE.json` is a separate creation/verification receipt so there is no archive/self-checksum cycle.

After extraction into an isolated directory, `sha256sum -c PACKAGE.sha256` verifies all retained payloads. The external archive receipt additionally binds the four index files and the compressed archive itself.

A published commit/ref may be recorded only after a remote update actually succeeds. The current package remains local.
