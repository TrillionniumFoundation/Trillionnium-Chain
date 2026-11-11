# Validation inventory

Current source: `cdd984808a088e6c2e13b1e1ae6630a94d500c89`. Retained prior source: `90ee47159e32e9014410a1823bed05d84c17b858`.

This snapshot keeps results separate by host and exact source. It includes completed local records and the five completed desktop primary records. Running repository-truth and full rust-baseline lanes are excluded.

| Host | Source | Completed records | PASS | FAIL |
|---|---|---:|---:|---:|
| desktop | cdd984808a088e6c2e13b1e1ae6630a94d500c89 | 5 | 5 | 0 |
| local-cloud | 90ee47159e32e9014410a1823bed05d84c17b858 | 16 | 11 | 5 |
| local-cloud | cdd984808a088e6c2e13b1e1ae6630a94d500c89 | 30 | 25 | 5 |

## M06 actual execution

On local-cloud at Z, 18 actual test executables produced 272 passed, 0 failed, 9 ignored, 0 measured and 0 filtered out. All 281 registered cases reconcile with the Rust summaries; ignored cases are not counted as passed. The five new account development scope tests all passed.

Each executable has its actual Cargo Running path, ELF/execute checks, byte size, SHA256 and stable before/after stat in the JSON inventory. All mtimes precede the recorded run finish. These are post-run artifact hashes, not signed at-execution attestations.

| Suite | Passed | Ignored |
|---|---:|---:|
| unittests src/lib.rs | 153 | 9 |
| tests/account_development_scope.rs | 5 | 0 |
| tests/capacity_progress.rs | 9 | 0 |
| tests/checkpoint_tile_material_v1.rs | 5 | 0 |
| tests/checkpoint_tile_policy_v1.rs | 1 | 0 |
| tests/continuity_v1.rs | 6 | 0 |
| tests/evaluation_quorum_v2.rs | 9 | 0 |
| tests/incremental_prefix.rs | 8 | 0 |
| tests/model_evolution_v5.rs | 4 | 0 |
| tests/pon_commitment.rs | 16 | 0 |
| tests/pq2_authority_capacity.rs | 2 | 0 |
| tests/pq3_quota_authority.rs | 8 | 0 |
| tests/pq4_task_authority.rs | 9 | 0 |
| tests/pq5_task_renewal.rs | 17 | 0 |
| tests/pq_account_owner.rs | 8 | 0 |
| tests/qualified_task_lifecycle_v2.rs | 8 | 0 |
| tests/qualified_task_lifecycle_v3.rs | 1 | 0 |
| tests/qualified_task_lifecycle_v4.rs | 3 | 0 |

## Desktop primary evidence

Preflight, source-before, workspace graph, four new Node tests, and strict workspace Clippy all completed with exit 0 at exact Z. The Node filter executed 4 passed / 0 failed / 0 ignored and filtered out 1398 other tests; it does not represent a full Node test run. Clippy used workspace, all targets, all features and -D warnings.

Node test ELF: 534143600 bytes, SHA256 `87ca599d29ed8a168694f4ff3b290c2eeefdcba1608804a70d131857a1558cad`.

Full primary archive: `/workspace/scratch/a4188f5c86b5/desktop-evidence/cdd984808a088e6c2e13b1e1ae6630a94d500c89/desktop-primary-evidence-v1.tar.gz`.
Archive SHA256: `6325997d4238a8fcdfc3ea59c3a55951d8c77066468111f31813eff418764f9c`; 891385 bytes; all 52 members verified, including 51 original source files.
Extraction: `/workspace/scratch/a4188f5c86b5/desktop-evidence/cdd984808a088e6c2e13b1e1ae6630a94d500c89/primary-evidence-v1`.

## Supply-chain preparation

The isolated desktop Cargo home contains 159 original checksum-verified crate archives and 143 original sparse cache files covering both unchanged locks. Main all-features metadata has 182 packages / 156 registry packages; fuzz metadata has 150 / 137. Both locked offline fetches succeeded, and package name/version/source sets match each lock exactly.

The existing cargo-deny 0.20.2 ELF was copied exactly into the dedicated tool root; it was not rebuilt. Its SHA256 is 5c6fbc977c16a36144f91ff4959e14a6e3468be150d6b2ac693bcdbdd591a535. The first preparation script assertion failed because default-feature metadata omitted five optional OpenSSL packages; that original FAIL remains in the archive. The continuation checked the existing all-features specification.

Official RustSec fetch completed, yielding one clean database at 28d73fc95e5972af3403225a217def57dcaba3c4, tree 247ffa118a3e073e70825e62bde8c473d4ac6b45. Its original git archive is retained with SHA256 fcc2e8035756170b2dd9e292dcc8e6ee9194b35b6e50e54eab513269db3ccf4d. This is preparation evidence only; supply-chain policy checks are not claimed PASS.

## Original failures preserved

Local Y retains its missing fuzz index, Node SIGKILL, repository cross-device failure, missing cargo-deny rust-baseline failure, and W1 historical golden mismatch. Local Z retains its Node SIGKILL, PQ CLI compilation SIGKILL, strict Clippy SIGKILL, missing GNU time repository attempt, and later no-space repository attempt. A SIGKILL is not diagnosed as OOM from these logs. Successful desktop executions do not rewrite any local failure.

No production qualification, PQ network qualification, or full CI acceptance is granted by this inventory.
