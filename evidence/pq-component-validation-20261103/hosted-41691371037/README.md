# Chain PQ witness CI evidence — original run 41691371037

Status: **original four-lane CI remains FAILED; whole-chain qualification remains HOLD / UNQUALIFIED.**

This package preserves the original results from [GitHub Actions run 41691371037](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/41691371037). It is a byte-preserving repack of supplied official artifacts, not a new CI execution or a repaired result. No Rust command was run while preparing this package.

## Exact source scope

- Head source: [`45962558a7133375b16c0ac2600f2edb4a115585`](https://github.com/TrillionniumFoundation/Trillionnium-Chain/commit/45962558a7133375b16c0ac2600f2edb4a115585).
- Actual prospective merge: [`9762e8e5c0485d148a01cf0810790497cb21968f`](https://github.com/TrillionniumFoundation/Trillionnium-Chain/commit/9762e8e5c0485d148a01cf0810790497cb21968f).
- Both recorded source trees: `8d1d6c4e18e395dfc842c3401844a8ddcd4c01d9`. Equal trees do not make the head and prospective-merge source identities interchangeable.
- The two supplied four-matrix summary JSON files are copied without changing any byte or selecting fields. Original command receipts and complete logs are retained inside the archive.

## Retained original results

Counts are per lane and must not be added together as unique test coverage. The full artifacts retain the same control records as the earlier controls artifacts; those are overlapping evidence, not additional executions.

| Lane | Full artifact ID | Earlier controls artifact ID | Source kind | Controls passed / failed | Full Node passed / failed / ignored | Build / strict Clippy exit codes |
| --- | ---: | ---: | --- | --- | --- | --- |
| x64-head | 13263326083 | 13262116480 | head | 42 / 1 of 43 | 940 / 1 / 23 | 0 / 0 |
| arm64-head | 13263262338 | 13262010223 | head | 42 / 1 of 43 | 940 / 1 / 23 | 0 / 0 |
| arm64-merge | 13263163201 | 13261235455 | prospective-merge | 42 / 1 of 43 | 940 / 1 / 23 | 0 / 0 |
| x64-merge | 13261143324 | 13260673197 | prospective-merge | 42 / 1 of 43 | 940 / 1 / 23 | 0 / 0 |

All four full Node runs exited **101**, with **940 passed, 1 failed and 23 ignored**. Each original 43-selector controls batch contains **42 successes and 1 failure**. Build and strict Clippy exited **0** in every lane. Both added witness tests passed in each full suite:

- `pq_rollback_witness::tests::known_checkpoint_preserves_exact_retry_and_unobserved_other_writer_progress`
- `pq_rollback_witness::tests::known_checkpoint_refuses_local_cas_conflicts_before_signing_or_transport`

The retained failing selector is `store::pq_rollback_witness::tests::exact_cas_retry_is_idempotent_but_fork_skip_and_wrap_refuse`. Its original assertion expected `PQ_WITNESS_CAS` and received `PQ_WITNESS_OBSERVATION_ROLLBACK` at the new client-entry consistency check. Source review identified an expectation mismatch caused by the intended earlier refusal. That explanation does not turn the original test or the full suite into a pass. The archive retains each original exit code, failure log and diagnostic record.

## Later test correction is a separate source

The published correction [`8a74a9e42a9efbc52d83e861f64f03efd40f1406`](https://github.com/TrillionniumFoundation/Trillionnium-Chain/commit/8a74a9e42a9efbc52d83e861f64f03efd40f1406), tree `3d3ab7ff49c7f0b9109ba9e5ede1362cf6b290e7`, preserves the original exact retry, sequence-skip and overflow controls, checks the known client's earlier local refusal, and uses a fresh client against the same existing owner to retain the original remote CAS refusal check.

**Native verification of that final correction was pending at this packaging handoff and is not contained in this archive.** These `45962558` / `9762e8e5` results cannot be relabelled as execution of `8a74a9e4`. The parent task will attach any later exact-source native receipt separately, retaining earlier failures.

The separately supplied local `witness-validation-45962558.tar.gz` receipt is not included here and does not supply final-correction evidence. Its parent-task identity is 105,006 bytes, SHA-256 `9dc5fc7159c99811dab7185fde572ba8d9cedeefe5d4e95320761f310f6c10ea`; publication of that independent local record is handled separately.

## Archive identity and byte preservation

- Archive: [`chain-pq-ci-run-41691371037-full-members.tar.xz`](chain-pq-ci-run-41691371037-full-members.tar.xz)
- Compressed bytes: **705,720**
- Archive SHA-256: `4f218c1f30760e81ab06740c3a7db02a0667d510385bdca8fa58cdba3f9157f6`
- Original full-ZIP payload members: **652**, totalling **40,861,110 bytes**.
- All **636** earlier control-ZIP members were compared byte-for-byte against their paired full ZIPs; every one is identical and is already retained in the full payloads.
- The archive contains **656** members: **652 original payload members plus 4 metadata copies**.

Each original full member is stored under one namespace: `x64-head/`, `arm64-head/`, `arm64-merge/` or `x64-merge/`. Its bytes are unchanged. No log is truncated or reformatted, and no JSON field is discarded. `metadata/` contains byte-identical copies of the two manifests and two summaries presented alongside this README.

**The new TAR/XZ hash is not any original GitHub ZIP hash.** The archive preserves uncompressed ZIP member bytes, not the original ZIP container representation, its central directory or its filesystem metadata. The original container sizes and hashes below apply only to the supplied `.zip` files. Deterministic TAR metadata is documented in `full-members-manifest.json`.

| Lane | Artifact role | Original ZIP artifact ID | Original ZIP bytes | Original ZIP SHA-256 |
| --- | --- | ---: | ---: | --- |
| x64-head | full | 13263326083 | 1,051,983 | `ea68862d35c9b480b557124c69ae80d904450f21ab6320d1be210310329292c1` |
| x64-head | controls | 13262116480 | 288,442 | `016ea69f8252c3d349f87e44455b2f0062d74d994364746836bcf3450e7987b3` |
| arm64-head | full | 13263262338 | 1,050,492 | `f5611e19ecf131726a908055ca6811907945419430babe87534e7671cd387f64` |
| arm64-head | controls | 13262010223 | 286,739 | `59e1079b8aa0fa6e93e30c9bc8fdc8754f58c77f1265e4a6a60b64583da0403f` |
| arm64-merge | full | 13263163201 | 1,053,443 | `8000f4b33ebbd684ccd3cfe86d3dfb5902f242057ae28c4d0152de3414a6cd85` |
| arm64-merge | controls | 13261235455 | 289,930 | `7fd2188a724fc89fdfb79a2bc071ba97957d468f11c38a81520f4d3e7b2503c0` |
| x64-merge | full | 13261143324 | 1,054,346 | `483a5e13f45c852d1435c2d44bb0eac403ab3eea1e208cf4d09c19c138121e2d` |
| x64-merge | controls | 13260673197 | 290,939 | `bac495a00b40d16c15bd59f361f51276ce475c14d90283184d4beede2c0bbc22` |

## Browse and verify

- [`source-artifacts.json`](source-artifacts.json): all eight original ZIP sizes, hashes, run/artifact URLs and source identities; exact control-to-full coverage.
- [`full-members-manifest.json`](full-members-manifest.json): every original full member's source artifact, original path, archive path, byte count, SHA-256 and original CRC32.
- [`four-matrix-controls-summary.json`](four-matrix-controls-summary.json): unchanged supplied summary, including all failures and diagnostic fields.
- [`four-matrix-complete-summary.json`](four-matrix-complete-summary.json): unchanged supplied build, strict Clippy and full Node summary.
- [`archive-verification.json`](archive-verification.json): archive identity and verification of every payload and metadata member against the manifests, plus unchanged-input checks.
- [`package-inventory.json`](package-inventory.json) and [`SHA256SUMS`](SHA256SUMS): outer package file inventory and hashes, with explicit self-exclusions.
- [`package-ci-evidence.py`](package-ci-evidence.py): standard-library-only packager and archive verifier; it executes no repository code.

To verify the downloaded package without extracting its logs or rerunning tests:

```sh
sha256sum -c SHA256SUMS
python3 package-ci-evidence.py --verify-only
```

The verifier requires all 652 original members, checks every member length and SHA-256, compares all four embedded metadata files with their outer copies, and refuses missing, duplicate or extra members. This establishes packaging integrity relative to the recorded supplied artifacts; it is not a cryptographic attestation of test execution or whole-chain security qualification.
