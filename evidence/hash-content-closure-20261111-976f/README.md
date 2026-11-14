# Hash-content closure: preserved B execution observations

**Whole-chain status remains `HOLD_NO_GO`.** This C-prime preservation change modifies documentation, evidence, and corpus retention declarations. Rust, Cargo inputs, CI workflows, production selection, and the 19-purpose hash contract remain unchanged. B observations and later C-prime executions have separate source identities.

## Immutable source identities

| Role | Commit |
| --- | --- |
| Retained C5 base | `6ac9a79c2fb37d6102c526c354fe2d448a9f4e6d` |
| A: runtime implementation | `55c0d0ea1330d80120754718f2f47f6a4a709aa3` |
| B: reviewed checkpoint | `9fd6ee29a7a663cef547040d9d42cc36a371a17e` |

B's tree is `7351f83fa9ac5c0e7540fa64bce06ea6f328602f`; A descends from the base and B from A. Original B recorder guards checked **28,334 tracked entries / 2,578,874,762 actual bytes** before and after commands. The authority payload's `source_revision=A` is `fixed-reviewed-file-lock-only`, not B's execution identity.

Checksums bind observations and file bytes; they establish no quantum-security estimate, historical authority, or compiler/provider attestation. Qualification fields remain false or unknown.

## Retained artifacts

- [Cloud archive](cloud-b-observations-976f.tar.gz): **378,819 bytes / 70 members**, SHA-256 `bbc1785b2325a4bc6de2f92a6b84ed9a981b9cde61c1f08dc6d51ecd67e5e07d`; [wrapper](cloud-b-observations-976f.archive.json). Preliminary members retain their original scope.
- [ai395 Python archive](ai395-b-python16-controls.tar.gz): **61,196 bytes / 52 members**; [compact results](ai395-b-python16-controls-compact.json), [member hashes](ai395-b-python16-controls-members.json).
- [ai395 metadata follow-up](ai395-b-all-features-metadata.tar.gz): **72,694 bytes / 5 members**; [compact results](ai395-b-all-features-metadata-compact.json), [member hashes](ai395-b-all-features-metadata-members.json).
- [ai395 native archive](ai395-b-native-observations.tar.xz): **69,876 bytes / 76 members**, SHA-256 `6e22bc3eb6899fa894a1db2f9003729fb51ca2b12d3dfa46fd737d68a2215847`; [summary](ai395-b-native-summary.json), [native-only member hashes](ai395-b-native-members.json). Its `original-full-archive-MANIFEST.json` preserves the original manifest bytes. The original 521,055-byte gzip, SHA-256 `c33562ad099b83720e0578763ac89922d83813c7bb4ab1f2702d8f7c9be3a296`, remains on ai395; its duplicate cloud members are preserved separately above.
- Original [publication](mac-publication-public-summary-976f.json) and [PR body update](mac-pr927-body-update-public-summary.json) summaries retain their original bytes and describe draft [PR #927](https://github.com/TrillionniumFoundation/Trillionnium-Chain/pull/927) at B, not publication of C-prime.
- [File manifest](staging-manifest.json) excludes itself. [Hash-purpose review](final-b-hash-purpose-preservation-review.json) and the cloud wrapper explicitly identify reconstructed packaging observations; they do not claim recovery of unavailable outer-summary bytes.

## Executed B commands and retained failures

All **16 Python commands succeeded**. Six suites executed **350 tests, all OK, without skips**: hash-purpose 33, authority 18, source-integrity 43, recorder 9, CI-contract 187, corpus 60. Their semantic verdicts remain `HOLD_NO_GO`, `HOLD`, or `CURRENT_MAPPING_REPRODUCED_SECURITY_HOLD`.

The original **21 support requirements each have a successful B observation**. Cloud format, default workspace metadata, fuzz metadata, and compiler reporting succeeded. Cloud all-features metadata failed with exit 101 because `foreign-types 0.3.2` was missing offline; the independent ai395 follow-up succeeded with **182 packages / 182 resolve nodes / 26 workspace members**. The cloud failure remains intact.

| Focused native observation | Passed / failed / ignored |
| --- | --- |
| Cloud TCG3 default | 16 / 0 / 0 |
| Cloud M06 history default | 11 / 0 / 0 |
| ai395 M06 history all-features | 11 / 0 / 0; 162 filtered |
| ai395 Node history default | 7 / 0 / 0; 1,343 filtered |
| ai395 Node history all-features | 7 / 0 / 0; 1,421 filtered |

| Package | Default passed / ignored | All-features passed / ignored | Documentation passed |
| --- | --- | --- | --- |
| protocol | 113 / 2 | 113 / 2 | 2 |
| crypto primitives | 196 / 0 | 196 / 0 | 2 |
| data availability | 731 / 0 | 731 / 0 | 17 |
| MVCC/fee | 164 / 9 | 164 / 9 | 3 |
| release bundle | 55 / 0 | 67 / 0 | 0 |

These library totals are **1,259 passed / 11 ignored** and **1,271 passed / 11 ignored**, with no failures. Documentation has **24 passed**, no failures/ignored; release's zero is a zero-case harness. Configurations are not unique-test totals. Strict Clippy covered six packages, all targets/features, with `-D warnings`, exit 0; it is not a test harness.

The preliminary TCG3 **15/16 failure**, repaired-B **ENOSPC build without tests**, and distinct **16/16 success** are all retained. C5 remains **overall FAIL: 22/23 commands and 62/64 native controls**. Post-run ELF sidecars have `held_live=false`. Optional SQLite hard-I/O observation remains **UNQUALIFIED**, reporting `RUSTC must be absolute`; passing suites do not establish hard I/O preemption.

## Recovery and meaning

[Unpublished cloud C](unpublished-cloud-c-observation.json) records actual commit `d3d8089eefb8425f1ee1c7f3d1feb7d1e5c10843`, tree `832183cb5b0a58cb17df81c8580eceaea2e465a0`, parent B, 20 changed files/16 evidence files. Initial `git add` failed with ENOSPC/128 before staging or commit; task-owned cleanup preceded successful staging/commit. Afterwards the disconnected executor rejected bundle/preflight process creation after a 45-second recovery timeout. C was not transferred, published, or tested. C-prime is a new equivalent preservation commit, not recovery of C's exact bytes.

[Recovery observations](recovery-observations.tar.xz) preserve the separate ai395 recorder refusal before preflight started, index forensics, 115 missing compressed files, and untouched old checkout. A separate complete B checkout passed the original guards/preflight. Later C-prime gates are recorded externally against C-prime, without borrowing B or lost-C execution identity.

TCG3 reads declared typed edges from verified canonical bytes under one independent full root pin: **256 nodes, 1,792 objects, 1,536 edges, depth 32**, shared budgets, complete bytes/EOF. Reserved prefixes do not discover arbitrary loader/ELF/JSON dependencies. V2 semantics stay unchanged.

CMH2 reads genesis-to-tip State/configuration and header/trace ancestry, admitting at most **32 non-genesis blocks / 32 MiB**; longer histories are refused, never tail-truncated. Node source admission is **128 MiB** with a **30-second cooperative deadline**; PQ-account snapshots and the growth backend are refused. This is no hard RSS or preemptive-I/O budget. Static review found late legacy-context rejection before successful readback and existing non-State metadata allocation outside CCH budgets.

Transaction/proof/receipt bodies, W1/effects, finality, prior key ownership, historical truth, migration authority, and activation remain outside scope. Rehashing an old SHA-256 digest cannot restore lost distinctions. All 19 purpose qualifications retain their original null/false values.
