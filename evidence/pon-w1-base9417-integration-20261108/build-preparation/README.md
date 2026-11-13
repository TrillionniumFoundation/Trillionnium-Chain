# C8 copied-cache preparation, owner launch failure, and strict import

This bundle binds the preparation and owner qualification for source `4e007a87ceecbec8d265f6a70cfd71d512a514b5`, tree `19a4f1a6e1cec5c27e595fa555b97cddc4717a3c`. It records three independent cache copies, a preserved owner launcher validation failure, the corrected external launcher, the completed owner qualification, and a strict import of its original evidence. It does not record a C8 runtime operation, timeout, refund, or cold reconciliation.

**Runtime readiness is blocked at this freeze.** The first same-source staged32 job `1a1ba8f182e-12894-1b97` failed with exit 1: 31 methods passed and 1 failed. Across the original eight qualification groups, this is **73 commands, 664 passed methods, 1 failed method, and 4 ignored**. The proposal's 665-method number is an expected coverage contract, not an observed initially all-green result.

## Cache origins and actual copy results

| Component | Regular file entries | Logical bytes | Copy result | New-stage origin |
| --- | ---: | ---: | --- | --- |
| Backend | 3,921 | 1,747,114,780 | Complete; direct child waited; exit 0 | Independent copy of the qualified C7 backend cache |
| Native/verifier | 2,014 | 923,467,631 | Complete; direct child waited; exit 0 | Independent copy of the qualified C7 native cache |
| Owner | 3,065 | 1,676,857,236 | Complete; direct child waited; exit 0 | Independent copy of the already built C7 debug owner and History release cache |

Each copy had its own declared 1,800-second preparation bound and completed before the next copy began. The receipts retain source ELF hashes and stat inventories before and after copying, initial destination ELF identities, and zero source-inode sharing, destination hardlinks, and duplicate destination inodes. Reflink copy-on-write extents may be shared. The old C7 targets and all prior operations remain preserved.

All three C8 targets have `fresh_cargo_target=false`. Registry and toolchain caches are reused. The owner's earlier C7 empty-target creation is historical provenance; it does not make the C8 copied target empty or an independent cleanroom build. Initial copied C7 executable hashes are not C8 qualification hashes. New C8 backend/native qualifications are separately pinned, and the owner qualification below binds its actual C8 Cargo artifact and executable.

## Preserved launcher failure and new qualification

The original owner job `1a1ba70f3e9-12894-1ab5` failed with exit 1 before creating the owner binding or executing the qualification driver. The frozen plan's cache description began `Independent copy`; v1 asserted that it contained `copied`. This was a launcher validation error, with **zero qualification commands and zero executed test methods**.

The original script, plan, traceback, process identity, and terminal records remain unchanged. V2 changes exactly three lines: the cache description guard now equals the original complete description, and the output and binding names use the independent `02` namespace. Actual source, copied-cache, inode, ELF, and 19-command guards remain in force.

The new owner job `1a1ba7cdd03-12894-1b0d` completed with authoritative exit 0 and complete, durable output. All **19 commands** succeeded. The actual test totals were **37 passed, 0 failed, 4 ignored**: M12 11, Node short paths 20, legacy admission 1, and legacy reorg 5. Source-before and source-after both bind exact C8. The separate new historical module's 10 regressions are not added to this owner total. History release compilation and listing execute no ignored test methods.

## Strict owner import

Job `1a1ba85c4c0-12894-1b51` completed the read-only import with exit 0. It independently rehashed and copied all **38 original stdout/stderr logs**, reparsed the Rust outcome summaries, verified both source identities, and selected the unique original no-run Cargo test artifact. It also checked the actual executable, current compiled checkout observation, original copied-cache receipt, launcher binding, unchanged plan and qualification driver, and both original job exits.

The C8 owner ELF is 467,190,280 bytes with SHA-256 `1cc1db569c0d21f27aabc3ddbef4730ce11a6481c026b35ed69460c09028d456`. The import records executable pins; executable bytes are not published here. The import performed no Cargo build, Node run, new test method, operation, or deadline selection. Its mapped manifest is explicitly derived and does not impersonate a previously existing root artifact.

## Original staged failure retained

The original staged manifest has `qualification_complete=false`. Its raw stderr reports `Ran 32 tests`, 31 `ok` results, and one failure in `test_ignored_sigterm_escalates_and_output_overflow_remains_failure`. The test expected `SIGKILL_DURING_SETTLEMENT`, but the actual result was `DEADLINE_EXHAUSTED_BEFORE_SPAWN`. Source-before and source-after both succeeded. The original 0.2-second fixture deadline is retained; the actual measure function uses the pre-existing 5-second default settlement grace. A test patch to 0.15 does not change that default argument, and 0.15 is not reported as the observed grace.

The first failure and its full job metadata, manifest, and raw logs are included. No repeat or research operation is run by this bundle. Any later separately declared repeat must be recorded as another attempt, retain this failure, and distinguish selected successful coverage from cumulative attempted tests. The unexecuted v1 preparer and proposal are preserved as drafts; a later binding must also explicitly retain the original failure and the unique repeat rather than treating the original suite as all passed.

## Prepared research code and boundaries

The unchanged driver-v4 has SHA-256 `b66019d2f47c225174de4f69c508e2b163d69f915b1e9eada59eef9368317464`. The C8 preparer fixes a new C8 experiment namespace and the actual qualified C8 inputs. It requires a later immutable eight-component gate binding, its exact digest, original successful job exits and raw command logs before creating an operation. The included proposal is an unstarted plan: operation ID, clock, and deadline are unset.

A later authorized C8 experiment would have one original 120-second runtime budget, 8 CPUs, 8 GiB, two segment workers, two compression workers, and Rayon 4. Its target timeout would precede typed Failure Unknown, explicit owner veto/NativeCancel, canonical fork removal/restoration of the same Cancel, and independent cold reconciliation. This bundle claims none of those runtime outcomes. Unknown GPU and full historical accounting cannot authorize provider payment or full cap release. A deterministic independent Node fixture's gross principal 1,000 cannot be added across C5/C6/future C8 as new global funds. The C7 launch-Unknown request is frozen and is never replayed.

## Evidence layout and precision

Top-level files provide the three copy receipts, the original launch failure, successful owner/import records, the derived owner qualification, and the unstarted research proposal. `raw/` retains allowlisted source receipts, original job metadata/logs, scripts, and all strict-import source records. `raw.tar.gz` has the exact same raw members, individually checked for byte length and SHA-256. `manifest.json` inventories every member and primary copy.

The earlier derived `backend-native-terminal-01.json` contains JSON-decoded `request_fingerprint` integers above JavaScript's exact integer range. Those numeric fields are not used as exact request identity. Original job IDs, launch nonces, string digests, and source/artifact hashes have separate bindings; no old derived JSON is silently rewritten. Original job metadata is retained as raw bytes. Packaging does not publish private SQLite databases, executable bytes, inherited environments, or credential-bearing request files. Packaging preflight is recorded separately and adds no source qualification methods or commands.
