# Hosted CI review — PR #838 frozen code commit

Report compiled: **2026-11-09 13:47:38 UTC / 08:47:38 America/New_York (EST)**.
Last inspected repository-truth status: **2026-11-09 13:45:30 UTC**.
Read-only inspection; no source edits, reruns, cancellations, or workflow dispatches.

## Identity and scope

- Repository: `TrillionniumFoundation/Trillionnium-Chain`.
- PR: https://github.com/TrillionniumFoundation/Trillionnium-Chain/pull/838
- Frozen code commit: `51683089c7ec75cca3e0bcfb2201c08aa5dab654`.
- Tree: `c85745e3396723b07bda7c86a36618c7863e65a5`.
- Parent / compared baseline: `e2a02f9271b49f146e70806c8a66e161b5973971`.
- Commit: https://github.com/TrillionniumFoundation/Trillionnium-Chain/commit/51683089c7ec75cca3e0bcfb2201c08aa5dab654

The nine changed paths are the development plan, fixed probability cost contract, new frontier Markdown / Python / tests, formal README, and three CI registration / contract files (`scripts/ci/check_ci_contract.py`, `scripts/ci/ci_job.sh`, `scripts/ci/test_ci_contract.py`). They do not include the historical implementation contract, Rust main.rs, store.rs, or lifetime ledger implementation.

## 1. W1 QROM implementation (head, x64): inherited historical input rejection

Current job: https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42627428643/job/129194708270

- Run `42627428643`; job `129194708270`; frozen head SHA matches the code commit above.
- Started **13:39:49 UTC**, completed **13:40:39 UTC**, conclusion **failure**.
- Ordered source identity verification before and after execution passed; project preflight passed.
- Fixed named controls failed at approximately **13:40:33 UTC**. The implementation audit group ran 19 tests and reported **2 failures and 2 errors**.
- Shared originating error:
  `AuditError: input exceeds bound: formal/pon-nakamoto-v1/w1_v2_verifier/src/main.rs`.
- Errors: `test_actual_saved_v2_mapping_keeps_all_security_claims_unqualified` and `test_import_cache_and_search_path_cannot_replace_checked_helper_bytes`.
- Failures: `test_changed_seal_word_is_rejected_by_full_artifact_identity` and `test_changed_source_snapshot_is_refused`. These expected `pinned input drift`, but the earlier main.rs byte bound rejection prevented that branch.
- Workflow gate `setUpClass` separately errors from the same bound rejection; no methods in that class ran.
- The direct mapping command at **13:40:34.3210013 UTC** returned `{"result":"INPUT_REJECTED","reason":"input exceeds bound: formal/pon-nakamoto-v1/w1_v2_verifier/src/main.rs",...}` with exit code 2. This is an application-level fail-closed result.
- Failure artifact upload succeeded: https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42627428643/artifacts/13678648694

### Exact baseline comparison

Baseline job: https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42575267240/job/129021450451

This job ran the parent commit, started **06:47:59 UTC**, completed **06:49:11 UTC**, and failed. Its fetched log independently shows the **same main.rs bound rejection**, the same 2 failures / 2 errors, the workflow gate class setup error, and the direct `INPUT_REJECTED` result around **06:49:04 UTC**.

GitHub file reads at both refs confirm:

| Path | Same Git blob at both refs | Relevant contents |
| --- | --- | --- |
| `config/pon/w1-qrom-implementation-v1.json` | `b8fe1e3f00d171400f57426dc3aa04d7b6faa0ca` | main.rs pinned byte bound **9,233**; pinned SHA-256 `07415e8e3bb53f3e81dd489e4ebda63368170efbe4a217ae6b0dd6cc0af14128` |
| `formal/pon-nakamoto-v1/w1_v2_verifier/src/main.rs` | `1b2999ec2efb51b1291e4fac19f55ee0afeb5d75` | Actual UTF-8 bytes **11,172** |

The historical contract declares `source_base_commit=cb114b13bf848a77634e40a08b31b30c7c758e7b`. The audit loader applies each pinned `bytes` value as an input bound. The head therefore inherits an already failing historical pin/current-source pairing. This finding does not justify silently refreshing historical pins.

The prospective merge job `129194708838` also has failure metadata, but its log was not independently examined; this report does not assign its exact cause.

## 2. W1 QROM closure: second inherited source identity rejection

Current head job: https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42627428712/job/129194708307

Its fetched log shows:

- At **13:41:28 UTC**, `test_w1_lifetime_ledger.LifetimeLedgerTests.setUpClass` errors with
  `LedgerError: source identity mismatch: trillionnium/crates/trnm-pon-node/src/store.rs`.
- This class reports zero executed test methods and one error. The fixed roster checker subsequently refuses `required named completion differs: started_ids`.
- At **13:41:48 UTC**, the direct ledger command returns
  `{"status":"REFUSED","error":"source identity mismatch: trillionnium/crates/trnm-pon-node/src/store.rs"}` with exit code 2.
- Before / after ordered source verification passes. The final stage completion gate fails.

Baseline head job: https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42575267136/job/129021450243

The parent job started **06:48:00 UTC**, completed **06:49:33 UTC**, and failed. Its fetched log independently contains the **same store.rs source identity mismatch**, class setup failure around **06:49:06 UTC**, and direct ledger refusal around **06:49:26 UTC**.

This exact failure was therefore already present on the parent. The prospective merge closure job was not independently log-reviewed.

## 3. Repository-truth / work-native-model: outcome still unresolved at observation time

Run `42627428812` (`trnm-required-baseline`) was read through the GitHub API with `per_page=100`; it returned all **18 jobs**.

| Job | Link | Last observed state at 13:45:30 UTC |
| --- | --- | --- |
| repository-truth head, `129194709339` | https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42627428812/job/129194709339 | Started 13:39:55; **in_progress**, conclusion null; actual repository-truth checks running |
| repository-truth prospective merge, `129194710086` | https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42627428812/job/129194710086 | Started 13:43:51; **in_progress**, conclusion null; same lane on prospective merge running |

The head completed checkout, ordered source verification, provider / host CI wiring and dependency setup successfully before the running check step. A log fetch while it was running returned storage `404 BlobNotFound`; that establishes only that the requested log was unavailable at that moment, **not** that the checks failed or that runner infrastructure caused a job failure.

No separate job named literally `work-native-model` was found in the complete baseline job listing or workflow source search. Local source instead identifies a **work/native model control group inside repository-truth**: `test_work_native_model_controls_cannot_be_omitted_or_moved`, and the checker assertion `work/native model controls must execute exactly once in repository-truth`. The workflow invokes `bash scripts/ci/ci_job.sh repository-truth` for the head and the corresponding prospective merge lane.

No completed outcome for those controls is established here. Do not turn this inspection into a repository-truth pass, native-model pass, or a claim that all nine changed files are regression-free.

## Attribution and practical conclusion

| Classification | Supported finding |
| --- | --- |
| Baseline / inherited | The two directly inspected QROM head failures reproduce the same application-level rejection in hosted runs of the parent commit. |
| Infrastructure | No infrastructure root cause was established for those two failures. The in-progress repository-truth log retrieval 404 is insufficient evidence of one. |
| This change | No inspected failure was shown to originate in the nine-file diff. Repository-truth and its work/native model controls were still unresolved when observed. |
| Unexamined | Prospective merge log causes, unrelated workflow failures, and final completion of all hosted CI were not inferred. |

PR draft / HOLD remains appropriate. This review neither changes the 16 actual cost points from null / unproved nor demonstrates an unconditional W1 lower bound. Hosted baseline failure classification is not an overall CI pass.

