# Fixture-composed full 974: actual terminal supplement

This package records the completed original-profile native Node run. It preserves the earlier PENDING prepublish snapshot unchanged.

## Actual native outcome

- Registered: **974 = original 971 + the three named diagnostic tests**.
- Actual terminal: **950 passed, 1 failed, 23 original ignored**.
- Actual native exit: **101**; timeout: **false**; original reader error: **null**.
- Original supervisor: **2700 seconds**. No budget was changed.
- Recorded wall time: **1384514025368 ns**; libtest's own final summary reports **1384.48 s**.
- The driver exited 0 after preserving the actual native failure; driver completion does not mean native acceptance.

The sole failed selector is `store::pq_rollback_witness::combined_tests::guarded_npq6_submit_recovers_after_invalid_signature_and_independent_process_restart`. The retained raw output reports an independent witness child failing before readiness with `Os { code: 1, kind: PermissionDenied, message: "Operation not permitted" }`. This remains a failure; it is not converted into a pass, waiver or new ignored test.

The independent reader validates the final EOF summary, all actual success/failure/ignored names, no duplicates, pairwise disjoint sets, full 974-name coverage, the exact original 971-name union with the three additions, and the unchanged original 23-name ignored set. It agrees with the original driver result and actual exit.

## Source, ELF and chronology

The execution plan retains its actual base `8ebded733d90bf74e7d8e3adbd2458ad8b572159` and the reviewed working-tree native inputs. The frozen 1190-path native manifest is `545222b5d1baa03ca3403375170c30416b8351fdc570e5d994603c3fb2fcaa82`. Its Cargo-produced Node ELF is `34bd6631d69e093be42a35e89ce3d989d60f7cee4f7eb75d1c0f0527c43d7acf`; the original run records the same ELF unchanged.

The clean exact-commit gate for `c5dd7c7718925b951dc6e4d5ccc5a86ccfa8e3c1`, tree `30f59a8ec2abdc269bf91e228c58206b23add43d`, completed at **2026-11-03T22:10:08.051381+00:00 while the full native run was still in progress**. It verified all 1190 native file bytes against the frozen build manifest. The native driver recorded completion at **2026-11-03T22:16:52.525096+00:00**; its terminal native manifest matched the same bytes again.

No full native run was launched or repeated from the clean c5dd checkout. This association does not claim that every tracked file in the later commit was an input to the native build. The main workspace's later one-line W1 workflow source-receipt correction is outside these native inputs; this package makes no whole-current-worktree clean claim.

## Lossless records and limits

`native.log.gz` retains the complete **7,289,315-byte** raw log, SHA256 `5204bbe992a2a21216aa44ffa521e602d2cd0ec0ca57fe40d8a97f0954ac86a1`. Both gzip outputs use `mtime=0`. `terminal-records.json.gz` preserves 33 original records in 26 deduplicated byte blobs, including the original execution plan, result, driver, source manifests, terminal receipt and clean-commit association receipts. Original receipt bases and outcome fields are unchanged.

The prior diagnostics-only ELF/result and older b280 results are not inherited. Parser preparation used the already-frozen b280 log solely to exercise actual libtest output grammar; it was not an input to this run's result.

This package qualifies the integrity and completeness of this native terminal evidence. It does not qualify real-Host execution, original 4s/F0/three-campaign performance, scientific/model evidence, or production activation. The nine-Host-selector and service gates retain their own source-specific outcomes.
