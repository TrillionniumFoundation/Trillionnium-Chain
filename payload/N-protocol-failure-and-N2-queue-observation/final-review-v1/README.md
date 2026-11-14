# N protocol failures and N2 required-workflow observation

## Result

Both completed protocol jobs in run 43582713392 fail the original `confirmation_report` acceptance with `CONFIRMATION_TARGET`. The five original named Rust invocations, service report and sustained report passed. This is a genuine business-confirmation acceptance failure; seven successful Submit ACKs do not establish a confirmed transaction.

The source is N `5a4b7fe8de1adce803184f262fd9f704ead1930c`, tree `4bc5ade0813ba3172eeb0ad7425358469a1b1edd`. The prospective job actually tested commit `6936874e73bef2b6629c132e1a214f281f49ef3d` with that same tree. Full original before/after source identities remain in the outer logs and Host-controller records. No result here is credited to R1.

| Sample | Original job / artifact | Attack-free baseline | Original 4-second / 16-worker pressure |
| --- | --- | --- | --- |
| Head | 132415017391 / 14111407094 | 7/7 replay accepted; 1 confirmation; latency 3,191,524,607 ns | 7 ACK; 1 history/replay; 0 accepted; 0 confirmed |
| Prospective | 132415017476 / 14111816359 | 7/7 replay accepted; 1 confirmation; latency 2,877,186,997 ns | 7 ACK; 2 history/replay; 1 accepted; 0 confirmed |

Head pressure replay 0 ran from 1,793,263,152 to 4,090,965,490 ns, wall 2,297,702,338 ns, calling-thread CPU 89,051,928 ns, then returned `PUBLIC_REQUEST_DEADLINE`. Prospective replay 0 succeeded at 3,365,724,546 ns; replay 1 ran from 3,465,184,758 to 4,061,195,689 ns, wall 596,010,931 ns, calling-thread CPU 36,714,448 ns, and returned the same deadline error.

In each pressure phase the exact required flags `finite_business_target_met`, `full_native_state_equal`, `client_confirmed_before_original_window_end` and `overlap_demonstrated` are false. All four are retained; this review does not narrow the original multi-field guard to a single condition. The calling-thread CPU and wall scopes differ; no additive CPU accounting or unique scheduler cause is inferred.

The outer Host controller reports child exit 1, `failure:null`, `final_host_errors:[]`, with preparation completed. This is not an outer timeout, an observed Host fence failure, a compilation failure or an observed source-pin failure. The failing child argv is `python3 scripts/ci/run_from_zero_native.py --out /home/runner/work/_temp/ci-observations/from-zero-native`.

## Current-head observation

The bounded, completed GETs show PR847 head N2 `096c6b5f9b952c49389fd975515744074ba61317`. Required workflow run 43588788281 is `pending`, conclusion null, and has zero jobs in the original response. Check pagination is complete: 146 records across two pages, with no duplicate IDs. Main protection requires strict matching and app 15368 for repository-truth, protocol-contract, fuzz-smoke, external-evidence-contract and rust-baseline. None of those five context records appears for the observed N2 head.

The original PR and PR readback bytes match. These are timestamped observations, not a promise that remote state remains unchanged. Older N successes or in-progress jobs are kept separate and do not satisfy N2 requirements. Four N Rust shards were still in progress in the last retained old-run response.

## What the selected local R1 changes

The immutable comparison uses N, N2 and R1 `2a86462a1ab20c68151719ba4635e3c294391e64` (tree `5c26776f96f15fd131e85a5c2d7c5e895ad7fab4`). It does not inspect or modify the live root worktree.

The native acceptance runner, Host controller and original `public_v3_from_zero.rs` fixture are byte-identical across all three commits. The six selected protocol paths are identical from N to N2. R1 changes `public_v3.rs` through the independently reviewed P1 immutable-prefix cache and restores `store.rs` to selected C0/M6 blob `d596dc6bab16698cd18bcc15bcbbe1fafedf603e`. R1's only selected `ci_job.sh` delta is the unrelated owned-process collector count 14 to 16.

This review supplies no R1 hosted 4-second / 16-worker acceptance result. Neither the pure-prefix component controls nor the restored store ordering demonstrate that the original gate now passes. It also does not predict a new R1 failure without running that source. The two N samples remain distinct from earlier C0 and e40d samples.

## Retained originals and proof

- `initial-GET-v1/`: complete two failed job logs, original job/run/PR/protection responses, bounded request receipts and raw stderr.
- `current-head-and-artifacts-GET-v1/`, `required-pagination-GET-v1/`: complete check pagination, current and old required-run responses, artifact metadata and PR readback.
- `official-complete-artifacts-v1/`: the two full ZIPs, original API/upload SHA binding, all 109 members per ZIP validated for CRC, byte size, SHA, duplicate/path/symlink safety, and completion receipts.
- `inner-originals-v1/`: exact selected original manifests, child process records/stdout/stderr and Host records. The large reports and SQLite/source payloads stay in the complete ZIPs; they are not duplicated.
- `actual-guard-and-acceptance-v1/`: exact acceptance guard excerpts and typed ACK/acceptance extraction.
- `protocol-source-comparison-v1/`, `immutable-N-R1-source-delta-v1/`: immutable Git objects, raw bounded deltas and exact selected source identities.
- `acquisition-producers-v1/`, `actual-tool-records-v1/`: producers and complete original terminal archives; a returned-page label does not truncate the archived full terminal.
- `final-review-v1/review.json`: exact review facts, source identity mappings and limitations.
- `ARCHIVE_MANIFEST.json`: strict file roster before its own creation and the seal. `ARCHIVE_SEAL.json` binds that manifest. Materialization explicitly adds both metadata files.

ZIP 14111407094 is 7,039,235 B / SHA256 `3a7ee31f6b28d9b283e2829dcea3e7ca4a415c14a88ba5cc6f16f408ac877086`.
ZIP 14111816359 is 7,283,601 B / SHA256 `954a7541c58b9117b8af08de3b9f0e0a096009f466c2ad96e916b6376484eed0`.

The original confirmation report member in each ZIP is `from-zero-native/confirmation/report.json`: head 12,179,136 B / `6ca59b1b4d4b0af4f3cd615a9ec1860e722fc1721bf5a36e8e071ae80e455748`; prospective 13,889,043 B / `1814ade47a1c616c96cdb95b5e510ff3ec07c922a43549f53a6f6e26ec4de68f`.

This work performs read-only acquisition and analysis. It does not execute artifact code, invoke native/Host tests, alter deadlines/workers/fixtures/quota/check frequency, change source or refs, cancel CI, or publish. Temporary signed download URL queries and credentials are excluded. ZIP integrity establishes the bytes retained, not complete repository semantic correctness or any production qualification.
