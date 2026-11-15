# Validation inventory

Generated 2026-11-11T06:36:28.766838+00:00. Exact current source: `cdd984808a088e6c2e13b1e1ae6630a94d500c89`; tree `1ed39b6ebe55cb00c238f26f6bfc9361ab93faec`.

63 original terminal records are preserved by host and source: 50 PASS and 13 FAIL. One separate original empty result is `INCOMPLETE_EMPTY_RESULT`; it has no fabricated return code and is counted as neither PASS nor FAIL.

| Host | Source commit | Terminal records | PASS | FAIL |
|---|---|---:|---:|---:|
| desktop | cdd984808a088e6c2e13b1e1ae6630a94d500c89 | 17 | 14 | 3 |
| local-cloud | 90ee47159e32e9014410a1823bed05d84c17b858 | 16 | 11 | 5 |
| local-cloud | cdd984808a088e6c2e13b1e1ae6630a94d500c89 | 30 | 25 | 5 |

## Preserved validation results

The local M06 run executed 18 actual test binaries: 272 passed, 0 failed, and 9 ignored. The five new account development scope tests all passed. Their actual Running paths, post-run SHA256 values, sizes and stable-stat observations remain unchanged in the JSON inventory.

The desktop primary queue retains five PASS records, including the four new Node tests and strict workspace Clippy with all targets and all features under -D warnings. Earlier local SIGKILL and tool/environment failures remain original FAIL records and are not retroactively replaced.

The original full rust-baseline is FAIL, return code 101. The actual data-availability library reported 713 passed, 2 failed, 0 ignored. Its retained TCP shared-quota test returned Unavailable; the retained RS46 shard-plan test returned RS46 provider deadline. Complete panic text and logs remain in the frozen full Rust archive. Its supply-chain subgate independently passed all seven original subprocess observations, with qualification still false. The later feature-off record passed one test, and the original queue source-after verified clean exact Z.

## Two independent Node follow-up queues

The original Node scoped queue has a PASS preflight and an empty result for all-targets. Its original stderr records LLVM ENOSPC, its stdout is empty, and source-after was absent. The runtime outcome was unknown without a confirmed terminal receipt. The old dedicated target was subsequently absent; the disappearance cause remains unknown. No target cleanup or actor is inferred. All original bytes and incident observations are preserved in a separate archive.

The DATA-volume queue uses different record IDs and a different target directory. Its four captured terminal records are:

| Record | Result | Return code |
|---|---|---:|
| node-retained-data-preflight | PASS | 0 |
| node-retained-data-source-before | PASS | 0 |
| node-retained-data-all-targets | FAIL | 101 |
| node-retained-data-source-after | PASS | 0 |

Actual Cargo Running headers from the DATA all-targets stderr:

- `Running unittests src/lib.rs (/data/chain-pq-a418-node-retained-target-20261111/debug/deps/trnm_pon_node-2cfc25289c60243c)`

Original test summary lines, including nested subprocess output; these are not added together:

- `test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 1401 filtered out; finished in 0.00s`
- `test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 1401 filtered out; finished in 0.00s`
- `test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 1401 filtered out; finished in 0.00s`
- `test result: FAILED. 1359 passed; 4 failed; 39 ignored; 0 measured; 0 filtered out; finished in 7809.10s`

Target compilation is not counted as target execution. This queue does not replace the original incomplete attempt or the original full Rust failure.

## Evidence and interpretation

The JSON inventory records the complete result objects, original context/stdout/stderr hashes, frozen archive and transfer hashes, and all actual observed test totals. Archive members, manifests, and extracted bytes were reverified before this update. The previous 58 record objects are unchanged.

The original before-additional-desktop snapshots and the exact before-node-queues snapshots remain separately preserved. The historical old-target Node ELF hash remains a post-run observation from that time, not a claim that the disappeared target currently exists.

No full CI, production-node or PQ-network qualification is granted. Ignored tests, missing tools, incomplete receipts, and compiled-only targets are not promoted to PASS. Y and Z source cohorts and local-cloud/desktop hosts remain separate.
