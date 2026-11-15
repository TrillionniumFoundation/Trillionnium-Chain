# PQ source pin integration repair and retained CI failures

The first published source `dcd114a9dc1308e069bae205cf3e091f62046ccc`
passed the selected 33-command plan. Its additional GitHub PQ workflow correctly
refused eight stale source pins. This was an integration omission relative to
base `4a7e07e970d5bdb79626dda6bc98ae7906a02f18`, not a claim that the base
had the same error. Four jobs (head/prospective merge, x64/ARM64) stopped at
`pq-source` before compiler/provider preparation or native execution.

The complete prior corpus had 580 pins matching its base tree. The integrated
candidate had 572 matching pins and eight reviewed changes. This correction
changes only those eight blob values. The strict checker, complete pin set,
required paths, budgets, native owners, upstream fields, old measurements and
all acceptance/activation assertions retain their original bytes or values.
The research status remains HOLD_NO_GO; old records are not current acceptance.

| Reviewed source | Prior Git blob | Current reviewed Git blob |
| --- | --- | --- |
| `scripts/ci/check_ci_contract.py` | `03926c57fb31756c98ec4630d86c22212f834670` | `b08492454cdf8e377d2e3356b83d554668444154` |
| `scripts/ci/ci_job.sh` | `af2d413c8ae5f170c693b1c4e8c85844146f7be0` | `72576f1412ff36aa0c2d99dcebc51927e4bbefa3` |
| `scripts/ci/test_ci_contract.py` | `2e71d8e683424a3aa36f7d1351ba413cb7c73618` | `55e13ea85db51ac8e95e72a979604cf0256fc774` |
| `trillionnium/crates/trnm-crypto-primitives/src/lib.rs` | `530d3097745eb2448300876aaaf34862b8a6aec0` | `b4b83396f1b7b7b88dddb25974dc4f8fa16076c8` |
| `trillionnium/crates/trnm-pon-node/examples/support/distributed_source_inventory.rs` | `3cec8fae2a55d6708d23ee1f37026aeba23b4fe5` | `69fa7aefe397cdc8a4eec67c2ef5bc8b981ad4e6` |
| `trillionnium/crates/trnm-pon-node/src/lib.rs` | `0b1e224e81bdd832f70891a71e8bacc977bb08d5` | `e52f09d92f4cc00319229fe9c868f03737fcbc69` |
| `trillionnium/crates/trnm-pon-node/src/store/task_operation_v2/reconciliation.rs` | `090ed0e0624c36275740aea0435e95ee8b67c378` | `8eb8638b78e8260d316aa15c84c7a95f7ac5e6ed` |
| `trillionnium/crates/trnm-pon-node/tests/native_task_operation_v2.rs` | `bc0cc0db2741ec44c460e536a80b2a28db613c03` | `7d27c2e45b51b8d3baa6206398c2cc434d51d902` |

## Complete retained event records

- [Head jobs and full source comparison](ci-pq-head-failure-v1.tar.gz) retain both original failed logs, exact base/head sources, full Git trees and all eight diffs.
- [Prospective merge jobs](ci-pq-prospective-failure-v1.tar.gz) retain both complete logs, original artifact ZIPs and all extracted source guards and failed-command receipts. The tested merge was `3f64cc5e08706e3ba9467ab2087450d7a24f5f0d`; its tree equals the first published tree `26db2d6c205caf634eaa9262eed14bbcf927109d`.
- [Unavailable historical pressure artifact audit](ci-retained-pressure-unavailable-v1.tar.gz) retains the current download failure, its exact unchanged workflow and bounded recovery searches. Historical run `37730166589` currently listed no artifacts; artifact `11531476198` returned 404. This does not establish whether it expired or was deleted. No verified complete substitute for historical source `560d44...` was found within the documented bounded searches, which are not an exhaustive search of every nested archive. This audit is not the missing historical artifact and does not make its gate pass.

Each archive has a separate `.manifest.json` alongside it. [Readback receipts](archive-readback.json) record full archive and member hashes. The first published 33-command result is preserved in [its original summary](initial-publication-validation-summary.json); it does not include the additional failed PQ source gate.

[The pin repair record](repair-record.json), [all 580 original pin observations](all-580-pins-before.json), and the complete before/after corpus files retain exact provenance. Source diffs are stored as lossless `.patch.gz` files, preserving original whitespace without changing their bytes.

## New validation scope

The corrected committed source receives a new exact-source 33-command run and
new original `record_pq_native_command.py` receipts for the nine commands in
`Require retained source and claim controls`. The original 24-command prefix,
all 33 frozen commands and time budgets stay unchanged. The publication PR
carries the exact resulting commit and complete new validation summaries;
those new receipts do not reclassify any earlier failure.

Source identity is not cryptographic acceptance, independent demand, authentic
consumer use, a physical meter or profile registration. Qualification remains
HOLD, actual chainwork is 0, and production activation is false. Preparation,
failed and network costs are retained as UNKNOWN wherever no authentic complete
meter exists. Ten explicitly ignored original core observations remain ignored.
