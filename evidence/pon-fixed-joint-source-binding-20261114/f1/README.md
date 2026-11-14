# F1: reviewed current MU1 relation-source mapping

The sole active contract change is one reviewed `pon_work.rs` digest in the
existing four-path source set. The other three source hashes, original reader,
all 16 original control methods, relation probability 1/16, research credit 16u,
context, accounting, strategy roster and open obligations remain unchanged.

The old contract's four pins match Git source 2bb56596e637908c44b5a2ef5984c9c37c7d3cc8.
The reviewed current sources are at 7d8d4c59fcd01480a12e1c64835b202079091800.
These are source checkpoints, not the later metadata commit identity.
The original JSON is retained under ../historical and the complete selected
source diff is under source-review. Nine raw original diagnostic files under
../original-diagnostics preserve the full 122-command summary and the specified
fixed/joint failures, without relabeling those failures as success.

## Targeted validation

The unchanged 16 methods passed on macOS with the recorded Python command.
The actual default reader reported binding_validation=PASS and
qualification=HOLD_NO_GO, with 16 unknown cost points. A separate direct call
to the same production reader rejected the original contract against current
sources with SOURCE_DIGEST_MISMATCH. Seven explicitly listed inputs matched
before and after validation. Exact commands and raw streams are in validation.

These targeted source/claim-boundary controls do not execute native Rust work,
establish a cost lower bound, or replace the successor full Linux lane or hosted
CI. All qualification and activation flags remain false/HOLD.
