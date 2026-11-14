# M6 repository-truth original receipt preparation

State: **prepared, not executed**. The original M6 lane was still running when this preparation was requested. This directory makes no pass/fail claim and contains no live receipt copies.

The prepared producer is fixed to head `2a62061177852dc3ebd200fa8d7c66c661a119a1`, tree `f8d170ff75990e879e93888a95e5408f36b36f6c`, and M5 start `08c9becab740ab2c375b970f376a7638f44c9e8e`. It requires the actual terminal summary SHA256 and terminal exit code supplied after completion. It preserves original `passed` or `failed` unchanged; packaging success never converts a failed lane into a pass.

It binds the reviewed 15,187-byte offline-v4 producer, its invocation and all 18 original commands, unchanged 2,700-second lane budget, 36 stdout/stderr streams, and the two exact source identity sidecars. The intended original set is 39 flat files. ZIP custody also contains the original driver, packaging producer and index: 42 members. Any additional original file causes a stop before archive outputs, with no silent exclusions.

`copy-plan.json` fixes the future ROG and Mac destinations. The later Mac copy must independently verify the complete ZIP and every original member and preserve 39 flat originals plus the driver with actual ROG origins. A ZIP alone is insufficient for the publisher.

Only Python syntax compilation is performed during preparation; no packager, original lane, source check, Git action or network action runs here. The future packager itself does not execute subprocesses. No files are added to the execution stage at this point.
