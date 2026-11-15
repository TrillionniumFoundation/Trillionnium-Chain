# ARM64 hosted confirmation target refusal

This is a retained failure observation from PR 784, exact head b5c655ebe9611b3d62cf739e61e6867decc053e3, workflow run 42431209912, job 128580281431. It does not qualify either actual security certificate.

The original release build and the five named native test invocations succeeded. The independent service and sustained-service reports passed their retained checks. The confirmation report has finite_target_met=false and the original driver rejects it with CONFIRMATION_TARGET. The job remains failure.

With the same seven honest packets and the unchanged four-second window, the baseline phase records one client confirmation; the pressure phase records zero confirmations before the window closes. This is an observed availability/timeliness target miss. It is not an estimated native security failure probability and does not establish a causal regression from this PR.

The original native test and its driver are byte-identical to integration base cb314bb4656e5da4844325cd83994ab4764fe8e9. Other downstream native source changed, so entry-point equality alone is not used to classify the outcome as a pre-existing bug.

[Final diagnosis](final-diagnosis.json) contains the exact native calls, validation stages, phase values and explicit false/null qualifications. [Raw hosted log](job-log.stdout) and raw job/check/annotation responses remain unmodified. The complete [original artifact ZIP](artifact.zip) has SHA256 56a055a59f8064cbf6c9e3fd578048f516229011d2af6ec7eeed1d16d2576194, matching GitHub's artifact digest, and includes all original manifests, native reports, SQLite files, test outputs and binaries. The extracted working copy is not duplicated here.

The earlier attempted artifact-name selection found no match and is retained. The complete later transfer is artifact 13597409283. No source, threshold, clock window, driver or CI result was altered. No workflow was rerun or cancelled by this review.
