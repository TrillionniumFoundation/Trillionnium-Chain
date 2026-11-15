# Other failed hosted checks in the PR 784 snapshot

These six jobs are the additional failures in the 2026-11-08T01:11:43Z snapshot of exact candidate b5c655ebe9611b3d62cf739e61e6867decc053e3. Their raw job metadata, complete hosted logs, bounded error excerpts and command receipts are retained. All remain failed.

Four native-priority service-model jobs (x64/ARM64, head/prospective merge) first fail at Execute original release from-zero controls. Their complete logs also preserve later scalar-meter observations. This review does not assign an internal manifest cause from an outer exit code or classify later observations as a successful whole lane.

The original native campaign x64/head/release job fails during Run three original campaigns under verified actual limits. The log reports systemd resource consumption and exit 1. Those values alone do not establish an out-of-memory event or the underlying native refusal, and no such cause is inferred here.

The CodeQL export job explicitly reports that exact-source analyses/checks did not complete and stabilize before the deadline. This is an export/readiness failure; it is not a reported security finding. The distinct real CodeQL analysis workflow has its own result in the complete snapshot.

[Structured job results](result.json) identify each exact job, failed step, source head, raw log byte count and SHA256. The original full log filenames are log-JOB_ID.stdout; bounded excerpts are failure-JOB_ID.txt. No workflow was changed, rerun or cancelled and no source was modified.

This archive does not assert all hosted checks passed, a causal regression from this PR, production qualification or an actual native security failure probability.
