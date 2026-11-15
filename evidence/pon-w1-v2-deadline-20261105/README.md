# W1 v2: original two-hour experiment timed out

The fixed guest was [reproduced](../pon-w1-pinned-rebuild-20261105/README.md)
without changing its image or verifier pin. A fresh complete experiment then
actually ran on local commit `2810f7c2b1b5e549302b3fdb2cf41b2a6ee19bff`,
whose tree equals published `a635200956843f0d2f335f929977d602b48b36ec`.
The distinction between executed and published commit identities is retained.

## Observed result

- Full execution and all 43 original segment proofs completed and verified.
- Recursive compression saved and verified 73 intermediate receipts, ending at
  `join-through-0036`. They are explicitly ineligible as a final full proof.
- `lift-0037` was interrupted by the unchanged total 7,200-second deadline.
  The coordinator recorded 7,200.081 seconds including termination settlement;
  compression returned -15 with `TIMEOUT`. The observed owned session was
  settled and no remaining process group was observed.
- No `succinct.bin` was produced. Full proof trials completed: **zero**.
  Independent final verification, local delivery, fixed-receipt replay and the
  58 actual saved-receipt controls did not execute.
- The original 300-second segment bound, 1-GiB disk floor and 256-MiB checkpoint
  cap were not changed. Checkpoint allocation ended at 41,541,632 bytes.

This is a failed original-budget observation, not proof completion or closure
of any security, performance, admission, PQ-128 or production gate. A future
new trial must preserve this failure and cannot reset the budget on this
checkpoint while claiming a fresh complete run.

## Raw evidence and resource diagnosis

[summary.json](summary.json) gives the exact outcome and longest recursive step.
The committed `raw-observations.tar.gz` contains **all 234 original observer
files**, including every stage declaration/result, stdout/stderr and process
samples. [raw-index.json](raw-index.json) supplies their byte counts and hashes.
Convenience compressed reports are also retained. [manifest.json](manifest.json)
and [checkpoint-index.json](checkpoint-index.json) bind the prepared input,
guest and partial checkpoint. The partial binary checkpoint archive remains
local and is explicitly not committed, as recorded in
[local-checkpoint-archive.json](local-checkpoint-archive.json).

The longest completed recursion step, `join-through-0032`, took 256.843 seconds.
First/last samples for its r0vm process cover 256.052 wall seconds and 685.01 CPU
seconds, approximately 2.68 effective cores, with maximum sampled RSS about
1.509 GB. Another long step covered 128.188 wall seconds and 542.04 CPU seconds.
The compression process tree's wait4 record reports zero major faults and
18,153.472 user / 178.034 system CPU seconds. These measurements do not establish
an exclusive host-contention cause, memory-bandwidth cause or algorithmic cause.
The recorded RSS is not an aggregate process-tree peak.

[recursion-resource-analysis.json](recursion-resource-analysis.json) retains
first/last sample CPU deltas by PID and birth tick. This is sampled accounting,
not full process accounting. [observer-gaps.json](observer-gaps.json) retains
sampling gaps over three seconds. In the existing observer, a sample's monotonic
time is taken before the proc scan and its Unix time afterward; they are not a
simultaneous clock pair. Some gaps therefore include expensive or delayed scans.
None is subtracted from the original total budget. Next work is controlled
repeat measurement of the same recursive operation, followed by a genuinely
fresh full trial if the measured runtime can satisfy the original budget.
