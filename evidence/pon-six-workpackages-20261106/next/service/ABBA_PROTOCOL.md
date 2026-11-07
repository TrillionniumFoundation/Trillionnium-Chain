# Native reorg component observation

This protocol is declared before the first performance execution. The earlier
external draft that called `/usr/bin/time` was never run and is superseded:
that executable is absent on this host. The runner uses the reviewed V5
`Popen`/`wait4` sole reaper. It retains the unreaped leader until its final
process-group signal and preserves stdout, stderr, actual exit or signal,
timeout, whole-process CPU and Linux `ru_maxrss` for every executed attempt.

The fixed order is baseline, candidate, candidate, baseline, repeated twice.
All eight attempts remain in the denominator. Each command has 300 seconds
plus 5 seconds of TERM grace before KILL; no option relaxes this budget. This
is a new local component observation, not the original 4-second public Host
or 4105-block paid History contract. It has no throughput acceptance target.
Do not start it until the coordinator confirms an idle build window.

The old control is commit `852b61eeeb41c283f3bc291ce71cbe32350087a1`, whose
parent is `0ca272d09d1522b0ffd740e441b6d3de1ed81de6` and whose only change
adds the identical observer. The candidate must be the coordinator's frozen,
clean joint commit. Both retain the existing SQL statement-cache capacity.
The runner checks exact tracked source before and after each command, source
bytes against build receipts, the embedded store and observer SHA256 in the
native report, and the actual retained ELF before and after execution.

Build receipts must contain `source_commit`, `build_exit` (integer zero),
`sha256`, `bytes`, `observer_sha256`, and `store_sha256`. The baseline also
contains `base`. Preserve the original build logs separately. The already
completed old build did not measure build CPU/RSS; those costs are unknown,
not zero, and are not included in runtime ratios. The runner copies receipt
bytes into its new output directory without rewriting them.

```sh
python3 evidence/pon-six-workpackages-20261106/next/service/run_reorg_abba.py \
  --baseline /absolute/path/reorg-cost-baseline \
  --candidate /absolute/path/reorg-cost-candidate \
  --baseline-receipt /absolute/path/control-cost-build-receipt.json \
  --candidate-receipt /absolute/path/candidate-cost-build-receipt.json \
  --expected-commit FULL_FROZEN_JOINT_COMMIT \
  --output /absolute/path/new-abba-output
```

Both implementations build the same 512 real maintenance PNW1 packets,
perform every admission, then perform complete Legacy activation and cold
reopen. The report retains fixture preparation CPU/wall separately and
inside its entire native scope. External `wait4` CPU and launcher wall cover
the whole native process, including output and final drops. The native
`entire` interval ends before those final operations; the scopes must not be
added together. Launcher bookkeeping has separate parent CPU and campaign
wall observations. Cumulative reaped-child CPU also includes Git source
checks and the native `wait4` captures; it must not be added to the native
`wait4` total again. Unreaped descendants may remain outside that scope.

Medians and ratios are produced only if all eight executions succeed, the
complete state and cold readback agree, and all context/input digests match.
A failure retains its measured cost and partial output; unknown cost stays
unknown. The sum includes every available `wait4` CPU, including failures.
`ru_maxrss` is a per-process high-water mark, not a sum or a simultaneous
global memory peak. Failed/unreaped descendants may be absent from kernel
accounting. No original-resource acceptance or production claim follows
from this component comparison.

The runner reuses `scripts/ci/run_w1_rank_batch_v5.py::capture`; its actual
success, nonzero, timeout, lingering-child and launch-failure controls remain
in `scripts/ci/test_run_w1_rank_batch_v5.py`. The adjacent readback tests
reject missing preparation, incomplete cold readback, source/input drift,
and deletion or zero-filling of a failed attempt.
