# Branch-encoding migration count correction

At candidate `ca45a48eec7997caf093881f7b9f03df94e4c157`, all four jobs in
[run 42154342369](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42154342369)
passed all 40 tests selected by `authenticated_migration`. The following guard
still required exactly 36, returned exit 1, and skipped the subsequent arithmetic,
public-service and lint steps. Those later steps are not accepted by this repair.

The job-named gzip files losslessly retain the complete selected invocation from `running
40 tests` through the final summary, removing only GitHub timestamp prefixes.
Compression preserves harness trailing spaces without weakening whitespace checks.
Nested process-exit and FIFO child harness output is retained, not deduplicated.
The parent `--show-output` successes list provides the complete 40-name roster:
26 migration tests, 11 reservation-I/O tests, two receipt-copy tests and one
reorganization-cancellation test whose name matches the original selector.
Jobs 127684791178 and 127684791498 are prospective-merge lanes; 127684791288
and 127684791333 are head lanes, covering arm64 and x64.

The fixed guard requires exactly 40 passed, zero failed and zero ignored.
Original compiler, release profile, selection, single-threaded execution,
pipefail, batch controls, downstream service and strict lint requirements remain.
Four Python regression cases replay all four actual transcripts, compare the
complete parent success roster with its source owners and reject reduced,
extra, failed, ignored, incomplete and child-only summaries. These controls do
not authenticate future test output or replace native execution.

The workflow's existing entry in `config/pon/pq-cross-branch-corpus-v1.json`
is updated to its actual new Git blob identity. No corpus paths, owners,
activation flags or acceptance meanings change. The exact-source checker still
reports HOLD_NO_GO. No Rust source changes, new native run, global gate closure,
resource-budget relaxation or production acceptance is claimed.
