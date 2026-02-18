# Operations / Testing Guide

## Fixture Verification
To verify cross-version semantic consistency between `lifecycle_summary_v2_ok.json` and `v3_ok.json`:

```bash
cd chain/tools/fixture_check
go run check_fixtures.go
```

This ensures that while the JSON structure evolves (v2 -> v3), the core business metrics (start/end height, status, worker address) remain identical for the same test scenario.

## Keeper Boundary Testing
We have added boundary tests for `SlashWorker` in `x/workload/keeper/msg_server_slash_worker_boundary_test.go`.

Run them with:
```bash
cd chain
go test ./x/workload/keeper -run TestSlashWorker_Boundary -v
```

Cases covered:
- **Exact Minimum Remaining Stake**: Verifies that slashing resulting in exactly 1000 stake is allowed.
- **Just Below Minimum Stake**: Verifies behavior around the 1000 stake threshold.
- **Multiple Slashes**: Ensures sequential slashes work correctly until minimum is hit.
- **Tiny Slash (Zero Amount)**: Ensures attempts to slash amounts that round down to 0 are rejected.

## Unbonding Safety Testing
We have added defensive tests for `FinalizeUnbonding` in `x/workload/keeper/msg_server_finalize_unbonding_test.go`.

Run them with:
```bash
cd chain
go test ./x/workload/keeper -run TestFinalizeUnbonding -v
```

These tests ensure that attempting to finalize an unbonding that does not exist (including `TestFinalizeUnbonding_NoRequest_Fails`) returns `ErrUnbondingNotFound` and does not alter state.

## Compute Lifecycle Smoke (Request -> Complete -> Task Sync)
For an existing `job_id` (typically CREATED state), run:

```bash
cd chain
SUMMARY_JSON=1 ./tools/compute_lifecycle_smoke.sh <JOB_ID> alice chain http://127.0.0.1:26657
```

What it checks:
- `tx compute request-job-execution` succeeds (`CREATED -> RUNNING`)
- `tx compute complete-job` succeeds (`RUNNING -> COMPLETED`)
- emits `compute_complete_job` event with `task_id`/`worker`
- `q workload task <task_id>` shows:
  - `status == 2`
  - `worker` matches sender
  - `result_hash` matches submitted result

Set `RESULT_HASH=<value>` to control deterministic replay assertions.

Diagnostics:
- on failure, script emits `failure_snapshot` logs (last step, node sync info, last tx excerpt, current task snapshot)
- tune tx excerpt size with `FAIL_SNAPSHOT_LINES=<N>`

Summary contract self-check:
```bash
cd chain
bash tools/compute_lifecycle_summary_contract_test.sh
```
