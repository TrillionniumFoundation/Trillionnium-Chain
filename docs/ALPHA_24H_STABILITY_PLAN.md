# Alpha 24h Stability Plan (2-3 Validators, 2 Workers)

## Objective
Run continuous workload lifecycle traffic for 24h and capture reliability SLOs.

## Topology
- Validators: 2-3
- Workers: 2 (both registered/staked)
- Task producer: 1 client loop (fixed interval)

## SLO Targets
- End-to-end success rate (request->complete->task-sync): >= 99%
- P95 completion latency: <= 10s
- Failed tx ratio: <= 1%
- Recovery time after node restart: <= 5min

## Traffic Pattern
- Every 30-60s create one compute job
- Alternate worker assignment opportunities
- Keep `SUMMARY_JSON=1` logs for each smoke execution

## Metrics to Collect
- tx success/fail counts by stage
- failure reasons (`worker not found`, state mismatch, insufficient funds, timeout)
- node health snapshots (height progression/catching_up)

## Runbook
1. Preflight: `tools/compute_lifecycle_preflight.sh`
2. Lifecycle smoke: `tools/compute_lifecycle_smoke.sh`
3. Persist logs to `docs/alpha-runs/<timestamp>.log`
4. Summarize SLOs at end of window

## Exit Criteria
- SLOs met for full 24h window
- No unresolved critical failure class
- Reproducible recovery documented
