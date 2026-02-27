# Consensus Fault Matrix (8 Cases) + Gate Tiering

Date: 2026-02-26
Owner: Trillionnium Rust L1

## Matrix Cases (3 -> 8)

1. `baseline`
2. `slow_block` (latency pressure)
3. `restart_recovery`
4. `byzantine_rounds`
5. `faulty_round_backoff`
6. `leader_jitter`
7. `message_reorder` (reorder/replay pressure proxy)
8. `slow_validator` (lagging quorum proxy)

## Unified Metrics (per case)

- `finality_p95_ms`
- `bft_round_change_total`
- `bft_committed_heights`
- `recovery_time_ms` (proxy: `bft_round_change_backoff_total_ms`)
- `fork_depth` (proxy: round-change depth in single-node harness)
- `state_root_consistent` (same height must not produce conflicting state_root)

## Gate Tiering

### Hard Gate (nightly + merge)

- `baseline`
- `restart_recovery`
- `byzantine_rounds`

Rationale: directly related to safety/liveness baseline and restart correctness.

### Soft Gate (nightly observe -> promote later)

- `slow_block`
- `faulty_round_backoff`
- `leader_jitter`
- `message_reorder`
- `slow_validator`

Rationale: stress scenarios are valuable for trend detection but should not block unrelated merges during initial observation window.

## Initial Threshold Profile (default)

- `finality_p95_ms <= 500`
- `bft_round_change_total <= 12`
- `bft_committed_heights >= 1`
- `recovery_time_ms <= 120`
- `fork_depth <= 12`
- `state_root_consistent = true`

## First Run Evidence

- Script: `trillionnium-rust/scripts/run_consensus_fault_matrix.sh`
- Report: `trillionnium-rust/run/health/consensus-fault-matrix-20260226-144750.txt`
- Result: `pass=8 fail=0 status=PASS`

## Next Tightening Plan

1. Observe 7 days nightly distribution (p50/p95/max) by case.
2. Tighten hard-gate thresholds first for baseline/restart/byzantine.
3. Promote 1-2 stable soft cases into hard gate (candidate: `leader_jitter`, `slow_validator`).
4. Keep case-specific overrides available through env vars to avoid flakiness-driven lockups.
