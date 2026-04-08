# Profiling Closeout Baseline
generated_at=2026-03-10T15:38:34.624638

## Inputs
- node_log: run/parallel-sanity.log
- classic_bench: run/bench/bench-matrix-20260310-153018.txt
- mixed_bench: run/bench/bench-mixed-matrix-20260310-bbb.txt
- executor_profile: /Users/qianqi/.openclaw/workspace/TrillionniumChain/trillionnium/run/bench/executor-profile-summary-20260310-153834.txt

## Block Metrics
- scheduler_elapsed_ms: min=0 p50=0 p95=0 max=0
- preexec_elapsed_ms: min=0 p50=0 p95=0 max=0
- commit_elapsed_ms: min=0 p50=0 p95=0 max=0
- state_root_total_ms: min=0 p50=0 p95=0 max=0
- critical_wait_blocks: min=1 p50=3 p95=3 max=3
- rollback_count: min=0 p50=0 p95=0 max=0
- groups: min=2 p50=4 p95=4 max=4
- elapsed_ms: min=1 p50=2 p95=2 max=2

## Consensus Summary
- finality_p50_ms: 2
- finality_p95_ms: 2
- scheduler_elapsed_p50_ms: 0
- scheduler_elapsed_p95_ms: 0
- preexec_elapsed_p50_ms: 0
- preexec_elapsed_p95_ms: 0
- commit_elapsed_p50_ms: 0
- commit_elapsed_p95_ms: 0
- state_root_total_p50_ms: 0
- state_root_total_p95_ms: 0
- critical_wait_blocks_p50: 3
- critical_wait_blocks_p95: 3
- rollback_total: 0
- preexec_reject_total: 10
- apply_error_total: 0
- bft_round_change_total: 0

## Benchmark Summary
# Executor Profile Summary
generated_at=2026-03-10T15:38:34.114316
classic_file=run/bench/bench-matrix-20260310-153018.txt
## Classic Matrix
rows=4
elapsed_ms: min=0 p50=0 max=1
groups: min=0 p50=1 max=1
avg_group_size: min=100.0000 p50=100.0000 max=100.0000
hot_object_share: min=0.0100 p50=0.0100 max=0.0100
conflict_hit_rate: min=0.0000 p50=0.0000 max=0.0000
top_conflict_rows:
  - keys=20000 | elapsed_ms=0 groups=1 hit_rate=0.0000
  - keys=10000 | elapsed_ms=0 groups=1 hit_rate=0.0000
  - keys=5000 | elapsed_ms=1 groups=1 hit_rate=0.0000
mixed_file=run/bench/bench-mixed-matrix-20260310-bbb.txt
## Mixed Matrix
(no rows)
