# Profiling / Closeout Baseline（Week 1-2）

目标：统一 Lane A Week 1-2 的 profiling 指标面，并沉淀最小 closeout 产物。

## 已落地指标

### Executor / bench
- `profile.group_count`
- `profile.avg_group_size`
- `profile.hot_object_share`
- 既有冲突/扫描指标继续保留

### Node block / consensus closeout
- `scheduler_elapsed_ms`
- `preexec_elapsed_ms`
- `commit_elapsed_ms`
- `state_root_total_ms`
- `rollback_count`
- `critical_wait_blocks`
- `critical_wait_blocks_p50/p95`
- 既有 `finality_p50/p95`、`rollback_total`、`preexec_reject_total` 等继续保留

## closeout 产物

### 1. bench 汇总
```bash
python3 scripts/executor_profile_report.py
```

### 2. node + bench 统一 closeout
```bash
python3 scripts/profiling_closeout_report.py
```

默认读取：
- `run/parallel-sanity.log`
- `run/bench/bench-matrix-*.txt`
- `run/bench/bench-mixed-matrix-*.txt`
- `run/bench/executor-profile-summary-*.txt`

输出：
- `docs/reports/profiling-closeout-baseline-<timestamp>.md`
- 报告会同时给出：
  - `total_evidence_coverage`：完整 closeout 证据覆盖率（`node_log + classic_bench + mixed_bench + executor_profile`）
  - `benchmark_artifact_coverage`：仅 bench 侧产物覆盖率（不含 `node_log`）

## 字段解释
- `scheduler_elapsed_ms`：从 block 内开始做 commit ordering，到拿到 `OrderingDecision` 的耗时
- `preexec_elapsed_ms`：ordering 内 pre-exec 实际运行耗时
- `commit_elapsed_ms`：进入 commit 循环到 block root 落定前的耗时
- `state_root_total_ms`：block 内所有 `state_root()` 调用耗时总和
- `rollback_count`：该 block 内 apply 失败并回滚的次数
- `critical_wait_blocks`：当前 block 因分组顺序引入的串行 barrier 数，近似为 `group_count - 1`
- `hot_object_share`：executor workload 中最热对象占全部去重对象触达的比例

## 最小验证建议
```bash
cargo test -p trnm-executor -q
cargo test -p trnm-node preexec_parallel_workers_match_single_worker_results -q
cargo run -q -p trnm-node -- --config configs/node1.toml --block-ms 5 --max-blocks 3 --demo-tasks 8 --demo-keys 3 --parallel-workers 4 > run/parallel-sanity.log
TXS=1000 ./scripts/run_bench_matrix.sh
TXS=1000 ./scripts/run_bench_mixed_matrix.sh
python3 scripts/executor_profile_report.py
python3 scripts/profiling_closeout_report.py
```
