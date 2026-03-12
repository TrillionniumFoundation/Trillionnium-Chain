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

### 1. executor profile 汇总产物
```bash
cargo run -q -p trnm-bench -- --profile
```

### 2. node + bench 统一 closeout
```bash
python3 scripts/profiling_closeout_report.py
```

默认读取：
- `trillionnium-rust/run/parallel-sanity.log`
- `trillionnium-rust/run/bench/bench-matrix-*.txt`（优先）
- `trillionnium-rust/run/bench/bench-mixed-matrix-*.txt`（优先）
- `trillionnium-rust/run/bench/executor-profile-summary-*.txt`（优先，由 `cargo run -q -p trnm-bench -- --profile` 生成）
- 若 `trillionnium-rust/run/bench/` 不存在，则回退读取仓库根 `run/bench/*.txt`

输出：
- `docs/reports/profiling-closeout-baseline-<timestamp>.md`
- 报告会同时给出：
  - `total_evidence_coverage`：完整 closeout 证据覆盖率（`node_log + classic_bench + mixed_bench + executor_profile`）
  - `benchmark_artifact_coverage`：仅 bench 侧产物覆盖率（不含 `node_log`）
  - `Closeout Action Summary`：聚合完整 4/4 证据集，输出 `closeout_decision=INCOMPLETE|REFRESH_REQUIRED|REFRESH_RECOMMENDED|READY`、blockers 与 ready_inputs，便于 autopilot/curator 直接判断是否可进入 review
  - `closeout_capture_cohesion` / `closeout_capture_spread_seconds`：额外判断 `node_log`、`classic_bench`、`mixed_bench`、`executor_profile` 是否来自同一 capture window；当结果为 `mixed_capture_window` 或 `divergent_capture_window` 时，都会建议 refresh，避免把“单个文件都不旧但采集窗口不够紧”的 4/4 证据误判为可直接 closeout
  - `Benchmark Next Step Matrix`：对 `classic_bench` / `mixed_bench` / `executor_profile` 分别输出 `action=produce|keep|refresh`，并附带 `age_seconds`、`updated_at`、`path`
  - `Benchmark Action Summary`：聚合给出 `benchmark_decision=INCOMPLETE|REFRESH_RECOMMENDED|READY` 与 action 计数，便于 autopilot/curator 直接决定是否需要先补产物、刷新产物，还是可以进入 review
  - `benchmark_capture_cohesion` / `benchmark_capture_spread_seconds`：额外判断 `classic_bench`、`mixed_bench`、`executor_profile` 是否来自同一 capture window；当结果为 `mixed_capture_window` 或 `divergent_capture_window` 时，都会建议 refresh，避免把时间上不够集中但“单个文件看起来都很新”的产物误当成一组可直接 closeout 的证据
- `Executor Auto-Adaptive Decision Summary`：当 `executor_profile` 含 `profile.auto.*` 字段时，额外汇总 `use_hot_bucket`、`reason`、`hot_key_share`、`expected_gain_score` 等自动策略决策字段，减少人工回看原始 profile txt 的需要

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
