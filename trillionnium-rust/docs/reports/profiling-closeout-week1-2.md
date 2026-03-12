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
  - `Artifact Discovery`：列出 `classic_bench` / `mixed_bench` / `executor_profile`（以及 `node_log`）的候选文件数量、当前选中的 latest 文件、候选窗口的 newest/oldest 与 `spread_seconds`、整组候选的 `candidate_freshness_counts`，以及最近若干个候选产物，帮助 autopilot 判断 latest 选择是否稳定、候选池里新旧产物是否混杂、是否存在大量并行采样产物需要人工抽查
  - `Benchmark Artifact Pool Health`：额外把 `classic_bench` / `mixed_bench` / `executor_profile` 的候选池压成一行摘要，输出 `status=tight|backlog_present|backlog_heavy|refresh_required` 与 `action=keep_latest|keep_latest_and_consider_archive|refresh`，并带出 `old_backlog`，便于 autopilot 在“latest 可用但历史产物堆积”的情况下快速判断是否需要做目录清理/归档，而不是只看到 selected latest
  - `Benchmark Pool Action Summary`：把三个 bench 候选池再聚合成一段总览，输出各类 `status` / `action` 计数、`benchmark_pool_attention`、`benchmark_pool_backlog_totals`，以及 `benchmark_pool_followup_command_chain`，方便 autopilot 直接判断当前是“缺产物”为主，还是“旧 backlog 堆积”为主，并决定下一步是补产物、刷新产物，还是保留 latest 并考虑归档旧 backlog
  - `Benchmark Archive Candidates`：当 bench 候选池存在 stale/old backlog 时，额外给出 `archive_candidate_count`、默认 `keep_latest=2` 以及若干 basename 预览，方便 autopilot/curator 在不影响 latest 证据集的前提下，快速判断哪些历史 bench 产物可以归档
  - `Benchmark Archive Summary`：把 `classic_bench` / `mixed_bench` / `executor_profile` 的 archive backlog 再聚合成一段总览，输出 `benchmark_archive_candidate_total`、`benchmark_archive_attention` 与 `benchmark_archive_recommendation`，便于 autopilot 先判断 backlog 是局部的还是跨多个池扩散，再决定是否需要人工清理/归档
  - `Benchmark Next Step Matrix`：对 `classic_bench` / `mixed_bench` / `executor_profile` 分别输出 `action=produce|keep|refresh`，并附带 `age_seconds`、`updated_at`、`path`
  - `Benchmark Action Summary`：聚合给出 `benchmark_decision=INCOMPLETE|REFRESH_RECOMMENDED|READY` 与 action 计数，便于 autopilot/curator 直接决定是否需要先补产物、刷新产物，还是可以进入 review
  - `benchmark_capture_cohesion` / `benchmark_capture_spread_seconds`：额外判断 `classic_bench`、`mixed_bench`、`executor_profile` 是否来自同一 capture window；当结果为 `mixed_capture_window` 或 `divergent_capture_window` 时，都会建议 refresh，避免把时间上不够集中但“单个文件看起来都很新”的产物误当成一组可直接 closeout 的证据
- `Executor Profile Context`：额外汇总 `profile.report.persist_profile`、`profile.report.path`，并在存在持久化失败时显式带出 `profile.report.persist_error`，方便 autopilot/curator 区分“bench 跑过了”与“profile 产物是否真的成功落盘”
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
