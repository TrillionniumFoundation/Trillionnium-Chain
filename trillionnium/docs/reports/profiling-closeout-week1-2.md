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
- `trillionnium/run/parallel-sanity.log`
- `trillionnium/run/bench/bench-matrix-*.txt`（优先）
- `trillionnium/run/bench/bench-mixed-matrix-*.txt`（优先）
- `trillionnium/run/bench/executor-profile-summary-*.txt`（优先，由 `cargo run -q -p trnm-bench -- --profile` 生成）
- 若 `trillionnium/run/bench/` 不存在，则回退读取仓库根 `run/bench/*.txt`

输出：
- `docs/reports/profiling-closeout-baseline-<timestamp>.md`
- 报告会同时给出：
  - `total_evidence_coverage`：完整 closeout 证据覆盖率（`node_log + classic_bench + mixed_bench + executor_profile`）
  - `benchmark_artifact_coverage`：仅 bench 侧产物覆盖率（不含 `node_log`）
  - `Closeout Action Summary`：聚合完整 4/4 证据集，输出 `closeout_decision=INCOMPLETE|REFRESH_REQUIRED|REFRESH_RECOMMENDED|READY`、`closeout_evidence_blockers`、`closeout_structural_blockers`、总 `closeout_blockers` 与 `ready_inputs`，便于 autopilot/curator 直接区分“证据本身缺/旧”与“结构性前置条件（如 `bench_dir` 缺失、capture window 分裂）”两类阻塞；当存在缺失/需刷新证据时，`closeout_followup_command_chain` 会把补采命令与最终 `python3 scripts/profiling_closeout_report.py` 重渲染串起来，避免只补产物却忘记刷新 markdown closeout
  - `closeout_capture_cohesion` / `closeout_capture_spread_seconds`：额外判断 `node_log`、`classic_bench`、`mixed_bench`、`executor_profile` 是否来自同一 capture window；当结果为 `mixed_capture_window` 或 `divergent_capture_window` 时，都会建议 refresh，避免把“单个文件都不旧但采集窗口不够紧”的 4/4 证据误判为可直接 closeout
  - `Artifact Capture Stamps`：现在会同时输出原始 `capture_stamp_family` / `capture_stamp` 与归一化后的 `capture_stamp_epoch`；对于 `bench-matrix-YYYYMMDD-HHMMSS.txt`、`executor-profile-summary-<epoch>.txt`，以及历史遗留的 `executor-profile-summary-YYYYMMDD-HHMMSS.txt` 这类不同命名族，会先归一化到同一秒级 epoch，再判断是否 `aligned_normalized`，避免因为文件名编码不同把同一次采样误判成 `mixed_family`
  - `Artifact Discovery`：列出 `classic_bench` / `mixed_bench` / `executor_profile`（以及 `node_log`）的候选文件数量、当前选中的 latest 文件、候选窗口的 newest/oldest 与 `spread_seconds`、整组候选的 `candidate_freshness_counts`，以及最近若干个候选产物，帮助 autopilot 判断 latest 选择是否稳定、候选池里新旧产物是否混杂、是否存在大量并行采样产物需要人工抽查
  - `candidate_count` / `effective_candidate_count` / `pending_count` / `missing_count`：候选池健康摘要里的 `candidate_count` 只统计当前真实存在的候选文件；`effective_candidate_count` 会把“当前已选中但仍处于 pending-write / 尚未落盘”的目标也算进来；`pending_count` 单独标出这类 pending-write 目标；`missing_count` 仅统计真正缺失且不是当前 pending 选中项的路径，避免把即将写出的 closeout 报告误计入 backlog 规模，同时让 fresh ratio / rank 分母更接近 autopilot 最终看到的候选集
  - `Benchmark Artifact Pool Health`：额外把 `classic_bench` / `mixed_bench` / `executor_profile` 的候选池压成一行摘要，输出 `status=tight|backlog_present|backlog_heavy|refresh_required` 与 `action=keep_latest|keep_latest_and_consider_archive|refresh`，并带出 `selected_age_seconds`、`selected_updated_at`、`old_backlog`、`fresh_ratio`、`old_backlog_ratio`，便于 autopilot 在“latest 可用但历史产物堆积”的情况下快速判断候选池到底是少量历史残留，还是已被 stale/old backlog 主导，而不是只看到 selected latest
  - `Benchmark Pool Action Summary`：把三个 bench 候选池再聚合成一段总览，输出各类 `status` / `action` 计数、`benchmark_pool_attention`、`benchmark_pool_backlog_totals`、`benchmark_pool_selection_mismatches`，以及 `benchmark_pool_followup_command_chain`，方便 autopilot 直接判断当前是“缺产物”为主，还是“旧 backlog 堆积”为主，同时显式暴露“selected 并非最新候选 / 仍处于 pending-write”的池，减少只看汇总计数时漏掉选中产物漂移的风险；该 command chain 只在需要 `produce` / `refresh` 时给出可执行命令，若仅剩 backlog 归档问题则保持 `none`，避免把目录存在性/重跑 closeout 误当成下一步修复动作
  - `Benchmark Archive Candidates`：当 bench 候选池存在 stale/old backlog 时，额外给出 `archive_candidate_count`、`archive_candidate_total_bytes`、按 stale/old 分解的 backlog bytes、默认 `keep_latest=2` 以及若干 basename 预览，方便 autopilot/curator 在不影响 latest 证据集的前提下，快速判断哪些历史 bench 产物可以归档，以及 backlog 是“文件数多但很轻”还是已经开始占据明显磁盘体积
  - `Benchmark Archive Summary`：把 `classic_bench` / `mixed_bench` / `executor_profile` 的 archive backlog 再聚合成一段总览，输出 `benchmark_archive_candidate_total`、`benchmark_archive_byte_totals`、`benchmark_archive_attention` 与 `benchmark_archive_recommendation`，便于 autopilot 先判断 backlog 是局部的还是跨多个池扩散，再决定是否需要人工清理/归档
  - `Baseline Report Action Summary`：对 `profiling-closeout-baseline-*.md` 候选池再压成一段摘要，输出 `baseline_closeout_report_status`、`baseline_closeout_report_action`、`baseline_closeout_report_decision`、`baseline_closeout_report_action_counts` 与 `baseline_closeout_report_followup_command_chain`，让 autopilot 在 closeout 报告目录堆积时也能快速判断是继续保留 latest、需要人工归档，还是应该刷新 closeout 产物；当 bench 侧证据已经 fresh 且齐全时，followup command chain 会最小化为仅重跑 `python3 scripts/profiling_closeout_report.py`，避免把“只需刷新 markdown closeout”的场景误升级成额外 bench 重采样
  - `Baseline Report Archive Summary`：新增输出 `baseline_closeout_report_archive_candidate_total`、`baseline_closeout_report_archive_freshness_counts`、`baseline_closeout_report_archive_byte_totals`、`baseline_closeout_report_archive_attention` 与 `baseline_closeout_report_archive_recommendation`，把 markdown closeout 自身的 stale/old backlog 单独压成一眼可读的归档摘要，避免 autopilot 只看到 latest 可用却忽略了 closeout 报告目录正在持续堆积，以及 backlog 到底只是数量堆积还是已经形成明显体积负担
  - `Benchmark Next Step Matrix`：对 `classic_bench` / `mixed_bench` / `executor_profile` 分别输出 `action=produce|keep|refresh`，并附带 `age_seconds`、`updated_at`、`path`
  - `Benchmark Action Summary`：聚合给出 `benchmark_decision=INCOMPLETE|REFRESH_RECOMMENDED|READY` 与 action 计数，便于 autopilot/curator 直接决定是否需要先补产物、刷新产物，还是可以进入 review
  - `benchmark_capture_cohesion` / `benchmark_capture_spread_seconds`：额外判断 `classic_bench`、`mixed_bench`、`executor_profile` 是否来自同一 capture window；当结果为 `mixed_capture_window` 或 `divergent_capture_window` 时，都会建议 refresh，避免把时间上不够集中但“单个文件看起来都很新”的产物误当成一组可直接 closeout 的证据
  - `benchmark_selected_capture_alignment` / `benchmark_selected_capture_alignment_reason`：benchmark summary 里的对齐判断只看 `classic_bench`、`mixed_bench`、`executor_profile` 三类 bench 产物，不再混入 `node_log`，避免 benchmark-only 结论被完整 closeout 缺口污染
- `Executor Profile Context`：额外汇总 `profile.report.persist_profile`、`profile.report.path`，并在存在持久化失败时显式带出 `profile.report.persist_error`，方便 autopilot/curator 区分“bench 跑过了”与“profile 产物是否真的成功落盘”
- `profile.report.ungrouped_count` / `profile.report.grouping_complete`：executor profile 现在会显式给出未入组交易数与布尔完备性标记，便于 autopilot/curator 直接判断当前 profile 是否覆盖了全部 benchmark tx，而不必再手工比对 `grouped` 与 `txs`
- `profile.report.effective_read_fanout` / `profile.report.effective_write_ratio` / `profile.report.workload_signature`：executor profile 现在会额外输出归一化后的 workload shape 摘要，让 autopilot/curator 在 closeout 报告里一眼看出当前 profile 是 classic 还是 mixed/hot-streak、有效读扇出是多少、写入占比大约多少，以及该 profile 对应的紧凑 workload signature，而不必回头人工拼装 `workload + txs + keys + read_fanout + write_every + strategy`
- `executor_profile.integrity_status`：当 embedded basename / capture epoch / report path 中任一可校验项与当前选中的 executor profile 产物不一致时，状态会显式落成 `FAIL`（而不是笼统 `PARTIAL`），便于 autopilot 更快识别“选中文件与嵌入元数据不匹配”的 closeout 风险
- `profile.report.capture_started_at_iso`：executor profile 产物现在同时输出真实 UTC RFC3339 时间戳（不再是 `unix:<epoch>` 伪 ISO），便于 closeout 报告直接做人读时间线核对，同时保留 `profile.report.capture_started_at_epoch` 供脚本侧比较
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
