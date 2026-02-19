# P2 Throughput Plan (Day1~Day5)

Date: 2026-02-19
Owner: TRNM Rust L1

## Goal
在已完成 P0/P1 质量闸门基础上，优先打深高吞吐任务链路与并发执行能力，允许必要 break change。

## SLO (v0 baseline target)
- Benchmark workload: `trnm-bench` with `txs=20000`
- Throughput proxy: `elapsed_ms` 越低越好
- P2 target (week):
  - `elapsed_ms` p50 降低 >= 20%（相对 Day1 baseline）
  - 在高冲突区（`keys<=200`）保持稳定，不出现异常退化（>10% 回退）

## Day1 (done)
1. 固化基线矩阵（固定参数）
   - Command: `TXS=20000 ./scripts/run_bench_matrix.sh`
   - Evidence: `trillionnium-rust/run/bench/bench-matrix-20260219-201531.txt`
2. 提取基线关键点
   - worst-case (`keys=20000`): `15769ms`
   - best point (`keys=100`): `8096ms`
   - spread improvement: `48.66%`

## Day2
1. Executor 分组策略剖析
   - 在 `trnm-executor` 增加轻量 profiling（group size 分布、冲突图统计）
2. 明确热点路径
   - 标注状态写入冲突热点与串行瓶颈

## Day3
1. 激进优化实验 A
   - 调整分组算法（启发式优先级 / 桶化策略）
2. 激进优化实验 B
   - 减少状态提交阶段锁竞争
3. 双分支对比
   - 使用同 seed 参数跑矩阵，记录 A/B 相对提升

### Day3-A/Day3-B 实测结论（2026-02-19 晚）
- 已新增策略：`footprint-desc` / `write-first` / `write-last` / `hot-bucket-interleave`。
- 对比脚本：`trillionnium-rust/scripts/run_bench_strategy_compare.sh`
- 报告样本：`trillionnium-rust/run/bench/bench-strategy-compare-20260219-211113.txt`
- 结论：
  - `footprint-desc/write-first/write-last` 对当前 mixed 样本几乎无结构性改善（与 original 基本持平）。
  - `hot-bucket-interleave` 在中低冲突（keys=5000/2000/500）有明显降组数（如 200→95, 482→389），
    但在极高冲突（keys=100）组数反而上升（1202→1744），且 elapsed_ms 增加（约 +7~9ms）。
- 决策：保持 `original` 为默认；`hot-bucket-interleave` 作为实验分支保留，进入 Day4 收敛评估。

## Day4
1. 收敛最佳方案
   - 合并最优实验路径
2. 回归保障
   - 运行 nightly health 等效子集（tests + state_root audit + bench）

### Day4 实跑结果（2026-02-19 晚）
- 收敛决策：
  - 默认策略保持 `original`（综合稳定性最好，且高冲突场景无退化）。
  - `hot-bucket-interleave` 继续保留为实验策略，不进入默认路径。
- Nightly 等效子集执行：
  1. `cargo test --workspace` ✅
  2. `./scripts/devnet_up.sh && sleep 12 && ./scripts/devnet_down.sh && ./scripts/audit_state_roots.sh` ✅
     - 报告：`trillionnium-rust/run/audit/state-root-audit-20260219-211304.txt`（`ok=true mismatch=0 missing=0`）
  3. `TXS=5000 ./scripts/run_bench_matrix.sh` ✅
     - 报告：`trillionnium-rust/run/bench/bench-matrix-20260219-211313.txt`
  4. `TXS=5000 ./scripts/run_bench_mixed_matrix.sh` ✅
     - 报告：`trillionnium-rust/run/bench/bench-mixed-matrix-20260219-211319.txt`
  5. `./scripts/executor_profile_report.py` ✅
     - 报告：`trillionnium-rust/run/bench/executor-profile-summary-20260219-211329.txt`
- 结论：Day4 收敛和回归门禁通过，可进入 Day5 RC 收口。

## Day5
1. RC 产出
   - 形成 P2 RC release note（含 break change 说明）
2. 风险登记
   - 明确兼容性影响、回滚策略、阈值变更（如需）

## Immediate next commands
```bash
# 1) 基线（已完成）
TXS=20000 ./scripts/run_bench_matrix.sh

# 2) 可选：高压样本
TXS=50000 ./scripts/run_bench_matrix.sh
```

## Notes
- 本阶段默认以性能上限优先，文档与治理项延后补齐。
- 若出现性能提升但 state_root 对账异常，视为无效优化。
