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

## Day4
1. 收敛最佳方案
   - 合并最优实验路径
2. 回归保障
   - 运行 nightly health 等效子集（tests + state_root audit + bench）

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
