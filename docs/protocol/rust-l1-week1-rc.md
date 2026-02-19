# Rust L1 Week-1 RC 说明

日期：2026-02-19
状态：Release Candidate（MVP）

## 本周交付摘要

- 已完成 Rust workspace 与核心 crates 骨架
- 已完成 PoUW 关键状态机路径（create/commit/reveal/challenge/resolve）
- 已完成 commitment 校验与 forged reveal 拒绝用例
- 已完成版本化状态存储与 state root 原型
- 已完成 node mock 出块与按块执行 demo mempool
- 已完成冲突检测与并发分组 planning
- 已完成首版 grouping benchmark

## 一键演示

```bash
cd trillionnium-rust
./scripts/demo_day7.sh
```

## RC 打包

```bash
cd trillionnium-rust
./scripts/release_rc.sh
```

输出目录：`trillionnium-rust/release/rc-<timestamp>/`

## 已知限制（MVP）

1. 共识层仍为 mock block loop，未接入生产 BFT 网络
2. mempool 为内存 demo 数据源
3. 并行执行已具备组内 pre-exec + 确定性提交，但仍缺少真实网络下的端到端压测闭环
4. 缺少生产级持久化与故障恢复语义（当前以内存态为主）

## 自动化健康检查（已接入）

- workflow：`.github/workflows/rust-l1-nightly-health.yml`
- 覆盖内容：
  1. `cargo test --workspace`
  2. `devnet_up/down + audit_state_roots.sh`
  3. 并行模式硬门禁（`trnm-node --parallel-workers 4`）
  4. `TXS=5000 run_bench_matrix.sh`
  5. `TXS=5000 run_bench_mixed_matrix.sh`
  6. `executor_profile_report.py` 汇总产出
- 产物：`run/audit/**`、`run/bench/**`、`run/node*.log`、`run/parallel-sanity.log`（以 artifact 上传）
- CI 阈值（warning + hard fail）：
  - 审计报告必须满足：`summary ok=true mismatch=0 missing=0`
  - classic warning/hard：`BENCH_WARN_MS=300` / `BENCH_MAX_MS=600`
  - mixed warning/hard：`BENCH_MIXED_WARN_MS=300` / `BENCH_MIXED_MAX_MS=600`

## 下阶段优先项

1. 真实并行执行器（组内 worker 并发 + 冲突回退）
2. 3 节点网络一致性对账（state root 对齐）
3. 压测维度扩展（吞吐/延迟/冲突率曲线）
4. 启动真实测试网 runbook
