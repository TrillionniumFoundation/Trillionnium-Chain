# Trillionnium Progress Board (2026-02-21)

## 已完成（Done）

1. 对标流水线基础设施
- 100-step 流水线（已跑通）
- 200-step 主流水线（已跑通，含断点续跑）
- 200-step v2 流水线（reports + soak + gov-mvp + ecosystem alpha，已跑通）

2. 关键兼容性修复
- `summarize_aggressive_profile.py` Python < 3.10 兼容
- `analyze_aggressive_scan_correlation.py` Python < 3.10 兼容
- 流水线 cargo PATH 问题修复

3. 策略与路线文档
- 12 周路线图（共识→治理→生态）
- crate 级 Rust issue 清单（A1~C3）
- v2 200-step 合并最终报告

4. codegen 自动流水线
- `run_codegen_pipeline.sh` 已落地并执行全绿（16/16）
- A2/A3 scaffold 已落库：
  - `trillionnium-rust/scripts/run_consensus_fault_matrix.sh`
  - `docs/protocol/consensus-v1-freeze.md`

---

## 进行中（In Progress）

- 从“脚手架自动化”转入“真实 Rust 功能实现”：
  - A1: finality/recovery 指标内建化（`trnm-node`）
  - B1: gov 状态机最小实现（`trnm-state` + `trnm-node`）

---

## 待执行（Next Up）

### Next-1（优先级 P0）
A1 实码实现（非 scaffold）：
- 在 `trnm-node` 增加 finality/recovery 指标输出结构
- 在 `testnet_preflight.sh` 增加指标存在性 gate
- 增加最小测试用例 + 文档字段对齐

### Next-2（优先级 P1）✅ 已完成
A2 已从脚手架升级到可执行 fault matrix：
- 已覆盖 3 类场景（baseline / slow_block / restart_recovery）
- 已产出结构化报告：`trillionnium-rust/run/health/consensus-fault-matrix-20260221-074329.txt`

### Next-3（优先级 P1）
B1 治理状态机最小闭环：
- proposal -> voting -> passed/rejected -> executed
- 非法迁移稳定错误码

---

## 当前结论
- 自动化体系已成型并稳定。
- 现阶段瓶颈不在“再加脚本”，而在“把 A1/B1 变成真实 Rust 功能代码并门禁化”。
