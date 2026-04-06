# Aggressive Round3 Patch B Report

日期：2026-02-20  
阶段：P3 / Week1 / Day4

---

## Patch B 内容

文件：`trillionnium/crates/trnm-executor/src/lib.rs`

- 将 Aggressive 默认路径重构为 **dependency-bound fast path**：
  - 默认不维护 deep-scan 专用的 group read/write hashset
  - 使用与 Original 同语义的 lower-bound 放置（按 latest reader/writer 依赖边界）
- Deep scan 完整路径保留为实验分支：
  - `TRNM_AGGR_DEEP_SCAN=1` 才启用

这次重点是**参数保护 + 默认安全高效路径**，避免实验逻辑在默认路径引入额外 CPU 开销。

---

## 验证

### 正确性
- `cargo test -q -p trnm-executor` 通过（6/6）

### 回归矩阵
- Patch A 基线：`run/bench/bench-regression-matrix-20260220-153932.csv`
- Patch B 结果：`run/bench/bench-regression-matrix-20260220-154327.csv`

---

## 关键结果

### 代表场景（mixed 20000/2000）
- Patch A: `69ms`
- Patch B: `36ms`
- 提升：**47.8%**（相对 Patch A）
- 对 Original 比值：**0.97x**（已达 `<1.8x` 目标）

### 全 workload 概览
- classic: Aggressive 与 Original 基本持平（1.00x）
- mixed: 0.97x ~ 1.00x
- hot-streak: 0.97x ~ 1.00x
- `candidate_groups_scanned`：默认路径保持 0（deep-scan 关闭）

---

## 风险说明

- 当前默认 Aggressive 与 Original 在行为上高度收敛（以性能稳定为优先）。
- 若需要继续探索更激进的 packing 收益，应在 `TRNM_AGGR_DEEP_SCAN=1` 下做受控实验，并通过门禁脚本验证回归风险。

---

## 结论

Patch B 完成 D4 阶段目标：
1. mixed 主场景比值显著低于 `<1.8x`；
2. 默认参数路径稳定且开销可控；
3. 实验能力保留在显式开关后，符合“实验态非默认”治理要求。
