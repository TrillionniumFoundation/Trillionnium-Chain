# Aggressive Round3 Patch A Report

日期：2026-02-20  
阶段：P3 / Week1 / Day3

---

## Patch A 内容

文件：`trillionnium/crates/trnm-executor/src/lib.rs`

- 在 `AggressiveGreedy` 路径引入 **lower-bound fast-path placement**：
  - 默认直接放入 `min_group`（由 latest writer/reader 依赖边界计算得到）
  - 跳过深度扫描路径
- 增加实验开关：`TRNM_AGGR_DEEP_SCAN`
  - `0`（默认）：启用 fast-path
  - `1`：回退到旧版深度扫描（便于 A/B）

设计意图：优先消除大量无效候选扫描和阶段冲突检查。

---

## 验证

### 正确性
- `cargo test -q -p trnm-executor` 全通过（6/6）

### 基准对比
- 旧基线：`run/bench/bench-regression-matrix-20260220-153109.csv`
- 新结果：`run/bench/bench-regression-matrix-20260220-153932.csv`

代表场景（mixed 20000/2000）：
- Aggressive：`85ms -> 69ms`（**18.8% 提升**）
- Original：`37ms`
- 比值：`2.30x -> 1.86x`

额外观测：
- `candidate_groups_scanned`：全 workload/key 档位从 ~14k~22k **降为 0**

---

## 整体结果摘要

- classic：约 **18%~21%** 提升，ratio 收敛到 **1.80x~2.00x**
- mixed：约 **16.7%~21.2%** 提升，ratio 收敛到 **1.81x~1.94x**
- hot-streak：约 **10%~16%** 提升，ratio 收敛到 **1.95x~2.06x**

---

## 结论

- Patch A 达成 Week1 D3 阶段目标（代表场景 >8%）。
- mixed 主场景已逼近 `<1.8x` 目标边缘，但尚未全面达标。
- 建议进入 D4（Patch B）：
  1) 针对 hot-streak 继续压缩比值；
  2) 增加受控参数保护与 CI 口径说明（`TRNM_AGGR_DEEP_SCAN`）。
