# Aggressive Round3 Week1 Report

日期：2026-02-20  
阶段：P3 / Week1（D1-D5）

---

## 本周目标回顾

目标：建立“归因 -> 优化 -> 验证 -> 门禁”的闭环，并把 mixed 代表场景比值压到可接受区间。

---

## 关键产物

1. D1 基线
- `docs/strategy/p3-week1-baseline.md`
- `run/bench/bench-regression-matrix-20260220-153109.csv`

2. D2 指标扩展
- `trillionnium/scripts/summarize_aggressive_profile.py`
- `docs/perf/aggressive-round3-metrics.md`

3. D3 Patch A
- `docs/perf/aggressive-round3-patch-a-report.md`
- `run/bench/bench-regression-matrix-20260220-153932.csv`

4. D4 Patch B
- `docs/perf/aggressive-round3-patch-b-report.md`
- `run/bench/bench-regression-matrix-20260220-154327.csv`

5. D5 门禁口径收敛
- `trillionnium/scripts/check_aggressive_regression.sh`（默认阈值收紧）
- `.github/workflows/rust-l1-nightly-health.yml`（nightly 阈值同步收紧）

---

## 结果摘要

### 代表场景（mixed 20000/2000）
- Week1 起点：Aggressive ~85ms，Original ~37ms（2.30x）
- Week1 终点：Aggressive ~36ms，Original ~37ms（0.97x）

### 过程收益
- Patch A：85ms -> 69ms（+18.8%）
- Patch B：69ms -> 36ms（再 +47.8%）
- 累计：85ms -> 36ms（约 +57.6%）

### 指标变化
- 默认路径 `candidate_groups_scanned`：2万级 -> 0
- 三类 workload 比值收敛到约 0.97x~1.00x

---

## 治理与风险

### 本周治理动作
- Deep scan 保留实验能力，但默认关闭：`TRNM_AGGR_DEEP_SCAN=1` 才开启。
- nighty ratio gate 从宽松值（3.75~4.75）收紧到：
  - classic <= 2.20
  - mixed <= 2.00
  - hot-streak <= 2.10

### 风险提示
- 默认 Aggressive 现已接近 Original 语义与性能；创新收益需在 deep-scan 分支继续探索。
- 后续如推进“重新拉开性能上限”，需在实验开关下做独立 A/B，不得影响默认稳定路径。

---

## Week1 Go/No-Go

结论：**GO**（进入 Week2）

理由：
1. 代表场景达标并显著优于 Week1 目标线；
2. 门禁已收紧，回归风险可控；
3. 默认路径 correctness 与性能均稳定。

---

## Week2 建议动作

1. 保持默认路径稳定，禁止无证据“激进改动”入主线；
2. 在 `TRNM_AGGR_DEEP_SCAN=1` 下继续做 Hot-streak 专项 A/B；
3. 把深扫实验结果纳入单独实验报告，不与默认 gate 混淆。
