# Aggressive Round3 Metrics（D2）

日期：2026-02-20  
阶段：P3 / Week1 / Day2

---

## 输入数据

- 基线 CSV：
  - `trillionnium/run/bench/bench-regression-matrix-20260220-153109.csv`
- 汇总脚本：
  - `trillionnium/scripts/summarize_aggressive_profile.py`（已扩展 CSV 聚合能力）
- 汇总产物：
  - `trillionnium/run/bench/aggressive-profile-summary-20260220-1532.md`

---

## 新增指标（本次已可用）

1. `scan_per_tx`：每 tx 平均候选扫描数（`candidate_groups_scanned / txs`）
2. `scan_per_group`：每组平均扫描数（`candidate_groups_scanned / groups`）
3. 冲突命中率：
   - `ww_hit_rate`
   - `wr_hit_rate`
   - `rw_hit_rate`
   - `total_hit_rate`
4. 按 workload 聚合：
   - `avg_ratio` / `p95_ratio`
   - `avg_scan_tx` / `avg_scan_group`
   - `avg_total_hit`

---

## 当前读数（关键结论）

### 性能比值（Aggressive / Original）
- classic: avg **2.384x**（最差 2.480x）
- mixed: avg **2.286x**（p95 2.297x）
- hot-streak: avg **2.276x**（p95 2.351x）

### 扫描特征
- mixed: `avg_scan_tx=1.085`（三类中最高）
- classic: `avg_scan_group=759.0`（分组内扫描成本极高）
- hot-streak: `avg_scan_group=13.933`（显著低于 classic/mixed）

### 冲突命中特征
- mixed 的 `wr_hit_rate` 与 `total_hit_rate` 相对最高（存在可利用结构）
- classic / hot-streak 命中率几乎为 0，说明大量扫描未转化为有效命中

---

## D2 结论

- Round3 的主攻点应优先放在：
  1) 降低 classic 场景的组内无效扫描；
  2) 利用 mixed 场景已有 wr 命中信号，做“命中优先”的候选筛选。

---

## 指标缺口（D3 前置）

以下指标需要在 Rust 侧继续补点（当前 CSV 尚无）：

1. 每 tx 冲突判定耗时分布（p50/p95/p99）
2. 每 block 候选组扫描分布（均值+分位）
3. 明确“无效扫描”口径（扫描后未形成有效分组/命中）

建议在 `trnm-executor` profile 输出新增上述字段后，复用现有汇总脚本接入。
