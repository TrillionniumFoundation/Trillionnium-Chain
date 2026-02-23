# PR-7 Runbook: 7天趋势阈值建议器（threshold-advisor）

## 目标
基于历史产物自动给出挑战告警阈值建议（`unresolved_challenges` / `forfeits_daily_increase` / `escrow_nonzero_hours`），并同时输出：

- 机器可读 JSON
- 人类可读 Markdown

当数据不足时，回退到保守默认（沿用 PR6 gate 阈值；若 gate 缺失则使用内置默认）。

## 输入来源
- `run/pr5-reconcile/*/reconcile-report.txt`（优先）
- `run/pr5-reconcile/*/summary.txt`（回退）
- `run/pr6-ops/pr6-alert-rules-gate.txt`（当前基线阈值 + 当前观测）

## 脚本
- `scripts/v2/pr7_threshold_advisor.py`

## 用法
```bash
# 默认：看最近7天，要求至少3天样本
scripts/v2/pr7_threshold_advisor.py

# 自定义参数
scripts/v2/pr7_threshold_advisor.py \
  --pr5-root run/pr5-reconcile \
  --pr6-ops-root run/pr6-ops \
  --lookback-days 7 \
  --min-days 3 \
  --out-dir run/pr7-threshold-advisor/manual-$(date +%Y%m%d-%H%M%S)
```

## 参数说明
- `--pr5-root`：PR5 历史产物根目录。
- `--pr6-ops-root`：PR6 ops 产物根目录（读取 gate 基线阈值）。
- `--lookback-days`：趋势窗口天数（默认 `7`）。
- `--min-days`：进入“趋势计算模式”所需最小样本天数（默认 `3`）。
- `--out-dir`：输出目录；为空时自动写入 `run/pr7-threshold-advisor/<timestamp>`。

## 结果解释
- `mode=trend_based`：样本充足，按7天趋势建议阈值（含 tail buffer）。
- `mode=conservative_default`：样本不足，保守回退至 PR6 基线阈值。

## 样例输出
- `examples/pr7-threshold-advisor/threshold-advice.sample.json`
- `examples/pr7-threshold-advisor/threshold-advice.sample.md`
