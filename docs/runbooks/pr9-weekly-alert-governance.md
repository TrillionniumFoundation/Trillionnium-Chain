# PR-9 Runbook：Weekly Alert Governance（含上周对比）

目标：每周自动产出告警治理报告，并提供与上周基线的差异分析（week-over-week）。

覆盖维度：

- 告警总量（alerts.total）
- 抑制率（suppression rate）
- 失败率（failure rate）
- TopN 异常变化（新增/退出/排名变动）
- 阈值变化（本周 env diff + 相比上周变化键集合）

## 1) 脚本与产物

- 脚本：`scripts/v2/pr9_weekly_alert_governance.py`
- 默认输出（Markdown）：`run/pr9/weekly-alert-governance.md`
- 默认输出（JSON）：`run/pr9/weekly-alert-governance.json`
- 历史快照（JSON）：`run/pr9/history/weekly-alert-governance-YYYYMMDDTHHMMSSZ.json`

> 说明：脚本会在每次运行后写入一份 history 快照，供下周对比使用。

## 2) 使用方式

```bash
# 默认：7天窗口
python3 ./scripts/v2/pr9_weekly_alert_governance.py

# 自定义窗口/输出
python3 ./scripts/v2/pr9_weekly_alert_governance.py \
  --lookback-days 7 \
  --top-n 5 \
  --out run/pr9/weekly-alert-governance.md \
  --json-out run/pr9/weekly-alert-governance.json \
  --history-dir run/pr9/history
```

## 3) 数据来源

- `run/pr7-alert-delivery/state.json`：告警发送/抑制/失败计数（主统计口径）
- `run/pr7-alert-delivery/dead-letter.jsonl`：近N天投递失败样本数
- `run/pr7-topn/*/topn-anomaly-summary.md`：TopN异常
- `run/pr7-threshold-advisor/*/threshold-advice.json`：阈值建议
- `run/pr9/alert-thresholds.env` 与 `run/pr9/alert-thresholds.previous.env`：本周阈值变更对比
- `run/pr9/history/weekly-alert-governance-*.json`：上周基线（自动选择最新一份）

## 4) 上周对比逻辑

脚本自动读取最近一份历史 JSON 作为基线，生成以下 diff：

- `alerts_total_delta`
- `suppression_rate_pct_delta`（百分点，pp）
- `failure_rate_pct_delta`（百分点，pp）
- TopN 变化：
  - `entered`
  - `exited`
  - `rank_shift`（from/to/Δrank）
- 阈值变化键集合差异：
  - `threshold_changed_keys_delta`
  - `threshold_new_keys_vs_last_week`
  - `threshold_removed_keys_vs_last_week`

## 5) 优雅降级（缺历史/缺数据）

当历史或部分输入缺失时，脚本不会失败，而是降级输出：

- 无上周基线：
  - Markdown 显示 `baseline unavailable`
  - JSON `week_over_week.available=false`
  - 对应 delta 字段为 `null`
- 无 TopN 源：
  - TopN section 输出 `no data / section empty`
  - JSON `degraded.missing_topn_source=true`
- 无 threshold advisor：
  - Markdown 输出 `threshold-advice unavailable`
  - JSON `degraded.missing_threshold_advice_source=true`

## 6) Nightly 接入（非阻断）

`rust-l1-nightly-health.yml` 推荐（已可用）配置：

```yaml
- name: Build PR-9 weekly alert governance (non-gate)
  if: always()
  continue-on-error: true
  run: |
    set -euo pipefail
    python3 ./scripts/v2/pr9_weekly_alert_governance.py
```

并追加：
- Step Summary 附加 `run/pr9/weekly-alert-governance.md`
- artifact 上传路径包含 `run/pr9/**`（含 `.md` + `.json`）

## 7) 样例输出

- Markdown：`examples/pr9-weekly-alert-governance/weekly-alert-governance.sample.md`
- JSON：`examples/pr9-weekly-alert-governance/weekly-alert-governance.sample.json`

## 8) 验收清单

- [ ] `run/pr9/weekly-alert-governance.md` 自动生成
- [ ] `run/pr9/weekly-alert-governance.json` 自动生成
- [ ] 报告包含与上周对比（总量、抑制率、失败率、TopN变化、阈值变化）
- [ ] 缺历史数据时优雅降级（不报错）
- [ ] nightly 流程以非阻断方式接入（`continue-on-error: true`）
- [ ] artifact 包含 `run/pr9/**`
