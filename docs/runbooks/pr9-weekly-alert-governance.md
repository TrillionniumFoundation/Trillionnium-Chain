# PR-9 Runbook：Weekly Alert Governance

目标：每周自动产出告警治理报告，聚合以下维度：

- 告警总量
- 抑制率（suppression rate）
- 失败率（failure rate）
- TopN 异常（复用 PR7 TopN 摘要）
- 阈值建议变更（复用 PR7 threshold advisor + PR9 env diff）

## 1) 脚本与产物

- 脚本：`scripts/v2/pr9_weekly_alert_governance.py`
- 默认输出：`run/pr9/weekly-alert-governance.md`

## 2) 使用方式

```bash
# 默认：7天窗口
python3 ./scripts/v2/pr9_weekly_alert_governance.py

# 自定义窗口/输出
python3 ./scripts/v2/pr9_weekly_alert_governance.py \
  --lookback-days 7 \
  --top-n 5 \
  --out run/pr9/weekly-alert-governance.md
```

## 3) 数据来源

- `run/pr7-alert-delivery/state.json`：告警发送/抑制/失败计数（主统计口径）
- `run/pr7-alert-delivery/dead-letter.jsonl`：近7天投递失败样本数
- `run/pr7-topn/*/topn-anomaly-summary.md`：TopN异常
- `run/pr7-threshold-advisor/*/threshold-advice.json`：阈值建议
- `run/pr9/alert-thresholds.env` 与 `run/pr9/alert-thresholds.previous.env`：阈值变更对比

## 4) Nightly 接入（非阻断）

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
- artifact 上传路径包含 `run/pr9/**`

## 5) 样例输出

- `examples/pr9-weekly-alert-governance/weekly-alert-governance.sample.md`

## 6) 验收清单

- [ ] `run/pr9/weekly-alert-governance.md` 自动生成
- [ ] 报告包含：告警总量、抑制率、失败率、TopN异常、阈值建议变更
- [ ] nightly 流程以非阻断方式接入（`continue-on-error: true`）
- [ ] artifact 包含 `run/pr9/**`
