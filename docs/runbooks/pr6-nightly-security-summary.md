# PR-6 Runbook：Nightly Daily Security Summary

目标：在 nightly 流程末尾自动生成一份可读、可追溯的安全日报，统一输出关键指标与告警。

## 1) 产物与位置

- 主报告：`run/pr6-ops/daily-security-summary.md`
- 触发方式：
  - GitHub Actions：`rust-l1-nightly-health`（自动）
  - 本地手动：

```bash
python3 ./scripts/v2/pr6_daily_security_summary.py
```

## 2) 指标来源（脚本自动探测）

- `trillionnium-rust/run/health/nightly-attribution-*.txt`
  - `attribution.labels`
  - `attribution.reasons`
- `trillionnium-rust/run/health/nightly-summary-*.md`
- `trillionnium-rust/run/health/auto-adaptive-threshold-suggestion-*.txt`
- `trillionnium-rust/run/bench/aggressive-profile-summary-*.md`
- `run/pr5-reconcile/*/summary.txt`
  - `status`
  - `record_count`
  - `challenge_events/resolve_events`
  - `forfeited/refunded`
  - `treasury_delta_sum/challenger_delta_sum`

## 3) 告警规则（当前版本）

以下任一触发将进入 `## Alerts`：

- nightly attribution label 非 `green/healthy/unknown`
- PR-5 对账 `status != PASS`
- 缺失关键产物：nightly attribution / nightly summary / PR-5 summary

## 4) 与 workflow summary/artifacts 的集成

`rust-l1-nightly-health.yml` 已接入：

1. 运行 `python3 ./scripts/v2/pr6_daily_security_summary.py`
2. 将 `run/pr6-ops/daily-security-summary.md` 追加到 `GITHUB_STEP_SUMMARY`
3. 上传 `run/pr6-ops/**` 到 nightly artifacts

## 5) 值班使用建议

- Step Summary 中快速看：`## PR-6 Daily Security Ops`
- 如有告警，先按 `Artifact Pointers` 回到源文件定位原因
- PR-5 相关异常，联动 runbook：`docs/runbooks/pr5-challenge-treasury-reconcile.md`

## 6) 验收清单（PR-6）

- [ ] nightly 结束后存在 `run/pr6-ops/daily-security-summary.md`
- [ ] 报告包含 Key Metrics + Alerts + Artifact Pointers
- [ ] Step Summary 出现 `PR-6 Daily Security Ops` 小节
- [ ] nightly artifact 包含 `run/pr6-ops/**`
