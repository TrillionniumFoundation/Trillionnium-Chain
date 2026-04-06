# L19 Ops Observability / Alerting / Reconcile Runbook

适用范围：TRNM lane L19 的 PR-5 / PR-6 / PR-7 / PR-9 运维链路，以及 oracle baseline 基线产物。

## Owned surfaces

- `OPERATIONS.md`
- `docs/runbooks/`
- `scripts/v2/pr5_*`
- `scripts/v2/pr6_*`
- `scripts/v2/pr7_*`
- `scripts/v2/pr9_*`
- `trillionnium/scripts/oracle`
- `trillionnium/docs/reports/oracle-baseline.md`

## Required gate set

在仓库根目录执行：

```bash
./scripts/v2/pr5_reconcile_conservation_test.sh
./scripts/v2/pr5_challenge_reconcile_gate.sh
./scripts/v2/pr6_alert_rules_gate.sh
./scripts/v2/pr7_alert_delivery_gate.sh
python3 ./scripts/v2/pr9_weekly_alert_governance.py
cd trillionnium && ./scripts/run_oracle_baseline.sh
```

通过标准：
- PR-5/6/7 gate 返回码为 `0`
- PR-9 成功写出当前周 `.md/.json`
- oracle baseline 成功输出 baseline + bench JSON

---

## PR-5 Reconcile（challenge / treasury / forfeits）

### Purpose
确认 challenge bond、refund、forfeit、treasury delta 在日志聚合后保持守恒，并能把异常写进对账报告。

### Primary commands

```bash
./scripts/v2/pr5_treasury_reconcile_report.sh
./scripts/v2/pr5_reconcile_conservation_test.sh
./scripts/v2/pr5_challenge_reconcile_gate.sh
```

### Inputs
- 默认事件日志：`trillionnium/run/event-field-check.log`
- 可覆盖：`SOURCE_LOG=<path>`

### Outputs
- `run/pr5-reconcile/<timestamp>/summary.txt`
- `run/pr5-reconcile/<timestamp>/reconcile.json`
- `run/pr5-reconcile/<timestamp>/reconcile-report.txt`
- `run/pr5-reconcile/<timestamp>/triad/triad-consistency.txt`

### Fast triage
先看：
- `status=`
- `conservation.gap=`
- `conservation.detail_count=`
- `conservation.detail.*=`

常见异常：
- `refund mismatch`
- `nonzero treasury_delta`
- challenge / resolve 缺配对

如果只是本地排障，可直接指定可疑日志：

```bash
SOURCE_LOG=/path/to/event.log ./scripts/v2/pr5_treasury_reconcile_report.sh
```

---

## PR-6 Alert Rules

### Purpose
根据 challenge 运维日志生成 `PASS/WARN/FAIL` 告警摘要，供 PR-7 投递和 PR-9 周报消费。

### Primary command

```bash
./scripts/v2/pr6_alert_rules_gate.sh
```

### Important env
- `EVENT_LOG`：默认 `trillionnium/run/event-field-check.log`
- `WINDOW_HOURS`：默认 `48`
- `FAIL_UNRESOLVED_CHALLENGES` / `WARN_UNRESOLVED_CHALLENGES`
- `FAIL_FORFEITS_DAILY_INCREASE` / `WARN_FORFEITS_DAILY_INCREASE`
- `FAIL_ESCROW_NONZERO_HOURS` / `WARN_ESCROW_NONZERO_HOURS`
- `CI_HARD_FAIL_ON_WARN=1`：WARN 也非 0
- `ALERT_POLICY_FILE` / `ALERT_POLICY_PROFILE`：启用版本化 policy 解析

### Outputs
- `run/pr6-alerts/<timestamp>/summary.txt`
- 可选：`run/pr6-alerts/<timestamp>/policy.env`

### Summary fields to inspect
- `status=`
- `alert_code=` / `alert_message=`
- `events_in_window=`
- `rule.unresolved_challenges.*`
- `rule.forfeits_daily_increase.*`
- `rule.escrow_nonzero_hours.*`

### Failure modes
- `rc=2`：参数非法
- `rc=3`：输入日志缺失或不可读
- `rc=4`：报告未生成、为空或缺 `status=`

---

## PR-7 Alert Delivery

### Purpose
把 PR-6 的 `WARN/FAIL` 摘要投递到消息通道，并做去重、防抖、重试、dead-letter、主备路由与失败升级。

### Recommended local smoke

```bash
DRY_RUN=1 ALERT_NOTIFY_CHANNEL=slack PR7_DELIVERY_FAIL_MODE=warn \
  ./scripts/v2/pr7_alert_delivery_gate.sh
```

### Core env
- `ALERT_NOTIFY_CHANNEL=slack|telegram|imessage`
- `ALERT_NOTIFY_PRIMARY_CHANNEL`
- `ALERT_NOTIFY_BACKUP_CHANNEL`
- `ALERT_NOTIFY_MIN_LEVEL=INFO|WARN|CRITICAL`（兼容 `PASS->INFO`、`FAIL->CRITICAL` 别名）
- `ALERT_NOTIFY_DEDUP_SECONDS`
- `ALERT_NOTIFY_AGGREGATE_SECONDS`
- `ALERT_NOTIFY_STATE_FILE`：默认 `run/pr7-alert-delivery/state.json`
- `ALERT_NOTIFY_AUDIT_FILE`：默认 `run/pr7-alert-delivery/audit.jsonl`
- `ALERT_NOTIFY_DEAD_LETTER_FILE`：默认 `run/pr7-alert-delivery/dead-letter.jsonl`
- `ALERT_NOTIFY_GLOBAL_RETRY_BUDGET_STATE_FILE`：默认 `run/pr7-alert-delivery/retry-budget-state.json`
- `PR7_DELIVERY_FAIL_MODE=ignore|warn|escalate`
- `DRY_RUN=1`

通道凭据：
- Slack：`SLACK_WEBHOOK_URL`
- Telegram：`TELEGRAM_BOT_TOKEN` + `TELEGRAM_CHAT_ID`
- iMessage：`IMESSAGE_TO`

### Outputs
- `run/pr7-alerts/<timestamp>-pid*/summary.txt`
- `run/pr7-alerts/<timestamp>-pid*/policy.env`（PR-6/PR-7 本次实际生效的策略快照）
- `run/pr7-alerts/<timestamp>-pid*/pr7-delivery-status.env`
- `run/pr7-alert-delivery/state.json`
- `run/pr7-alert-delivery/audit.jsonl`
- `run/pr7-alert-delivery/dead-letter.jsonl`
- `run/pr7-alert-delivery/retry-budget-state.json`

### Status file fields worth checking
- `status`
- `pr6_rc` / `pr7_rc` / `final_rc`
- `fail_mode`
- `delivery_event`
- `primary_channel` / `backup_channel`
- `success_channels` / `failed_channels`
- `channels_ok` / `channels_failed`
- `partial_success`
- `lock_dir`
- `audit_file`

### Triage notes
- 若 `status=PASS` 且 `ALERT_NOTIFY_MIN_LEVEL=WARN`，出现 `skip: level=INFO below min_level=WARN` 属预期。
- 若需要“规则通过但投递失败也升级”，用 `PR7_DELIVERY_FAIL_MODE=escalate`。
- 若只想保留可观测性、不阻断本地 smoke，用 `PR7_DELIVERY_FAIL_MODE=warn`。
- 若 `status=LOCK_TIMEOUT` / `pr7_rc=5`，优先检查并清理遗留锁目录 `run/pr7-alert-delivery/.gate-lock`，再确认是否存在并发 gate run 导致的锁竞争。

---

## PR-6 Nightly Daily Security Summary

### Command

```bash
python3 ./scripts/v2/pr6_daily_security_summary.py
```

### Output
- `run/pr6-ops/daily-security-summary.md`

### What it summarizes
- PR-5 reconcile 状态
- PR-7 TopN / delivery state 是否可见
- 若干 nightly 产物是否缺失（以 `MISSING` 标记）

这一步更偏“汇总展示”，不是规则判定入口。

---

## PR-9 Weekly Alert Governance

### Purpose
生成每周告警治理报告，聚合发送量、抑制量、失败量、dead letter、TopN 异常、阈值建议和 week-over-week diff。

### Primary command

```bash
python3 ./scripts/v2/pr9_weekly_alert_governance.py
```

### Helpful pre-steps

```bash
./scripts/v2/pr7_topn_summary_gate.sh
python3 ./scripts/v2/pr7_threshold_advisor.py
python3 ./scripts/v2/pr9_weekly_alert_governance.py
```

### Outputs
- `run/pr9/weekly-alert-governance.md`
- `run/pr9/weekly-alert-governance.json`
- `run/pr9/history/weekly-alert-governance-YYYYMMDDTHHMMSSZ.json`

### Optional args
- `--lookback-days <n>`
- `--top-n <n>`
- `--out <path>`
- `--json-out <path>`
- `--history-dir <path>`

### Expected degraded behavior
- 无上一周 baseline：Markdown/JSON 仍输出，但写 `baseline unavailable`
- 无 TopN 或 threshold advice：在 JSON `degraded.*` 中标记，并在 Markdown 写 `MISSING` / `unavailable`
- 若当前 JSON 与最新历史快照完全相同：跳过新的 history snapshot，仅刷新当前周 `.md/.json`
- 选择 week-over-week baseline 时会忽略未来时间戳的 stray history snapshot，避免被未来产物污染

### Triage fields
- `metrics.alerts_sent` / `metrics.alerts_suppressed` / `metrics.alerts_failed`
- `metrics.dead_letter_entries`
- `degraded.*`
- `week_over_week.*`

---

## Oracle baseline

### Command

```bash
cd trillionnium
./scripts/run_oracle_baseline.sh
```

### Outputs / expectations
终端会打印两段 JSON：
- `baseline`
- `bench`

主要指标：
- `oracle_ingest_latency_ms`
- `oracle_stale_reject_total`
- `oracle_quorum_reject_total`
- `oracle_drift_reject_total`
- `oracle_source_cardinality`
- `ingest_latency_p50_ms`
- `ingest_latency_p95_ms`
- `ingest_latency_max_ms`

文档基线说明：`trillionnium/docs/reports/oracle-baseline.md`

---

## Suggested cron / CI posture

- PR-6 / PR-7：阻断或半阻断，取决于 `CI_HARD_FAIL_ON_WARN` 与 `PR7_DELIVERY_FAIL_MODE`
- PR-9：建议 `continue-on-error: true`
- Oracle baseline：可作为非阻断基线观测，也可在后续引入 p95 阈值门禁

## Minimal incident checklist

1. 先确认输入日志是否存在、可读、时间窗口正确。
2. 再确认 PR-5 对账是否已经出现 `conservation.detail.*` 异常。
3. 若 PR-6 异常，直接检查 `summary.txt` 三组 `rule.*` 字段。
4. 若 PR-7 无消息，先看 `pr7-delivery-status.env`，再看 `audit.jsonl` / `dead-letter.jsonl`。
5. 若 PR-9 数据不全，确认 PR-7 state、TopN 摘要、threshold advice 是否实际生成。
6. 若 oracle baseline 漂移，记录 baseline/bench JSON 并与上次产物对比，不在 L19 里顺手改核心 oracle 逻辑。
