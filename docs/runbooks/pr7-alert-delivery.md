# PR7 告警通知投递（alert-delivery）

目标：将 PR6 `summary.txt` 里的 `WARN/FAIL` 告警投递到消息通道（当前支持 Slack Webhook / Telegram Bot），并提供去重防抖（窗口内相同告警不重复发送）。

## 脚本

- `scripts/v2/pr7_alert_delivery.py`：读取 PR6 报告并投递
- `scripts/v2/pr7_alert_delivery_gate.sh`：串联 PR6 gate + PR7 投递

## 触发逻辑

- 从 `summary.txt` 解析 `status=PASS|WARN|FAIL`
- 默认 `ALERT_NOTIFY_MIN_LEVEL=WARN`
  - `PASS`：不发送
  - `WARN/FAIL`：发送
- 去重指纹由核心字段生成（status + 各 rule status/value）
- 在 `ALERT_NOTIFY_DEDUP_SECONDS` 窗口内，相同指纹不重复发送

## 环境变量

### 通用

- `ALERT_NOTIFY_CHANNEL`：`slack`（默认）或 `telegram`
- `ALERT_NOTIFY_MIN_LEVEL`：`WARN`（默认）或 `FAIL`
- `ALERT_NOTIFY_DEDUP_SECONDS`：去重窗口秒数，默认 `1800`
- `ALERT_NOTIFY_STATE_FILE`：状态文件路径，默认 `run/pr7-alert-delivery/state.json`
- `DRY_RUN=1`：本地演示模式，不实际发消息

### Slack

- `SLACK_WEBHOOK_URL`：Incoming Webhook URL

### Telegram

- `TELEGRAM_BOT_TOKEN`
- `TELEGRAM_CHAT_ID`

## 用法

### A. 仅投递（已有 PR6 报告）

```bash
DRY_RUN=1 \
python3 scripts/v2/pr7_alert_delivery.py \
  --report run/pr6-alerts/<timestamp>/summary.txt \
  --channel slack
```

### B. 串联执行（推荐）

```bash
DRY_RUN=1 \
ALERT_NOTIFY_CHANNEL=slack \
./scripts/v2/pr7_alert_delivery_gate.sh
```

> `pr7_alert_delivery_gate.sh` 会先执行 PR6 gate 产出 `summary.txt`，再尝试投递；最终退出码保持 PR6 语义（用于 CI 兼容）。

## 本地无密钥测试（最小可靠路径）

```bash
cat > /tmp/pr6-summary-warn.txt <<'EOF'
status=WARN
alert_code=PR6_ALERT_RULES
alert_message=[PR6][WARN] challenge risk snapshot @ 2026-02-23T10:00:00+00:00 | unresolved=4 | forfeits_daily_increase=72 | escrow_nonzero_hours=17.20
generated_at_utc=2026-02-23T10:00:00+00:00
rule.unresolved_challenges.status=WARN
rule.unresolved_challenges.value=4
rule.forfeits_daily_increase.status=WARN
rule.forfeits_daily_increase.value=72
rule.escrow_nonzero_hours.status=WARN
rule.escrow_nonzero_hours.value=17.20
EOF

DRY_RUN=1 python3 scripts/v2/pr7_alert_delivery.py --report /tmp/pr6-summary-warn.txt --channel slack
```

重复执行同命令（在 dedup 窗口内）应看到 `dedup suppressed`，用于防止狂发。
