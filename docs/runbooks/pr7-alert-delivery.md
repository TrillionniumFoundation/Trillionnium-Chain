# PR7 告警通知投递（alert-delivery）

目标：将 PR6 `summary.txt` 里的 `WARN/FAIL` 告警投递到消息通道（支持 iMessage / Slack Webhook / Telegram Bot），并提供去重防抖、失败重试、死信落盘与重放。

## 脚本

- `scripts/v2/pr7_alert_delivery.py`：读取 PR6 报告并投递（含 retry + dead-letter）
- `scripts/v2/pr7_alert_delivery_gate.sh`：串联 PR6 gate + PR7 投递
- `scripts/v2/pr7_dead_letter_replay.py`：重放 dead-letter

## 触发逻辑

- 从 `summary.txt` 解析 `status=PASS|WARN|FAIL`
- 默认 `ALERT_NOTIFY_MIN_LEVEL=WARN`
  - `PASS`：不发送
  - `WARN/FAIL`：发送
- 去重指纹由核心字段生成（status + 各 rule status/value）
- 在 `ALERT_NOTIFY_DEDUP_SECONDS` 窗口内，相同指纹不重复发送

## 可靠性逻辑（P8-2）

- 单次发送失败后，按指数退避重试：
  - 退避序列：`base_backoff_ms * 2^(attempt-1)`
  - 上限：`max_backoff_ms`
- 当总尝试次数超过 `max_retries + 1` 仍失败：
  - 记录到 `dead-letter.jsonl`
  - 返回退出码 `3`
- 可通过重放脚本补发 dead-letter；成功后会从 dead-letter 文件移除

## 环境变量

### 通用

- `ALERT_NOTIFY_CHANNEL`：`imessage` / `slack` / `telegram`
- `ALERT_NOTIFY_MIN_LEVEL`：`WARN`（默认）或 `FAIL`
- `ALERT_NOTIFY_DEDUP_SECONDS`：去重窗口秒数，默认 `1800`
- `ALERT_NOTIFY_STATE_FILE`：状态文件路径，默认 `run/pr7-alert-delivery/state.json`
- `ALERT_NOTIFY_DEAD_LETTER_FILE`：死信文件路径，默认 `run/pr7-alert-delivery/dead-letter.jsonl`
- `ALERT_NOTIFY_MAX_RETRIES`：失败后最大重试次数（不含首次），默认 `3`
- `ALERT_NOTIFY_BASE_BACKOFF_MS`：基础退避毫秒，默认 `500`
- `ALERT_NOTIFY_MAX_BACKOFF_MS`：最大退避毫秒，默认 `8000`
- `DRY_RUN=1`：演示模式，不真实发消息
- `ALERT_NOTIFY_DRY_RUN_SIMULATE_FAILURES`：仅 dry-run 生效，前 N 次尝试注入失败（用于演示 dead-letter）

### iMessage

- `IMESSAGE_TO`

### Slack

- `SLACK_WEBHOOK_URL`

### Telegram

- `TELEGRAM_BOT_TOKEN`
- `TELEGRAM_CHAT_ID`

## 用法

### A. 仅投递（已有 PR6 报告）

```bash
python3 scripts/v2/pr7_alert_delivery.py \
  --report run/pr6-alerts/<timestamp>/summary.txt \
  --channel imessage
```

### B. 串联执行（推荐）

```bash
ALERT_NOTIFY_CHANNEL=imessage \
./scripts/v2/pr7_alert_delivery_gate.sh
```

> `pr7_alert_delivery_gate.sh` 会先执行 PR6 gate 产出 `summary.txt`，再尝试投递；最终退出码保持 PR6 语义（用于 CI 兼容）。

## Dry-run 演示：失败入死信 + 重放清理

### 1) 构造一份 WARN 报告

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
```

### 2) 注入失败（超过重试后写 dead-letter）

```bash
DRY_RUN=1 ALERT_NOTIFY_DRY_RUN_SIMULATE_FAILURES=9 \
python3 scripts/v2/pr7_alert_delivery.py \
  --report /tmp/pr6-summary-warn.txt \
  --channel imessage \
  --state-file /tmp/pr7-state.json \
  --dead-letter-file /tmp/pr7-dead-letter.jsonl \
  --max-retries 2 \
  --base-backoff-ms 10 \
  --max-backoff-ms 20

cat /tmp/pr7-dead-letter.jsonl
```

### 3) 重放 dead-letter（dry-run 成功补发并清理）

```bash
python3 scripts/v2/pr7_dead_letter_replay.py \
  --dead-letter-file /tmp/pr7-dead-letter.jsonl \
  --dry-run \
  --max-retries 1 \
  --base-backoff-ms 10 \
  --max-backoff-ms 20

# 期望为空文件（或 remaining=0）
cat /tmp/pr7-dead-letter.jsonl
```

## 排障

- 出现 `dedup suppressed`：同指纹告警仍在去重窗口内，属预期
- 出现 `notify delivery exhausted retries`：查看 dead-letter 文件并重放
- 重放失败：检查通道密钥（`IMESSAGE_TO/SLACK_WEBHOOK_URL/TELEGRAM_*`）和网络连通性
