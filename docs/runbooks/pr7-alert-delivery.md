# PR7 告警通知投递（alert-delivery）

目标：将 PR6 `summary.txt` 里的 `WARN/FAIL` 告警投递到消息通道（支持 iMessage / Slack Webhook / Telegram Bot），并提供去重防抖、失败重试、死信落盘与重放；同时支持告警治理策略（quiet-hours + WARN 自动升级 CRITICAL）以及多通道路由（主/备 + 失败自动切备 + 审计）。

## 脚本

- `scripts/v2/pr7_alert_delivery.py`：读取 PR6 报告并投递（含 retry + dead-letter）
- `scripts/v2/pr7_alert_delivery_gate.sh`：串联 PR6 gate + PR7 投递
- `scripts/v2/pr7_dead_letter_replay.py`：重放 dead-letter

## 触发逻辑

- 从 `summary.txt` 解析 `status=PASS|WARN|FAIL`
- 默认 `ALERT_NOTIFY_MIN_LEVEL=WARN`
  - `PASS`：不发送
  - `WARN/FAIL`：发送
- 路由策略：
  - `WARN`：发送到主通道（`primary-channel`）
  - `CRITICAL`：发送到主通道 + 备通道（若已配置）
  - 若 `WARN` 主通道投递失败，自动切到备通道重试（fallback）
- 去重指纹由核心字段生成（status + 各 rule status/value）
- 在 `ALERT_NOTIFY_DEDUP_SECONDS` 窗口内，相同指纹不重复发送

## 告警治理策略（P9）

### 1) Quiet Hours（夜间仅 CRITICAL）

- 开启后，quiet-hours 窗口内仅允许 `CRITICAL` 投递；`INFO/WARN` 会被抑制并计入 `alerts_suppressed`
- **安全约束（Round-3 修复）**：quiet-hours 判断基于原始告警级别执行（`status/alert_level`），在 quiet-hours 内即使命中 `WARN->CRITICAL` 升级阈值也不会绕过静默
- **一致性约束（Round-3 Hotfix）**：若 `status` 与 `alert_level` 同时存在且映射不一致（例如 `status=WARN` + `alert_level=CRITICAL`），则直接拒绝发送并写入审计（`audit.jsonl` 中 `rejected=true`），防止通过字段冲突绕过 quiet-hours 与策略判断
- 适用于值班降噪，避免夜间非关键告警打扰

### 2) 连续 WARN 自动升级 CRITICAL

- 当同类 `WARN` 在升级窗口内达到 `N` 次时，当前告警自动提升为 `CRITICAL`
- 升级后会在消息中附带：`escalated_from=WARN (streak=..., threshold=...)`
- 升级成功发送后会重置该类 WARN streak 计数

## 可靠性逻辑（P8-2）

- 单次发送失败后，按指数退避重试：
  - 退避序列：`base_backoff_ms * 2^(attempt-1)`
  - 上限：`max_backoff_ms`
- 当总尝试次数超过 `max_retries + 1` 仍失败：
  - 若**所有目标通道都失败**：记录到 `dead-letter.jsonl`，返回退出码 `3`
  - 若主备路由出现**部分送达**（至少一个目标成功）：标记 `partial_success`，返回 `0`，不写 dead-letter（避免把“已部分送达”误记为主失败）
  - `audit.jsonl` 除每通道记录外，会追加一条 `record_type=delivery_summary` 的汇总记录（`sent/partial_success/failed`），供 P11 guard 按“每次告警”口径统计失败率
- 可通过重放脚本补发 dead-letter；成功后会从 dead-letter 文件移除

## 环境变量

### 通用

- `ALERT_NOTIFY_CHANNEL`：默认通道（兼容旧配置），`imessage` / `slack` / `telegram`
- `ALERT_NOTIFY_PRIMARY_CHANNEL`：主通道（默认继承 `ALERT_NOTIFY_CHANNEL`）
- `ALERT_NOTIFY_BACKUP_CHANNEL`：备通道（可选，`imessage|slack|telegram`）
- `ALERT_NOTIFY_AUDIT_FILE`：路由审计日志（jsonl），默认 `run/pr7-alert-delivery/audit.jsonl`
- `ALERT_NOTIFY_MIN_LEVEL`：`WARN`（默认）或 `FAIL`
- `ALERT_NOTIFY_DEDUP_SECONDS`：基础去重窗口秒数，默认 `1800`
- `ALERT_NOTIFY_AGGREGATE_SECONDS`：同类告警聚合窗口，默认继承 `ALERT_NOTIFY_DEDUP_SECONDS`
- `ALERT_NOTIFY_COOLDOWN_INFO`：INFO 级别冷却窗口，默认继承 `ALERT_NOTIFY_DEDUP_SECONDS`
- `ALERT_NOTIFY_COOLDOWN_WARN`：WARN 级别冷却窗口，默认继承 `ALERT_NOTIFY_DEDUP_SECONDS`
- `ALERT_NOTIFY_COOLDOWN_CRITICAL`：CRITICAL 级别冷却窗口，默认 `300`
- `ALERT_NOTIFY_STATE_FILE`：状态文件路径，默认 `run/pr7-alert-delivery/state.json`
- `ALERT_NOTIFY_DEAD_LETTER_FILE`：死信文件路径，默认 `run/pr7-alert-delivery/dead-letter.jsonl`
- `ALERT_NOTIFY_MAX_RETRIES`：失败后最大重试次数（不含首次），默认 `3`
- `ALERT_NOTIFY_BASE_BACKOFF_MS`：基础退避毫秒，默认 `500`
- `ALERT_NOTIFY_MAX_BACKOFF_MS`：最大退避毫秒，默认 `8000`
- `ALERT_NOTIFY_GLOBAL_RETRY_BUDGET`：跨进程全局重试预算（窗口内可消费的 retry token 数，默认 `0`=关闭）
- `ALERT_NOTIFY_GLOBAL_RETRY_WINDOW_SECONDS`：全局重试预算窗口秒数，默认 `300`
- `ALERT_NOTIFY_GLOBAL_RETRY_BUDGET_STATE_FILE`：全局重试预算状态文件，默认 `run/pr7-alert-delivery/retry-budget-state.json`
- `ALERT_NOTIFY_QUIET_HOURS_ENABLED`：`1|0`，是否开启 quiet-hours（默认 `0`）
- `ALERT_NOTIFY_QUIET_HOURS_START`：quiet-hours 起始（`HH:MM`，默认 `23:00`）
- `ALERT_NOTIFY_QUIET_HOURS_END`：quiet-hours 结束（`HH:MM`，默认 `08:00`）
- `ALERT_NOTIFY_QUIET_HOURS_TZ`：quiet-hours 时区（默认 `Asia/Shanghai`）
- `ALERT_NOTIFY_WARN_ESCALATE_COUNT`：连续 WARN 升级阈值 N（默认 `0`，表示关闭）
- `ALERT_NOTIFY_WARN_ESCALATE_WINDOW_SECONDS`：WARN 连续计数窗口，默认 `3600`
- `DRY_RUN=1`：演示模式，不真实发消息
- `ALERT_NOTIFY_DRY_RUN_SIMULATE_FAILURES`：仅 dry-run 生效，前 N 次尝试注入失败（用于演示 dead-letter）
- `ALERT_NOTIFY_DRY_RUN_FAIL_CHANNELS`：仅 dry-run 生效，逗号分隔强制失败通道（例：`imessage,slack`）
- `PR7_GATE_LOCK_DIR`：`pr7_alert_delivery_gate.sh` 并发互斥锁目录（默认 `run/pr7-alert-delivery/.gate-lock`）
- `PR7_GATE_LOCK_WAIT_SECONDS`：等待锁超时秒数（默认 `30`，超时返回 `rc=5`）
- `RUN_DIR`：可显式指定产物目录；未指定时脚本自动生成 `run/pr6-alerts/<ts>-pid<pid>-<rand>`，避免并发覆盖

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
ALERT_NOTIFY_QUIET_HOURS_ENABLED=1 \
ALERT_NOTIFY_QUIET_HOURS_START=23:00 \
ALERT_NOTIFY_QUIET_HOURS_END=08:00 \
ALERT_NOTIFY_QUIET_HOURS_TZ=Asia/Shanghai \
ALERT_NOTIFY_WARN_ESCALATE_COUNT=3 \
ALERT_NOTIFY_WARN_ESCALATE_WINDOW_SECONDS=3600 \
./scripts/v2/pr7_alert_delivery_gate.sh
```

> `pr7_alert_delivery_gate.sh` 会先执行 PR6 gate 产出 `summary.txt`，再尝试投递；默认 `PR7_DELIVERY_FAIL_MODE=ignore` 保持 PR6 语义。若设置 `PR7_DELIVERY_FAIL_MODE=escalate`，当投递失败（`pr7_rc!=0`）会返回 `rc=4`，并写出 `pr7-delivery-status.env` 供 nightly 可观测。脚本内置 gate 级互斥锁，避免 non-gate 并发执行时状态文件覆盖与重试风暴。

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

> 回放脚本已增加并发锁 + 幂等回执：
> - 锁文件默认：`<dead-letter-file>.lock`（已有回放在执行时返回 rc=4，避免并发重复发送）
> - 幂等回执默认：`<dead-letter-file>.replayed.jsonl`（已成功补发的 replay_key 不再重复发送）

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

回归脚本（锁/幂等）：

```bash
./scripts/v2/pr7_dead_letter_replay_idempotency_test.sh
```

## Dry-run 演示：主备路由 + fallback + 审计

```bash
# WARN：主通道 iMessage 失败后自动切备 Telegram；写入 audit.jsonl
DRY_RUN=1 \
ALERT_NOTIFY_DRY_RUN_FAIL_CHANNELS=imessage \
python3 scripts/v2/pr7_alert_delivery.py \
  --report /tmp/pr6-summary-warn.txt \
  --primary-channel imessage \
  --backup-channel telegram \
  --state-file /tmp/pr7-state-route.json \
  --dead-letter-file /tmp/pr7-dead-letter-route.jsonl \
  --audit-file /tmp/pr7-audit-route.jsonl \
  --max-retries 1

cat /tmp/pr7-audit-route.jsonl
# 期望: 先记录 imessage planned_route fail，再记录 telegram fallback_after_primary_failure ok
```

```bash
# CRITICAL：主+备都执行（升级通知）
cat > /tmp/pr6-summary-critical.txt <<'EOF'
status=FAIL
alert_code=PR6_ALERT_RULES
alert_message=[PR6][FAIL] challenge risk snapshot critical
generated_at_utc=2026-02-23T10:00:00+00:00
rule.unresolved_challenges.status=FAIL
rule.unresolved_challenges.value=7
rule.forfeits_daily_increase.status=FAIL
rule.forfeits_daily_increase.value=101
rule.escrow_nonzero_hours.status=FAIL
rule.escrow_nonzero_hours.value=24.10
EOF

DRY_RUN=1 python3 scripts/v2/pr7_alert_delivery.py \
  --report /tmp/pr6-summary-critical.txt \
  --primary-channel imessage \
  --backup-channel telegram \
  --state-file /tmp/pr7-state-route.json \
  --audit-file /tmp/pr7-audit-route.jsonl

# 期望: route_results 包含 imessage+telegram 均为 planned_route
```

## Dry-run 演示：quiet-hours + WARN 自动升级

### 1) Quiet-hours 抑制 WARN（仅 CRITICAL 通过）

```bash
DRY_RUN=1 \
ALERT_NOTIFY_QUIET_HOURS_ENABLED=1 \
ALERT_NOTIFY_QUIET_HOURS_START=00:00 \
ALERT_NOTIFY_QUIET_HOURS_END=23:59 \
python3 scripts/v2/pr7_alert_delivery.py \
  --report /tmp/pr6-summary-warn.txt \
  --channel imessage \
  --state-file /tmp/pr7-state-governance.json

# 期望输出: suppressed(quiet-hours)
```

### 2) 连续 WARN 达 N 次自动升级 CRITICAL

```bash
# 准备: 关闭 dedup，避免演示时被冷却窗口抑制
for i in 1 2 3; do
  DRY_RUN=1 \
  ALERT_NOTIFY_DEDUP_SECONDS=0 \
  ALERT_NOTIFY_WARN_ESCALATE_COUNT=3 \
  ALERT_NOTIFY_WARN_ESCALATE_WINDOW_SECONDS=3600 \
  python3 scripts/v2/pr7_alert_delivery.py \
    --report /tmp/pr6-summary-warn.txt \
    --channel imessage \
    --state-file /tmp/pr7-state-governance.json
  echo "---"
done

# 期望: 第3次出现 level=CRITICAL 且 escalated_from_warn=True
```

## P11：Notification SLO 报表（24h / 7d）

脚本：`scripts/v2/p11_notification_slo_report.py`

产物：
- `run/pr11/notification-slo.md`
- `run/pr11/notification-slo.json`

指标（每个窗口都输出）：
- `sent_rate`
- `suppressed_rate`
- `failed_rate`
- `p95_delivery_attempts`
- `channel_split`（imessage/slack/telegram）

执行：

```bash
python3 scripts/v2/p11_notification_slo_report.py \
  --audit-file run/pr7-alert-delivery/audit.jsonl \
  --dead-letter-file run/pr7-alert-delivery/dead-letter.jsonl \
  --state-file run/pr7-alert-delivery/state.json \
  --out run/pr11/notification-slo.md \
  --json-out run/pr11/notification-slo.json
```

数据不足降级策略：
- 优先使用 `audit.jsonl` + `dead-letter.jsonl` 计算 24h/7d 窗口。
- 若窗口内无时间戳事件，但 `state.json` 有累计计数，则回退为累计计数（非窗口化），并在报告中标记 `degraded=true` 与 note。
- 若缺少 attempts/成功投递样本，则 `p95_delivery_attempts` 或 `channel_split` 会显示不可用并附带 note。

## Nightly 端到端可达性（Round-11）

新增 hard gate：

```bash
./scripts/v2/pr7_delivery_e2e_gate.sh
```

验证链路：`delivery failure -> dead-letter -> replay drain`，避免仅 dry-run 非门禁导致“流程不可达”盲区。

并发风暴控制回归：

```bash
./scripts/v2/pr7_global_retry_budget_storm_test.sh
```

该测试验证跨进程共享重试预算在窗口内生效，避免多实例同时重试放大告警风暴。

## 回归测试 / 门禁补充

- 回归脚本：
  - `scripts/v2/pr7_quiet_hours_warn_escalation_bypass_test.sh`（验证 quiet-hours 不会被 WARN 升级 CRITICAL 绕过）
  - `scripts/v2/pr7_quiet_hours_status_alert_level_mismatch_test.sh`（验证 `status/alert_level` 不一致时拒绝发送并审计）
  - `scripts/v2/pr7_partial_success_route_test.sh`（验证 CRITICAL 主备路由部分送达时标记 `partial_success` 且不写 dead-letter）
- Gate 非阻断自测（可选）：设置 `ALERT_NOTIFY_SELFTEST_QUIET_HOURS=1` 后执行 `scripts/v2/pr7_alert_delivery_gate.sh`，若自测失败会打印 `[PR7][WARN]` 但不改变主退出码。
- Nightly 可观测推荐：`PR7_DELIVERY_FAIL_MODE=escalate DRY_RUN=1 ./scripts/v2/pr7_alert_delivery_gate.sh`（workflow 使用 `continue-on-error: true`，失败会在 step/artifact 中可见）。

### Red 复验命令

```bash
cd /Users/qianqi/.openclaw/workspace/TrillionniumChain
./scripts/v2/pr7_quiet_hours_status_alert_level_mismatch_test.sh
./scripts/v2/pr7_quiet_hours_warn_escalation_bypass_test.sh
./scripts/v2/pr7_partial_success_route_test.sh
./scripts/v2/pr7_delivery_e2e_gate.sh
./scripts/v2/pr7_global_retry_budget_storm_test.sh
```

## 排障

- 出现 `dedup suppressed`：同指纹告警仍在去重窗口内，属预期
- 出现 `suppressed(quiet-hours)`：当前在 quiet-hours 内且级别非 CRITICAL，属预期
- 连续 WARN 未升级：检查 `ALERT_NOTIFY_WARN_ESCALATE_COUNT` 是否 >0、`ALERT_NOTIFY_WARN_ESCALATE_WINDOW_SECONDS` 是否过小
- 出现 `notify delivery exhausted retries`：查看 dead-letter 文件并重放
- 重放失败：检查通道密钥（`IMESSAGE_TO/SLACK_WEBHOOK_URL/TELEGRAM_*`）和网络连通性
