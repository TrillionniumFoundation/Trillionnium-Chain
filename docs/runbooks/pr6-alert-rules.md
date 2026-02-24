# PR6 最小异常告警规则（alert-rules）

脚本：
- `scripts/v2/pr6_challenge_alert_rules.py`
- `scripts/v2/pr6_alert_rules_gate.sh`

## 覆盖规则

1. `unresolved_challenges` 超阈值
2. `forfeits` 日增异常（今日 - 昨日）
3. `escrow` 长时间不归零

统一输出：
- 人类可读：`alert_message=[PR6][PASS|WARN|FAIL] ...`
- 机器可解析：`status=PASS|WARN|FAIL` + `rule.*` key=value

---

## 快速运行

```bash
./scripts/v2/pr6_alert_rules_gate.sh
```

默认读取：
- `trillionnium-rust/run/event-field-check.log`

产物：
- `run/pr6-alerts/<timestamp>/summary.txt`

---

## 参数说明

### Python 脚本参数

```bash
python3 scripts/v2/pr6_challenge_alert_rules.py \
  --event-log trillionnium-rust/run/event-field-check.log \
  --window-hours 48 \
  --fail-unresolved-challenges 5 \
  --warn-unresolved-challenges 3 \
  --fail-forfeits-daily-increase 100 \
  --warn-forfeits-daily-increase 70 \
  --fail-escrow-nonzero-hours 24 \
  --warn-escrow-nonzero-hours 16 \
  --report run/pr6-alerts/manual-summary.txt
```

说明：
- `--window-hours`：统计窗口（默认 48h）
- `warn-*` 未显式给出时，自动按 `floor(fail*0.7)` 推导
- `--ci-hard-fail-on-warn`：CI 模式下将 WARN 也作为非零退出

### Gate 脚本环境变量

- `EVENT_LOG`（默认 `trillionnium-rust/run/event-field-check.log`）
- `WINDOW_HOURS`（默认 `48`）
- `FAIL_UNRESOLVED_CHALLENGES` / `WARN_UNRESOLVED_CHALLENGES`
- `FAIL_FORFEITS_DAILY_INCREASE` / `WARN_FORFEITS_DAILY_INCREASE`
- `FAIL_ESCROW_NONZERO_HOURS` / `WARN_ESCROW_NONZERO_HOURS`
- `CI_HARD_FAIL_ON_WARN=1`（启用后 WARN 也返回 exit 1）
- 参数健壮性：gate 会在执行前校验关键阈值参数（非法值返回 `rc=2`，并打印 `[PR6][FAIL] invalid ...`）
- 兼容性说明：`pr6_alert_rules_gate.sh` 已兼容 macOS 默认 bash（`set -u` 下可正常运行，无需额外 workaround）

---

## CI / Nightly 接入示例

### 示例 1：merge gate（仅 FAIL 阻断）

```bash
./scripts/v2/pr6_alert_rules_gate.sh
```

### 示例 2：nightly（WARN 也视为失败）

```bash
CI_HARD_FAIL_ON_WARN=1 \
FAIL_UNRESOLVED_CHALLENGES=4 \
FAIL_FORFEITS_DAILY_INCREASE=80 \
FAIL_ESCROW_NONZERO_HOURS=18 \
./scripts/v2/pr6_alert_rules_gate.sh
```

---

## 样例输出

### PASS

```text
status=PASS
alert_code=PR6_ALERT_RULES
alert_message=[PR6][PASS] challenge risk snapshot @ 2026-02-23T10:00:00+00:00 | unresolved=1 | forfeits_daily_increase=5 | escrow_nonzero_hours=2.50
rule.unresolved_challenges.status=PASS
rule.forfeits_daily_increase.status=PASS
rule.escrow_nonzero_hours.status=PASS
```

### WARN

```text
status=WARN
alert_code=PR6_ALERT_RULES
alert_message=[PR6][WARN] challenge risk snapshot @ 2026-02-23T10:00:00+00:00 | unresolved=4 | forfeits_daily_increase=72 | escrow_nonzero_hours=17.20
rule.unresolved_challenges.status=WARN
rule.forfeits_daily_increase.status=WARN
rule.escrow_nonzero_hours.status=WARN
reasons=
- unresolved_challenges=4 threshold_warn=3 threshold_fail=5
- forfeits_daily_increase=72 threshold_warn=70 threshold_fail=100
- escrow_nonzero_hours=17.20 threshold_warn=16.00 threshold_fail=24.00
```

### FAIL

```text
status=FAIL
alert_code=PR6_ALERT_RULES
alert_message=[PR6][FAIL] challenge risk snapshot @ 2026-02-23T10:00:00+00:00 | unresolved=9 | forfeits_daily_increase=130 | escrow_nonzero_hours=33.80
rule.unresolved_challenges.status=FAIL
rule.forfeits_daily_increase.status=FAIL
rule.escrow_nonzero_hours.status=FAIL
```
