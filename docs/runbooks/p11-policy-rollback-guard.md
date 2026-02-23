# P11 Runbook：Policy Rollback Guard（Dry-run）

目标：基于 PR-7 投递结果做自动回滚守卫判定（当前仅 dry-run，不阻断 nightly）。

## 1) 脚本与产物

- 脚本（Python）：`scripts/v2/p11_policy_rollback_guard.py`
- 脚本（Shell）：`scripts/v2/p11_policy_rollback_guard.sh`
- 文本产物：`run/pr11/policy-rollback-guard.txt`
- JSON 产物：`run/pr11/policy-rollback-guard.json`

## 2) 触发规则（默认 1h）

满足任一即判定 `FAIL`（dry-run would rollback）：

1. `failed_rate > 20%`
2. `consecutive_failures > 10`
3. `critical alerts failed > 0`

说明：
- `failed_rate` 口径来自 `run/pr7-alert-delivery/state.json` 的累计计数（与 PR-9 报告一致）。
- `critical alerts failed` 统计 `dead-letter.jsonl` 在 lookback 窗口内的 critical/FAIL 失败事件。
- `consecutive_failures` 优先读取 `audit.jsonl`（若存在）；不存在时降级为窗口内 dead-letter 条数估算，并输出 WARN。

## 3) 输出语义

脚本会输出：
- 总体状态：`PASS | WARN | FAIL`
- 文本结论：`would-rollback: YES/NO`

其中：
- `FAIL`：命中回滚触发条件（但当前仅 dry-run，不执行真实回滚）
- `WARN`：未命中 FAIL，但存在数据缺失/降级（例如 audit 文件缺失）
- `PASS`：未命中 FAIL，且无降级告警

## 4) 使用方式

```bash
# 默认执行
./scripts/v2/p11_policy_rollback_guard.sh

# 自定义阈值/窗口
P11_ROLLBACK_GUARD_LOOKBACK_SECONDS=3600 \
P11_ROLLBACK_GUARD_FAILED_RATE_THRESHOLD_PCT=20 \
P11_ROLLBACK_GUARD_CONSECUTIVE_FAILURES_THRESHOLD=10 \
./scripts/v2/p11_policy_rollback_guard.sh
```

可选环境变量：
- `P11_ROLLBACK_GUARD_STATE_FILE`
- `P11_ROLLBACK_GUARD_DEAD_LETTER_FILE`
- `P11_ROLLBACK_GUARD_AUDIT_FILE`
- `P11_ROLLBACK_GUARD_OUT`
- `P11_ROLLBACK_GUARD_JSON_OUT`
- `P11_ROLLBACK_GUARD_POLICY_TAG`

## 5) Nightly 非阻断接入（补丁）

已建议/接入如下 step（`continue-on-error: true`）：

```yaml
- name: Build P11 policy rollback guard (dry-run, non-gate)
  if: always()
  continue-on-error: true
  run: |
    set -euo pipefail
    ./scripts/v2/p11_policy_rollback_guard.sh
```

并在 artifact 中加入：

```yaml
run/pr11/**
```

## 6) 验收清单

- [ ] 生成 `run/pr11/policy-rollback-guard.txt`
- [ ] 生成 `run/pr11/policy-rollback-guard.json`
- [ ] 输出 `PASS/WARN/FAIL`
- [ ] 输出 `would-rollback` 文本
- [ ] nightly 以非阻断方式接入（`continue-on-error: true`）
