# P11 Runbook：Policy Rollback Guard（Dry-run）

目标：基于 PR-7 投递结果做自动回滚守卫判定（当前仅 dry-run，不阻断 nightly）。

## 0) Promotion 执行前置（审批门禁）

> 为避免绕过审批直接发版：`p11_policy_promote.sh` 现已内建非 dry-run 审批校验。

执行策略：
- 推荐入口：`scripts/v2/p11_policy_promote_gate.sh`
- 非 dry-run 必须显式 `--approve --approval-code <code> --approved-by <id> --reviewed-by <id>`
- `--approved-by` 与 `--reviewed-by` 必须是两个不同身份（双签）
- 默认且强制要求 `P11_APPROVAL_SHARED_SECRET`（legacy bypass 已关闭）
- `--dry-run` 仅做校验与候选生成，不写 `profiles/`、snapshot、audit log（无文件副作用）
- direct 调用 `p11_policy_promote.sh` 未携带完整审批参数会返回 `3` 且输出 `[P11][BLOCKED]`

示例：

```bash
# 预演（无审批，仅输出 challenge digest，不泄露 approval code）
./scripts/v2/p11_policy_promote_gate.sh --from staging --to prod --dry-run

# 正式（需审批，approval-code 需由持有 P11_APPROVAL_SHARED_SECRET 的审批终端离线计算）
P11_APPROVAL_SHARED_SECRET=<secret> \
./scripts/v2/p11_policy_promote_gate.sh --from staging --to prod --approve --approval-code <code> --approved-by <approver-id> --reviewed-by <reviewer-id>
```

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
- `failed_rate` 必须使用 **lookback 窗口样本**，防止历史累计样本稀释近期故障：
  - 优先：`audit.jsonl` 窗口内 `ok=false / total`（`failed_rate_basis=audit_window`）
  - 降级：若 audit 窗口为空且 dead-letter 有数据，则使用 dead-letter 窗口保守估算（`failed_rate_basis=dead_letter_window_fallback`），并输出 WARN。
- `critical alerts failed` 统计 `dead-letter.jsonl` 在 lookback 窗口内的 critical/FAIL 失败事件。
- `consecutive_failures` 优先读取 `audit.jsonl`（若存在）；不存在时降级为窗口内 dead-letter 条数估算，并输出 WARN。
- `audit.jsonl` 采样会排除 `rejected=true` 或 `attempts<=0` 的记录（这类属于策略拒绝/未投递，不计入投递失败样本），避免误触发回滚。

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

窗口 failed_rate 回归测试（防累计稀释绕过）：
```bash
./scripts/v2/p11_policy_rollback_guard_window_rate_test.sh
```

rejected/attempts=0 误算防回归测试：
```bash
./scripts/v2/p11_policy_rollback_guard_rejected_attempts0_test.sh
```

partial_success 口径一致性回归测试（PR7 summary 与 P11 guard 一致）：
```bash
./scripts/v2/p11_partial_success_metric_consistency_test.sh
```

promotion 审批与 dry-run 副作用回归测试：
```bash
./scripts/v2/p11_policy_promote_approval_bypass_test.sh
```

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
