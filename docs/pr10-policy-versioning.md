# PR10 Policy Versioning（告警策略治理）

## 目标

将 PR6/PR7/PR9 的告警参数从“散落环境变量”治理为“可版本化策略配置”：
- 阈值（thresholds）
- quiet hours
- 升级规则（warn escalate）
- channel 路由（info/warn/critical）

同时保留旧有环境变量兼容能力（显式设置的 env 优先）。

## 文件结构

- `config/alert-policy/current.json`：当前生效策略（可版本化）
- `config/alert-policy/schema.v1.json`：策略 schema（文档/约束）
- `scripts/v2/alert_policy_lint.py`：策略校验（schema/lint）
- `scripts/v2/alert_policy_resolve.py`：策略解析为 env，并写审计快照
- `run/pr9/policy-changelog.md`：策略变更审计日志（本地）
- `run/pr9/policy-history/*.json`：每次解析时的历史快照

## 兼容性策略

- `scripts/v2/pr6_alert_rules_gate.sh` 与 `scripts/v2/pr7_alert_delivery_gate.sh` 在运行前会尝试加载策略文件。
- 使用 `--only-missing`：若某环境变量已显式提供，则不会被策略覆盖。
- 因此兼容：
  - 现有 PR6/PR7 手工注入 env 的流程
  - PR9 产出的 `run/pr9/alert-thresholds.env` 注入流程

## 验证命令

```bash
# 1) lint 配置
python3 scripts/v2/alert_policy_lint.py --policy config/alert-policy/current.json

# 2) 手动解析策略（不覆盖已有 env）
python3 scripts/v2/alert_policy_resolve.py \
  --policy config/alert-policy/current.json \
  --profile default \
  --out-env run/pr9/policy.resolved.env \
  --only-missing --audit

# 3) 跑 PR6 gate（将自动加载策略）
scripts/v2/pr6_alert_rules_gate.sh

# 4) 跑 PR7 gate（将自动加载策略并按 min_level 路由 channel）
DRY_RUN=1 scripts/v2/pr7_alert_delivery_gate.sh

# 5) 旧流程兼容验证（显式 env 覆盖策略）
WARN_UNRESOLVED_CHALLENGES=99 scripts/v2/pr6_alert_rules_gate.sh
```

## 版本升级建议

- 修改 `current.json` 时同步更新 `version` 字段。
- 每次上线前先执行 lint，再做 dry-run。
- 如果需要回滚，直接切回旧版本 policy 文件并重跑 gate。
