# Governance Proposal Template — Upgrade to v0.3.0

更新日期：2026-02-19
用途：主网/测试网升级与参数切换提案模板

---

## 1) Proposal Metadata

- **Title**: Upgrade TrillionniumChain to v0.3.0
- **Type**: Software Upgrade + Parameter Update
- **Proposer**: `<name/address>`
- **Target Height**: `<upgrade_height>`
- **Binary/Tag**: `<git tag / release artifact>`
- **Estimated Window**: `<start - end>`

## 2) Executive Summary

本提案将链从 `v0.2.x` 升级到 `v0.3.0`，目标是：
1. 固化 PoUW v1 主路径并提升可运维性；
2. 明确 dev-fast 与 prod-like 参数口径；
3. 关闭 legacy `submit-result` 兼容路径（如社区同意）。

## 3) Change Set

### 3.1 Software Upgrade
- 升级二进制至：`<binary release>`
- Upgrade Height：`<upgrade_height>`
- 风险等级：`<low/medium/high>`

### 3.2 Parameter Changes (Template)

```json
{
  "workload_denom": "utrnm",
  "challenge_window_blocks": "100",
  "challenge_deposit": "1000000",
  "challenger_slash_percent": "10",
  "worker_slash_percent_on_bad_result": "20",
  "reveal_window_blocks": "50",
  "allow_legacy_submit_result": false
}
```

> dev-fast 测试口径可将 `challenge_deposit` 调整为 `10000`，但不得与 prod-like 报告混用。

## 4) Migration / Compatibility

- 保持任务状态机主路径不变：
  `OPEN -> ASSIGNED -> COMMITTED -> REVEALED -> CHALLENGED -> COMPLETED/SLASHED`
- 迁移后兼容策略：
  - 关闭 legacy `submit-result`（若本提案通过）
  - 旧调用在升级后应返回明确错误与迁移指引

## 5) Validation Gates (Must Pass)

升级前后均需执行并归档：
- `./scripts/p0_merge_gate.sh`
- `./scripts/p1_negative_suite.sh`

验收门槛：
- `fail = 0`
- `critical skip = 0`

## 6) Rollback Criteria

任一触发即回滚：
1. 升级后连续 N 个区块不可生产；
2. 关键路径不可用（create/accept/commit/reveal）；
3. 状态一致性检查失败。

## 7) Rollback Plan

1. 停止新版本节点；
2. 恢复升级前备份（数据 + 配置 + 二进制）；
3. 验证出块与关键查询恢复；
4. 发布回滚公告并启动复盘。

## 8) Voting Guidance

- **Vote YES** if:
  - 升级收益明确且回滚预案充分；
  - gate 结果满足要求；
  - 社区认可参数变更方向。
- **Vote NO** if:
  - 缺少完整验证证据；
  - 参数变更风险未解释清楚。

## 9) Attached Evidence Checklist

- [ ] 升级前快照（参数、任务、挑战）
- [ ] 升级后快照（同口径）
- [ ] P0 gate 报告路径
- [ ] P1 gate 报告路径
- [ ] 回滚演练记录（至少一次）
