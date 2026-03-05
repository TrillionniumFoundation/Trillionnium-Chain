# governance-guard (Rust MVP skeleton)

Rust 版外置治理骨架（in-memory state machine）：

- `propose -> queue -> execute -> cancel`
- `emergency_pause`（立即生效）
- `schedule_unpause -> execute_unpause`（受 timelock 约束）

> 该 crate 先聚焦“治理门控逻辑 + fail-closed 行为”，不绑定链上 runtime/ABI。

## API

核心结构：`GovernanceGuard`

- `propose(caller, param_key, old_value, new_value, eta, reason_hash, now)`
- `queue(caller, proposal_id)`
- `execute(caller, proposal_id, now)`
- `cancel(caller, proposal_id)`
- `emergency_pause(caller, reason_hash)`
- `schedule_unpause(caller, eta, reason_hash, now)`
- `execute_unpause(caller, proposal_id, now)`

权限模型：

- `admin`：配置角色与白名单参数键
- `proposer`：发起/排队参数提案
- `executor`：执行已到期提案与 unpause
- `guardian`：取消提案、触发紧急暂停、安排恢复

## 与 trnm-state 的映射

外置 `param_key` 直接映射 `trnm-state` 的治理参数键（`set_gov_param*` 的 key 语义）。

建议高风险键（与 docs/protocol/external-contracts/governance-guard-mvp.md 对齐）：

- `challenge_window_blocks`
- `challenge_min_bond`
- `challenge_success_bounty`
- `min_worker_stake`
- `challenge_min_bond_bounty_bps`
- `challenge_min_bond_worker_stake_bps`
- `resolve_authority`
- `oracle_source_whitelist`
- `oracle_min_samples`
- `oracle_max_drift_bps`

双闸门建议：

1. 外置 `governance-guard` timelock（时间戳）
2. 链内 `trnm-state` timelock（高度 + pending queue）

`emergency_pause` 对齐：

- pause：外置层立即触发
- unpause：必须经 timelock 到期后执行

## Fail-closed 测试覆盖

`cargo test` 包含：

1. **timelock 绕过**：未到 `eta` 执行失败，且无状态副作用
2. **重复执行**：同一 proposal 二次执行失败
3. **权限漂移**：撤销 proposer/executor/guardian 后调用失败
4. **pause 恢复**：pause 立即生效；unpause 到期前失败、到期后成功
