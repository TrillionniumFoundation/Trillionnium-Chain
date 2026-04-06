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
- `proposer`：可撤销自己的待执行提案

并发一致性（v2+）：

- 每个参数提案在 `propose` 时会快照 `base_version`。
- `execute` 时要求当前 `param_version` 未变化；若期间有其他提案成功写入同参数，会返回 `ParamVersionMismatch`，避免并发提案覆盖。
- 参数执行成功后会触发 `param_version + 1`。

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
3. **版本漂移保护**：同参数并发提案会因版本改变而拒绝执行，避免覆盖
4. **权限漂移**：撤销 proposer/executor/guardian 后调用失败
5. **pause 恢复**：pause 立即生效；unpause 到期前失败、到期后成功
6. **审计日志链路**：提案流转与暂停恢复路径会产生日志，支持链下查询与状态追踪

## 审计日志（v2）

新增 `GovernanceGuard` 可观测能力（便于 indexer + 风控）：
- `audit_log() -> &[GovernanceEvent]`
- `consume_audit_log() -> Vec<GovernanceEvent>`

事件包括：`ProposalProposed`、`ProposalQueued`、`ProposalExecuted`、`ProposalCancelled`、`PauseSet`、`PauseRestoreScheduled`、`PauseRestoreExecuted`。

## Runtime / ABI boundary（truthful snapshot）

- 当前 crate 仍是 **Rust MVP / in-memory governance state machine**；它先固定 timelock、版本漂移保护、pause/unpause 与审计语义，**不表示** 已接入 canonical `HostAbiV1`、`trnm-node` deterministic WASM executor，或链上参数写入管线。
- README 中对 `trnm-state` 的映射，应理解为“未来宿主接线的目标语义边界”，而不是“当前仓内已经闭合的 runtime integration 事实”。
- 当前也不应把这个 crate 表述成已默认产出 canonical `wasm32-unknown-unknown` artifacts，或已完成 `sdk/` + `runtime-spec/` + golden integration replay 闭环。
- 是否进入 Day-1 / release-ready / public-mainnet scope，仍应以仓库根 `RELEASE_READINESS.md` 与 `trillionnium/docs/release/TRNM_MAINNET_GAP_MATRIX_2026-03-26.md` 为准。


## 标准化审计事件（v1）

新增 `normalized_audit_log() -> Vec<AuditEvent>`（复用 `audit-events` 共享 schema）：
- `source: "governance-guard"`
- `event_type`：`governance.proposal_proposed` / `governance.proposal_queued` / `governance.proposal_executed` / `governance.proposal_cancelled` / `governance.pause_set` / `governance.pause_restore_scheduled` / `governance.pause_restore_executed`。
- 可携带 `actor`（提案人/执行人/守护者）、`object_id`（提案 id）、`related_id`（参数名/前后状态）用于链下检索。
