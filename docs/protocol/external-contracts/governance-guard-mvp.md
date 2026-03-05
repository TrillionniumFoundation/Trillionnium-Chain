# GovernanceGuard + EmergencyCircuitBreaker (MVP)

> 目标：为 Trillionnium 提供一个**最小外置治理合约**，用于高风险参数变更的 `proposal -> timelock -> execute` 流程，以及紧急暂停（Emergency Pause）控制。

## 1. 设计范围（MVP）

### 1.1 保护对象
- 高风险治理参数（来自 `trnm-state` 的 sensitive key）：
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

### 1.2 紧急暂停范围（MVP）
- 外置合约仅负责对链内 `emergency_pause` 的治理触发；
- 由链内模块（现状见 `trnm-pouw`）执行实际冻结语义：
  - 冻结 challenged 路径的 challenge/resolve/timeout 结算；
  - 非 challenged 正常路径可继续（按当前实现）。

### 1.3 明确不做（MVP边界）
- 不做投票机制（投票结果由上层治理系统产出，合约只接收“已通过提案”的执行权）；
- 不做复杂多提案依赖图；
- 不做跨链消息桥/自动执行机器人。

---

## 2. 状态机与流程

## 2.1 参数变更流程（Proposal -> Timelock -> Execute）

1) **proposeParamChange**
- 输入：`paramKey, oldValue, newValue, eta, reasonHash`
- 校验：
  - `paramKey` 必须在 allowlist（高风险 key）内；
  - `eta >= block.timestamp + minTimelockDelay`；
  - `oldValue != newValue`。
- 产出：`proposalId = keccak256(paramKey, oldValue, newValue, eta, nonce)`。

2) **queueProposal**（可合并在 propose 中，MVP 选择显式 queue 便于审计）
- 标记为 `Queued`；记录 `eta`。

3) **executeProposal**
- 条件：
  - `block.timestamp >= eta`；
  - proposal 未执行、未取消；
  - 执行人具备 `EXECUTOR_ROLE`（或开放执行但受签名校验，MVP 用角色控制）。
- 行为：
  - 调用链内治理入口（适配层）写入目标参数；
  - 成功后将 proposal 标记 `Executed`，不可重复执行。

4) **cancelProposal**
- 由 `GUARDIAN_ROLE` / `DEFAULT_ADMIN_ROLE` 取消尚未执行提案。

## 2.2 Emergency Circuit Breaker

- `emergencyPause(reasonHash)`：
  - 由 `GUARDIAN_ROLE` 立即触发；
  - 立即调用链内 `emergency_pause=true`（不走 timelock）。
- `emergencyUnpause(eta)`：
  - 为降低误恢复风险，MVP 采用 timelock 恢复（默认与参数变更同等 delay）；
  - 到期后执行 `emergency_pause=false`。

> 原则：**Pause 快，Unpause 慢**。

---

## 3. 最小数据结构与审计字段

## 3.1 Proposal
- `proposalId: bytes32`
- `proposer: address`
- `executor: address`（最终执行地址，执行时写入）
- `eta: uint64`
- `paramKey: string`
- `oldValue: string`
- `newValue: string`
- `reasonHash: bytes32`
- `status: Pending | Queued | Executed | Cancelled`
- `executedAt: uint64`

## 3.2 核心事件（必须字段）

1) `ParamChangeProposed`
- `proposal_id`
- `proposer`
- `eta`
- `param_key`
- `old_value`
- `new_value`
- `reason_hash`

2) `ParamChangeQueued`
- `proposal_id`
- `eta`

3) `ParamChangeExecuted`
- `proposal_id`
- `executor`
- `eta`
- `param_key`
- `old_value`
- `new_value`
- `executed_at`

4) `ProposalCancelled`
- `proposal_id`
- `canceller`

5) `EmergencyPaused`
- `triggered_by`
- `reason_hash`
- `at`

6) `EmergencyUnpauseScheduled`
- `proposal_id`
- `proposer`
- `eta`

7) `EmergencyUnpaused`
- `proposal_id`
- `executor`
- `at`

---

## 4. 与 trnm-state 的映射关系（MVP）

## 4.1 参数键映射
- GovernanceGuard 的 `paramKey` 直接映射 `StateStore::set_gov_param{_with_action}` 的 `key`。
- `old/new` 在链外提案中保持字符串语义，与 `trnm-state` 的 `GovParamObject.value: String` 对齐。

## 4.2 timelock 对齐
- `trnm-state` 对 sensitive key 已内置 `GOV_SENSITIVE_PARAM_TIMELOCK_BLOCKS=20`。
- 外置合约 timelock 是**前置治理门**（L0），链内 timelock 是**最终执行门**（L1）。
- 因此实际安全模型为“双闸门”：
  - L0：外置合约基于时间戳；
  - L1：链内基于高度/pending queue。

## 4.3 emergency_pause 对齐
- `trnm-state` 中 `emergency_pause` 是 allowlist 但非 sensitive（立即生效，且 key_id=7999 强约束）。
- 外置合约不改变该事实：
  - pause 立即；
  - unpause 通过外置 timelock 延迟恢复（额外人为控制层）。

## 4.4 权限模型对齐
- `proposer` 对应外置治理提案发起者，不直接映射链内 signer；
- `executor` 对应外置执行实体，并应在链内映射到允许调用治理写入的授权账户；
- 建议链内继续保持 `resolve_authority`、`emergency_pause key_id` 等 fail-closed 规则不变。

---

## 5. 最小测试计划（必须覆盖）

## 5.1 Timelock 绕过
- 用例：`eta` 未到时执行提案；
- 期望：revert（`TimelockNotReady`），状态不变，事件不发 `Executed`。

## 5.2 重复执行
- 用例：同一 `proposalId` 连续执行两次；
- 期望：第一次成功，第二次 revert（`AlreadyExecuted`）。

## 5.3 权限漂移
- 用例：
  - 移除 `EXECUTOR_ROLE` 后尝试执行；
  - 移除 `PROPOSER_ROLE` 后尝试提案；
  - 非 guardian 调用 pause。
- 期望：全部权限拒绝，链上状态无副作用。

## 5.4 Pause 恢复
- 用例：
  - guardian 触发 pause 后，关键路径被冻结（链内行为验证）；
  - unpause 必须走 schedule + eta 到期后执行。
- 期望：pause 立即生效；unpause 到期前不可执行；恢复后路径重开。

---

## 6. 失败/阻断策略（Blocker 模板）

若外置合约无法直接写入链内治理（缺少 precompile / RPC adaptor / bridge），按以下格式上报：

- `blocker`: 缺少 GovernanceBridge 接口，无法在 execute 时原子调用 `set_gov_param`。
- `impact`: 仅能完成提案排队与审计，不可落地参数写入。
- `required_owner`: core protocol (state/rpc)
- `required_change`: 提供 `applyGovParam(key, value)` 和 `setEmergencyPause(bool)` 的受控入口。
- `temporary_mitigation`: 使用离线执行器读取事件并通过受控运维通道提交链内交易。

---

## 7. MVP 验收标准
- 有独立文档定义状态机、pause 范围、事件字段、测试计划；
- 有最小骨架合约（含 proposal/timelock/execute/pause）；
- 明确与 `trnm-state` 的键与语义映射；
- 明确 blocker 上报路径，避免“持续空跑”。
