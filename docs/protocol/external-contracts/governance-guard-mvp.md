# GovernanceGuard + EmergencyCircuitBreaker（M0 Lane-3 MVP）

## 目标
提供高风险参数变更的最小外置治理：`proposal -> timelock -> execute`，并提供紧急停止（pause）与受控恢复（unpause）。

## 流程定义
1. **Propose**：提交参数提案（`param_key`, `old_value`, `new_value`, `eta`, `reason_hash`）
2. **Queue**：进入可执行队列（状态 `Queued`）
3. **Execute**：`block.timestamp >= eta` 后由执行者调用执行
4. **Cancel**：guardian/admin 可取消未执行提案

## EmergencyCircuitBreaker 范围
- `emergencyPause`：立即生效（不经 timelock）
- `emergencyUnpause`：必须 timelock 后执行（避免过早恢复）
- 链内实际冻结语义继续由 `trnm-pouw + trnm-state` 保证

## 关键审计事件字段
必须包含：`proposer / executor / eta / param_key / old / new`

- `ParamChangeProposed(proposal_id, proposer, eta, param_key, old_value, new_value, reason_hash)`
- `ParamChangeQueued(proposal_id, eta)`
- `ParamChangeExecuted(proposal_id, executor, eta, param_key, old_value, new_value, executed_at)`
- `ProposalCancelled(proposal_id, canceller)`
- `EmergencyPaused(triggered_by, reason_hash, at)`
- `EmergencyUnpauseScheduled(proposal_id, proposer, eta)`
- `EmergencyUnpaused(proposal_id, executor, at)`

## 与当前 trnm-state 治理机制映射

### 参数键映射
外置 `param_key` 直接映射 `StateStore::set_gov_param*` 的 `key`。

### 高风险键（敏感）
对应 `GOV_SENSITIVE_KEYS`：
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

### 双闸门
- 外置合约 timelock（时间戳）= 治理前置门
- 链内 `trnm-state` timelock（高度 + pending queue）= 最终执行门
- 结果：敏感参数需同时通过两层门控

### emergency_pause 对齐
- 链内 `emergency_pause` 立即生效，且 `key_id=7999` 固定
- 外置层保持 pause 快速触发；仅对 unpause 加入 timelock 恢复

## 最小测试计划（MVP）
1. **Timelock 绕过**：未到 `eta` 执行必须失败（无状态副作用）
2. **重复执行**：同一 proposal 二次执行失败
3. **权限漂移**：撤销 proposer/executor/guardian 后调用应失败
4. **Pause 恢复**：pause 立即生效；unpause 到期前不可执行，到期后可恢复

## Blocker 报告（若执行桥接受阻）
- blocker: 缺少链内治理桥接接口（`applyGovParam` / `setEmergencyPause`）
- impact: 外置合约只能排队审计，无法落地参数写入
- required_change: 提供受控桥接入口或预编译
- temporary_mitigation: 离线执行器监听事件并走受控运维提交流程
