# BridgeRelay Rust MVP (contracts/bridge-relay)

Rust 版本的 BridgeRelay 最小可测试合约骨架（状态机模型），用于承载当前外置合约路线的核心接口验证。

## 范围

当前 crate 聚焦最小 fail-closed 行为，不做链上执行：

- `submit_proof`：
  - 检查外部 `deadline`
  - `admin` 可配置 validator 集合与阈值（预留用于后续治理联动）
  - 检查消息域（`target_chain_id`/`target_bridge`）
  - 检查消息内 `deadline`
  - 做 proof digest 去重（重放防护）
  - 做 `validator` 白名单、去重和 Ed25519 签名校验（签名格式：32 字节 validator 公钥 + 64 字节签名）
- `consume_nonce`：
  - 使用域隔离键 `nonce_key(source_chain_id, source_bridge_id, target_chain_id, target_bridge, action, nonce)`
  - 一次消费后不可重复
- `finalize_settlement`：
  - 内部串联 `submit_proof` + `consume_nonce`
  - settlement 只允许 finalize 一次
- `audit_log()` 与 `consume_audit_log()`：
  - 记录关键变更与执行路径（配置变更/提交证明/结算完成）
  - 便于 indexer 与风控模块做链下审计

## 数据与哈希

- 哈希算法：`sha2::Sha256`（MVP 骨架）
- `ACTION_SETTLEMENT_FINALIZE`：使用 `Keccak256("SETTLEMENT_FINALIZE")` 计算 32 字节域标识

## 关键 fail-closed 测试

已覆盖：

1. 过期 proof 拒绝（`ProofExpired`）
2. 重复 finalize 拒绝（`SettlementAlreadyFinalized` 为 finalize 终态优先拒绝；`ProofAlreadyUsed` 仍用于 `submit_proof` 重放）
3. 结算标识域绑定：`settlement_id` 覆盖 source/target chain 与 bridge 字段，避免跨域/目标复用导致身份碰撞
4. 链域不匹配拒绝（`InvalidTargetChain`）
5. nonce 域隔离 + 重放防护（相同 nonce、不同 action 可并存；同域重复消费拒绝）
6. 签名长度不合法与签名绑定失配拒绝
7. 配置一致性约束：`min_validator_signatures > 0` 且 `min_validator_signatures <= validators.len()`；不允许将 validator 集合清空或收缩到低于阈值以下
8. 非管理员不能篡改 validator 配置
9. 配置版本一致性检查（`message.config_version` 必须匹配当前配置版本）
10. tx receipt 约束：`tx_receipt_status` 必须为成功（`TX_RECEIPT_SUCCESS`）以绑定执行/回执状态
11. 审计日志可查询与清空（`audit_log` / `consume_audit_log`）
12. finalize 终态幂等绑定：同一 `settlement_id` 一旦进入终态，后续 finalize 重放（含不同 `nonce`、或签名无效输入）统一返回 `SettlementAlreadyFinalized`，`submit_proof` 重放仍返回 `ProofAlreadyUsed`

## 运行测试

```bash
cd contracts/bridge-relay
cargo test
```

## Runtime / ABI boundary（truthful snapshot）

- 当前 crate 是 **Rust MVP / in-memory state machine**，用于先固定 BridgeRelay 的 fail-closed 语义、审计事件和配置版本约束；**不表示** 已接入 canonical `HostAbiV1` 或 `trnm-node` 的 deterministic WASM executor。
- 当前 README 不应被解读为：本 crate 已默认产出链上 canonical `wasm32-unknown-unknown` artifacts，或已经完成 `sdk/` + `runtime-spec/` + integration replay 闭环。
- `audit-events` 的标准化事件接线有助于后续 indexer / 风控统一口径，但它本身 **不等价于** host runtime integration 已闭合。
- 是否进入 Day-1 / release-ready / public-mainnet scope，仍应以仓库根 `RELEASE_READINESS.md` 与 `trillionnium/docs/release/TRNM_MAINNET_GAP_MATRIX_2026-03-26.md` 为准。

## 下一步（v1）

- 对接真实签名密钥生命周期与链上治理更新（签名验证链路已对接 Ed25519 示例验签，可继续扩展为生产签名算法）
- 已对接治理变更并发控制（最小治理接线）：
- 参考接线协议：`docs/reviews/TRNM_REVIEW_BRIDGE_RELAY_CONFIG_VERSION_GOVERNANCE_PROTOCOL_2026-03-16.md`
  - 对外提供 `config_version()` 查询当前配置版本。
  - 新增治理写入的带版本方法（`set_admin_with_version` / `set_min_validator_signatures_with_version` / `set_validators_with_version`）：
    - 要求调用携带期望版本，过期版本调用将被 `InvalidConfigVersion` 拒绝，避免并发配置更新竞争。

- 对接真实执行层（资产结算/状态提交）
- 在 `sdk/` / `runtime-spec/` 明确落地前，保持 README 与实现口径一致：只表述当前语义骨架，不提前宣称 canonical Host ABI/runtime 已完成
- 增加更多 domain 约束与 fuzz/property 测试

## 标准化审计事件（v1）

新增 `normalized_audit_log() -> Vec<AuditEvent>`（复用 `audit-events` 共享 schema）：
- `source: "bridge-relay"`
- `event_type`：`bridge_relay.proof_submitted` / `bridge_relay.proof_submitted_and_stored` / `bridge_relay.settlement_finalized` / `bridge_relay.nonce_consumed` / `bridge_relay.admin_updated` / `bridge_relay.min_signatures_updated` / `bridge_relay.validators_updated` / `bridge_relay.config_version_updated`
- 字段纪律：
  - `object_id` 承载主对象主键，例如 `proof_digest` / `settlement_id` / `nonce_key`，以及配置类事件中的 `bridge_config`。
  - `related_id` 仅承载次级关联对象，例如 `settlement_finalized -> proof_digest`，或配置类事件中的 `config_version` / `min_signatures` / `validators`。
  - `reason` 仅承载归因标签，不复用为主键字段；当前配置类事件分别使用 `admin_rotation` / `config_version_rotation` / `validator_threshold_rotation` / `validator_set_rotation`。
  - `amount` 仅承载计数值或阈值，不与 ID 字段混用；当前用于签名计数、配置版本号、新阈值、新 validator 数。
- `admin_updated` 采用 `actor=caller`、`object_id=new_admin`、`related_id=old_admin`，保持“主对象=当前生效对象，关联对象=被替换对象”的归一化约定。
