# BridgeRelay Rust MVP (contracts-rust/bridge-relay)

Rust 版本的 BridgeRelay 最小可测试合约骨架（状态机模型），用于替代 Solidity MVP lane 的核心接口验证。

## 范围

当前 crate 聚焦最小 fail-closed 行为，不做链上执行：

- `submit_proof`：
  - 检查外部 `deadline`
  - `admin` 可配置 validator 集合与阈值（预留用于后续治理联动）
  - 检查消息域（`target_chain_id`/`target_bridge`）
  - 检查消息内 `deadline`
  - 做 proof digest 去重（重放防护）
  - 做 `validator` 白名单、去重和“签名绑定消息摘要”校验
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
2. 重复 finalize 拒绝（`ProofAlreadyUsed` / `SettlementAlreadyFinalized`）
3. 链域不匹配拒绝（`InvalidTargetChain`）
4. nonce 域隔离 + 重放防护（相同 nonce、不同 action 可并存；同域重复消费拒绝）
5. 签名长度不合法与签名绑定失配拒绝
6. 非管理员不能篡改 validator 配置
7. 审计日志可查询与清空（`audit_log` / `consume_audit_log`）

## 运行测试

```bash
cd contracts-rust/bridge-relay
cargo test
```

## 下一步（v1）

- 对接真实签名验证算法（例如 EIP-712/Ed25519/Secp256k1）
- 对接真实执行层（资产结算/状态提交）
- 增加更多 domain 约束与 fuzz/property 测试