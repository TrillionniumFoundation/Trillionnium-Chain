# BridgeRelay Rust MVP (contracts-rust/bridge-relay)

Rust 版本的 BridgeRelay 最小可测试合约骨架（状态机模型），用于替代 Solidity MVP lane 的核心接口验证。

## 范围

当前 crate 聚焦最小 fail-closed 行为，不做链上执行：

- `submit_proof`：
  - 检查外部 `deadline`
  - 检查消息域（`target_chain_id`/`target_bridge`）
  - 检查消息内 `deadline`
  - 做 proof digest 去重（重放防护）
  - 使用签名数量占位阈值检查（后续可替换真实签名验证）
- `consume_nonce`：
  - 使用域隔离键 `nonce_key(source_chain_id, source_bridge_id, target_chain_id, target_bridge, action, nonce)`
  - 一次消费后不可重复
- `finalize_settlement`：
  - 内部串联 `submit_proof` + `consume_nonce`
  - settlement 只允许 finalize 一次

## 数据与哈希

- 哈希算法：`sha2::Sha256`（MVP 占位，便于本地测试）
- `ACTION_SETTLEMENT_FINALIZE`：固定 32-byte action 域值

## 关键 fail-closed 测试

已覆盖：

1. 过期 proof 拒绝（`ProofExpired`）
2. 重复 finalize 拒绝（`ProofAlreadyUsed` / `SettlementAlreadyFinalized`）
3. 链域不匹配拒绝（`InvalidTargetChain`）
4. nonce 域隔离 + 重放防护（相同 nonce、不同 action 可并存；同域重复消费拒绝）

## 运行测试

```bash
cd contracts-rust/bridge-relay
cargo test
```

## 下一步（v1）

- 替换签名数量占位逻辑为真实签名验证（例如 EIP-712/ed25519/secp256k1）
- 对接真实执行层（资产结算/状态提交）
- 增加更多 domain 约束与 fuzz/property 测试
