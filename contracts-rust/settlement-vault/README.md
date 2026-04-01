# settlement-vault (Rust)

最小可测试的 `SettlementVault` Rust 合约骨架（内存态状态机版本）。

## 功能范围

当前实现提供以下最小接口：

- `deposit`
- `lock`
- `release`
- `slash`
- `transfer`
- `pause`
- `unpause`

并包含 fail-closed 约束：

- 重复请求（`DuplicateRequest`）拒绝
- 越权调用（`Unauthorized`）拒绝
- 非法状态迁移（`InvalidStateTransition`）拒绝
- 暂停期间所有状态变更入口拒绝（`Paused`）

## 构建与测试

在目录 `contracts-rust/settlement-vault` 下执行：

```bash
cargo test
```

## 说明

- 当前版本为纯 Rust 内存状态机，便于先行验证接口语义与状态迁移。
- 后续可平滑迁移到链上执行环境（例如存储抽象、权限模型、事件接口等）。

## 建议提交信息前缀

```text
trnm(contract-rs-vault): ...
```


## 可观测能力（审计事件）

新增 `SettlementVault` 可观测能力：
- `audit_log() -> &[VaultEvent]`
- `consume_audit_log() -> Vec<VaultEvent>`

事件包括：`Deposited`、`Locked`、`Released`、`Slashed`、`Transferred`、`Paused`、`Unpaused`。


## 标准化审计事件（v1）

新增 `normalized_audit_log() -> Vec<AuditEvent>`（复用 `audit-events` 共享 schema）：
- `source: "settlement-vault"`
- `event_type`：`vault.deposited` / `vault.locked` / `vault.released` / `vault.slashed` / `vault.transferred` / `vault.paused` / `vault.unpaused`。
- `amount` 承载金额；`object_id` 承载主对象（如 `request_id`，或转账发起账户）；`related_id` 承载次级关联对象（如账户、受益人、转账接收方），避免多主体事件归一化后丢键。
