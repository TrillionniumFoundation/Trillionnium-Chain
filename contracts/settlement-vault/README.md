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

在目录 `contracts/settlement-vault` 下执行：

```bash
cargo test
```

## 说明

- 当前版本为纯 Rust 内存状态机，便于先行验证接口语义与状态迁移。
- 这里的“可迁移”仅表示语义与边界可以为后续宿主接线提供基线；**不表示** 当前 crate 已接入 canonical `HostAbiV1`、`trnm-node` deterministic WASM executor，或已默认产出 `wasm32-unknown-unknown` 合约工件。
- 按 `trillionnium/docs/protocol/external-contracts-rust/RUST_NATIVE_EXTERNAL_CONTRACTS_ARCH_2026-03-05.md` 的目标布局，`SettlementVault` 未来应与 `sdk/`、`runtime-spec/`、`integration-tests/` 一起构成更完整的 external-contract workspace；当前 README 只能被读作单 crate Rust MVP 说明，**不能**反推这些目录、宿主 trait 接线或 golden replay 已在仓内落地。
- 是否进入 Day-1 / release-ready / public-mainnet scope，仍应以仓库根 `RELEASE_READINESS.md` 与 `trillionnium/docs/release/TRNM_MAINNET_GAP_MATRIX_2026-03-26.md` 为准；在 scope freeze 明确前，更安全的口径是把本 crate 视作 scope-dependent / trailing-capable 模块，而不是默认 Day-1 minimum。

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
- `vault.slashed` 的标准化事件使用 `related_id=locked_account`，并将 `beneficiary` 放入 `note`（如 `beneficiary=treasury`），避免把多个主体拼进同一个 ID 字段。
- `vault.transferred` 的标准化事件使用 `object_id=from`、`related_id=to`，保持“主对象在前、次级关联对象在后”的共享归一化约定。
