# settlement-vault (Rust)

最小可测试的 `SettlementVault` Rust 合约骨架（内存态状态机版本）。

## 功能范围

当前实现提供以下最小接口：

- `deposit`
- `lock`
- `release`
- `slash`
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
