# PoUW v1 Error Mapping (Stable Surface)

日期：2026-02-19  
范围：`trillionnium-rust/crates/trnm-pouw`

## 目标

将实现层错误统一映射到 v1 冻结的稳定错误语义，便于 RPC/SDK/审计侧对齐。

## 稳定错误码集合（v1）

- `InvalidTransition`
- `VersionConflict`
- `MissingWorker`
- `MissingCommitment`
- `CommitmentMismatch`
- `Unauthorized`
- `InsufficientStake`

## 实现映射（当前）

| `PouwError` 变体 | `stable_code()` | 说明 |
|---|---|---|
| `InvalidTransition` | `InvalidTransition` | 非法状态迁移 |
| `VersionConflict` | `VersionConflict` | 乐观并发版本冲突 |
| `MissingWorker` | `MissingWorker` | 缺少 worker 绑定 |
| `MissingCommitment` | `MissingCommitment` | 缺少 committed_hash |
| `CommitmentMismatch` | `CommitmentMismatch` | reveal 与 commitment 不一致 |
| `Unauthorized` | `Unauthorized` | actor 与权限/绑定不匹配 |
| `InsufficientStake` | `InsufficientStake` | 质押不足 |
| `State(String)` | `StateInternal` | 内部状态层错误（非协议稳定集合） |

> 约束：对外接口（RPC/SDK）应优先暴露 `stable_code()`；`StateInternal` 不应作为 v1 协议稳定语义依赖。

## 测试覆盖

- `stable_error_code_mapping`
- `state_error_mapping_version_conflict`
- `reveal_missing_worker_is_mapped`

位置：`trillionnium-rust/crates/trnm-pouw/src/lib.rs`
