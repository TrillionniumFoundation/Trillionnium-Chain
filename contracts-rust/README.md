# contracts-rust

Rust-native external contracts 子树。

## 当前状态（truthful snapshot）

当前目录已经有 4 个独立 contract crates：

- `settlement-vault/`
- `bridge-relay/`
- `governance-guard/`
- `audit-events/`

它们当前主要是 **Rust MVP / in-memory state machine / shared schema** 形态，用于先验证接口、审计事件和 fail-closed 语义；**还不是** 已接入 TRNM host runtime 的生产 external-contract workspace。

## 与架构目标的关系

`trillionnium-rust/docs/protocol/external-contracts-rust/RUST_NATIVE_EXTERNAL_CONTRACTS_ARCH_2026-03-05.md` 定义的是目标布局：

```text
contracts-rust/
  sdk/
  runtime-spec/
  settlement-vault/
  bridge-relay/
  governance-guard/
  integration-tests/
```

截至当前仓库快照：

- **已存在**：`settlement-vault/`、`bridge-relay/`、`governance-guard/`
- **部分相关**：`audit-events/` 提供共享审计事件 schema
- **尚未落地为目录**：`sdk/`、`runtime-spec/`、`integration-tests/`

因此，这个子树目前应被理解为：

> external-contract Rust 化方向已经起步，但 Host ABI/runtime boundary 仍处在“架构已冻结、工程接线未闭环”的阶段。

## Runtime boundary（当前不要过度表述）

当前仓内不应把这些 crate 表述成：

- 已经编译为 canonical `wasm32-unknown-unknown` production artifacts
- 已经接入 `trnm-node` 的 deterministic WASM executor
- 已经具备 `sdk/` + `runtime-spec/` + golden integration replay 全套闭环
- 已经构成 public-mainnet readiness 证明

更准确的说法是：

- external contracts 保持在 `contracts-rust/` 独立子树，而不是物理并入 `trillionnium-rust/`
- 当前 crate 更接近 contract semantics / audit normalization / fail-closed behavior 的 Rust MVP
- 当前仓内 **还没有** 已落地的 `sdk/`、`runtime-spec/`、`integration-tests/` 目录，因此不要把架构目标布局误读成“工程已接线完成”
- 是否进入 Day-1 mainnet scope，应继续以 `RELEASE_READINESS.md` 与 `TRNM_MAINNET_GAP_MATRIX_2026-03-26.md` 的口径为准

## 目录说明

### `settlement-vault/`

最小可测试的结算金库合约骨架；当前重点是授权、锁定/释放/惩罚和审计事件。

### `bridge-relay/`

最小 BridgeRelay 合约骨架；当前重点是 proof/nonce/finality 相关 fail-closed 行为。

### `governance-guard/`

最小治理门控合约骨架；当前重点是 timelock、版本漂移保护和暂停/恢复语义。

### `audit-events/`

共享审计事件 schema crate；用于 contract 模块输出统一 normalized audit event。

## Host / runtime boundary（按当前仓库状态理解）

当前更可信的边界应理解为：

- `contracts-rust/*`：独立 contract crates / shared schema，主要承载合约语义、共享事件 schema 与 fail-closed 规则
- `trnm-node`：未来的 deterministic WASM executor / gas / quota / rollback runtime 宿主；**当前仓内不应宣称已与本子树完成 canonical runtime 接线**
- `trnm-state`：未来承接 contract storage delta 与 state-root inclusion；**当前也不应表述成这些 crates 已纳入 canonical state root pipeline**
- `trnm-rpc`：未来承接 versioned contract call/query/event mapping；**当前不应把现有 crate 直接描述成对外稳定 ABI 已上线**

换句话说：这里现在更像 external-contract runtime perimeter 的 Rust 侧骨架，而不是已经闭合的 host ABI/runtime integration plane。

## 构建边界

当前目录下还没有统一 workspace `Cargo.toml`，因此不要假设可以在 `contracts-rust/` 根目录直接运行统一 workspace gate。

如需验证，当前应按 crate 单独执行，例如：

```bash
cd contracts-rust/settlement-vault && cargo test
cd ../bridge-relay && cargo test
cd ../governance-guard && cargo test
cd ../audit-events && cargo test
```

## Release / mainnet 边界

按当前 truth sources：

- `RELEASE_READINESS.md`：仓库整体 **Not release-ready**
- `TRNM_MAINNET_GAP_MATRIX_2026-03-26.md`：external contracts 更接近 launch-adjacent / scope-dependent 面，不自动属于 Day-1 core minimum
- `TRNM_WEB4_PLATFORM_SCORECARD_2026-03-31.md`：TRNM 仍是强链核、弱平台外围；contract runtime perimeter 也仍在收口阶段

因此，`contracts-rust/` 当前最准确的定位是：

> 一个应被持续推进、但必须保持边界诚实的 Rust-native external-contracts 子树。
