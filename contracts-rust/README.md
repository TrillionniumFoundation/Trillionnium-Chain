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
- **部分相关**：`audit-events/` 提供共享审计事件 schema，但它是配套 shared-schema crate，**不等价于** 目标布局里的 `sdk/` 或 `runtime-spec/`
- **尚未落地为目录**：`sdk/`、`runtime-spec/`、`integration-tests/`

换句话说：当前目录树已经出现了“3 个 contract crates + 1 个 shared schema crate”的 Rust MVP 形态，但**还没有** 达到架构文档里描述的 host ABI/runtime-spec/package-layout 闭环。

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

### 当前可安全假设的 ABI / runtime boundary

为避免把“目标架构”误写成“当前事实”，当前仓库下对 external contracts 最安全的表述应收敛为：

- **可以说**：这些 crate 已经把部分合约语义、审计事件 schema、fail-closed 约束先用 Rust 形式固定下来
- **可以说**：`audit-events/` 提供 shared schema 邻接层，有助于后续统一事件口径
- **不要说**：当前已经存在可复用的 canonical `HostAbiV1` 实现或稳定宿主 trait 接线
- **不要说**：当前已经有 node-side deterministic WASM sandbox、gas metering、storage delta apply、RPC ABI versioning 的闭环集成
- **不要说**：当前 `contracts-rust/*` crates 已默认编译并交付为链上 canonical `wasm32-unknown-unknown` artifacts
- **不要说**：当前 external contracts 已自动进入 public-mainnet Day-1 minimum scope；是否纳入 launch promise，仍取决于 `RELEASE_READINESS.md` 与 `TRNM_MAINNET_GAP_MATRIX_2026-03-26.md`

这组边界的核心含义是：**架构方向已锁定，但 runtime 接线、ABI 冻结落地、以及 Day-1 scope 判定都还不能被提前宣称为完成。**

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
- `trillionnium-rust/docs/protocol/external-contracts-rust/RUST_NATIVE_EXTERNAL_CONTRACTS_ARCH_2026-03-05.md`：定义的是目标 package layout / Host ABI / runtime boundary，不能把目标布局误读为当前工程已闭环

### Day-1 scope 判读（保持与 gap matrix 一致）

当前 `contracts-rust/` 子树更适合作为 **Day-1 scope-dependent / trailing-capable** 的外围面来描述，而不是默认 P0：

- `settlement-vault/`：只有在公开 launch promise 明确包含 oracle-backed settlement / vault semantics 时，才应上升为 Day-1 blocker；否则更接近可后置模块。
- `bridge-relay/`：只有在公开 day-1 叙事包含 cross-chain / bridge positioning 时，才应被视为 P0；否则按 gap matrix 应维持 trailing-capable 口径。
- `governance-guard/`：可以帮助冻结 upgrade / pause discipline，但当前 crate 仍是 Rust MVP 语义骨架，不等价于已完成链上治理接线或 public-mainnet governance closure。
- `audit-events/`：只是 shared schema 邻接层；它有助于统一事件口径，但不单独决定 external contracts 已进入 Day-1 minimum scope。

因此，在 README、对外材料或内部 handoff 中，更安全的写法应是：

> `contracts-rust/` 代表 TRNM external-contract perimeter 的 Rust MVP 子树；哪些模块会进入 Day-1 launch promise，仍取决于当轮 mainnet scope freeze，而不是由目录存在本身自动决定。

因此，`contracts-rust/` 当前最准确的定位是：

> 一个应被持续推进、但必须保持边界诚实的 Rust-native external-contracts 子树。
