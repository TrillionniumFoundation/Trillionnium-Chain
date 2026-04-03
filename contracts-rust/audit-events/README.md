# audit-events

共享审计事件模型（Rust contracts）

本 crate 提供统一字段 schema：

```rust
pub struct AuditEvent {
    pub source: &'static str,
    pub event_type: &'static str,
    pub actor: Option<String>,
    pub object_id: Option<String>,
    pub related_id: Option<String>,
    pub amount: Option<u128>,
    pub reason: Option<String>,
    pub note: Option<String>,
}
```

各 module 在 `normalized_audit_log()` 中将本地事件转成该结构，供 indexer / 风控流水统一消费。

## Boundary note

- `audit-events/` 是共享审计事件 schema crate，帮助 `contracts-rust/*` 在 Rust MVP 阶段先统一 normalized event 口径。
- 它 **不等价于** `sdk/`、`runtime-spec/` 或 host ABI/runtime integration 已经落地；也**不表示** 当前 external-contract crates 已默认形成 canonical `wasm32-unknown-unknown` 交付物闭环。
- 因此，这个 crate 更适合被理解为 runtime boundary 外围的 shared-schema 邻接层，而不是 Day-1 mainnet / release-ready 证明。
