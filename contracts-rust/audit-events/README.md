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
