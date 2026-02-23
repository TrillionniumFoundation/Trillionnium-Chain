# PR-3 Events Audit Field Mapping

## 目标
在 node 事件输出（`[event] ...`）与 RPC 事件查询（`query-events` / `query-request-full`）之间统一审计字段：
- `signer`
- `challenger`
- `tx_hash`
- `resolution_code`

并保持向后兼容（旧字段保留，新增字段按可获取性透出）。

## 字段映射表

| 审计字段 | Node 日志键 | RPC `EventQueryResponse` 字段 | 取值规则 |
|---|---|---|---|
| signer | `signer=` | `signer` (Option<String>) | Node 端默认取 `actor`；RPC 端优先读取 node 事件，缺失时回退到 `actor` |
| challenger | `challenger=` | `challenger` (Option<String>) | 仅 challenge 事件有值；其余事件 node 记为 `-`，RPC 解析为 `None` |
| tx_hash | `tx_hash=` | `tx_hash` (Option<String>) | Node mock 事件输出 `0xmock{tx_id_hex}`；`query-request-full` 对 commit/reveal 事件优先绑定 ingress 中 `commit_tx_hash`/`reveal_tx_hash` |
| resolution_code | `resolution_code=` | `resolution_code` (Option<String>) | resolve 事件输出并透出；`query-request-full` 优先使用 ingress `resolution_code`，否则用 node 事件值 |

## 兼容性说明

1. **RPC 向后兼容**
   - `EventQueryResponse` 新增字段均为 `Option<String>`。
   - 序列化使用 `skip_serializing_if = "Option::is_none"`，旧消费者在字段缺失场景下得到与过去一致的 JSON 形状。
2. **Node 日志向后兼容**
   - 原有字段（`event_type/task_id/.../ts_unix_ms`）保持不变。
   - 仅追加新 token，不破坏按旧 token 解析的消费者。
3. **数据可用性分层**
   - 事件日志层提供基础审计字段。
   - `query-request-full` 在 commit/reveal/resolve 场景会用 ingress 记录补全更权威的 `tx_hash`/`resolution_code`。
