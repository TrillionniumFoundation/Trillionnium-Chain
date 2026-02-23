# PR-4 Challenge 经济审计字段映射（RPC / Node Event）

## 新增字段（向后兼容）

在 `EventQueryResponse` 中新增可选字段（`Option` + `skip_serializing_if`）：

- `treasury_delta: Option<i128>`
- `challenger_delta: Option<i128>`
- `bond_disposition: Option<String>`

当字段缺失时不会出现在 JSON 中，旧客户端无需修改即可继续反序列化。

## Node 事件 -> RPC 字段映射

Node 事件日志新增 kv：

- `treasury_delta`
- `challenger_delta`
- `bond_disposition`

`trnm-rpc` 的 `load_latest_node_events()` 会读取并解析上述字段，随后在：

- `query-events`
- `query-request-full`

中透传到 `EventQueryResponse`。

## Challenge 经济语义（当前实现）

### 1) `event_type=challenge`
- `bond_disposition="posted"`
- `challenger_delta = -bond`
- `treasury_delta = 0`

### 2) `event_type=resolve` 且 `slash_worker=true`
- `bond_disposition="refunded"`
- `challenger_delta = +challenge_bond`
- `treasury_delta = 0`

### 3) `event_type=resolve` 且 `slash_worker=false`
- `bond_disposition="forfeited"`
- `challenger_delta = 0`
- `treasury_delta = 0`

> 备注：当前 MVP forfeited bond 未记入 treasury（锁定/销毁语义），因此 `treasury_delta` 维持 0。后续若经济规则改为入库国库，仅需调整 node 事件赋值逻辑，RPC 结构无需再改。

## 兼容性策略

1. **只增不改**：新增字段全部为可选，不修改既有字段名/类型。
2. **旧日志兼容**：旧 node 日志缺少新 kv 时，RPC 解析为 `None`。
3. **契约稳定**：已有“字段缺失时 JSON 形状不变”测试继续成立。
