# Trillionnium Web4 MCP Adapter Contract v1（Track A1）

## 1. 目标与范围

定义 Web4 计算市场最小可用 MCP adapter 契约，确保任务请求可以在平台侧被标准化接入、结算并审计。

## 2. 传输与鉴权

- 传输层：HTTPS + JSON
- 鉴权：`Authorization: Bearer <capability_token>`
- 请求必须携带：`X-TRNM-Request-ID`
- 请求必须携带：`X-TRNM-Timestamp`（RFC3339 UTC），允许时钟偏差 ≤ 300 秒；超窗请求按 `401 capability_invalid` fail-closed
- 请求必须携带：`X-TRNM-Schema-Version`（当前固定 `mcp-adapter-v1`）；版本不匹配按 `400 schema_invalid` fail-closed
- 请求必须携带：`X-TRNM-Nonce`（最小 16 字符、120 秒内不可重放）；重放命中按 `401 capability_invalid` fail-closed
- 重试安全：`Idempotency-Key`（同一键值 + 同一请求体必须幂等返回同一 `task_id`）

## 3. 最小请求/响应语义

### 3.1 Request

必填字段：
- `request_id`（string）
- `task_type`（string）
- `input_hash`（64位小写 hex）
- `model.model_id` / `model.version`
- `provenance.producer_did` / `provenance.produced_at` / `provenance.privacy_tier`

### 3.2 Response

必填字段：
- `request_id`
- `task_id`
- `status`（`accepted|rejected|settled`）
- `settlement_ref`（可空）
- `provenance_fingerprint`（可空，遵循隐私策略）

## 4. 错误模型（Fail-Closed）

- 非法 schema：`400 schema_invalid`
- 鉴权失败：`401 capability_invalid`
- 策略拒绝：`403 policy_denied`
- 上游执行失败：`502 upstream_execution_failed`

错误响应最小字段：`request_id` / `error.code` / `error.message`。

## 5. 验收与证据

最小验收证据：
- 请求/响应样例（脱敏）
- `request_id -> task_id` 对账映射
- 结算事件引用（若 `status=settled`）
- 协议版本与适配器传输层记录

## 6. 回滚方案（Reversible）

- 停止 adapter 路由并恢复到前一版本映射
- 撤销新增 capability token
- 冻结本次接入环境凭据
- 标记接入状态为 `reverted`

参考命令：
- `trnm-agent mcp-adapter rollback --env <env> --request-id <request_id> --root-cause-tag <tag>`

根因标签示例：`schema_drift` / `auth_scope_mismatch` / `upstream_contract_break`
