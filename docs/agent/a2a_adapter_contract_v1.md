# Trillionnium Web4 A2A Adapter Contract v1（Track A2）

## 1. 目标与范围

定义 Web4 最小可用 A2A adapter 契约，确保 Agent-to-Agent 任务委派在平台侧可鉴权、可结算、可审计。

## 2. 传输与鉴权

- 传输层：HTTPS + JSON
- 鉴权：`Authorization: Bearer <capability_token>`
- 请求必须携带：`X-TRNM-Request-ID`
- `X-TRNM-Request-ID` 必须为去首尾空白后的非空字符串；出现前后空白或空串按 `400 schema_invalid` fail-closed
- 请求头 `X-TRNM-Request-ID` 必须与请求体 `request_id` 严格一致；不一致按 `400 schema_invalid` fail-closed
- 请求必须携带：`X-TRNM-Trace-ID`（与审计导出 `trace_id` 一致）
- 请求必须携带：`X-TRNM-Timestamp`（RFC3339 UTC），时钟偏差 ≤ 300 秒
- `X-TRNM-Timestamp` 必须为 `Z` 结尾的 UTC 时间戳；偏移时区按 `400 schema_invalid` fail-closed
- 请求必须携带：`X-TRNM-Schema-Version`（固定 `a2a-adapter-v1`）；版本不匹配按 `400 schema_invalid` fail-closed
- 重试安全：`Idempotency-Key`（同一键值 + 同一请求体必须幂等返回同一 `task_id`）
- 防重放：`X-TRNM-Nonce`
- `X-TRNM-Nonce` 必须绑定 `request_id + X-TRNM-Body-SHA256`；同一 `request_id` 出现重复或漂移 nonce 按 `409 replay_detected` fail-closed
- 请求完整性：`X-TRNM-Body-SHA256`（SHA-256 小写 hex）；与服务端重算不一致按 `400 schema_invalid` fail-closed
- 请求内容类型：`Content-Type: application/json`
- 请求可接受类型：`Accept` 必须显式包含 `application/json`；缺失或不包含 JSON 按 `400 schema_invalid` fail-closed
- `Accept` 中若 `application/json;q=0`（显式不可接受）必须视为不接受 JSON，并按 `400 schema_invalid` fail-closed
- `Accept` 仅为通配符（如 `*/*` 或 `application/*`）不视为“显式包含 `application/json`”，必须按 `400 schema_invalid` fail-closed
- 响应内容类型：`Content-Type: application/json; charset=utf-8`；非 JSON 响应按 `502 upstream_execution_failed` fail-closed
- 响应必须回显：`X-TRNM-Schema-Version: a2a-adapter-v1`；缺失或不匹配按 `502 upstream_execution_failed` fail-closed
- `X-TRNM-Schema-Version` 回显值必须为未加引号的精确 token `a2a-adapter-v1`（禁止 `"a2a-adapter-v1"`、前后空白或参数拼接）；否则按 `502 upstream_execution_failed` fail-closed
- 响应若出现多个 `X-TRNM-Schema-Version` 头（重复字段）必须按协议违约处理，并按 `502 upstream_execution_failed` fail-closed（禁止“取第一个/最后一个”容错）
- 响应必须回显：X-TRNM-Request-ID（与请求值逐字节一致）
- 响应必须回显：X-TRNM-Trace-ID（与请求值逐字节一致）
- 响应体 `request_id` 必须与响应头 `X-TRNM-Request-ID` 严格一致；不一致按 `502 request_id_mismatch` fail-closed
- 错误响应（4xx/5xx）也必须回显 `X-TRNM-Request-ID`，且必须与错误体 `request_id` 严格一致；不一致按 `502 request_id_mismatch` fail-closed

## 3. 最小请求/响应语义

### 3.1 Request

必填字段：
- `request_id`
- `agent_from`
- `agent_to`
- `intent`
- `input_hash`
- `provenance.producer_did` / `provenance.produced_at` / `provenance.privacy_tier`

### 3.2 Response

必填字段：
- `request_id`
- `task_id`
- `status`（`accepted|rejected|settled`）
- `settlement_ref`（可空）
- `provenance_fingerprint`（可空，遵循隐私策略）

## 4. 错误模型（Fail-Closed）

- 非法 schema：`400 schema_invalid`（Agent 侧语义归一：`invalid-request`）
- 鉴权失败：`401 capability_invalid`
- 策略拒绝：`403 policy_denied`
- 上游执行失败：`502 upstream_execution_failed`（Agent 侧语义归一：`internal`）
- 任务不存在：`404 task_not_found`（Agent 侧语义归一：`not-found`）
- 幂等键冲突（同键不同请求体）：`409 idempotency_conflict`
- 防重放冲突：`409 replay_detected`
- 响应请求 ID 不一致：`502 request_id_mismatch`（fail-closed，不允许继续结算）
- 响应 trace ID 不一致：`502 trace_id_mismatch`（fail-closed，不允许继续结算）

错误响应最小字段：`request_id` / `error.code` / `error.message`。

A2 查询工作流稳定性约束：
- Adapter 错误语义必须可稳定映射为 `not-found` / `invalid-request` / `internal`。
- 不允许把 schema 错误或上游失败降级为 `not-found`（fail-closed）。

## 5. 验收与证据

最小验收证据：
- 请求/响应样例（脱敏）
- `request_id -> task_id` 对账映射
- 结算事件引用（若 `status=settled`）
- 协议版本与适配器传输层记录

## 6. 回滚方案（Reversible）

- 停止 A2A adapter 路由并恢复到前一版本
- 撤销新增 capability token
- 冻结本次接入环境凭据
- 标记接入状态为 `reverted`

参考命令：
- `trnm-agent a2a-adapter rollback --env <env> --request-id <request_id> --root-cause-tag <tag>`

根因标签示例：`schema_drift` / `auth_scope_mismatch` / `upstream_contract_break`
