# Trillionnium Web4 A2A Adapter Contract v1（Track A2）

## 1. 目标与范围

定义 Web4 最小可用 A2A adapter 契约，确保 Agent-to-Agent 任务委派在平台侧可鉴权、可结算、可审计。

## 2. 传输与鉴权

- 传输层：HTTPS + JSON
- 鉴权：`Authorization: Bearer <capability_token>`
- 请求必须携带：`X-TRNM-Request-ID`
- 请求必须携带：`X-TRNM-Trace-ID`（与审计导出 `trace_id` 一致）
- 请求必须携带：`X-TRNM-Timestamp`（RFC3339 UTC），时钟偏差 ≤ 300 秒
- 请求必须携带：`X-TRNM-Schema-Version`（固定 `a2a-adapter-v1`）
- 重试安全：`Idempotency-Key`
- 防重放：`X-TRNM-Nonce`
- 请求完整性：`X-TRNM-Body-SHA256`（SHA-256 小写 hex）
- 请求内容类型：`Content-Type: application/json`
- 响应内容类型：`Content-Type: application/json; charset=utf-8`
- 响应必须回显：X-TRNM-Request-ID

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

- 非法 schema：`400 schema_invalid`
- 鉴权失败：`401 capability_invalid`
- 策略拒绝：`403 policy_denied`
- 上游执行失败：`502 upstream_execution_failed`
- 幂等键冲突（同键不同请求体）：`409 idempotency_conflict`
- 防重放冲突：`409 replay_detected`

错误响应最小字段：`request_id` / `error.code` / `error.message`。

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
