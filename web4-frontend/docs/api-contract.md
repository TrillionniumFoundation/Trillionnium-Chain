# API 合约（只读查询）

## 范围

当前前端合约层覆盖以下只读接口：

- `GET /query-task/:taskId`
- `GET /query-events/:taskId`
- `GET /query-capability-audit/:subject`
- `GET /query-normalized-audit-events` (可选：统一事件流，若未部署则前端静默退化)

实现目录：`lib/api-contract/`

## 语义边界

- 本文档描述的是**当前前端实际消费的只读查询接口**。
- 当前仓内并没有 `/api/v0/web4/*` 对应 route；若你在历史文档里看到这些路径，应理解为未落地的聚合草案，而不是现有实现。
- Dashboard 默认走只读 API client；仅在显式 `?mode=mock` 时回退到本地 mock snapshot。

## 分层结构

1. **类型层**：`types.ts`
2. **校验层**：`schemas.ts`（zod）
3. **适配层**：`adapters.ts`（raw -> typed model）
4. **客户端层**：`client.ts`（GET、超时、重试、错误归一）

## 错误模型（FrontendApiError.code）

- `NETWORK`：网络/连接失败
- `TIMEOUT`：请求超时
- `ABORTED`：主动取消（AbortController）
- `HTTP_STATUS`：非 2xx（包含 `status`）
- `INVALID_PAYLOAD`：响应不符合合约
- `UNKNOWN`：兜底错误

> 约定：`TIMEOUT` 与 `ABORTED` 语义必须区分。

## 重试策略

默认重试策略（`withRetry`）：

- retries: `2`
- base delay: `250ms`
- max delay: `2000ms`
- 指数退避 + jitter

仅当错误标记为 `retryable` 时重试。

## 使用示例

```ts
import { createFrontendApiClient } from "@/lib/api-contract";

const api = createFrontendApiClient({ baseUrl: "https://rpc.example.com" });

const task = await api.queryTask("task-123");
const events = await api.queryEvents("task-123", { retries: 3 });
const audit = await api.queryCapabilityAudit("alice");
const normalizedEvents = await api.queryNormalizedAuditEvents();
```

## 变更规则

- 仅允许**向后兼容**的增量字段变更。
- 破坏性变更必须同 PR 更新：
  - `types.ts`
  - `schemas.ts`
  - `adapters.ts`
  - 本文档
