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
- `docs/agent/a2a_adapter_contract_v1.md` 与 `docs/agent/mcp_adapter_contract_v1.md` 描述的是 **agent-facing adapter contracts**，用于 MCP/A2A 平台接入边界、鉴权、审计与结算语义；它们**不是**当前 `web4-frontend` 的 route contract，也不能据此推断前端已具备写路径。
- 若 agent-facing adapter contract 与 readonly query contract 同时被引用，应以“前台只读查询面”和“Agent 接入面”分开表述，避免把 adapter fail-closed 语义误读为现有 dashboard route 行为。

## 分层结构

1. **类型层**：`types.ts`
2. **校验层**：`schemas.ts`（zod）
3. **适配层**：`adapters.ts`（raw -> typed model）
4. **客户端层**：`client.ts`（GET、超时、重试、错误归一）

约定：只读查询 contract 在 TypeScript 层按 `Readonly` / `ReadonlyArray` 暴露，调用方不应原地修改解析后的响应对象或事件数组；需要派生视图时请复制后处理。

补充：`checkedAt` 目前是共享 contract 字段，语义只接受两类值——链高度标记（`height:<non-negative integer>`）或 ISO-8601 时间字符串。类型层与 zod schema 需保持同步；TypeScript 合约侧应保持为收窄后的 `HeightCheckedAt | IsoDatetimeString`，不应把它当成任意自由格式时间文本。

## 错误模型（FrontendApiError.code）

- `BAD_REQUEST`：HTTP 400 / 调用方输入无效
- `NOT_FOUND`：HTTP 404 / 资源不存在
- `NETWORK`：网络/连接失败
- `TIMEOUT`：请求超时
- `ABORTED`：主动取消（AbortController）
- `HTTP_STATUS`：其余非 2xx（包含 `status`）
- `INVALID_PAYLOAD`：响应不符合合约
- `UNKNOWN`：兜底错误

> 约定：`TIMEOUT` 与 `ABORTED` 语义必须区分。
> 约定：`400` / `404` 不再折叠成通用 `HTTP_STATUS`。

## 重试策略

默认重试策略（`withRetry`）：

- retries: `2`
- base delay: `250ms`
- max delay: `2000ms`
- 指数退避 + jitter

仅当错误标记为 `retryable` 时重试。

`BAD_REQUEST` / `NOT_FOUND` 默认不重试。

`HTTP_STATUS` fallback 仅对更可能瞬时恢复的集合开启重试：`408`、`429`、`500`、`502`、`503`、`504`；其余状态（含非瞬时 `5xx`，如 `501`）默认 fail-closed，不自动重试。

## 使用示例

```ts
import { createFrontendApiClient } from "@/lib/api-contract";

const api = createFrontendApiClient({ baseUrl: "https://rpc.example.com" });

const task = await api.queryTask("task-123");
const events = await api.queryEvents("task-123", { retries: 3 });
const audit = await api.queryCapabilityAudit("alice");
const normalizedEvents = await api.queryNormalizedAuditEvents({
  source: "governance-guard",
  eventType: "governance.proposal_executed",
  limit: 20,
});
```

## Dashboard 环境变量

可选环境变量（`web4-frontend`）

- `NEXT_PUBLIC_DASHBOARD_NORMALIZED_AUDIT_EVENT_LIMIT`：标准化审计事件分页大小（正整数，默认 `60`）
- `NEXT_PUBLIC_DASHBOARD_NORMALIZED_AUDIT_MAX_PAGES`：单次快照抓取最大页数（正整数，默认 `4`）

说明：若设置非法值（空/非数字/小于等于 0），系统回退为默认值。

推荐把上述变量同步维护在 `web4-frontend/.env.example`，按环境复制为 `.env.local`/部署注入。


## Dashboard 消费策略

`fetchReadonlySnapshotFromApi()` 会自动分页拉取标准化审计事件流（默认 60 条/页，最多 4 页），用于将 `Bridge/Governance/Settlement` 的统一审计事件并入前端事件面板。
如服务端不返回 `nextCursor`/`hasMore`，会走单页读取并继续退化。

## 变更规则

- 仅允许**向后兼容**的增量字段变更。
- canonical 只读查询响应当前按 **fail-closed** 处理：未在 `schemas.ts` 声明的根字段或条目字段，不应被前端静默接收。
- 破坏性变更必须同 PR 更新：
  - `types.ts`
  - `schemas.ts`
  - `adapters.ts`
  - 本文档


## 统一审计事件分页约定（可选）

`queryNormalizedAuditEvents(query?, options?)` 支持分页参数：
- `source`：按合约来源过滤（如 `"bridge-relay"` / `"governance-guard"` / `"settlement-vault"`）
- `eventType`：按事件类型过滤（支持前缀或全量匹配）
- `limit`：每页数量（正整数）
- `cursor`：游标（上一次返回 `nextCursor` 继续拉取）

响应可选返回字段：
- `nextCursor`：下一页游标
- `hasMore`：是否有更多
- `total`：后端可选的总记录数估计

额外约束：若响应声明 `hasMore: true`，则必须同时返回非空 `nextCursor`；否则前端按合约违规 fail-closed 处理。
