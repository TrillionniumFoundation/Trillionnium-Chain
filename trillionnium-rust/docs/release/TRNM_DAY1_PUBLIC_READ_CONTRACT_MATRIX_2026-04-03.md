# TRNM Day-1 Public Read Contract Matrix (2026-04-03)

适用快照：`main@bb83dd6a3`

## 用途

本文件把 `TRNM_DAY1_PUBLIC_READ_CONTRACT_2026-04-03.md` 压成**执行矩阵**，用于：
- backend / RPC 对齐
- frontend client / adapter 对齐
- conformance tests 对齐
- release signoff 对齐

它回答的不是“未来想支持什么”，而是：

> **当前 Day-1 允许冻结哪些 public read endpoints，以及每个 endpoint 的最小 contract、错误语义与 out-of-scope 边界。**

---

## Day-1 in-scope matrix

| Endpoint | 目标语义 | 当前调用入口 | 最小输入 | 最小成功输出 | 必须 fail-closed 的点 | Day-1 不承诺的内容 |
|---|---|---|---|---|---|---|
| `GET /query-task/:taskId` | 查询单个 task 的最小只读状态 | `web4-frontend/lib/api-contract/client.ts#queryTask` | `taskId` path 参数 | `task`，最小可归一化为 `id/name/status/owner/createdAt/metadata` | canonical payload 出现未知字段时不得静默透传；无效 taskId 不得隐式降级 | 不承诺 block/tx/account 关联聚合、不承诺 indexer-backed history |
| `GET /query-events/:taskId` | 查询 task 事件序列 | `client.ts#queryEvents` | `taskId`；可选 `limit` | `taskId + events[]`，每个 event 最小可归一化为 `id/taskId/type/level/timestamp/payload` | frozen M2V2 resolution code 必须 fail-closed 映射到 error-level；`resolutionCode` / `resolution_code` alias 必须稳定归一化 | 不承诺任意全链事件检索，不承诺 archive replay 历史 completeness |
| `GET /query-capability-audit/:subjectOrToken` | 查询 capability 审计状态 | `client.ts#queryCapabilityAudit` | `subjectOrToken` path 参数 | `subject + audits[]`，每条 audit 最小为 `subject/capability/granted/reason/checkedAt` | DID registration history 不得误判为 capability grant；不存在 subject/token 不得冒充空成功 | 不承诺 generalized auth graph，不承诺跨系统 capability federation |
| `GET /query-normalized-audit-events?...` | 查询统一后的 normalized audit events | `client.ts#queryNormalizedAuditEvents` | 仅接受 `normalizedAuditEventsQuerySchema` 已允许的 query 字段 | `events[]` + pagination/nextPage（若存在）；返回应与 parsed query 保持一致 | query 参数无效时必须直接报错；不得隐式接受 schema 外字段；pagination 语义必须稳定 | 不承诺未来筛选器；不承诺 durable explorer lag/SLO；不承诺超出 schema 的查询维度 |
| `GET /healthz` | 运维 health probe | RPC health endpoint | 无 | 最小为 `ok/service/ts_unix_ms/version` | 不能把 healthz 冒充公共数据接口；异常时不能伪装成功 | 不计入产品级 public read surface |

---

## Explicitly out of Day-1 freeze

以下内容当前**明确不纳入** Day-1 public read contract：

1. `block query`
2. `tx query`
3. `account query` 的 public freeze
4. durable explorer backend contract
5. historical read-model contract
6. index lag / public SLO contract
7. archive / replay-backed explorer guarantees

原因不是“永远不做”，而是：

> **在当前代码快照下，它们还没有闭环到足以成为 Day-1 public promise。**

---

## Error semantics matrix

| Contract layer | 语义 | 何时出现 | 调用方默认行为 |
|---|---|---|---|
| `BAD_REQUEST` | 输入非法 | 非法 path 参数 / 非法 query 参数 / schema 校验失败 | 修正输入，不重试 |
| `NOT_FOUND` | 资源不存在 | task 不存在 / token 不存在 / subject 不存在 | 不做猜测性重试 |
| `INVALID_PAYLOAD` | backend 返回不符合 contract 的 payload | 非 JSON / adapter 无法归一化 / canonical payload 含未知字段 | fail-closed，不当作成功 |
| `TIMEOUT` | 请求超时 | backend 超时 / timeout guard 命中 | 可重试 |
| `ABORTED` | 调用方主动取消 | caller abort / signal abort | 不重试 |
| `NETWORK` | 网络错误 | fetch/network 层失败 | 可重试 |
| `UNKNOWN` | 未知错误 | 无法归类但明确不应算成功 | 默认不宣称成功 |

---

## Compatibility rules

### Allowed
- backend 内部实现替换（future indexer / replay source / storage backend）
- canonical payload 与 rpc fallback payload 并存，只要 adapter 输出 contract 不变
- health probe 实现细节调整，只要最小字段保持稳定

### Not allowed
- 无文档通知地增加/删除必填字段
- 依赖 frontend adapter 猜测未来 schema
- 把 explorer scaffold 或 local placeholder 表述成 durable explorer backend
- 把未冻结的 block/tx/account 读取能力写成 Day-1 承诺

---

## 当前最小 signoff 条件

本矩阵可进入 Day-1 signoff 的前提是：

1. `client.ts` / `schemas.ts` / `types.ts` / `adapters.ts` 与本表一致
2. 对应 RPC handler 路径已与本表一致
3. adapter tests 覆盖所有 fail-closed 规则
4. query-normalized-audit-events 的 query 字段有表格化说明
5. out-of-scope 项未被 README / frontend / runbook 误写成已支持
6. 若 signoff 同时引用 operator-facing deployment path，则必须先做 **template selection**，再决定允许附哪类 handoff evidence：
   - 若证据仍来自 `trillionnium-rust/docs/runbooks/explorer-service-scaffold.md` 的静态 scaffold bring-up，或 `deployment_evidence_scope` 仍是 `placeholder-only`，则只允许附 `TRNM_EXPLORER_SCAFFOLD_HANDOFF_TEMPLATE_2026-04-04.md` 对应 evidence，不得把 placeholder packet 改写成 durable handoff
   - 只有当 `deployment_evidence_scope=durable-read-service`、`service_mode=non-placeholder-durable-read-service`、6 个 durable-read anchors 都已有真实值，且 replay / restore / checkpoint / lag evidence 同时具备时，才允许附 `TRNM_DURABLE_READ_SERVICE_HANDOFF_TEMPLATE_2026-04-04.md` 对应 evidence
   - placeholder-only 场景下，必须附：
     - `trillionnium-rust/docs/runbooks/explorer-service-scaffold.md`
     - env file 关键字段（`EXPLORER_HOST` / `EXPLORER_PORT` / `EXPLORER_PUBLIC_BASE_URL` / `EXPLORER_HEALTH_URL` / `EXPLORER_RPC_BASE_URL`）
     - 一次 `./scripts/v2/explorer_service_status.sh` 输出
     - 一次 `/index.json` 抓取结果
     - fail-closed blocker markers：`deployment_evidence_scope=placeholder-only`、`rank1_read_surface_blocker=still-open`、`durable_indexer_status=not-implemented-in-this-scaffold`、`historical_query_scope=rpc-retention-bounded`、`durable_read_anchor_complete=false`
   - 若上述 durable 条件不满足，则一律按 blocker-open / placeholder-only 处理，而不是补写 future durable 字段

---

## 下一步直连项

- `TRNM_QUERY_NORMALIZED_AUDIT_EVENTS_CONTRACT_TABLE_2026-04-03.md`
- `TRNM_GROUPA_CONFORMANCE_CHECKLIST_2026-04-03.md`
- `TRNM_DAY1_PUBLIC_READ_CONTRACT_2026-04-03.md`
- `TRNM_RANK1_READ_SURFACE_TASK_BOARD_2026-04-03.md`
