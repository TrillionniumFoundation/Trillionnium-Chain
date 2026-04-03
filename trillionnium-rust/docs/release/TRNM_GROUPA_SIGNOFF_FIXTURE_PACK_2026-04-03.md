# TRNM Group A Signoff Fixture Pack (2026-04-03)

适用快照：`main@bb83dd6a3`

## 用途

本文件是 Group A / Rank 1 的**最小 signoff evidence packet**。

它不是新的 truth-source，作用是把已经完成的 Group A 收口压成一页可引用的证据，回答四个问题：

1. Day-1 public read contract 到底覆盖哪些 endpoint？
2. 每个 endpoint 目前由哪些 tests 在兜底？
3. 哪些 fail-closed 行为已经有自动化证据？
4. 哪些仍然是 open item，而不是被误包装成“已完全关闭”？

配套文档：
- `TRNM_DAY1_PUBLIC_READ_CONTRACT_2026-04-03.md`
- `TRNM_DAY1_PUBLIC_READ_CONTRACT_MATRIX_2026-04-03.md`
- `TRNM_QUERY_NORMALIZED_AUDIT_EVENTS_CONTRACT_TABLE_2026-04-03.md`
- `TRNM_GROUPA_CONFORMANCE_CHECKLIST_2026-04-03.md`
- `TRNM_GROUPA_CONTRACT_DRIFT_GUARD_PACK_2026-04-03.md`

---

## Current evidence command

```bash
cd web4-frontend
npx vitest run \
  tests/unit/normalized-audit-query-contract.test.ts \
  tests/unit/api-client-retry.test.ts \
  tests/unit/api-contract-adapters.test.ts \
  tests/unit/dashboard-source-pagination.test.ts
```

当前实测结果（2026-04-03）：
- `4 files passed / 105 tests passed`

---

# A. Endpoint signoff matrix

## A1. `GET /query-task/:taskId`

### Contract scope
- 查询单个 task 的最小只读状态面。
- 最小成功输出：`task.id / name / status / owner / createdAt / metadata`

### Current evidence
**Primary file**
- `web4-frontend/tests/unit/api-contract-adapters.test.ts`

**Covered tests**
- `accepts canonical query-task payload`
- `fails closed on canonical query-task payloads with unknown fields`
- `adapts rpc query-task payload`
- `fails closed on canonical query-task payloads with invalid status`
- `fails closed on canonical query-task payloads missing task id`
- `fails closed on rpc query-task payloads missing task_id`
- `fails closed on rpc query-task payloads with invalid status`

### Signoff statement
- canonical success 有证据
- rpc fallback success 有证据
- invalid status / missing id / unknown fields 的 fail-closed 有证据

**Status:** `SIGNOFF-READY (Group A scope)`

---

## A2. `GET /query-events/:taskId`

### Contract scope
- 查询 task 事件序列。
- 最小成功输出：`taskId + events[]`
- 冻结点包含：`resolutionCode` / `resolution_code` alias、frozen M2V2 resolution mapping、mixed-task-id fail-closed

### Current evidence
**Primary file**
- `web4-frontend/tests/unit/api-contract-adapters.test.ts`

**Covered tests**
- `adapts rpc query-events array payload`
- `normalizes canonical events with frozen M2V2 resolution code to fail-closed level`
- `normalizes canonical events using snake_case resolution_code alias`
- `ignores canonical resolution_code aliases that normalize to empty noise`
- `falls back to snake_case resolution_code when camelCase alias is blank noise`
- `prefers canonical resolutionCode alias when both aliases are present`
- `does not over-trigger fail-closed mapping for non-frozen canonical resolution codes`
- `maps frozen M2V2 resolution codes to fail-closed error signal`
- `canonicalizes M2V2 resolution code casing/whitespace before fail-closed mapping`
- `canonicalizes hyphen/space-separated M2V2 resolution code tokens before fail-closed mapping`
- `canonicalizes unicode dash-separated M2V2 resolution code tokens before fail-closed mapping`
- `canonicalizes boundary separators around M2V2 resolution code before fail-closed mapping`
- `canonicalizes M2V2 resolution code with BOM/zero-width noise before fail-closed mapping`
- `treats all frozen M2V2 resolution codes as fail-closed errors`
- `fails closed when rpc events contain mixed task ids`
- `fails closed on malformed payload`

### Signoff statement
- alias normalization 有证据
- frozen M2V2 codes -> error-level signal 有证据
- malformed payload / mixed task ids fail-closed 有证据
- non-frozen canonical resolution code 不误报 error-level 有证据

**Status:** `SIGNOFF-READY (Group A scope)`

---

## A3. `GET /query-capability-audit/:subjectOrToken`

### Contract scope
- 查询 capability 审计状态。
- 最小成功输出：`subject + audits[]`
- 冻结点包含：DID registration history ≠ capability grant；subject/token path 参数不能为空；token-revoked 语义不能误伤非 capability history

### Current evidence
**Primary files**
- `web4-frontend/tests/unit/api-contract-adapters.test.ts`
- `web4-frontend/tests/unit/api-client-retry.test.ts`

**Covered tests**
- `treats DID registration history as non-grant in rpc capability audit fallback`
- `adapts rpc capability audit payload`
- `preserves historical grant entries while annotating token-revoked capability audit state`
- `preserves explicit capability revoke history under token-revoked semantics`
- `keeps non-capability history entries non-grant even when token is revoked`
- `falls back to action when rpc capability audit note is blank or whitespace`
- `accepts canonical capability audit payload with height marker checkedAt`
- `accepts canonical capability audit payload with iso checkedAt`
- `fails closed on canonical capability audit entries with unknown fields`
- `treats blank revoked_at as absent instead of forcing token-revoked audit semantics`
- `fails closed when rpc capability audit contains invalid height markers`
- `fails closed when rpc capability audit token subject is missing`
- `normalizes capability audit subject before path construction`
- `fails closed on blank capability audit subject before request`

### Signoff statement
- canonical success 有证据
- rpc fallback success 有证据
- DID registration history 不误判为 grant 有证据
- blank subject / malformed token history fail-closed 有证据

**Status:** `SIGNOFF-READY (Group A scope)`

---

## A4. `GET /query-normalized-audit-events?...`

### Contract scope
- 查询 normalized audit events。
- 冻结点分为三层：
  1. query/request-side schema enforcement
  2. response/page contract enforcement
  3. pagination runtime behavior

### Current evidence
**Primary files**
- `web4-frontend/tests/unit/normalized-audit-query-contract.test.ts`
- `web4-frontend/tests/unit/api-client-retry.test.ts`
- `web4-frontend/tests/unit/api-contract-adapters.test.ts`
- `web4-frontend/tests/unit/dashboard-source-pagination.test.ts`

**Covered tests / checks**

**Request-side**
- `freezes the schema key set to the expected day-1 query keys`
- `serializes every schema-approved query key through the drift-guard helper`
- `rejects unknown query fields before request construction`
- `rejects invalid cursor values fail-closed`
- `rejects invalid limit values fail-closed`
- `omits absent optional fields from the serialized query string`
- `serializes the currently supported scalar query keys with stable names`
- `builds normalized audit query params`
- `fails closed on malformed normalized audit query params`
- `fails closed on unknown normalized audit query params`
- `uses normalized audit endpoint`

**Response-side**
- `adapts canonical paginated normalized audit-events payload`
- `fails closed when canonical normalized audit pagination reports hasMore without usable cursor`
- `fails closed when canonical normalized audit pagination loops back to the requested cursor`
- `fails closed on malformed canonical normalized audit-events items`
- `fails closed on malformed canonical normalized audit-events envelope`
- `fails closed on canonical normalized audit-event entries with unknown fields`
- `fails closed on canonical normalized audit-events page nextCursor type mismatch`
- `fails closed on canonical normalized audit-events page hasMore type mismatch`
- `fails closed on canonical normalized audit-events page total non-integer`
- `fails closed when canonical normalized audit-events page sets hasMore without nextCursor`
- `adapts normalized audit-events fallback with eventType/objectId aliases`
- `fails closed on fallback normalized audit-events entries with unknown fields`

**Pagination/runtime**
- `uses env-configured pagination limits for normalized audit events`
- `falls back to defaults when env values are invalid`
- `falls back to default pagination limit when env is zero`
- `loads multiple normalized audit pages and merges into dashboard events`
- `fails closed when normalized audit pagination cannot be loaded`
- `fails closed when normalized audit pagination repeats a cursor`
- `fails closed when normalized audit pagination declares more pages without a cursor`
- `fails closed when normalized audit pagination exceeds the configured max pages`

### Signoff statement
- request-side fail-closed 有证据
- response/page fail-closed 有证据
- pagination runtime red线有证据
- request serialization drift guard 有证据

**Status:** `SIGNOFF-READY (Group A scope)`

---

## A5. `GET /healthz`

### Contract scope
- 运维探针。
- 不属于产品级 public data plane。

### Current evidence
**Primary source**
- `TRNM_DAY1_PUBLIC_READ_CONTRACT_2026-04-03.md`
- `TRNM_DAY1_PUBLIC_READ_CONTRACT_MATRIX_2026-04-03.md`
- `TRNM_GROUPA_CONTRACT_DRIFT_GUARD_PACK_2026-04-03.md`

### Signoff statement
- 当前有**文档边界证据**，但没有与前四个 endpoint 同等级的 frontend conformance test pack。

**Status:** `DOC-GUARDED ONLY`

---

# B. Fail-closed behavior summary

## B1. Request-side fail-closed
已覆盖：
- blank / malformed normalized audit query
- unknown normalized audit query field
- blank capability audit subject
- invalid path/query input 不得在 request 发出后再靠 backend 猜测修复

## B2. Adapter fail-closed
已覆盖：
- canonical unknown fields
- malformed canonical payloads
- rpc fallback payload 缺失关键字段
- mixed task ids
- invalid task status / missing task identifiers
- invalid capability audit height markers / missing token subject
- invalid normalized audit pagination envelope

## B3. Error taxonomy fail-closed
已覆盖：
- `400 -> BAD_REQUEST`
- `404 -> NOT_FOUND`
- non-JSON payload -> `INVALID_PAYLOAD`
- contract-invalid JSON payload -> `INVALID_PAYLOAD`
- timeout / aborted / network / unknown 区分
- retryability boundaries

---

# C. Current open items

## C1. `healthz` is doc-guarded only
- 当前仍主要依赖文档边界保护。
- 尚未进入与其它四个 Day-1 endpoint 同等级的 frontend conformance pack。

## C2. Group A signoff ≠ overall launch signoff
- 本包只说明：**Day-1 public read surface 的 Group A contract 已有最小自动化证据包。**
- 不意味着 durable explorer backend、historical read-model、archive replay guarantee、block/tx/account public freeze 已关闭。
- 也不意味着整体 mainnet release 已 GO。

## C3. Out-of-scope must stay out-of-scope
以下仍不得借 signoff 包被重新包装成“已支持”：
- block query
- tx query
- account query public freeze
- durable explorer backend contract
- historical read-model contract
- public SLO / index-lag contract

---

# D. Minimal signoff note

如果现在要给 Group A 一个最小 signoff 结论，可写成：

> 基于 `TRNM_DAY1_PUBLIC_READ_CONTRACT_2026-04-03.md`、`TRNM_DAY1_PUBLIC_READ_CONTRACT_MATRIX_2026-04-03.md`、`TRNM_QUERY_NORMALIZED_AUDIT_EVENTS_CONTRACT_TABLE_2026-04-03.md` 与当前最小证据命令（`4 files passed / 105 tests passed`），Group A 当前可将以下 Day-1 public read endpoints 视为 **contract signoff-ready within scope**：`query-task`、`query-events`、`query-capability-audit`、`query-normalized-audit-events`。`healthz` 当前为 **doc-guarded only**，不应按同等级自动化证据对待。Group A signoff 不扩展到 durable explorer backend、historical read-model、archive replay guarantee、block/tx/account public freeze，也不代表整体主网发布 GO。

---

# 一句话

> **GA-09 的价值，是把 Group A 从“有很多测试”提升成“有一页可以直接贴进 signoff/review 结论的最小证据包”。**
