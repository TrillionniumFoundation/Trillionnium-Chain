# TRNM Group A Contract Drift Guard Pack (2026-04-03)

适用快照：`main@bb83dd6a3`

## 用途

本文件是 Group A / Rank 1 的 **drift guard mapping note**。

它解决的问题不是“接口未来可能长什么样”，而是：

> **当 Day-1 public read contract 已经开始冻结时，reviewer 如何快速判断：文档、schema、types、client、adapter、tests 之间有没有漂移。**

配套 truth-source：
- `TRNM_DAY1_PUBLIC_READ_CONTRACT_2026-04-03.md`
- `TRNM_DAY1_PUBLIC_READ_CONTRACT_MATRIX_2026-04-03.md`
- `TRNM_QUERY_NORMALIZED_AUDIT_EVENTS_CONTRACT_TABLE_2026-04-03.md`
- `TRNM_GROUPA_CONFORMANCE_CHECKLIST_2026-04-03.md`
- `TRNM_GROUPA_CONFORMANCE_CODE_TASKS_2026-04-03.md`
- `TRNM_GROUPA_SIGNOFF_FIXTURE_PACK_2026-04-03.md`

---

## Review fast-path

如果只做一次最小 drift 审计，顺序建议固定为：

1. 先看 `TRNM_DAY1_PUBLIC_READ_CONTRACT_2026-04-03.md`
2. 再看 `TRNM_DAY1_PUBLIC_READ_CONTRACT_MATRIX_2026-04-03.md`
3. 对照本文件的 endpoint mapping
4. 跑当前最小证据命令：

```bash
cd web4-frontend
npx vitest run \
  tests/unit/normalized-audit-query-contract.test.ts \
  tests/unit/api-client-retry.test.ts \
  tests/unit/api-contract-adapters.test.ts \
  tests/unit/dashboard-source-pagination.test.ts
```

当前实测基线（2026-04-03）：
- `4 files passed / 105 tests passed`

---

# A. Endpoint → Code/Test mapping

## A1. `GET /query-task/:taskId`

| Layer | Truth-source |
|---|---|
| Client entry | `web4-frontend/lib/api-contract/client.ts#queryTask` |
| Response schema | `web4-frontend/lib/api-contract/schemas.ts#queryTaskResponseSchema` |
| Shared schema nodes | `schemas.ts#chainTaskSchema` + `schemas.ts#taskStatusSchema` |
| Public types | `web4-frontend/lib/api-contract/types.ts#QueryTaskResult` + `ChainTask` + `TaskStatus` |
| Adapter entry | `web4-frontend/lib/api-contract/adapters.ts#adaptQueryTask` |
| Primary conformance tests | `web4-frontend/tests/unit/api-contract-adapters.test.ts` |
| Current frozen checks | `accepts canonical query-task payload`; `fails closed on canonical query-task payloads with unknown fields`; `adapts rpc query-task payload`; `fails closed on canonical query-task payloads with invalid status`; `fails closed on canonical query-task payloads missing task id`; `fails closed on rpc query-task payloads missing task_id`; `fails closed on rpc query-task payloads with invalid status` |

**Reviewer question**
- 如果 `taskStatusSchema`、`ChainTask` 或 `adaptQueryTask()` 中任一方改了字段/状态枚举，以上测试是否仍能直接解释这个改动是否合法？

---

## A2. `GET /query-events/:taskId`

| Layer | Truth-source |
|---|---|
| Client entry | `web4-frontend/lib/api-contract/client.ts#queryEvents` |
| Response schema | `web4-frontend/lib/api-contract/schemas.ts#queryEventsResponseSchema` |
| Shared schema nodes | `schemas.ts#chainEventSchema` |
| Public types | `web4-frontend/lib/api-contract/types.ts#QueryEventsResult` + `ChainEvent` |
| Adapter entry | `web4-frontend/lib/api-contract/adapters.ts#adaptQueryEvents` |
| Primary conformance tests | `web4-frontend/tests/unit/api-contract-adapters.test.ts` |
| Current frozen checks | `adapts rpc query-events array payload`; `normalizes canonical events with frozen M2V2 resolution code to fail-closed level`; `normalizes canonical events using snake_case resolution_code alias`; `ignores canonical resolution_code aliases that normalize to empty noise`; `falls back to snake_case resolution_code when camelCase alias is blank noise`; `prefers canonical resolutionCode alias when both aliases are present`; `does not over-trigger fail-closed mapping for non-frozen canonical resolution codes`; `maps frozen M2V2 resolution codes to fail-closed error signal`; `canonicalizes M2V2 resolution code casing/whitespace before fail-closed mapping`; `canonicalizes hyphen/space-separated M2V2 resolution code tokens before fail-closed mapping`; `canonicalizes unicode dash-separated M2V2 resolution code tokens before fail-closed mapping`; `canonicalizes boundary separators around M2V2 resolution code before fail-closed mapping`; `canonicalizes M2V2 resolution code with BOM/zero-width noise before fail-closed mapping`; `treats all frozen M2V2 resolution codes as fail-closed errors`; `fails closed when rpc events contain mixed task ids`; `fails closed on malformed payload` |

**Reviewer question**
- `resolutionCode` / `resolution_code` alias、frozen M2V2 code、mixed-task-id fail-closed 这三类规则，是否仍与 Day-1 matrix 完全一致？

---

## A3. `GET /query-capability-audit/:subjectOrToken`

| Layer | Truth-source |
|---|---|
| Client entry | `web4-frontend/lib/api-contract/client.ts#queryCapabilityAudit` |
| Path normalization | `client.ts#normalizeRequiredPathParam` |
| Response schema | `web4-frontend/lib/api-contract/schemas.ts#queryCapabilityAuditResponseSchema` |
| Shared schema nodes | `schemas.ts#capabilityAuditEntrySchema` + `schemas.ts#checkedAtSchema` |
| Public types | `web4-frontend/lib/api-contract/types.ts#QueryCapabilityAuditResult` + `CapabilityAuditEntry` + `CheckedAt` |
| Adapter entry | `web4-frontend/lib/api-contract/adapters.ts#adaptQueryCapabilityAudit` |
| Primary conformance tests | `web4-frontend/tests/unit/api-contract-adapters.test.ts`; `web4-frontend/tests/unit/api-client-retry.test.ts` |
| Current frozen checks | `treats DID registration history as non-grant in rpc capability audit fallback`; `adapts rpc capability audit payload`; `preserves historical grant entries while annotating token-revoked capability audit state`; `preserves explicit capability revoke history under token-revoked semantics`; `keeps non-capability history entries non-grant even when token is revoked`; `falls back to action when rpc capability audit note is blank or whitespace`; `accepts canonical capability audit payload with height marker checkedAt`; `accepts canonical capability audit payload with iso checkedAt`; `fails closed on canonical capability audit entries with unknown fields`; `treats blank revoked_at as absent instead of forcing token-revoked audit semantics`; `fails closed when rpc capability audit contains invalid height markers`; `fails closed when rpc capability audit token subject is missing`; `normalizes capability audit subject before path construction`; `fails closed on blank capability audit subject before request` |

**Reviewer question**
- 现在如果 reviewer 不读 adapter 源码，是否也能仅凭测试名判断：DID registration history 不等于 capability grant、blank subject 不得发请求、token-revoked semantics 不会误伤非 capability history？

---

## A4. `GET /query-normalized-audit-events?...`

| Layer | Truth-source |
|---|---|
| Client entry | `web4-frontend/lib/api-contract/client.ts#queryNormalizedAuditEvents` |
| Request helper | `client.ts#buildNormalizedAuditEventsQueryParams` |
| Request drift guard | `client.ts#NORMALIZED_AUDIT_EVENTS_QUERY_PARAM_KEYS` |
| Request schema | `web4-frontend/lib/api-contract/schemas.ts#normalizedAuditEventsQuerySchema` |
| Response schema | `schemas.ts#queryNormalizedAuditEventsResponseSchema` + `queryNormalizedAuditEventsPageSchema` + `normalizedAuditEventSchema` |
| Public types | `web4-frontend/lib/api-contract/types.ts#NormalizedAuditEventsQuery` + `QueryNormalizedAuditEventsResult` + `NormalizedAuditEvent` |
| Adapter entry | `web4-frontend/lib/api-contract/adapters.ts#adaptQueryNormalizedAuditEvents` |
| Primary conformance tests | `web4-frontend/tests/unit/normalized-audit-query-contract.test.ts`; `web4-frontend/tests/unit/api-client-retry.test.ts`; `web4-frontend/tests/unit/api-contract-adapters.test.ts`; `web4-frontend/tests/unit/dashboard-source-pagination.test.ts` |
| Request-side frozen checks | `freezes the schema key set to the expected day-1 query keys`; `serializes every schema-approved query key through the drift-guard helper`; `rejects unknown query fields before request construction`; `rejects invalid cursor values fail-closed`; `rejects invalid limit values fail-closed`; `omits absent optional fields from the serialized query string`; `serializes the currently supported scalar query keys with stable names`; `builds normalized audit query params`; `fails closed on malformed normalized audit query params`; `fails closed on unknown normalized audit query params`; `uses normalized audit endpoint` |
| Response-side frozen checks | `adapts canonical paginated normalized audit-events payload`; `fails closed when canonical normalized audit pagination reports hasMore without usable cursor`; `fails closed when canonical normalized audit pagination loops back to the requested cursor`; `fails closed on malformed canonical normalized audit-events items`; `fails closed on malformed canonical normalized audit-events envelope`; `fails closed on canonical normalized audit-event entries with unknown fields`; `fails closed on canonical normalized audit-events page nextCursor type mismatch`; `fails closed on canonical normalized audit-events page hasMore type mismatch`; `fails closed on canonical normalized audit-events page total non-integer`; `fails closed when canonical normalized audit-events page sets hasMore without nextCursor`; `adapts normalized audit-events fallback with eventType/objectId aliases`; `fails closed on fallback normalized audit-events entries with unknown fields` |
| Pagination/runtime frozen checks | `uses env-configured pagination limits for normalized audit events`; `falls back to defaults when env values are invalid`; `falls back to default pagination limit when env is zero`; `loads multiple normalized audit pages and merges into dashboard events`; `fails closed when normalized audit pagination cannot be loaded`; `fails closed when normalized audit pagination repeats a cursor`; `fails closed when normalized audit pagination declares more pages without a cursor`; `fails closed when normalized audit pagination exceeds the configured max pages` |

**Reviewer question**
- 如果 query schema、client serialization helper、adapter pagination normalization 三者有任意一处改动，本文件列出的四组测试里是否至少会有一组红线？

---

## A5. `GET /healthz`

| Layer | Truth-source |
|---|---|
| Product boundary | `TRNM_DAY1_PUBLIC_READ_CONTRACT_2026-04-03.md` / `TRNM_DAY1_PUBLIC_READ_CONTRACT_MATRIX_2026-04-03.md` |
| Backend truth-source | `trillionnium/crates/trnm-rpc/src/main.rs` |
| Current frontend dependency | 无 Day-1 frontend contract 依赖 |
| Current automated guard | 文档边界检查；尚无 Group A frontend unit test 直接覆盖 |

**Reviewer question**
- healthz 是否仍被明确表述成“运维探针”，没有被 README / runbook / frontend 误包装成 public data plane substitute？

---

# B. Current explicit drift tripwires

## B1. Compile-side tripwires
- `NORMALIZED_AUDIT_EVENTS_QUERY_PARAM_KEYS as const satisfies Record<keyof NormalizedAuditEventsQuery, string>`
  - 作用：schema/type 扩字段而 client drift 时，至少在 compile/test 层显式暴露。

## B2. Test-side tripwires
- `normalized-audit-query-contract.test.ts`
  - schema key set == client serialization key set
  - per-key serialization fixture check
  - wire key uniqueness
- `api-contract-adapters.test.ts`
  - 各 endpoint 的 canonical/rpc fallback/fail-closed 规则
- `api-client-retry.test.ts`
  - request-side validation + error taxonomy + retry semantics
- `dashboard-source-pagination.test.ts`
  - normalized audit pagination runtime behavior

## B3. Doc-side tripwires
- `TRNM_DAY1_PUBLIC_READ_CONTRACT_2026-04-03.md`
  - 写范围与边界
- `TRNM_DAY1_PUBLIC_READ_CONTRACT_MATRIX_2026-04-03.md`
  - 写 endpoint 最小 contract 与 error semantics
- `TRNM_QUERY_NORMALIZED_AUDIT_EVENTS_CONTRACT_TABLE_2026-04-03.md`
  - 单点写清 query / response / pagination

---

# C. Release review checklist (drift-oriented)

## C1. Endpoint contract drift
- [ ] `query-task` 的 canonical schema、rpc fallback、adapter tests 三者一致
- [ ] `query-events` 的 alias / M2V2 mapping / mixed-task-id fail-closed 三者一致
- [ ] `query-capability-audit` 的 subject normalization、registry/token distinction、canonical checkedAt 三者一致
- [ ] `query-normalized-audit-events` 的 query schema、serialization helper、adapter pagination 三者一致
- [ ] `healthz` 仍只被表述为 ops probe

## C2. Error vocabulary drift
- [ ] `BAD_REQUEST` / `NOT_FOUND` / `INVALID_PAYLOAD` / `TIMEOUT` / `ABORTED` / `NETWORK` / `UNKNOWN` 与 `HTTP_STATUS` fallback 没有被第二套词汇替代
- [ ] `web4-frontend/docs/api-contract.md`、Day-1 contract docs、tests 的错误语义一致

## C3. Scope drift
- [ ] block / tx / account 没被写成 Day-1 public promise
- [ ] durable explorer backend 没被当成已关闭 blocker
- [ ] historical read-model / archive replay guarantee 没被误写成已冻结
- [ ] healthz 没被当 public read plane substitute

## C4. Evidence drift
- [ ] 当前最小证据命令仍可通过
- [ ] 新增字段/alias/path 语义时，同步更新了至少一处 truth-source 文档 + 对应 unit test
- [ ] reviewer 不需要靠“读 adapter 源码猜行为”才能完成 Group A 审查

---

# D. Current open item

目前 Group A drift guard pack 仍有一个明确缺口：

- `GET /healthz` 目前主要由文档边界约束保护，尚没有纳入与其它四个 public read endpoint 同等级的 frontend conformance test pack。

这不阻止当前 Group A 审查，但它意味着：

> `healthz` 的 guard 目前更接近“文档红线”，而不是“测试红线”。

若后续要继续补齐，可在 GA-09 signoff pack 中把它明确标成 **doc-guarded only**，避免被误解成“已具备同等级自动化证据”。

---

# 一句话

> **GA-08 的价值，不是再写一份 contract，而是把“每个 Day-1 endpoint 到底由哪些 schema/type/adapter/test 在兜底”一次性摊平，防止 reviewer 靠记忆做审查。**
