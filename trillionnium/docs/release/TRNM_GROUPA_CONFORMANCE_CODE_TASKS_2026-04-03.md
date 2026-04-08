# TRNM Group A Conformance Code Tasks (2026-04-03)

适用快照：`main@bb83dd6a3`

## 目的

本文件把 `TRNM_GROUPA_CONFORMANCE_CHECKLIST_2026-04-03.md` 继续往下拆成：

> **可以直接分配给工程实现的代码任务。**

拆分原则：
- 每个任务都尽量能落到 **具体文件**；
- 每个任务都要说明 **要补哪类测试**；
- 每个任务都带 **完成定义（DoD）**；
- 优先修 Group A 的 contract freeze / conformance，不扩 scope 到 durable indexer / explorer backend。

---

## 任务分组

### Group A1 — Adapter conformance
- GA-01 query-task contract
- GA-02 query-events contract
- GA-03 capability-audit contract
- GA-04 normalized-audit response contract

### Group A2 — Client / schema conformance
- GA-05 normalized-audit query schema enforcement
- GA-06 error taxonomy + retry semantics
- GA-07 request serialization drift guard

### Group A3 — Freeze evidence support
- GA-08 contract drift guard
- GA-09 Group A signoff fixture pack

---

# Group A1 — Adapter conformance

## GA-01 — `query-task` adapter fail-closed coverage

**目标**
- 把 `GET /query-task/:taskId` 的 canonical payload / fallback payload 行为冻结成测试，而不是继续靠适配器隐式容忍。

**主要文件**
- `web4-frontend/lib/api-contract/adapters.ts`
- `web4-frontend/tests/unit/api-contract-adapters.test.ts`

**需要补的测试**
- canonical task payload 成功归一化
- canonical task payload 出现未知字段时 fail-closed
- rpc fallback task payload 成功归一化
- 非法 `status` / 缺失 `id` / 缺失 `taskId` 不得伪装成功

**完成定义（DoD）**
- 至少新增 3~4 条 task-specific adapter tests
- adapter 不再通过“兜底猜测”吞掉 malformed task payload
- `TRNM_DAY1_PUBLIC_READ_CONTRACT_MATRIX_2026-04-03.md` 中 query-task 项能直接引用这些测试

**2026-04-03 实现进展**
- `web4-frontend/tests/unit/api-contract-adapters.test.ts` 已补齐 `query-task` fail-closed coverage：
  - canonical task payload invalid status -> fail-closed
  - canonical task payload missing `id` -> fail-closed
  - rpc fallback payload missing `task_id` -> fail-closed
  - rpc fallback payload invalid status -> fail-closed
- 既有 coverage 继续保留并回归通过：
  - canonical task payload success
  - canonical unknown-field fail-closed
  - rpc fallback success
- 已验证通过：
  - `npx vitest run tests/unit/api-contract-adapters.test.ts tests/unit/api-client-retry.test.ts tests/unit/normalized-audit-query-contract.test.ts tests/unit/dashboard-source-pagination.test.ts`
  - 结果：`4 files passed / 104 tests passed`

---

## GA-02 — `query-events` resolution mapping freeze

**目标**
- 把 `query-events` 的 alias / casing / M2V2 resolution mapping 冻成稳定 contract。

**主要文件**
- `web4-frontend/lib/api-contract/adapters.ts`
- `web4-frontend/tests/unit/api-contract-adapters.test.ts`

**需要补的测试**
- canonical event payload success
- rpc array payload success
- `resolutionCode` / `resolution_code` alias 行为一致
- frozen M2V2 resolution code → error-level signal 的 fail-closed 行为
- casing noise / whitespace / empty alias 不得错误触发 normalization

**完成定义（DoD）**
- 事件 adapter 的关键 alias 行为有显式测试
- “error-level on frozen codes” 成为可回归检查，不再只是文档承诺

**2026-04-03 实现进展**
- `web4-frontend/tests/unit/api-contract-adapters.test.ts` 已补齐/冻结：
  - canonical `resolutionCode` success path
  - `resolutionCode` / `resolution_code` alias 一致性
  - camelCase alias 为空噪声时回退到 snake_case alias
  - 双 alias 同时存在时优先采用 canonical `resolutionCode`
  - frozen M2V2 resolution code -> `level=error` / `m2v2ErrorCode` fail-closed mapping
  - non-frozen canonical resolution code 不得误触发 error-level mapping
- `web4-frontend/lib/api-contract/adapters.ts` 已补 canonical alias 归一化 helper，使 alias fallback/preference 成为显式实现而非隐式副产物。
- 已验证通过：
  - `npx vitest run tests/unit/api-contract-adapters.test.ts tests/unit/api-client-retry.test.ts tests/unit/normalized-audit-query-contract.test.ts tests/unit/dashboard-source-pagination.test.ts`
  - 结果：`4 files passed / 95 tests passed`

---

## GA-03 — `query-capability-audit` subject/token semantics freeze

**目标**
- 冻结 capability audit 的最小语义，尤其是：
  - DID registration history ≠ capability grant
  - missing subject/token 不得被吞掉

**主要文件**
- `web4-frontend/lib/api-contract/adapters.ts`
- `web4-frontend/tests/unit/api-contract-adapters.test.ts`

**需要补的测试**
- canonical capability audit success
- rpc fallback capability audit success
- registry history / token history distinction
- DID registration history must not be treated as granted capability
- subject/token missing or malformed → fail-closed

**完成定义（DoD）**
- capability audit 不再依赖阅读 adapter 源码才能理解边界
- Group A 文档里的 capability semantics 都能被测试映射到

**2026-04-03 实现进展**
- `web4-frontend/lib/api-contract/client.ts` 已补 `normalizeRequiredPathParam()`，修复 `queryCapabilityAudit()` 之前依赖未定义 helper 的 latent bug。
- `web4-frontend/tests/unit/api-client-retry.test.ts` 已补：
  - capability audit subject trim + path encoding
  - blank subject request-side fail-closed（不得发请求）
- `web4-frontend/tests/unit/api-contract-adapters.test.ts` 已补：
  - canonical capability audit success（ISO `checkedAt`）
  - canonical capability audit unknown-field fail-closed
  - rpc capability audit token subject missing -> fail-closed
- 既有能力语义测试继续保留并回归通过：
  - DID registration history ≠ capability grant
  - token revoked / non-capability history distinction
  - blank `revoked_at` 不得伪造 token-revoked semantics
- 已验证通过：
  - `npx vitest run tests/unit/api-client-retry.test.ts tests/unit/api-contract-adapters.test.ts tests/unit/normalized-audit-query-contract.test.ts tests/unit/dashboard-source-pagination.test.ts`
  - 结果：`4 files passed / 100 tests passed`

---

## GA-04 — `query-normalized-audit-events` response contract freeze

**目标**
- 冻结 normalized audit response 侧 contract：items / nextCursor / hasMore / total / event shape。

**主要文件**
- `web4-frontend/lib/api-contract/adapters.ts`
- `web4-frontend/tests/unit/api-contract-adapters.test.ts`
- `web4-frontend/tests/unit/dashboard-source-pagination.test.ts`

**需要补的测试**
- valid `items[]` payload success
- malformed `items[]` fail-closed
- `nextCursor` type mismatch fail-closed
- `hasMore` type mismatch fail-closed
- `total` non-integer fail-closed
- adapter 必须使用 payload + parsedQuery 共同归一化，而不是忽略 request 语义

**完成定义（DoD）**
- `TRNM_QUERY_NORMALIZED_AUDIT_EVENTS_CONTRACT_TABLE_2026-04-03.md` 的 response/page 规则有直接测试映射
- pagination 响应不再靠前端页面层隐式容错

**2026-04-03 实现进展**
- `adaptQueryNormalizedAuditEvents(payload, parsedQuery?)` 已开始使用 `payload + parsedQuery` 共同归一化分页语义。
- 已新增/补齐 normalized audit response contract 测试：
  - malformed canonical items fail-closed
  - `nextCursor` type mismatch fail-closed
  - `hasMore` type mismatch fail-closed
  - `total` non-integer fail-closed
  - `hasMore=true + blank nextCursor` → adapter fail-closed 为 `hasMore=false`
  - `hasMore=true + nextCursor == requested cursor` → adapter fail-closed 为 `hasMore=false`
- 为通过 dashboard pagination 回归，已修复 `web4-frontend/lib/dashboard/source.ts` 中的 `seenEventKeys` 缺失定义。
- 已验证通过：
  - `npx vitest run tests/unit/api-contract-adapters.test.ts tests/unit/dashboard-source-pagination.test.ts tests/unit/normalized-audit-query-contract.test.ts tests/unit/api-client-retry.test.ts`
  - 结果：`4 files passed / 88 tests passed`

---

# Group A2 — Client / schema conformance

## GA-05 — `normalizedAuditEventsQuerySchema` request enforcement

**目标**
- 把 query-normalized-audit-events 的 request 侧 fail-closed 规则变成代码级保证。

**主要文件**
- `web4-frontend/lib/api-contract/schemas.ts`
- `web4-frontend/lib/api-contract/client.ts`
- `web4-frontend/tests/unit/api-client-retry.test.ts`
- `web4-frontend/tests/unit/dashboard-source-pagination.test.ts`

**需要补的测试**
- schema 外字段必须在 request 发出前直接失败
- `cursor` 非法值 fail-closed
- `limit` 非正整数 / 非法值 fail-closed
- 未提供的可选字段不得编码为空字符串进 query string
- schema 接受字段与 `params.set(...)` 实际序列化键一致

**完成定义（DoD）**
- request-side fail-closed 规则有显式测试，不再只写在文档里
- `TRNM_QUERY_NORMALIZED_AUDIT_EVENTS_CONTRACT_TABLE_2026-04-03.md` 的 query matrix 可逐条映射到测试

**2026-04-03 实现进展**
- 已新增 request-side helper：`buildNormalizedAuditEventsQueryParams()`
- 已新增 drift guard 常量：`NORMALIZED_AUDIT_EVENTS_QUERY_PARAM_KEYS`
- 已新增专项测试：`web4-frontend/tests/unit/normalized-audit-query-contract.test.ts`
- 已验证通过：
  - `npx vitest run tests/unit/normalized-audit-query-contract.test.ts tests/unit/api-client-retry.test.ts`
  - 结果：`2 files passed / 28 tests passed`

---

## GA-06 — Error taxonomy / retry semantics freeze

**目标**
- 冻结 Group A 当前最小错误语义：
  - `BAD_REQUEST`
  - `NOT_FOUND`
  - `INVALID_PAYLOAD`
  - `TIMEOUT`
  - `ABORTED`
  - `NETWORK`
  - `UNKNOWN`

**主要文件**
- `web4-frontend/lib/api-contract/client.ts`
- `web4-frontend/lib/api-contract/errors.ts`
- `web4-frontend/lib/api-contract/retry.ts`
- `web4-frontend/tests/unit/api-client-retry.test.ts`

**需要补的测试**
- 400 → bad request mapping
- 404 → not found mapping
- malformed payload → invalid payload mapping
- timeout / abort / network 区分
- retryability boundaries：
  - timeout/network 可重试
  - aborted 不重试
  - invalid payload 不重试

**完成定义（DoD）**
- 错误分类不再需要靠 client 实现细节“推断”
- 文档中的 error taxonomy 与 test behavior 对齐

**2026-04-03 实现进展**
- `web4-frontend/lib/api-contract/errors.ts` 已新增 HTTP status → error code 分类：
  - `400 -> BAD_REQUEST`
  - `404 -> NOT_FOUND`
  - 其余非 2xx -> `HTTP_STATUS` fallback
- `web4-frontend/lib/api-contract/client.ts` 已改为按上述分类抛错，并收紧 retryability：
  - `BAD_REQUEST` / `NOT_FOUND` 不重试
  - `HTTP_STATUS` 仅在 retryable status 集合内重试
- `web4-frontend/tests/unit/api-client-retry.test.ts` 已补：
  - `400 -> BAD_REQUEST`（non-retryable）
  - `404 -> NOT_FOUND`（non-retryable）
  - non-JSON backend payload -> `INVALID_PAYLOAD`
  - contract-invalid JSON payload -> `INVALID_PAYLOAD`
- 已验证通过：
  - `npx vitest run tests/unit/api-client-retry.test.ts tests/unit/normalized-audit-query-contract.test.ts tests/unit/api-contract-adapters.test.ts tests/unit/dashboard-source-pagination.test.ts`
  - 结果：`4 files passed / 92 tests passed`

---

## GA-07 — Request serialization drift guard

**目标**
- 防止 schema / client / adapter 三者分叉。

**主要文件**
- `web4-frontend/lib/api-contract/schemas.ts`
- `web4-frontend/lib/api-contract/client.ts`
- `web4-frontend/tests/unit/api-client-retry.test.ts`

**需要补的测试/检查**
- normalized audit query schema 中允许的 key 与 client 序列化的 key 一致
- 若新增 query key，但 client 未 `params.set(...)`，测试应失败或显式提醒
- 若 client 序列化了 schema 未允许的 key，测试应失败

**完成定义（DoD）**
- 至少有 1 个 drift guard test 或 helper
- 后续扩 query 字段时，不会只改 schema 或只改 client 其中一侧

**2026-04-03 实现进展**
- `web4-frontend/lib/api-contract/client.ts`
  - `NORMALIZED_AUDIT_EVENTS_QUERY_PARAM_KEYS` 已增加 compile-side drift guard：
    - `as const satisfies Record<keyof NormalizedAuditEventsQuery, string>`
- `web4-frontend/tests/unit/normalized-audit-query-contract.test.ts` 已补 test-side drift guard：
  - schema key set == client serialization key set
  - wire key set freeze + unique-key check
  - per-key serialization fixture test（每个 schema-approved key 都必须经 helper 实际写入 query string）
- 这意味着：
  - schema 新增 key 但 client 常量未同步 -> compile/test 会显式失败
  - client 常量新增 key 但 helper 未真正序列化 -> per-key serialization test 会失败
- 已验证通过：
  - `npx vitest run tests/unit/normalized-audit-query-contract.test.ts tests/unit/api-client-retry.test.ts tests/unit/api-contract-adapters.test.ts tests/unit/dashboard-source-pagination.test.ts`
  - 结果：`4 files passed / 105 tests passed`

---

# Group A3 — Freeze evidence support

## GA-08 — Contract drift guard pack

**目标**
- 为 Group A 提供一组“文档 ↔ schema ↔ types ↔ adapter”漂移检测点。

**主要文件**
- `trillionnium/docs/release/TRNM_DAY1_PUBLIC_READ_CONTRACT_2026-04-03.md`
- `trillionnium/docs/release/TRNM_DAY1_PUBLIC_READ_CONTRACT_MATRIX_2026-04-03.md`
- `trillionnium/docs/release/TRNM_QUERY_NORMALIZED_AUDIT_EVENTS_CONTRACT_TABLE_2026-04-03.md`
- `web4-frontend/lib/api-contract/*`
- `web4-frontend/tests/unit/*`

**需要补的内容**
- 一页 mapping note：每个 endpoint 对应哪些 schema/type/adapter/test
- 一份 release review checklist，检查 out-of-scope 项有没有被写超前

**完成定义（DoD）**
- Group A review 时，不需要靠人工全量读源码才能判断是否 drift

**2026-04-03 实现进展**
- 已新增：`trillionnium/docs/release/TRNM_GROUPA_CONTRACT_DRIFT_GUARD_PACK_2026-04-03.md`
- 文档内容已覆盖：
  - 每个 Day-1 endpoint 对应的 client / schema / types / adapter / tests mapping
  - 当前 compile-side / test-side / doc-side drift tripwires
  - 一份 drift-oriented release review checklist
  - 当前唯一显式 open item：`healthz` 仍主要由 doc guard 保护，尚未进入同等级 frontend conformance pack
- 该文档已挂回 `TRNM_GROUPA_CONFORMANCE_CHECKLIST_2026-04-03.md` 作为 review 入口之一。

---

## GA-09 — Group A signoff fixture pack

**目标**
- 为 Day-1 public read contract 准备一个最小 signoff 包。

**主要文件**
- `web4-frontend/tests/unit/api-contract-adapters.test.ts`
- `web4-frontend/tests/unit/api-client-retry.test.ts`
- `web4-frontend/tests/unit/dashboard-source-pagination.test.ts`
- `trillionnium/docs/release/TRNM_DAY1_PUBLIC_READ_CONTRACT_2026-04-03.md`

**需要补的内容**
- 一份列明：
  - 哪些 test 对应哪个 endpoint contract
  - 哪些 fail-closed 行为已覆盖
  - 哪些仍是 open item

**完成定义（DoD）**
- Group A 可产出一页 signoff note
- Rank 1 / Group A 不再只是“有很多文档”，而是有可引用的最小 evidence packet

**2026-04-03 实现进展**
- 已新增：`trillionnium/docs/release/TRNM_GROUPA_SIGNOFF_FIXTURE_PACK_2026-04-03.md`
- 文档已明确：
  - 哪些 test 对应哪个 Day-1 endpoint contract
  - 哪些 fail-closed 行为已有自动化证据
  - 哪些仍是 open item（尤其是 `healthz = DOC-GUARDED ONLY`）
  - 当前最小证据命令与结果：`4 files passed / 105 tests passed`
- 该文档已挂回 `TRNM_GROUPA_CONFORMANCE_CHECKLIST_2026-04-03.md`，可直接作为 Group A signoff/review 引用页。

---

# 建议的最小实现顺序

如果现在就要开始写代码，我建议顺序是：

1. **GA-05** request-side schema enforcement
2. **GA-04** normalized-audit response contract
3. **GA-06** error taxonomy / retry semantics
4. **GA-02** query-events resolution mapping
5. **GA-03** capability-audit distinction
6. **GA-01** query-task fail-closed coverage
7. **GA-07** serialization drift guard
8. **GA-08 / GA-09** evidence support

这样排的理由是：
- 先把最容易漂的 request/response 规则钉死；
- 再去补 endpoint-specific adapter hardening；
- 最后再把 evidence pack 整理出来。

---

# 一句话

> **Group A 现在已经可以直接进入实现阶段了。**
> **最有价值的下一步不是继续写总文档，而是按 GA-05 → GA-04 → GA-06 的顺序补 request/response/error conformance tests。**
