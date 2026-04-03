# TRNM Query Normalized Audit Events Contract Table (2026-04-03)

适用快照：`main@bb83dd6a3`

## 用途

本文件把 `GET /query-normalized-audit-events?...` 的 **query 字段、分页字段、response shape 与 fail-closed 规则** 单独抽成表格，作为 Group A 的实现/测试基准。

它补充：
- `TRNM_DAY1_PUBLIC_READ_CONTRACT_2026-04-03.md`
- `TRNM_DAY1_PUBLIC_READ_CONTRACT_MATRIX_2026-04-03.md`
- `TRNM_GROUPA_CONFORMANCE_CHECKLIST_2026-04-03.md`

---

## Endpoint

- Method: `GET`
- Path: `/query-normalized-audit-events`
- Client entry: `web4-frontend/lib/api-contract/client.ts#queryNormalizedAuditEvents`
- Adapter entry: `web4-frontend/lib/api-contract/adapters.ts#adaptQueryNormalizedAuditEvents`

Client-side request rule:
- request 在发出前必须先经 `normalizedAuditEventsQuerySchema.parse(...)`
- 只有 schema 接受且值存在的字段才会被编码进 URL query string
- 未提供的可选字段必须被省略，而不是发送空字符串占位

---

## Query field matrix

| Field | Type | Required | Constraints | 当前语义 | URL 编码行为 | Fail-closed rule |
|---|---|---|---|---|---|---|
| `source` | `string` | No | trimmed, min 1 | 按事件来源过滤；仅接受 schema 明确允许的来源值。 | 有值才写入 query string | 非法类型或 schema 外值必须直接报错，不得隐式忽略。 |
| `eventType` | `string` | No | trimmed, min 1 | 按标准化事件类型过滤。 | 有值才写入 query string | 非法类型或 schema 外值必须直接报错，不得隐式忽略。 |
| `limit` | `number` | No | integer, positive | 每页返回条数上限。 | 有值才写入 query string | 非正整数或超出 schema 上限时必须直接报错，不得静默截断到任意默认值。 |
| `cursor` | `string` | No | trimmed, min 1 | 分页游标；仅接受非空字符串。 | 有值才写入 query string | 空字符串、非法类型或 schema 不接受的值必须直接报错，不得伪装成第一页。 |

### 当前 query key 序列化顺序（client 实现）

当前 `queryNormalizedAuditEvents()` 中，query string 只会按以下 keys 写入：

- `source`
- `eventType`
- `cursor`
- `limit`

这意味着：
- schema 中若未来新增字段，但 client 尚未显式 `params.set(...)`，则**不能**自动算作 Day-1 public promise。

---

## Response page matrix

| Field | Type | Required | Constraints | 当前语义 | Fail-closed rule |
|---|---|---|---|---|---|
| `events` | `array` | Yes | — | 分页响应字段。 | 字段不符合 schema 时必须 fail-closed。 |
| `nextCursor` | `string` | No | min 1 | 下一页游标；不存在时表示无后续游标。 | 无效 cursor 不得被自动修正；缺失表示无下一页。 |
| `hasMore` | `boolean` | No | — | 是否存在后续页。 | 若类型不是 boolean，必须 fail-closed。 |
| `total` | `number` | No | integer | 当前响应中可报告的总量/计数。 | 若类型不是整数，必须 fail-closed。 |

---

## Normalized event minimum shape

| Field | Type | Required | Constraints | 说明 |
|---|---|---|---|---|
| `source` | `string` | Yes | min 1 | 按事件来源过滤；仅接受 schema 明确允许的来源值。 |
| `event_type` | `string` | Yes | min 1 | normalized audit event 字段。 |
| `actor` | `string` | No | min 1 | 按 actor 过滤。 |
| `object_id` | `string` | No | — | normalized audit event 字段。 |
| `related_id` | `string` | No | — | normalized audit event 字段。 |
| `amount` | `number` | No | — | normalized audit event 字段。 |
| `reason` | `string` | No | — | 标准化 reason。 |
| `note` | `string` | No | — | 附加说明。 |
| `checkedAt` | `string` | No | — | normalized audit event 字段。 |
| `timestamp` | `string` | No | — | normalized audit event 字段。 |
| `subject` | `string` | No | — | normalized audit event 字段。 |

---

## Pagination semantics

Day-1 只冻结当前代码已经表现出来的最小分页语义：

1. `cursor` 是可选输入；缺失时表示从默认起始窗口查询。
2. `limit` 是可选输入；若提供，必须先过 schema 校验。
3. `nextCursor` 缺失，表示当前响应未显式给出下一页游标。
4. `hasMore` 是显式布尔值；不存在时不允许由调用方自行猜测。
5. `total` 若存在，必须视为当前 response contract 的一部分；若类型不合法，adapter 必须 fail-closed。

---

## Fail-closed rules

### Request side
- schema parse 失败时，请求不得发出。
- schema 外字段不得被静默透传到 backend。
- 空字符串、非法类型、非法数字边界不得被自动“修正成看起来能跑”。

### Response side
- `items` 不合法时，adapter 必须直接报 `INVALID_PAYLOAD` 风格错误。
- page-level 字段（`nextCursor` / `hasMore` / `total`）类型不符时，不得降级成部分成功。
- adapter 必须使用 **payload + parsedQuery** 共同归一化，而不是忽略请求语义。

---

## Out of scope

当前本表不冻结：
- future filter keys
- archive / replay-backed historical guarantees
- explorer backend lag / freshness SLO
- block / tx / account read query integration

---

## Implementation notes for Group A

- 先让本表与 `schemas.ts` / `types.ts` / `client.ts` / `adapters.ts` 一致。
- 再据此补 conformance tests，而不是反过来让 tests 自己发明 contract。
- 若未来 query 字段扩展，必须先更新本表，再更新 schema/client/adapter/tests。
