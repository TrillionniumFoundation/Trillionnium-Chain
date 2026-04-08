# TRNM Group A Conformance Checklist (2026-04-03)

适用快照：`main@bb83dd6a3`

## 目的

本清单服务于 Rank 1 / Group A：
- **R1-01 — Day-1 Public Read Surface Freeze**
- **R1-02 — Query Schema / Error Contract Freeze**

目标不是继续讨论抽象方向，而是形成一套：

> **可以直接拿去对代码、测试、文档逐项打勾的实现 checklist。**

配套代码任务板：
- `TRNM_GROUPA_CONFORMANCE_CODE_TASKS_2026-04-03.md`

配套 drift guard pack：
- `TRNM_GROUPA_CONTRACT_DRIFT_GUARD_PACK_2026-04-03.md`

配套 signoff fixture pack：
- `TRNM_GROUPA_SIGNOFF_FIXTURE_PACK_2026-04-03.md`

---

# A. Truth-source 对齐

## A1. Day-1 contract 文档齐备
- [ ] `TRNM_DAY1_PUBLIC_READ_CONTRACT_2026-04-03.md` 仍与当前 `main` 对齐
- [ ] `TRNM_DAY1_PUBLIC_READ_CONTRACT_MATRIX_2026-04-03.md` 与代码接口一致
- [ ] `TRNM_RANK1_READ_SURFACE_TASK_BOARD_2026-04-03.md` 中 R1-01 / R1-02 未与 truth-source 矛盾

## A2. Out-of-scope 边界明确
- [ ] block/tx/account 没被误写成 Day-1 public promise
- [ ] durable explorer backend 没被误写成已关闭 blocker
- [ ] historical read-model 没被误写成已冻结
- [ ] `healthz` 仅被表述为运维探针，不被包装成产品读面

---

# B. Endpoint-by-endpoint 对齐

## B1. `GET /query-task/:taskId`
### Code surface
- [ ] `web4-frontend/lib/api-contract/client.ts` 有稳定 `queryTask()` 入口
- [ ] `web4-frontend/lib/api-contract/adapters.ts` 能把 canonical payload 归一化成 task contract
- [ ] canonical payload 出现未知字段时 fail-closed
- [ ] RPC fallback payload 仍可稳定归一化

### Tests
- [ ] adapter test 覆盖 canonical success
- [ ] adapter test 覆盖 canonical unknown-field fail-closed
- [ ] adapter test 覆盖 rpc fallback success

## B2. `GET /query-events/:taskId`
### Code surface
- [ ] `queryEvents()` 入口稳定
- [ ] `limit` 语义有明确处理
- [ ] canonical events payload 可归一化
- [ ] rpc array payload 可归一化
- [ ] M2V2 frozen resolution code 映射规则稳定
- [ ] `resolutionCode` / `resolution_code` alias 行为一致

### Tests
- [ ] canonical event success
- [ ] rpc event success
- [ ] M2V2 fail-closed mapping
- [ ] casing / whitespace normalization
- [ ] noise / empty alias 不误触发 normalization

## B3. `GET /query-capability-audit/:subjectOrToken`
### Code surface
- [ ] `queryCapabilityAudit()` 入口稳定
- [ ] registry / token history 能区分 capability issuance 与 DID registration history
- [ ] subject / token path 参数缺失或错误时 fail-closed

### Tests
- [ ] canonical success path
- [ ] rpc fallback success path
- [ ] DID registration history ≠ capability grant
- [ ] missing/not found handling consistent

## B4. `GET /query-normalized-audit-events?...`
### Code surface
- [ ] `queryNormalizedAuditEvents()` 在发请求前先走 schema parse
- [ ] schema 外 query 字段 fail-closed
- [ ] adapter 接收 payload + parsedQuery 做归一化
- [ ] pagination / next page 语义不隐式漂移

### Tests
- [ ] valid query success
- [ ] invalid query fail-closed
- [ ] pagination semantics stable
- [ ] filter semantics stable
- [ ] adapter 不吞掉 malformed payload

## B5. `GET /healthz`
### Code surface
- [ ] RPC health endpoint 最小字段稳定：`ok/service/ts_unix_ms/version`
- [ ] 无额外产品语义绑定到 healthz

### Tests / docs
- [ ] 文档明确写明 healthz 是运维探针
- [ ] 没有任何地方把 healthz 当 public data plane substitute

---

# C. Error contract freeze

## C1. Frontend client 错误分类
- [ ] `BAD_REQUEST`
- [ ] `NOT_FOUND`
- [ ] `HTTP_STATUS`
- [ ] `INVALID_PAYLOAD`
- [ ] `TIMEOUT`
- [ ] `ABORTED`
- [ ] `NETWORK`
- [ ] `UNKNOWN`

## C2. 行为语义一致
- [ ] `BAD_REQUEST` = 修正输入，不猜测性重试
- [ ] `NOT_FOUND` = 资源不存在，不伪装空成功
- [ ] `HTTP_STATUS` = 非 400/404 的其余非 2xx fallback，并保留 `status`
- [ ] `INVALID_PAYLOAD` = fail-closed，不吞错误
- [ ] `TIMEOUT` / `NETWORK` = retryable
- [ ] `ABORTED` = non-retryable caller action
- [ ] `UNKNOWN` = 不宣称成功

## C3. 文档对齐
- [ ] contract 文档与 client 行为一致
- [ ] runbook / frontend docs 不使用另一套错误词汇
- [ ] future explorer/read-service draft 不引入第二套 taxonomy

---

# D. Query schema freeze

## D1. Schema ↔ types ↔ adapters 一致
- [ ] `schemas.ts` 定义的 query 输入与 `types.ts` 一致
- [ ] `client.ts` 只发送 schema 接受的字段
- [ ] `adapters.ts` 不依赖 undocumented 字段

## D2. query-normalized-audit-events 表格化
- [ ] 每个允许 query 字段有名称、类型、含义、默认行为、fail-closed 规则
- [ ] pagination 字段表格化
- [ ] filter 组合规则表格化
- [ ] unknown fields handling 写清楚

参考 truth-source：
- `TRNM_QUERY_NORMALIZED_AUDIT_EVENTS_CONTRACT_TABLE_2026-04-03.md`
- `TRNM_GROUPA_CONTRACT_DRIFT_GUARD_PACK_2026-04-03.md`

## D3. drift guard
- [ ] 至少有一处测试在 schema 改动时会显式失败
- [ ] adapter / client / truth-source 之间有清晰同步点

---

# E. Release signoff 前检查

## E1. 文档一致性
- [ ] `README` 不超前于 contract freeze
- [ ] `web4-frontend` docs 不超前于 contract freeze
- [ ] explorer scaffold 文档仍保留“不是 durable explorer backend”口径

## E2. 实现一致性
- [ ] frontend client / schema / types / adapters 已对齐
- [ ] RPC 路径与 contract 命名一致
- [ ] 没有额外 undocumented public query 面被前端依赖

## E3. Evidence
- [ ] 至少一轮 adapter/unit tests 通过
- [ ] 至少一轮 query schema validation tests 通过
- [ ] out-of-scope 项已写清楚
- [ ] 一页 signoff note 可以明确回答“Day-1 到底承诺什么”

---

# 最小交付顺序

如果现在就要开工，建议顺序是：

1. **补 query-normalized-audit-events 的字段表**
2. **补 error taxonomy 一致性页**
3. **补 adapter/client conformance tests 缺口**
4. **做一页 Day-1 signoff note**

---

# 一句话

> **Group A 的关键不是“再发明一个 API”，而是把当前已经存在的最小 public read surface 说清楚、测清楚、冻下来。**
