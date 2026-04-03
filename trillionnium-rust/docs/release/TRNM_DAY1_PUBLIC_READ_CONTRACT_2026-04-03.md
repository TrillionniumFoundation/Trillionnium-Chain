# TRNM Day-1 Public Read Contract (2026-04-03)

适用快照：`main@bb83dd6a3`

## 文档目的

本文件是 **Rank 1 / Group A（R1-01 + R1-02）** 的 truth-source 候选稿，回答的问题是：

> **当前 TRNM Day-1 可以对外冻结哪些 public read endpoints、它们的参数/错误语义/边界是什么、哪些内容明确不在 Day-1 freeze 范围内。**

本文件不等于 durable indexer / explorer backend 已关闭。

相反，它的作用是：

- 先冻结 **Day-1 minimum public read surface**；
- 再为后续 durable indexer / historical read-model / explorer backend 提供稳定 contract；
- 避免 frontend、RPC、runbook 各说各话。

---

## Truth-source boundary

引用本文件时，必须同时参考：

- `RELEASE_READINESS.md`
- `trillionnium-rust/docs/release/TRNM_RANK1_READ_SURFACE_TASK_BOARD_2026-04-03.md`
- `trillionnium-rust/docs/runbooks/explorer-service-scaffold.md`
- `web4-frontend/lib/api-contract/client.ts`
- `web4-frontend/lib/api-contract/schemas.ts`
- `web4-frontend/lib/api-contract/types.ts`
- `web4-frontend/lib/api-contract/adapters.ts`
- `trillionnium-rust/crates/trnm-rpc/src/main.rs`

---

## 当前结论

当前代码基础上，能够被比较可信地冻结为 **Day-1 public read surface** 的，不应贪多，而应只包含：

1. `GET /query-task/:taskId`
2. `GET /query-events/:taskId`
3. `GET /query-capability-audit/:subjectOrToken`
4. `GET /query-normalized-audit-events?...`

以及一个**运维用途**的：

5. `GET /healthz` / health probe path

注意：

> **block / tx / account public query 目前不应被写进 Day-1 freeze。**

理由很直接：
- 仓内已有 query / adapter / frontend contract 主要围绕 task / events / capability / normalized audit；
- 当前 durable indexer / historical read-model / public explorer backend 仍未闭环；
- 如果今天把 block / tx / account 拉进 contract freeze，会把文档写得比实际系统更超前。

---

# Part I — Day-1 surface 范围

## In scope

### 1) `GET /query-task/:taskId`

**用途**
- 按 task id 查询单个 task 的最小只读状态面。

**当前代码形态**
- frontend client 通过 `queryTask(taskId)` 访问
- frontend adapter 允许两类输入：
  - canonical payload
  - rpc-derived fallback payload

**冻结内容**
- path parameter `taskId` 必须为任务 ID
- 成功返回单个 task 结果
- task 结果需要至少可归一化到：
  - `id`
  - `name`
  - `status`
  - `owner`
  - `createdAt`
  - `metadata`

**允许的 backend 实现自由度**
- backend 内部可来源于 node events / adapter records / future indexer
- 但外部响应的 schema / 状态枚举归一化语义必须稳定

---

### 2) `GET /query-events/:taskId`

**用途**
- 查询 task 相关事件序列。

**当前代码形态**
- frontend client 通过 `queryEvents(taskId)` 访问
- RPC 已支持 `limit` 解析
- adapter 已对 canonical / rpc-array payload 做统一归一化
- event level / resolution code 有明确 fail-closed 归一化逻辑

**冻结内容**
- path parameter `taskId`
- optional `limit`
- 返回结果必须能稳定归一化为：
  - `taskId`
  - `events[]`
- 每个 event 至少有：
  - `id`
  - `taskId`
  - `type`
  - `level`
  - `timestamp`
  - `payload`

**特殊冻结语义**
- frozen M2V2 resolution code 必须被 fail-closed 地映射到 error-level signal
- `resolutionCode` / `resolution_code` 等 alias 归一化行为必须稳定

---

### 3) `GET /query-capability-audit/:subjectOrToken`

**用途**
- 查询 capability 审计状态。

**当前代码形态**
- frontend client 通过 `queryCapabilityAudit(subjectOrToken)` 访问
- backend path 已从 target/path suffix 解析 subject or token
- frontend adapter 已对 registry-derived 历史与 capability issuance 做 fail-closed 区分

**冻结内容**
- path parameter 为 `subjectOrToken`
- 成功结果必须可归一化为：
  - `subject`
  - `audits[]`
- 每条 audit 至少有：
  - `subject`
  - `capability`
  - `granted`
  - `reason`
  - `checkedAt`

**特殊冻结语义**
- DID registration history 不得被误判为 capability granted
- capability issuance / revocation / absence 的语义必须可区分

---

### 4) `GET /query-normalized-audit-events?...`

**用途**
- 查询统一后的 normalized audit events。

**当前代码形态**
- frontend client 通过 `queryNormalizedAuditEvents(query)` 访问
- query 在 client 侧先过 `normalizedAuditEventsQuerySchema`
- adapter 接收 payload + parsedQuery 共同归一化

**冻结内容**
- query object 必须由 frontend schema 验证后再发起请求
- 返回结果必须可归一化为：
  - `events[]`
  - `pagination/nextPage`（如存在）
  - 与 query 语义一致的 filtering window

**当前应冻结的 query 维度**
只冻结已在 schema / adapter 中真实存在的维度，不把未来想要的筛选器提前写进 contract。

最小原则：
- 哪些筛选器当前 schema 接受，就冻结哪些；
- schema 未接受的，不写成 Day-1 promise。

**特殊冻结语义**
- query 参数必须 fail-closed：不合法 query 直接报错，不做隐式降级猜测
- pagination / watermark / filtering 行为必须有明确稳定语义

---

### 5) `GET /healthz`（运维附属，不计入产品读面）

**用途**
- 运维探针，不属于产品级 public data plane。

**当前代码形态**
- RPC 已返回：
  - `ok`
  - `service`
  - `ts_unix_ms`
  - `version`

**冻结内容**
- 只冻结为 health probe contract
- 不把它当成 explorer/indexer/read surface blocker 已关闭的证据

---

## Explicitly out of scope for Day-1 freeze

下面这些当前**不应**写进 Day-1 public read contract：

1. `block query`
2. `tx query`
3. `account query` 的对外 public freeze
4. archive / replay-backed historical explorer query
5. durable explorer backend SLO
6. index lag / ingestion checkpoint public contract

这些内容不是永远不做，而是：

> **在 current main 上，它们还没有足够稳定/闭环到可冻结为 Day-1 public promise。**

---

# Part II — Error taxonomy（Day-1 候选冻结）

基于当前 client / RPC 实现，建议先冻结下面这组最小错误语义：

## HTTP layer
- `400 BAD_REQUEST`
  - 非法 path 参数
  - 非法 query 参数
  - 缺失 subject/token
- `404 NOT_FOUND`
  - task 不存在
  - token/subject 不存在
  - resource 不存在
- `200 OK`
  - 合法请求，返回 payload

## Frontend/client semantic layer
前端 client 当前已显式区分：
- `HTTP_STATUS`
- `INVALID_PAYLOAD`
- `TIMEOUT`
- `ABORTED`
- `NETWORK`
- `UNKNOWN`

建议 Day-1 freeze 的含义是：

### `BAD_REQUEST`
- 调用方输入无效
- 不可重试（除非修正输入）

### `NOT_FOUND`
- 资源不存在
- 不可因为网络策略自动重试成别的资源

### `INVALID_PAYLOAD`
- backend 返回了不符合 public contract 的 payload
- 这是 fail-closed error，不允许 adapter 猜测修复成“看起来能用”

### `TIMEOUT`
- 请求超时
- client 可重试

### `ABORTED`
- 调用方主动取消
- 不重试

### `NETWORK`
- 网络层失败
- 可重试

### `UNKNOWN`
- 未知错误
- 默认不声称成功，也不做隐式语义转换

---

# Part III — Pagination / filtering / compatibility rules

## Pagination
Day-1 只冻结已真实存在并可证明的 pagination 行为。

尤其是 `query-normalized-audit-events`：
- query schema 中存在的分页字段才可承诺
- page/window/next marker 语义必须显式
- 不允许“有时 offset、有时 cursor”的隐式双轨语义

## Filtering
只冻结 schema 当前真实支持的筛选器。

## Compatibility
### Allowed
- backend 内部实现替换（node events → future durable indexer）
- canonical payload 与 rpc fallback payload 并存，只要 adapter 输出 contract 不变

### Not allowed
- 无文档通知地增加/删除必填字段
- 让 unknown fields 静默穿透 canonical contract
- 把 frontend adapter 的 fallback 当成 public API 兼容策略的长期替代品

---

# Part IV — 当前代码支持到哪一步

## 已经足够支撑 freeze 的部分
1. frontend 已有明确 client layer
2. frontend 已有 schema + types + adapters
3. RPC 已有 4 个实际 query endpoints
4. canonical / fallback payload 已有归一化逻辑
5. timeout / retry / abort / payload failure 已有显式错误分类

## 还不够支撑 freeze closure 的部分
1. durable indexer 尚未闭环
2. explorer backend 尚未脱离 scaffold
3. historical read-model 尚未闭环
4. public SLO / lag contract 尚未冻结
5. block/tx/account public contract 尚未达到 Day-1 freeze 条件

因此：

> **本文件只能关闭 Group A 的“contract freeze”部分，不能单独关闭整个 Rank 1。**

---

# Part V — 需要立刻跟进的实现任务

## G-A1 — 把本文件升级成正式 truth-source
- 对照 `schemas.ts` / `types.ts` / `adapters.ts` / RPC handler
- 把 query-normalized-audit-events 的 query 字段一项项落成正式表格
- 明确 block/tx/account out-of-scope

## G-A2 — 增加 contract conformance tests
- backend response ↔ frontend adapter contract tests
- canonical payload unknown-field fail-closed tests
- normalized audit pagination / query validation tests

## G-A3 — 冻结 error semantics vocabulary
- BAD_REQUEST / NOT_FOUND / INVALID_PAYLOAD / TIMEOUT / ABORTED / NETWORK / UNKNOWN
- 写成统一错误语义页，不让 frontend / RPC / docs 分裂

## G-A4 — 形成 Day-1 public read contract signoff note
- 一页 memo
- 引用本文件
- 说明：哪些是 Day-1 promise，哪些明确不承诺

---

# 最终一句话

> **当前代码已经足够冻结一份“最小 Day-1 public read contract”，但这份 contract 只应覆盖 task / events / capability audit / normalized audit + health probe。**
> **block / tx / account / durable explorer / historical read-model 仍不能被提前写进 Day-1 public promise。**
