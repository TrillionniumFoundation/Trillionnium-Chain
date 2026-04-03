# Web4 Frontend API Interface V0（2026-03-03）

## 1) 当前实现状态（As-Is）
- 前端目录：`web4-frontend/`
- 实际读路径：`web4-frontend/lib/api-contract/*` + `web4-frontend/lib/dashboard/source.ts`
- 现状说明：当前 Dashboard **默认尝试只读 API client**，查询 `query-task` / `query-events` / `query-capability-audit`；仅在显式 `?mode=mock` 时回退到本地 snapshot fallback。
- 口径澄清：`web4-frontend/app/dashboard-data.ts` 已不是当前语义锚点；`/api/v0/web4/*` 也不是当前仓内已实现 route。

## 2) 与 Master/Phase 文档对齐结论
- 对齐 `docs/WEB4_INFRA_PLATFORM_DEVELOPMENT_MASTER.md`：当前属于 Phase A 的可观测性可视化前置阶段（A3 视图层先行）。
- 对齐 `docs/development/roadmap-progress.json`：链内开发主线已 100%，前端 API 契约进入文档先行冻结（不改核心业务逻辑）。
- 对齐 XI 门禁脚本说明：前端仅消费只读聚合数据，不绕过以下门禁结论：
  - `./scripts/v2/x2_settlement_contract_gate.sh`
  - `./scripts/v2/i2_token_lifecycle_gate.sh`

## 3) 当前只读接口契约（实现对齐版）
> 说明：以下是**当前前端已消费**的最小只读接口，不是新的 dashboard route 设计。保持 fail-closed；请求失败时页面报错，开发/演示可显式切到 mock fallback。

### 3.1 `GET /query-task/:taskId`
用途：查询单个任务快照，前端再映射成 Overview/Tasks 卡片。

### 3.2 `GET /query-events/:taskId`
用途：查询任务相关事件流，前端映射成 Events 视图。

### 3.3 `GET /query-capability-audit/:subject`
用途：查询 capability audit 条目，前端映射成 Audit 视图。

### 3.4 关于 `/api/v0/web4/*`
- 这些路径只代表 2026-03-03 文档草案中的聚合命名。
- 当前仓内**没有**对应的 Next.js route / server handler / backend implementation。
- 若未来需要引入 dashboard 聚合 API，应新开文档与实现，不应把本草案误读为“现已落地”。

## 4) 前端接入守则（Gate-aware）
- 仅允许只读 GET；禁止在 Dashboard 暴露写入/管理操作。
- 字段命名采用 snake_case（与链上/CLI 导出聚合层保持一致）。
- 严禁把 not-found 映射为 success（沿用 I2 稳定 not-found 语义）。

## 5) 最小校验命令
```bash
# 当前只读客户端实现存在
test -f web4-frontend/lib/api-contract/client.ts
test -f web4-frontend/lib/dashboard/source.ts

# XI 门禁脚本存在（接口接入不得绕开）
test -f scripts/v2/x2_settlement_contract_gate.sh
test -f scripts/v2/i2_token_lifecycle_gate.sh
```
