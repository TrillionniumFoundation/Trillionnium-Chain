# Web4 Frontend API Interface V0（2026-03-03）

## 1) 当前实现状态（As-Is）
- 前端目录：`web4-frontend/`
- 数据来源：`web4-frontend/app/dashboard-data.ts`
- 现状说明：当前 Dashboard 使用**本地静态 mock 数据**，尚未接入后端只读 API。

## 2) 与 Master/Phase 文档对齐结论
- 对齐 `docs/WEB4_INFRA_PLATFORM_DEVELOPMENT_MASTER.md`：当前属于 Phase A 的可观测性可视化前置阶段（A3 视图层先行）。
- 对齐 `docs/development/roadmap-progress.json`：链内开发主线已 100%，前端 API 契约进入文档先行冻结（不改核心业务逻辑）。
- 对齐 XI 门禁脚本说明：前端仅消费只读聚合数据，不绕过以下门禁结论：
  - `./scripts/v2/x2_settlement_contract_gate.sh`
  - `./scripts/v2/i2_token_lifecycle_gate.sh`

## 3) V0 只读接口契约（建议）
> 说明：以下为前端接入时的最小契约草案，保持 fail-closed；若字段缺失返回空值而非伪造默认成功态。

### 3.1 `GET /api/v0/web4/dashboard/kpis`
返回：
```json
{
  "uptime_pct": 99.982,
  "pending_tasks": 17,
  "open_incidents": 2,
  "audit_coverage_pct": 94.6,
  "updated_at": "2026-03-03T10:30:00Z"
}
```

### 3.2 `GET /api/v0/web4/dashboard/tasks`
返回（数组）：`id,title,owner,priority,status,updated_at`

### 3.3 `GET /api/v0/web4/dashboard/events`
返回（数组）：`id,time,category,summary,severity`

### 3.4 `GET /api/v0/web4/dashboard/audits`
返回（数组）：`id,control,result,reviewer,reviewed_at`

## 4) 前端接入守则（Gate-aware）
- 仅允许只读 GET；禁止在 Dashboard 暴露写入/管理操作。
- 字段命名采用 snake_case（与链上/CLI 导出聚合层保持一致）。
- 严禁把 not-found 映射为 success（沿用 I2 稳定 not-found 语义）。

## 5) 最小校验命令
```bash
# Frontend mock 数据源仍存在（接入前兜底）
test -f web4-frontend/app/dashboard-data.ts

# XI 门禁脚本存在（接口接入不得绕开）
test -f scripts/v2/x2_settlement_contract_gate.sh
test -f scripts/v2/i2_token_lifecycle_gate.sh
```
