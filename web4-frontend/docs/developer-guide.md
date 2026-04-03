# 开发指南

## 环境要求

- Node.js 20+
- npm 10+

## 本地启动（最小可执行）

```bash
npm ci
npm run dev
```

访问：<http://localhost:3000>

> 当前默认运行语义：前端优先读取只读查询 API；仅在显式 `?mode=mock` 时回退到本地 mock snapshot。不要把本地页面可打开，误读成仓库已具备写路径或整体 release-ready。

## 开发前自检

```bash
npm run lint
npm run typecheck
npm run test
```

## 入口与 truth-source 速查

开发过程中若不确定“该看哪个文档、哪个结论代表什么”，按下面顺序判读：

1. `./README.md`：web4-frontend 文档中心入口
2. `./api-contract.md`：只读查询契约与字段语义
3. `./operations-runbook.md`：发布 / 回滚 / 排障与 operator 语义
4. `../../RELEASE_READINESS.md`：TRNM 仓库级 release truth source
5. 若当前 checkout 含有 `docs/reports/TRNM_WEB4_PLATFORM_SCORECARD_2026-03-31.md`，优先引用该 Web4 平台阶段评分卡来描述成熟度位置；它不用于 release 放行

避免两个常见误读：

- `npm run ci:check` 或 `npm run release:ready` 通过，只能说明 **web4-frontend 子项目** 本地门禁通过。
- 页面在 `?mode=mock` 下可正常展示，只能说明 **explicit mock fallback** 可用，不能说明真实查询环境或写路径已就绪。


## 环境配置

推荐在本地和部署前拷贝并维护：`web4-frontend/.env.example`。

- 若当前目录是 `web4-frontend/`：执行 `cp .env.example .env.local`
- 若当前目录是仓库根：执行 `cp web4-frontend/.env.example web4-frontend/.env.local`

关键变量：
- `NEXT_PUBLIC_QUERY_API_BASE_URL`（后端查询 API 地址）
- `NEXT_PUBLIC_DASHBOARD_TASK_ID`（默认展示任务）
- `NEXT_PUBLIC_DASHBOARD_AUDIT_SUBJECT`（`queryCapabilityAudit` 的默认 subject）
- `NEXT_PUBLIC_DASHBOARD_NORMALIZED_AUDIT_EVENT_LIMIT`（标准化审计分页大小，默认 60）
- `NEXT_PUBLIC_DASHBOARD_NORMALIZED_AUDIT_MAX_PAGES`（标准化审计分页页数，默认 4）

非法值会回退默认值，不会中断前端启动。

## API 合约开发约束

涉及 `lib/api-contract/` 的改动，必须同步：

1. 更新 zod schema（`schemas.ts`）
2. 更新类型（`types.ts`）
3. 更新 adapter（`adapters.ts`）
4. 补充/更新测试（单测或契约测试）
5. 更新文档：`docs/api-contract.md`

## 提交前推荐流程

```bash
npm run ci:check
```

如需在本地模拟 CI + E2E：

```bash
CI_RUN_E2E=1 npm run ci:check
```

## 发布前推荐流程

```bash
npm run release:preflight
```

该命令会额外执行 `test:contract` 并产出报告：`run/release-preflight-report.txt`。

如需判断“整个 TRNM 仓库现在能否对外表述为 release-ready”，请返回仓库根目录查看 `RELEASE_READINESS.md`，不要只依据前端子项目门禁结果下结论。
