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
