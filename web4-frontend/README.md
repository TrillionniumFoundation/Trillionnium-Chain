# web4-frontend

Web4 前端项目（Next.js 16 + React 19）。

> 文档统一入口：**[docs/README.md](./docs/README.md)**
> 当前运行语义：默认使用 readonly API client；仅在显式 `?mode=mock` 时回退到本地 mock snapshot；不提供写路径。

## 快速开始（最小可执行）

```bash
npm ci
npm run dev
```

打开 <http://localhost:3000>

## 文档入口与判读边界

优先按下面顺序查阅，避免把不同层级的结论混在一起：

- [`docs/README.md`](./docs/README.md)：**前端文档统一入口**（开发 / API 合约 / 测试 / 运维）
- [`docs/developer-guide.md`](./docs/developer-guide.md)：开发者本地启动、环境变量、提交流程
- [`docs/operations-runbook.md`](./docs/operations-runbook.md)：operator / 发布 / 回滚 / 排障操作
- [`../RELEASE_READINESS.md`](../RELEASE_READINESS.md)：**仓库级 release truth source**；判断 TRNM 是否可对外表述为 release-ready 时，以此为准。引用该文件时，应同时记录当前 `git rev-parse origin/main` 输出，避免把旧快照当成实时结论
- 若当前 checkout 含有 [`../docs/reports/TRNM_WEB4_PLATFORM_SCORECARD_2026-03-31.md`](../docs/reports/TRNM_WEB4_PLATFORM_SCORECARD_2026-03-31.md)，优先引用该 Web4 平台阶段评分卡来描述成熟度位置；它适用的仓库快照是 `main@9ea9e7751`，用于回答“当时大致处于哪个平台阶段”，**不等于** release-ready 证明，也不自动等于当前实时状态
- 当前 checkout 中，`docs/WEB4_INFRA_PLATFORM_DEVELOPMENT_MASTER.md` **缺失**；不要把它当作当前 truth source，优先退回 `RELEASE_READINESS.md` 与 `web4-frontend/docs/README.md`

可用一句话记忆：

> `web4-frontend` 的门禁绿灯，表示**前端子项目预检通过**；不表示整个 TRNM 仓库已经 release-ready。

## 环境变量（可选）

生产/测试环境建议使用本地化配置文件：

若当前目录是 `web4-frontend/`：

```bash
cp .env.example .env.local
```

若当前目录是仓库根：

```bash
cp web4-frontend/.env.example web4-frontend/.env.local
```

可选变量说明见：
- `NEXT_PUBLIC_QUERY_API_BASE_URL`
- `NEXT_PUBLIC_DASHBOARD_TASK_ID`
- `NEXT_PUBLIC_DASHBOARD_AUDIT_SUBJECT`
- `NEXT_PUBLIC_DASHBOARD_NORMALIZED_AUDIT_EVENT_LIMIT`
- `NEXT_PUBLIC_DASHBOARD_NORMALIZED_AUDIT_MAX_PAGES`

未设置时使用内置默认值（参考 `docs/api-contract.md`）。

## 常用命令（统一）

- `npm run dev`：本地开发
- `npm run lint`：ESLint
- `npm run typecheck`：TypeScript 类型检查
- `npm run test`：默认测试入口（当前映射 `test:unit`）
- `npm run test:unit`：Vitest 单元/组件测试
- `npm run test:contract`：API 合约适配层测试
- `npm run test:e2e`：Playwright E2E
- `npm run ci:check`：统一门禁检查（默认不跑 e2e）
- `CI_RUN_E2E=1 npm run ci:check`：显式开启 E2E（CI workflow 默认已开启）
- `npm run release:preflight`：发布前检查（含 contract + build，输出报告）
- `npm run release:ready`：发布准备检查（版本号 ↔ CHANGELOG ↔ preflight）

## 发布（最小路径）

```bash
npm ci
npm run release:ready
npm run start
```

> `release:ready` 会先校验当前版本在 `CHANGELOG.md` 中有对应条目，再执行 `release:preflight`（lint/typecheck/test/test:contract/build）。

详细说明见：`docs/operations-runbook.md`；发布前门禁与人工复核清单见：`docs/release-checklist.md`

## 对外表述最小口径

若需要在交接、演示、排障记录里简短描述当前 Web4 前端状态，优先使用：

- **默认是 readonly API client**
- **仅在显式 `?mode=mock` 时回退到本地 mock snapshot**
- **不提供写路径**
- **仓库级 release 判定仍以根目录 `RELEASE_READINESS.md` 为准**
- **当前平台成熟度表述若需引用阶段口径，优先引用 `docs/reports/TRNM_WEB4_PLATFORM_SCORECARD_2026-03-31.md`，不要泛化为“最新某份评分文档”**
- **若 `docs/WEB4_INFRA_PLATFORM_DEVELOPMENT_MASTER.md` 在当前 checkout 不存在，应明确说明该 master 文档缺席，而不是继续给出死链或把其路线目标写成现状**
