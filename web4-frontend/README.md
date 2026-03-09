# web4-frontend

Web4 前端项目（Next.js 16 + React 19）。

> 文档统一入口：**[docs/README.md](./docs/README.md)**

## 快速开始（最小可执行）

```bash
npm ci
npm run dev
```

打开 <http://localhost:3000>

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

详细说明见：`docs/operations-runbook.md`
