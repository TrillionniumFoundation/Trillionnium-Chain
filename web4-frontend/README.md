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
- `npm run ci:check`：CI 同步检查（lint + typecheck + test + build；默认不跑 e2e）
- `CI_RUN_E2E=1 npm run ci:check`：CI 中开启 E2E
- `npm run release:preflight`：发布前检查（含 contract + build，输出报告）

## 发布（最小路径）

```bash
npm ci
npm run release:preflight
npm run start
```

> `release:preflight` 已包含 lint/typecheck/test/test:contract/build。

详细说明见：`docs/operations-runbook.md`
