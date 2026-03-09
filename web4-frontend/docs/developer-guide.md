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

## 开发前自检

```bash
npm run lint
npm run typecheck
npm run test
```

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
