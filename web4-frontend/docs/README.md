# 文档中心（入口）

本文档为 web4-frontend 的文档入口。前端运行语义以本目录和 `lib/api-contract/*` / `lib/dashboard/source.ts` 为准；仓库级 release 判定仍以根级 `RELEASE_READINESS.md` 为准。

## 1. 上手与开发

- [开发指南](./developer-guide.md)

## 2. API 合约

- [API 合约（只读查询）](./api-contract.md)

## 3. 测试与 CI

- [测试与 CI 规范](./testing-ci.md)

## 4. 运维与发布

- [运维手册（发布/回滚/排障）](./operations-runbook.md)
- [发布前 Checklist](./release-checklist.md)

---

## 命令统一约定

以下命令在所有文档中保持一致：

- 安装依赖：`npm ci`
- 开发：`npm run dev`
- 质量检查：`npm run lint` / `npm run typecheck`
- 测试：`npm run test` / `npm run test:unit` / `npm run test:contract` / `npm run test:e2e`
- CI 总检查：`npm run ci:check`
- CI 开启 E2E：`CI_RUN_E2E=1 npm run ci:check`
- 发布前检查：`npm run release:preflight`
- 发布准备（版本/changelog/预检串联）：`npm run release:ready`
- 生产运行：`npm run build && npm run start`
