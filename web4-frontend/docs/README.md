# 文档中心（入口）

本文档为 web4-frontend 的文档入口。前端运行语义以本目录和 `lib/api-contract/*` / `lib/dashboard/source.ts` 为准；仓库级 release 判定仍以根级 `RELEASE_READINESS.md` 为准。

> 边界提醒：当前 Web4 前端语义是 **readonly API client + explicit mock fallback**。
> - 默认路径：读取查询 API
> - 显式 `?mode=mock`：回退到本地 mock snapshot
> - 不提供写路径，也不应据此推断整个 TRNM 仓库已 release-ready

## 1. 上手与开发

- [开发指南](./developer-guide.md)

## 2. API 合约

- [API 合约（只读查询）](./api-contract.md)

## 3. 测试与 CI

- [测试与 CI 规范](./testing-ci.md)

## 4. 运维与发布

- [运维手册（发布/回滚/排障）](./operations-runbook.md)
- [发布前 Checklist](./release-checklist.md)

发布/RC/对外口径引用时，建议同时回看：
- 仓库级 truth source：[`../../RELEASE_READINESS.md`](../../RELEASE_READINESS.md)
- Web4 平台主文档：[`../../docs/WEB4_INFRA_PLATFORM_DEVELOPMENT_MASTER.md`](../../docs/WEB4_INFRA_PLATFORM_DEVELOPMENT_MASTER.md)

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
