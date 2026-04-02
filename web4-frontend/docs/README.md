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

## 5. 状态口径与证据入口

发布/RC/对外口径引用时，建议按下面顺序取材，避免把历史证据误写成当前 readiness：

- 仓库级 truth source：[`../../RELEASE_READINESS.md`](../../RELEASE_READINESS.md)
- Web4 平台主文档：[`../../docs/WEB4_INFRA_PLATFORM_DEVELOPMENT_MASTER.md`](../../docs/WEB4_INFRA_PLATFORM_DEVELOPMENT_MASTER.md)
- Web4 阶段快照（历史状态，不等于当前 release-ready）：[`../../docs/development/WEB4_PHASE_B_MILESTONE_SNAPSHOT_2026-02-28.md`](../../docs/development/WEB4_PHASE_B_MILESTONE_SNAPSHOT_2026-02-28.md)
- Web4 前端接口基线：[`../../docs/development/WEB4_FRONTEND_API_INTERFACE_V0.md`](../../docs/development/WEB4_FRONTEND_API_INTERFACE_V0.md)
- Web4 修复证据（历史 run evidence，不等于当前 release-ready）：[`../../docs/release/web4-fix-sequence-2026-03-04-evidence.md`](../../docs/release/web4-fix-sequence-2026-03-04-evidence.md)

> 当前更准确的外部口径应是：**强链核 + 初步平台壳的 Alpha 后段项目**，而不是 Beta / production-ready Web4 platform。
>
> 若需要一句最短、最不易误导的表述，优先采用：
> **默认是 readonly API client + explicit mock fallback 的 Web4 前端入口；仓库级 release 判定仍以 `RELEASE_READINESS.md` 为准。**

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
