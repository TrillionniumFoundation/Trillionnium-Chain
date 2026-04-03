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
- Web4 当前阶段评分卡：[`../../docs/reports/TRNM_WEB4_PLATFORM_SCORECARD_2026-03-31.md`](../../docs/reports/TRNM_WEB4_PLATFORM_SCORECARD_2026-03-31.md)（若当前 checkout 含有该文件，优先引用它描述平台成熟度；它是基于特定仓库快照的阶段评分卡，不等于当前 release-ready，也不自动等于实时状态）
- Web4 阶段快照（历史状态，不等于当前 release-ready）：[`../../docs/development/WEB4_PHASE_B_MILESTONE_SNAPSHOT_2026-02-28.md`](../../docs/development/WEB4_PHASE_B_MILESTONE_SNAPSHOT_2026-02-28.md)
- Web4 前端接口基线：[`../../docs/development/WEB4_FRONTEND_API_INTERFACE_V0.md`](../../docs/development/WEB4_FRONTEND_API_INTERFACE_V0.md)
- Web4 修复证据（历史 run evidence，不等于当前 release-ready）：[`../../docs/archive/web4-history/web4-fix-sequence-2026-03-04-evidence.md`](../../docs/archive/web4-history/web4-fix-sequence-2026-03-04-evidence.md)

### 5.1 三类问题，分别引用哪份文档

| 你要回答的问题 | 应优先引用 | 不能顺手放大的结论 |
| --- | --- | --- |
| **现在整个 TRNM 仓库能否对外说 release-ready？** | [`../../RELEASE_READINESS.md`](../../RELEASE_READINESS.md) | 不能把某次 Web4 预检、RC 演练、历史 GO-ready 证据外推为“整个仓库已 ready” |
| **当前 Web4 平台大致成熟到哪个阶段？** | 若当前 checkout 含有 `docs/reports/TRNM_WEB4_PLATFORM_SCORECARD_2026-03-31.md`，优先引用它；若缺失，则退回 [`../../docs/WEB4_INFRA_PLATFORM_DEVELOPMENT_MASTER.md`](../../docs/WEB4_INFRA_PLATFORM_DEVELOPMENT_MASTER.md) 并明确这是路线/能力文档，不是阶段评分卡 | 不能把“Alpha 后段 / 接近 Beta-prep 之前”润色成“Beta”或“production-ready”，也不能把路线图目标写成当前成熟度事实 |
| **平台路线图、能力域目标、下一阶段该补什么？** | [`../../docs/WEB4_INFRA_PLATFORM_DEVELOPMENT_MASTER.md`](../../docs/WEB4_INFRA_PLATFORM_DEVELOPMENT_MASTER.md) | 不能把路线图里的 To-Be 目标写成当前已完成事实 |

> 一个好用的心智模型：
> - `RELEASE_READINESS.md` 回答 **现在能不能放行**
> - Scorecard 回答 **现在大概到哪一阶段**
> - Master 文档回答 **接下来应该往哪补**

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
