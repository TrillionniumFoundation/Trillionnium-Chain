# Web4 Frontend 发布前 Checklist

> 目标：发布前确保最小闭环门禁全部通过，避免“可构建不可发布”。

## 必过门禁（Hard Gates）

- [ ] `npm run lint`
- [ ] `npm run typecheck`
- [ ] `npm run test`
- [ ] `npm run test:contract`
- [ ] `npm run build`

可一键执行：

```bash
npm run release:preflight
```

执行后报告会写入：`run/release-preflight-report.txt`

## CI 对齐检查

- [ ] GitHub Actions `web4-frontend-ci` 绿灯
- [ ] PR 中仅修改前端路径时，前端门禁自动触发
- [ ] `main` 分支 push 也会自动触发同一套门禁
- [ ] CI 默认强制 E2E（`CI_RUN_E2E=1`），本地默认不强制

## 发布自动化最小链路（版本 / Changelog / 预检）

1. 更新版本号（`package.json` 的 `version`）。
2. 在 `CHANGELOG.md` 添加同版本条目（如 `## [0.1.1] - YYYY-MM-DD`）。
3. 执行：

```bash
npm run release:ready
```

`release:ready` 会先校验 `CHANGELOG.md` 存在对应版本，再执行 `release:preflight`。

> 边界说明：这里的 `release:ready` 只表示 **web4-frontend 子项目** 已通过版本 / 变更日志 / 预检串联检查；**不等于整个 TRNM 仓库已经 release-ready**。仓库级发布口径仍以根目录 `RELEASE_READINESS.md` 为准。
>
> 对外 release / RC / handoff 语境，建议同时回看：
> - `../../RELEASE_READINESS.md`
> - `./operations-runbook.md`

## 发布前人工复核（轻量）

- [ ] `docs/api-contract.md` 与当前 adapter/schema 变更一致
- [ ] 如改动 `lib/api-contract/**`，确认 `tests/unit/api-contract-adapters.test.ts` 覆盖关键分支
- [ ] 如涉及页面渲染，至少本地打开首页做一次 smoke check

## Truth-source / handoff 复核（避免误导）

- [ ] 若在 release / RC / handoff 语境引用本次结果，同时记录仓库根目录 `RELEASE_READINESS.md` 与当下的 `git rev-parse origin/main` 输出；不要只引用前端子项目绿灯截图
- [ ] 若演示或排障使用了 `?mode=mock`，在交接记录中明确标注“explicit mock fallback”，不要把 mock 页面结果描述成真实查询环境状态
- [ ] 对外表述优先使用“web4-frontend 子项目预检通过”而不是“TRNM Web4 platform 已 release-ready”
