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

## 发布前人工复核（轻量）

- [ ] `docs/frontend-api-contract.md` 与当前 adapter/schema 变更一致
- [ ] 如改动 `lib/api-contract/**`，确认 `tests/unit/api-contract-adapters.test.ts` 覆盖关键分支
- [ ] 如涉及页面渲染，至少本地打开首页做一次 smoke check
