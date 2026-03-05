# 测试与 CI 规范

## 测试分层

- 默认测试入口：`npm run test`（当前等价于 `npm run test:unit`）
- 单元/组件测试：`npm run test:unit`（Vitest）
- 合约测试：`npm run test:contract`（API contract adapters）
- 端到端测试：`npm run test:e2e`（Playwright）

## CI 统一入口

```bash
npm run ci:check
```

`ci:check` 执行顺序（见 `scripts/ci-check.sh`）：

1. `npm run lint`
2. `npm run typecheck`
3. `npm run --if-present test`
4. （可选）`npm run --if-present test:e2e`
5. `npm run build`

默认跳过 E2E；设置环境变量后启用：

```bash
CI_RUN_E2E=1 npm run ci:check
```

## 失败排查建议

1. lint 失败：先修格式/规则问题。
2. typecheck 失败：优先修类型定义，不要绕过。
3. test 失败：先最小复现，再修业务逻辑。
4. build 失败：检查 Next.js 页面/服务端组件边界和依赖解析。
