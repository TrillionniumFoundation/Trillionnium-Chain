# 运维手册（发布 / 回滚 / 排障）

## 发布最小路径

```bash
npm ci
npm run release:ready
npm run start
```

> `release:ready` 会校验 `package.json` 当前版本是否已写入 `CHANGELOG.md`，随后自动执行 `release:preflight`。
>
> 边界说明：这里的 `release:ready` 仅表示 **web4-frontend 子项目** 已通过本地版本/变更日志/预检串联检查；**不等于整个 TRNM 仓库已经 release-ready**。仓库级发布口径仍以根目录 `RELEASE_READINESS.md` 为准。

## 回滚最小路径

当新版本不可用时：

1. 切回上一稳定版本（Git tag/commit）。
2. 重新执行：

```bash
npm ci
npm run build
npm run start
```

> 回滚版本必须对应已通过 `npm run ci:check` 的提交。

## 常见故障排障

### 1) 本地启动失败

- 检查 Node/npm 版本是否满足要求（Node 20+）。
- 执行 `npm ci` 重新安装依赖。

### 2) CI 通过但 E2E 未执行

`ci-check.sh` 本身默认跳过 E2E；仓库 workflow 正常情况下会通过 `CI_RUN_E2E=1` 强制开启。

如需本地复现 CI 行为：

```bash
CI_RUN_E2E=1 npm run ci:check
```

### 3) API 响应解析失败（INVALID_PAYLOAD）

- 对照 `docs/api-contract.md` 与 `lib/api-contract/schemas.ts`
- 确认后端字段与类型是否一致
- 必要时补向后兼容映射，避免直接破坏前端读取

### 4) 超时与取消语义混淆

- 超时必须映射 `TIMEOUT`
- 主动取消必须映射 `ABORTED`

若出现混淆，优先检查 `lib/api-contract/client.ts` 错误归一逻辑。

### 5) build 阶段字体下载失败（Geist / fonts.gstatic）

症状：`next build` 报字体下载或 `@vercel/turbopack-next/internal/font/google/font` 相关错误。

排查方向：

1. 先确认当前环境是否可访问 `fonts.gstatic.com`。
2. 受限网络环境建议改为本地托管字体或移除在线字体依赖。
3. 重新执行 `npm run build` 验证。


## 标准化审计事件链路排障

若 Dashboard 事件面板异常增多或为空，可按以下顺序排查：

1. 确认 `.env.local` 中 `NEXT_PUBLIC_QUERY_API_BASE_URL` 指向正确网关。
2. 检查 endpoint 连通：
   ```bash
   curl "$NEXT_PUBLIC_QUERY_API_BASE_URL/query-normalized-audit-events?limit=1"
   ```
3. 若返回 404/5xx：后端未部署该 endpoint，前端会降级不影响主路径（但标准化事件缺失）。
4. 检查分页参数：
   - `NEXT_PUBLIC_DASHBOARD_NORMALIZED_AUDIT_EVENT_LIMIT` 是否为正整数
   - `NEXT_PUBLIC_DASHBOARD_NORMALIZED_AUDIT_MAX_PAGES` 是否为正整数
5. 观察浏览器 Network：应看到 `/query-task/:id`、`/query-events/:id`、`/query-capability-audit/:subject`、`/query-normalized-audit-events` 请求

