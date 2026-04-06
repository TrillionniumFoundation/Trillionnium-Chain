# Web4 并 main 前证据包（Pre-main Evidence Pack）

在合并到 `main` 之前，使用以下单命令生成可复现证据包：

```bash
./scripts/v2/web4_premerge_evidence_pack.sh
```

## 失败即停止（fail-closed）策略

脚本会在以下场景直接失败并退出：

- 执行前工作区非 clean（`git status --porcelain` 非空）
- 任一核心检查失败
- 检查后工作区变脏（避免“证据通过但源码发生漂移”）

## 固化检查项

1. `cargo test --workspace`（在 `trillionnium/` 内执行）
2. `./scripts/v2/web4_release_aggregate_gate.sh`
3. `web4-frontend` 全量校验：
   - `npm run lint`
   - `npm run typecheck`
   - `npm run test --if-present`
   - `npm run build`

## 输出目录

默认输出到：

- `run/web4-premerge-evidence/<timestamp>/summary.md`
- `run/web4-premerge-evidence/<timestamp>/*.log`

可通过环境变量覆盖：

```bash
WEB4_PREMERGE_RUN_DIR=/tmp/web4-premerge-evidence ./scripts/v2/web4_premerge_evidence_pack.sh
```

`summary.md` 会记录 branch/head 与检查结果，可直接附到 release 收口审阅材料中。
