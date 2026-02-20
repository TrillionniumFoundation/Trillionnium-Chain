# Rust L1 Demo Runbook v1

更新日期：2026-02-20

## 目标
给对外演示提供统一口径：同一套命令、同一套叙事、同一套验收输出。

## 演示脚本顺序
1. P0 quick acceptance（基础健康）
2. Challenge re-exec 模板（争议裁决闭环）
3. Worker contract smoke（幂等/可观测字段）

## 一键命令
```bash
./scripts/demo_storyline.sh
```

## 预期输出
- `[DEMO][OK] p0 quick acceptance ...`（若仓库具备该脚本）
- `[DEMO][OK] challenge reexec template smoke`
- `[DEMO][OK] worker onchain contract smoke`
- 汇总文件：`data/demo/<timestamp>/summary.txt`

## 对外讲解话术（简版）
- “先看链健康，再看争议重执行，再看生产级 worker 契约。”
- “重点不是单次跑通，而是可重复、可追踪、可恢复。”
