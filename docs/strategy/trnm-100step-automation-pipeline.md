# Trillionnium 100-Step 自动化流水线

更新时间：2026-02-20

## 目标
把后续推进拆成可连续执行、可追踪、可复跑的 100 步流水线。

## 组成
- 步骤文件：`scripts/auto_relay_100.steps`
- 启动脚本：`scripts/run_100step_pipeline.sh`
- 执行引擎：`scripts/auto_relay.sh`

## 五大阶段
1. **P0/P1 语义与守门（1-10）**
2. **基线与回归矩阵扩展（11-40）**
3. **策略实验批跑（41-60）**
4. **归因与分析循环（61-80）**
5. **预发布与生产烟测（81-100）**

## 运行方式
```bash
# 默认：失败即停，1轮100步
./scripts/run_100step_pipeline.sh

# 连跑2轮（200步）
ROUNDS=2 ./scripts/run_100step_pipeline.sh

# 仅预演（不执行）
DRY_RUN=1 STEPS_FILE=./scripts/auto_relay_100.steps ./scripts/auto_relay.sh
```

## 产物
- 总结：`data/auto-relay/<run_id>/summary.md`
- 分步日志：`data/auto-relay/<run_id>/round-*-step-*.log`
- bench/health：`trillionnium-rust/run/bench`、`trillionnium-rust/run/health`
