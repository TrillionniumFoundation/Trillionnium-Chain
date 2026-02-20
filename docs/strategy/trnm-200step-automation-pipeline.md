# Trillionnium 200-Step 自动化流水线（12周细化版）

更新时间：2026-02-20

## 对应12周路线图
- Step 1-80：共识机制收敛与抗压验证
- Step 81-140：治理MVP回归循环（含可观测与守门）
- Step 141-200：生态就绪与对标报告节奏

## 执行入口
```bash
./scripts/run_200step_pipeline.sh
```

多轮 soak：
```bash
ROUNDS=2 ./scripts/run_200step_pipeline.sh
```

预演：
```bash
DRY_RUN=1 STEPS_FILE=./scripts/auto_relay_200.steps ./scripts/auto_relay.sh
```

## 产物
- `data/auto-relay/<run_id>/summary.md`
- `data/auto-relay/<run_id>/round-*-step-*.log`
- `trillionnium-rust/run/bench/*`
- `trillionnium-rust/run/health/*`
