# Trillionnium 对标 Solana / Sui 的完整流水线

更新日期：2026-02-20

本文件定义 `scripts/auto_relay.steps` 的设计目标：
- 对标 Solana/Sui 的核心竞争轴：
  1) correctness / determinism
  2) throughput / latency
  3) hotspot / conflict degradation
  4) observability / attribution
  5) release-readiness

## 执行入口

```bash
# 串行全量跑一轮（失败即停）
STOP_ON_ERROR=1 ./scripts/auto_relay.sh

# 连续多轮 soak（例如 3 轮）
STOP_ON_ERROR=1 ROUNDS=3 ./scripts/auto_relay.sh
```

## 结果位置
- Auto relay 汇总：`data/auto-relay/<run_id>/summary.md`
- 每步日志：`data/auto-relay/<run_id>/round-*-step-*.log`
- bench/health 产物：`trillionnium-rust/run/bench`、`trillionnium-rust/run/health`

## 对标说明（简）
- Solana 侧重点：热点冲突下性能退化曲线、调度策略收益、阈值调优。
- Sui 侧重点：冲突隔离与并行执行稳定性、语义正确性与状态一致性。
- Trillionnium 侧输出：通过 nightly attribution + summary 形成可解释归因，避免只看单一 TPS 数字。
