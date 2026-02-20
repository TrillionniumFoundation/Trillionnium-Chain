# Aggressive Week2 Day1 Plan（Deep-scan 实验分支）

日期：2026-02-20

## 目标
在不影响默认路径（`TRNM_AGGR_DEEP_SCAN=0`）的前提下，独立评估 deep-scan 的可行收益窗口。

## 今日已执行
- 新增脚本：`trillionnium-rust/scripts/run_aggressive_deepscan_ab_hotstreak.sh`
- 产物：`trillionnium-rust/run/bench/aggressive-deepscan-ab-hotstreak-20260220-154943.txt`

## A/B 快照（hot-streak, txs=20000, keys=2000）
- original: `36ms`
- aggressive(default): `37ms`
- aggressive(deep-scan=1): `86ms`

结论：当前 deep-scan 分支明显退化（约 2.39x vs original），暂不具备进入默认路径条件。

## Week2 Day1~Day2 下一动作
1. deep-scan 仅在实验任务中启用，禁止进入默认 gate。
2. 在 deep-scan 路径新增“早停”实验（按命中率/扫描收益阈值提前终止）。
3. 输出 `deep-scan` 专项报告（单独口径，不混入默认 Aggressive 周报）。

## 风险控制
- 任何 deep-scan 改动必须满足：
  - 默认行为不变（`TRNM_AGGR_DEEP_SCAN` 默认关闭）
  - regression matrix 与 nightly gate 无负面影响
