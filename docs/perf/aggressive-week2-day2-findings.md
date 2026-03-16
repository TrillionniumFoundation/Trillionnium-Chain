# Aggressive Week2 Day2 Findings（Deep-scan）

日期：2026-02-20

## 实验结论
- 在 hot-streak（txs=20000, keys=2000）上复验 deep-scan：
  - `TRNM_AGGR_DEEP_SCAN=1` => `elapsed_ms=88~89`, `candidate_groups_scanned=19521`
- 对比默认路径（~37ms）仍显著退化，约 **2.4x**。

## 结论判定
- **No-Go（deep-scan 本轮不继续做主线优化）**
- 继续保持：
  - 默认路径稳定（deep-scan 关闭）
  - deep-scan 仅限隔离实验，不进入 gate 与默认发布口径

## 下一步建议（Week2 Day3）
1. 转向 `hot-bucket-interleave / auto-adaptive` 在 hot-streak 的专项调优（不碰默认 Aggressive 快路径）
2. 深扫分支仅保留最小维护，待有明确新假设再开下一轮
