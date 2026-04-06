# Aggressive Week2 Day3 Findings（Hotspot 策略）

日期：2026-02-20

## 实验输入
- 脚本：`trillionnium/scripts/run_executor_hotspot_experiment.sh`
- 参数：`TXS=20000 KEYS=2000 READ_FANOUT=3 WRITE_EVERY=2`
- 产物：`trillionnium/run/bench/executor-hotspot-exp-20260220-155811.txt`

## 结果摘要
- original: `37ms`（groups=579）
- aggressive(default): `37ms`（groups=579）
- auto-adaptive(默认阈值): `38ms`（未触发 hot-bucket，reason=low_expected_gain）
- hot-bucket-interleave: `42ms`（groups=489，仍更慢）

### 额外调参试验（auto-adaptive）
- 手动放宽阈值使其触发 hot-bucket：
  - `TRNM_AUTO_MIN_EXPECTED_GAIN_SCORE=0.006`
  - `TRNM_AUTO_REORDER_MIN_HOT_KEY_SHARE=0.007`
  - `TRNM_AUTO_REORDER_MIN_MARGIN=0.03`
- 结果：`43ms`（更慢）

## 结论
- Week2 Day3 判定：**No-Go（hot-bucket/auto-adaptive 在该代表 hotspot 场景无收益）**
- 建议维持：
  1) 默认路径继续使用当前稳定实现（original/aggressive default 快路径）
  2) auto-adaptive 默认阈值不放宽
  3) hotspot 重排策略作为可选实验保留，不进默认 gate
