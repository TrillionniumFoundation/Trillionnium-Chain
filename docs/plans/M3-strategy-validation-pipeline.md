# M3 策略验证流水线（Replay -> Backtest -> SimLive）

## 目标
从固定回放到小规模仿真实盘，建立可重复的一致性验证链。

## 阶段 A：固定数据回放
- [ ] 选定 golden dataset（固定 dataset_id）
- [ ] 固定策略参数快照（param_hash）
- [ ] 产出基线结果（signals/trades/pnl/drawdown）

## 阶段 B：回测一致性
- [ ] 同输入同参数重复 N 次（建议 N=5）
- [ ] 比对关键指标偏差：
  - [ ] `trade_count`
  - [ ] `signal_count`
  - [ ] `net_pnl`
  - [ ] `max_drawdown`
- [ ] 设定阈值（建议初版）：
  - [ ] trade/signal 偏差 = 0
  - [ ] net_pnl 偏差 <= 1e-9（浮点系统按实际设）
  - [ ] mdd 偏差 <= 1e-9

## 阶段 C：小规模仿真实盘
- [ ] 限定标的（1-2）+ 限定仓位
- [ ] 运行时长（先 1~3 个交易日）
- [ ] 监控：下单成功率、延迟、拒单原因、风险触发
- [ ] 与回放预期做偏差对账

## Gate 建议（最小）
```bash
./scripts/v2/run_strategy_replay_golden.sh
./scripts/v2/check_backtest_consistency.sh
./scripts/v2/run_simlive_smoke.sh
```

## 出口标准（进入更大规模前）
- [ ] 三阶段连续通过
- [ ] 无未分类错误
- [ ] 所有失败都具备 M1 产物可追溯
