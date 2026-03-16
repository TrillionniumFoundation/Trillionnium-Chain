# Aggressive Week2 Day4 Decision Memo

日期：2026-02-20

## 决策摘要

基于 Week2 Day1~Day3 的实验结果，做出以下决策：

1. **默认路径冻结（继续）**
   - 维持当前 Aggressive 默认快路径（dependency-bound fast path）。
   - 不引入 deep-scan / hotspot 重排到默认执行链路。

2. **实验路径隔离（继续）**
   - `TRNM_AGGR_DEEP_SCAN=1`、hot-bucket、auto-adaptive 调参仅在实验任务中运行。
   - 不进入 nightly 默认 gate 口径。

3. **阶段目标切换**
   - 从“继续榨 Aggressive 策略”切换为“保持稳定 + 防回归 + 运维可观测”。

---

## 证据摘要

- Day1/Day2：deep-scan 在代表 hotspot 下约 `88~89ms`，显著慢于默认路径（~37ms）。
- Day3：hot-bucket / auto-adaptive 在代表 hotspot 场景无收益（42~43ms，慢于 37ms）。
- 默认 Aggressive 快路径已与 Original 收敛（约 0.97x~1.00x），且门禁已收紧。

---

## 风险与控制

### 风险
- 实验策略误入默认路径导致性能/稳定性回退。

### 控制
1. 默认关闭实验开关（当前已执行）。
2. 继续执行回归矩阵 + ratio gate（当前阈值已收紧）。
3. 实验结果与默认发布口径严格分离（文档与 CI 均区分）。

---

## 下阶段（Week2 Day5 / Week3）

1. 完成 Week2 总结与 backlog 清理；
2. 增强 nightly 摘要中的“策略来源标签”（default vs experiment）；
3. 把精力转到 state_root/恢复性与运维可观测增强任务。
