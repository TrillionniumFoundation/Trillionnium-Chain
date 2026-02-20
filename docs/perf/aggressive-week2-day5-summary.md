# Aggressive Week2 Day5 Summary（One-Pager）

日期：2026-02-20

## 本周目标
在不破坏默认稳定路径的前提下，验证 deep-scan / hotspot 重排是否存在可上线收益。

## 执行结果
- Day1：建立 deep-scan A/B 脚本与基线。
- Day2：deep-scan 复验，性能显著退化（No-Go）。
- Day3：hot-bucket / auto-adaptive 调参与复验，仍无收益（No-Go）。
- Day4：决策备忘录落地，冻结默认路径、隔离实验路径。
- Day5：总结与 backlog 收敛（本文件）。

## 关键数据（代表场景 hot-streak 20000/2000）
- original: ~36-37ms
- aggressive(default): ~37ms
- aggressive(deep-scan=1): ~88-89ms（明显退化）
- hot-bucket / auto-adaptive: ~42-43ms（无收益）

## 决策
1. 默认执行链路保持当前快路径（稳定优先）。
2. deep-scan 与 hotspot 重排继续保留为实验能力，不进入默认 gate。
3. 资源转向：稳定性/可恢复性/可观测性增强。

## 下阶段任务（建议）
1. P2-1：nightly 摘要增加“default vs experiment”策略来源标签。
2. P1/P2：state_root 对账定位工具与回滚/恢复压测增强。
3. P2-3：整理对外演示口径（强调“可持续提速 + 可治理”）。
