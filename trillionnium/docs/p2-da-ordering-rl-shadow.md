# P2: DA/排序解耦 + RL 建议器（Shadow Mode）

## 目标
在不改变主路径默认行为的前提下，落地可演进骨架：

1. 将 `consensus` 与 `DA/ordering` 通过接口解耦（最小改造）
2. 引入 RL advisor 的 shadow-only 接口（仅建议，不执行）
3. 提供可控开关，默认关闭

## 开关
`trnm-node` 新增参数：

- `--enable-da-ordering-decouple`（默认 `false`）
  - `false`：走原有 legacy 路径（`build_parallel_groups + pre_execute_group_parallel`）
  - `true`：走解耦脚手架（`DaProvider + OrderingEngine`），当前仍保持等价行为
- `--rl-advisor-shadow`（默认 `false`）
  - 开启后仅输出建议日志，不改变提交顺序
- `--rl-advisor-shadow-topk`（默认 `4`）
  - 控制 shadow 建议输出数量

## 为什么不会影响现网主路径
- 所有新能力默认关闭：默认参数仍走 legacy 执行流程
- RL advisor 为 shadow-only，代码中明确 `applied=false`，不会写入状态或改变 commit 顺序
- 解耦路径开启后当前使用 `LegacyMempoolDaProvider + PreexecOrderingEngine`，语义与原路径保持一致
- 增加了最小单测：
  - 开关 off/on 在 happy path 上顺序一致
  - RL shadow 仅建议，不改变 baseline 顺序

## 后续演进建议
- DA 层替换为真实 external DA batch source（e.g. blob/certificate）
- Ordering 层接入可插拔策略（heuristic / RL policy）
- RL advisor 从规则占位升级为离线训练策略，并继续 shadow 验证后再灰度执行
