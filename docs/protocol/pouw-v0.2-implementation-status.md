# PoUW v0.2 实现对照表（2026-02-18）

> 目的：把 v0.2 设计目标与当前链上实现逐项对齐，方便研发/测试/运维同步。

## 总览

- ✅ 已实现（核心闭环）：状态常量收敛、`AcceptTask` 接单、commit/reveal、挑战与裁决、资金流审计事件、可替换 DisputeResolver、状态迁移守卫、细粒度错误码、关键测试。
- 🟡 部分实现：任务状态机语义已增强，但尚未引入独立 `COMMITTED/REVEALED` 枚举状态值（当前以字段驱动）。
- ⏳ 待实现：状态机矩阵测试补完、迁移脚本与升级文档、文档与实现字段完全一致化。

---

## 1) 状态机与状态常量

| 项目 | 目标 | 当前状态 | 备注 |
|---|---|---|---|
| 去裸数字状态 | 统一常量 | ✅ 已实现 | `types.TaskStatus*`, `types.ChallengeStatus*` 已接管 keeper 逻辑 |
| 扩展完整状态机 | `OPEN -> ASSIGNED -> COMMITTED -> REVEALED -> CHALLENGED -> FINALIZED` | 🟡 部分实现 | 当前已引入 `ASSIGNED`；仍用 `RESULT_SUBMITTED` 承载 reveal 后状态 |
| 状态迁移守卫 | 全迁移可校验 | ✅ 已实现 | 已有集中守卫与迁移白名单（keeper 统一校验） |

---

## 2) Commit-Reveal

| 项目 | 目标 | 当前状态 | 备注 |
|---|---|---|---|
| MsgAcceptTask | 显式接单并绑定 worker | ✅ 已实现 | OPEN -> ASSIGNED |
| MsgCommitResult | 支持结果承诺 | ✅ 已实现 | 需 ASSIGNED worker 提交 |
| MsgRevealResult | 支持揭示与哈希校验 | ✅ 已实现 | `sha256(taskID|resultHash|salt|worker)` 校验 |
| 兼容 SubmitResult | 参数开关控制 | ✅ 已实现 | `allow_legacy_submit_result` |
| reveal 超时恢复 | commit 过期回收 | ✅ 已实现 | `AutoRecoverExpiredCommits` |

---

## 3) 挑战与裁决

| 项目 | 目标 | 当前状态 | 备注 |
|---|---|---|---|
| ChallengeResult | 挑战期 + 保证金 | ✅ 已实现 | 含挑战窗口校验与保证金转入 |
| ResolveChallenge | 仅 authority 裁决 | ✅ 已实现 | 保持治理权限模型 |
| 裁决解耦 | 可替换仲裁器接口 | ✅ 已实现 | `DisputeResolver` + 默认 `authorityResolver` |
| 注入可测性 | 自定义 resolver 测试 | ✅ 已实现 | 已有注入测试与 nil 回退测试 |

---

## 4) 资金流审计事件

| 项目 | 目标 | 当前状态 | 备注 |
|---|---|---|---|
| 标准化事件 | `workload_fund_flow` | ✅ 已实现 | 字段：task_id/from/to/amount/denom/reason |
| 覆盖关键 reason | `bounty_lock/challenge_* /worker_slash/task_burn` | ✅ 已实现 | 且有测试断言 |

---

## 5) 参数与兼容迁移

| 项目 | 目标 | 当前状态 | 备注 |
|---|---|---|---|
| 新增 params | reveal window + legacy 开关 | ✅ 已实现 | `reveal_window_blocks`, `allow_legacy_submit_result` |
| 默认值与校验 | 参数可安全落地 | ✅ 已实现 | params.go + tests 已更新 |
| 链升级迁移脚本 | 兼容既有状态 | ⏳ 待实现 | 若上测试网/主网前需要补 |
| 细粒度错误码 | 状态/worker/挑战窗口错误可机读 | ✅ 已实现 | `ErrInvalidTaskStateTransition/ErrWorkerMismatch/ErrChallengeWindow*` |

---

## 6) 测试覆盖

| 项目 | 目标 | 当前状态 | 备注 |
|---|---|---|---|
| commit/reveal 正反路径 | 通过 + 错误分支 | ✅ 已实现 | 包含 hash mismatch/未授权 worker |
| challenge resolve 分支 | 成功/失败路径 | ✅ 已实现 | 既有测试持续通过 |
| 超时恢复 | reveal 超时清理 | ✅ 已实现 | `task_timeout_recovery_test.go` |
| 资金流事件 | reason 不回归 | ✅ 已实现 | `fund_flow_event_test.go` |
| 状态机守卫单测 | 迁移白名单正确性 | ✅ 已实现 | `task_state_transition_test.go` |
| 状态机全表测试 | 所有迁移矩阵 | ⏳ 待实现 | 建议补 `task_state_machine_test.go` |

---

## 7) 未完成项（建议优先级）

### P0（建议下一迭代）
1. 将 commit/reveal 对应到独立状态值（或完善注释规范）
2. 增加状态机矩阵测试（覆盖所有非法迁移）
3. 把 deprecated `UpdateTask` 限制为更窄内部用途

### P1
1. 迁移脚本与升级说明
2. 观察性增强（按 task_id 汇总资金流）
3. 增加 challenger/worker 经济参数边界回归测试

### P2
1. 迁移脚本与升级说明
2. 观察性增强（按 task_id 汇总资金流）

---

## 8) 结论

当前实现已经具备 **PoUW v0.2 的可运行安全闭环**：
- 有承诺揭示、
- 有挑战裁决、
- 有惩罚与资金流审计、
- 并支持后续替换仲裁器。

下一阶段重点应从“功能可用”转向“状态机严格化 + 升级可运维化”。
