# Trillionnium MVP 里程碑清单（按天）

> 目标：7 天内拿到可演示、可复现、可验收的最小闭环（链上任务 + Worker 执行 + 结果验证 + 奖励/惩罚）

## Day 1 — 闭环骨架对齐
- [ ] 冻结最小任务协议字段：`task_id / image / input_uri / bounty / deadline / challenge_window`
- [ ] 确认链上状态流：`Created -> Assigned(Optional) -> Submitted -> Challenged(Optional) -> Finalized`
- [ ] Worker 侧统一执行规范：固定 Docker 运行参数（CPU/内存/超时）
- [ ] 定义 Demo 命令脚本入口（`scripts/demo_e2e.sh`）

交付物：
- 一页状态机图（可文本）
- 一份最小 protobuf/消息字段清单

## Day 2 — Create/Lock 与 Worker 拉取
- [ ] `create-task` 成功锁定赏金到模块账户
- [ ] Worker 可轮询链上待执行任务并拉取输入
- [ ] 执行前校验：镜像白名单 + 输入 hash 校验

交付物：
- CLI 演示：发布任务后可在 worker 日志看到拉取

## Day 3 — Submit/Verify/Fund Transfer
- [ ] Worker 提交 `result_hash + execution_metadata`
- [ ] 验证节点完成最小重放校验（同输入/同镜像/同约束）
- [ ] Finalize 后赏金转账给 worker，任务状态落盘

交付物：
- 从 `create-task` 到 `finalize` 的完整交易序列截图/日志

## Day 4 — 挑战与惩罚路径
- [ ] 实现 `challenge-result`（在 challenge window 内可提交挑战）
- [ ] 验证挑战成功时：任务转争议态 + worker 触发 slash
- [ ] 失败挑战处理：挑战者可选押金惩罚（可后续）

交付物：
- 一条恶意结果被挑战并处罚的可复现实验

## Day 5 — 解质押安全流
- [ ] `request-unbonding` 启动冷却
- [ ] 冷却期内禁止直接提取
- [ ] `finalize-unbonding` 到期后提取成功

交付物：
- Worker 生命周期（注册→工作→申请解质押→提取）日志

## Day 6 — 事件与可观测性
- [ ] 补齐结构化事件：task/worker/slash/unbonding 全链路
- [ ] 导出最小监控指标（任务成功率、平均完成时长、挑战率）
- [ ] 统一错误码/错误消息（便于前端与脚本消费）

交付物：
- 事件字典文档 + 1 份指标样例输出

## Day 7 — 演示彩排与发布包
- [ ] 一键演示脚本跑通（本地单机）
- [ ] 5 个验收场景全部通过（见 TEST_ACCEPTANCE_MATRIX.md）
- [ ] 输出 Alpha 说明：已支持/未支持/风险项

交付物：
- Alpha Demo 包：脚本 + 文档 + 日志

---

## DoD（本周完成定义）
1. 至少 1 条任务可无人工干预完成并结算。
2. 至少 1 条恶意结果能被挑战并触发惩罚。
3. 解质押流程存在冷却且无法绕过。
4. 所有关键步骤都有事件可追踪。
5. 新人按文档可在 30 分钟内复现 demo。
