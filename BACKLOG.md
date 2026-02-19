# TrillionniumChain BACKLOG

更新日期：2026-02-19

---

## P0（必须优先，阻塞发布/协作）

### P0-1 提交基线整理与推送 ✅（已完成 2026-02-19）
- 描述：将本地 ahead 14 commits 按主题整理并推送，确保团队可见、可审阅。
- 验收：
  - `git status` 干净
  - `git log --oneline origin/main..main` 为空或仅保留明确待审分支
- Owner：齐教授 / 发发

### P0-2 v1 状态机与接口冻结 ✅（已完成 2026-02-19）
- 描述：冻结 `Task` 状态机、权限边界、事件字段（含 CLI 映射）。
- 验收：
  - 文档与实现一致
  - 关键命令帮助文本一致
  - 兼容路径（legacy submit-result）有明确退役说明
- Owner：发发

### P0-3 一键验收入口 ✅（已完成 2026-02-19）
- 描述：给出标准化验收入口（脚本+预期输出），避免“靠经验跑”。
- 验收：
  - 单命令可跑关键 acceptance
  - 输出包含通过/失败摘要与定位信息
- Owner：发发

---

## P1（重要但不阻塞本轮基线）

### P1-1 Upgrade/Migration 文档与脚本
- 描述：补齐测试网前升级迁移路径。
- 验收：
  - 有明确 upgrade checklist
  - 参数迁移和兼容策略可执行

### P1-2 Worker 生产级对接规范（进行中）
- 描述：冻结 worker 提交协议（重试、幂等、失败恢复）。
- 产出：`docs/protocol/worker-onchain-integration-v1.md`
- 验收：
  - 失败路径可重放
  - 日志字段可用于定位

### P1-3 Challenge 重执行框架（简版，进行中）
- 描述：实现挑战后的最小重执行闭环。
- 产出：`docs/protocol/challenge-reexecution-framework-v0.1.md`、`scripts/challenge_reexec_resolve_template.sh`
- 验收：
  - 挑战入口可触发
  - 重执行结果可回写裁决

---

## P2（增强项）

### P2-1 观测增强（进行中）
- 描述：按 task_id / trace_id 聚合资金流与状态演进，提升排障效率。
- 当前进展：reexec 模板与 e2e summary 已引入 trace_id 贯穿字段。

### P2-2 经济参数边界回归
- 描述：补足 challenger/worker 参数边界测试（压力与极值）。

### P2-3 Demo 资产整理
- 描述：对外演示脚本、话术、样例任务模板标准化。

---

## 本周执行顺序（建议）
1. P0-1 提交整理与推送
2. P0-2 v1 接口冻结
3. P0-3 一键验收入口
4. 启动 P1-2（并行预研）
