# TrillionniumChain ROADMAP（两周冲刺）

更新日期：2026-02-20
策略：先稳内核，再接外设。

> 注：本文件保留为前一阶段（W1/W2）记录，不是当前 release readiness / truth source，也不应被解读为“今天已达到可发布基线”。
> 当前是否可发布、哪些 ready/GO 表述仍有效，请以仓库根 `RELEASE_READINESS.md` 为准。
> 下一阶段（P3→P5）执行路线见：
> - `docs/strategy/rust-l1-p3-p5-competitive-roadmap.md`
> - `docs/strategy/p3-week1-execution-plan.md`

---

## Sprint W1（本周）：可发布基线 + v1 接口冻结

### 目标
- 把当前代码与文档整理为“可发布、可审阅、可回滚”的基线。
- 冻结链上任务闭环 v1 的接口语义。

### 交付物
1. `STATUS.md`（当前状态与风险）
2. `BACKLOG.md`（P0/P1/P2）
3. 基线验收报告（测试摘要 + 脚本入口）
4. v1 接口冻结清单（Task 状态机 / 权限 / 事件字段）

### 关键动作
- A. 提交整理与推送
  - 按主题分组 commits，形成可审阅历史
- B. 测试与稳定性
  - workload 模块测试全跑
  - alpha acceptance 至少 1 轮全绿
- C. 文档一致性
  - README、protocol 文档、脚本帮助一致

### 完成标准（W1 DoD）
- `ahead` 清零或仅保留明确待审分支
- 关键测试可复现、结果可读
- v1 接口冻结并对齐 CLI/文档

---

## Sprint W2（下周）：Worker 最小接入 + Fraud Proof 框架

### 目标
- 建立最小可行的 Worker 上链执行闭环（生产视角）。
- 落地挑战重执行框架（先简版，不追求一次完美）。

### 交付物
1. Worker 接入规范 v1（提交/重试/幂等/故障恢复）
2. Challenge 重执行框架（入口、窗口、处理结果）
3. E2E smoke（含失败路径）

### 关键动作
- A. Worker 协议
  - 明确 `resultHash + execution metadata` 最小集
  - 标准化错误码与可观测字段
- B. Fraud Proof 最小闭环
  - 挑战入口
  - 重执行接口
  - 裁决回写与事件记录
- C. 运维保障
  - 异常脚本与 runbook 补齐

### 完成标准（W2 DoD）
- 至少 1 条完整 E2E 路径稳定通过（含挑战分支）
- 失败可诊断、可恢复（日志和事件字段足够）
- 对外可演示“可信 AI 计算闭环”

---

## 里程碑映射

- M1：可发布基线（W1 完成）
- M2：MVP 可信执行闭环（W2 完成）
- M3：测试网前运维化（后续迭代）
