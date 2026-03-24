# TrillionniumChain BACKLOG

更新日期：2026-02-20

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

### P1-0 负向回归套件固化 ✅（已完成 2026-02-19）
- 描述：落地 `scripts/p1_negative_suite.sh`，并引入 PASS/FAIL/SKIP 统计语义，覆盖关键对抗路径。
- 产出：
  - `scripts/p1_negative_suite.sh`
  - `docs/P1_NEGATIVE_COVERAGE.md`
  - 新增脚本：`scenario_F_forged_reveal.sh`、`scenario_G_duplicate_reveal.sh`
- 最新结果：`total=6 pass=6 fail=0 skip=0`（`data/p1-negative/20260219-140336/summary.json`）
- Owner：发发

### P1-1 Upgrade/Migration 文档与脚本（进行中）
- 描述：补齐测试网前升级迁移路径。
- 产出：
  - `docs/protocol/upgrade-migration-v1.md`（已完成首版参数迁移草案）
  - `docs/UPGRADE_MIGRATION_CHECKLIST.md`（可执行 checklist）
- 验收：
  - 有明确 upgrade checklist
  - 参数迁移和兼容策略可执行

### P1-2 Worker 生产级对接规范 ✅（已完成 2026-02-21）
- 描述：冻结 worker 提交协议（重试、幂等、失败恢复）。
- 产出：`docs/protocol/worker-onchain-integration-v1.md`
- 最新进展（2026-02-21）：
  - `trnm-worker-agent` ack 记录新增 `commit_tx_hash/reveal_tx_hash`。
  - `scripts/v2/worker_agent_verify_with_rpc.sh` 新增 tx_hash 非空 hard-check。
  - `scripts/v2/worker_agent_full_loop.sh` 透传 `ACK_LOG` 并纳入 tx_hash 验证。
  - CI 硬门禁已接入：
    - `.github/workflows/rust-l1-nightly-health.yml`
    - `.github/workflows/trnm-merge-gates.yml`
  - codegen relay 20-step 实跑全绿（含 `worker_agent_full_loop` / `worker_replay_guard_test`）。
- 验收：
  - 失败路径可重放
  - 日志字段可用于定位
  - 回执 tx_hash 字段可追踪且为门禁必检

### P1-3 Challenge 重执行框架（简版，进行中）
- 最新进展（2026-02-20）：补齐可执行模板脚本 `scripts/challenge_reexec_resolve_template.sh` 与 smoke `scripts/challenge_reexec_template_smoke.sh`，可一键生成 authority 回写命令模板。
- 描述：实现挑战后的最小重执行闭环。
- 产出：`docs/protocol/challenge-reexecution-framework-v0.1.md`、`scripts/challenge_reexec_resolve_template.sh`
- 验收：
  - 挑战入口可触发
  - 重执行结果可回写裁决

---

## P2（增强项）

### P2-1 观测增强 ✅（已完成 2026-02-20）
- 描述：按 task_id / trace_id 聚合资金流与状态演进，提升排障效率。
- 完成项：
  - reexec 模板与 e2e summary 已引入 trace_id 贯穿字段；worker listener 提交链路日志已输出 trace_id。
  - nightly regression matrix 新增 `strategy_source=default|experiment` 标注。
  - nightly summary 输出 `strategy_source` 聚合标签，避免实验结果与默认口径混淆。
- 验收：default / experiment 双口径 regression matrix 已分别产出并完成 summary 渲染。

### P2-2 经济参数边界回归
- 描述：补足 challenger/worker 参数边界测试（压力与极值）。

### P2-3 Demo 资产整理（进行中）
- 描述：对外演示脚本、话术、样例任务模板标准化。
- 最新进展（2026-02-20）：新增 `scripts/demo_storyline.sh` 与 `docs/demo/rust-l1-demo-runbook-v1.md`，形成可重复的一键演示流程。

### P2-4 Aggressive 实验治理收口 ✅（已完成 2026-02-20）
- 描述：完成 Aggressive Round3 的 Week1~Week2 实验收口与治理闭环。
- 结果：
  - 默认快路径稳定（与 Original 收敛，代表场景约 0.97x~1.00x）。
  - deep-scan / hotspot 重排结论均为 No-Go，保留实验态隔离。
  - nightly 回归阈值已收紧并通过本地验证。
- 参考文档：
  - `docs/perf/aggressive-round3-week1-report.md`
  - `docs/perf/aggressive-week2-day4-decision-memo.md`
  - `docs/perf/aggressive-week2-day5-summary.md`

### P2-4 Aggressive 实验治理收口 ✅（已完成 2026-02-20）
- 描述：完成 Aggressive Round3 的 Week1~Week2 实验收口与治理闭环。
- 结果：
  - 默认快路径稳定（与 Original 收敛，代表场景约 0.97x~1.00x）。
  - deep-scan / hotspot 重排结论均为 No-Go，保留实验态隔离。
  - nightly 回归阈值已收紧并通过本地验证。
- 参考文档：
  - `docs/perf/aggressive-round3-week1-report.md`
  - `docs/perf/aggressive-week2-day4-decision-memo.md`
  - `docs/perf/aggressive-week2-day5-summary.md`

---

## 下阶段执行顺序（建议）
1. P2-1 观测增强（nightly 策略来源标签 + summary 口径收敛）
2. P1-3 Challenge 重执行框架完善（从模板到可执行闭环）
3. P1-2 Worker 生产级对接规范冻结
4. P2-3 Demo 资产整理（对外叙事与样例统一）
