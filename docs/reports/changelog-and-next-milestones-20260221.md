# Trillionnium Rust L1 — Changelog & Next Milestones

日期：2026-02-21  
范围：面向当前外部同步（工程进展 + 下一阶段计划）

## 1) Changelog（since 2026-02-20）

### A. 共识 / 治理 / 生态主线从脚手架到可执行
- 共识侧：
  - `trnm-node` 增加 finality/recovery 指标与 preflight gate。
  - `run_consensus_fault_matrix.sh` 升级为可执行 3 场景矩阵。
- 治理侧：
  - 提案最小状态机落地，非法迁移拦截。
  - 参数白名单更新路径落地。
  - `emergency_pause` + node 侧高风险交易拒绝逻辑落地。
- 生态侧：
  - `trnm-rpc` 稳定查询 schema 持续切换到 state/event-backed。
  - 开发者 onboarding + examples + smoke 已补齐。
  - 生态反馈台账闭环（录入脚本 + 追踪链路）。

### B. Worker-Agent 进入“可门禁、可审计”阶段
- 新增 `trnm-worker-agent` crate：
  - `run-once` / `flush-submissions` / commit-reveal 执行链路。
- adapter 升级为双模式：`mock` / `command`。
- 回执语义强化：
  - `ack` 记录 `commit_tx_hash` / `reveal_tx_hash`。
  - replay 拒绝（`rc=9`）与 nonce 单调拒绝（`rc=10`）被明确定义为终态语义。

### C. 自动化与门禁收口
- codegen relay 扩展至 21 步，并持续全绿。
- merge/nightly 默认启用 strict real-cli 路线（可临时回退开关）。
- 新增并稳定运行：
  - `run_worker_receipt_gates.sh`
  - `run_worker_receipt_gates_real_cli.sh`

### D. 原生 CLI 里程碑
- 新增 `trnm-cli` crate，提供：
  - `tx commit-result`
  - `tx reveal-result`
  - `query`
- strict gate 可直接使用 Rust 原生 CLI 实跑通过：
  - `TRNM_TX_CLI=./trillionnium-rust/target/debug/trnm-cli`

### E. 今日补充验证（本轮执行）
- strict real-cli 全门禁通过。
- worker-agent 异常注入边界回归通过：
  - 重试/backoff 生效（注入两次失败后成功）。
  - replay guard：`rc=9`。
  - nonce monotonic guard：`rc=10`。

---

## 2) 当前对外状态（一句话版）

Rust L1 已从“核心协议实现”推进到“worker 回执链路可硬门禁验收”，并完成 strict real-cli 默认化，具备对外展示“可执行、可审计、可回放”的工程成熟度。

---

## 3) Next Milestones（建议 7~10 天）

### M1（D+2）：发布面固化
- 交付：
  - 对外 Release Note（中文/英文双语简版）
  - 关键门禁矩阵图（哪些是 hard gate、哪些是 advisory）
- DoD：
  - 任何 reviewer 可在 10 分钟内复现 strict gate 最小路径。

### M2（D+4）：异常恢复能力增强
- 交付：
  - worker-agent 异常矩阵扩展（网络抖动/局部超时/部分 ack 丢失）。
  - 失败恢复 runbook（按 rc 分类操作指南）。
- DoD：
  - “失败可恢复”路径有脚本化证据与日志样本。

### M3（D+7）：对外演示包 v1
- 交付：
  - 一键 demo 脚本（含 commit/reveal/challenge/resolve + worker receipt）。
  - 演示证据包（日志、摘要、关键 tx_hash 索引）。
- DoD：
  - 在全新环境可一键跑通并导出演示报告。

### M4（D+10）：测试网前门禁审计
- 交付：
  - nightly/merge gate 的阈值审计与冻结清单。
  - 需要 owner override 的场景白名单。
- DoD：
  - 门禁策略从“经验驱动”升级为“规则驱动 + 审计留痕”。

---

## 4) 建议对外措辞（可直接复用）

> Trillionnium Rust L1 has completed strict worker receipt gating with real CLI execution, including replay and nonce-monotonic safety semantics. The stack now demonstrates auditable commit/reveal operations with deterministic recovery paths, moving from feature completion to operational hardening.
