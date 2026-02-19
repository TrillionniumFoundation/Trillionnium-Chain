# TrillionniumChain STATUS

更新日期：2026-02-19（14:10 CST）
负责人：齐教授 / 发发

## 1) 当前状态（可发布基线视角）

### 仓库状态
- 分支：`main`
- 相对远端：`ahead 14`（本地领先 14 个提交，尚未推送）
- 最新提交主题集中在：
  - PoUW v0.2 状态机与 CLI 闭环
  - Alpha 场景稳定性与验收脚本
  - 安全默认与 release guard
  - testnet 计划与治理模板文档

### 功能能力（当前可用）
- 已具备 PoUW v0.2 核心闭环：
  - `create -> accept -> commit -> reveal -> challenge -> resolve`
- 已具备关键安全与运维特性：
  - challenge/resolution 权限与路径稳定
  - unbonding guard 状态安全修复
  - release guard 基线
  - observability smoke 套件与文档
  - P1 negative suite（6 case）可稳定执行，支持 PASS/FAIL/SKIP 语义

### 已有文档资产
- `docs/protocol/pouw-v0.2-implementation-status.md`
- `docs/protocol/pouw-security-closure-v0.2-plan.md`
- `docs/alpha-runs/*`（验收矩阵、runbook、参数单）
- `docs/RELEASE_NOTE_2026-02-19.md`

## 2) 风险与缺口

### P0 风险（本周应收敛）
1. 本地 14 commits 未推送，协作可见性不足。
2. `UpdateTask` 退役/收敛策略仍需明确（避免接口混用）。
3. 状态机“全迁移矩阵”自动化测试仍可加强（已有局部覆盖）。

### P1 风险（下周处理）
1. 升级迁移脚本与运维指南需进一步固化（测试网前置项）。
2. Worker 与链上 commit/reveal 的生产级对接协议（重试、幂等、失败恢复）需最终冻结。
3. challenge_path 依赖 challenger 可用押金余额；需在 dev profile 与 prod-like profile 间明确参数策略，避免误判（PASS/FAIL/SKIP）。

## 3) 最新验收结果（2026-02-19）

- `scripts/p0_merge_gate.sh`：通过（5/5）
- `scripts/p1_negative_suite.sh`：通过（`total=6 pass=6 fail=0 skip=0`）
- 结果样本：
  - `data/p0-acceptance/20260219-124434/summary.json`
  - `data/p1-negative/20260219-140336/summary.json`

## 4) 立即执行建议（下一步）

1. 完成一次“基线验收包”输出：
   - 测试结果摘要（通过/失败/Flaky）
   - 关键脚本入口映射
   - 对外可讲的一页状态说明
2. 将当前 14 commits 做逻辑分组后推送（保持可审阅）。
3. 冻结 v1 闭环接口约束：Task 状态、权限边界、事件字段。

## 5) Dry-run 演练结果（2026-02-19 16:44~16:49）

- 演练目录：`data/upgrade-runs/20260219-164421`
- 首轮（chain down）：`pre p0=0/p1=1`，`post p0=0/p1=1`
- 修复动作：启动本地链（`./build/chaind start --home ~/.chain --minimum-gas-prices 0stake`）
- 复跑结果：`pre_p1=0`、`snapshot_diff=0`、`post_p1=0`（见 `rerun-summary.txt`）
- 结论：P1-1 升级演练流程已具备可执行样本，可进入“发布前标准门禁”阶段。

## 6) 今日压缩推进（2026-02-19 晚间）

- CI：已新增 `trnm-merge-gates` 与 `trnm-gate-quick-check`；quick-check 已调整为 `shellcheck -S error`，避免非阻塞告警导致红灯。
- 升级演练：`data/upgrade-runs/20260219-164421` 已形成可审计样本。
- 治理收口：新增 `docs/protocol/legacy-submit-result-deprecation-plan-v0.3.0.md`（announce/canary/full + 硬回滚阈值）。
- 稳定性收敛：`scripts/p0_acceptance.sh` 增加一步重试（3s backoff）以降低链启动瞬时竞态误报。
- 最新回归样本：
  - P0：`data/p0-acceptance/20260219-170905/summary.json`（5/5）
  - P1：`data/p1-negative/20260219-171027/summary.json`（6/6，skip=0）

## 7) 临时门禁策略（方案 B，已执行）

- 已新增：`docs/MANUAL_MERGE_GATE_CHECKLIST.md`
- 适用条件：私有仓库当前无法启用 GitHub required checks（平台套餐限制）。
- 执行要求：合并前必须附 P0/P1 summary 证据（P0 fail=0；P1 fail=0 & skip=0）+ quick gate 通过记录。

## 8) Rust 旁路 PoC（新增）

- 新增 `rust/verifier`：commitment 校验 sidecar（输入 task_id/result_hash/reveal_salt/worker_address/committed_hash）。
- 新增 fixtures：`match.json` / `mismatch.json`。
- 新增本地入口：`scripts/run_rust_verifier_poc.sh`。
- 新增 CI：`.github/workflows/rust-verifier-poc.yml`（build + test + fixture verification）。
- 文档：`docs/protocol/rust-verifier-poc.md`。

## 9) Rust 旁路接入进展（执行中）

- 已在场景脚本输出结构化标记：`[VERIFIER_INPUT] {...}`
  - `scripts/scenario_C_challenge.sh`
  - `scripts/scenario_F_forged_reveal.sh`
  - `scripts/scenario_G_duplicate_reveal.sh`
- 新增导出脚本：`scripts/export_verifier_inputs.sh`
  - 最新导出：`data/verifier-input/20260219-180016`（3 条）
- 已完成 Rust 批量复验：`data/rust-verifier-local/20260219-180016`
  - `scenario_C/F/G` 均 `matched=true`
- 已将 Rust 旁路串入 P1 套件（可选）：`WITH_RUST_VERIFY=1 ./scripts/p1_negative_suite.sh`
  - 最新样本：`data/p1-negative/20260219-180412/summary.json`
  - 结果：`pass=6 fail=0 skip=0`，`rust_verify_matched=3 mismatch=0`
- 已将 `p0_merge_gate.sh` 默认接入 Rust 旁路链路（默认 `WITH_RUST_VERIFY=1` 后置执行 P1+verifier）。
  - 备注：当前 P0 前置阶段存在本地序列/提交竞态（`smoke_pouw_cli_flow`、`worker_reconcile_smoke`），导致 gate 在进入 P1 前失败，需先修复稳定性。

## 10) Definition of Done（本轮）

- [ ] 所有 P0 项均有 owner 与截止时间
- [ ] 关键测试可一键复现（命令固定）
- [ ] `main` 与 `origin/main` 对齐（或仅保留明确的待审 PR）
- [ ] v1 闭环接口冻结并文档化

## 6) P1-1 Dry-run 演练结果（2026-02-19 16:44 CST）

- 演练目录：`data/upgrade-runs/20260219-164421`
- Checklist 流程已执行：run_id 初始化、pre/post 快照采集、gate 复跑、diff 归档。
- gate 结果：
  - pre: `p0_rc=0`, `p1_rc=1`
  - post: `post_p0_rc=0`, `post_p1_rc=1`
- 阻塞原因：本地链未启动（`127.0.0.1:26657 connection refused`），`p1_negative_suite` 在 preflight 主动终止，避免误报。
- 结论：流程脚手架可用；待链恢复后需补一次“全绿 dry-run（含 p1=0）”以达成 P1-1 验收。
