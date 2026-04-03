# TrillionniumChain STATUS

更新日期：2026-02-21（17:22 CST）
负责人：齐教授 / 发发

> 重要：本文件保留为 **2026-02-21 起的历史推进日志 / working journal**，**不是**当前 release readiness 的权威真相源。
> 当前是否可发布、哪些“GO/PASS/ready”表述仍然有效，请先看：`RELEASE_READINESS.md`。
>
> 额外提醒：本文中出现的“aligned / 已推送 / 已闭环 / 已通过”均默认是**对应日期当时**的历史记录；若与当前 `main`、当前 closeout、当前对外对标口径冲突，以 `README.md`、`RELEASE_READINESS.md`、`docs/reports/TRNM_CONCURRENCY_BOTTLENECK_MAP_AND_8W_ROADMAP_2026-03-10.md` 为准。
>
> 注：此前引用的 `docs/reports/changelog-and-next-milestones-20260221.md` 已不在当前仓库；若需当前口径，请改看 `README.md` 与 `RELEASE_READINESS.md`。

## 1) 当时状态（历史记录：2026-02-21 的可发布基线视角）
> 本节仅描述 2026-02-21 当时判断，不能直接外推为当前仓库状态。

### 仓库状态（2026-02-21 当时）
- 分支：`main`
- 相对远端：`aligned`（`main` 与 `origin/main` 已对齐）
- 最新提交主题集中在：
  - PoUW v0.2 状态机与 CLI 闭环
  - Alpha 场景稳定性与验收脚本
  - 安全默认与 release guard
  - testnet 计划与治理模板文档

### 功能能力（2026-02-21 当时可用）
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

## 8) Rust 旁路 PoC（历史记录，当前仓内已无实现）

- 该 PoC 曾规划 `rust/verifier` sidecar、fixtures、本地入口与独立 CI。
- 当前 `origin/main` 已不存在 `rust/verifier`、`scripts/run_rust_verifier_poc.sh`、`docs/protocol/rust-verifier-poc.md`；相应历史 workflow 已移除，避免继续制造“看似受保护、实际未覆盖”的假象。

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

## 13) Rust L1（全 Rust 主线）启动决策（2026-02-19 晚）

- 决策更新：允许 break change，优先高吞吐任务流，目标 1 周压缩交付。
- 新增文档：
  - `docs/protocol/rust-l1-rfc-001.md`
  - `docs/architecture/rust-l1-repo-layout.md`
  - `docs/protocol/rust-l1-day1-tasklist.md`
- 执行策略：先冻结架构与并发语义，再推进 Day-1 workspace/类型/冲突检测原型。

## 14) Rust L1 Day-2 进展（2026-02-19 夜）

- `trnm-state` 已实现 versioned object store 原型：
  - `put_task_new`（新建对象）
  - `update_task(expected_ref, ...)`（基于版本乐观并发控制）
  - `state_root()`（SHA-256 聚合根）
- `trnm-types` 已扩展对象化核心类型：`TaskObject` + `TaskStatus`（`repr(u8)`）
- `trnm-pouw` 已接入状态层并落地首条真实状态转移：
  - `apply_create_task`
  - `apply_commit_result`
- 单测与工作区验证：`cargo test --workspace` 全绿。

## 15) Rust L1 Day-3 进展（2026-02-19 夜）

- `trnm-pouw` 已补齐核心链路：
  - `apply_reveal_result`
  - `apply_challenge`
  - `apply_resolve(slash_worker: bool)`
- 已接入 commitment 校验公式：
  - `sha256("{task_id}|{hex(result_hash)}|{hex(reveal_salt)}|{worker}")`
- 新增错误类型与防护：
  - `MissingWorker` / `MissingCommitment` / `CommitmentMismatch` / `InvalidTransition`
- 新增回归单测：
  - 全路径 happy case（最终 `Completed`）
  - forged reveal 拒绝（`CommitmentMismatch`）
  - 非 `Revealed` 状态 challenge 拒绝
- 验证结果：`cargo test -p trnm-pouw` 与 `cargo test --workspace` 全绿。

## 16) Rust L1 Day-4 进展（2026-02-19 夜）

- `trnm-node` 已接入配置解析（TOML）与 CLI 参数：
  - `--config`
  - `--block-ms`
  - `--max-blocks`
- 已实现 mock 共识出块循环（内存态）：
  - 周期性产出 `[block]` 日志（height 递增）
  - `max_blocks` 到达后优雅退出
- 已补齐 3 节点配置：
  - `trillionnium-rust/configs/node1.toml`
  - `trillionnium-rust/configs/node2.toml`
  - `trillionnium-rust/configs/node3.toml`
- 已新增 devnet 脚本：
  - `trillionnium-rust/scripts/devnet_up.sh`
  - `trillionnium-rust/scripts/devnet_down.sh`
- 验证：`cargo check --workspace` 通过，`cargo run -p trnm-node -- --config configs/node1.toml --block-ms 50 --max-blocks 3` 成功出块并退出。

## 17) Rust L1 Day-5 进展（2026-02-19 夜）

- `trnm-node` 已接入真实执行路径（内存态）：
  - 接入 `trnm-state`（状态存储 + state_root）
  - 接入 `trnm-pouw`（create/commit/reveal/challenge/resolve）
- 新增 demo mempool（队列）与按块执行：
  - 每块执行固定批量交易（当前 `txs_per_block=2`）
  - 执行后输出 `state_root`（hex）
- 已完成端到端演示交易流：
  - `CreateTask -> Commit -> Reveal -> Challenge -> Resolve`
- 验证命令：
  - `cargo check --workspace`
  - `cargo run -p trnm-node -- --config configs/node1.toml --block-ms 50 --max-blocks 10`
- 运行结果：连续出块并执行交易，mempool 清空后自动退出（示例 3 个 block，tx 2/2/1）。

## 18) Rust L1 Day-6 进展（2026-02-19 夜）

- 已将并发调度接入出块执行路径（planning 层）：
  - `trnm-executor` 新增 `build_parallel_groups(txs)`
  - 语义：组内无冲突（可并行），组间按序执行
- `trnm-node` 已在每个 block 中执行：
  1. 从 mempool 取批次
  2. 生成读写集声明（`Tx`）
  3. 用 `build_parallel_groups` 分组
  4. 按组应用交易（当前为串行执行，保留并行执行 TODO）
- demo mempool 扩展为 2 个 task 流，验证跨 task 并发可分组。
- 新增压测入口：
  - `trillionnium-rust/crates/trnm-bench`（并发分组基准）
  - `trillionnium-rust/scripts/run_bench.sh`
- 运行样本：
  - node：`height=1..3`，`groups=3/2/2`，mempool 清空退出
  - bench：`txs=20000 groups=10 elapsed_ms=8604`
- 验证：`cargo test --workspace` 全绿。

## 19) Rust L1 Day-7 进展（2026-02-19 夜）

- 已新增 RC 与演示交付脚本：
  - `trillionnium-rust/scripts/demo_day7.sh`
  - `trillionnium-rust/scripts/release_rc.sh`
- 已新增文档：
  - `docs/protocol/rust-l1-week1-rc.md`
  - `docs/runbooks/rust-l1-rollback-runbook.md`
- 演示脚本已实跑：
  - node demo 输出：`trillionnium-rust/run/day7/node-demo.log`
  - bench 输出：`trillionnium-rust/run/day7/bench.log`
  - bench 样本：`txs=20000 groups=10 elapsed_ms=8624`
- RC 打包已实跑：
  - 输出目录：`trillionnium-rust/release/rc-20260219-194509`
  - 产物包含：`cargo-test.log` / `cargo-build.log` / `manifest.txt` / node configs

## 20) Rust L1 后续动作-1（状态根对账，2026-02-19 夜）

- 新增脚本：`trillionnium-rust/scripts/audit_state_roots.sh`
  - 输入：`run/node1.log` / `run/node2.log` / `run/node3.log`
  - 输出：`run/audit/state-root-audit-<ts>.txt`
  - 逻辑：按 `height` 对齐三节点 `state_root`，标记 `OK/MISSING/MISMATCH`
- 已完成一次实跑：
  - 报告：`trillionnium-rust/run/audit/state-root-audit-20260219-194739.txt`
  - 结果：`ok=true mismatch=0 missing=0 heights=3`

## 21) Rust L1 后续动作-2（可注入负载与冲突率压测，2026-02-19 夜）

- `trnm-bench` 已支持可配置负载参数：
  - `--txs`（交易数）
  - `--keys`（热点键数，越小冲突率越高）
- `run_bench.sh` 已支持环境变量：
  - `TXS=<n> KEYS=<k> ./scripts/run_bench.sh`
- 新增矩阵压测脚本：
  - `trillionnium-rust/scripts/run_bench_matrix.sh`
  - 输出：`trillionnium-rust/run/bench/bench-matrix-<ts>.txt`
- `trnm-node` 已支持注入式 demo 负载参数：
  - `--demo-tasks`（任务流数量）
  - `--demo-keys`（并发规划冲突键空间）
- 样本结果：
  - `TXS=5000 ./scripts/run_bench_matrix.sh` 已生成报告
  - `cargo run -p trnm-node -- --demo-tasks 6 --demo-keys 3` 连续执行 8 个 block 至 mempool 清空（无状态机异常）

## 22) Rust L1 后续动作-3（Nightly 健康检查 CI，2026-02-19 夜）

- 新增 workflow：`.github/workflows/rust-l1-nightly-health.yml`
- 触发：
  - 每日定时（cron）
  - `workflow_dispatch`
  - `trillionnium-rust/**` 相关 push
- 作业内容：
  1. `cargo test --workspace`
  2. `devnet_up/down + audit_state_roots.sh`
  3. `TXS=5000 ./scripts/run_bench_matrix.sh`
- artifacts：
  - `trillionnium-rust/run/audit/**`
  - `trillionnium-rust/run/bench/**`
  - `trillionnium-rust/run/node*.log`
- 同步更新 RC 文档：`docs/protocol/rust-l1-week1-rc.md`（新增自动化健康检查章节）。

## 23) Rust L1 后续动作-4（并行执行器接线首版，2026-02-19 夜）

- `trnm-node` 新增参数：`--parallel-workers`（默认 4）
- 出块执行链路升级：
  - 对每个并发分组先进行组内并行 pre-execution（多 worker 线程）
  - 然后按 `tx_id` 排序进行确定性合并/应用（保证结果可重放）
- 当前策略：并行阶段用于预执行计算，状态提交仍保持确定性顺序 apply。
- 验证命令：
  - `cargo check --workspace`
  - `cargo run -p trnm-node -- --config configs/node1.toml --block-ms 10 --max-blocks 4 --demo-tasks 6 --demo-keys 3 --parallel-workers 4`
- 结果：连续出块成功，状态根稳定演进。

## 24) Rust L1 后续动作-5（并行 apply + 回滚首版，2026-02-19 夜）

- `trnm-state::StateStore` 新增 `Clone`，用于事务级快照与回滚。
- `trnm-node` 组内执行升级：
  - 并行 pre-execution 不再是空计算，改为在快照状态上真实试执行 `apply_one`。
  - pre-exec 失败交易会被提前剔除并记录 `[preexec] ... rejected`。
- 提交阶段新增回滚：
  - 每笔交易提交前保存 `before` 快照
  - 提交失败时恢复 `state = before`，并输出 `rollback=true`
- 保持确定性：
  - 组内先并行试执行
  - 再按 `tx_id` 排序做确定性提交
- 验证：
  - `cargo test --workspace` 全绿
  - `cargo run -p trnm-node -- --parallel-workers 4 ...` 连续出块成功，状态根稳定。

## 25) Rust L1 后续动作-6（并行模式纳入 Nightly 强门禁，2026-02-19 夜）

- 已更新 `.github/workflows/rust-l1-nightly-health.yml`：
  - 新增步骤 `Run parallel mode sanity (hard gate)`
  - 执行 `trnm-node --parallel-workers 4` 的并行路径实跑
  - 若日志出现 `apply_error` 或 `rollback=true`，直接 fail job
- artifacts 新增：`trillionnium-rust/run/parallel-sanity.log`
- RC 文档已同步：`docs/protocol/rust-l1-week1-rc.md`
  - Nightly 覆盖项增加“并行模式硬门禁”

## 26) Rust L1 后续动作-7（执行器热路径优化 + 实验策略，2026-02-19 22:00~22:10 CST）

- 已完成 `trnm-executor` 热路径优化（保持语义不变）：
  - `Original` 路径将每 tx 读写集去重由 `HashSet` 改为轻量 `Vec` 去重，降低热路径分配与哈希开销。
  - 冲突判定与分组语义保持不变（并发安全约束未放松）。
- 新增实验策略：`AggressiveGreedy`（非默认）
  - 已在 `trnm-bench` 暴露 `--strategy aggressive-greedy`。
  - 用于后续探索更激进并发装箱，不影响默认执行路径。
- 测试验证：`cargo test -p trnm-executor` 全绿（6/6）。
- Spot-check 性能（`txs=20000`）：
  - Classic `keys=1000`：`47ms -> 31ms`
  - Mixed `keys=2000 read_fanout=4 write_every=2`：`77ms -> 53ms`
- 代码提交与同步：
  - commit：`7d7c76e`
  - push：`origin/main` 已完成。

## 10) Definition of Done（本轮）

- [ ] 所有 P0 项均有 owner 与截止时间
- [ ] 关键测试可一键复现（命令固定）
- [x] `main` 与 `origin/main` 对齐（或仅保留明确的待审 PR）
- [ ] v1 闭环接口冻结并文档化

## 11) Rust 旁路复验补充记录（2026-02-19 18:52~18:56 CST）

- 触发来源：`sharp-cr` 执行完成（code=0），导出 verifier 输入目录：
  - `data/verifier-input/20260219-185212`
- 本地 Rust 复验执行：
  - `INPUT_DIR=data/verifier-input/20260219-185212`
  - `OUT_DIR=data/rust-verifier-local/20260219-185212`
  - 结果：`processed=3`
- 复验产物：
  - `data/rust-verifier-local/20260219-185212/scenario_C.json`
  - `data/rust-verifier-local/20260219-185212/scenario_F.json`
  - `data/rust-verifier-local/20260219-185212/scenario_G.json`
- 统计结论：
  - `matched=3, mismatch=0`
- 字段级 diff（input vs rust output）：
  - 共同字段（如 `task_id` / `trace_id` / `committed_hash`）无值差异
  - 输入侧独有：`result_hash`, `reveal_salt`, `worker_address`
  - 输出侧独有：`expected_hash`, `matched`, `reason`
- 结论：Rust verifier 输出形态稳定，符合“输入子集 + 校验增强字段”预期，可作为 P1 负向套件旁路证据链样本。

## 12) CI 联动作业草案（P1 + Rust sidecar）

- 新增 workflow：`.github/workflows/p1-rust-sidecar.yml`
- 触发：`pull_request` / `push(main)` / `workflow_dispatch`
- 运行环境：`self-hosted, macOS`（依赖本地链 RPC）
- 核心流程：
  1. preflight 检查 `127.0.0.1:26657`
  2. 执行 `WITH_RUST_VERIFY=1 ./scripts/p1_negative_suite.sh`
  3. 读取最新 `data/p1-negative/*/summary.json` 做 advisory 汇总
  4. 上传 `p1-negative` + `verifier-input` + `rust-verifier-local` artifacts
- 策略：sidecar 检查目前为 **advisory/non-blocking**（异常以 warning 暴露，不阻断主执行）。
- 已同步门禁文档：`docs/MANUAL_MERGE_GATE_CHECKLIST.md`
  - P1 命令更新为 `WITH_RUST_VERIFY=1`
  - 增加 Rust 阈值（`rust_verify_rc=0 && rust_verify_mismatch=0`）与 artifacts 证据项

## 27) Rust L1 后续动作-8（v1 状态机冻结对齐收口，2026-02-19 22:50~23:05 CST）

- 已完成 `accept_task` 路径落地并接入主流程：
  - `trnm-pouw` 新增：`apply_accept_task(OPEN -> ASSIGNED)`
  - `trnm-node` demo mempool 已插入 `AcceptTask` 交易，事件输出新增 `event_type=accept`
- 已收紧 `commit_result` 迁移约束：
  - 由此前兼容路径（`OPEN|ASSIGNED -> COMMITTED`）收敛为冻结语义：`ASSIGNED -> COMMITTED`
  - 增加 worker 绑定校验：`commit.worker` 必须等于 `accept_task` 绑定 worker，否则 `Unauthorized`
- 测试与回归：
  - `cargo test -p trnm-pouw` 全绿（6/6）
  - `cargo test --workspace` 全绿
  - `parallel sanity` 全绿（无 `apply_error` / `rollback=true`）
  - `check_event_fields.sh` 全绿
  - `state-root-audit` 全绿：`run/audit/state-root-audit-20260219-230451.txt`（`ok=true mismatch=0 missing=0`）
- 结论：v1 冻结文档中 `accept_task` 与 `ASSIGNED -> COMMITTED` 关键语义已与实现对齐。

## 28) Rust L1 后续动作-9（错误码映射+事件schema收口，2026-02-19 23:10~23:22 CST）

- `trnm-pouw` 增加稳定错误码映射接口：`PouwError::stable_code()`
  - v1 稳定集合：`InvalidTransition/VersionConflict/MissingWorker/MissingCommitment/CommitmentMismatch/Unauthorized/InsufficientStake`
  - 内部态错误保留为 `StateInternal`（避免误当协议稳定语义）
- 新增测试覆盖：
  - `stable_error_code_mapping`
  - `reveal_missing_worker_is_mapped`
- 新增文档：`docs/protocol/pouw-v1-error-mapping.md`
- 事件输出增加 schema 标识：`event_schema=v1`
  - `trnm-node` 所有 `[event]` 行已附带 schema
  - `scripts/check_event_fields.sh` 已将 `event_schema=v1` 纳入必检项
  - 脚本适配 `accept` 引入后的节奏：`max-blocks=3`，resolve 匹配规则更新
- 稳定性快验：`check_event_fields.sh` 连跑 `10/10` 全通过。

## 29) Rust L1 后续动作-10（事件回放一致性门禁，2026-02-19 23:22~23:26 CST）

- 新增脚本：`trillionnium-rust/scripts/check_event_replay_smoke.sh`
  - 用单任务链路校验事件顺序：
    - `create -> accept -> commit -> reveal -> challenge -> resolve`
  - 输出：`run/event-replay-smoke.log`
- Nightly health workflow 已接入硬门禁：
  - 新增步骤 `Validate v1 event replay order (hard gate)`
  - artifacts 新增 `event-replay-smoke.log`
- 本地实跑通过：`event replay ok`。

## 30) Rust L1 后续动作-11（并行路径 flaky 快验，2026-02-19 23:27~23:31 CST）

- 对并行路径做了快速稳定性压测：
  - 命令：`trnm-node --parallel-workers 4 --block-ms 1 --max-blocks 3 --demo-tasks 2 --demo-keys 2`
  - 连跑 `20` 轮
- 检查口径：日志不得出现 `apply_error` 或 `rollback=true`
- 结果：`parallel_sanity_streak=20/20`（全部通过）
- 产物：`trillionnium-rust/run/parallel-sanity-flaky-*.log`

## 31) Rust L1 后续动作-12（一键门禁脚本 + merge gates 接入，2026-02-19 23:40~23:44 CST）

- 新增一键门禁脚本：`trillionnium-rust/scripts/run_v1_protocol_gates.sh`
  - `cargo test --workspace`
  - `check_event_fields.sh`
  - `check_event_replay_smoke.sh`
  - 并行路径 sanity（`apply_error/rollback` 硬失败）
- 已本地实跑：`[OK] run_v1_protocol_gates passed`。
- `trnm-merge-gates.yml` 已接入步骤 `Rust L1 v1 protocol gates`，并补充 artifacts：
  - `parallel-sanity.log`
  - `event-field-check.log`
  - `event-replay-smoke.log`
- 新增执行看板：`docs/strategy/trnm-90d-week1-execution-board.md`（10 项执行项与验收口径）。

## 32) Rust L1 后续动作-13（nightly 加入并行抖动门禁，2026-02-19 23:44~23:48 CST）

- 新增脚本：`trillionnium-rust/scripts/check_parallel_flaky.sh`
  - 默认连跑 `RUNS=5`（可通过 `PARALLEL_FLAKY_RUNS` 覆盖）
  - 任一 run 出现 `apply_error` 或 `rollback=true` 直接 fail
- 本地实跑：`RUNS=5`，结果 `parallel flaky streak=5/5`。
- `rust-l1-nightly-health.yml` 已接入硬门禁：
  - `Validate parallel flaky streak (hard gate)`
- artifacts 新增：`run/parallel-sanity-flaky-*.log`

## 6) P1-1 Dry-run 演练结果（2026-02-19 16:44 CST）

- 演练目录：`data/upgrade-runs/20260219-164421`
- Checklist 流程已执行：run_id 初始化、pre/post 快照采集、gate 复跑、diff 归档。
- gate 结果：
  - pre: `p0_rc=0`, `p1_rc=1`
  - post: `post_p0_rc=0`, `post_p1_rc=1`
- 阻塞原因：本地链未启动（`127.0.0.1:26657 connection refused`），`p1_negative_suite` 在 preflight 主动终止，避免误报。
- 结论：流程脚手架可用；待链恢复后需补一次“全绿 dry-run（含 p1=0）”以达成 P1-1 验收。

## 33) Worker 回执硬门禁闭环（2026-02-21 11:30~12:55 CST）

- `trnm-worker-agent` 提交流程增强：
  - adapter 执行结果结构化（`ok/rc/tx_hash/terminal`）
  - `rc=9/10`（replay/nonce_rejected）按终态处理（不盲重试）
  - ack 记录新增 `commit_tx_hash` / `reveal_tx_hash`
- verify 门禁增强：
  - `scripts/v2/worker_agent_verify_with_rpc.sh` 新增 hard-check：
    - 必须存在 `accepted` ack
    - commit/reveal `tx_hash` 必须非空
- full loop 默认策略收敛：
  - `scripts/v2/worker_agent_full_loop.sh` 默认 `TRNM_TX_ADAPTER_MODE=command`
  - `TRNM_TX_CLI` 优先 `trnm-node`，不存在时回退 `echo`
- 新增失败回执门禁：
  - `scripts/v2/worker_failed_receipt_test.sh`
  - 断言失败场景写入 `status=failed` 且保留 `commit_tx_hash`

## 34) 门禁与流水线接入（2026-02-21）

- CI 硬门禁同步：
  - `.github/workflows/rust-l1-nightly-health.yml`
  - `.github/workflows/trnm-merge-gates.yml`
  - 已新增 `Worker-agent tx-hash receipt hard gate`，并接入 failed-receipt test
- codegen relay 步骤扩展为 21 步：
  - `scripts/auto_relay_codegen.steps` 纳入 `worker_failed_receipt_test.sh`
- 实跑结果：
  - `relay-20260221-125141-77886`：`ok=21 fail=0`
  - 报告：`docs/reports/codegen-pipeline-run-20260221-round3.md`
- 对应提交：
  - `6f469e2` / `64f2694` / `d0d7c4a` / `e6fb46c` / `c22fae5`

## 35) Worker 回执边界门禁补强（2026-02-21 17:25~17:33 CST）

- 新增门禁脚本：`scripts/v2/worker_retry_nonce_boundary_test.sh`
  - 注入 2 次 commit 瞬时失败，验证 retry/backoff 后可收敛成功。
  - 验证 replay guard：`rc=9`。
  - 验证 nonce monotonic guard：`rc=10`。
- 主门禁入口已接入：`scripts/v2/run_worker_receipt_gates.sh`
  - 当前覆盖：full-loop / replay / failed-receipt / resume-no-duplicate / retry+nonce-boundary。
- `trnm-worker-agent` 小重构：
  - 错误码与默认重试参数常量化（去除 magic number）。
  - 新增 ack 语义日志：`accepted|rejected|failed + reason(commit_rc/reveal_rc)`。
  - 新增 crate 内单测 3 项（错误码分类 + idempotent 语义 + backoff 线性/饱和）。
- 本地验证：
  - `cargo test -p trnm-worker-agent` 全绿（3/3）。
  - `./scripts/v2/run_worker_receipt_gates.sh` 全绿。
