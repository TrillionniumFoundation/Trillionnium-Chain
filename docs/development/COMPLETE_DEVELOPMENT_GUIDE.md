# TrillionniumChain 完整开发文档（Draft v1）

> 目标：作为 Rust L1 主线的统一开发手册，覆盖架构、环境、开发流程、测试门禁、发布与 Web4.0 扩展路线。

---

## 1. 项目定位与范围

- 项目：TrillionniumChain（TRNM）
- 定位：面向 Decentralized AI Compute 的 Rust-native Layer 1（PoUW）
- 主线代码目录：`trillionnium-rust/`
- 核心状态机：`OPEN -> ASSIGNED -> COMMITTED -> REVEALED -> CHALLENGED -> COMPLETED/SLASHED`

核心 crate：
- `trnm-node`：出块循环、执行接线、事件输出
- `trnm-state`：versioned object store + governance state
- `trnm-pouw`：任务状态迁移（create/commit/reveal/challenge/resolve/timeout）
- `trnm-rpc`：查询/交易接入与可靠性层
- `trnm-executor`：并发分组与冲突检测
- `trnm-cli`：开发/运维 CLI
- `trnm-worker-agent`：任务执行与提交代理

---

## 2. 开发环境与依赖

## 2.1 基础要求
- Rust stable toolchain（建议 rustup 管理）
- `cargo`, `rustfmt`, `clippy`
- `jq`, `bash`
- GitHub CLI（可选，用于 PR/CI 操作）

## 2.2 本地初始化
```bash
cd trillionnium-rust
cargo build
cargo test --workspace
```

## 2.3 推荐目录约定
- 文档：`docs/`
- 自动化脚本：`scripts/`, `scripts/v2/`
- 报告产物：`run/`、`docs/reports/`

---

## 3. 架构与模块边界

本节按“代码真实职责”拆分，不按概念图拆分。核心边界以 `trillionnium-rust/crates/*` 与 `trillionnium-rust/scripts/*` 为准。

## 3.1 模块边界总览（谁负责什么）

### trnm-node（编排层 + 区块循环）
- 入口：`crates/trnm-node/src/main.rs`
- 职责：
  - 驱动区块循环（mempool 取交易、BFT 回合、提交/跳过区块）。
  - 生成并维护执行计划：把交易映射成读写集合，交给 `trnm-executor::build_parallel_groups` 分组并行预执行。
  - 在提交阶段调用 `trnm-pouw` 的状态迁移函数（`apply_*`）。
  - 维护共识 WAL 与 checkpoint：
    - `run/consensus-wal/consensus-wal-meta.toml`
    - `run/consensus-wal/consensus-checkpoints.toml`
    - `run/consensus-wal/consensus-wal.toml`
  - 输出标准化事件日志 `[event] ...`（含 `event_type/task_id/state_root/tx_hash/treasury_delta/...`）。
- 不做：
  - 不定义业务状态机规则（由 `trnm-pouw` 定义）。
  - 不持有底层对象版本语义实现（由 `trnm-state` 提供）。

### trnm-pouw（业务状态机层）
- 入口：`crates/trnm-pouw/src/lib.rs`
- 职责：
  - 定义 Task 全流程迁移：`apply_create_task/accept/commit/reveal/challenge/resolve/timeout`。
  - 执行规则校验：状态合法性、deadline、承诺/揭示一致性、权限、stake/bond 约束。
  - challenge/resolve/timeout 相关资金与惩罚逻辑（escrow/forfeit/slash 账户语义）。
- 不做：
  - 不负责 WAL/checkpoint 落盘。
  - 不负责请求入口协议（RPC/CLI）。

### trnm-state（状态存储与可验证落盘元数据）
- 入口：`crates/trnm-state/src/lib.rs`
- 职责：
  - 维护对象与版本（`StateStore`，对象 optimistic version check）。
  - 维护余额、治理参数、pending 治理更新。
  - 计算 `state_root()`（对象+余额+pending 更新共同哈希）。
  - 定义 WAL/Checkpoint 元数据结构：`WalMeta`、`CheckpointMeta`。
  - 提供 `verify_wal_and_find_checkpoint()` 做重启恢复时的链式校验与回退锚点选择。
- 不做：
  - 不做 RPC 协议编排。
  - 不跑区块循环。

### trnm-rpc（查询/入口适配层，文件态后端）
- 入口：`crates/trnm-rpc/src/main.rs` + `crates/trnm-rpc/src/lib.rs`
- 职责：
  - 提供查询命令：`query-task/query-events/query-request/query-request-full/query-challenge-treasury/...`。
  - 提供消息入口与调度入口：`submit-message`、`dispatch-open`。
  - 维护文件态存储：
    - `run/message-gateway/requests.jsonl`（请求生命周期）
    - `run/rpc/accounts.json`（账户余额/nonce）
    - `run/rpc/txs.json`（转账 tx 生命周期）
    - `run/rpc/faucet_limits.json`（faucet 限流）
  - 从 node 日志回建事件视图（`run/node*.log`、`run/parallel-sanity.log` 等 tail 解析）。
- 不做：
  - 不直接执行业务状态迁移（不调用 `apply_*` 去修改链状态）。

### trnm-cli（用户侧命令入口）
- 入口：`crates/trnm-cli/src/main.rs`
- 职责：
  - 钱包管理（create/import/address/sign）。
  - tx 命令封装（transfer、query、wait；支持 `TRNM_TX_*` 模板命令桥接）。
  - query 命令封装（balance；支持 `TRNM_QUERY_BALANCE_CMD`）。
- 边界：
  - 主要是“协议适配器/壳层”，默认可走本地伪实现，生产可替换外部命令。

### trnm-worker-agent（异步执行与回执编排）
- 入口：`crates/trnm-worker-agent/src/main.rs`
- 职责：
  - 消费 `requests.jsonl` 中 `ASSIGNED` 请求（`run-assigned`）。
  - 调用 LLM adapter（默认 `./scripts/llm_adapter_mock.sh`）产出 model output 并做本地 verifier。
  - 对 accepted 请求产出 commit/reveal 提交记录（`/tmp/trnm-worker-agent-submissions.jsonl`）。
  - 执行 flush：通过 `./scripts/worker_tx_adapter.sh` 发 commit/reveal，写 ack/event/progress 日志，并回填 ingress 记录状态。
- 不做：
  - 不直接修改 `StateStore`。
  - 不直接成为共识节点。

## 3.2 关键交互关系（跨模块）

1. **Node ↔ PoUW ↔ State**
   - `trnm-node` 是唯一的区块执行编排者；
   - `trnm-pouw` 提供迁移规则；
   - `trnm-state` 提供版本化对象存储与状态根计算。

2. **RPC ↔ Worker-Agent**
   - `trnm-rpc submit-message` 创建 `OPEN` 请求到 `requests.jsonl`；
   - `trnm-rpc dispatch-open` 把请求变成 `ASSIGNED`；
   - `trnm-worker-agent run-assigned/flush-submissions` 推进到 `COMMIT_QUEUED/REVEAL_SUBMITTED` 或失败终态。

3. **Worker-Agent ↔ Node/CLI（通过脚本桥接）**
   - 默认通过 `scripts/worker_tx_adapter.sh` 执行 commit/reveal；
   - adapter 可 mock，也可 command 模式透传 `TRNM_TX_CLI`（例如转发到 `trnm-node tx ...` 或其他真实客户端）。

4. **RPC ↔ Node（读侧耦合）**
   - `trnm-rpc` 不直接连内存态 node，而是读取 run/ 日志与文件产物聚合查询视图；
   - 这意味着查询一致性依赖日志写入与 tail 解析窗口（`TRNM_RPC_NODE_EVENT_LOG_TAIL_BYTES`）。

## 3.3 治理与紧急机制边界

- `emergency_pause` 存于 `trnm-state` 治理参数；`trnm-node` 在执行前用 `is_rejected_by_emergency_pause` 过滤高风险 tx（create/accept/commit/reveal/challenge），但 **resolve 保持可执行** 以清算存量挑战。
- 敏感治理参数（如 `challenge_window_blocks/challenge_min_bond/...`）在 `trnm-state` 内执行 timelock + rate-limit + replace/cancel 语义。
- `trnm-pouw` 读取治理参数快照驱动业务约束（如 bond floor、resolve authority）。

## 3.4 “请求到状态落盘”时序（文字版）

以消息请求驱动任务为例：

1. 客户端调用 `trnm-rpc submit-message`，写入 `run/message-gateway/requests.jsonl`，状态为 `OPEN`。
2. 调度调用 `trnm-rpc dispatch-open`，将请求状态转为 `ASSIGNED` 并绑定 worker。
3. `trnm-worker-agent run-assigned` 读取 `ASSIGNED` 请求：
   - 调 LLM adapter 生成输出；
   - verifier 通过则生成 `result_hash/salt/commit_hash`，写 submission 日志并把请求推进到 `COMMIT_QUEUED`。
4. `trnm-worker-agent flush-submissions --execute`：
   - 通过 `worker_tx_adapter.sh` 发 `commit` 后发 `reveal`（含重试、幂等 RC 处理）；
   - 写 ack/event/progress；
   - 回填 ingress 记录为 `REVEAL_SUBMITTED`（或 `REJECTED/FAILED_SUBMISSION`）。
5. `trnm-node` 在区块循环中：
   - 从 mempool/输入取 tx，做并行预执行分组；
   - 逐笔调用 `trnm-pouw apply_*` 变更 `trnm-state`；
   - 成功后输出 `[event]` 日志并更新 `state_root`。
6. 区块提交时 `trnm-node` 落盘：
   - 追加 `WalMeta` 到 `consensus-wal-meta.toml`；
   - 满足间隔时写 `CheckpointMeta` 到 `consensus-checkpoints.toml`；
   - 更新 `consensus-wal.toml`（next_height/lock）。
7. 读侧回查：`trnm-rpc query-*` 从 `requests.jsonl + node event log + rpc/*.json` 聚合返回最终状态视图。

## 3.5 共识/安全关键点（实现对应）
- 身份与签名路径：`trnm-node` 中 vote 签名/nonce/replay 拒绝统计，事件里写 `signer/challenger`。
- 状态迁移 fail-closed：`trnm-pouw` 对非法状态、deadline、权限、bond/accounting 不变量直接拒绝。
- 版本冲突保护：`trnm-state` 的 `version conflict` + node 失败回滚，避免脏写。
- 恢复一致性：`trnm-state::verify_wal_and_find_checkpoint` + `trnm-node recover_wal_state` 防止损坏 WAL 继续前进。

---

## 4. 日常开发流程（强约束）

1. 从 `main` 同步：
```bash
git checkout main
git pull --ff-only
```
2. 建分支开发（小步提交）
3. 先跑目标测试，再跑 workspace 测试
4. 提交信息清晰标注作用域（如 `laneA:`, `laneB:`, `laneC:`）
5. PR 必须附：变更摘要、验证命令、回滚路径

---

## 5. 测试与门禁

> 说明：以下命令均基于仓库内已存在脚本路径，可直接在仓库根目录执行。

## 5.1 本地快速（开发中反复执行，目标 1~5 分钟）

```bash
# 1) Shell 脚本快速门禁（语法 + shellcheck）
./scripts/quick_gate_shell.sh scripts trillionnium-rust/scripts

# 2) 治理参数 schema 关键拒绝路径（PR-1 配套）
./scripts/v2/governance_value_schema_reject_test.sh

# 3) （可选）本机未安装 shellcheck 时，先跑语法预检
QUICK_GATE_SKIP_SHELLCHECK=1 ./scripts/quick_gate_shell.sh scripts trillionnium-rust/scripts
```

## 5.2 PR 前（分支合并前必须通过）

```bash
# 1) Worker 回执门禁（唯一入口）
./scripts/v2/run_worker_receipt_gates.sh

# 2) 治理暂停演练（参数白名单 + checked-path）
./scripts/v2/emergency_pause_drill.sh

# 3) PR-1 安全补丁配套门禁（建议至少跑这三项）
./scripts/v2/rpc_query_hardcap_enforcement_test.sh
./scripts/v2/governance_value_schema_reject_test.sh
./scripts/v2/worker_real_cli_fake_wrapper_block_test.sh
```

## 5.3 发布前（冻结窗口/Tag 前）

```bash
# 1) 产品层最小交易闭环 smoke
./scripts/v2/product_layer_smoke.sh

# 2) P1 串联门禁（产品层 + challenge/treasury 一致性）
./scripts/v2/run_p1_integration_gate.sh

# 3) Tokenomics 回归门禁（R1-R14 快集）
./scripts/v2/run_tokenomics_r1_r14_regression_gate.sh

# 4) PR-2 超时迁移 + challenge bond（高风险状态迁移）
./scripts/v2/pouw_commit_timeout_migration_test.sh
./scripts/v2/pouw_challenge_timeout_migration_test.sh
./scripts/v2/challenge_bond_enforcement_test.sh
```

## 5.4 失败排查顺序（建议按序执行）

1. **先看退出码与首个失败点**：不要只看最后一行，优先定位第一处 `FAIL`/`error`。
2. **确认执行目录**：必须在仓库根目录运行；脚本内部会切换路径，手动改 cwd 容易引入假失败。
3. **检查依赖是否齐全**：`rustup/cargo/bash/jq`、`shellcheck`（若走 quick gate 默认路径）。
4. **单脚本复跑并保留日志**：把失败的聚合 gate 拆成单个脚本重跑，例如先单跑 `governance_value_schema_reject_test.sh`。
5. **核对环境变量污染**：清理/重置 `TRNM_TX_CLI`、`QUICK_GATE_SKIP_SHELLCHECK`、`OUT_DIR` 等变量后再跑。
6. **验证本地构建状态**：进入 `trillionnium-rust/` 执行 `cargo build`，排除编译缓存损坏或目标文件缺失。
7. **对照 run/ 产物**：优先查看脚本输出的 `run/.../summary.txt|json`，不要凭终端截断输出下结论。

## 5.5 最小通过标准（建议写入 PR 描述）

- 本地快速门禁：至少 1 条 quick gate + 1 条治理/安全脚本通过。
- PR 前：`run_worker_receipt_gates.sh` 与关键安全脚本通过。
- 发布前：`product_layer_smoke.sh` + `run_p1_integration_gate.sh` + tokenomics 回归通过。

---

## 6. 代码质量与安全编码规范

- 所有输入解析路径必须：
  - 明确 canonicalization
  - 拒绝空白/伪格式
  - 保持错误语义稳定
- 状态迁移必须 fail-closed（缺关键元数据直接拒绝）
- 禁止“宽松默认成功”行为（尤其 parser / auth / governance）
- 新增规则必须补回归测试

---

## 7. 发布流程（建议）

1. 冻结窗口（仅修复阻塞）
2. 全量门禁 + 定向高风险场景回归
3. 生成发布报告（变更、风险、回滚）
4. 标记发布（tag/release）
5. 发布后观察（SLO/告警）

回滚策略：
- 优先回滚 merge commit
- 或按 lane 范围选择性回滚

---

## 8. Web4.0 Infra 扩展开发指南

> 范围：围绕 TrillionniumChain 主网能力，分阶段补齐 Web4.0 infra 所需的“可执行、可验证、可结算、可治理”最小闭环。

### 8.1 三阶段实施路线

#### 阶段 I（0-3 月）：最小可运行闭环（MVP）

目标：打通 `任务发布 -> 执行证明 -> 结算` 主路径，形成可回归测试的工程基线。

可交付物：
- 任务市场最小协议（TaskSpec/报价/接单/状态机）与版本化 schema（v0）。
- 执行结果提交接口（含结果哈希、执行元数据、签名）与 on-chain 记录。
- 基础结算模块（成功结算、失败退款、超时回收）及事件日志。
- 端到端集成测试（happy path + 失败路径）与 CI 门禁（lint/test/e2e）。

验收标准：
- 在测试网连续完成 >=100 笔任务闭环交易，成功率 >=95%。
- 任一阶段失败后可在 2 个区块内进入可恢复状态（退款或重试）。
- CI 中 e2e 用例稳定通过率 >=99%（最近 30 次流水线）。
- 协议字段变更需触发 schema 兼容性检查并产出变更记录。

#### 阶段 II（3-6 月）：可验证执行与跨域互通

目标：将“执行可信性”与“跨链最小互操作”纳入主流程，降低结算争议风险。

可交付物：
- 可验证执行抽象层（VerifyAdapter）：统一 fraud proof/TEE attestation/ZK receipt 接口。
- 争议与仲裁流程（challenge window、证据提交、裁决回执）与状态机。
- 跨链消息与结算最小能力（链间消息确认、资产桥接白名单、失败补偿机制）。
- SLA/SLO 监控面板（任务时延、争议率、跨链失败率）与告警规则。

验收标准：
- 三类验证适配器至少接入 2 类并完成同一 API 回归测试。
- 争议样例集（>=20 个）全部可复现，裁决结果与预期一致率 100%。
- 跨链消息在目标确认窗口内成功率 >=99%，失败交易补偿可自动触发。
- 关键指标纳入发布门禁：争议率、跨链失败率、P95 结算时延均有阈值。

#### 阶段 III（6-12 月）：生产级治理、身份与审计

目标：从“能跑”升级为“可规模化运行”，补齐权限、治理、审计与运维自动化。

可交付物：
- DID + capability-based authZ（按角色/资源/动作授权）与密钥轮换机制。
- 数据溯源与审计链路（provenance graph、隐私分级、可追溯日志归档）。
- 治理参数化与升级流程（提案、投票、灰度发布、回滚 runbook）。
- 压测与容量模型（吞吐、延迟、成本）及季度演练制度。

验收标准：
- 权限策略覆盖核心接口 100%，未授权访问拦截率 100%。
- 审计抽样可在 30 分钟内完成“任务输入-执行节点-结算结果”全链路还原。
- 升级演练至少每季度 1 次，具备可执行回滚脚本并通过演练验收。
- 基于压测结果形成容量规划，生产阈值与扩容策略文档化并进入发布流程。

### 8.2 与成熟 L1 能力对齐（简版）

| Web4.0 能力域 | 成熟 L1 常见能力 | TrillionniumChain 当前/目标 | 差距与优先动作 |
|---|---|---|---|
| 执行与可验证性 | 确定性执行、证明/验证框架、可重放测试 | 已有链上执行基础；目标接入 VerifyAdapter | 优先统一证明接口与争议状态机，先支持 2 类证明 |
| 共识与终局性 | 明确 finality、分叉处理、故障恢复流程 | 主线具备发布与回滚机制；目标细化跨链终局策略 | 增加跨链确认窗口策略与失败补偿自动化 |
| 经济与结算 | 费用模型、激励/惩罚、异常退款机制 | 目标构建任务结算与超时回收 | 先落地结算状态机与事件可观测性，再引入惩罚参数 |
| 身份与权限 | 账户体系、角色授权、密钥管理 | 目标引入 DID + capability authZ | 先覆盖核心接口最小权限，再做细粒度策略扩展 |
| 可观测与运维 | 指标/日志/追踪、SLO、告警、发布演练 | 已有 CI 门禁基础；目标生产级 SLO | 建立指标阈值门禁与季度故障/回滚演练 |
| 治理与升级 | 提案投票、参数治理、可控升级 | 目标完善治理与灰度发布 | 定义治理参数清单、提案模板与升级 runbook |

执行约束：
- 任何新能力必须附带：协议变更说明、测试用例、回滚路径。
- 任何跨链/验证能力上线必须先在测试网完成故障注入演练。
- 文档与代码同 PR 提交，避免“实现先行、规范缺失”。

---

## 9. 故障排查速查

- CI 全红但本地绿：检查 workflow 触发条件与脚本路径
- parser 类误判：优先补 canonicalization + 拒绝策略 + fuzz/噪声样例
- governance 断言失败：先确认 key-id 与 schema 校验顺序是否符合预期
- timeout/resolve 异常：优先看 metadata 是否完整与单调

---

## 10. 后续文档拆分计划

本文件为完整总览，建议拆分为：
- `docs/development/architecture.md`
- `docs/development/dev-workflow.md`
- `docs/development/testing-and-gates.md`
- `docs/development/release-runbook.md`
- `docs/development/web4-roadmap.md`

并由子代理持续维护、每次合并后自动更新索引。
