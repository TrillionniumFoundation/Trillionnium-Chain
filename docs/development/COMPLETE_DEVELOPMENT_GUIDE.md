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

## 3.1 数据流（高层）
1. RPC/CLI 接收请求
2. Node 组块并调用 Executor 并行预执行
3. PoUW 状态迁移执行
4. State 落库 + 事件输出
5. Worker-Agent 与 CLI 查询回读状态

## 3.2 治理与紧急机制
- `emergency_pause` 用于暂停高风险交易路径
- 敏感治理参数支持更严格检查（timelock/replace/cancel 等路径需门禁保护）
- 建议所有治理关键行为都有 merge-gate 对应测试

## 3.3 共识/安全关键点
- 身份 canonicalization（validator / signer / challenger）
- replay/nonce/seq 保护
- timeout/challenge/resolve 元数据不变量

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
