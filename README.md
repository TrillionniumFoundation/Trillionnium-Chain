# Trillionnium Chain (TRNM)

Rust-native Layer 1 for **Decentralized AI Compute**（PoUW）。

> 当前主线：`trillionnium-rust/`  
> 历史归档：`legacy/`

---

## 1. 项目定位

TRNM 是面向 AI 计算任务结算与验证的 Rust L1 项目，核心关注：

- **PoUW 状态机**（任务创建、提交、揭示、挑战、裁决）
- **高并发执行**（冲突检测与并发分组）
- **可审计事件与稳定接口**（便于集成、回放、治理与运维）
- **Worker Agent + CLI**（从任务执行到链上提交的闭环）

---

## 2. 仓库结构（按当前代码）

```text
TrillionniumChain/
├── trillionnium-rust/           # Rust workspace（核心主线）
│   ├── crates/
│   │   ├── trnm-node
│   │   ├── trnm-types
│   │   ├── trnm-state
│   │   ├── trnm-pouw
│   │   ├── trnm-executor
│   │   ├── trnm-mempool
│   │   ├── trnm-rpc
│   │   ├── trnm-bench
│   │   ├── trnm-worker-agent
│   │   ├── trnm-cli
│   │   └── trnm-bridge-poc
│   ├── configs/
│   ├── scripts/
│   └── run/
├── web4-frontend/               # Web4 前端（Next.js + Vitest + Playwright）
├── scripts/                     # 仓库级流水线与自动化脚本
├── docs/                        # 架构 / 协议 / 开发 / runbook / 报告
├── config/                      # 策略与告警配置
├── data/                        # 验收数据与实验产物
├── run/                         # 运行日志与 gate 输出
├── examples/                    # SDK/演示样例
└── legacy/                      # 历史冻结代码
```

---

## 3. 核心模块职责

### Rust 主链（`trillionnium-rust/crates`）

- `trnm-node`：节点主循环、执行接线、事件输出
- `trnm-state`：版本化状态存储与 `state_root`
- `trnm-pouw`：PoUW 任务状态机与验证逻辑
- `trnm-executor`：冲突检测与并发调度策略
- `trnm-mempool`：交易池与打包/接入策略
- `trnm-rpc`：RPC 服务与稳定查询接口
- `trnm-worker-agent`：Worker 执行与提交链路
- `trnm-cli`：原生 CLI（tx/query）
- `trnm-bench`：性能基准工具
- `trnm-types`：共享类型
- `trnm-bridge-poc`：桥接 PoC

### Web4 前端（`web4-frontend`）

- Next.js 应用（`app/`）
- 合约/接口适配层（`lib/`）
- 测试（unit / component / contract / e2e）
- 发布前检查脚本（位于 `web4-frontend/scripts/`；入口命令见 `web4-frontend/package.json`：`npm run ci:check` / `npm run release:preflight` / `npm run release:ready`）

---

## 4. 快速开始

### 4.1 环境

- Rust stable（建议与 `rust-toolchain`/CI 保持一致）
- Node.js 20+（前端/脚本）
- Git

### 4.2 克隆

```bash
git clone https://github.com/ProfAlexQI/TrillionniumChain.git
cd TrillionniumChain
```

### 4.3 Rust 主线最小验证

```bash
cd trillionnium-rust
cargo test --workspace
```

### 4.4 Web4 前端最小验证

```bash
cd web4-frontend
npm ci
npm run ci:check
# 若需强制跑 e2e
CI_RUN_E2E=1 npm run ci:check
```

---

## 5. 常用命令（仓库根目录）

### 5.1 仓库级 gate / pipeline

```bash
# 快速门禁
./scripts/quick_gate_shell.sh

# 自动化流水线
./scripts/run_100step_pipeline.sh
./scripts/run_200step_pipeline.sh
./scripts/run_200step_v2_pipeline.sh
./scripts/run_codegen_pipeline.sh
```

### 5.2 Worker / Receipt 相关

```bash
# Worker receipt gates
./scripts/v2/run_worker_receipt_gates.sh

# strict real-cli gate
TRNM_TX_CLI=./trillionnium-rust/target/debug/trnm-cli \
  ./scripts/v2/run_worker_receipt_gates_real_cli.sh
```

### 5.3 Tokenomics 回归门禁

```bash
./scripts/v2/run_tokenomics_r1_r14_regression_gate.sh
```

---

## 6. 文档入口

- 当前发布/就绪真相源（绑定当前 `origin/main` 快照 `0b209289`）：[RELEASE_READINESS.md](RELEASE_READINESS.md)
- 项目状态（历史推进日志，不作为 release truth source）：[STATUS.md](STATUS.md)
- 统一开发调度（planning board，不覆盖 release 判定）：[docs/development/DEVELOPMENT_MASTER_UNIFIED_2026-03-04.md](docs/development/DEVELOPMENT_MASTER_UNIFIED_2026-03-04.md)
- 并发瓶颈图与 8 周路线（当前 closeout / roadmap 入口）：[docs/reports/TRNM_CONCURRENCY_BOTTLENECK_MAP_AND_8W_ROADMAP_2026-03-10.md](docs/reports/TRNM_CONCURRENCY_BOTTLENECK_MAP_AND_8W_ROADMAP_2026-03-10.md)
- TRNM vs Solana vs Sui 对外对标口径（架构/benchmark 口径，不宣称 production parity）：[docs/reports/TRNM_CONCURRENCY_COMPARISON_2026-03-05.md](docs/reports/TRNM_CONCURRENCY_COMPARISON_2026-03-05.md)
- Web4 基础设施总览（平台路线图）：[docs/WEB4_INFRA_PLATFORM_DEVELOPMENT_MASTER.md](docs/WEB4_INFRA_PLATFORM_DEVELOPMENT_MASTER.md)
- PoUW 机制说明：[trillionnium-rust/docs/challenge-economics-minimal.md](trillionnium-rust/docs/challenge-economics-minimal.md)
- A2A 适配契约：[docs/agent/a2a_adapter_contract_v1.md](docs/agent/a2a_adapter_contract_v1.md)
- MCP 适配契约：[docs/agent/mcp_adapter_contract_v1.md](docs/agent/mcp_adapter_contract_v1.md)
- 运维手册：[OPERATIONS.md](OPERATIONS.md)
- OpenClaw 微型运维 Runbook：[docs/development/OPENCLAW_OPS_MICRO_RUNBOOK.md](docs/development/OPENCLAW_OPS_MICRO_RUNBOOK.md)
- Web4 前端说明：[web4-frontend/README.md](web4-frontend/README.md)

> 轻量校验：可运行 `./scripts/check_root_readme_local_links.sh` 验证 README 本地相对链接是否全部可达。

---

## 7. CI / 工作流

仓库包含主链与前端多条工作流（位于 `.github/workflows/`），其中包括：

- `trnm-merge-gates.yml`
- `rust-l1-nightly-health.yml`
- `trnm-gate-quick-check.yml`
- `web4-frontend-ci.yml`

建议在提交前本地先跑最小 gate，减少 CI 往返。

---

## 8. 现阶段说明

- 主线开发入口为 `trillionnium-rust/`。
- `legacy/` 仅作归档，不作为当前开发入口。
- 当前是否“可发布 / release-ready”请以 [RELEASE_READINESS.md](RELEASE_READINESS.md) 为准；历史证据文档不自动代表今日状态。
- Web4 当前语义是：**前端默认走只读 API client；只在显式 `?mode=mock` 时回退到本地 mock snapshot；不暴露写路径。**
- 文档中若出现 `/api/v0/web4/*`，应视为历史草案命名；当前仓内前端实际消费的是 `query-task` / `query-events` / `query-capability-audit` / `query-normalized-audit-events` 这组只读接口，**不是仓内已实现的 Next.js route**。
- Explorer / indexer 接入时可先把这组接口当作最小 read-model 契约：
  - `query-events/<task_id>` 未显式传 `?limit=` 时默认返回 **100** 条，硬上限 **500** 条；超大分页请求会被 clamp，不应假设无限历史窗口。
  - `query-events/<task_id>` 的历史排序应视为 **确定性回放顺序**：node event 主路径按 `block_height -> tx_id -> ts_unix_ms -> event_type -> from_status -> to_status` 稳定排序；索引侧若要做持久化增量回放，不应自行改写这条顺序轴。
  - 若索引器要保存增量 checkpoint，优先持久化“**最后一个已应用事件的稳定排序 key**”（至少覆盖 `block_height + tx_id + ts_unix_ms + event_type + from_status + to_status`），而不是只记 page offset / 本地扫描轮次；否则在历史补档、manifest 扩容或重新去重后，resume 点可能漂移到错误位置。
  - 更稳妥的做法是把 checkpoint 与一份 **canonical replay source fingerprint** 绑定持久化（例如规范化后 manifest/env 源集合的摘要 + 最近可信高度）；只要 source fingerprint 变化，就应触发回退重放或人工确认，而不是直接沿用旧 resume 点。
  - 当 node event 缺失、只能退回 adapter 记录时，`query-events` 只会在**已持久化 commit 存在**时补出 `commit -> reveal` 历史；单独的 reveal 不会被当成完整历史链。索引器不应把 reveal-only 记录解释成可独立落库的已完成回放片段。
  - `query-capability-audit/<subject-or-token>` 同时接受 capability token id 与 subject DID，索引侧不必为两种 key 维护两套入口。
  - 若需要从归档日志重放历史 read-model，优先通过 `TRNM_RPC_NODE_EVENT_LOG_MANIFEST` 指向一个 manifest 文件，再用 `TRNM_RPC_NODE_EVENT_LOG_SOURCES` 补充临时源；manifest 内的**相对路径以 manifest 所在目录为基准解析**，而 env 里的相对路径以 `trnm-rpc` 运行根目录为基准解析。
  - `TRNM_RPC_NODE_EVENT_LOG_MANIFEST` 自身也会先做包装/注释归一化：带引号、前后空白、inline comment、UTF-8 BOM 的值仍按 **RPC root 相对路径** 解析；sidecar / operator script 不必为了规避 shell 注释、归档拷贝留下的 BOM、或引用风格差异而改写同一条历史源声明。
  - historical replay 的日志源会先做**词法归一化 + 去重**（例如引号包裹、`./`、注释尾巴、等价相对路径），索引器/sidecar 不应依赖“同一路径写多次”来制造重复回放。
  - 若要做 durable index persistence，建议把本地索引库/缓存视为**可重建派生状态**：权威 replay source 仍应是 node event 日志（优先 manifest，其次临时 env 补源），持久化层只保存 checkpoint / watermark / 派生物；当 checkpoint 与历史日志不一致时，应回退到最近可信高度重放，而不是把旧索引快照当作唯一真相。
  - 更具体地说：一旦 `TRNM_RPC_NODE_EVENT_LOG_MANIFEST` / `TRNM_RPC_NODE_EVENT_LOG_SOURCES` 的**规范化后源集合**发生变化（例如 BOM/引号/注释清洗后去重结果不同、manifest 扩容、历史补档、路径别名合并），就不应盲目沿用旧 checkpoint；应至少回退到最近可信高度或直接从权威历史源重扫，以免把“旧源集合下的 resume 点”错当成当前唯一真相。
  - 这组路径当前都属于只读查询面，前端/脚本不应通过它们推断存在对称写接口。
- 自动化脚本较多，优先使用本 README、`RELEASE_READINESS.md` 和 `docs/development` 下统一调度文档作为导航。

---

## License

MIT
