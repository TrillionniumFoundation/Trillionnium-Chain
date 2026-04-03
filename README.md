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
├── contracts-rust/              # Rust-native external contracts 子树（当前为独立 MVP contract crates / shared schema，尚未形成闭合 host runtime）
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

- 当前发布/就绪真相源（引用时须同时记录当下 `git rev-parse origin/main` 输出，勿把旧的固定 commit hash 当长期 truth source）：[RELEASE_READINESS.md](RELEASE_READINESS.md)
- 项目状态（历史推进日志，不作为 release truth source）：[docs/archive/root-history/STATUS.md](docs/archive/root-history/STATUS.md)
- 历史路线图（前一阶段 sprint 记录）：[docs/archive/root-history/ROADMAP.md](docs/archive/root-history/ROADMAP.md)
- 历史 backlog（前一阶段待办快照）：[docs/archive/root-history/BACKLOG.md](docs/archive/root-history/BACKLOG.md)
- 统一开发调度（planning board，不覆盖 release 判定）：[docs/development/DEVELOPMENT_MASTER_UNIFIED_2026-03-04.md](docs/development/DEVELOPMENT_MASTER_UNIFIED_2026-03-04.md)
- 并发瓶颈图与 8 周路线（当前 closeout / roadmap 入口）：[docs/reports/TRNM_CONCURRENCY_BOTTLENECK_MAP_AND_8W_ROADMAP_2026-03-10.md](docs/reports/TRNM_CONCURRENCY_BOTTLENECK_MAP_AND_8W_ROADMAP_2026-03-10.md)
- TRNM vs Solana vs Sui 对外对标口径（架构/benchmark 口径，不宣称 production parity）：[docs/reports/TRNM_CONCURRENCY_COMPARISON_2026-03-05.md](docs/reports/TRNM_CONCURRENCY_COMPARISON_2026-03-05.md)
- Web4 基础设施总览（平台路线图）：[docs/WEB4_INFRA_PLATFORM_DEVELOPMENT_MASTER.md](docs/WEB4_INFRA_PLATFORM_DEVELOPMENT_MASTER.md)
- Rust-native external contracts 架构基线（目标 package layout / Host ABI / runtime boundary）：[trillionnium-rust/docs/protocol/external-contracts-rust/RUST_NATIVE_EXTERNAL_CONTRACTS_ARCH_2026-03-05.md](trillionnium-rust/docs/protocol/external-contracts-rust/RUST_NATIVE_EXTERNAL_CONTRACTS_ARCH_2026-03-05.md)
- `contracts-rust/` 当前状态与边界说明：[contracts-rust/README.md](contracts-rust/README.md)
- PoUW 机制说明：[trillionnium-rust/docs/challenge-economics-minimal.md](trillionnium-rust/docs/challenge-economics-minimal.md)
- A2A 适配契约：[docs/agent/a2a_adapter_contract_v1.md](docs/agent/a2a_adapter_contract_v1.md)
- MCP 适配契约：[docs/agent/mcp_adapter_contract_v1.md](docs/agent/mcp_adapter_contract_v1.md)
- 运维手册：[OPERATIONS.md](OPERATIONS.md)
- OpenClaw 微型运维 Runbook：[docs/development/OPENCLAW_OPS_MICRO_RUNBOOK.md](docs/development/OPENCLAW_OPS_MICRO_RUNBOOK.md)
- Web4 前端说明：[web4-frontend/README.md](web4-frontend/README.md)
- Web4 文档中心（统一入口）：[web4-frontend/docs/README.md](web4-frontend/docs/README.md)
  - 开发指南：[web4-frontend/docs/developer-guide.md](web4-frontend/docs/developer-guide.md)
  - 运维手册：[web4-frontend/docs/operations-runbook.md](web4-frontend/docs/operations-runbook.md)
  - 发布前 Checklist：[web4-frontend/docs/release-checklist.md](web4-frontend/docs/release-checklist.md)

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
- `contracts-rust/` 当前表示的是 **Rust-native external contracts 的独立子树与 MVP 合约骨架**；它不等于已完成 `sdk/`、`runtime-spec/`、`integration-tests/` 目标布局，也不单独构成 mainnet-ready 证明。
  - 其中 `audit-events/` 更接近 shared audit-event schema 邻接层；它**不等价于** `sdk/` / `runtime-spec/` 已落地，也**不表示** canonical `wasm32-unknown-unknown` Host ABI/runtime integration 已完成。
- Web4 当前语义是：**前端默认走只读 API client；只在显式 `?mode=mock` 时回退到本地 mock snapshot；不暴露写路径。**
- 文档中若出现 `/api/v0/web4/*`，应视为历史草案命名；当前仓内前端实际消费的是 `query-task` / `query-events` / `query-capability-audit` / `query-normalized-audit-events` 这组只读接口，**不是仓内已实现的 Next.js route**。
- Explorer / indexer 接入时可先把这组接口当作最小 read-model 契约：
  - `query-task/<task_id>`
  - `query-events/<task_id>?limit=<n>`
  - `query-capability-audit/<subject-or-token>`
  - `query-normalized-audit-events?source=<source>&eventType=<eventType>&cursor=<cursor>&limit=<n>`
  - `query-events/<task_id>` 未显式传 `?limit=` 时默认返回 **100** 条，硬上限 **500** 条；超大分页请求会被 clamp，不应假设无限历史窗口。
  - `query-events/<task_id>` 的 query schema 当前 **只接受单个 `limit` 键**；未知键、重复 `limit`、大小写漂移（如 `Limit=`）、空值与编码分隔符都按 fail-closed 处理，接入侧不要假设“多余参数会被静默忽略”。
  - `query-capability-audit/<subject-or-token>` 同时接受 capability token id 与 subject DID，索引侧不必为两种 key 维护两套入口。
  - `query-normalized-audit-events` 当前只接受 `source` / `eventType` / `cursor` / `limit` 这组 query 参数；重复键、未知键、空值、编码分隔符与 query smuggling 都按 fail-closed 处理，接入侧不要把“额外参数会被忽略”当作兼容约定。
  - 带路径后缀的只读路径（如 `query-task/<id>/`、`query-events/<id>/`、`query-capability-audit/<subject>/`）接受**单个** operator trailing slash；但 `query-normalized-audit-events` 走**精确路径匹配**，不应假设 `/query-normalized-audit-events/` 可兼容。
  - 以上路径仍会对额外层级、原始/编码斜杠、query/fragment smuggling 维持 fail-closed；接入侧不要把模糊路径当作可兼容输入。
  - 这组路径当前都属于只读查询面，前端/脚本不应通过它们推断存在对称写接口。
  - 在 durable indexer / archive read replica 落地前，历史查询语义仍以当前 RPC retention window 为边界，不应把脚手架或前端只读 client 误读为“无限历史可查”。
- 本地最小 explorer service 仍只是 operator-facing scaffolding，不应误判为 production indexer：
  - 从仓库根执行：`./trillionnium-rust/scripts/v2/explorer_service_up.sh`
  - 从仓库根执行：`./trillionnium-rust/scripts/v2/explorer_service_status.sh`
  - 从仓库根执行：`./trillionnium-rust/scripts/v2/explorer_service_down.sh`
  - 或先 `cd trillionnium-rust`，再执行 `./scripts/v2/explorer_service_{up,status,down}.sh`
  - 若 `trillionnium-rust/run/explorer-service/explorer-service.env` 已存在，上述三个脚本会自动加载它；值班切换时无需再手动 `source` 才能复用同一组 bind / public URL / RPC URL 配置。
  - 若需要对外暴露该脚手架，优先采用“loopback bind + reverse proxy” 形态；最小 `nginx` 骨架与 handoff 注意事项见 `trillionnium-rust/docs/runbooks/explorer-service-scaffold.md`。
  - 默认健康检查：`http://127.0.0.1:8090/healthz`；若需非默认地址，可覆盖 `EXPLORER_HOST` / `EXPLORER_PORT` 或直接传 `EXPLORER_HEALTH_URL`。
  - `explorer_service_status.sh` 会直接回显 `pid_file` / `log_file` / `health_url`，并明确标记 `service_mode=operator-facing-static-scaffold`、`production_ready=false`，同时附带最小 Day-1 read-contract 字段（`read_contract_mode`、`day1_surface`、`historical_query_scope` 等），便于 operator 在 down/degraded/handoff 场景直接确认这是 RPC-backed 的只读脚手架，而不是 durable indexer。
  - `explorer_service_down.sh` 现在也会复用同一组 read-contract 字段，便于在 stop / stale-pid 清理 / handoff 场景保留一致的只读边界说明，而不必额外跑一次 `status`。
  - 推荐将脚手架操作与值班排障步骤统一参照：`trillionnium-rust/docs/runbooks/explorer-service-scaffold.md`
- 自动化脚本较多，优先使用本 README、`RELEASE_READINESS.md` 和 `docs/development` 下统一调度文档作为导航。

---

## License

MIT
