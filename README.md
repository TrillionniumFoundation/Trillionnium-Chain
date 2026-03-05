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
- 发布前检查脚本（`scripts/ci-check.sh`, `scripts/release-preflight.sh`, `scripts/release-ready.sh`）

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

- 项目状态：`STATUS.md`
- 统一开发调度：`docs/development/DEVELOPMENT_MASTER_UNIFIED_2026-03-04.md`
- 架构总览：`docs/architecture/README.md`
- 代码地图：`docs/architecture/CODEBASE_MAP.md`
- PoUW 时序：`docs/architecture/rust-l1-pouw-sequence.md`
- v1 接口冻结：`docs/protocol/rust-l1-v1-interface-freeze.md`
- 运维手册：`OPERATIONS.md`
- Web4 前端说明：`web4-frontend/README.md`

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

- 主线已完成“Rust L1 收敛”，默认入口为 `trillionnium-rust/`。
- `legacy/` 仅作归档，不作为当前开发入口。
- 自动化脚本较多，优先使用本 README 和 `docs/development` 下统一调度文档作为导航。

---

## License

MIT
