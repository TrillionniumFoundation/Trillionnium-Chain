# Trillionnium Chain (TRNM)

Rust-native Layer 1 for Decentralized AI Compute（PoUW）。

> 当前主线：`trillionnium-rust/`
>  
> 历史 Cosmos/早期代码：`legacy/`

## 快速导航

- 架构总览：`docs/architecture/README.md`
- 代码地图（新增）：`docs/architecture/CODEBASE_MAP.md`
- PoUW 时序：`docs/architecture/rust-l1-pouw-sequence.md`
- v1 接口冻结：`docs/protocol/rust-l1-v1-interface-freeze.md`
- 项目状态：`STATUS.md`
- 统一开发调度：`docs/development/DEVELOPMENT_MASTER_UNIFIED_2026-03-04.md`
- 运维手册：`OPERATIONS.md`

## 当前仓库结构（真实）

```text
TrillionniumChain/
├── trillionnium-rust/         # Rust workspace（核心代码）
│   ├── crates/
│   │   ├── trnm-node
│   │   ├── trnm-state
│   │   ├── trnm-pouw
│   │   ├── trnm-executor
│   │   ├── trnm-mempool
│   │   ├── trnm-rpc
│   │   ├── trnm-worker-agent
│   │   ├── trnm-cli
│   │   ├── trnm-bench
│   │   └── trnm-types
│   ├── configs/
│   ├── scripts/
│   └── run/
├── scripts/                   # 仓库级自动化与 gate 编排
├── docs/                      # 架构/协议/产品/runbook 文档
├── data/                      # 各类运行产物（验收、回归、报告）
├── run/                       # 仓库级运行日志与阶段输出
├── config/                    # 策略与告警配置
└── legacy/                    # 冻结归档
```

## 核心 crates（职责）

- `trnm-node`：节点主循环、执行接线、事件输出
- `trnm-state`：版本化状态存储与 state root
- `trnm-pouw`：PoUW 状态机（create/commit/reveal/challenge/resolve）
- `trnm-executor`：冲突检测与并发分组
- `trnm-rpc`：稳定查询接口与服务层
- `trnm-worker-agent`：worker 任务执行与链上提交链路
- `trnm-cli`：原生命令行（tx/query）
- `trnm-bench`：性能基准
- `trnm-types`：共享类型
- `trnm-mempool`：交易池与打包策略

## 常用命令（仓库根目录）

```bash
# 快速门禁检查
./scripts/quick_gate_shell.sh

# 自动化流水线
./scripts/run_100step_pipeline.sh
./scripts/run_200step_pipeline.sh
./scripts/run_200step_v2_pipeline.sh
./scripts/run_codegen_pipeline.sh

# Worker receipt gates
./scripts/v2/run_worker_receipt_gates.sh
# strict real-cli
TRNM_TX_CLI=./trillionnium-rust/target/debug/trnm-cli \
  ./scripts/v2/run_worker_receipt_gates_real_cli.sh

# Tokenomics regression gate (R1-R14, targeted fast set)
./scripts/v2/run_tokenomics_r1_r14_regression_gate.sh
```

## 代码整理说明

本仓库已完成“Rust L1 主线收敛”：
- 旧结构（`core/ tasks/ worker/ chain/`）不再作为主线入口；
- 文档与脚本将以 `trillionnium-rust/ + scripts/v2` 为第一入口持续维护。

## License

MIT
