# Trillionnium Codebase Map

_Last updated: 2026-02-25_

## 1) 主线定位

- 主线代码：`trillionnium-rust/`
- 编排/自动化入口：仓库根 `scripts/`（尤其 `scripts/v2/`）
- 文档中心：`docs/`
- 历史冻结：`legacy/`

## 2) Rust workspace 结构

`trillionnium-rust/Cargo.toml` 当前包含 10 个 crates：

- `trnm-node`：节点循环、执行接线、事件产出
- `trnm-state`：版本化对象存储、`state_root()`
- `trnm-pouw`：PoUW 状态机（OPEN→...→COMPLETED/SLASHED）
- `trnm-executor`：冲突检测、并发执行分组
- `trnm-mempool`：交易池与打包策略
- `trnm-rpc`：RPC 查询与服务层
- `trnm-worker-agent`：worker 拉取/执行/commit-reveal/重试与去重
- `trnm-cli`：tx/query 原生 CLI
- `trnm-bench`：classic/mixed 等基准测试
- `trnm-types`：跨 crate 共享类型

配套目录：
- `trillionnium-rust/configs/`：节点/环境配置
- `trillionnium-rust/scripts/`：workspace 内脚本
- `trillionnium-rust/run/`：Rust 侧运行产物
- `trillionnium-rust/release/`：RC/发布产物

## 3) 仓库根目录分层

- `scripts/`：跨模块自动化与回归编排
  - `run_100step_pipeline.sh`
  - `run_200step_pipeline.sh`
  - `run_200step_v2_pipeline.sh`
  - `run_codegen_pipeline.sh`
  - `quick_gate_shell.sh`
  - `v2/`：当前主力 gate 与产品层脚本
- `docs/`：架构、协议、perf、runbook、产品文档
- `data/`：测试/验收/回归/报告输出（时间戳目录）
- `run/`：仓库级运行输出（按 PR/场景分类）
- `config/`：告警/策略配置
- `legacy/`：历史归档（非主线）

## 4) 推荐阅读顺序

1. `README.md`
2. `docs/architecture/README.md`
3. `docs/protocol/rust-l1-v1-interface-freeze.md`
4. `STATUS.md`
5. `OPERATIONS.md`

## 5) 推荐执行顺序（本地健康检查）

```bash
./scripts/quick_gate_shell.sh
./scripts/run_200step_v2_pipeline.sh
./scripts/v2/run_worker_receipt_gates.sh
```

如需真实交易环境 strict 检查：

```bash
TRNM_TX_CLI=./trillionnium-rust/target/debug/trnm-cli \
  ./scripts/v2/run_worker_receipt_gates_real_cli.sh
```

## 6) 整理原则（后续维护）

- 任何新功能必须明确归属到某个 crate 与对应 gate。
- 任何脚本新增，优先进入 `scripts/v2/` 并补最小文档链接。
- `data/` 与 `run/` 只放产物，不作为“源码事实来源”。
- 历史路径仅保留在 `legacy/`，避免在主 README 继续暴露旧入口。
