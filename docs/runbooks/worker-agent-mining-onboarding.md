# Worker-Agent 挖矿接入 Runbook（MVP）

日期：2026-02-21  
目标：30~60 分钟内完成 **1 个 AI agent** 的 PoUW 最小可用接入，并可复现扩展。

## 0) 前提

- 仓库根目录：`TrillionniumChain/`
- 本地已有可运行链路（dev/test 环境）
- 可用 Rust toolchain（若 PATH 不稳定，见下方命令）

## 1) 一键执行（推荐）

```bash
cd TrillionniumChain
./scripts/v2/worker_agent_onboard_mvp.sh
```

该脚本会做：
1. real-cli readiness 检查
2. worker receipt gates（full-loop/replay/failed/resume/retry+nonce）
3. strict real-cli gates（使用 `trnm-cli`）

## 2) 手动分步（排障用）

### 2.1 构建 `trnm-cli`

```bash
cd TrillionniumChain/trillionnium-rust
export PATH="/Users/$USER/.rustup/toolchains/stable-aarch64-apple-darwin/bin:$PATH"
export RUSTC="/Users/$USER/.rustup/toolchains/stable-aarch64-apple-darwin/bin/rustc"
export CARGO="/Users/$USER/.rustup/toolchains/stable-aarch64-apple-darwin/bin/cargo"
$CARGO build -p trnm-cli
```

### 2.2 基础门禁

```bash
cd TrillionniumChain
./scripts/v2/run_worker_receipt_gates.sh
```

### 2.3 strict real-cli 门禁

```bash
TRNM_TX_CLI=./trillionnium-rust/target/debug/trnm-cli \
  ./scripts/v2/run_worker_receipt_gates_real_cli.sh
```

## 3) 通过标准（Go / No-Go）

- `run_worker_receipt_gates.sh` 最后一行出现：
  - `[OK] worker receipt gates passed ...`
- `run_worker_receipt_gates_real_cli.sh` 最后一行出现：
  - `[OK] worker receipt real-cli gates passed ...`
- readiness 报告生成：
  - `data/worker-cli-readiness/worker-real-cli-readiness-<ts>.md`

## 4) 扩展到多 agent（建议）

- 先固定 1 个模板 worker（`worker1`）跑通，再并行复制为 `worker2~N`
- 每个 worker 使用独立 state/submit/ack 日志，避免 nonce/replay 污染
- 保持统一 adapter 与 retry/backoff 参数，先求稳定后调性能

## 5) 常见问题

- `cargo: command not found`：使用显式 toolchain PATH（见 2.1）
- readiness 显示 NOT_READY：检查 `TRNM_TX_CLI` 是否支持 `tx --help`
- replay/nonce 异常：确认是否复用了旧状态文件或共享日志路径
