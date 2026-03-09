# Local Release Evidence Runbook

## 单命令生成证据包

在仓库根目录执行：

```bash
./scripts/run_local_release_evidence.sh
```

脚本会串联以下检查：

1. `cargo test`（关键包：`trnm-node` / `trnm-worker-agent` / `trnm-rpc` / `trnm-pouw` / `trnm-state`）
2. `scripts/check_request_tx_binding.sh`
3. `scripts/run_request_fault_injection.sh`
4. challenge reexec 入口（必跑；若未找到 `*challenge*reexec*.sh` 则直接记为 FAIL）

输出目录统一为：

- `run/health/evidence-<timestamp>/`
- 汇总文件：`run/health/evidence-<timestamp>/summary.txt`
- 各步骤日志：`*.log`
- 子脚本证据文件（例如 `request-tx-binding-*.txt`、`request-fault-injection-*.txt`）

可选：通过 `OUT_DIR` 指定证据根目录：

```bash
OUT_DIR=/tmp/trnm-evidence ./scripts/run_local_release_evidence.sh
```

## RC 复现与回滚留痕（M3）

为减少“同命令不同结果”的波动，建议在采集证据前固定环境：

```bash
export CARGO_TERM_COLOR=never
export RUST_BACKTRACE=1
export CARGO_BUILD_JOBS=1
./scripts/run_local_release_evidence.sh
```

执行完成后，在 `summary.txt` 末尾追加：

- 本次证据目录绝对路径
- 复放命令：`./scripts/run_local_release_evidence.sh`
- 回滚命令：`rm -rf <evidence_dir>`（仅删除本次生成目录）
