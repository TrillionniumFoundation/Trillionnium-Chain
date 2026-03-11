# Local Release Evidence Runbook

## 单命令生成证据包

在仓库根目录执行：

```bash
./scripts/run_local_release_evidence.sh
```

脚本会串联以下检查：

> 注意：该脚本生成的是 **release evidence bundle**，不是“必定通过”的绿色证明。任一步骤失败时，脚本会 **fail-closed**，并在 `summary.txt` 中把对应步骤记为 `FAIL(...)`；是否可用于当前 release/readiness 判断，必须结合仓库根 `RELEASE_READINESS.md` 与本次 `summary.txt` 一起看。

1. `cargo test`（关键包：`trnm-node` / `trnm-worker-agent` / `trnm-rpc` / `trnm-pouw` / `trnm-state`）
2. `scripts/check_request_tx_binding.sh`
3. `scripts/run_request_fault_injection.sh`
4. challenge reexec 入口（必跑；若未找到 `*challenge*reexec*.sh` 则直接记为 FAIL）

输出目录统一为：

- `run/health/evidence-<timestamp>/`
- 汇总文件：`run/health/evidence-<timestamp>/summary.txt`
- 各步骤日志：`*.log`
- 子脚本证据文件（例如 `request-tx-binding-*.txt`、`request-fault-injection-*.txt`）

判读规则：
- `summary.txt` 是本次证据包的**唯一汇总入口**。
- 只要任一步骤记为 `FAIL(...)`，本次证据包就只能作为失败/差距留痕，**不能**被表述为“当前 release-ready 证明”。
- 若需要引用历史成功证据，必须明确它是历史轮次产物，不能覆盖当前 truth-source。

可选：通过 `OUT_DIR` 指定证据根目录：

```bash
OUT_DIR=/tmp/trnm-evidence ./scripts/run_local_release_evidence.sh
```

## RC 复现与回滚留痕（M3）

为减少“同命令不同结果”的波动，建议在采集证据前固定环境，并优先使用与 `RELEASE_READINESS.md` 一致的 deterministic 前缀：

```bash
env TZ=UTC LC_ALL=C LANG=C SOURCE_DATE_EPOCH=1704067200 \
  CARGO_TERM_COLOR=never \
  RUST_BACKTRACE=1 \
  CARGO_BUILD_JOBS=1 \
  ./scripts/run_local_release_evidence.sh
```

如需二次复跑比对，请保持命令与环境完全一致，再连续执行一次相同命令，避免把一次性绿灯误判为稳定 release 证据。

执行完成后，在 `summary.txt` 末尾追加：

- 本次证据目录绝对路径
- 复放命令：`./scripts/run_local_release_evidence.sh`
- 回滚命令：`rm -rf <evidence_dir>`（仅删除本次生成目录）
