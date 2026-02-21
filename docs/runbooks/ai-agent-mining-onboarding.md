# AI Agent 挖矿接入 Runbook（单机 -> 多 Agent）

更新：2026-02-21

## 目标

在本地完成两件事：
1. 验证 Worker-Agent 门禁（含 replay/nonce/retry/failed/resume）。
2. 用多 worker 身份做一轮可复现 smoke，形成可审计产物。

---

## 0) 前置条件

- 仓库根目录：`TrillionniumChain/`
- 已具备 Rust 工具链（若 PATH 无 `cargo`，脚本会走 rustup 路径）
- 建议先确保 tx CLI 可用：
  - `./trillionnium-rust/target/debug/trnm-cli tx --help`
- 建议先初始化一个本地钱包（MVP）：
  - `./trillionnium-rust/target/debug/trnm-cli wallet generate --name dev`
  - `./trillionnium-rust/target/debug/trnm-cli wallet address --name dev`

---

## Wallet 连接（当前 MVP）

当前通过 `trnm-cli wallet` 做本地 key 管理（文件钱包）：

```bash
# 生成钱包
./trillionnium-rust/target/debug/trnm-cli wallet generate --name dev

# 导入钱包（32-byte hex 私钥）
./trillionnium-rust/target/debug/trnm-cli wallet import --name dev2 --private-key-hex <hex>

# 查看地址
./trillionnium-rust/target/debug/trnm-cli wallet address --name dev

# 对消息签名
./trillionnium-rust/target/debug/trnm-cli wallet sign --name dev --message "hello"
```

> 注意：这是开发期 MVP 钱包（本地文件存储），用于联调；生产环境需接入 HSM/远程签名或标准 keyring。

## 1) 单机最小接入（标准）

```bash
cd TrillionniumChain
./scripts/v2/run_worker_receipt_gates.sh
```

通过标准：
- full-loop / replay / failed / resume / retry+nonce boundary 全部 `[OK]`
- 最终出现：`worker receipt gates passed`

---

## 2) 单机最小接入（strict real-cli）

```bash
cd TrillionniumChain
TRNM_TX_CLI=./trillionnium-rust/target/debug/trnm-cli \
  ./scripts/v2/run_worker_receipt_gates_real_cli.sh
```

通过标准：
- readiness 报告生成：`data/worker-cli-readiness/worker-real-cli-readiness-*.md`
- 最终出现：`worker receipt real-cli gates passed`

---

## 3) 一键“单机->多 Agent”验证

```bash
cd TrillionniumChain
TRNM_TX_CLI=./trillionnium-rust/target/debug/trnm-cli AGENTS=3 \
  ./scripts/v2/worker_agent_mining_onboard.sh

# 并发提交模式（默认开启）
TRNM_TX_CLI=./trillionnium-rust/target/debug/trnm-cli AGENTS=8 PARALLEL_SUBMIT=1 MAX_PARALLEL=4 \
  ./scripts/v2/worker_agent_mining_onboard.sh
```

可选：

```bash
# 不跑门禁，只做多 Agent smoke
SKIP_GATES=1 AGENTS=5 ./scripts/v2/worker_agent_mining_onboard.sh
```

输出产物：
- `data/worker-onboard/<run_tag>/submits.jsonl`
- `data/worker-onboard/<run_tag>/acks.jsonl`
- `data/worker-onboard/<run_tag>/events.jsonl`
- `data/worker-onboard/<run_tag>/progress.jsonl`
- `data/worker-onboard/<run_tag>/summary.json`

通过标准：
- `summary.json` 中 `ok=true`
- `failed=0` 且 `terminal(accepted+rejected) >= AGENTS`
- 吞吐字段存在：
  - `throughput.submit_tasks_per_sec`
  - `throughput.flush_acks_per_sec`
  - `throughput.end2end_tasks_per_sec`

---

## 4) 失败排查

1. `cargo: command not found`
   - 使用 rustup 环境执行，或补 PATH 到 rust toolchain。
2. real-cli not ready
   - 检查 `TRNM_TX_CLI` 指向的程序是否支持 `tx --help`。
3. accepted 数不足
   - 查看 `acks.jsonl` / `events.jsonl` 的 `reason` 与 `reason_code`。

---

## 5) 团队移交建议

- CI 侧默认跑：`run_worker_receipt_gates.sh`
- 预发布/夜间跑：`run_worker_receipt_gates_real_cli.sh`
- 集成演示与验收用：`worker_agent_mining_onboard.sh`（AGENTS 按容量调节）
