# Operations（Agent↔User Phase A 补充）

> 适用范围：`trillionnium-rust/crates/trnm-rpc` Phase A 可靠性与 relay 语义。

## 新增参数

### 1) 批量 ACK（relay）

`RelayAckRequest` 新增：

- `upto_seq: Option<u64>`：按 session 内消息序号做“前缀批量 ACK”（`sequence <= upto_seq` 全部确认）。
- `envelope_ids: Vec<u64>` 仍保留，兼容单条/批量按 ID ACK。

建议：
- 实时消费端优先用 `upto_seq`，可减少 ACK 请求数量与去重复杂度。
- 对跨会话 ACK 无效（仅作用于当前 `session_id`）。

### 2) Retry 熔断（reliability）

`RetryConfig` 参数：

- `base_backoff_ms`：重试基础退避
- `max_backoff_ms`：重试退避上限
- `max_attempts`：单消息最大重试次数（超限后丢弃 pending）
- `circuit_breaker_threshold`：触发熔断阈值（连续失败计数）
- `circuit_open_ms`：熔断打开窗口（窗口内暂停重试发放）

## 排障方法

### A. ACK 批量异常

现象：`poll` 仍返回已处理消息。

排查：
1. 确认 ACK 请求 `session_id` 与消息一致。
2. 使用 `upto_seq` 时，确认阈值序号覆盖到目标消息（`sequence <= upto_seq`）。
3. 混用 `envelope_ids` 与 `upto_seq` 时，以服务端返回 `acked` 数量核对预期。

### B. Retry 无重放 / 重试突然停止

现象：`collect_due_retries` 返回空，但存在 pending。

排查：
1. 检查是否触发熔断窗口（circuit open）。
2. 检查是否达到 `max_attempts`（达到后 pending 会被清理）。
3. 核对当前时间戳与 `next_retry_at_unix_ms`、`circuit_open_ms`。

## 持久化 store（生产默认）

Phase A gate 默认使用 sqlite 持久化 reliability store（用于重启后去重 smoke）：

- `RELIABILITY_STORE`：`sqlite`（默认）或 `memory`（显式兼容模式）
- `RELIABILITY_DB_PATH`：sqlite DB 路径覆盖项；未设置时默认顺序为：`$XDG_STATE_HOME/trillionnium/reliability.sqlite` → `$HOME/.trillionnium/reliability.sqlite` → `run/reliability/reliability.sqlite`

示例：

```bash
cd trillionnium-rust
RELIABILITY_STORE=sqlite \
RELIABILITY_DB_PATH=run/health/reliability-phasea.sqlite \
./scripts/run_agent_user_phasea_gate.sh
```

排障：
- 现象：sqlite smoke 未执行
  - 检查是否显式设置了 `RELIABILITY_STORE=memory`（该模式下会跳过 sqlite smoke）
- 现象：报错 `expected sqlite db created`
  - 检查 `RELIABILITY_DB_PATH`（若设置）目录是否可写
  - 检查 gate 报告里是否出现 `reliability_db_path=...`

## Soak SLO 门禁（Phase A）

新增脚本：`trillionnium-rust/scripts/run_phasea_soak_gate.sh`

用途：读取 soak / fault 报告并按阈值做自动判定，默认阈值：

- `COMMIT_QUEUED >= 99%`
- `proof_verify_fail = 0`
- `store_rejected <= 0`（可配）
- `retry_exhausted <= 0`（可配）

默认输入文件（可被环境变量覆盖）：

- `SOAK_RESULT`：默认优先匹配 `run/health/phasea-soak-*`，其次 `run/health/*phasea*soak*`
- `FAULT_RESULT`：默认优先匹配 `run/health/request-fault-injection-*`

阈值环境变量：

- `MIN_COMMIT_QUEUED_PCT`（默认 `99`）
- `MAX_PROOF_VERIFY_FAIL`（默认 `0`）
- `MAX_STORE_REJECTED`（默认 `0`）
- `MAX_RETRY_EXHAUSTED`（默认 `0`）

输出：`run/health/phasea-soak-gate-<timestamp>.txt`

示例：

```bash
cd trillionnium-rust
SOAK_RESULT=run/health/phasea-soak-20260222-200000.txt \
FAULT_RESULT=run/health/request-fault-injection-20260222-200010.txt \
MAX_STORE_REJECTED=2 \
MAX_RETRY_EXHAUSTED=1 \
./scripts/run_phasea_soak_gate.sh
```

失败判定：任一指标越阈值即非 0 退出，并在报告中写入 `phasea_soak_gate.fail=...`。

## 门禁与 CI 纳管

已纳入 `run_agent_user_phasea_gate.sh` 的显式检查：

- `relay_ack_upto_seq_batch_and_boundaries`
- `circuit_breaker_opens_and_recovers_after_window`
- `reliability_persistent_store_smoke`（当 `RELIABILITY_STORE=sqlite` 时执行）

CI workflow：`.github/workflows/agent-user-phasea-gate.yml`（调用上述 gate 脚本）。

## 产品层最小 API 测试步骤（Create Account -> Balance -> Transfer -> GetTx）

建议按固定顺序执行（与脚本化联调一致）：

1. 创建/准备测试账户（`ALICE_ADDR`、`BOB_ADDR`）
2. `balance(ALICE_ADDR)` 确认初始余额
3. `nonce(ALICE_ADDR)` 获取下一 nonce
4. `sendTx(from,to,amount,nonce,signature)` 发起转账
5. `getTx(txHash)` 轮询至终态（`committed/success`）

可直接复用仓库根目录 `OPERATIONS.md` 中同名章节示例命令。

一键脚本（推荐）：

```bash
./scripts/v2/product_layer_smoke.sh
```

脚本会按 `wallet create -> query balance -> tx transfer -> getTx` 顺序执行，并输出统一结果：
- `[SMOKE][PASS] ...` / `[SMOKE][FAIL] ...`
- `address=...`
- `tx_hash=...`
- `status=...`

## 一键回滚（Phase A）

仓库根目录提供回滚脚本：`scripts/rollback_phasea.sh`

```bash
./scripts/rollback_phasea.sh <commit-or-tag>
# 跳过确认（CI/自动化场景）
./scripts/rollback_phasea.sh <commit-or-tag> --yes
```

行为：
1. 解析并校验目标 commit/tag
2. 交互确认（默认需输入 `ROLLBACK`）
3. `git checkout --detach <target>` 切换代码
4. 运行态清理（devnet 关闭、常见进程清理、phaseA 临时文件清理）
5. 执行最小验证：`trillionnium-rust/scripts/run_agent_user_phasea_gate.sh`

安全约束：
- 默认拒绝脏工作区（可用 `ALLOW_DIRTY=1` 显式覆盖）
- 任一步骤失败即退出（`set -euo pipefail`）
- 回滚日志与 gate 产物路径：`run/rollback-phasea/<timestamp>/`
