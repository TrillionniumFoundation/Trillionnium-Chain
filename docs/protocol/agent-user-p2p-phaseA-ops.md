# Agent↔User P2P Phase A（MVP）运行说明与门禁

状态：实施中（对应 `agent-user-p2p-communication-min-spec-v0.1` 的 Phase A）

## 1. 模块范围

当前 Phase A 在 Rust L1 代码中的最小可运行链路：

- `trnm-rpc`
  - `submit-message`：写入 ingress 请求
  - `dispatch-open`：将 `OPEN` 请求分配给 worker
  - `query-request` / `query-request-full`：查询 request + verifier + events 聚合
- `trnm-worker-agent`
  - `run-assigned`：消费 `ASSIGNED` 请求，调用 LLM adapter，执行 verifier，生成提交记录
  - `flush-submissions`：调用 TX adapter，回填 `commit_tx_hash` / `reveal_tx_hash`

默认 ingress 文件：
- `trillionnium-rust/run/message-gateway/requests.jsonl`

## 2. 最小使用路径

在仓库根目录执行：

```bash
cd trillionnium-rust

# 1) 用户提交消息
cargo run -q -p trnm-rpc -- submit-message \
  --channel telegram \
  --user-id demo-user \
  --session-id demo-sid \
  --text "hello" \
  --idempotency-key demo-ikey-001

# 2) 调度 OPEN -> ASSIGNED
cargo run -q -p trnm-rpc -- dispatch-open --worker-id worker-1 --limit 1

# 3) worker 消费 ASSIGNED 请求
cargo run -q -p trnm-worker-agent -- run-assigned \
  --worker worker-1 \
  --ingress-file run/message-gateway/requests.jsonl \
  --limit 1 \
  --llm-adapter-cmd ./scripts/llm_adapter_mock.sh

# 4) 查询聚合状态
cargo run -q -p trnm-rpc -- query-request-full --request-id <request_id>
```

可选：提交链上 mock 回执（本地 adapter）

```bash
cargo run -q -p trnm-worker-agent -- flush-submissions \
  --submit-log /tmp/trnm-worker-agent-submissions.jsonl \
  --ingress-file run/message-gateway/requests.jsonl \
  --execute \
  --adapter-cmd ./scripts/worker_tx_adapter.sh
```

## 3. 配置项（Phase A）

### 3.1 run-assigned 参数

- `--worker`：worker 标识（必填）
- `--ingress-file`：请求入口 jsonl（默认 `run/message-gateway/requests.jsonl`）
- `--limit`：单次处理条数上限
- `--llm-adapter-cmd`：LLM 适配器脚本
- `--verifier-max-output-chars`：输出长度上限（默认 4000）
- `--llm-adapter-max-retries` / `--llm-adapter-backoff-ms` / `--llm-adapter-timeout-ms`

### 3.2 flush-submissions 参数

- `--adapter-cmd`：TX 适配器脚本（默认 `./scripts/worker_tx_adapter.sh`）
- `--max-retries` / `--backoff-ms`
- `--ack-log` / `--event-log` / `--progress-log`

### 3.3 环境变量（优先级低于显式 CLI 参数）

- `TRNM_TX_ADAPTER_MAX_RETRIES`
- `TRNM_TX_ADAPTER_BACKOFF_MS`
- `TRNM_LLM_ADAPTER_MAX_RETRIES`
- `TRNM_LLM_ADAPTER_BACKOFF_MS`
- `TRNM_LLM_ADAPTER_TIMEOUT_MS`

### 3.4 Relay / Reliability 新参数（Phase A）

- Relay ACK 支持 `upto_seq`：可按 session 序号做前缀批量 ACK（`sequence <= upto_seq`）。
- `RetryConfig` 新增：
  - `max_attempts`
  - `circuit_breaker_threshold`
  - `circuit_open_ms`
- Phase A gate 持久化 smoke（可选）：
  - `RELIABILITY_STORE=sqlite` 启用 sqlite 持久化 store
  - `RELIABILITY_DB_PATH=<path>` 指定 sqlite 文件路径

详见：`docs/OPERATIONS.md`

## 4. 威胁模型（Phase A 最小集）

1. **重放攻击**
   - 风险：重复提交或重复消费请求。
   - 缓解：`idempotency_key`、request 状态机、adapter 结果回填与去重。

2. **适配器异常/恶意输出**
   - 风险：invalid JSON、超长输出、超时导致状态漂移。
   - 缓解：fault injection 覆盖 `ok / invalid_json / too_long / timeout`；verifier 拒绝路径可观测。

3. **提交结果与链上回执脱钩**
   - 风险：request 最终状态缺少 tx hash 审计锚点。
   - 缓解：`check_request_tx_binding.sh` 强制校验 `commit_tx_hash` / `reveal_tx_hash` 回填。

4. **本地日志篡改/丢失**（已知限制）
   - 风险：当前 Phase A 以本地 jsonl 为入口与审计源，抗篡改能力有限。
   - 缓解：作为 MVP 仅用于流程验证；生产阶段需升级到 append-only + 远端审计存储。

## 5. 已知限制

- 当前实现为 MVP：本地文件 ingress + mock adapter 形态，不等价于生产级网关。
- 尚未实现完整 WebSocket relay、签名 envelope 验签链路、Merkle transcript proof API。
- `query-request-full` 聚合依赖本地运行产物，跨环境一致性需后续统一证据索引。

## 6. 门禁与 CI

### 本地一键门禁（新增）

```bash
cd trillionnium-rust
./scripts/run_agent_user_phasea_gate.sh
```

校验内容：
1. `trnm-rpc + trnm-worker-agent` 构建测试（`cargo test -p ...`）
2. relay ack/retry/proof 基础门禁
3. （可选）`RELIABILITY_STORE=sqlite` 时执行持久化去重 smoke
4. submit/dispatch/consume/query 最小闭环
5. 断言 `status=COMMIT_QUEUED` 且 `verifier_status=accepted`

输出：
- `trillionnium-rust/run/health/agent-user-phasea-gate-<ts>.txt`

### CI

- workflow：`.github/workflows/agent-user-phasea-gate.yml`
- 触发：`trnm-rpc` / `trnm-worker-agent` / Phase A 脚本与文档变更
- 执行：`trillionnium-rust/scripts/run_agent_user_phasea_gate.sh`
