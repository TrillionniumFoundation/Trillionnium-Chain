# trnm-worker-agent timeout/retry 参数口径（Runbook）

## 0) devnet / smoke 最小前置条件（run-assigned）

`trnm-worker-agent run-assigned` **只会处理** ingress 中同时满足以下条件的记录：

- `status == "assigned"`
- `assigned_worker == <当前 --worker>`

如果 devnet smoke 输入还是 `open` / `queued`，或者没有写入 `assigned_worker`，worker 会跳过该记录，不会生成 submission。这是当前约定行为，不是链路故障。

### 最小可处理样例

```jsonl
{"request_id":"req-devnet-1","task_id":4242,"channel":"telegram","user_id":"u1","session_id":"s1","text":"Return JSON with result field only","idempotency_key":"idem-1","status":"assigned","created_at_unix_ms":1700000000000,"assigned_worker":"worker-a","assigned_at_unix_ms":1700000001000}
```

### 诊断口径

`run-assigned` 结束时会输出 `skipped=` 汇总，常见值：

- `status_not_assigned`
- `assigned_worker_missing`
- `assigned_worker_mismatch`

这几个计数优先用于定位 devnet/operator smoke 输入问题。

---

## 1) 统一参数与优先级

本次将 `timeout/max_retries/backoff_ms` 统一为“**CLI > ENV > 内置默认值**”的读取顺序，并集中在 `crates/trnm-worker-agent/src/main.rs` 的配置解析函数中。

- `resolve_tx_retry_policy(...)`
- `resolve_llm_adapter_policy(...)`
- `resolve_u32/resolve_u64(...)`

### TX 提交适配器（flush-submissions）
- `max_retries`
  - CLI: `--max-retries`
  - ENV: `TRNM_TX_ADAPTER_MAX_RETRIES`
  - 默认: `3`
- `backoff_ms`
  - CLI: `--backoff-ms`
  - ENV: `TRNM_TX_ADAPTER_BACKOFF_MS`
  - 默认: `200`

### LLM 适配器（run-assigned）
- `max_retries`
  - CLI: `--llm-adapter-max-retries`
  - ENV: `TRNM_LLM_ADAPTER_MAX_RETRIES`
  - 默认: `2`
- `backoff_ms`
  - CLI: `--llm-adapter-backoff-ms`
  - ENV: `TRNM_LLM_ADAPTER_BACKOFF_MS`
  - 默认: `200`
- `timeout_ms`
  - CLI: `--llm-adapter-timeout-ms`
  - ENV: `TRNM_LLM_ADAPTER_TIMEOUT_MS`
  - 默认: `10000`
  - 约束: `>=1`，非法值（如 `0`/非数字）自动回退默认值

---

## 2) Prod 推荐值与调参边界

> 目标：在链上提交成功率、端到端延迟和下游稳定性之间取平衡。

### 推荐起步（prod baseline）

- TX adapter:
  - `TRNM_TX_ADAPTER_MAX_RETRIES=5`
  - `TRNM_TX_ADAPTER_BACKOFF_MS=300`
- LLM adapter:
  - `TRNM_LLM_ADAPTER_MAX_RETRIES=3`
  - `TRNM_LLM_ADAPTER_BACKOFF_MS=300`
  - `TRNM_LLM_ADAPTER_TIMEOUT_MS=15000`

### 边界建议（避免极端参数）

- `max_retries`: 建议 `0~8`
  - `0` 仅用于压测/故障注入，不建议常态生产
  - `>8` 往往只会放大尾延迟
- `backoff_ms`: 建议 `100~2000`
  - `<100` 可能导致瞬时重试风暴
  - `>2000` 容易拖慢恢复时间
- `timeout_ms`（LLM）: 建议 `3000~60000`
  - `<3000` 容易误杀慢请求
  - `>60000` 会积压 worker 并放大排队时延

### 调参策略

1. 先调 `timeout_ms` 到 P95~P99 响应时间上方。
2. 再调 `max_retries`（2→3→5）观察成功率收益。
3. 最后调 `backoff_ms`，优先避免重试风暴（建议 `200~500ms` 起步）。

---

## 3) 兼容性说明

- CLI 参数名保持不变，仅将默认值解析方式统一到集中逻辑。
- 新增 ENV 读取：
  - `TRNM_TX_ADAPTER_MAX_RETRIES`
  - `TRNM_TX_ADAPTER_BACKOFF_MS`
  - `TRNM_LLM_ADAPTER_MAX_RETRIES`
  - `TRNM_LLM_ADAPTER_BACKOFF_MS`
- `TRNM_LLM_ADAPTER_TIMEOUT_MS` 仍保留；同时支持 CLI `--llm-adapter-timeout-ms` 覆盖。
- 非法值回退默认值，不会导致进程启动失败（向后兼容）。
