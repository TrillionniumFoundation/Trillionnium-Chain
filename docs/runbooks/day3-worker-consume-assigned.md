# Day3 落地：Worker-Agent 消费 ASSIGNED 并生成 commit/reveal 队列

## 新增命令
`trnm-worker-agent` 新增：

```bash
run-assigned --worker <worker-id> [--ingress-file <path>] [--limit <n>] [--submit-log <path>]
```

## 行为
- 从 `requests.jsonl` 读取 `status=ASSIGNED` 且 `assigned_worker` 匹配的请求
- 以消息 `text` 作为 payload 执行 `execute_payload`（MVP占位）
- 生成 `result_hash/salt_hex/commit_hash`
- 写入提交队列（`submit_log`，默认 `/tmp/trnm-worker-agent-submissions.jsonl`）
- 将请求状态更新为 `COMMIT_QUEUED`

## 示例

```bash
cd trillionnium-rust
cargo run -q -p trnm-worker-agent -- run-assigned \
  --worker worker-1 \
  --ingress-file run/message-gateway/requests.jsonl \
  --limit 5 \
  --submit-log /tmp/trnm-worker-agent-submissions.jsonl
```

## 本地验证结果
- 两条 ASSIGNED 请求已转为 `COMMIT_QUEUED`
- `submissions.jsonl` 已包含对应 `commit_cmd/reveal_cmd`

## 下一步（Day4）
- 将 LLM Adapter 真正接入 `run-assigned` 的执行路径（替换 demo payload hash）
- 引入验证器输出（schema/长度/策略/nonce检查）并回写状态
