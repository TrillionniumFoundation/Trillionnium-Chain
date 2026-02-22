# Day2 落地：Dispatcher（OPEN → ASSIGNED）骨架

## 新增命令
`trnm-rpc` 新增：

```bash
dispatch-open --worker-id <id> --limit <n>
```

作用：
- 从 `run/message-gateway/requests.jsonl` 中扫描 `status=OPEN` 请求
- 批量分配给指定 worker
- 更新状态为 `ASSIGNED`
- 返回本次分配列表

## 数据字段扩展
`MessageIngressRecord` 新增：
- `assigned_worker`
- `assigned_at_unix_ms`

## 示例

```bash
cd trillionnium-rust
cargo run -q -p trnm-rpc -- submit-message \
  --channel telegram --user-id u456 --session-id s002 \
  --text "解释一下PoUW" --idempotency-key msg-002

cargo run -q -p trnm-rpc -- dispatch-open --worker-id worker-1 --limit 2
```

## 预期
- OPEN 请求转为 ASSIGNED
- 同一请求不会被重复分配（除非手工改状态）

## 下一步（Day3）
- Worker-Agent 读取 ASSIGNED 请求
- 执行 LLM Adapter，产出 canonical result + result_hash
- 回写 commit/reveal 提交队列
