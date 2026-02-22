# Day1 落地：Message Ingress 协议与入口骨架

## 新增能力
通过 `trnm-rpc` 增加两条命令：

1. `submit-message`
2. `query-request`

用于把用户消息登记为链上任务前置请求（MVP Day1）。

## 字段规范
- `request_id`：`req_<16hex>`，由 channel/user/session/idempotency_key/time 生成
- `session_id`：会话主键（用户维度）
- `idempotency_key`：客户端幂等键，重复提交返回同一个记录
- `task_id`：本地骨架中从 10001 起分配

## 存储
- 文件：`trillionnium-rust/run/message-gateway/requests.jsonl`
- 一行一个 JSON 记录，方便后续 Dispatcher/Worker 读取

## 使用示例

```bash
cd trillionnium-rust
cargo run -q -p trnm-rpc -- submit-message \
  --channel telegram \
  --user-id u123 \
  --session-id s001 \
  --text "帮我总结这段话" \
  --idempotency-key msg-001

cargo run -q -p trnm-rpc -- query-request req_xxxxxxxxxxxxxxxx
```

## 预期输出
- `submit-message` 输出 `request_id/task_id/status=OPEN`
- 重复相同 `session_id + idempotency_key` 不会生成新任务

## 下一步（Day2）
- Dispatcher 读取 OPEN 请求并生成 ASSIGNED
- Worker-Agent 拉取 ASSIGNED 并接入 LLM Adapter
