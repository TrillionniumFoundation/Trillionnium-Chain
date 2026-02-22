# Day5 落地：Request 全量查询（request + verifier + events）

## 新增能力
`trnm-rpc` 新增命令：

```bash
query-request-full --request-id <id>
```

返回结构：
- `request`：基础请求信息（request_id/task_id/status/session）
- `verifier_status`
- `resolution_code`
- `result_hash`
- `events`：按 task_id 关联到 node 事件流

## 目标
让用户侧/运维侧可按 `request_id` 一次性看到：
- 当前处理状态
- LLM 输出是否通过验证
- 上链事件是否推进

## 示例

```bash
cd trillionnium-rust
cargo run -q -p trnm-rpc -- query-request-full --request-id req_482f8c7865e25d55
```

## 当前样例结果
- `status=COMMIT_QUEUED`
- `verifier_status=accepted`
- `resolution_code=ok`
- `result_hash` 已生成
- `events` 当前为空（尚未进入链上 commit/reveal 执行后阶段）

## 下一步（Day6）
- 接入故障注入（adapter timeout / invalid json / verifier reject）
- 输出 request 级失败原因统计
