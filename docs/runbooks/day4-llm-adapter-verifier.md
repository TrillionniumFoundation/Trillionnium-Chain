# Day4 落地：LLM Adapter + Verifier 接入 run-assigned

## 新增能力
`trnm-worker-agent run-assigned` 现已接入：
- LLM Adapter 调用（可插拔命令）
- 基础 Verifier（空输出 / 超长输出拦截）

## 新参数
```bash
--llm-adapter-cmd <cmd>           # 默认 ./scripts/llm_adapter_mock.sh
--verifier-max-output-chars <n>   # 默认 4000
```

## 状态流
- `ASSIGNED` + verifier accepted -> `COMMIT_QUEUED`
- verifier rejected -> `REJECTED`

并回写字段：
- `model_output`
- `result_hash`
- `verifier_status`
- `resolution_code`

## Mock Adapter
新增脚本：`scripts/llm_adapter_mock.sh`
- 入参：prompt
- 出参 JSON：`output_text`, `provider_request_id`

## 验证样例
```bash
cargo run -q -p trnm-worker-agent -- run-assigned \
  --worker worker-1 \
  --ingress-file run/message-gateway/requests.jsonl \
  --limit 1 \
  --submit-log /tmp/trnm-worker-agent-submissions.jsonl \
  --llm-adapter-cmd ./scripts/llm_adapter_mock.sh \
  --verifier-max-output-chars 4000
```

## 下一步（Day5）
- challenge/resolve 最小路径接入 request_id 维度查询
- Query API 返回 request + events + verifier 状态汇总
