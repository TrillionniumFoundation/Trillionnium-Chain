# Day6 落地：Request 级故障注入与结果汇总

新增脚本：
- `trillionnium-rust/scripts/run_request_fault_injection.sh`

新增 mock adapter：
- `scripts/llm_adapter_invalid_json.sh`
- `scripts/llm_adapter_timeout.sh`
- `scripts/llm_adapter_echo.sh`

## 覆盖场景
1. `ok`：正常模型回包
2. `invalid_json`：adapter 返回非法 JSON
3. `too_long`：模型输出超长，触发 verifier 拒绝

## 最近一次报告
- `trillionnium-rust/run/health/request-fault-injection-20260222-104834.txt`

结果摘要：
- ok -> `COMMIT_QUEUED` / `accepted` / `ok`
- invalid_json -> `ASSIGNED`（run-assigned 返回非0，待后续补“adapter错误显式状态”）
- too_long -> `REJECTED` / `rejected` / `output_too_long`

## 结论
- verifier 拒绝路径已可观测（request 维度）
- adapter 非法回包路径已可复现
- 下一步应补：adapter 异常时把状态从 ASSIGNED 明确推进到 `FAILED_ADAPTER`
