# Trillionnium Message→LLM→Verify→Chain MVP（7天落地草案）

## 目标
在 7 天内打通最小闭环：

用户发消息 → 平台生成链上任务 → Worker-Agent 调用大模型 → 结果回传并可验证 → 链上确认与事件回放。

---

## 一、最小闭环架构

1. **Gateway（消息入口）**
   - 接收用户消息（imessage/telegram/webhook）
   - 生成 `request_id`（全局唯一）
   - 调用 `trnm-cli tx commit-result` / 任务创建接口写入 `OPEN`

2. **Scheduler / Dispatcher（任务调度）**
   - 从链上/RPC 拉取 `OPEN` 任务
   - 分配给 `trnm-worker-agent`（`ASSIGNED`）

3. **LLM Adapter（模型适配层）**
   - 统一请求：`model, prompt, session_id, temperature, max_tokens`
   - 统一响应：`output_text, finish_reason, token_usage, latency_ms, provider_request_id`
   - 产出 `result_hash=sha256(canonical_result_json)`

4. **Verifier（结果验证）**
   - 校验字段完整性、schema、max length、敏感内容策略
   - 校验 `nonce/request_id/session_id` 绑定
   - 输出 `verified=true/false` 与 `resolution_code`

5. **Chain Commit（上链确认）**
   - 通过 commit/reveal/challenge/resolve 状态机提交
   - 事件输出包含：`request_id/session_id/model/result_hash/resolution_code`

6. **Query / Replay（查询回放）**
   - 用户可按 `request_id` 查询：原始消息摘要、模型响应摘要、链上状态、审计事件

---

## 二、接口草案（MVP）

## 1) 消息入口 API
`POST /v1/messages`

```json
{
  "channel": "telegram",
  "user_id": "u123",
  "session_id": "s456",
  "text": "帮我总结这段话",
  "idempotency_key": "msg-20260222-xxx"
}
```

返回：

```json
{
  "request_id": "req_abc",
  "task_id": "1001",
  "status": "OPEN"
}
```

## 2) Worker 执行结果上报
`POST /v1/worker/results`

```json
{
  "request_id": "req_abc",
  "task_id": "1001",
  "worker_id": "worker-1",
  "model": "gemini-flash",
  "output_text": "...",
  "token_usage": {"prompt": 120, "completion": 220},
  "latency_ms": 840,
  "provider_request_id": "pr_xxx",
  "nonce": 12
}
```

返回：

```json
{
  "verified": true,
  "result_hash": "0x...",
  "next_state": "REVEALED"
}
```

## 3) 查询 API
`GET /v1/requests/{request_id}`

返回：

```json
{
  "request_id": "req_abc",
  "task_id": "1001",
  "status": "COMPLETED",
  "model": "gemini-flash",
  "result_hash": "0x...",
  "resolution_code": 0,
  "events": ["create","accept","commit","reveal","resolve"]
}
```

---

## 三、7天实施计划

### Day 1
- 定义 `request_id/session_id/idempotency_key` 规范
- Gateway 创建链上任务（OPEN）

### Day 2
- Dispatcher + Worker 拉取 OPEN→ASSIGNED
- LLM Adapter 接入一个模型（先单供应商）

### Day 3
- 结果 canonical JSON + `result_hash`
- commit/reveal 端到端跑通

### Day 4
- Verifier（schema/长度/nonce/会话绑定）
- replay/reject 路径联调

### Day 5
- challenge/resolve 最小路径打通
- request 级查询接口 + 事件回放

### Day 6
- 压测：并发 100~300 请求
- 失败注入：超时、重放、重复提交

### Day 7
- 门禁脚本接入 CI（MVP profile）
- 输出 runbook + 演示脚本

---

## 四、MVP 验收标准（必须同时满足）

1. 端到端成功率 ≥ 99%（1000 条样本）
2. 重放攻击拦截率 = 100%
3. `apply_error_total=0`、`rollback_total=0`
4. 每条请求可查询 `request_id -> result_hash -> events`
5. 故障恢复后无重复结算（幂等保证）

---

## 五、当前已具备 vs 缺口

**已具备**
- BFT 基础门禁与恢复门禁
- Worker-Agent 基本链路（去重/重放拒绝）
- CLI/RPC 基础能力

**主要缺口**
- 用户消息入口到链上 request 的统一协议层
- 模型输出的标准化证明字段（可追责）
- challenge/resolve 在真实 LLM 回包场景的策略化治理

---

## 六、风险提示

- 不建议直接公网开放“无配额/无风控”的模型调用入口。
- 必须加：速率限制、租户隔离、token 成本上限、内容合规策略。
- 生产前至少跑一轮 7d soak + 故障注入报告。
