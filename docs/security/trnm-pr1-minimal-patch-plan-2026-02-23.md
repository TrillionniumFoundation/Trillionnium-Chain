# TRNM PR-1 Minimal Patch Plan (P0 quick win)

> PR-1 目标：先拿下“最小安全闭环”三件事
> 1) Governance value schema
> 2) RPC hard caps
> 3) Strict real-cli 真实性门禁

---

## A. Governance value schema（`trnm-state` + `trnm-node`）

## 需改文件
- `trillionnium-rust/crates/trnm-state/src/lib.rs`
- `trillionnium-rust/crates/trnm-node/src/main.rs`（若有参数生效路径）

## 具体改动
1. 在 `trnm-state` 增加解析器：
   - `parse_u64_in_range(key, value, min, max)`
   - `parse_bool_strict(key, value)`
2. 建立 key->schema 映射（先覆盖高风险参数）：
   - `max_block_ms`（u64, 范围）
   - `challenge_window_blocks`（u64, 范围）
   - `min_worker_stake`（u64, 范围）
   - `emergency_pause`（bool 严格）
3. `set_governance_param` 写入前校验 schema，失败返回明确错误。
4. 生效链路打印审计日志：`key, old, new, proposal_id, actor, height`。

## 验收
- 非法值无法写入
- `emergency_pause=TRUE/1/yes` 等非严格值拒绝

---

## B. RPC hard caps（`trnm-rpc`）

## 需改文件
- `trillionnium-rust/crates/trnm-rpc/src/main.rs`

## 具体改动
1. 增加统一常量：
   - `QUERY_EVENTS_LIMIT_DEFAULT = 100`
   - `QUERY_EVENTS_LIMIT_MAX = 500`
   - `QUERY_FULL_LIMIT_DEFAULT = 50`
   - `QUERY_FULL_LIMIT_MAX = 200`
   - `DISPATCH_OPEN_LIMIT_DEFAULT = 20`
   - `DISPATCH_OPEN_LIMIT_MAX = 100`
2. `QueryEvents` / `QueryRequestFull` 参数入口做 clamp。
3. `DispatchOpen --limit` 做服务端 clamp + over-limit warning。
4. 统一超限错误码或错误消息格式。

## 验收
- 所有相关接口都无法突破服务端 hard cap
- over-limit 请求可在日志中识别

---

## C. Strict real-cli 真实性门禁（`scripts/v2`）

## 需改文件
- `trillionnium-rust/scripts/v2/worker_real_cli_readiness.sh`
- `trillionnium-rust/scripts/v2/run_worker_receipt_gates_real_cli.sh`

## 具体改动
1. readiness 增加“最小生命周期验证”：
   - 调 `trnm-cli tx commit-result`（或项目已有最小 tx）
   - 获取 txhash
   - 再调 query 接口确认 txhash 可查询
2. 校验 txhash 格式（长度/前缀）与 query 结果字段一致性。
3. 真实性检查失败直接退出非 0，阻断 gate。
4. 将 fake-wrapper 路径纳入负例测试。

## 验收
- fake wrapper 不能通过 strict real-cli gates
- 真 CLI 路径稳定通过

---

## D. 配套测试（PR-1 必带）

- `scripts/v2/rpc_query_hardcap_enforcement_test.sh`
- `scripts/v2/worker_real_cli_fake_wrapper_block_test.sh`
- 治理参数非法值回归测试（命名建议：`scripts/v2/governance_value_schema_reject_test.sh`）

---

## E. 提交顺序建议（降低冲突）

1. Commit-1：`trnm-state` schema 校验 + 单测
2. Commit-2：`trnm-rpc` hard cap + 单测
3. Commit-3：`scripts/v2` strict real-cli 真实性门禁 + 负例测试
4. Commit-4：文档与 gate 说明更新（`OPERATIONS.md` 或相关 docs）

---

## F. 风险与回滚

- 风险：hard cap 调得过低影响调试/批处理效率
  - 回滚策略：保留 env 覆盖（仅非生产 profile 可放宽）
- 风险：strict real-cli 新门禁导致 CI 初期波动
  - 回滚策略：先在 nightly 观察 1-2 天，再设为 merge hard gate
