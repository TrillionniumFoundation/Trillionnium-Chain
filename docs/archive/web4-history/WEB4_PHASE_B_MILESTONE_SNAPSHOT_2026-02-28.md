# Web4 Phase B Milestone Snapshot (2026-02-28)

## 状态快照
- 结论：**本轮 Phase B 里程碑收口完成（workspace green）**
- 门禁状态：X2 / I2 / M2 / D2（query CLI + runbook/smoke）均已在 `main` 合入并完成本地复核

## 本轮已合入 main 的能力与提交

### X2 gate 接入
- `8cc6b50` laneXI: wire x2 settlement contract gate into p1 chain
- `839fe2f` laneXI: add X2 minimal settlement confirm+compensation loop

能力结果：
- X2 最小结算闭环（heartbeat → confirm/fail → compensation）可执行
- P1 integration gate 已接入 x2 settlement contract gate

### I2 token 精确查询
- `3686c0a` laneXI: add capability audit query rpc entry with stable not-found
- `8cab53b` laneXI: tighten capability audit token_id filtering

能力结果：
- capability audit 查询具备稳定 not-found 语义
- `token_id` 过滤收紧为精确匹配（避免误命中）

### M2 policy gate
- `169a839` laneMV: add reputation-weighted market match scoring
- `992fb6c` laneMV: add M2 policy gate bounds drift guard with regression tests

能力结果：
- M2 信誉加权撮合已落地
- policy gate 增加 bounds drift 防护与回归测试，避免策略阈值漂移

### D2 query CLI + runbook/smoke
- `863f5c2` laneDAE: add minimal audit index CLI query by task_id
- `71a5fbb` laneDAE: add query-audit runbook and smoke check

能力结果：
- 提供最小可用 D2 审计索引查询 CLI（按 `task_id`）
- 补齐 runbook 与 smoke 校验脚本，支持标准化验收

## 复核证据（本地命令）
> 仅列关键验证命令；结果均为 PASS

```bash
# X2 gate
./scripts/v2/x2_settlement_contract_gate.sh
# => [X2][GATE][PASS] settlement contract gate passed

# I2 token lifecycle gate
./scripts/v2/i2_token_lifecycle_gate.sh
# => [I2][PASS] capability token lifecycle gate

# M2 policy gate regression
cd trillionnium-rust
cargo test -p trnm-rpc market_match_m2_policy_gate_clamps_invalid_env_values -- --exact
# => test ... ok

# D2 query smoke
./scripts/check_query_audit_smoke.sh
# => [OK] query-audit smoke passed
```

## Lane MV（Market / Verification）下一阶段推进包（高 ROI）

> 目标：基于 M2 已落地的信誉加权撮合与 policy gate，把 MV 从“可用”推进到“可解释、可回放、可压测”，并为 V2 证明回执接入预留稳定契约。

### MV-1：M2 策略可解释输出（Explainability）
- 为撮合决策补充稳定解释字段：`base_score / reputation_weight / penalty / final_score`（仅文档先行锁定字段语义）。
- 约束解释输出必须与 gate 阈值同源，避免“通过门禁但无法解释”的运维盲区。
- 产物：在 runbook 中新增 `match explain` 样例与故障排查路径（阈值漂移、环境变量污染）。

验收信号：
- 任意一次撮合可给出可复算的 score 分解；
- 解释字段与 policy gate 阈值一致性可通过单测回归验证。

### MV-2：V2 回执接入前的契约冻结（Receipt Contract Freeze）
- 明确 `fraud_proof | tee_receipt | zk_receipt` 在市场结算视角的最小统一字段（`task_id/proof_type/verdict/verified_at/cost_hint`）。
- 规定“证明缺失/迟到/格式不合法”进入争议或降级路径，不允许静默成功。
- 产物：补充 M2↔V2 交界的错误码与状态迁移表，减少后续跨 crate 漂移风险。
- 最小错误码映射（冻结）：`proof_missing -> ERR_M2V2_PROOF_MISSING`、`proof_late -> ERR_M2V2_PROOF_LATE`、`proof_invalid -> ERR_M2V2_PROOF_INVALID`、`settlement_degraded -> ERR_M2V2_SETTLEMENT_DEGRADED`。
- 最小状态迁移映射（冻结）：`pending_proof -> disputed(proof_missing|proof_late|proof_invalid) -> downgraded(settlement_degraded)`。

验收信号：
- 回执缺失/异常时，策略层 fail-closed 且错误码稳定；
- 文档状态迁移可直接映射到 gate 测试用例。

### MV 定向门禁（持续）
```bash
# M2 阈值漂移防护（夜间门禁）
./scripts/v2/m2_policy_gate_nightly_signal_test.sh

# M2 关键回归（精确用例）
cd trillionnium-rust
cargo test -p trnm-rpc market_match_m2_policy_gate_clamps_invalid_env_values -- --exact
```

## 变更策略说明
- 本次收口采用 **1 个可回滚微补丁**：新增 XI 下一阶段推进包（文档约束，不改业务逻辑）。
- 回滚方式：`git revert <this_commit>` 即可完整回退。
