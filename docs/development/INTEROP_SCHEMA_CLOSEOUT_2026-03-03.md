# Interop/Schema 清零收口（2026-03-03）

## 目标
将以下联动维度从 `Open/Partial` 收敛到 `Closed`：
- I↔D↔E
- X↔I
- A↔V

## 本轮证据（定向 + 必选 gate）

### 定向测试（接口联动）
- `./scripts/v2/run_p1_integration_gate_x2_invocation_test.sh` ✅
- `./scripts/v2/run_p1_integration_gate_i2_invocation_test.sh` ✅
- `./scripts/v2/a1_mcp_adapter_contract_response_schema_version_echo_test.sh` ✅

### 必选 gate（x2 / i2）
- `./scripts/v2/x2_settlement_contract_gate.sh` ✅（由 aggregate gate 链式执行）
- `./scripts/v2/i2_token_lifecycle_gate.sh` ✅（由 aggregate gate 链式执行）

### web4 aggregate gate
- `./scripts/v2/web4_release_aggregate_gate.sh` ✅

## 四维状态（收口后）

| 维度 | 当前状态 | 关闭依据 |
|---|---|---|
| I↔D↔E | Closed | D1 schema gate + E2 schema spoof/compact 回归 + aggregate 全绿 |
| X↔I | Closed | x2 settlement gate + i2 lifecycle gate + P1 invocation 双向回归全绿 |
| A↔V | Closed | A1 schema-version echo fail-closed + V1 proof registry gate 全绿 |
| Web4 Aggregate | Closed | `web4_release_aggregate_gate.sh` 全链路通过 |

## 未清零阻塞
- 无（本轮未发现阻塞项）。

## 回滚点
- 本次仅新增收口记录文档，单提交可直接 `git revert <commit>` 回滚。
