# BridgeSettle 回执绑定烟雾检查 Runbook

> 目标：在一个可复现的最小路径中，验证 `BridgeSettle` 相关的回执/最终化闭环是否仍满足 fail-closed。

## 适用范围

- `contracts-rust/bridge-relay`：`submit_proof`/`finalize_settlement` 的 `tx_receipt_status` 约束
- `trnm-types`：`SettlementRecord::apply_status_with_receipt_status` 的最终化回执检查

## 快速执行

在仓库根目录执行：

```bash
./scripts/check_bridge_settle_receipt_smoke.sh
```

默认会按时间戳写入日志到：

- `run/health/bridge-settle-receipt-smoke-YYYYMMDD-HHMMSS.log`

## 检查项（脚本内置）

1. **bridge-relay**
   - `submit_proof_rejects_non_success_tx_receipt`
   - `finalize_settlement_rejects_non_success_tx_receipt`
   - `finalize_settlement_rejects_stale_config_version_after_governance_change`
     - 覆盖治理变更后 stale `config_version` 的 finalize fail-closed 路径，要求不写入 proof/nonce/finalize 审计副作用。
   - `governance_write_with_stale_config_version_is_fail_closed_and_side_effect_free`
     - 覆盖治理写路径使用 stale `config_version` 时的 fail-closed 语义，要求 admin / config_version / audit_log 均保持不变。

2. **trnm-types（核心状态机）**
   - `settlement_state_machine_enforces_receipt_success_for_finalization`

3. **trnm-types（回归测试）**
   - `settlement_finalization_rejects_failed_tx_receipt`

以上三类失败将直接导致非 0 退出码，且写入日志。

## 失败时处理

- `bridge-relay` 用例失败：检查 `tx_receipt_status` 是否在提交的 `BridgeSettlementMessage` 上正确设置（默认示例值必须为成功态）。
- `trnm-types` 用例失败：检查 `SettlementRecord::apply_status_with_receipt_status` 是否被误改，重点看 `SETTLEMENT_TX_RECEIPT_SUCCESS` 与 `InteropIdentityError::InvalidSettlementReceiptStatus`。
- 若日志长时间无输出：确认 `cargo` 工具链可用，`PATH` 包含 rustup bin（脚本默认预设 `PATH="/opt/homebrew/opt/rustup/bin:$PATH"`）。

## 回归建议

- 发布前至少执行一次该脚本；若作为持续集成前置，可按项目环境拆分为单独步骤。
- 与前端/运维链路联调时，按本 runbook 的脚本输出结合最近一版配置版本治理文档进行一致性比对。
