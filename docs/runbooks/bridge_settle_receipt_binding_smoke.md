# BridgeSettle 回执绑定烟雾检查 Runbook

> 目标：在一个可复现的最小路径中，验证 `BridgeSettle` 相关的回执/最终化闭环是否仍满足 fail-closed。

## 适用范围

- `contracts/bridge-relay`：`submit_proof`/`finalize_settlement` 的 `tx_receipt_status` 约束
- `trnm-types`：`SettlementRecord::apply_status_with_receipt_status` 的最终化回执检查
- 桥接结算审计语义：结合 `trillionnium/docs/release/TRNM_BRIDGE_SETTLEMENT_AUDIT_NOTE_2026-04-02.md` 一起解读，避免把回执烟雾测试通过误读成“可放宽 settlement confirm 边界”

> 路径提示：本 runbook 以当前仓库布局 `contracts/bridge-relay` 为准。若其他遗留文档仍写成 `contracts-rust/bridge-relay`，请按过时路径处理，避免在错误目录执行验证。

## 快速执行

在仓库根目录执行：

```bash
./scripts/check_bridge_settle_receipt_smoke.sh
```

默认会先做 manifest 预检，确认当前仓库布局仍是 `contracts/bridge-relay` 与 `trillionnium/Cargo.toml`，再按时间戳写入日志到：

- `run/health/bridge-settle-receipt-smoke-YYYYMMDD-HHMMSS.log`

## 检查项（脚本内置）

1. **bridge-relay**
   - `submit_proof_rejects_non_success_tx_receipt`
   - `submit_proof_replay_after_finalize_stays_proof_replay_bound`
     - 覆盖 finalize 终态后的 proof 重放保护，要求重复 proof 继续命中 `ProofAlreadyUsed`，不能因 settlement 已终结而落入其他错误路径。
   - `proof_replay_rejection_is_side_effect_free`
     - 覆盖 proof digest 重放拒绝时的副作用约束，要求审计日志不追加重复事件，且后续 fresh proof 仍可正常通过。
   - `finalize_settlement_rejects_non_success_tx_receipt`
   - `finalize_settlement_rejects_stale_config_version_after_governance_change`
     - 覆盖治理变更后 stale `config_version` 的 finalize fail-closed 路径，要求不写入 proof/nonce/finalize 审计副作用。
   - `finalize_settlement_rejects_target_bridge_mismatch_without_audit_side_effects`
     - 覆盖目标桥域校验的 fail-closed 语义：当 `target_bridge` 与本桥不匹配时，必须直接拒绝 finalize，且不得追加 proof / nonce / finalize 审计事件。
   - `finalize_settlement_is_idempotent_by_settlement_id_even_with_new_nonce`
     - 覆盖 finalize 终态语义：即使重放请求携带了新的 `nonce`，只要 `settlement_id` 相同，仍必须优先返回 `SettlementAlreadyFinalized`，避免 fresh nonce 绕过 terminal state。
   - `duplicate_finalize_is_side_effect_free`
     - 覆盖重复 finalize 的副作用约束：重复请求必须直接命中终态，不得追加新的 proof / nonce / finalize 审计事件。
   - `finalize_settlement_nonce_collision_rolls_back_proof_side_effects`
     - 覆盖 finalize 过程中 nonce 已被占用时的回滚语义：必须撤销本次 proof 占用与临时审计写入，避免 nonce 冲突把 relay 留在“proof 已用但 settlement 未终结”的半提交状态。
   - `duplicate_finalize_with_fresh_nonce_and_bad_receipt_still_stops_at_terminal_state`
     - 覆盖 finalize 终态优先级：即使重放请求携带 fresh `nonce` 且 `tx_receipt_status` 失败，只要 `settlement_id` 相同，仍必须先返回 `SettlementAlreadyFinalized`，避免 fresh nonce + bad receipt 组合绕过 terminal state 或污染审计。
   - `duplicate_finalize_with_stale_config_version_after_governance_change_still_stops_at_terminal_state`
     - 覆盖 finalize 终态优先级：即使治理已推进 `config_version`，对已终结 settlement 的重复 finalize 也必须先返回 `SettlementAlreadyFinalized`，避免被 stale config drift 改写成其他错误路径。
   - `duplicate_finalize_with_fresh_config_version_after_governance_change_still_stops_at_terminal_state`
     - 覆盖 finalize 终态优先级：即使重放请求已经跟上最新 `config_version`，对已终结 settlement 的重复 finalize 也必须先返回 `SettlementAlreadyFinalized`，避免 fresh config 被错误当成可重入放行条件。
   - `governance_write_with_stale_config_version_is_fail_closed_and_side_effect_free`
     - 覆盖治理写路径使用 stale `config_version` 时的 fail-closed 语义，要求 admin / config_version / audit_log 均保持不变。
   - `stale_validator_rotation_is_fail_closed_and_side_effect_free`
     - 覆盖 validator set 轮换写路径的 stale `config_version` fail-closed 语义，要求 validator 配置、`config_version` 与治理审计事件均保持不变。
   - `stale_validator_rotation_does_not_admit_new_validator`
     - 覆盖 stale validator 轮换的成员替换防线：过期版本的轮换请求不得把新 validator 偷带入 allowlist，且后续 proof 仍必须只接受旧集合中的签名。

2. **trnm-types（核心状态机）**
   - `settlement_state_machine_enforces_receipt_success_for_finalization`

3. **trnm-types（回归测试）**
   - `settlement_finalization_rejects_failed_tx_receipt`

以上三类失败将直接导致非 0 退出码，且写入日志。

## 失败时处理

- `bridge-relay` 用例失败：检查 `tx_receipt_status` 是否在提交的 `BridgeSettlementMessage` 上正确设置（默认示例值必须为成功态）。
- `bridge-relay` 若失败集中在 duplicate/finalize terminal-state 用例：优先检查 `settlement_id` 终态短路是否仍先于 fresh `nonce`、stale/fresh `config_version`、以及 bad receipt 分支执行，避免重复 finalize 落入非终态错误路径。
- `bridge-relay` 若失败集中在 stale validator/config_version 用例：检查治理写路径与 validator 轮换写路径是否继续 fail-closed，确认 stale 请求不会改写 validator 集、`config_version`、`audit_log` 或 `normalized_audit_log`，也不会把新 validator 偷带入 allowlist。
- `trnm-types` 用例失败：检查 `SettlementRecord::apply_status_with_receipt_status` 是否被误改，重点看 `SETTLEMENT_TX_RECEIPT_SUCCESS` 与 `InteropIdentityError::InvalidSettlementReceiptStatus`。
- 若脚本一开始就报 missing manifest：优先检查是否误在过时目录布局下执行。当前有效路径必须包含 `contracts/bridge-relay/Cargo.toml` 与 `trillionnium/Cargo.toml`，旧的 `contracts-rust/bridge-relay` 引用应视为文档漂移。
- 若回执相关测试通过，但桥接结算 incident 仍表现异常，回到 `trillionnium/docs/release/TRNM_BRIDGE_SETTLEMENT_AUDIT_NOTE_2026-04-02.md` 核对当前 replay 证据是否仍满足 fail-closed 边界：`target < confirm <= source + 1`，且当 `target == source` 时只能接受 `confirm == source + 1`。
- 做 incident 摘要时，优先引用冻结审计元组而不是自由文本日志，推荐模板：`phase=<phase> hb=(<source>,<target>,<latency_ms>) confirm_height=<confirm_height> confirm_reason=<confirm_reason>`。
- 若日志长时间无输出：确认 `cargo` 工具链可用，`PATH` 包含 rustup bin（脚本默认预设 `PATH="/opt/homebrew/opt/rustup/bin:$PATH"`）。

## 回归建议

- 发布前至少执行一次该脚本；若作为持续集成前置，可按项目环境拆分为单独步骤。
- 与前端/运维链路联调时，按本 runbook 的脚本输出结合最近一版配置版本治理文档进行一致性比对。
