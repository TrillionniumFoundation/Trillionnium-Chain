# governance-guard (MVP skeleton)

最小外置治理合约骨架：
- `GovernanceGuardMVP.sol`

用途：
- 高风险参数变更（proposal -> queue -> timelock -> execute）
- Emergency pause 立即触发 + timelock unpause

说明：
- 通过 `IGovernanceBridge` 对接 TRNM 链内治理入口（`applyGovParam` / `setEmergencyPause`）。
- 当前为骨架，不含部署脚本与完整测试框架。
- 详细设计见：`docs/protocol/external-contracts/governance-guard-mvp.md`。
