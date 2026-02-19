# EVM Residue Scan（2026-02-19）

目标：识别仓库中与 EVM 旧路线相关的残留内容，并给出分层清理建议。

## A. 发现结果（高置信）

1) 历史归档目录（保留）
- `legacy/evm-contracts/`
- `legacy/evm-contracts/README.md`
- `legacy/evm-contracts/WorkRegistryV1.sol`
- `legacy/evm-contracts/WorkRegistryV2.sol`

2) 主文档中的 EVM 历史引用（建议保留但降噪）
- `README.md`
  - `Solidity contracts are archived under legacy/evm-contracts for reference only.`
  - 目录树中展示 `legacy/evm-contracts`
- `PROJECT_SUMMARY.md`
  - `Historical Solidity contracts (EVM-phase)`

3) 非 EVM 误报（无需处理）
- `chain/tools/*schema_contract*` 中的 `contract` 为“schema contract”语义，不是 EVM 智能合约。
- `core/protocol_simulator.py` 的 `WorkRegistryContract` 为本地模拟类命名，不是链上 Solidity 合约。

---

## B. 建议清理策略（分层）

## 层 1：生产路径零 EVM 暴露（今天可做）
- [ ] `README.md` 首页保持一句话历史说明即可，不展开 EVM 细节。
- [ ] 将 EVM 相关说明统一转移到单一“历史归档”段，避免多处重复。

## 层 2：文档归档标准化（今天可做）
- [ ] 在 `PROJECT_SUMMARY.md` 标注：`legacy/evm-contracts` 仅历史归档，不纳入 roadmap。
- [ ] 新增“路线声明”：当前唯一主线为 Cosmos SDK PoUW。

## 层 3：命名去歧义（可选，本周）
- [ ] `core/protocol_simulator.py` 中 `WorkRegistryContract` 可更名为 `WorkRegistrySim`，减少误解。

---

## C. 建议执行顺序

1. 先改文档（README + PROJECT_SUMMARY）统一口径。
2. 再做可选命名修正（若你希望彻底降噪）。
3. 保留 `legacy/evm-contracts` 作为历史档案，不直接删除。

---

## D. 不建议动作

- 不建议直接删除 `legacy/evm-contracts`：会损失演进证据与历史可追溯性。
- 不建议在主流程继续扩写 EVM 兼容路线，避免对外造成双路线预期。
