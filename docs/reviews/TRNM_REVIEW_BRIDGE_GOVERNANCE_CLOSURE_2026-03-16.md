# TRNM Bridge Relay 治理闭环复核（2026-03-16）

- 范围：`contracts/bridge-relay`（签名验签、validator 配置治理接口）、`trillionnium/crates/trnm-rpc`（能力与标准化审计对接）、链上治理接线上下文（跨仓讨论）。
- 结论：**签名闭环与配置防误配已落地；剩余核心差距主要在“真实 signer / committee auth context / governance wiring”层。**

---

## 1. 本轮已闭环项（核验通过）

1. `bridge-relay` 已从 Tag 绑定切到 Ed25519 验签：
   - `parse_validator_signature` 改为解析 `96B` 载荷（`32B` 公钥 + `64B` 签名）。
   - `validate_validator_signatures` 使用 `VerifyingKey::from_bytes(validator).verify(message_digest, signature)`。
   - 证据：`contracts/bridge-relay/src/lib.rs:451-476`。

2. 签名配置误配防线增强：
   - 新增 `InvalidValidatorConfiguration`。
   - `set_min_validator_signatures` + `set_validators` + `submit_proof` 统一校验：
     - `min_validator_signatures > 0`
     - `available_validators > 0`
     - `min_validator_signatures <= validators.len()`
   - 证据：`contracts/bridge-relay/src/lib.rs:224-267`。

3. 回归覆盖已补齐：
   - `governance_like_admin_rejects_zero_min_signatures`
   - `governance_like_admin_rejects_empty_validator_set`
   - `governance_like_admin_rejects_validator_set_below_threshold`
   - `governance_like_admin_rejects_configuration_without_validators`
   - `submit_proof_rejects_invalid_validator_signature_configuration`
   - `governance_like_admin_can_rotate_validator_set_and_threshold`

---

## 2. 当前残留风险（优先级顺序）

### A. 真实 signer 绑定（Real signer binding）

- **问题**：签名验证面当前是“将签名者公钥内联在 proof 中 + 本地公钥白名单”，并未绑定到链上签名者身份链（如签名者来源证明、签名者轮换链上的权威来源）。
- **影响**：在跨域部署时，若 `validator_pubkey` 的生命周期和授权来源不能与治理状态同步，可能出现“密钥被替换但未更新/未撤销”导致的安全漂移。
- **最小下一步**：
  1. 约定 `validator_pubkey` 只允许来源于治理发布的 committee 根（或 committee 配置版本）；
  2. 在签名提交时校验 `proof` 带有 `config_version`，与本地配置快照一致；
  3. 在配置变更时加入版本递增事件（用于审计链路定位）。

### B. Committee auth context / governance wiring

- **问题**：`bridge-relay` 目前仍是纯状态机（内置 `HashSet<[u8;32]>`）测试向导，不具备与主链治理能力、授权动作、提案生命周期强绑定。
- **影响**：`admin/validator/threshold` 的有效性在生产运行中仍依赖外部“人工一致性”约束，属于**闭环不全**。
- **最小下一步**：
  1. 将 committee 配置更新从“纯方法调用”转为“治理动作输入”的最小网关层（哪怕先是本地 mock，但要保留固定字段）；
  2. 对 `set_admin / set_validators / set_min_validator_signatures` 增加“治理来源标签”参数（例如：`change_id` / `change_idempotency_key`）；
  3. 在失败路径返回明确错误码，保留 fail-closed（拒绝无法确认来源的治理变更）。

### C. 链上回执与 finality 绑定

- **问题**：当前 `bridge-relay` 以 `BridgeSettlementMessage` 字段 + 签名多签作为提交条件，没有在当前仓内绑定到主链 tx 回执、finality depth 或事件回源证据。
- **影响**：仍属于“消息可达性 + 域隔离 + 重放防护”层，而非与主链执行状态一致的最终保障。
- **最小下一步**：
  1. 在消息模型中引入 `source_tx_receipt_root / source_block_finalized`（或等价最小字段）；
  2. 明确 `hash_message` 与接入字段映射（`source_tx_receipt` 的最小可验证属性）；
  3. 用可选 `finalized` 开关形成两阶段提交：`submit_proof` 仍可用于预校验，但 `finalize_settlement` 需额外约束到已确认状态。

---

## 3. 建议的最小执行清单（不影响现有前端主链路）

1. **先不改前端**：继续保持 `trillionnium` / `web4-frontend` 兼容。
2. 在 `bridge-relay` 增加最小“配置版本”字段 + 版本化审计（仅 metadata，不改变现有签名语义）。
3. 增加一个“committee 配置事件 + 版本”快照测试，验证：
   - 版本不一致时拒绝新签名提交；
   - 版本回滚/更新时老 proof 与新 proof 的边界行为明确。
4. 在 docs 中补充“治理接线接入位点”草图，标明下一阶段接入主链 governance 的具体文件/函数点。

---

## 4. 与主链语义差距对齐（对照）

- 当前与主流跨链方案相比，`bridge-relay` 已完成：
  - 多签聚合签名检查（含阈值 + 去重 + 重放防护）。
  - `proof` 与域字段验签。
- 当前仍与主流语义差距较大：
  - 治理动作签名来源链路（root-of-trust）未闭环；
  - 回执/最终性未成为验签输入；
  - committee 成员轮换未与 on-chain event / governance 状态统一。

---

## 5. 状态更新

- 本轮实现与测试已由 commit 追踪：
  - `3093bc8d`（Ed25519 实名验证）
  - `ba9d6068`（清理旧 tag 绑定辅助逻辑）
  - `c983c7b5`（配置一致性防误配）
- 所有新增/既有前端链路不变，三合约统一审计链路继续按降级策略保留。