# TRNM Lane 08：ZKP / TEE / Fraud verification backend 对比评审材料（2026-03-10）

- 范围：仅比较当前仓内 `fraud / tee / zk` 三条 verification line 的后端接入现状，不讨论 proving market、经济参数或链下运维。
- 结论先行：
  - **Fraud**：当前不是“backend verification”线路，而是 **envelope/binding 校验 + challenge 流程语义**；无独立密码学 backend。
  - **TEE**：已有 **backend 抽象与路由骨架**，但默认只接 `noop`；当前仓内**没有真实 attestation verifier**，所以 reveal 会 fail-closed / indeterminate。
  - **ZK**：已有 **backend 抽象、payload 规范、router 入口**，但默认同样只接 `noop`；当前仓内**没有真实 Groth16 / Plonk / Halo2 / RISC Zero / SP1 verifier**，所以 reveal 会 fail-closed / indeterminate。

---

## 1. 对比总表

| 线路 | 当前现状 | 直接证据（精确路径 / 函数 / 错误消息） | 当前阻塞点 | 下一步工程动作 |
|---|---|---|---|---|
| Fraud | **无独立 backend**。当前仅做 `FRAUD:` envelope 绑定校验；业务语义仍依赖 challenge 期，而不是 reveal 时立刻做密码学校验。 | 1. `trillionnium/crates/trnm-pouw/src/verification/verifiers/fraud.rs:8-15`，函数 `FraudVerifier::verify_proof()` 直接调用 `verify_bound_envelope(task, proof_data, b"FRAUD:", "fraud proof")`。<br>2. `trillionnium/crates/trnm-pouw/src/lib.rs:831-835` 注释明确写明：`For Fraud proofs, we rely on the challenge period (no immediate verification).`<br>3. `trillionnium/crates/trnm-pouw/src/verification/registry.rs:354-363`，`VerifierRegistry::verify()` 的 fail-closed 错误消息为：`verification failed closed: no verifier registered for proof type: {}`。 | 没有独立 `fraud backend` trait / registry family；没有 fraud-specific cryptographic or execution replay verifier；当前无法与 TEE / ZK 一样做 backend readiness、选择、替换、能力探测。 | 1. 明确 Fraud 是否要升级为真正 backend 线路：若要，应新增 `fraud` family，而不是继续复用纯 envelope 校验。<br>2. 为 fraud 定义 canonical payload（challenge trace / witness / disputed step / claimed result binding）。<br>3. 补 `FraudBackend` trait、registry、`NotConfigured / InvalidProof / Internal` 分类，与 TEE/ZK 统一。 |
| TEE | **有 backend 骨架，但默认无真实 backend**。先过 `TEE:` envelope gate，再进入 backend；默认 backend=`noop`，因此当前 reveal 会返回 indeterminate，而不是通过。 | 1. `trillionnium/crates/trnm-pouw/src/verification/verifiers/tee.rs:17-35`，函数 `TeeVerifier::verify_backend()` 通过 `self.backends.resolve("tee", &self.backend)` 选 backend，并执行 `backend.verify(...)`。<br>2. `trillionnium/crates/trnm-pouw/src/verification/verifiers/tee.rs:50-63`，函数 `TeeVerifier::verify_proof()` 在 envelope 通过后，将 `BackendExecutionError::NotConfigured` 映射为错误消息：`TEE receipt cryptographic verification backend not configured`。<br>3. `trillionnium/crates/trnm-pouw/src/verification/backend.rs:29-42`，`VerificationBackendConfig::default()` 将 `tee_backend` 默认设为 `ZkBackendKind::Noop`。<br>4. `trillionnium/crates/trnm-pouw/src/verification/backend.rs:168-179`，`NoopZkBackend::verify()` 返回精确错误：`cryptographic verification backend not configured: {backend}`。<br>5. `trillionnium/crates/trnm-pouw/src/verification/verifiers/tee.rs:94-107` 的测试 `tee_verifier_requires_cryptographic_backend_after_bound_envelope_validation()` 断言了上述 indeterminate 文案。 | 仓内没有任何真实 TEE verifier 实现；`impl ZkBackend for ...` 的生产代码只有 `NoopZkBackend`，见 `trillionnium/crates/trnm-pouw/src/verification/backend.rs:170-179`；`grep` 结果显示源码内无 SGX / DCAP / TDX / SEV-SNP verifier 实装。 | 1. 把 TEE 从“共享 ZkBackend trait 的占位复用”拆成更清晰的 attestation backend contract，或至少补一套 `tee-*` backend 实现。<br>2. 首个落地建议：接入一个明确目标（如 `intel-sgx-dcap` 或 `amd-sev-snp`）并固定 `quote/report -> claims -> task binding` 映射。<br>3. 补 capability / config / smoke test：验证 `tee_backend != noop` 时，`quote` 真正进入 verifier，而不是只过 envelope。 |
| ZK | **有 backend 骨架 + canonical payload 规范 + mock backend 测试，但默认无真实 backend**。当前实际生产路径仍是 fail-closed / indeterminate。 | 1. `trillionnium/crates/trnm-pouw/src/verification/verifiers/zk.rs:27-52`，函数 `ZkVerifier::verify_backend()` 会在检测到 JSON payload 时调用 `parse_zk_proof_payload(task, proof_data)`，然后把 `zk_payload` 交给 backend。<br>2. `trillionnium/crates/trnm-pouw/src/verification/verifiers/zk.rs:66-83`，函数 `ZkVerifier::verify_proof()` 将 `BackendExecutionError::NotConfigured` 映射为精确错误：`ZK proof cryptographic verification backend not configured`；若 `task.result_hash` 缺失则直接报：`Invalid ZK proof envelope: missing task result_hash binding context`。<br>3. `trillionnium/crates/trnm-pouw/src/verification/backend.rs:63-74` 定义 `ParsedZkProofPayload`；`182-231` 的函数 `parse_zk_proof_payload()` 强制校验 `task_id / worker / proof_type / result_hash / vk_ref / proof / public_inputs`，并会抛出精确错误，如：`invalid zk payload: body must be canonical JSON object`、`invalid zk payload: vk_ref is required`、`invalid zk payload: public_inputs mismatch`。<br>4. `trillionnium/docs/zk-proof-payload-v1.md` 已冻结 payload v1：要求 `vk_ref`、`proof_encoding`、`proof`、`public_inputs.order/values`。<br>5. `trillionnium/docs/architecture/TRNM_ZKP_PLATFORM_V0.md` 明确写明当前目标仍是“可插拔、多 backend 的验证平台骨架”，而非已落地的多 backend 生产实现。<br>6. `trillionnium/crates/trnm-pouw/src/verification/verifiers/zk.rs:122-129` 的 `MockSuccessBackend` 只存在于测试模块；源码中除 `NoopZkBackend` 外没有生产 ZK backend。 | 没有真实 verifier backend；`ZkBackendKind` 当前只有 `Noop` 与 `Custom(String)`，见 `trillionnium/crates/trnm-pouw/src/verification/backend.rs:8-25`，但仓内没有任何 `Custom(...)` 生产注册代码。平台文档已先行，真实 backend 仍缺席。 | 1. 选定第一条生产 ZK 路线（建议只选一个：Groth16 / RISC Zero / SP1 其一），把 `vk_ref + proof + public_inputs` 真正接到 verifier。<br>2. 将 `docs/architecture/TRNM_ZKP_PLATFORM_V0.md` 中的 router / backend / config 冻结项落地为代码与配置读取，而非停留在文档。<br>3. 增加非 mock 的集成测试，覆盖 `valid / invalid / not configured / backend internal error` 四类结果。 |

---

## 2. 共同基线：三条线目前共享的 verification entry 结构

### 2.1 Registry 已统一注册三类 verifier
`trillionnium/crates/trnm-pouw/src/verification/registry.rs:22-41`，函数 `VerifierRegistry::with_backend_config()` 当前统一注册：

- `verifiers::FraudVerifier`
- `verifiers::TeeVerifier::new(config.tee_backend, ...)`
- `verifiers::ZkVerifier::new(config.zk_backend, ...)`

这说明：**路由层已经统一，但 backend 成熟度不统一。**

### 2.2 reveal 入口对 TEE/ZK 是 fail-closed 的
`trillionnium/crates/trnm-pouw/src/lib.rs:841-899`：

- `ProofType::Tee | ProofType::Zk` 必须携带非空 proof payload；
- 空 payload 会报：`Proof verification failed: missing proof payload for {:?}`；
- `VerificationResult::Invalid(reason)` 会被映射成：`Proof verification failed: {reason}`；
- `VerificationResult::Indeterminate(reason)` 会被映射成：`Proof verification indeterminate: {reason}`。

这意味着：**TEE/ZK 已从“无 backend 也可完成”收紧为 fail-closed / 不确定即拒绝推进完成态。**

### 2.3 内建 V1 stack 的真实状态是 “fraud 可过 envelope，tee/zk 默认未配置”
`trillionnium/crates/trnm-pouw/src/verification/registry.rs:1975-2007` 的测试 `registry_with_builtin_verifiers_registers_v1_stack()` 已直接固定该事实：

- `fraud` -> `VerificationResult::Valid`
- `tee` -> `VerificationResult::Indeterminate(msg)`，且 `msg.contains("cryptographic verification backend not configured")`
- `zk` -> `VerificationResult::Indeterminate(msg)`，且 `msg.contains("cryptographic verification backend not configured")`

这正是当前三线差异的最短证据链。

---

## 3. 评审判断

### 3.1 Fraud 线
当前更像 **protocol/challenge semantics**，不是 backend verification 产品线。

如果 Lane 08 的目标是“ZKP / TEE / Fraud verification backend 对比”，那么 Fraud 当前应被如实标注为：

- **已接入统一 registry**；
- **未进入 backend 化阶段**；
- **仍依赖 challenge window 解决争议，而非 reveal 时的独立 verifier backend**。

### 3.2 TEE 线
当前属于 **架构已到位、生产 backend 缺位**。

优点：
- 已有 envelope gate；
- 已有 backend selector；
- 已有 fail-closed 映射；
- 已有别名 / proof type 标准化。

短板：
- 仍无真实 quote/report verifier；
- 目前“backend family = tee”只是路由语义，不是可运行能力。

### 3.3 ZK 线
当前属于 **文档和接口冻结领先，真实 backend 实装滞后**。

优点：
- payload 规范最完整；
- 已有 `vk_ref / proof / public_inputs` 约束；
- 已有 mock backend 验证代码路径。

短板：
- 真实 cryptographic backend 仍为空；
- 文档里规划的 `groth16 / plonk / halo2 / risc0 / sp1` 仍未在生产代码中注册。

---

## 4. 建议的工程优先级

1. **先做 ZK 还是先做 TEE，只能二选一作为首个生产 backend**。当前两线都还是 `noop`，并行铺开只会扩大测试面和配置复杂度。
2. **Fraud 线应先做产品定位决策**：
   - 若继续保持 challenge semantics，则在 Lane 08 文档中明确其“非 backend line”身份；
   - 若要纳入 backend 对比，则必须新增 fraud backend contract，而不是拿当前 envelope gate 冒充 backend 完成度。
3. **所有生产 backend 必须补统一 readiness 证据**：
   - 非 `noop` 配置加载成功；
   - 至少一条真实 `valid proof` 集成测试；
   - 至少一条真实 `invalid proof` 集成测试；
   - 一条 `backend internal/unavailable` 测试，确认仍 fail-closed。

---

## 5. 供评审会直接使用的一句话结论

> TRNM 当前已经具备 `fraud / tee / zk` 的统一 verifier registry 与 fail-closed reveal 入口，但 **只有 Fraud 处于“无 backend、仅 envelope + challenge semantics”状态；TEE 与 ZK 虽已有 backend 抽象和路由骨架，默认仍仅接 `noop`，仓内没有任何真实密码学验证后端实现，因此两者目前都只能作为“平台骨架已完成、生产 backend 未落地”的线路进入评审。**
