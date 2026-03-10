# TRNM ZKP 80% 验收 DoD（2026-03-10）

- 状态：**Draft / Formal DoD for 60% -> 80% closeout**
- 适用范围：TRNM `ProofType::Zk` 验证线路；只定义 **80% 收口所需验收条件、证据项、回归集、非目标范围**
- 口径定位：本文不是 release-ready 声明，也不是 100% 完成判定；它只回答：**从当前约 60%/平台骨架态，推进到可汇报的 80% 工程完成态，需要什么被证明为真**

> 真相源分工：
> - ZKP 平台边界 / 抽象冻结：`docs/architecture/TRNM_ZKP_PLATFORM_V0.md`
> - ZK payload / public-input 协议：`docs/protocol/zk-proof-payload-public-input-v0.md`
> - proof backend 观测口径：`docs/architecture/TRNM_PROOF_BACKEND_OBSERVABILITY_V0.md`
> - 当前 release 口径：仓库根 `RELEASE_READINESS.md`
> - 当前 verification line 对比事实：`docs/reviews/TRNM_REVIEW_LANE_08_VERIFICATION_BACKEND_COMPARISON_2026-03-10.md`

---

## 1. 为什么是“80%”而不是“已完成”

截至本文起草时，TRNM 的 ZK 线路已经具备：

1. `ProofType::Zk` 的统一 verifier registry 入口；
2. fail-closed reveal 语义；
3. canonical payload / public inputs 协议冻结；
4. backend router / config / error-class / observability 的架构文档冻结；
5. `noop` / mock 路径下的单元级行为约束。

但仍 **没有真实生产级 cryptographic verifier backend**，因此当前状态更准确地说是：

- **平台骨架已成形；**
- **真实后端尚未落地；**
- **不能声称 production-ready；**
- **可以进入“80% 收口验收”前置定义阶段。**

本文将 **80%** 定义为：

> **ZK 线路已经从“纯文档 + noop/mock 骨架”推进到“单一路线、单一后端、可配置、可回归、可举证”的工程可验收状态，但仍未宣称多 backend 完备、性能优化完成、主网上线就绪。**

---

## 2. 当前 60% 基线（进入本 DoD 前默认已满足）

若以下任一项不成立，则不应申请 80% 验收，而应先回退为 60% 未达基线。

### 2.1 平台/协议基线

- `ProofType::Zk` 已纳入统一 verifier registry 与 reveal 路径。
- reveal 对 `Zk` 缺失 payload、绑定缺失、backend 未配置采用 fail-closed / indeterminate，而不是静默放行。
- ZK payload canonical shape、`public_inputs.order/values`、`vk_ref` 约束已冻结为协议文档。
- backend router / config / error class / observability 已至少冻结为稳定文档契约。

### 2.2 事实证据锚点

至少应能引用并复核以下事实：

- 当前仓内默认 `zk` backend 仍为 `noop` / not configured；
- `not configured` 会被映射为 fail-closed / indeterminate；
- 除测试 mock 外，没有真实生产 ZK backend 已注册；
- 协议与架构文档已明确“平台骨架 ≠ 生产后端已完成”。

---

## 3. 80% 验收定义（Definition of Done）

要把 ZKP 从当前 60% 推到 80%，以下 **四大门** 必须全部满足；缺任一门，只能判为 `CONDITIONAL GO` 或 `NO-GO`。

### Gate A：单一路线真实 backend 已落地，不再只有 noop/mock

必须满足：

1. **只选定一条生产 ZK 路线** 作为 80% 收口对象，例如：`groth16` / `risc0` / `sp1` 三选一；
2. 该路线存在 **真实 cryptographic verifier backend**，而不是 `noop`、假实现、纯 mock、或只做 envelope/binding 校验；
3. backend 能消费 canonical payload 中至少以下字段：
   - `proof`
   - `proof_encoding`
   - `public_inputs.order`
   - `public_inputs.values`
   - `vk_ref`（或等价 verifier image / method id 引用）
4. backend 结果能稳定映射为：
   - `Valid`
   - `Invalid`
   - `Indeterminate(unavailable)`
   - `Indeterminate(backend_error)` 或等价 fail-closed 语义
5. `noop` 仍可保留为禁用态/默认态，但 **80% 验收时必须能举证存在一个非 noop backend 可被实际路由命中**。

**判废条件：**
- 只有 trait / config / 文档，没有真实 verifier 执行；
- 只有 mock backend 通过测试；
- 通过 alias/兼容逻辑绕过 canonical payload 校验；
- backend 实际不校验 cryptographic proof，只做格式检查。

### Gate B：配置与路由契约已闭环

必须满足：

1. 存在稳定的 ZK backend 配置入口，可显式选择该 backend；
2. 当 backend 被启用时，`ProofType::Zk` 请求可被路由到目标 backend，而非隐式回落到 `noop`；
3. 当 backend 未启用/未配置时，行为仍是 fail-closed；
4. `zk_system / backend_id / backend_version / vk_ref` 的使用规则与文档口径一致；
5. 路由选择、未配置、配置错误三种路径都有可复核测试。

**判废条件：**
- 配置只是文档示意，代码不读取；
- 路由失败时静默 fallback 到其它 proving system；
- 未配置时仍能进入“成功完成态”；
- `backend_id` / `vk_ref` 被实现层静默忽略。

### Gate C：最小回归矩阵已经形成，且覆盖真实 backend 四类结局

必须至少有一套稳定回归集，覆盖：

1. **valid**：真实合法 proof 被接受；
2. **invalid**：proof 或 statement/public inputs 不匹配时被拒绝；
3. **unavailable**：backend 未配置/禁用/依赖缺失时 fail-closed；
4. **backend_error**：backend 自身内部错误时 fail-closed，且错误不会被误记成 valid。

此外还必须覆盖两类前置 gate：

5. **malformed payload**：非 canonical JSON、缺 `vk_ref`、缺 `proof`、`public_inputs` 形状错误；
6. **binding mismatch**：`task_id / worker / proof_type / result_hash` 任一漂移都会拒绝。

**判废条件：**
- 只有 happy path；
- invalid 与 unavailable 未被区分；
- backend_error 被吞掉或被错误映射成 unavailable/valid；
- 真实 backend 没有任何集成级回归，只靠单元 mock。

### Gate D：验收证据可回收、可汇报、可复跑

必须满足：

1. 80% 验收包中能提供**精确文档链接、命令入口、测试名或脚本名、结果摘要**；
2. 至少有一份 evidence 能证明：
   - 命中了非 noop backend；
   - 成功校验了一条真实 valid proof；
   - 对 invalid/unavailable/backend_error 的 fail-closed 语义仍成立；
3. 至少有一份 evidence 能证明 payload / binding 协议没有因接入真实 backend 而退化；
4. 至少有一份 evidence 能证明 observability label contract 没有失真（至少 outcome / stage / error_class 口径稳定）；
5. 汇报材料必须明确写出：**80% != production-ready != multi-backend complete != performance sign-off**。

**判废条件：**
- 只有口头说明，没有落盘证据；
- 证据无法复跑或无法定位到具体文件/测试；
- 汇报中把“单 backend 可跑”夸大成“ZKP 平台已完成”。

---

## 4. 80% 验收所需证据项（Evidence Checklist）

通过 80% DoD，建议一次性收齐以下证据；缺失项必须在汇报中显式标红。

### E1. 架构/协议一致性证据

- `docs/architecture/TRNM_ZKP_PLATFORM_V0.md` 与实现口径一致；
- `docs/protocol/zk-proof-payload-public-input-v0.md` 中 canonical payload 规则未被真实 backend 绕开；
- 若引入 backend-specific 扩展字段，必须落在显式命名空间，并写清不影响 canonical binding。

### E2. 真实 backend 接线证据

- 代码路径显示已注册/可解析目标 backend；
- 配置样例或测试配置能启用目标 backend；
- 至少一条测试/脚本命中非 noop backend；
- 对外文档能说清该 backend 对应的 `zk_system` 与 `vk_ref` 语义。

### E3. Valid / Invalid 证据

- 一条真实合法 proof 的通过证据；
- 一条真实非法 proof 或 public input mismatch 的拒绝证据；
- 二者必须能区分“proof 不成立”与“backend 不可用”。

### E4. Fail-closed 证据

- backend 未配置时，不会进入完成态；
- backend 内部错误时，不会进入完成态；
- malformed payload / binding mismatch 在进入 backend 前被拒绝。

### E5. 回归与观测证据

- 最小回归集脚本/测试入口存在且可重复运行；
- 至少保留 outcome / stage / error_class 的稳定观测口径；
- 汇报材料能给出一次最近回归摘要（通过/失败项、失败语义、定位路径）。

---

## 5. 最小回归集（Regression Set）

以下回归集是 **80% 必跑**，不是“有空再补”。命名可以调整，但语义不能缺。

### R1. Canonical payload / envelope gate

至少覆盖：

- 非 `ZK:` 前缀拒绝；
- `ZK:` 后不是单 JSON object 拒绝；
- 缺 `proof` / `proof_encoding` / `public_inputs` / `vk_ref` 拒绝；
- duplicate / spoofed 字段拒绝；
- `public_inputs.order` 与 `values` 长度/顺序不一致拒绝。

### R2. Binding gate

至少覆盖：

- `task_id` mismatch；
- `worker` mismatch；
- `proof_type != zk`；
- `result_hash` mismatch 或上下文缺失；
- 历史 alias 归一化后进入 canonical payload 仍必须是 `zk`。

### R3. Backend routing

至少覆盖：

- 目标 backend 已配置且被命中；
- backend 未配置时返回 unavailable / indeterminate；
- 非法 `backend_id` / 不支持的 `zk_system` 不会静默走其它 backend；
- `noop` 与真实 backend 的结果路径可区分。

### R4. Real backend verdicts

至少覆盖：

- 真实 `valid proof`；
- 真实 `invalid proof`；
- backend internal error；
- backend dependency/readiness unavailable。

### R5. Observability / receipt contract

至少覆盖：

- valid -> `outcome=valid`；
- malformed payload -> `stage=envelope`；
- not configured -> `stage=backend`, `error_class=unavailable`；
- backend internal failure -> `stage=backend`, `error_class=backend_error`。

### R6. End-to-end reveal safety

至少覆盖：

- `ProofType::Zk` 在 valid proof 时可推进成功路径；
- 在 invalid / unavailable / backend_error / malformed 任一场景下，reveal 仍 fail-closed；
- 不会因引入真实 backend 而放松既有 reveal guard。

---

## 6. 非目标范围（Out of Scope for 80%）

以下内容 **不属于本次 80% DoD 的必要条件**；即便未完成，也不妨碍判定 80% 达成，但必须在汇报中明确未覆盖。

1. **多 backend 并存成熟度**：80% 只要求一个真实 backend 路线闭环，不要求 Groth16 / RISC0 / SP1 同时完成。
2. **性能/吞吐优化签字**：不要求 verifier 性能调优、并发吞吐压测、GPU/硬件加速、成本最优。
3. **主网/生产运维就绪**：不要求 HA、滚动升级、跨环境密钥管理、完整 SLO/SLA、灾备演练。
4. **证明市场/经济学闭环**：不要求 proving market、报价、结算激励、经济惩罚机制完善。
5. **TEE / Fraud backend 同步成熟**：80% 的 ZK DoD 不要求 TEE/Fraud 同步达成 backend 化。
6. **所有历史 alias/legacy payload 永久兼容**：可以保留兼容策略，但不要求在 80% 阶段把所有遗留格式都当成一等公民。
7. **100% 级别的发布断言**：80% 不是 `GO-LIVE`、不是 release sign-off、不是 audit complete。

---

## 7. 建议的验收结论模板

### GO（满足 80%）

当且仅当：Gate A/B/C/D 全满足，且 evidence checklist 无关键缺项。

建议结论模板：

> TRNM ZKP 已完成 60% -> 80% 收口：单一路线真实 verifier backend 已接入，canonical payload / binding / fail-closed 语义未退化，最小回归矩阵与证据包已具备。该结论仅表示“平台骨架已进入单 backend 工程可验收态”，**不表示** 多 backend 完成、性能达标或 production-ready。

### CONDITIONAL GO（接近 80%，但证据缺口仍需补）

适用情形示例：

- 真实 backend 已接入，但缺少 invalid/backend_error 其中一项证据；
- 回归存在，但 observability 口径未落稳；
- 有 valid proof 集成测试，但未形成可回收 evidence 包。

### NO-GO（仍停留在 60% 档）

适用情形示例：

- 仍只有 noop/mock；
- 未命中真实 backend；
- fail-closed 被打穿；
- payload/binding 规范被真实 backend 接线绕过；
- 没有可复跑、可汇报的最小回归集。

---

## 8. 结论

这份 DoD 刻意把“80%”卡在一个克制的位置：

- 它要求 **真实 backend、真实回归、真实证据**；
- 但不假装已经来到 **多 backend、主网、性能签字、100% 完成**。

因此，后续所有“ZKP 已到 80%”的回收与汇报，都应严格以本文四大 Gate、证据项、回归集和非目标范围为准；超出本文边界的表述，均应视为夸大。
