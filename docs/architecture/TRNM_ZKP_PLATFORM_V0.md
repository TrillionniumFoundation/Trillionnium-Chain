# TRNM ZKP Platform v0（Lane A 架构冻结）

- 状态：**Frozen / v0 baseline**
- 范围：只定义平台抽象、契约、兼容策略；**不引入业务逻辑改动**
- 目标：把 TRNM 的 ZKP 从当前“fail-closed 壳”推进为**可插拔、多 backend 的验证平台骨架**
- 适用边界：当前仓内 PoUW / Verification 路径，尤其是 `ProofType::Zk` 的验证入口与回执语义
- BL09 退役准备口径：本文若提到保留中的 PoUW / verification 回执边界，默认仅指迁移期兼容与 provenance / audit evidence，不应被解读为继续把 PoUW 作为 payout authority，也不为保留 work-unit payout 公式的默认结算路径背书

---

## 1. 背景与冻结目标

当前实现已经具备三件关键能力：

1. **proof type 路由骨架**：`fraud | tee | zk` 统一接入 `VerifierRegistry`
2. **fail-closed 基线**：缺失、漂移、重复绑定、非 canonical 绑定时拒绝放行
3. **统一验证结果语义**：`Valid | Invalid | Indeterminate`

但当前 ZK 仍更像“单后端占位壳”：

- 路由粒度停留在 `ProofType::Zk`
- proof payload 未冻结为平台级规范
- backend 选择、配置、能力探测、错误归类、兼容回退尚未形成稳定文档契约

**本文件冻结的不是 proving system 细节，而是平台边界。**

---

## 2. 设计原则

### 2.1 Fail-closed first
- 任何 proof payload 缺失、格式不合法、上下文绑定不完整、backend 未配置、backend 返回不确定结果时，默认**拒绝视为成功**。
- `unavailable` 与 `backend error` 不是“放行理由”，只能进入上层重试/降级/争议路径。

### 2.2 Proof system 与 backend 解耦
- `proof system` 表示证明语义类别：Groth16、PLONK、Halo2、RISC Zero receipt、SP1 proof 等。
- `backend` 表示具体验证执行体：本地库、FFI、外部 prover/verifier service、硬件/TEE 辅助验证器。
- 平台必须允许 **同一 proof system 对应多个 backend**，也允许 **同一 backend 覆盖多个 proof system**。

### 2.3 Canonical envelope before cryptographic verification
- 先做**平台层 envelope / binding / schema 校验**，再进入具体 backend 验证。
- backend 不负责弥补 envelope 规范缺口。

### 2.4 v0 先冻结接口，不冻结实现数量
- v0 只要求抽象层、字段、错误语义、配置入口稳定。
- v0 不要求一次性接入多种 proving system 的生产实现。

---

## 3. 平台分层

```text
Task / Settlement Layer
        |
        v
ZKP Platform Router
  - proof type normalization
  - envelope validation
  - backend selection
  - error mapping
        |
        v
ZKP Backend Adapter Layer
  - local verifier adapter
  - ffi adapter
  - remote verifier adapter
  - mock / disabled adapter
        |
        v
Concrete Backend
  - groth16 backend
  - plonk backend
  - halo2 backend
  - risc0 receipt verifier
  - sp1 verifier
  - future custom systems
```

### 3.1 Router 层职责
Router 是平台边界，负责：

- 规范化 `proof_type` / `backend` / `version`
- 解析 proof payload 与 public inputs
- 做 canonical 绑定校验：`task_id / worker / proof_type / result_hash`
- 基于配置与 feature flag 选择 backend
- 将 backend 结果映射为稳定错误类别
- 生成统一 verification receipt / observability 字段

### 3.2 Backend Adapter 层职责
Adapter 是 proof system/backend 的胶水层，负责：

- 把平台规范中的 canonical payload 翻译成具体 backend 需要的输入
- 适配本地库 / FFI / 远程 API / sandbox 执行模型
- 把 backend 原始错误折叠为平台标准错误
- 暴露能力元数据（支持的 proving system / version / curve / recursion / limits）

### 3.3 Concrete Backend 职责
Concrete backend 只负责：

- 对给定 proving system 执行验证
- 返回明确的 `valid / invalid / unavailable / backend_error`
- 不负责市场结算状态机，不负责静默兼容旧格式

---

## 4. 核心抽象冻结

## 4.1 Canonical proof kind
v0 在路由层保持当前顶层种类不变：

- `fraud`
- `tee`
- `zk`

其中 **ZK 平台扩展在 `zk` 内部发生**，不立即扩张链上/任务对象的顶层 `ProofType` 枚举。

原因：

- 最小化对现有业务逻辑与状态机的冲击
- 保持当前 `ProofType::Zk` 入口兼容
- 让 proving system 的多样性下沉到 payload + backend 元数据层

## 4.2 ZK backend descriptor
对 `ProofType::Zk`，平台层引入如下概念字段：

- `zk_system`：证明系统标识，例如 `groth16 | plonk | halo2 | risc0 | sp1 | custom`
- `backend_id`：具体 backend 实例标识，例如 `local-groth16-bn254`、`risc0-host-v1`
- `backend_version`：backend 契约版本，例如 `v1`
- `proof_format`：proof 编码格式，例如 `raw-bytes | hex | base64 | json-envelope`
- `vk_ref`：verification key / verifier image / method id / verifier config 的引用

### 4.3 推荐 trait 形态（文档冻结，不要求本次实现）

```rust
trait ZkpBackend {
    fn backend_id(&self) -> &str;
    fn supports(&self, req: &ZkpVerifyRequest) -> bool;
    fn verify(&self, req: &ZkpVerifyRequest) -> ZkpBackendResult;
}
```

其中：

- `ZkpVerifyRequest` 是平台 canonical 输入
- `ZkpBackendResult` 必须可映射到标准错误分类
- `supports()` 只做能力判断，不做真实验证

---

## 5. Proof payload / public input 规范

本章只保留平台层摘要；**字段级协议真相源**已经拆分到：

- `docs/protocol/zk-proof-payload-public-input-v0.md`

Router / backend 实现涉及 payload 形状、`public_inputs` 顺序、编码、`vk_ref` 与 binding 约束时，必须以该协议文档为准。

## 5.1 平台层要求（摘要）

对所有 `zk` 验证请求：

1. Router 在进入 backend 前必须先形成 canonical request。
2. Envelope 与 cryptographic payload 必须分离校验。
3. `task_id / proof_type / worker / result_hash` 必须在平台层完成 fail-closed 绑定校验。
4. `public_inputs` 的**顺序、编码、最小绑定集**不是 backend 私有约定，而是平台协议的一部分。
5. `vk_ref` 是审计保留字段，backend 不得静默改写或忽略。

## 5.2 架构与协议分工

- 本架构文档负责：平台分层、抽象边界、错误分类、feature flag、兼容策略
- 协议文档负责：canonical payload shape、`public_inputs.order/values`、字段编码、`vk_ref` 引用规则、`task_id/worker/result_hash/proof_type` binding

若未来代码实现与协议文档冲突，应先评审协议版本变更（例如新增 `trnm.zk.payload.v1`），不得在实现里静默漂移。

---

## 6. Feature flag / config 冻结

## 6.1 Feature flag
v0 建议冻结以下 feature flag 名称：

- `zk_platform_v0`：总开关；关闭则保持当前单壳行为
- `zk_backend_router`：启用 backend 路由层
- `zk_payload_v0_envelope`：强制要求 canonical payload v0
- `zk_allow_legacy_receipt_aliases`：允许旧 receipt alias 映射到 `zk`
- `zk_allow_backend_fallback`：允许从首选 backend 回退到同系统备 backend
- `zk_explicit_backend_required`：要求 payload 显式带 `backend_id`

## 6.2 Config 结构
建议配置结构如下：

```toml
[zk]
enabled = true
platform_version = "v0"
default_backend = "local-disabled"
allow_legacy_receipt_aliases = true
allow_backend_fallback = false
explicit_backend_required = false

[zk.backends.local-disabled]
enabled = true
mode = "disabled"

[zk.backends.local-groth16-bn254]
enabled = false
system = "groth16"
backend_version = "v1"
proof_format = ["base64", "hex"]
vk_ref = "vk://trnm/zk/groth16/main/v1"

[zk.backends.risc0-host-v1]
enabled = false
system = "risc0"
backend_version = "v1"
proof_format = ["json-envelope"]
image_id = "risc0://trnm/settlement-v1"
```

## 6.3 配置规则
- 未启用 backend 不得被路由。
- `default_backend` 若不存在或未启用，返回 `unavailable`，不得静默落到“假成功”。
- `allow_backend_fallback=false` 时，首选 backend 失败不得尝试第二个 backend。
- fallback 仅允许发生在**同一 `zk_system`** 内，不允许跨 proving system 猜测式切换。

---

## 7. 错误分类冻结

v0 将 ZK 平台错误归并为四大类：

## 7.1 `invalid`
含义：proof 经验证后**确定无效**。

典型场景：
- 证明不成立
- public inputs 与 proof 不匹配
- vk/image/method id 不匹配
- statement 绑定值与任务上下文不匹配

处理原则：
- fail-closed
- 不自动切换到其他 proving system
- 上层进入 `proof_invalid` / dispute / reject 路径

## 7.2 `unavailable`
含义：平台暂时**没有可用验证能力**，但不是 proof 自身被证伪。

典型场景：
- backend 未配置
- backend 被禁用
- required verifier image / vk 缺失
- 外部 verifier service 不可达
- 资源限额导致暂不可服务

处理原则：
- fail-closed
- 可重试 / 可人工恢复
- 与 `invalid` 严格区分，避免误伤有效证明

## 7.3 `backend_error`
含义：backend 执行中发生内部异常，平台无法得出可靠验证结论。

典型场景：
- verifier panic / FFI crash / decode panic
- 返回码异常
- 外部服务协议违反契约
- 内部执行超时但无法判定是否已有结果

处理原则：
- fail-closed
- 不得映射为 `invalid`
- 必须记录 backend_id / backend_version / raw category 以便审计

## 7.4 `malformed`
含义：proof payload / envelope / public input 在进入 cryptographic verification 前就不符合平台规范。

典型场景：
- 缺失必填字段
- schema_version 不支持
- proof_blob 编码错误
- public_inputs 非 canonical 编码
- duplicate binding / unexpected binding / 非 canonical worker / result_hash 形状错误

处理原则：
- 视为输入不合法
- fail-closed
- 不重试同 payload

## 7.5 与当前实现语义的对应关系
当前代码里的：

- `VerificationResult::Valid` → `valid`
- `VerificationResult::Invalid(reason)` → `invalid` 或 `malformed`（取决于 reason 来源）
- `VerificationResult::Indeterminate(reason)` → `unavailable` 或 `backend_error`

v0 冻结要求：

- 未来实现必须把 `Indeterminate` **继续细分落盘/可观测化**，不能长期只保留一个模糊桶
- 对外稳定错误 contract 以四类为准

---

## 8. 兼容策略冻结

## 8.1 对现有 `ProofType::Zk` 兼容
- 维持当前顶层 `ProofType::Zk` 不变。
- 不要求任务对象立刻新增 proving system 枚举字段。
- 多 backend 选择由 payload / config 层承载。

## 8.2 对 legacy receipt alias 兼容
v0 保留当前规范化策略：

- `zk_receipt`
- `zk_proof`
- `zkp`
- `zero knowledge proof`

等历史别名，可继续折叠到 canonical `zk`。

但注意：

- **alias 兼容只负责 proof type 归一化**
- 不代表旧 payload 自动满足 `trnm.zk.payload.v0`
- 旧 payload 若缺字段，只能按 `malformed` 或 `unavailable` 处理，不得静默补全到模糊成功

## 8.3 旧壳到新平台的 rollout 策略
分三阶段：

1. **Observe**：记录 backend_id / zk_system / payload schema，但仍允许旧路径
2. **Enforce envelope**：开启 `zk_payload_v0_envelope`
3. **Enforce router**：开启 `zk_backend_router`，由平台层统一做 backend 选择和错误映射

## 8.4 不兼容项（明确拒绝）
以下做法在 v0 明确不允许：

- 同一 payload 同时声明多个 `zk_system`
- backend 根据裸 payload 猜测 proving system 且不留审计痕迹
- backend 失败后跨 proving system 自动回退
- 把 `backend not configured` 映射为 proof invalid
- 把 malformed payload 直接交给 backend “试试看”

---

## 9. v0 支持范围（明确边界）

v0 **支持**：

1. 在 `ProofType::Zk` 内部引入 backend abstraction
2. 统一 canonical payload / public inputs / binding 规范
3. 用 feature flag / config 驱动 backend 选择
4. 用四类错误冻结对外契约
5. 与现有 fail-closed shell 共存

v0 **不承诺**：

1. 同时上线多个生产级 proving system
2. 递归证明/聚合证明的统一成本模型
3. 证明生成（proving）平台，只覆盖验证平台
4. 链上 verifier 合约矩阵统一
5. 自动 proof migration / re-encoding

---

## 10. 未来扩展位（保留口）

以下字段与能力在 v0 预留，但不强制一次实现：

- `proof_aggregation_id`
- `recursion_depth`
- `curve_id`
- `statement_hash`
- `journal_digest`
- `verifier_caps`
- `cost_hint.verify_ms`
- `cost_hint.memory_mb`
- `cost_hint.gas_estimate`
- `attestation_ref`（用于 TEE+ZK 混合路径）

未来可扩展 proving system 包括但不限于：

- Groth16
- PLONK / UltraPLONK
- Halo2
- STARK / zkVM receipt
- RISC Zero
- SP1
- 自定义 `custom:<org>:<system>`

原则：**新增 proving system 不改 Router 对外契约，只新增 backend capability。**

---

## 11. 统一回执与观测字段

在现有最小字段 `task_id/proof_type/verdict/verified_at/cost_hint` 基础上，ZK 平台 v0 建议补充：

- `zk_system`
- `backend_id`
- `backend_version`
- `payload_schema`
- `error_class`
- `error_code`
- `vk_ref`

其中：

- `proof_type` 仍固定记为 `zk`
- `zk_system` 用于区分 Groth16 / RISC0 / SP1 等内部实现
- `error_class` 必须属于 `invalid | unavailable | backend_error | malformed`

---

## 12. 实施约束（Lane A 落地约束）

1. **本轮只允许改文档，不改业务逻辑。**
2. 后续实现不得绕开本文定义的 canonical payload / error class / compatibility 规则。
3. 若未来代码实现与本文冲突，以本文作为 Lane A 冻结基线，先修文档差异评审，再动实现。
4. 新 backend 接入 PR 必须说明：
   - `zk_system`
   - `backend_id`
   - payload schema/version
   - public inputs canonicalization
   - 失败时如何映射四类错误
   - 是否允许 fallback

---

## 13. 冻结结论

TRNM 的 ZKP v0 平台化路线，现冻结为：

- **顶层 proof kind 继续保持 `zk`**，不扩大业务枚举面
- **backend 插件化发生在 `zk` 内部**
- **canonical payload + public inputs + binding 先行冻结**
- **错误对外统一为 `invalid / unavailable / backend_error / malformed`**
- **兼容旧 alias，但不兼容模糊成功语义**
- **v0 先把“可插拔验证平台”文档化定型，再逐步接入多 proving system**

这意味着：TRNM 从“只有 fail-closed 外壳的 ZK 入口”，正式迈向“多 backend、多 proving system 可演进的平台底座”。
