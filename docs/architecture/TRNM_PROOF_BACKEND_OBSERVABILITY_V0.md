# TRNM Proof Backend Observability v0（Lane 18 冻结草案）

- BL09 退役准备口径：本文若提到 `trnm-pouw`、PoUW proof verification 或保留中的 challenge/resolve 验证边界，默认仅指迁移期兼容、provenance / audit evidence 与残余观测面；不应被解读为当前默认 payout authority，也不为默认 work-unit payout path 背书。对外付款判断与默认结算 authority 仍应以 PoCO settlement anchor 为准。

## 1. 目标

为 `fraud / tee / zk` verification 平台冻结一套**最小可落地**的观测口径，满足：

- 能回答“哪条 proof 线在失败/退化”；
- 能区分“proof 自身无效” vs “backend 没配/暂不可用” vs “payload 先天畸形”；
- 不要求立刻接入 Prometheus / OpenTelemetry，但代码里要有稳定 label contract，避免后续 exporter 各写各的；
- 保持低基数（low cardinality），不把 `task_id / worker / vk_ref / raw error` 直接打进 metrics label。

这份 v0 面向 **proof verification backend**，不是全链通用 telemetry 规范。

---

## 2. 最小 metrics 面

建议至少暴露 4 组指标；如果当前只愿意做最小钩子，则先保证这些名字/label 语义稳定。

### 2.1 Counter：`trnm_proof_verification_attempts_total`

表示 verification 尝试次数。

**labels：**

- `proof_type`：`fraud | tee | zk`
- `outcome`：`valid | invalid | indeterminate`
- `stage`：`envelope | backend`
- `error_class`：`invalid | malformed | unavailable | backend_error`（成功时省略或记空）
- `backend_family`：`tee | zk`（Fraud 无）
- `configured_backend`：如 `noop | intel-sgx-dcap | risc0-host-v1`（仅 backend-capable family）
- `active_backend`：实际返回结果的 backend 标识；`tee:noop` / `zk:noop` 这类可保留
- `zk_system`：如 `groth16 | plonk | risc0 | sp1`（仅 ZK 且 payload 可解析时）

### 2.2 Histogram：`trnm_proof_verification_duration_ms`

表示从 verifier 入口到 verdict 的耗时。

**labels：**

- `proof_type`
- `outcome`
- `stage`
- `backend_family`（可选）
- `configured_backend`（可选）

v0 不强求代码里立刻埋直方图，但要求未来耗时指标沿用相同 label contract。

### 2.3 Gauge / last-seen：`trnm_proof_backend_configured`

表示某 backend family 当前是否配成可用后端，而不是 `noop`。

**labels：**

- `backend_family`
- `configured_backend`

**值语义：**

- `0`：未配置 / noop
- `1`：配置了非 noop backend

### 2.4 Counter：`trnm_proof_backend_errors_total`

只统计 backend stage 的失败/退化，便于快速区分“envelope 攻击面”与“真实 backend 健康问题”。

**labels：**

- `proof_type`
- `backend_family`
- `configured_backend`
- `active_backend`
- `error_class`
- `zk_system`（仅 ZK）

---

## 3. 错误分类冻结

v0 只允许这 4 类错误桶进入 metrics label：

### 3.1 `invalid`

含义：proof 语义上确定无效。

例子：

- `task_id / worker / result_hash / proof_type` 绑定不一致；
- backend 明确返回 proof rejected；
- public inputs 与 statement 不匹配。

### 3.2 `malformed`

含义：在进入密码学校验前，payload / envelope 自身不符合协议形状。

例子：

- `ZK:` 之后不是 canonical JSON；
- `vk_ref` 缺失；
- proof bytes 不是合法 hex/base64；
- 必填字段缺失导致 fail-closed。

### 3.3 `unavailable`

含义：proof 不一定错，但当前没有可用验证能力。

例子：

- backend `noop` / not configured；
- backend readiness 未就绪；
- backend 明确返回“暂不可验证”。

### 3.4 `backend_error`

含义：backend 自身异常，超出正常 proof verdict 范围。

例子：

- verifier 进程崩溃；
- FFI / host service internal error；
- unexpected backend exception。

---

## 4. stage 口径冻结

### 4.1 `stage=envelope`

表示失败发生在 canonical envelope / binding 校验阶段，尚未进入真实 backend。典型如：

- missing / duplicate / spoofed `task_id`；
- worker mismatch；
- malformed JSON envelope；
- result hash binding 缺失。

### 4.2 `stage=backend`

表示已越过 envelope gate，并进入 backend dispatch / execution 阶段。典型如：

- `tee:noop` / `zk:noop` not configured；
- backend 明确 reject proof；
- backend internal failure。

**Fraud 当前定位：**
- 仍是 backendless semantic verifier；
- 因此 Fraud v0 主要产出 `stage=envelope`；
- 只有未来真正引入 `fraud backend` trait 后，才应出现 `stage=backend` 的 Fraud 指标。

---

## 5. 高基数字段处理规则

以下字段可以进日志 / 审计回执，但**不得直接进 metrics label**：

- `task_id`
- `worker`
- `vk_ref`
- `result_hash`
- 原始 error message
- quote / proof blob / public_inputs 明文

推荐策略：

- metrics 只保留 `error_class / outcome / proof_type / backend* / zk_system`；
- 详细原因进入 structured log / receipt；
- 如需排障，日志里单独挂 `task_id`，但不要作为 metrics label。

---

## 6. 代码钩子约定（本次最小落地）

本次 Lane 18 不强求接 exporter，只要求在 `trnm-pouw` 内提供稳定映射函数：

- `VerificationResult -> outcome_label`
- `BackendExecutionError -> error_class`
- `VerificationResult / BackendExecutionError -> ProofVerificationObservation`

这意味着未来无论接：

- Prometheus counter/histogram
- tracing span fields
- audit receipt enrich
- RPC debug endpoint

都应优先复用同一 observation contract，而不是重新猜 label 名。

---

## 7. 当前代码状态与实施建议

### 已具备

- `TEE / ZK` 已有 backend family 与 fail-closed `noop` 行为；
- `ZK` 已有 canonical payload 解析与 pre-crypto malformed/invalid 区分；
- `Fraud` 已明确是 backendless semantic verifier。

### 本次最小补丁的价值

- 把“结果/错误如何统计”从文档口头约定变成代码里的稳定 API；
- 先统一 label contract，再决定 exporter 细节；
- 为后续接入真实 `tee-*` / `zk-*` backend 留下兼容口径。

### 下一步建议

1. 在 reveal / verify 主路径记录 `start_ms`，落 `duration_ms` histogram。
2. 将 `ProofVerificationObservation::label_pairs()` 接到 RPC debug / tracing。
3. 当首个真实 backend 上线时，再补：
   - `backend_version`
   - `capability_state`（ready / degraded / disabled）
   - `retryable=true|false`（仅日志字段，不建议先入 metrics）

---

## 8. v0 结论

TRNM proof backend observability 的最小冻结面应是：

- **三类 outcome**：`valid / invalid / indeterminate`
- **四类 error_class**：`invalid / malformed / unavailable / backend_error`
- **两段 stage**：`envelope / backend`
- **有限 backend labels**：`backend_family / configured_backend / active_backend / zk_system`

先把这些低基数标签定死，再去接 exporter，才不会把 observability 做成另一层协议漂移。
