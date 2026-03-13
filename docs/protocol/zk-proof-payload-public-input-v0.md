# TRNM ZK Payload / Public Inputs Protocol v0

- 状态：**Draft v0 / protocol freeze candidate**
- 适用范围：`ProofType::Zk` 的平台层 envelope、canonical payload、public inputs、verification-key 引用与最小绑定约束
- 配套架构：`docs/architecture/TRNM_ZKP_PLATFORM_V0.md`
- 说明：本文件是 **ZK payload / public-input 的单独协议真相源**；架构文档只保留平台分层、错误分类与 rollout 语义，不再重复定义字段细节。

---

## 1. 目标

冻结 ZK 验证请求在进入具体 backend 前的最小、可复现、fail-closed 输入契约，避免后续 Groth16 / PLONK / Halo2 / zkVM backend 各自重新解释：

- canonical payload 长什么样
- `public_inputs` 的顺序与编码如何冻结
- `vk_ref` 如何作为 verification-key / image / method-id 引用
- `task_id / worker / result_hash / proof_type` 如何与 statement 绑定

---

## 2. 验证流水线

ZK 路径必须按以下顺序执行，不得跳步：

1. **Envelope gate**
   - 先验证 `proof_data` 是否是合法 `ZK:` envelope。
   - 先做 top-level binding 校验：`task_id / worker / proof_type / result_hash` 必须与链上任务上下文一致。
   - 若 envelope 非法、缺字段、重复绑定、字段名伪造、大小写/编码不满足 canonical 约束，则直接 fail-closed。
2. **Payload parse gate**
   - 仅在 envelope gate 通过后，解析 `ZK:` 后缀 JSON 为 canonical payload。
3. **Statement/public-input gate**
   - 校验 `public_inputs` 顺序、长度、编码、字段语义，并验证其与 top-level binding 一致。
4. **Backend gate**
   - backend 仅消费已经 canonicalized 的 payload；不得自行猜字段名、猜顺序、猜 proving system，或用 backend 容错去补齐协议缺口。

---

## 3. Canonical payload

`proof_data` MUST be UTF-8 and begin with literal `ZK:`. The suffix MUST be a single JSON object.

### 3.1 Canonical shape

```json
{
  "task_id": 99,
  "worker": "worker-zk",
  "proof_type": "zk",
  "result_hash": "1111111111111111111111111111111111111111111111111111111111111111",
  "zk_system": "groth16",
  "backend_id": "local-groth16-bn254",
  "backend_version": "v1",
  "schema_version": "trnm.zk.payload.v0",
  "vk_ref": "vk://trnm/zk/groth16/main/v1",
  "proof_encoding": "base64",
  "proof": "AQIDBA==",
  "public_inputs": {
    "order": ["task_id", "proof_type", "worker", "result_hash"],
    "values": [
      "99",
      "zk",
      "worker-zk",
      "1111111111111111111111111111111111111111111111111111111111111111"
    ]
  },
  "meta": {
    "circuit_id": "settlement-result-v1"
  }
}
```

### 3.2 Required fields

v0 必填：

- `task_id`
- `proof_type`，固定为 `zk`
- `zk_system`
- `schema_version`，固定为 `trnm.zk.payload.v0`
- `proof_encoding`
- `proof`
- `public_inputs.order`
- `public_inputs.values`

条件必填：

- `worker`：当任务上下文存在 worker 绑定时必填
- `result_hash`：当任务上下文要求绑定 reveal/result commitment 时必填
- `backend_id`：当平台启用显式 backend 选择时必填
- `backend_version`：当同一 `backend_id` 有多版本可路由时必填
- `vk_ref`：对需要 verification key / method id / image id / verifier config 的 proving system 必填

### 3.3 Unknown / duplicate fields

- 重复字段名：**MUST reject**
- 与 v0 语义冲突的未知字段：**MUST reject**
- 纯扩展性元数据：仅允许放入 `meta`，且不得影响 binding 语义
- backend-specific 私有字段：应置于 `meta.backend_extensions` 等显式命名空间，不得污染 canonical binding 集合

---

## 4. 字段编码规则

### 4.1 `task_id`

- 无符号 64-bit 整数语义
- top-level 中可表现为 JSON number
- 在 `public_inputs.values` 中 **MUST** 编码为十进制字符串，如 `"99"`
- 必须与链上 `TaskObject.task_id` 精确一致

### 4.2 `proof_type`

- canonical 值固定为小写 `zk`
- envelope gate 可兼容历史 alias 的归一化输入，但一旦进入 canonical payload，`proof_type` **MUST** 为 `zk`
- 在 `public_inputs.values` 中也 **MUST** 为 `"zk"`

### 4.3 `worker`

- canonical worker account id 字符串
- 必须与任务上下文中的 worker 做 byte-for-byte 一致比较
- 不允许 trim、大小写折叠、Unicode 兼容归一化后的“宽松相等”
- 在 `public_inputs.values` 中按 canonical UTF-8 字符串承载

### 4.4 `result_hash`

- 32-byte 结果承诺
- top-level canonical 编码：**64 个小写十六进制字符，不带 `0x` 前缀**
- `public_inputs.values` 中采用同一 canonical 文本编码
- 解析器可以为了兼容诊断做大小写无关比较，但生产者 **SHOULD** 始终输出小写 canonical 形式

### 4.5 `proof_encoding`

v0 允许：

- `base64`
- `hex`

规则：

- `proof` decode 后必须非空
- 非法编码、空 proof、decode 后空字节串：**MUST reject as malformed**

### 4.6 `zk_system`

示例：

- `groth16`
- `plonk`
- `halo2`
- `risc0`
- `sp1`
- `custom:<org>:<system>`

规则：

- 必须显式给出，不允许 backend 从 proof blob 猜测
- fallback 仅允许在同一 `zk_system` 内发生

### 4.7 `vk_ref`

`vk_ref` 是一个 **opaque verifier reference**，可指向：

- verification key
- verifier image / method id
- verifier config bundle
- registry key / content-addressed object / on-chain verifier object

规则：

- 必须非空
- 只要求字符串层面的稳定引用语义；解析方式由对应 backend 负责
- 平台层不解释其内部路径结构，但会把它作为审计/可观测字段保留下来
- backend 不得在未记录审计痕迹的情况下 silently rewrite `vk_ref`
- v0 router / registry 必须能把 `vk_ref` 解析为稳定的 verifier 元数据；对于 ZK 路径，至少包括 canonical `zk_system`（如 `groth16`、`plonk`）
- 若 `vk_ref` 无法解析，或解析结果缺失该 canonical `zk_system` 元数据，**MUST fail closed**
- payload 中声明的 `zk_system` **MUST** 与 `vk_ref` 解析出的 canonical `zk_system` 一致
- 若 payload 显式给出 `backend_id`，且 router/backend selection 能从该 backend token 推断 proving-system hint，则该 hint **MUST** 与 `vk_ref` 解析出的 canonical `zk_system` 一致
- backend router 选中的最终 backend 若带有可推断的 proving-system hint，也 **MUST** 与 `vk_ref` 解析出的 canonical `zk_system` 一致；不得跨 proving system 静默 fallback

---

## 5. Public inputs 规范

### 5.1 Container shape

v0 统一采用：

```json
{
  "order": ["task_id", "proof_type", "worker", "result_hash"],
  "values": ["99", "zk", "worker-zk", "1111..."]
}
```

约束：

- `order.len()` 必须等于 `values.len()`
- `order` 中字段名不得重复
- `order[i]` 与 `values[i]` 的位置绑定即语义绑定
- backend **MUST NOT** 重新排序后再解释

### 5.2 v0 canonical order

当上下文要求完整绑定集时，v0 canonical order 冻结为：

1. `task_id`
2. `proof_type`
3. `worker`
4. `result_hash`

也即：

```json
{
  "order": ["task_id", "proof_type", "worker", "result_hash"]
}
```

如果某上下文中 `worker` 或 `result_hash` 不适用，则允许删去对应项，但剩余字段顺序仍必须保持 **该 canonical 顺序的子序列**：

- 仅 `task_id + proof_type`
- `task_id + proof_type + worker`
- `task_id + proof_type + result_hash`
- `task_id + proof_type + worker + result_hash`

v0 **不允许**：

- `worker` 出现在 `task_id` 之前
- `result_hash` 出现在 `proof_type` 之前
- 任意 backend 自定义新的 binding 排序却仍声称是 `trnm.zk.payload.v0`

### 5.3 Value encoding by field

- `task_id` → 十进制字符串
- `proof_type` → 小写字符串 `zk`
- `worker` → canonical UTF-8 字符串
- `result_hash` → 64 个小写 hex 字符，不带 `0x`

### 5.4 Binding equality rule

对每个出现在 `public_inputs.order` 里的 binding 字段，平台都必须验证：

`top-level payload value == reconstructed public-input value == task-context expected value`

任一不等，**MUST fail closed before crypto**。

### 5.5 Systems with non-literal public exposure

若某 proving system 无法把 `task_id / proof_type / worker / result_hash` 逐字面暴露为 public inputs，则必须通过以下任一等价公开 statement 提供可验证绑定：

- statement digest
- receipt/journal public output
- verifier image + committed public output

但在 `trnm.zk.payload.v0` 下，payload 仍必须显式给出本协议中的 canonical binding 字段，供平台层先做 envelope 校验与审计落盘。也就是说：

- **可以**由 backend 把这些字段映射到系统原生 statement 形式
- **不可以**完全省略这些字段，然后让平台“盲信 backend”

---

## 6. 最小绑定约束

### 6.1 Required binding set

v0 要求 ZK statement 至少绑定以下最小集合：

- `task_id`
- `proof_type = zk`
- `worker`（若任务上下文有 worker）
- `result_hash`（若任务上下文有结果哈希绑定）

### 6.2 Why `proof_type` is included

即使当前顶层已经走到了 `ProofType::Zk`，v0 仍要求把 `proof_type` 纳入 statement 绑定，原因是：

- 防止跨 proof-family payload 被错误复用
- 防止历史 alias / 兼容层在 envelope 外绕过语义固定
- 给未来混合验证路径（如 TEE+ZK）保留明确 statement 域分隔

### 6.3 No partial silent binding

以下情况一律视为协议不满足：

- top-level 有 `result_hash`，但 `public_inputs` / 等价 statement 不绑定它
- top-level 有 `worker`，但后端只验证 `task_id`
- backend 仅验证 `vk_ref` 与 proof 成对，却不验证任务上下文绑定

---

## 7. Backend handoff contract

平台向 backend 交付的最小验证合同应当至少包含：

- decoded proof bytes
- `zk_system`
- `backend_id` / `backend_version`（如适用）
- `vk_ref`
- canonicalized binding map（按 `public_inputs.order` + `values` 重建）
- 原始 `public_inputs` 容器
- top-level envelope fields（供审计与错误回映）

backend 行为约束：

- 不得自行补默认 `task_id / worker / result_hash / proof_type`
- 不得在未记录审计痕迹时忽略 payload 中的 `vk_ref`
- 不得把 malformed payload 映射为 cryptographically invalid proof

---

## 8. Fail-closed cases

以下情况在 v0 下必须在密码学验证前失败：

1. `ZK:` 后不是单个 JSON object
2. 缺少 `schema_version = trnm.zk.payload.v0`
3. `proof_type != zk`
4. `public_inputs.order` / `values` 长度不一致
5. `public_inputs.order` 重复字段
6. `public_inputs` 顺序不符合 v0 canonical order
7. `task_id / proof_type / worker / result_hash` 任一绑定值不一致
8. `proof` 编码非法或 decode 为空
9. `vk_ref` 在要求场景下缺失
10. 试图用未知顶层 binding 字段替代 canonical 字段

---

## 9. Test vectors

### 9.1 Valid path

- envelope bindings 正确
- `schema_version = trnm.zk.payload.v0`
- `public_inputs.order = ["task_id", "proof_type", "worker", "result_hash"]`
- `public_inputs.values = ["99", "zk", "worker-zk", "<64-lower-hex>"]`
- `vk_ref` 非空
- `proof` 成功 decode
- backend 返回 `valid`

### 9.2 Binding mismatch

- top-level `result_hash = a...a`
- `public_inputs.values[3] = b...b`
- 结果：payload parser / statement gate 直接拒绝，**不得调用 cryptographic backend**

### 9.3 Wrong order

- `order = ["worker", "task_id", "proof_type", "result_hash"]`
- 即使 `values` 语义上可解释，也必须判为 `malformed`

### 9.4 Missing `proof_type` in statement

- top-level 有 `proof_type = "zk"`
- 但 `public_inputs.order = ["task_id", "worker", "result_hash"]`
- 若上下文要求完整绑定集，则必须判为 `malformed`

---

## 10. 与架构文档的关系

- 平台分层、trait 形态、错误分类、feature flag、compatibility rollout：见 `docs/architecture/TRNM_ZKP_PLATFORM_V0.md`
- 本文件只负责冻结 **payload / public_inputs / vk_ref / binding** 的协议细节
- 若未来实现与本文冲突，应先更新协议或新增版本（如 `trnm.zk.payload.v1`），不得在代码中静默漂移

---

## 11. v0 冻结结论

TRNM ZK payload/public-input v0 的核心冻结点是：

1. canonical payload 必须显式包含 `task_id / proof_type / worker / result_hash`
2. `public_inputs` 必须是 **顺序敏感** 的 `order + values` 容器
3. v0 canonical binding order 冻结为 `task_id -> proof_type -> worker -> result_hash`
4. `vk_ref` 是必须审计保留的 opaque verifier reference
5. top-level binding、public inputs、链上任务上下文三者必须在进入 crypto 前先完成一致性校验
6. backend 只能消费 canonicalized 请求，不能把协议缺口变成实现层“宽松兼容”
