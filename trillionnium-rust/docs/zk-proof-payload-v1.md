# TRNM ZK Proof Payload / Public Input Spec (v1)

## Goal
固定 `ZK:` envelope 之后，送入真实 verifier/backend 的最小输入格式，避免后续 backend 接入时再发明字段或重新解释绑定关系。

## Verification pipeline
1. **Envelope gate**: `verify_bound_envelope()` 先 fail-closed 校验 `task_id / worker / proof_type / result_hash` 与链上任务上下文完全绑定；格式错误、重复字段、伪造字段名时在密码学前直接失败。
2. **Payload parse gate**: 仅当 envelope 通过后，ZK verifier 将 `ZK:` 后的 JSON 解析为 canonical payload。
3. **Backend gate**: backend 只消费 canonical payload，不再自行猜字段名。

## Canonical payload shape
`proof_data` MUST be UTF-8 and begin with `ZK:`. The suffix MUST be a JSON object:

```json
{
  "task_id": 99,
  "worker": "worker-zk",
  "proof_type": "zk",
  "result_hash": "1111111111111111111111111111111111111111111111111111111111111111",
  "vk_ref": "vk://trnm/dev/mock-groth16/v1",
  "proof_encoding": "base64",
  "proof": "AQIDBA==",
  "public_inputs": {
    "order": ["task_id", "worker", "result_hash"],
    "values": [
      "99",
      "worker-zk",
      "1111111111111111111111111111111111111111111111111111111111111111"
    ]
  }
}
```

## Field encoding rules
- `task_id`: unsigned 64-bit integer, exact match to on-chain `TaskObject.task_id`.
- `worker`: canonical worker account id string, exact byte-for-byte match to task worker.
- `proof_type`: literal `zk` (case-insensitive accepted by envelope gate, canonical lower-case for payload generation).
- `result_hash`: 32-byte result commitment encoded as 64 lowercase hex chars. Payload parser accepts case-insensitive comparison, but producers SHOULD emit lowercase.
- `vk_ref`: opaque verification-key reference string. Examples: content-addressed URI, registry key, on-chain object ref, or backend-local alias. MUST be non-empty.
- `proof_encoding`: `base64` or `hex`. Default is `base64`.
- `proof`: encoded proof bytes. Non-empty after decode.
- `public_inputs`: the minimal backend-facing public-input mapping container. To avoid duplicate top-level binding keys inside the envelope body, v1 encodes this as:
  - `order = ["task_id", "worker", "result_hash"]`
  - `values = [task_id_as_decimal_string, worker, result_hash_hex]`

## Mapping contract
Backend adapters MUST treat the following as the actual verifier input contract:

- **Proof bytes** = decoded `proof`
- **Verification key selector** = `vk_ref`
- **Public inputs** = zip(`public_inputs.order`, `public_inputs.values`)
  - index 0: `task_id -> u64`
  - index 1: `worker -> canonical UTF-8 string`
  - index 2: `result_hash -> 32-byte digest from hex`

Any mismatch between top-level fields and `public_inputs` MUST fail closed before crypto.

## Test vectors
### 1. Valid proof path
- envelope bindings correct
- JSON canonical
- `public_inputs` matches top-level + task context
- `proof` decodes successfully
- mock backend returns `Valid`

### 2. Invalid proof path
- envelope bindings correct
- JSON canonical
- `public_inputs.result_hash` mismatches task/top-level binding
- parser rejects with `public_inputs mismatch`
- no cryptographic backend call should be needed

### 3. Malformed envelope fail-closed before crypto
- payload example: `ZK:   \n\t`
- envelope gate rejects as `Invalid ZK proof envelope`
- parser/backend are not reached

## Backend integration note
`BackendVerificationRequest` now carries:
- `zk_payload: Option<&ParsedZkProofPayload>`
- `resolved_vk_ref: Option<&ResolvedVkRef>`

So a real Groth16/Plonk/STARK adapter can consume already-validated:
- `vk_ref`
- registry-resolved VK metadata (for example `scope` / proving-system hint)
- decoded proof bytes
- minimal public inputs

This keeps current mocked tests useful while making the handoff to a real backend mechanical rather than interpretive.
