# PoUW LLM Token Meter v1 (Draft)

Status: Draft
Scope: additive metering schema proposal for LLM-oriented workloads under PoUW-compatible task lifecycle semantics
Compatibility: does **not** require redefining the existing PoUW state machine (`OPEN -> ASSIGNED -> COMMITTED -> REVEALED -> CHALLENGED -> COMPLETED/SLASHED`); instead introduces a new workload/metering class layered on top of it.
BL09 retirement-prep note: during PoCO migration, treat this draft as legacy metering and challenge-compatibility guidance. Retained PoUW-specific receipts, policy snapshots, or crate names should be read as migration-era compatibility or provenance / audit evidence only, not as evidence that PoUW remains the default payout authority.

---

## 1. Goal

Define a **verifiable**, **challengeable**, and **settleable** workload meter for LLM inference that is easier to audit than raw throughput.

This proposal explicitly avoids using `tokens/sec` as the consensus workload metric.

Instead, it standardizes an attested receipt around:

- `prompt_tokens`
- `generated_tokens` (canonical output-token field; JSON alias: `completion_tokens`)
- `decode_steps`
- `kv_bytes_moved`
- `prefill_ms`
- `decode_ms`
- attested execution timestamps
- device profile metadata

and derives a normalized `work_units` value from those counters.

---

## 2. Why not raw throughput

Raw throughput (`tokens/sec`) is useful for:

- scheduling
- pricing hints
- market ranking
- capacity planning

But it is a weak consensus workload metric because it varies with:

- tokenizer version
- model/runtime implementation
- batching policy
- quantization
- cache behavior
- hardware throttling
- host/runtime noise

For PoUW, we want the chain to settle on **counters that can be challenged and recomputed**, not on a noisy performance ratio.

---

## 3. Design summary

Introduce a new workload class / metering schema:

- `workload_class = llm_inference`
- `metering_schema = llm_token_meter_v1`

Workers still follow the existing lifecycle:

1. execute assigned task
2. produce attested metering receipt inside TEE
3. `commit` receipt hash
4. `reveal` full metering receipt
5. allow `challenge`
6. `resolve` to final settlement / slash

---

## 4. Canonical counters

`llm_token_meter_v1` defines the following canonical counters.

### 4.1 Required counters

- `prompt_tokens: u64`
- `generated_tokens: u64` (canonical output-token field; JSON alias: `completion_tokens`)
- `decode_steps: u64`
- `kv_bytes_moved: u64` (canonicalized byte-movement counter; may be `0` when a backend does not meter KV movement yet)
- `prefill_ms: u64`
- `decode_ms: u64`

### 4.2 Required timing fields

- `attested_started_at_unix_ms: u64`
- `attested_finished_at_unix_ms: u64`
- `attested_elapsed_ms: u64`

Constraint:

- `attested_finished_at_unix_ms >= attested_started_at_unix_ms`
- `attested_elapsed_ms == attested_finished_at_unix_ms - attested_started_at_unix_ms`
- `prefill_ms + decode_ms <= attested_elapsed_ms + jitter_budget_ms`

### 4.3 Required model / tokenizer identity

- `model_family: String`
- `model_id: String`
- `tokenizer_id: String`
- `tokenizer_version: String`

These fields prevent workers from silently changing tokenization semantics.

### 4.4 Required device profile

- `device_profile_id: String`
- `device_vendor: String`
- `device_class: String`
- `accelerator_kind: String`  
  Example: `cpu`, `gpu`, `tpu`, `npu`
- `quantization: String`  
  Example: `fp16`, `bf16`, `int8`, `int4`
- `runtime_name: String`
- `runtime_version: String`

This is **not** used as the primary workload metric. It is attested metadata used for challenge context, scheduling, and pricing.

---

## 5. Receipt structure

Suggested reveal payload:

```json
{
  "workload_class": "llm_inference",
  "metering_schema": "llm_token_meter_v1",
  "task_id": "task_123",
  "worker_id": "worker_abc",
  "assignment_id": "assign_456",
  "model_family": "llm",
  "model_id": "meta-llama-3.1-70b-instruct",
  "tokenizer_id": "llama3-tokenizer",
  "tokenizer_version": "1.0.0",
  "prompt_hash": "0x...",
  "output_hash": "0x...",
  "prompt_tokens": 1824,
  "generated_tokens": 512,
  "decode_steps": 512,
  "kv_bytes_moved": 4096,
  "prefill_ms": 147,
  "decode_ms": 923,
  "attested_started_at_unix_ms": 1760000000123,
  "attested_finished_at_unix_ms": 1760000001193,
  "attested_elapsed_ms": 1070,
  "device_profile_id": "h100-sxm-bf16-v1",
  "device_vendor": "nvidia",
  "device_class": "h100-sxm",
  "accelerator_kind": "gpu",
  "quantization": "bf16",
  "runtime_name": "vllm",
  "runtime_version": "0.8.4",
  "batch_size": 1,
  "tee_attestation": {
    "attester": "sgx-dcap",
    "quote_hash": "0x...",
    "measurement": "0x..."
  },
  "receipt_hash": "0x..."
}
```

---

## 6. What gets committed vs revealed

### 6.1 Commit phase

Worker commits a minimal hash envelope:

```json
{
  "task_id": "task_123",
  "metering_schema": "llm_token_meter_v1",
  "receipt_hash": "0x..."
}
```

### 6.2 Reveal phase

Worker reveals the full receipt payload.

The chain validates:

- schema id recognized
- receipt hash matches prior commit
- required fields present
- counters/timestamps satisfy invariants
- attestation is valid for accepted verifier policy

---

## 7. Settlement metric: normalized work units

The chain should not settle on raw throughput. It should settle on:

```text
work_units =
    a * prompt_tokens
  + b * generated_tokens
  + c * decode_steps
  + d * kv_bytes_moved
```

Optional additive terms may be introduced later, for example:

```text
  + e * verifier_penalty_units
```

### Recommended v1 simplification

For v1, keep it simple:

```text
work_units =
    a * prompt_tokens
  + b * generated_tokens
  + c * decode_steps
  + d * kv_bytes_moved
```

Where:

- `a`, `b`, `c`, `d` are governance-controlled parameters (or published via a governance-approved Oracle path)
- `decode_steps` allows explicit accounting for iterative generation
- `generated_tokens` is the canonical output-token field (`completion_tokens` is accepted as a JSON alias)
- `prompt_tokens` covers prefill work
- `kv_bytes_moved` covers explicit KV-cache / state-movement accounting when the backend can attest it; otherwise it remains `0`

### Important

- `prefill_ms` and `decode_ms` are **attested observability fields**
- they are **not** the primary settlement quantity in v1
- they are still useful during challenge and benchmarking

---

## 8. Challenge rules

Any challenger may challenge a receipt on one or more of the following grounds.

### 8.1 Hash mismatch

- revealed `receipt_hash` does not match committed hash

### 8.2 Schema violation

- missing required field
- malformed field type
- unsupported schema version

### 8.3 Counter inconsistency

- `generated_tokens > 0` but `decode_steps == 0`
- negative/overflow-like impossible values
- `attested_elapsed_ms` inconsistent with timestamps
- `prefill_ms + decode_ms` exceeds allowed timing envelope

### 8.4 Tokenization mismatch

- `tokenizer_id/version` incompatible with assigned task requirements
- recomputed token counts do not match reveal payload

### 8.5 Attestation mismatch

- quote invalid
- measurement unapproved
- TEE policy mismatch
- receipt fields not covered by the attested statement

### 8.6 Device profile misreport

- attested environment contradicts declared `device_profile_id`
- runtime / quantization / accelerator metadata inconsistent with attested evidence

---

## 9. Resolve outcomes

Suggested resolve codes:

- `0 = receipt_valid`
- `1 = hash_mismatch`
- `2 = schema_invalid`
- `3 = counter_inconsistent`
- `4 = tokenizer_mismatch`
- `5 = attestation_invalid`
- `6 = device_profile_mismatch`
- `7 = insufficient_reveal`

Result policy:

- `receipt_valid` -> settle by `work_units`
- any invalid outcome -> slash or reject settlement depending on governance policy

---

## 10. Event fields

Recommended additional reveal / resolve event fields:

- `workload_class`
- `metering_schema`
- `receipt_hash`
- `work_units`
- `prompt_tokens`
- `generated_tokens`
- `decode_steps`
- `kv_bytes_moved`
- `prefill_ms`
- `decode_ms`
- `device_profile_id`
- `resolution_code`

This keeps auditability without forcing every consumer to parse the full receipt body.

---

## 11. TEE attestation boundary

The TEE must cover at least:

- model/tokenizer identity binding
- canonical counters
- timing fields
- device/runtime profile fields
- receipt hash

If a field is not inside the attested statement, it should not be trusted for settlement.

---

## 12. Compatibility strategy

Because the existing Rust L1 v1 interface semantics are frozen, the safest path is:

1. keep current state machine semantics unchanged
2. add a new metering schema id
3. route PoUW settlement through schema-aware validation
4. treat `llm_token_meter_v1` as a new workload subtype
5. during PoCO-primary migration, treat any retained PoUW metering path as compatibility or audit evidence support, not as the default payout authority

This avoids silently redefining old PoUW field meanings while keeping BL09 retirement-prep wording attached to the remaining compatibility surface.

### Current scaffold status (March 2026)

The Rust scaffold now includes:

- `trnm-pouw::metering` receipt/schema types
- canonical receipt-hash generation + validation
- `work_units` calculation for `prompt_tokens + generated_tokens + decode_steps + kv_bytes_moved`
- reveal-side validation on the non-verifiable/Fraud path, where a supplied `llm_token_meter_v1` JSON receipt is accepted only if it validates and matches the canonical `task_id` / `worker_id` / `result_hash` binding
- reveal-side persistence of a metering snapshot onto task metadata (`receipt_hash`, counters, coefficient snapshot, `normalized_work_units`)
- reveal-side persistence also freezes the **metering policy snapshot** used for later adjudication / payouts (policy snapshot version + floor / ratio parameters)
- challenge/resolve-side reading of that persisted snapshot with fail-closed validation: malformed or internally inconsistent `normalized_work_units` snapshots are rejected before state transition
- resolve-side governance adjudication gate: when `slash_worker = false`, an LLM-metered task must satisfy the **snapshotted** `min_accept_work_units`; later governance drift must not retroactively reinterpret already-revealed metered tasks
- slash-path payout integration: challenge-success bounty can now include a metered bonus derived from `normalized_work_units`, using governance ratio keys `llm_meter_challenge_success_bounty_per_work_unit_num` / `llm_meter_challenge_success_bounty_per_work_unit_den`
- for metered tasks, that challenge-success bounty policy is read from the **snapshotted reveal-time policy**, not re-read from live governance at resolve time
- node event audit visibility: reveal / resolve / timeout event lines can now emit `metering_*` flat key-value fields carrying `normalized_work_units`, counters, weights, and frozen payout/floor policy summary
- RPC audit visibility: `trnm-rpc` now parses those `metering_*` event fields back into a nested `metering` audit block for event-oriented queries, `query-task` can also expose the persisted metering snapshot when configured with a task-state snapshot source, and the RPC-layer `metering` block now carries a standardized `derived` section (accept-floor hit, challenge bonus total, worker bonus, worker rebate) computed from the snapshotted policy
- CLI audit visibility: `trnm-cli query task <task_id>`, `trnm-cli query events <task_id> --limit N`, and `trnm-cli query request-full <request_id> --limit N` now pretty-print the same nested metering audit block / timeline when the underlying RPC response includes it; `query events` and `query request-full` also support `--summary` for a compact human-auditable metering timeline view that prefers the RPC-provided standardized `derived` audit block and only falls back to local recomputation when older responses omit it
- worker-side terminal accounting integration:
  - completed-path worker bonus can be paid from `CHALLENGE_FORFEIT_TREASURY_ACCOUNT`, using `llm_meter_worker_completion_bonus_per_work_unit_num` / `llm_meter_worker_completion_bonus_per_work_unit_den`
  - slashed-path worker rebate can return a metered share of locked worker stake back to the worker before the remainder is sent to `WORKER_SLASH_TREASURY_ACCOUNT`, using `llm_meter_worker_slash_rebate_per_work_unit_num` / `llm_meter_worker_slash_rebate_per_work_unit_den`
- governance allowlist + schema validation for the coefficient/adjudication keys:
  - `llm_meter_prompt_token_weight`
  - `llm_meter_generated_token_weight`
  - `llm_meter_decode_step_weight`
  - `llm_meter_kv_byte_weight`
  - `llm_meter_min_accept_work_units`
  - `llm_meter_challenge_success_bounty_per_work_unit_num`
  - `llm_meter_challenge_success_bounty_per_work_unit_den`
  - `llm_meter_worker_completion_bonus_per_work_unit_num`
  - `llm_meter_worker_completion_bonus_per_work_unit_den`
  - `llm_meter_worker_slash_rebate_per_work_unit_num`
  - `llm_meter_worker_slash_rebate_per_work_unit_den`

Still pending:

- TEE-side attested receipt generation
- deeper settlement policy design beyond the current additive gates/bonuses/rebates (for example, making bounty sizing itself natively work-unit priced)

---

## 13. Suggested Rust-side schema skeleton

```rust
pub struct LlmTokenMeterV1Receipt {
    pub workload_class: String,
    pub metering_schema: String,
    pub task_id: String,
    pub worker_id: String,
    pub assignment_id: String,

    pub model_family: String,
    pub model_id: String,
    pub tokenizer_id: String,
    pub tokenizer_version: String,

    pub prompt_hash: String,
    pub output_hash: String,

    pub prompt_tokens: u64,
    pub generated_tokens: u64,
    pub decode_steps: u64,
    pub kv_bytes_moved: u64,
    pub prefill_ms: u64,
    pub decode_ms: u64,

    pub attested_started_at_unix_ms: u64,
    pub attested_finished_at_unix_ms: u64,
    pub attested_elapsed_ms: u64,

    pub device_profile_id: String,
    pub device_vendor: String,
    pub device_class: String,
    pub accelerator_kind: String,
    pub quantization: String,
    pub runtime_name: String,
    pub runtime_version: String,
    pub batch_size: u32,

    pub receipt_hash: String,
    pub tee_attestation: TeeAttestationEnvelope,
}
```

---

## 14. Suggested implementation sequence

1. add schema type + serde model
2. add receipt hash canonicalization
3. add reveal-side validation rules
4. add `work_units` calculator
5. add challenge/resolve validation path
6. add event emission fields
7. add worker-agent metering adapter for LLM tasks
8. add TEE-side attested receipt generation

---

## 15. Open questions

- Should `decode_steps` always equal `generated_tokens` for v1, or remain separately reported?
- Should `prefill_ms` / `decode_ms` be bounded by device-profile-specific reasonability windows?
- Do we want optional `kv_cache_bytes` / `batch_context_tokens` in v2?
- Should pricing use a distinct off-chain throughput market while settlement stays on normalized units?

---

## 16. Recommendation

Adopt `llm_token_meter_v1` as a **new additive metering schema**, not as a hidden reinterpretation of existing PoUW fields.

Consensus settles on `work_units`, not on raw throughput.
Attested timing and device profile remain important, but as verifiable metadata and challenge context rather than the sole workload scalar.
