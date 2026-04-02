use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

pub const LLM_INFERENCE_WORKLOAD_CLASS: &str = "llm_inference";
pub const LLM_TOKEN_METER_V1_SCHEMA: &str = "llm_token_meter_v1";
pub const DEFAULT_LLM_TOKEN_METER_JITTER_BUDGET_MS: u64 = 5;

fn default_workload_class() -> String {
    LLM_INFERENCE_WORKLOAD_CLASS.to_string()
}

fn default_metering_schema() -> String {
    LLM_TOKEN_METER_V1_SCHEMA.to_string()
}

fn default_batch_size() -> u32 {
    1
}

fn normalize_hex(raw: &str) -> &str {
    let trimmed = raw.trim();
    trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
        .unwrap_or(trimmed)
}

fn require_non_empty(value: &str, field: &'static str) -> Result<(), LlmTokenMeterError> {
    if value.trim().is_empty() {
        Err(LlmTokenMeterError::MissingField(field))
    } else {
        Ok(())
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum LlmTokenMeterError {
    #[error("missing field: {0}")]
    MissingField(&'static str),
    #[error("invalid workload class: expected {expected}, got {actual}")]
    InvalidWorkloadClass {
        expected: &'static str,
        actual: String,
    },
    #[error("invalid metering schema: expected {expected}, got {actual}")]
    InvalidMeteringSchema {
        expected: &'static str,
        actual: String,
    },
    #[error("invalid counter: {0}")]
    InvalidCounter(&'static str),
    #[error("invalid timing: {0}")]
    InvalidTiming(&'static str),
    #[error("receipt hash mismatch: expected {expected}, got {actual}")]
    ReceiptHashMismatch { expected: String, actual: String },
    #[error("canonicalization error: {0}")]
    Canonicalization(String),
    #[error("serde error: {0}")]
    Serde(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TeeAttestationEnvelope {
    pub attester: String,
    pub quote_hash: String,
    pub measurement: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct LlmTokenMeterV1WorkUnitCoefficients {
    pub prompt_tokens: u128,
    #[serde(alias = "completion_tokens")]
    pub generated_tokens: u128,
    pub decode_steps: u128,
    #[serde(default)]
    pub kv_bytes_moved: u128,
}

impl Default for LlmTokenMeterV1WorkUnitCoefficients {
    fn default() -> Self {
        Self {
            prompt_tokens: 1,
            generated_tokens: 1,
            decode_steps: 1,
            kv_bytes_moved: 0,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LlmTokenMeterV1Receipt {
    #[serde(default = "default_workload_class")]
    pub workload_class: String,
    #[serde(default = "default_metering_schema")]
    pub metering_schema: String,
    pub task_id: u64,
    pub worker_id: String,
    pub assignment_id: String,
    pub model_family: String,
    pub model_id: String,
    pub tokenizer_id: String,
    pub tokenizer_version: String,
    pub prompt_hash: String,
    pub output_hash: String,
    pub prompt_tokens: u64,
    #[serde(alias = "completion_tokens")]
    pub generated_tokens: u64,
    pub decode_steps: u64,
    #[serde(default)]
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
    #[serde(default = "default_batch_size")]
    pub batch_size: u32,
    pub tee_attestation: TeeAttestationEnvelope,
    pub receipt_hash: String,
}

#[derive(Serialize)]
struct CanonicalLlmTokenMeterV1Receipt<'a> {
    workload_class: &'a str,
    metering_schema: &'a str,
    task_id: u64,
    worker_id: &'a str,
    assignment_id: &'a str,
    model_family: &'a str,
    model_id: &'a str,
    tokenizer_id: &'a str,
    tokenizer_version: &'a str,
    prompt_hash: &'a str,
    output_hash: &'a str,
    prompt_tokens: u64,
    generated_tokens: u64,
    decode_steps: u64,
    kv_bytes_moved: u64,
    prefill_ms: u64,
    decode_ms: u64,
    attested_started_at_unix_ms: u64,
    attested_finished_at_unix_ms: u64,
    attested_elapsed_ms: u64,
    device_profile_id: &'a str,
    device_vendor: &'a str,
    device_class: &'a str,
    accelerator_kind: &'a str,
    quantization: &'a str,
    runtime_name: &'a str,
    runtime_version: &'a str,
    batch_size: u32,
    tee_attestation: &'a TeeAttestationEnvelope,
}

impl LlmTokenMeterV1Receipt {
    fn canonical_view(&self) -> CanonicalLlmTokenMeterV1Receipt<'_> {
        CanonicalLlmTokenMeterV1Receipt {
            workload_class: &self.workload_class,
            metering_schema: &self.metering_schema,
            task_id: self.task_id,
            worker_id: &self.worker_id,
            assignment_id: &self.assignment_id,
            model_family: &self.model_family,
            model_id: &self.model_id,
            tokenizer_id: &self.tokenizer_id,
            tokenizer_version: &self.tokenizer_version,
            prompt_hash: &self.prompt_hash,
            output_hash: &self.output_hash,
            prompt_tokens: self.prompt_tokens,
            generated_tokens: self.generated_tokens,
            decode_steps: self.decode_steps,
            kv_bytes_moved: self.kv_bytes_moved,
            prefill_ms: self.prefill_ms,
            decode_ms: self.decode_ms,
            attested_started_at_unix_ms: self.attested_started_at_unix_ms,
            attested_finished_at_unix_ms: self.attested_finished_at_unix_ms,
            attested_elapsed_ms: self.attested_elapsed_ms,
            device_profile_id: &self.device_profile_id,
            device_vendor: &self.device_vendor,
            device_class: &self.device_class,
            accelerator_kind: &self.accelerator_kind,
            quantization: &self.quantization,
            runtime_name: &self.runtime_name,
            runtime_version: &self.runtime_version,
            batch_size: self.batch_size,
            tee_attestation: &self.tee_attestation,
        }
    }

    pub fn canonical_receipt_hash(&self) -> Result<String, LlmTokenMeterError> {
        let payload = serde_json::to_vec(&self.canonical_view())
            .map_err(|err| LlmTokenMeterError::Canonicalization(err.to_string()))?;
        let mut hasher = Sha256::new();
        hasher.update(payload);
        Ok(hex::encode(hasher.finalize()))
    }

    pub fn with_computed_receipt_hash(mut self) -> Result<Self, LlmTokenMeterError> {
        self.receipt_hash = self.canonical_receipt_hash()?;
        Ok(self)
    }

    pub fn validate_receipt_hash(&self) -> Result<(), LlmTokenMeterError> {
        require_non_empty(&self.receipt_hash, "receipt_hash")?;
        let expected = self.canonical_receipt_hash()?;
        let actual = normalize_hex(&self.receipt_hash).to_ascii_lowercase();
        if actual != expected {
            return Err(LlmTokenMeterError::ReceiptHashMismatch { expected, actual });
        }
        Ok(())
    }

    pub fn normalized_work_units(
        &self,
        coefficients: &LlmTokenMeterV1WorkUnitCoefficients,
    ) -> u128 {
        coefficients
            .prompt_tokens
            .saturating_mul(self.prompt_tokens as u128)
            .saturating_add(
                coefficients
                    .generated_tokens
                    .saturating_mul(self.generated_tokens as u128),
            )
            .saturating_add(
                coefficients
                    .decode_steps
                    .saturating_mul(self.decode_steps as u128),
            )
            .saturating_add(
                coefficients
                    .kv_bytes_moved
                    .saturating_mul(self.kv_bytes_moved as u128),
            )
    }

    pub fn validate(&self, jitter_budget_ms: u64) -> Result<(), LlmTokenMeterError> {
        if self.workload_class != LLM_INFERENCE_WORKLOAD_CLASS {
            return Err(LlmTokenMeterError::InvalidWorkloadClass {
                expected: LLM_INFERENCE_WORKLOAD_CLASS,
                actual: self.workload_class.clone(),
            });
        }
        if self.metering_schema != LLM_TOKEN_METER_V1_SCHEMA {
            return Err(LlmTokenMeterError::InvalidMeteringSchema {
                expected: LLM_TOKEN_METER_V1_SCHEMA,
                actual: self.metering_schema.clone(),
            });
        }

        require_non_empty(&self.worker_id, "worker_id")?;
        require_non_empty(&self.assignment_id, "assignment_id")?;
        require_non_empty(&self.model_family, "model_family")?;
        require_non_empty(&self.model_id, "model_id")?;
        require_non_empty(&self.tokenizer_id, "tokenizer_id")?;
        require_non_empty(&self.tokenizer_version, "tokenizer_version")?;
        require_non_empty(&self.prompt_hash, "prompt_hash")?;
        require_non_empty(&self.output_hash, "output_hash")?;
        require_non_empty(&self.device_profile_id, "device_profile_id")?;
        require_non_empty(&self.device_vendor, "device_vendor")?;
        require_non_empty(&self.device_class, "device_class")?;
        require_non_empty(&self.accelerator_kind, "accelerator_kind")?;
        require_non_empty(&self.quantization, "quantization")?;
        require_non_empty(&self.runtime_name, "runtime_name")?;
        require_non_empty(&self.runtime_version, "runtime_version")?;
        require_non_empty(&self.tee_attestation.attester, "tee_attestation.attester")?;
        require_non_empty(
            &self.tee_attestation.quote_hash,
            "tee_attestation.quote_hash",
        )?;
        require_non_empty(
            &self.tee_attestation.measurement,
            "tee_attestation.measurement",
        )?;

        if self.generated_tokens > 0 && self.decode_steps == 0 {
            return Err(LlmTokenMeterError::InvalidCounter(
                "generated_tokens > 0 requires decode_steps > 0",
            ));
        }

        if self.attested_finished_at_unix_ms < self.attested_started_at_unix_ms {
            return Err(LlmTokenMeterError::InvalidTiming(
                "attested_finished_at_unix_ms must be >= attested_started_at_unix_ms",
            ));
        }

        let elapsed = self
            .attested_finished_at_unix_ms
            .saturating_sub(self.attested_started_at_unix_ms);
        if self.attested_elapsed_ms != elapsed {
            return Err(LlmTokenMeterError::InvalidTiming(
                "attested_elapsed_ms must equal finished-started",
            ));
        }

        if self.prefill_ms.saturating_add(self.decode_ms)
            > self.attested_elapsed_ms.saturating_add(jitter_budget_ms)
        {
            return Err(LlmTokenMeterError::InvalidTiming(
                "prefill_ms + decode_ms exceeds attested_elapsed_ms + jitter_budget_ms",
            ));
        }

        self.validate_receipt_hash()
    }
}

pub fn parse_llm_token_meter_v1_receipt_json(
    payload: &[u8],
) -> Result<LlmTokenMeterV1Receipt, LlmTokenMeterError> {
    serde_json::from_slice(payload).map_err(|err| LlmTokenMeterError::Serde(err.to_string()))
}

pub fn parse_and_validate_llm_token_meter_v1_receipt_json(
    payload: &[u8],
    jitter_budget_ms: u64,
) -> Result<LlmTokenMeterV1Receipt, LlmTokenMeterError> {
    let receipt = parse_llm_token_meter_v1_receipt_json(payload)?;
    receipt.validate(jitter_budget_ms)?;
    Ok(receipt)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_receipt() -> LlmTokenMeterV1Receipt {
        LlmTokenMeterV1Receipt {
            workload_class: LLM_INFERENCE_WORKLOAD_CLASS.to_string(),
            metering_schema: LLM_TOKEN_METER_V1_SCHEMA.to_string(),
            task_id: 42,
            worker_id: "worker1".to_string(),
            assignment_id: "assign_42".to_string(),
            model_family: "llm".to_string(),
            model_id: "meta-llama-3.1-70b-instruct".to_string(),
            tokenizer_id: "llama3-tokenizer".to_string(),
            tokenizer_version: "1.0.0".to_string(),
            prompt_hash: "0x1111".to_string(),
            output_hash: "0x2222".to_string(),
            prompt_tokens: 100,
            generated_tokens: 25,
            decode_steps: 25,
            kv_bytes_moved: 4_096,
            prefill_ms: 30,
            decode_ms: 70,
            attested_started_at_unix_ms: 1_000,
            attested_finished_at_unix_ms: 1_100,
            attested_elapsed_ms: 100,
            device_profile_id: "h100-sxm-bf16-v1".to_string(),
            device_vendor: "nvidia".to_string(),
            device_class: "h100-sxm".to_string(),
            accelerator_kind: "gpu".to_string(),
            quantization: "bf16".to_string(),
            runtime_name: "vllm".to_string(),
            runtime_version: "0.8.4".to_string(),
            batch_size: 1,
            tee_attestation: TeeAttestationEnvelope {
                attester: "sgx-dcap".to_string(),
                quote_hash: "0x3333".to_string(),
                measurement: "0x4444".to_string(),
            },
            receipt_hash: String::new(),
        }
    }

    #[test]
    fn llm_token_meter_receipt_round_trips_hash_validation() {
        let receipt = sample_receipt().with_computed_receipt_hash().unwrap();
        receipt
            .validate(DEFAULT_LLM_TOKEN_METER_JITTER_BUDGET_MS)
            .unwrap();
    }

    #[test]
    fn llm_token_meter_receipt_accepts_completion_tokens_alias() {
        let receipt = sample_receipt().with_computed_receipt_hash().unwrap();
        let json = serde_json::json!({
            "workload_class": receipt.workload_class,
            "metering_schema": receipt.metering_schema,
            "task_id": receipt.task_id,
            "worker_id": receipt.worker_id,
            "assignment_id": receipt.assignment_id,
            "model_family": receipt.model_family,
            "model_id": receipt.model_id,
            "tokenizer_id": receipt.tokenizer_id,
            "tokenizer_version": receipt.tokenizer_version,
            "prompt_hash": receipt.prompt_hash,
            "output_hash": receipt.output_hash,
            "prompt_tokens": receipt.prompt_tokens,
            "completion_tokens": 25,
            "decode_steps": receipt.decode_steps,
            "kv_bytes_moved": receipt.kv_bytes_moved,
            "prefill_ms": receipt.prefill_ms,
            "decode_ms": receipt.decode_ms,
            "attested_started_at_unix_ms": receipt.attested_started_at_unix_ms,
            "attested_finished_at_unix_ms": receipt.attested_finished_at_unix_ms,
            "attested_elapsed_ms": receipt.attested_elapsed_ms,
            "device_profile_id": receipt.device_profile_id,
            "device_vendor": receipt.device_vendor,
            "device_class": receipt.device_class,
            "accelerator_kind": receipt.accelerator_kind,
            "quantization": receipt.quantization,
            "runtime_name": receipt.runtime_name,
            "runtime_version": receipt.runtime_version,
            "batch_size": receipt.batch_size,
            "tee_attestation": {
                "attester": receipt.tee_attestation.attester,
                "quote_hash": receipt.tee_attestation.quote_hash,
                "measurement": receipt.tee_attestation.measurement,
            },
            "receipt_hash": receipt.receipt_hash,
        });

        let parsed = parse_and_validate_llm_token_meter_v1_receipt_json(
            serde_json::to_vec(&json).unwrap().as_slice(),
            DEFAULT_LLM_TOKEN_METER_JITTER_BUDGET_MS,
        )
        .unwrap();
        assert_eq!(parsed.generated_tokens, 25);
    }

    #[test]
    fn llm_token_meter_receipt_computes_normalized_work_units_including_kv_bytes() {
        let receipt = sample_receipt().with_computed_receipt_hash().unwrap();
        let coefficients = LlmTokenMeterV1WorkUnitCoefficients {
            prompt_tokens: 2,
            generated_tokens: 3,
            decode_steps: 5,
            kv_bytes_moved: 7,
        };
        let expected = 2 * 100u128 + 3 * 25u128 + 5 * 25u128 + 7 * 4_096u128;
        assert_eq!(receipt.normalized_work_units(&coefficients), expected);
    }

    #[test]
    fn llm_token_meter_receipt_rejects_non_monotonic_timing() {
        let mut receipt = sample_receipt();
        receipt.attested_finished_at_unix_ms = 999;
        receipt = receipt.with_computed_receipt_hash().unwrap();
        let err = receipt
            .validate(DEFAULT_LLM_TOKEN_METER_JITTER_BUDGET_MS)
            .unwrap_err();
        assert!(matches!(err, LlmTokenMeterError::InvalidTiming(_)));
    }

    #[test]
    fn llm_token_meter_receipt_rejects_generated_tokens_without_decode_steps() {
        let mut receipt = sample_receipt();
        receipt.decode_steps = 0;
        receipt = receipt.with_computed_receipt_hash().unwrap();
        let err = receipt
            .validate(DEFAULT_LLM_TOKEN_METER_JITTER_BUDGET_MS)
            .unwrap_err();
        assert!(matches!(err, LlmTokenMeterError::InvalidCounter(_)));
    }

    #[test]
    fn llm_token_meter_receipt_accepts_uppercase_prefixed_receipt_hash() {
        let mut receipt = sample_receipt().with_computed_receipt_hash().unwrap();
        receipt.receipt_hash = format!("0X{}", receipt.receipt_hash.to_ascii_uppercase());
        receipt
            .validate(DEFAULT_LLM_TOKEN_METER_JITTER_BUDGET_MS)
            .expect("uppercase 0X-prefixed receipt hashes should canonicalize");
    }

    #[test]
    fn llm_token_meter_receipt_accepts_whitespace_padded_prefixed_receipt_hash() {
        let mut receipt = sample_receipt().with_computed_receipt_hash().unwrap();
        receipt.receipt_hash = format!("  0x{}\n", receipt.receipt_hash);
        receipt
            .validate(DEFAULT_LLM_TOKEN_METER_JITTER_BUDGET_MS)
            .expect("trimmed 0x-prefixed receipt hashes should canonicalize");
    }

    #[test]
    fn llm_token_meter_receipt_rejects_hash_mismatch() {
        let mut receipt = sample_receipt().with_computed_receipt_hash().unwrap();
        receipt.receipt_hash = "deadbeef".to_string();
        let err = receipt
            .validate(DEFAULT_LLM_TOKEN_METER_JITTER_BUDGET_MS)
            .unwrap_err();
        assert!(matches!(
            err,
            LlmTokenMeterError::ReceiptHashMismatch { .. }
        ));
    }
}
