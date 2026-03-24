use super::*;
use crate::{LlmTokenMeterV1Receipt, LLM_INFERENCE_WORKLOAD_CLASS, LLM_TOKEN_METER_V1_SCHEMA};
fn seeded_state() -> StateStore {
    let mut st = StateStore::new();
    st.set_balance("worker1", 1_000);
    st.set_balance("worker2", 1_000);
    st
}
fn set_resolve_authority(st: &mut StateStore, authority: &str) {
    // Some fail-closed tests intentionally attempt malformed/reserved authorities.
    // Keep the fixture helper tolerant so those tests can still exercise resolve
    // authorization behavior even when governance-layer validation rejects writes.
    let _ =
        st.set_gov_param_bootstrap_unchecked(9_500, "resolve_authority".into(), authority.into());
}
fn sample_llm_token_meter_receipt_json(task_id: u64, worker: &str, result_hash: Hash32) -> Vec<u8> {
    let receipt = LlmTokenMeterV1Receipt {
        workload_class: LLM_INFERENCE_WORKLOAD_CLASS.to_string(),
        metering_schema: LLM_TOKEN_METER_V1_SCHEMA.to_string(),
        task_id,
        worker_id: worker.to_string(),
        assignment_id: format!("assign-{}", task_id),
        model_family: "llm".to_string(),
        model_id: "meta-llama-3.1-70b-instruct".to_string(),
        tokenizer_id: "llama3-tokenizer".to_string(),
        tokenizer_version: "1.0.0".to_string(),
        prompt_hash: "0x1111".to_string(),
        output_hash: hex::encode(result_hash),
        prompt_tokens: 128,
        generated_tokens: 32,
        decode_steps: 32,
        kv_bytes_moved: 4096,
        prefill_ms: 20,
        decode_ms: 80,
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
        tee_attestation: crate::metering::TeeAttestationEnvelope {
            attester: "sgx-dcap".to_string(),
            quote_hash: "0xaaaa".to_string(),
            measurement: "0xbbbb".to_string(),
        },
        receipt_hash: String::new(),
    }
    .with_computed_receipt_hash()
    .unwrap();
    serde_json::to_vec(&receipt).unwrap()
}
fn dirty_actor_ids() -> Vec<&'static str> {
    vec![
        "worker 1",
        "worker\t1",
        "worker\n1",
        "worker\u{200b}1",
        "worker\u{2060}1",
        "wørker1",
        "worker,1",
        "worker，1",
        "worker;1",
        "worker；1",
        "worker|1",
        "worker｜1",
        "worker/1",
        "worker／1",
        "worker:1",
        "worker：1",
    ]
}

#[path = "tests/challenge_timeout.rs"]
mod challenge_timeout;
#[path = "tests/create_accept.rs"]
mod create_accept;
#[path = "tests/metering_settlement/mod.rs"]
mod metering_settlement;
#[path = "tests/resolve_auth.rs"]
mod resolve_auth;
#[path = "tests/reveal_commit.rs"]
mod reveal_commit;
