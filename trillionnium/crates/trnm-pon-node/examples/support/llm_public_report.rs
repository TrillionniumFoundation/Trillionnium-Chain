//! Public bridge receipts are an explicit scalar/digest allowlist, never raw metadata.
use serde::{Deserialize, Serialize};
use serde_json::Value;
use trnm_pon_node::{digest, Result};
use trnm_protocol::pon_wire::Hash;

pub fn contract_id(value: &Value) -> Result<Hash> {
    let text = value.as_str().ok_or("CONTRACT_ID")?;
    digest(text).map_err(|_| "CONTRACT_ID".into())
}

pub fn bound_contract(roster: &Value, metadata: &Value) -> Result<Hash> {
    let expected = contract_id(roster)?;
    if contract_id(metadata)? != expected {
        return Err("CANDIDATE_ASSESSMENT_BINDING".into());
    }
    Ok(expected)
}

// Unknown members are deliberately omitted at every level. Known members have
// concrete types, so an object smuggled into a public scalar fails closed.
// These are the existing v1 receipt fields, not a new signed/stored schema.
#[derive(Deserialize, Serialize)]
struct Binding {
    schema: String,
    network: String,
    parameters: String,
    genesis: String,
    family: String,
    plan: String,
    artifact: String,
    artifact_bytes: u64,
    control_plan: String,
    assessment: String,
    original_material_ports_contract: String,
    scope: String,
    score: u64,
    model_value_accepted: bool,
    independent_accepted: bool,
    public_network_ready: bool,
}

#[derive(Deserialize, Serialize)]
struct SourceFile {
    path: String,
    bytes: u64,
    digest: String,
}

#[derive(Deserialize, Serialize)]
struct SourceReceipt {
    schema: String,
    builder_commit_claim: Option<String>,
    builder_tree_claim: Option<String>,
    inventory: Vec<SourceFile>,
    inventory_digest: String,
    binary_digest: String,
    binary_bytes: u64,
    scope: String,
}

#[derive(Deserialize, Serialize)]
struct ClosedResult {
    schema: String,
    candidate: String,
    round: String,
    closed_height: u64,
    status: String,
    score: u64,
    records_digest: String,
    missing_reveal_count: u64,
    conflict_count_before_close: u64,
    independent_governance_accepted: bool,
    objective_model_quality: bool,
}

#[derive(Deserialize, Serialize)]
struct StateMetrics {
    network: String,
    parameters: String,
    genesis: String,
    tip: String,
    height: u64,
    chainwork_hex: String,
    state_root: String,
    generation: u64,
    state_keys: u64,
    stored_blocks: u64,
    events: u64,
    authenticated_sessions: u64,
    authenticated_pending: u64,
    authenticated_audit_rows: u64,
    authenticated_outbox_sessions: u64,
    authenticated_outbox_pending: u64,
    production_activation: bool,
}

#[derive(Deserialize, Serialize)]
struct SettlementRefusal {
    tag: u8,
    error: String,
    durable_state_unchanged: bool,
}

#[derive(Deserialize, Serialize)]
struct Summary {
    schema: String,
    source: SourceReceipt,
    binding: Binding,
    candidate: String,
    closed_result: ClosedResult,
    state: StateMetrics,
    blocks: u64,
    mining_attempts: u64,
    actual_settlement_refusals: Vec<SettlementRefusal>,
    clock_scope: String,
    score: u64,
    adopted: bool,
    model_contribution_reward: u64,
    mining_subsidy_separate: bool,
    native_ml_execution_claim: bool,
    public_network_ready: bool,
    independent_accepted: bool,
    work_profile_qualified: bool,
}

fn canonical(value: impl Serialize) -> Result<Vec<u8>> {
    // Retain the existing sorted-object encoding, rather than declaration order.
    let value = serde_json::to_value(value).map_err(|_| "PUBLIC_REPORT_SHAPE")?;
    serde_json::to_vec(&value).map_err(|_| "PUBLIC_REPORT_SHAPE".into())
}

pub fn binding_bytes(value: &Value) -> Result<Vec<u8>> {
    let binding: Binding =
        serde_json::from_value(value.clone()).map_err(|_| "PUBLIC_REPORT_SHAPE")?;
    contract_id(&Value::String(
        binding.original_material_ports_contract.clone(),
    ))?;
    canonical(binding)
}

pub fn summary_bytes(value: Value) -> Result<Vec<u8>> {
    let summary: Summary = serde_json::from_value(value).map_err(|_| "PUBLIC_REPORT_SHAPE")?;
    contract_id(&Value::String(
        summary.binding.original_material_ports_contract.clone(),
    ))?;
    canonical(summary)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const CANARY: &str = "SYNTHETIC_PRIVATE_FIELD_NOT_A_SECRET";

    fn fixture() -> Value {
        // Serialization counterexample only; not a native execution receipt.
        let id = "ab".repeat(32);
        json!({
            "schema":"native-llm-zero-gain-round-v1",
            "source":{"schema":"native-llm-bridge-source-v1","builder_commit_claim":null,"builder_tree_claim":null,
                "inventory":[{"path":"synthetic.rs","bytes":1,"digest":id}],
                "inventory_digest":id,"binary_digest":id,"binary_bytes":1,"scope":"fixture"},
            "binding":{"schema":"native-llm-external-pilot-binding-v1","network":id,"parameters":id,"genesis":id,
                "family":id,"plan":id,"artifact":id,"artifact_bytes":1,"control_plan":id,"assessment":id,
                "original_material_ports_contract":id,"scope":"fixture","score":0,"model_value_accepted":false,
                "independent_accepted":false,"public_network_ready":false},
            "candidate":id,
            "closed_result":{"schema":"pon-native-closed-evaluation-v2","candidate":id,"round":id,"closed_height":48,
                "status":"complete-scored","score":0,"records_digest":id,"missing_reveal_count":0,
                "conflict_count_before_close":0,"independent_governance_accepted":false,"objective_model_quality":false},
            "state":{"network":id,"parameters":id,"genesis":id,"tip":id,"height":64,"chainwork_hex":"00".repeat(64),
                "state_root":id,"generation":64,"state_keys":37,"stored_blocks":65,"events":64,
                "authenticated_sessions":0,"authenticated_pending":0,"authenticated_audit_rows":0,
                "authenticated_outbox_sessions":0,"authenticated_outbox_pending":0,"production_activation":false},
            "blocks":64,"mining_attempts":128,
            "actual_settlement_refusals":[{"tag":8,"error":"PUBLIC_EVAL_ADOPTION","durable_state_unchanged":true}],
            "clock_scope":"fixture","score":0,"adopted":false,"model_contribution_reward":0,
            "mining_subsidy_separate":true,"native_ml_execution_claim":false,"public_network_ready":false,
            "independent_accepted":false,"work_profile_qualified":false
        })
    }

    #[test]
    fn valid_public_fields_and_canonical_bytes_are_preserved() {
        let value = fixture();
        assert_eq!(
            summary_bytes(value.clone()).unwrap(),
            serde_json::to_vec(&value).unwrap()
        );
        assert_eq!(
            binding_bytes(&value["binding"]).unwrap(),
            serde_json::to_vec(&value["binding"]).unwrap()
        );
        let contract = json!("ab".repeat(32));
        assert_eq!(bound_contract(&contract, &contract).unwrap(), [0xab; 32]);
    }

    #[test]
    fn unknown_sensitive_members_are_omitted_at_every_public_level() {
        let expected = fixture();
        let mut changed = expected.clone();
        for pointer in [
            "",
            "/binding",
            "/source",
            "/source/inventory/0",
            "/closed_result",
            "/state",
            "/actual_settlement_refusals/0",
        ] {
            changed
                .pointer_mut(pointer)
                .unwrap()
                .as_object_mut()
                .unwrap()
                .insert("private_access_token".into(), json!({"secret":CANARY}));
        }
        let bytes = summary_bytes(changed.clone()).unwrap();
        assert_eq!(bytes, serde_json::to_vec(&expected).unwrap());
        assert!(!String::from_utf8(bytes).unwrap().contains(CANARY));
        assert_eq!(
            binding_bytes(&changed["binding"]).unwrap(),
            serde_json::to_vec(&expected["binding"]).unwrap()
        );
    }

    #[test]
    fn non_scalar_or_invalid_contract_outputs_fail_without_echoing_the_value() {
        for pointer in [
            "/state/height",
            "/binding/score",
            "/closed_result/status",
            "/source/inventory/0/path",
            "/actual_settlement_refusals/0/error",
        ] {
            let mut changed = fixture();
            *changed.pointer_mut(pointer).unwrap() = json!({"private_access_token":CANARY});
            let error = summary_bytes(changed).unwrap_err().to_string();
            assert_eq!(error, "PUBLIC_REPORT_SHAPE");
            assert!(!error.contains(CANARY));
        }
        let mut changed = fixture();
        changed["binding"]["original_material_ports_contract"] = json!(CANARY);
        assert_eq!(
            summary_bytes(changed.clone()).unwrap_err().to_string(),
            "CONTRACT_ID"
        );
        assert_eq!(
            binding_bytes(&changed["binding"]).unwrap_err().to_string(),
            "CONTRACT_ID"
        );
    }
}
