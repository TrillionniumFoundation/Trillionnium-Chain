//! SP27-03 research bridge to the existing native Hepta admission verifier.
//!
//! This executable does not implement a current-authority owner, dispatch an
//! effect, supply FinalUse, or run a native Node. Current expectations must be
//! supplied independently by the research consumer's controlled transaction
//! domain. Public deterministic fixture keys are deliberately not production
//! credentials. Recovery/content generation is not authorization incarnation.

use ed25519_dalek::SigningKey;
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::io::{self, Read};
use trnm_research_protocol::{
    AuthorityIdentityV1, AuthoritySetV1, HeptaArtifactAdmissionV1, SignedHeptaAdmissionV1,
    MAX_HANDOFF_ENVELOPE_BYTES,
};

const REQUEST_SCHEMA: &str = "sp27-03.chain-adapter-request.v1";
const RECEIPT_SCHEMA: &str = "sp27-03.chain-adapter-receipt.v1";
const MAX_REQUEST_BYTES: u64 = 65_536;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthorityInput {
    signer_did: String,
    public_key_hex: String,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "action", deny_unknown_fields)]
enum Request {
    #[serde(rename = "fixture_sign")]
    FixtureSign {
        schema: String,
        chain_id: String,
        signer_did: String,
        fixture_key_label: String,
        admission: HeptaArtifactAdmissionV1,
    },
    #[serde(rename = "verify")]
    Verify {
        schema: String,
        envelope_hex: String,
        expected_chain_id: String,
        expected_admission: HeptaArtifactAdmissionV1,
        authorities: Vec<AuthorityInput>,
        now_unix_s: u64,
    },
}

fn sha256(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn base_receipt(action: &str) -> Value {
    json!({
        "schema": RECEIPT_SCHEMA,
        "action": action,
        "layer": "native_chain_library_boundary",
        "authority_source": "controlled_external_snapshot",
        "signature_profile": "ed25519-v1-controlled-fixture",
        "grants_execution_authority": false,
        "pq_qualified": false,
        "native_node_e2e_executed": false,
        "effect_executed": false,
        "content_generation_is_authorization_incarnation": false,
        "native_canonical_decode_invoked": false,
        "native_context_verifier_invoked": false,
        "error_code": null,
        "error_detail": null
    })
}

fn input_error(detail: impl Into<String>) -> Value {
    let mut receipt = base_receipt("input");
    receipt["accepted"] = json!(false);
    receipt["verdict"] = json!("INPUT_ERROR");
    receipt["error_code"] = json!("ADAPTER_INPUT_ERROR");
    receipt["error_detail"] = json!(detail.into());
    receipt
}

fn check_schema(schema: &str) -> Result<(), String> {
    if schema == REQUEST_SCHEMA {
        Ok(())
    } else {
        Err("request schema must exactly match sp27-03.chain-adapter-request.v1".into())
    }
}

fn strict_admission_fields(value: &Value) -> Result<(), String> {
    let field = match value.get("action").and_then(Value::as_str) {
        Some("fixture_sign") => "admission",
        Some("verify") => "expected_admission",
        _ => return Err("unsupported action".into()),
    };
    let admission = value
        .get(field)
        .and_then(Value::as_object)
        .ok_or_else(|| format!("{field} must be an object"))?;
    let expected = BTreeSet::from([
        "operation_id",
        "artifact_digest",
        "owner_admission_digest",
        "family_digest",
        "source_digest_profile_digest",
        "parent_artifact_digest",
        "generation",
        "withdrawal_scope_digest",
        "withdrawal_head_digest",
        "registry_head_digest",
        "evaluation_plan_digest",
        "task_scope_digest",
        "export_permission_digest",
        "payload_digest",
        "payload_len",
        "created_at_unix_s",
        "expires_at_unix_s",
    ]);
    let actual: BTreeSet<&str> = admission.keys().map(String::as_str).collect();
    if actual != expected {
        return Err(format!(
            "{field} must contain exactly the 17 native admission fields"
        ));
    }
    Ok(())
}

fn handle(request: Request) -> Result<Value, String> {
    match request {
        Request::FixtureSign {
            schema,
            chain_id,
            signer_did,
            fixture_key_label,
            admission,
        } => {
            check_schema(&schema)?;
            // These public fixed seeds are test material only. This interface
            // never accepts or loads a real signing credential.
            let seed = match fixture_key_label.as_str() {
                "owner-a" => [0x31; 32],
                "owner-b" => [0x52; 32],
                _ => return Err("fixture_key_label must be owner-a or owner-b".into()),
            };
            let signer = SigningKey::from_bytes(&seed);
            let signed =
                SignedHeptaAdmissionV1::sign(chain_id, signer_did.clone(), admission, &signer)
                    .map_err(|error| format!("native fixture signing refused: {error:?}"))?;
            let wire = signed.canonical_bytes();
            let mut receipt = base_receipt("fixture_sign");
            receipt["accepted"] = json!(true);
            receipt["verdict"] = json!("SIGNED_FIXTURE");
            receipt["native_source_api"] = json!("SignedHeptaAdmissionV1::sign");
            receipt["fixture_key_label"] = json!(fixture_key_label);
            receipt["public_test_key"] = json!(true);
            receipt["public_key_hex"] = json!(hex::encode(signed.public_key));
            receipt["signer_did"] = json!(signer_did);
            receipt["envelope_hex"] = json!(hex::encode(&wire));
            receipt["envelope_sha256"] = json!(sha256(&wire));
            receipt["admission_digest_hex"] =
                json!(hex::encode(signed.admission.admission_digest()));
            Ok(receipt)
        }
        Request::Verify {
            schema,
            envelope_hex,
            expected_chain_id,
            expected_admission,
            authorities,
            now_unix_s,
        } => {
            check_schema(&schema)?;
            if envelope_hex.len() > MAX_HANDOFF_ENVELOPE_BYTES * 2 {
                return Err("envelope hexadecimal exceeds original native byte bound".into());
            }
            if authorities.len() > 64 {
                return Err("controlled authority snapshot exceeds 64 identities".into());
            }
            let wire = hex::decode(envelope_hex)
                .map_err(|_| "envelope_hex must encode exact bytes".to_string())?;
            let mut pins = Vec::with_capacity(authorities.len());
            for pin in authorities {
                let key: [u8; 32] = hex::decode(pin.public_key_hex)
                    .map_err(|_| "authority public_key_hex is not hexadecimal".to_string())?
                    .try_into()
                    .map_err(|_| "authority public key must be 32 bytes".to_string())?;
                pins.push(
                    AuthorityIdentityV1::new(pin.signer_did, key)
                        .map_err(|error| format!("invalid current authority: {error:?}"))?,
                );
            }
            let authorities = AuthoritySetV1::new(Vec::new(), pins)
                .map_err(|error| format!("invalid current authority set: {error:?}"))?;
            let mut receipt = base_receipt("verify");
            receipt["native_source_api"] = json!(
                "SignedHeptaAdmissionV1::from_canonical_bytes + SignedHeptaAdmissionV1::verify_for_context"
            );
            receipt["native_canonical_decode_invoked"] = json!(true);
            receipt["envelope_sha256"] = json!(sha256(&wire));
            receipt["expected_admission_digest_hex"] =
                json!(hex::encode(expected_admission.admission_digest()));
            receipt["expected_chain_id"] = json!(expected_chain_id);
            receipt["now_unix_s_argument"] = json!(now_unix_s);
            let signed = match SignedHeptaAdmissionV1::from_canonical_bytes(&wire) {
                Ok(signed) => signed,
                Err(error) => {
                    receipt["accepted"] = json!(false);
                    receipt["verdict"] = json!("REJECTED");
                    receipt["error_code"] = json!(format!("{error:?}"));
                    receipt["error_detail"] = json!(error.to_string());
                    return Ok(receipt);
                }
            };
            receipt["admission_digest_hex"] =
                json!(hex::encode(signed.admission.admission_digest()));
            receipt["native_context_verifier_invoked"] = json!(true);
            match signed.verify_for_context(
                &authorities,
                &expected_chain_id,
                &expected_admission,
                now_unix_s,
            ) {
                Ok(()) => {
                    receipt["accepted"] = json!(true);
                    receipt["verdict"] = json!("ACCEPTED");
                }
                Err(error) => {
                    receipt["accepted"] = json!(false);
                    receipt["verdict"] = json!("REJECTED");
                    receipt["error_code"] = json!(format!("{error:?}"));
                    receipt["error_detail"] = json!(error.to_string());
                }
            }
            Ok(receipt)
        }
    }
}

fn run(bytes: &[u8]) -> Result<Value, String> {
    let value: Value =
        serde_json::from_slice(bytes).map_err(|error| format!("invalid JSON request: {error}"))?;
    strict_admission_fields(&value)?;
    let request =
        serde_json::from_slice(bytes).map_err(|error| format!("invalid typed request: {error}"))?;
    handle(request)
}

fn main() {
    let mut bytes = Vec::new();
    let input = io::stdin()
        .lock()
        .take(MAX_REQUEST_BYTES + 1)
        .read_to_end(&mut bytes);
    let result = match input {
        Err(error) => Err(format!("cannot read request: {error}")),
        Ok(_) if bytes.len() as u64 > MAX_REQUEST_BYTES => {
            Err("request exceeds 65536 bytes".into())
        }
        Ok(_) => run(&bytes),
    };
    let (mut receipt, exit_code) = match result {
        Ok(receipt) => (receipt, 0),
        Err(detail) => (input_error(detail), 2),
    };
    receipt["input_sha256"] = json!(sha256(&bytes));
    println!("{receipt}");
    std::process::exit(exit_code);
}
