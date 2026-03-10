use std::sync::OnceLock;

use ark_bn254::{Bn254, Fr};
use ark_ff::PrimeField;
use ark_groth16::{prepare_verifying_key, Groth16, PreparedVerifyingKey, Proof, VerifyingKey};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_serialize::CanonicalDeserialize;
use ark_snark::{CircuitSpecificSetupSNARK, SNARK};
use rand::{rngs::StdRng, SeedableRng};

use crate::verification::{ProofVerifier, VerificationResult};
use trnm_types::TaskObject;

use super::verify_bound_envelope;

const DEMO_BACKEND_ID: &str = "ark-groth16-bn254-demo";
const DEMO_BACKEND_FIELD: &str = "backend";
const DEMO_PROOF_FIELD: &str = "proof";

pub struct ZkVerifier;

#[derive(Clone)]
struct DemoSquareCircuit {
    witness: Option<u64>,
    public_output: u64,
}

impl ConstraintSynthesizer<Fr> for DemoSquareCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let witness = cs.new_witness_variable(|| {
            self.witness
                .map(Fr::from)
                .ok_or(SynthesisError::AssignmentMissing)
        })?;
        let public_output = cs.new_input_variable(|| Ok(Fr::from(self.public_output)))?;
        cs.enforce_constraint(
            ark_relations::lc!() + witness,
            ark_relations::lc!() + witness,
            ark_relations::lc!() + public_output,
        )?;
        Ok(())
    }
}

struct DemoBackendParams {
    vk: PreparedVerifyingKey<Bn254>,
}

fn demo_backend_params() -> &'static DemoBackendParams {
    static PARAMS: OnceLock<DemoBackendParams> = OnceLock::new();
    PARAMS.get_or_init(|| {
        let circuit = DemoSquareCircuit {
            witness: None,
            public_output: 0,
        };
        let mut rng = StdRng::seed_from_u64(0x54524e4d5f5a4b50);
        let (_pk, vk) = Groth16::<Bn254>::setup(circuit, &mut rng)
            .expect("deterministic demo Groth16 setup must succeed");
        DemoBackendParams {
            vk: prepare_verifying_key(&vk),
        }
    })
}

fn public_output_from_result_hash(task: &TaskObject) -> Option<u64> {
    let result_hash = task.result_hash?;
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&result_hash[..8]);
    Some(u64::from_be_bytes(bytes))
}

fn is_identifier_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

fn is_value_terminator(b: u8) -> bool {
    b.is_ascii_whitespace()
        || matches!(b, b',' | b';' | b'}' | b']' | b')' | b'\'' | b'"' | b'\n' | b'\r' | b'\t')
}

fn find_token_field(body: &str, field: &str) -> Option<String> {
    let lower = body.to_ascii_lowercase();
    let field_lower = field.to_ascii_lowercase();
    let body_bytes = body.as_bytes();
    let field_bytes = field.as_bytes();
    let mut cursor = 0usize;

    while let Some(found) = lower[cursor..].find(&field_lower) {
        let idx = cursor + found;
        let before_ok = idx == 0 || !is_identifier_byte(body_bytes[idx - 1]);
        let after = idx + field_bytes.len();
        let after_ok = after >= body_bytes.len() || !is_identifier_byte(body_bytes[after]);
        if !before_ok || !after_ok {
            cursor = idx + 1;
            continue;
        }

        let mut i = after;
        while i < body_bytes.len() && body_bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        if i < body_bytes.len() && (body_bytes[i] == b':' || body_bytes[i] == b'=') {
            i += 1;
        } else {
            cursor = idx + 1;
            continue;
        }
        while i < body_bytes.len() && body_bytes[i].is_ascii_whitespace() {
            i += 1;
        }

        let quote = if i < body_bytes.len() && (body_bytes[i] == b'"' || body_bytes[i] == b'\'') {
            let q = body_bytes[i];
            i += 1;
            Some(q)
        } else {
            None
        };

        let start = i;
        while i < body_bytes.len() {
            if let Some(q) = quote {
                if body_bytes[i] == q {
                    break;
                }
            } else if is_value_terminator(body_bytes[i]) {
                break;
            }
            i += 1;
        }

        if i == start {
            cursor = idx + 1;
            continue;
        }

        if let Some(q) = quote {
            if i >= body_bytes.len() || body_bytes[i] != q {
                cursor = idx + 1;
                continue;
            }
            let token = &body[start..i];
            return Some(token.to_string());
        }

        return Some(body[start..i].to_string());
    }

    None
}

fn decode_proof_hex(hex_text: &str) -> Result<Proof<Bn254>, String> {
    let proof_bytes = hex::decode(hex_text)
        .map_err(|_| "Invalid ZK proof envelope: malformed proof encoding".to_string())?;
    Proof::<Bn254>::deserialize_compressed(proof_bytes.as_slice())
        .map_err(|_| "Invalid ZK proof envelope: malformed proof encoding".to_string())
}

fn verify_demo_backend(task: &TaskObject, proof_hex: &str) -> VerificationResult {
    let Some(public_output) = public_output_from_result_hash(task) else {
        return VerificationResult::Invalid(
            "Invalid ZK proof envelope: missing task result_hash binding context".to_string(),
        );
    };

    let proof = match decode_proof_hex(proof_hex) {
        Ok(proof) => proof,
        Err(err) => return VerificationResult::Invalid(err),
    };

    let public_inputs = [Fr::from(public_output)];
    match Groth16::<Bn254>::verify_with_processed_vk(
        &demo_backend_params().vk,
        &public_inputs,
        &proof,
    ) {
        Ok(true) => VerificationResult::Valid,
        Ok(false) => VerificationResult::Invalid(
            "ZK proof cryptographic verification failed".to_string(),
        ),
        Err(err) => VerificationResult::Indeterminate(format!(
            "ZK proof backend unavailable: {DEMO_BACKEND_ID} verify error: {err}"
        )),
    }
}

impl ProofVerifier for ZkVerifier {
    fn proof_type(&self) -> &str {
        "zk"
    }

    fn verify_proof(&self, task: &TaskObject, proof_data: &[u8]) -> VerificationResult {
        let verification = verify_bound_envelope(task, proof_data, b"ZK:", "ZK proof");
        if matches!(verification, VerificationResult::Valid) && task.result_hash.is_none() {
            return VerificationResult::Invalid(
                "Invalid ZK proof envelope: missing task result_hash binding context".to_string(),
            );
        }

        match verification {
            VerificationResult::Valid => {
                let payload = String::from_utf8_lossy(proof_data);
                let body = payload
                    .split_once(':')
                    .map(|(_, body)| body)
                    .unwrap_or_default();
                let backend = find_token_field(body, DEMO_BACKEND_FIELD);
                let proof_hex = find_token_field(body, DEMO_PROOF_FIELD);

                match (backend.as_deref(), proof_hex.as_deref()) {
                    (Some(DEMO_BACKEND_ID), Some(proof_hex)) => verify_demo_backend(task, proof_hex),
                    (Some(DEMO_BACKEND_ID), None) => VerificationResult::Invalid(
                        "Invalid ZK proof envelope: missing proof binding".to_string(),
                    ),
                    (Some(other), _) => VerificationResult::Indeterminate(format!(
                        "ZK proof backend unavailable: unsupported backend: {other}"
                    )),
                    (None, _) => VerificationResult::Indeterminate(
                        "ZK proof cryptographic verification backend not configured".to_string(),
                    ),
                }
            }
            other => other,
        }
    }
}

#[cfg(test)]
pub(crate) fn demo_backend_proof_hex_for_public_output(public_output: u64) -> String {
    let circuit = DemoSquareCircuit {
        witness: Some(integer_square_root(public_output).expect("public output must be square")),
        public_output,
    };
    let setup_circuit = DemoSquareCircuit {
        witness: None,
        public_output: 0,
    };
    let mut rng = StdRng::seed_from_u64(0x54524e4d5f5a4b50);
    let (pk, _vk): (_, VerifyingKey<Bn254>) =
        Groth16::<Bn254>::setup(setup_circuit, &mut rng).expect("setup must succeed");
    let proof = Groth16::<Bn254>::prove(&pk, circuit, &mut rng).expect("proof must succeed");
    let mut bytes = Vec::new();
    proof
        .serialize_compressed(&mut bytes)
        .expect("proof serialization must succeed");
    hex::encode(bytes)
}

#[cfg(test)]
fn integer_square_root(value: u64) -> Option<u64> {
    let root = (value as f64).sqrt() as u64;
    [root.saturating_sub(1), root, root.saturating_add(1)]
        .into_iter()
        .find(|candidate| candidate.saturating_mul(*candidate) == value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use trnm_types::{ProofType, TaskObject, TaskStatus};

    fn mock_task() -> TaskObject {
        let public_output = 81u64;
        let mut result_hash = [0u8; 32];
        result_hash[..8].copy_from_slice(&public_output.to_be_bytes());
        TaskObject {
            task_id: 99,
            creator: "alice".into(),
            bounty: 1,
            status: TaskStatus::Committed,
            proof_type: ProofType::Zk,
            metadata: None,
            worker: Some("worker-zk".into()),
            committed_hash: None,
            result_hash: Some(result_hash),
            reveal_salt: None,
            committed_at_height: None,
            reveal_deadline_height: None,
            challenge_deadline_height: None,
            challenge_window_blocks_snapshot: None,
            challenged_at_height: None,
            resolve_deadline_height: None,
            challenge_bond: None,
            challenger: None,
            challenge_bond_forfeited: None,
            version: 1,
        }
    }

    #[test]
    fn zk_verifier_requires_cryptographic_backend_after_bound_envelope_validation() {
        let verifier = ZkVerifier;
        let task = mock_task();

        assert!(matches!(
            verifier.verify_proof(
                &task,
                b"ZK:{\"task_id\":99,\"worker\":\"worker-zk\",\"proof_type\":\"zk\",\"result_hash\":\"0000000000000051000000000000000000000000000000000000000000000000\",\"proof\":\"...\"}"
            ),
            VerificationResult::Indeterminate(msg)
                if msg.contains("cryptographic verification backend not configured")
        ));
    }

    #[test]
    fn zk_verifier_accepts_valid_real_groth16_proof() {
        let verifier = ZkVerifier;
        let task = mock_task();
        let public_output = public_output_from_result_hash(&task).unwrap();
        let proof_hex = demo_backend_proof_hex_for_public_output(public_output);
        let proof = format!(
            "ZK:task_id=99,worker=worker-zk,proof_type=zk,result_hash=0000000000000051000000000000000000000000000000000000000000000000,backend={DEMO_BACKEND_ID},proof={proof_hex}"
        );

        assert_eq!(
            verifier.verify_proof(&task, proof.as_bytes()),
            VerificationResult::Valid
        );
    }

    #[test]
    fn zk_verifier_rejects_invalid_real_groth16_proof() {
        let verifier = ZkVerifier;
        let task = mock_task();
        let public_output = public_output_from_result_hash(&task).unwrap();
        let mut proof_hex = demo_backend_proof_hex_for_public_output(public_output);
        proof_hex.replace_range(0..2, if &proof_hex[0..2] == "00" { "11" } else { "00" });
        let proof = format!(
            "ZK:task_id=99,worker=worker-zk,proof_type=zk,result_hash=0000000000000051000000000000000000000000000000000000000000000000,backend={DEMO_BACKEND_ID},proof={proof_hex}"
        );

        assert!(matches!(
            verifier.verify_proof(&task, proof.as_bytes()),
            VerificationResult::Invalid(msg) if msg.contains("malformed proof encoding") || msg.contains("cryptographic verification failed")
        ));
    }

    #[test]
    fn zk_verifier_distinguishes_unsupported_backend_from_malformed_envelope() {
        let verifier = ZkVerifier;
        let task = mock_task();

        assert!(matches!(
            verifier.verify_proof(
                &task,
                b"ZK:task_id=99,worker=worker-zk,proof_type=zk,result_hash=0000000000000051000000000000000000000000000000000000000000000000,backend=unknown-demo,proof=abcd"
            ),
            VerificationResult::Indeterminate(msg) if msg.contains("backend unavailable")
        ));

        assert!(matches!(
            verifier.verify_proof(
                &task,
                b"ZK:task_id=99,worker=worker-zk,proof_type=zk,result_hash=0000000000000051000000000000000000000000000000000000000000000000,backend=ark-groth16-bn254-demo"
            ),
            VerificationResult::Invalid(msg) if msg.contains("missing proof binding")
        ));
    }
}
