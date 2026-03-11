use std::sync::Arc;
#[cfg(feature = "real-zk-backend")]
use std::sync::OnceLock;

#[cfg(feature = "real-zk-backend")]
use ark_bn254::{Bn254, Fr};
#[cfg(all(test, feature = "real-zk-backend"))]
use ark_groth16::VerifyingKey;
#[cfg(feature = "real-zk-backend")]
use ark_groth16::{prepare_verifying_key, Groth16, PreparedVerifyingKey, Proof};
#[cfg(feature = "real-zk-backend")]
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
#[cfg(feature = "real-zk-backend")]
use ark_serialize::CanonicalDeserialize;
#[cfg(all(test, feature = "real-zk-backend"))]
use ark_serialize::CanonicalSerialize;
#[cfg(feature = "real-zk-backend")]
use ark_snark::{CircuitSpecificSetupSNARK, SNARK};
#[cfg(feature = "real-zk-backend")]
use rand::{rngs::StdRng, SeedableRng};

use crate::verification::backend::{
    parse_zk_proof_payload, BackendExecutionError, BackendVerificationRequest,
    ParsedZkProofPayload, VerificationBackendConfig, VerificationBackendError,
    VerificationBackendFamily, VerificationErrorClass, ZkBackendKind, ZkBackendRegistry,
};
use crate::verification::{ProofVerifier, VerificationResult};
use trnm_types::TaskObject;

use super::verify_bound_envelope;

const DEMO_BACKEND_ID: &str = "ark-groth16-bn254-demo";
const DEMO_BACKEND_FIELD: &str = "backend";
const DEMO_PROOF_FIELD: &str = "proof";

fn expected_zk_system_for_backend(backend_id: &str) -> Option<&'static str> {
    let normalized = backend_id.trim().to_ascii_lowercase();
    if normalized.is_empty() {
        return None;
    }
    if normalized == DEMO_BACKEND_ID || normalized.starts_with("mock-zk") {
        return Some("groth16");
    }
    if normalized.starts_with("mock-plonk") {
        return Some("plonk");
    }
    None
}

fn resolve_vk_ref(
    vk_ref: &str,
    backend_id: Option<&str>,
    zk_system: Option<&str>,
) -> Result<(), BackendExecutionError> {
    let vk_ref = vk_ref.trim();
    let vk_ref_lower = vk_ref.to_ascii_lowercase();
    let zk_system = zk_system.map(str::trim).filter(|raw| !raw.is_empty());
    let backend_id = backend_id.map(str::trim).filter(|raw| !raw.is_empty());

    let is_mock_groth16 = vk_ref_lower.starts_with("vk://trnm/dev/mock-groth16/");
    let is_demo_groth16 = vk_ref_lower.starts_with("vk://trnm/dev/ark-groth16-bn254-demo/");
    let is_mock_plonk = vk_ref_lower.starts_with("vk://trnm/dev/mock-plonk/");

    if is_mock_groth16 || is_demo_groth16 {
        if let Some(system) = zk_system {
            if !system.eq_ignore_ascii_case("groth16") {
                return Err(BackendExecutionError::MalformedProof {
                    backend: format!("zk:{}", backend_id.unwrap_or("payload")),
                    reason: format!(
                        "invalid zk payload: vk_ref '{vk_ref}' requires zk_system 'groth16', got '{system}'"
                    ),
                });
            }
        }
        if is_demo_groth16 {
            if let Some(backend_id) = backend_id {
                if !backend_id.eq_ignore_ascii_case(DEMO_BACKEND_ID) {
                    return Err(BackendExecutionError::MalformedProof {
                        backend: format!("zk:{backend_id}"),
                        reason: format!(
                            "invalid zk payload: vk_ref '{vk_ref}' is reserved for backend_id '{DEMO_BACKEND_ID}'"
                        ),
                    });
                }
            }
        }
        return Ok(());
    }

    if is_mock_plonk {
        if let Some(system) = zk_system {
            if !system.eq_ignore_ascii_case("plonk") {
                return Err(BackendExecutionError::MalformedProof {
                    backend: format!("zk:{}", backend_id.unwrap_or("payload")),
                    reason: format!(
                        "invalid zk payload: vk_ref '{vk_ref}' requires zk_system 'plonk', got '{system}'"
                    ),
                });
            }
        }
        if let Some(backend_id) = backend_id {
            if !backend_id.to_ascii_lowercase().starts_with("mock-plonk") {
                return Err(BackendExecutionError::MalformedProof {
                    backend: format!("zk:{backend_id}"),
                    reason: format!(
                        "invalid zk payload: vk_ref '{vk_ref}' is reserved for mock-plonk backends"
                    ),
                });
            }
        }
        return Ok(());
    }

    Err(BackendExecutionError::MalformedProof {
        backend: format!("zk:{}", backend_id.unwrap_or("payload")),
        reason: format!("invalid zk payload: unknown vk_ref '{vk_ref}'"),
    })
}

#[cfg(feature = "real-zk-backend")]
#[derive(Clone)]
struct DemoSquareCircuit {
    witness: Option<u64>,
    public_output: u64,
}

#[cfg(feature = "real-zk-backend")]
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

#[cfg(feature = "real-zk-backend")]
struct DemoBackendParams {
    vk: PreparedVerifyingKey<Bn254>,
}

#[cfg(feature = "real-zk-backend")]
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

#[allow(dead_code)]
#[cfg(any(test, feature = "real-zk-backend"))]
fn public_output_from_result_hash(task: &TaskObject) -> Option<u64> {
    let result_hash = task.result_hash?;
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&result_hash[..8]);
    Some(u64::from_be_bytes(bytes))
}

fn extract_body(proof_data: &[u8]) -> Option<&str> {
    proof_data
        .iter()
        .position(|b| *b == b':')
        .and_then(|idx| proof_data.get(idx + 1..))
        .and_then(|body| std::str::from_utf8(body).ok())
}

fn is_identifier_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

fn is_value_terminator(b: u8) -> bool {
    b.is_ascii_whitespace()
        || matches!(
            b,
            b',' | b';' | b'}' | b']' | b')' | b'\'' | b'"' | b'\n' | b'\r' | b'\t'
        )
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
            return Some(body[start..i].to_string());
        }

        return Some(body[start..i].to_string());
    }

    None
}

fn legacy_backend_and_proof(proof_data: &[u8]) -> (Option<String>, Option<String>) {
    let Some(body) = extract_body(proof_data) else {
        return (None, None);
    };
    (
        find_token_field(body, DEMO_BACKEND_FIELD),
        find_token_field(body, DEMO_PROOF_FIELD),
    )
}

#[cfg(feature = "real-zk-backend")]
fn decode_proof_hex(hex_text: &str) -> Result<Proof<Bn254>, BackendExecutionError> {
    let proof_bytes = hex::decode(hex_text).map_err(|_| BackendExecutionError::MalformedProof {
        backend: format!("zk:{DEMO_BACKEND_ID}"),
        reason: "malformed proof encoding".to_string(),
    })?;
    Proof::<Bn254>::deserialize_compressed(proof_bytes.as_slice()).map_err(|_| {
        BackendExecutionError::MalformedProof {
            backend: format!("zk:{DEMO_BACKEND_ID}"),
            reason: "malformed proof encoding".to_string(),
        }
    })
}

#[cfg(feature = "real-zk-backend")]
fn verify_demo_backend(task: &TaskObject, proof_hex: &str) -> Result<(), VerificationBackendError> {
    let Some(public_output) = public_output_from_result_hash(task) else {
        return Err(BackendExecutionError::InvalidProof {
            backend: format!("zk:{DEMO_BACKEND_ID}"),
            reason: "Invalid ZK proof envelope: missing task result_hash binding context"
                .to_string(),
        }
        .into());
    };

    let proof = decode_proof_hex(proof_hex)?;
    let public_inputs = [Fr::from(public_output)];
    match Groth16::<Bn254>::verify_with_processed_vk(
        &demo_backend_params().vk,
        &public_inputs,
        &proof,
    ) {
        Ok(true) => Ok(()),
        Ok(false) => Err(BackendExecutionError::InvalidProof {
            backend: format!("zk:{DEMO_BACKEND_ID}"),
            reason: "ZK proof cryptographic verification failed".to_string(),
        }
        .into()),
        Err(err) => Err(BackendExecutionError::Unavailable {
            backend: format!("zk:{DEMO_BACKEND_ID}"),
            reason: format!("verify error: {err}"),
        }
        .into()),
    }
}

#[cfg(not(feature = "real-zk-backend"))]
fn verify_demo_backend(
    _task: &TaskObject,
    _proof_hex: &str,
) -> Result<(), VerificationBackendError> {
    Err(BackendExecutionError::Unavailable {
        backend: format!("zk:{DEMO_BACKEND_ID}"),
        reason: "support compiled out (enable real-zk-backend)".to_string(),
    }
    .into())
}

#[cfg(all(test, feature = "real-zk-backend"))]
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

#[cfg(all(test, feature = "real-zk-backend"))]
fn integer_square_root(value: u64) -> Option<u64> {
    let root = (value as f64).sqrt() as u64;
    [root.saturating_sub(1), root, root.saturating_add(1)]
        .into_iter()
        .find(|candidate| candidate.saturating_mul(*candidate) == value)
}

pub struct ZkVerifier {
    backend: ZkBackendKind,
    backends: Arc<ZkBackendRegistry>,
    config: VerificationBackendConfig,
}

impl ZkVerifier {
    pub fn new(backend: ZkBackendKind, backends: Arc<ZkBackendRegistry>) -> Self {
        Self {
            backend: backend.clone(),
            backends,
            config: VerificationBackendConfig {
                zk_backend: backend,
                ..VerificationBackendConfig::default()
            },
        }
    }

    #[allow(dead_code)]
    pub fn from_config(
        config: &VerificationBackendConfig,
        backends: Arc<ZkBackendRegistry>,
    ) -> Self {
        Self {
            backend: config.zk_backend.clone(),
            backends,
            config: config.clone(),
        }
    }

    fn has_json_envelope(proof_data: &[u8]) -> bool {
        proof_data
            .iter()
            .position(|b| *b == b':')
            .and_then(|idx| proof_data.get(idx + 1..))
            .and_then(|body| std::str::from_utf8(body).ok())
            .map(|body| {
                let trimmed = body.trim_start();
                trimmed.starts_with('{')
                    && (trimmed.contains("\"vk_ref\"") || trimmed.contains("\"public_inputs\""))
            })
            .unwrap_or(false)
    }

    fn classify_backend_err(err: VerificationBackendError) -> VerificationResult {
        match err {
            VerificationBackendError::Selection(selection) => {
                VerificationResult::Indeterminate(format!("unavailable: {selection}"))
            }
            VerificationBackendError::Execution(BackendExecutionError::InvalidProof {
                reason, ..
            }) => VerificationResult::Invalid(format!(
                "{}: {reason}",
                VerificationErrorClass::Invalid.as_str()
            )),
            VerificationBackendError::Execution(BackendExecutionError::MalformedProof {
                reason, ..
            }) => VerificationResult::Invalid(format!("malformed: {reason}")),
            VerificationBackendError::Execution(BackendExecutionError::NotConfigured { .. }) => {
                VerificationResult::Indeterminate(
                    "unavailable: ZK proof cryptographic verification backend not configured"
                        .to_string(),
                )
            }
            VerificationBackendError::Execution(BackendExecutionError::Unavailable {
                backend,
                reason,
            }) => VerificationResult::Indeterminate(format!(
                "unavailable: verification backend '{backend}' cannot currently verify proof: {reason}"
            )),
            VerificationBackendError::Execution(BackendExecutionError::Internal {
                backend,
                reason,
            }) => VerificationResult::Indeterminate(format!(
                "backend_error: verification backend '{backend}' failed: {reason}"
            )),
        }
    }

    fn backend_system_for_kind(kind: &ZkBackendKind) -> Option<&'static str> {
        match kind {
            ZkBackendKind::Custom(id) => expected_zk_system_for_backend(id),
            ZkBackendKind::Noop => None,
        }
    }

    fn should_attempt_backend_fallback(err: &VerificationBackendError) -> bool {
        matches!(
            err,
            VerificationBackendError::Selection(_)
                | VerificationBackendError::Execution(BackendExecutionError::NotConfigured { .. })
                | VerificationBackendError::Execution(BackendExecutionError::Unavailable { .. })
        )
    }

    fn can_fallback_to(
        &self,
        primary: &ZkBackendKind,
        fallback: &ZkBackendKind,
        payload: Option<&ParsedZkProofPayload>,
    ) -> bool {
        if primary == fallback || matches!(fallback, ZkBackendKind::Noop) {
            return false;
        }
        let payload_system = payload
            .and_then(|payload| payload.zk_system.as_deref())
            .map(str::trim)
            .filter(|raw| !raw.is_empty());
        let primary_system = Self::backend_system_for_kind(primary).or(payload_system);
        let fallback_system = Self::backend_system_for_kind(fallback).or(payload_system);
        matches!((primary_system, fallback_system), (Some(a), Some(b)) if a.eq_ignore_ascii_case(b))
    }

    fn verify_with_backend_kind(
        &self,
        selected_backend: &ZkBackendKind,
        task: &TaskObject,
        proof_data: &[u8],
        zk_payload: Option<&ParsedZkProofPayload>,
    ) -> Result<(), VerificationBackendError> {
        if matches!(selected_backend, ZkBackendKind::Custom(id) if id.eq_ignore_ascii_case(DEMO_BACKEND_ID))
        {
            let proof_hex = zk_payload
                .map(|payload| payload.proof.trim())
                .filter(|proof| !proof.is_empty())
                .ok_or_else(|| BackendExecutionError::InvalidProof {
                    backend: format!("zk:{DEMO_BACKEND_ID}"),
                    reason: "Invalid ZK proof envelope: missing proof binding".to_string(),
                })?;
            return verify_demo_backend(task, proof_hex);
        }

        let backend = self
            .backends
            .resolve(VerificationBackendFamily::Zk, selected_backend)?;
        backend.verify(BackendVerificationRequest {
            family: VerificationBackendFamily::Zk,
            task,
            proof_data,
            zk_payload,
        })?;
        Ok(())
    }

    fn verify_backend(
        &self,
        task: &TaskObject,
        proof_data: &[u8],
    ) -> Result<(), VerificationBackendError> {
        let flags = &self.config.zk_features;
        let has_json_envelope = Self::has_json_envelope(proof_data);

        if !has_json_envelope {
            let (legacy_backend, legacy_proof) = legacy_backend_and_proof(proof_data);
            if let Some(backend_id) = legacy_backend
                .as_deref()
                .map(str::trim)
                .filter(|raw| !raw.is_empty())
            {
                if backend_id.eq_ignore_ascii_case(DEMO_BACKEND_ID) {
                    let proof_hex = legacy_proof.as_deref().ok_or_else(|| {
                        BackendExecutionError::InvalidProof {
                            backend: format!("zk:{DEMO_BACKEND_ID}"),
                            reason: "Invalid ZK proof envelope: missing proof binding".to_string(),
                        }
                    })?;
                    return verify_demo_backend(task, proof_hex);
                }
                return Err(BackendExecutionError::Unavailable {
                    backend: format!("zk:{backend_id}"),
                    reason: format!("unsupported backend: {backend_id}"),
                }
                .into());
            }
        }

        if flags.zk_payload_v0_envelope && !has_json_envelope {
            return Err(BackendExecutionError::MalformedProof {
                backend: "zk:payload".to_string(),
                reason: "invalid zk payload: canonical JSON object is required when zk_payload_v0_envelope is enabled".to_string(),
            }
            .into());
        }

        let zk_payload = if has_json_envelope {
            let payload = parse_zk_proof_payload(task, proof_data)?;

            if flags.zk_payload_v0_envelope && payload.meta.schema_version != "trnm.zk.payload.v0" {
                return Err(BackendExecutionError::MalformedProof {
                    backend: "zk:payload".to_string(),
                    reason: "invalid zk payload: meta.schema_version must be trnm.zk.payload.v0"
                        .to_string(),
                }
                .into());
            }

            if flags.zk_explicit_backend_required
                && payload
                    .backend_id
                    .as_deref()
                    .map(str::trim)
                    .unwrap_or_default()
                    .is_empty()
            {
                return Err(BackendExecutionError::MalformedProof {
                    backend: "zk:payload".to_string(),
                    reason: "invalid zk payload: backend_id is required when zk_explicit_backend_required is enabled".to_string(),
                }
                .into());
            }

            if let (Some(backend_id), Some(zk_system)) = (
                payload
                    .backend_id
                    .as_deref()
                    .map(str::trim)
                    .filter(|raw| !raw.is_empty()),
                payload
                    .zk_system
                    .as_deref()
                    .map(str::trim)
                    .filter(|raw| !raw.is_empty()),
            ) {
                if let Some(expected_system) = expected_zk_system_for_backend(backend_id) {
                    if !zk_system.eq_ignore_ascii_case(expected_system) {
                        return Err(BackendExecutionError::MalformedProof {
                            backend: format!("zk:{backend_id}"),
                            reason: format!(
                                "invalid zk payload: backend_id '{backend_id}' requires zk_system '{expected_system}', got '{zk_system}'"
                            ),
                        }
                        .into());
                    }
                }
            }

            resolve_vk_ref(
                &payload.vk_ref,
                payload.backend_id.as_deref(),
                payload.zk_system.as_deref(),
            )?;

            Some(payload)
        } else {
            None
        };

        let selected_backend = if flags.zk_platform_v0 && flags.zk_backend_router {
            if let Some(payload_backend_id) = zk_payload
                .as_ref()
                .and_then(|payload| payload.backend_id.as_deref())
                .map(str::trim)
                .filter(|raw| !raw.is_empty())
            {
                ZkBackendKind::Custom(payload_backend_id.to_string())
            } else {
                self.backend.clone()
            }
        } else {
            self.backend.clone()
        };

        match self.verify_with_backend_kind(
            &selected_backend,
            task,
            proof_data,
            zk_payload.as_ref(),
        ) {
            Ok(()) => Ok(()),
            Err(err)
                if flags.zk_allow_backend_fallback
                    && Self::should_attempt_backend_fallback(&err)
                    && self.can_fallback_to(
                        &selected_backend,
                        &self.backend,
                        zk_payload.as_ref(),
                    ) =>
            {
                self.verify_with_backend_kind(&self.backend, task, proof_data, zk_payload.as_ref())
            }
            Err(err) => Err(err),
        }
    }
}

impl Default for ZkVerifier {
    fn default() -> Self {
        Self::from_config(
            &VerificationBackendConfig::default(),
            Arc::new(ZkBackendRegistry::new()),
        )
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
            VerificationResult::Valid => match self.verify_backend(task, proof_data) {
                Ok(()) => VerificationResult::Valid,
                Err(err) => Self::classify_backend_err(err),
            },
            other => other,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::verification::backend::{BackendVerificationSuccess, ZkBackend, ZkFeatureFlags};
    use trnm_types::{ProofType, TaskObject, TaskStatus};

    fn mock_task() -> TaskObject {
        TaskObject {
            task_id: 99,
            creator: "alice".into(),
            bounty: 1,
            status: TaskStatus::Committed,
            proof_type: ProofType::Zk,
            metadata: None,
            worker: Some("worker-zk".into()),
            committed_hash: None,
            result_hash: Some([0x11; 32]),
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

    struct MockSuccessBackend;
    impl ZkBackend for MockSuccessBackend {
        fn backend_id(&self) -> &str {
            "mock-zk"
        }
        fn verify(
            &self,
            request: BackendVerificationRequest<'_>,
        ) -> Result<BackendVerificationSuccess, BackendExecutionError> {
            let payload = request.zk_payload.expect("zk payload required");
            assert_eq!(request.family, VerificationBackendFamily::Zk);
            assert_eq!(
                payload.public_inputs.order,
                vec!["task_id", "proof_type", "worker", "result_hash"]
            );
            assert_eq!(payload.public_inputs.values[0], "99");
            assert_eq!(payload.public_inputs.values[1], "zk");
            assert_eq!(payload.worker, "worker-zk");
            assert_eq!(payload.vk_ref, "vk://trnm/dev/mock-groth16/v1");
            Ok(BackendVerificationSuccess {
                backend_id: self.backend_id().into(),
            })
        }
    }

    struct MockPlonkSuccessBackend;
    impl ZkBackend for MockPlonkSuccessBackend {
        fn backend_id(&self) -> &str {
            "mock-plonk-success"
        }
        fn verify(
            &self,
            request: BackendVerificationRequest<'_>,
        ) -> Result<BackendVerificationSuccess, BackendExecutionError> {
            assert_eq!(request.family, VerificationBackendFamily::Zk);
            Ok(BackendVerificationSuccess {
                backend_id: self.backend_id().into(),
            })
        }
    }

    struct MockUnavailableBackend;
    impl ZkBackend for MockUnavailableBackend {
        fn backend_id(&self) -> &str {
            "mock-zk-unavailable"
        }

        fn verify(
            &self,
            request: BackendVerificationRequest<'_>,
        ) -> Result<BackendVerificationSuccess, BackendExecutionError> {
            assert_eq!(request.family, VerificationBackendFamily::Zk);
            Err(BackendExecutionError::Unavailable {
                backend: request.backend_label(self.backend_id()),
                reason: "mock zk backend unavailable".to_string(),
            })
        }
    }

    struct MockInvalidBackend;
    impl ZkBackend for MockInvalidBackend {
        fn backend_id(&self) -> &str {
            "mock-zk-invalid"
        }

        fn verify(
            &self,
            request: BackendVerificationRequest<'_>,
        ) -> Result<BackendVerificationSuccess, BackendExecutionError> {
            assert_eq!(request.family, VerificationBackendFamily::Zk);
            Err(BackendExecutionError::InvalidProof {
                backend: request.backend_label(self.backend_id()),
                reason: "mock zk backend rejected proof".to_string(),
            })
        }
    }

    struct MockInternalBackend;
    impl ZkBackend for MockInternalBackend {
        fn backend_id(&self) -> &str {
            "mock-zk-internal"
        }

        fn verify(
            &self,
            request: BackendVerificationRequest<'_>,
        ) -> Result<BackendVerificationSuccess, BackendExecutionError> {
            assert_eq!(request.family, VerificationBackendFamily::Zk);
            Err(BackendExecutionError::Internal {
                backend: request.backend_label(self.backend_id()),
                reason: "mock zk backend panicked".to_string(),
            })
        }
    }

    struct MockMalformedBackend;
    impl ZkBackend for MockMalformedBackend {
        fn backend_id(&self) -> &str {
            "mock-zk-malformed"
        }

        fn verify(
            &self,
            request: BackendVerificationRequest<'_>,
        ) -> Result<BackendVerificationSuccess, BackendExecutionError> {
            assert_eq!(request.family, VerificationBackendFamily::Zk);
            Err(BackendExecutionError::MalformedProof {
                backend: request.backend_label(self.backend_id()),
                reason: "mock zk payload malformed downstream".to_string(),
            })
        }
    }

    fn router_config() -> VerificationBackendConfig {
        VerificationBackendConfig {
            zk_backend: ZkBackendKind::Noop,
            zk_features: ZkFeatureFlags {
                zk_platform_v0: true,
                zk_backend_router: true,
                zk_payload_v0_envelope: true,
                zk_explicit_backend_required: true,
                ..ZkFeatureFlags::default()
            },
            ..VerificationBackendConfig::default()
        }
    }

    #[test]
    fn zk_verifier_requires_cryptographic_backend_after_bound_envelope_validation() {
        let verifier = ZkVerifier::default();
        let task = mock_task();

        assert!(matches!(
            verifier.verify_proof(
                &task,
                b"ZK:task_id=99,worker=worker-zk,proof_type=zk,result_hash=1111111111111111111111111111111111111111111111111111111111111111,proof=ok"
            ),
            VerificationResult::Indeterminate(msg)
                if msg.contains("unavailable:") && msg.contains("cryptographic verification backend not configured")
        ));
    }

    #[test]
    fn zk_verifier_requires_cryptographic_backend_for_legacy_proof_type_alias() {
        let verifier = ZkVerifier::default();
        let task = mock_task();

        assert!(matches!(
            verifier.verify_proof(
                &task,
                b"ZK:task_id=99,worker=worker-zk,proof_type=zk_snark,result_hash=1111111111111111111111111111111111111111111111111111111111111111,proof=ok"
            ),
            VerificationResult::Indeterminate(msg)
                if msg.contains("cryptographic verification backend not configured")
        ));
    }

    #[test]
    fn zk_verifier_valid_proof_path_with_mock_backend() {
        let mut backends = ZkBackendRegistry::new();
        backends.register(Arc::new(MockSuccessBackend));
        let verifier = ZkVerifier::from_config(&router_config(), Arc::new(backends));
        let task = mock_task();
        let payload = br#"ZK:{"task_id":99,"worker":"worker-zk","proof_type":"zk","result_hash":"1111111111111111111111111111111111111111111111111111111111111111","zk_system":"groth16","backend_id":"mock-zk","backend_version":"v1","vk_ref":"vk://trnm/dev/mock-groth16/v1","proof_encoding":"hex","proof":"01020304","public_inputs":{"order":["task_id","proof_type","worker","result_hash"],"values":["99","zk","worker-zk","1111111111111111111111111111111111111111111111111111111111111111"]},"meta":{"schema_version":"trnm.zk.payload.v0","circuit_id":"settlement-result-v1"}}"#;
        assert!(matches!(
            verifier.verify_proof(&task, payload),
            VerificationResult::Valid
        ));
    }

    #[test]
    fn zk_verifier_routes_to_payload_selected_backend_when_router_enabled() {
        let mut backends = ZkBackendRegistry::new();
        backends.register(Arc::new(MockSuccessBackend));
        let verifier = ZkVerifier::from_config(&router_config(), Arc::new(backends));
        let task = mock_task();
        let payload = br#"ZK:{"task_id":99,"worker":"worker-zk","proof_type":"zk","result_hash":"1111111111111111111111111111111111111111111111111111111111111111","zk_system":"groth16","backend_id":"mock-zk","backend_version":"v1","vk_ref":"vk://trnm/dev/mock-groth16/v1","proof_encoding":"hex","proof":"01020304","public_inputs":{"order":["task_id","proof_type","worker","result_hash"],"values":["99","zk","worker-zk","1111111111111111111111111111111111111111111111111111111111111111"]},"meta":{"schema_version":"trnm.zk.payload.v0"}}"#;
        assert_eq!(
            verifier.verify_proof(&task, payload),
            VerificationResult::Valid
        );
    }

    #[test]
    fn zk_verifier_invalid_proof_path_with_mock_backend() {
        let mut backends = ZkBackendRegistry::new();
        backends.register(Arc::new(MockInvalidBackend));
        let verifier = ZkVerifier::from_config(&router_config(), Arc::new(backends));
        let task = mock_task();
        let payload = br#"ZK:{"task_id":99,"worker":"worker-zk","proof_type":"zk","result_hash":"1111111111111111111111111111111111111111111111111111111111111111","zk_system":"groth16","backend_id":"mock-zk-invalid","backend_version":"v1","vk_ref":"vk://trnm/dev/mock-groth16/v1","proof_encoding":"hex","proof":"01020304","public_inputs":{"order":["task_id","proof_type","worker","result_hash"],"values":["99","zk","worker-zk","1111111111111111111111111111111111111111111111111111111111111111"]},"meta":{"schema_version":"trnm.zk.payload.v0"}}"#;
        assert!(matches!(
            verifier.verify_proof(&task, payload),
            VerificationResult::Invalid(msg) if msg.contains("invalid:") && msg.contains("mock zk backend rejected proof")
        ));
    }

    #[test]
    fn zk_verifier_unknown_backend_selection_maps_to_indeterminate_unavailable() {
        let verifier =
            ZkVerifier::from_config(&router_config(), Arc::new(ZkBackendRegistry::new()));
        let task = mock_task();
        let payload = br#"ZK:{"task_id":99,"worker":"worker-zk","proof_type":"zk","result_hash":"1111111111111111111111111111111111111111111111111111111111111111","zk_system":"groth16","backend_id":"missing-zk-backend","backend_version":"v1","vk_ref":"vk://trnm/dev/mock-groth16/v1","proof_encoding":"hex","proof":"01020304","public_inputs":{"order":["task_id","proof_type","worker","result_hash"],"values":["99","zk","worker-zk","1111111111111111111111111111111111111111111111111111111111111111"]},"meta":{"schema_version":"trnm.zk.payload.v0"}}"#;
        assert!(matches!(
            verifier.verify_proof(&task, payload),
            VerificationResult::Indeterminate(msg)
                if msg.contains("unavailable:")
                    && msg.contains("family 'zk'")
                    && msg.contains("missing-zk-backend")
        ));
    }

    #[test]
    fn zk_verifier_backend_internal_maps_to_backend_error_indeterminate() {
        let mut backends = ZkBackendRegistry::new();
        backends.register(Arc::new(MockInternalBackend));
        let verifier = ZkVerifier::from_config(&router_config(), Arc::new(backends));
        let task = mock_task();
        let payload = br#"ZK:{"task_id":99,"worker":"worker-zk","proof_type":"zk","result_hash":"1111111111111111111111111111111111111111111111111111111111111111","zk_system":"groth16","backend_id":"mock-zk-internal","backend_version":"v1","vk_ref":"vk://trnm/dev/mock-groth16/v1","proof_encoding":"hex","proof":"01020304","public_inputs":{"order":["task_id","proof_type","worker","result_hash"],"values":["99","zk","worker-zk","1111111111111111111111111111111111111111111111111111111111111111"]},"meta":{"schema_version":"trnm.zk.payload.v0"}}"#;
        assert!(matches!(
            verifier.verify_proof(&task, payload),
            VerificationResult::Indeterminate(msg)
                if msg.contains("backend_error:") && msg.contains("mock zk backend panicked")
        ));
    }

    #[test]
    fn zk_verifier_backend_malformed_maps_to_invalid_malformed_taxonomy() {
        let mut backends = ZkBackendRegistry::new();
        backends.register(Arc::new(MockMalformedBackend));
        let verifier = ZkVerifier::from_config(&router_config(), Arc::new(backends));
        let task = mock_task();
        let payload = br#"ZK:{"task_id":99,"worker":"worker-zk","proof_type":"zk","result_hash":"1111111111111111111111111111111111111111111111111111111111111111","zk_system":"groth16","backend_id":"mock-zk-malformed","backend_version":"v1","vk_ref":"vk://trnm/dev/mock-groth16/v1","proof_encoding":"hex","proof":"01020304","public_inputs":{"order":["task_id","proof_type","worker","result_hash"],"values":["99","zk","worker-zk","1111111111111111111111111111111111111111111111111111111111111111"]},"meta":{"schema_version":"trnm.zk.payload.v0"}}"#;
        assert!(matches!(
            verifier.verify_proof(&task, payload),
            VerificationResult::Invalid(msg)
                if msg.contains("malformed:") && msg.contains("mock zk payload malformed downstream")
        ));
    }

    #[test]
    fn zk_verifier_fallback_disabled_does_not_silently_retry_configured_backend() {
        let mut backends = ZkBackendRegistry::new();
        backends.register(Arc::new(MockSuccessBackend));
        backends.register(Arc::new(MockUnavailableBackend));
        let mut config = router_config();
        config.zk_backend = ZkBackendKind::Custom("mock-zk".into());
        config.zk_features.zk_allow_backend_fallback = false;
        let verifier = ZkVerifier::from_config(&config, Arc::new(backends));
        let task = mock_task();
        let payload = br#"ZK:{"task_id":99,"worker":"worker-zk","proof_type":"zk","result_hash":"1111111111111111111111111111111111111111111111111111111111111111","zk_system":"groth16","backend_id":"mock-zk-unavailable","backend_version":"v1","vk_ref":"vk://trnm/dev/mock-groth16/v1","proof_encoding":"hex","proof":"01020304","public_inputs":{"order":["task_id","proof_type","worker","result_hash"],"values":["99","zk","worker-zk","1111111111111111111111111111111111111111111111111111111111111111"]},"meta":{"schema_version":"trnm.zk.payload.v0"}}"#;
        assert!(matches!(
            verifier.verify_proof(&task, payload),
            VerificationResult::Indeterminate(msg)
                if msg.contains("unavailable:") && msg.contains("mock zk backend unavailable")
        ));
    }

    #[test]
    fn zk_verifier_fallback_enabled_retries_same_system_configured_backend() {
        let mut backends = ZkBackendRegistry::new();
        backends.register(Arc::new(MockSuccessBackend));
        backends.register(Arc::new(MockUnavailableBackend));
        let mut config = router_config();
        config.zk_backend = ZkBackendKind::Custom("mock-zk".into());
        config.zk_features.zk_allow_backend_fallback = true;
        let verifier = ZkVerifier::from_config(&config, Arc::new(backends));
        let task = mock_task();
        let payload = br#"ZK:{"task_id":99,"worker":"worker-zk","proof_type":"zk","result_hash":"1111111111111111111111111111111111111111111111111111111111111111","zk_system":"groth16","backend_id":"mock-zk-unavailable","backend_version":"v1","vk_ref":"vk://trnm/dev/mock-groth16/v1","proof_encoding":"hex","proof":"01020304","public_inputs":{"order":["task_id","proof_type","worker","result_hash"],"values":["99","zk","worker-zk","1111111111111111111111111111111111111111111111111111111111111111"]},"meta":{"schema_version":"trnm.zk.payload.v0"}}"#;
        assert_eq!(
            verifier.verify_proof(&task, payload),
            VerificationResult::Valid
        );
    }

    #[test]
    fn zk_verifier_accepts_second_system_mock_plonk_backend() {
        let mut backends = ZkBackendRegistry::new();
        backends.register(Arc::new(MockPlonkSuccessBackend));
        let verifier = ZkVerifier::from_config(&router_config(), Arc::new(backends));
        let task = mock_task();
        let payload = br#"ZK:{"task_id":99,"worker":"worker-zk","proof_type":"zk","result_hash":"1111111111111111111111111111111111111111111111111111111111111111","zk_system":"plonk","backend_id":"mock-plonk-success","backend_version":"v1","vk_ref":"vk://trnm/dev/mock-plonk/v1","proof_encoding":"hex","proof":"01020304","public_inputs":{"order":["task_id","proof_type","worker","result_hash"],"values":["99","zk","worker-zk","1111111111111111111111111111111111111111111111111111111111111111"]},"meta":{"schema_version":"trnm.zk.payload.v0"}}"#;
        assert_eq!(
            verifier.verify_proof(&task, payload),
            VerificationResult::Valid
        );
    }

    #[test]
    fn zk_verifier_rejects_second_system_vk_ref_mismatch_fail_closed() {
        let config = VerificationBackendConfig {
            zk_backend: ZkBackendKind::Custom("mock-plonk-success".into()),
            zk_features: ZkFeatureFlags {
                zk_platform_v0: true,
                zk_backend_router: true,
                zk_payload_v0_envelope: true,
                zk_explicit_backend_required: false,
                ..ZkFeatureFlags::default()
            },
            ..VerificationBackendConfig::default()
        };
        let mut backends = ZkBackendRegistry::new();
        backends.register(Arc::new(MockPlonkSuccessBackend));
        let verifier = ZkVerifier::from_config(&config, Arc::new(backends));
        let task = mock_task();
        let payload = br#"ZK:{"task_id":99,"worker":"worker-zk","proof_type":"zk","result_hash":"1111111111111111111111111111111111111111111111111111111111111111","zk_system":"groth16","backend_version":"v1","vk_ref":"vk://trnm/dev/mock-plonk/v1","proof_encoding":"hex","proof":"01020304","public_inputs":{"order":["task_id","proof_type","worker","result_hash"],"values":["99","zk","worker-zk","1111111111111111111111111111111111111111111111111111111111111111"]},"meta":{"schema_version":"trnm.zk.payload.v0"}}"#;
        let verdict = verifier.verify_proof(&task, payload);
        match verdict {
            VerificationResult::Invalid(msg) => {
                assert!(msg.contains("malformed:"));
                assert!(msg.contains("vk_ref 'vk://trnm/dev/mock-plonk/v1'"));
                assert!(msg.contains("requires zk_system 'plonk'"));
            }
            other => panic!("unexpected verdict: {other:?}"),
        }
    }

    #[test]
    fn zk_verifier_fallback_enabled_does_not_cross_zk_systems() {
        let mut backends = ZkBackendRegistry::new();
        backends.register(Arc::new(MockUnavailableBackend));
        backends.register(Arc::new(MockPlonkSuccessBackend));
        let mut config = router_config();
        config.zk_backend = ZkBackendKind::Custom("mock-plonk-success".into());
        config.zk_features.zk_allow_backend_fallback = true;
        let verifier = ZkVerifier::from_config(&config, Arc::new(backends));
        let task = mock_task();
        let payload = br#"ZK:{"task_id":99,"worker":"worker-zk","proof_type":"zk","result_hash":"1111111111111111111111111111111111111111111111111111111111111111","zk_system":"groth16","backend_id":"mock-zk-unavailable","backend_version":"v1","vk_ref":"vk://trnm/dev/mock-groth16/v1","proof_encoding":"hex","proof":"01020304","public_inputs":{"order":["task_id","proof_type","worker","result_hash"],"values":["99","zk","worker-zk","1111111111111111111111111111111111111111111111111111111111111111"]},"meta":{"schema_version":"trnm.zk.payload.v0"}}"#;
        assert!(matches!(
            verifier.verify_proof(&task, payload),
            VerificationResult::Indeterminate(msg)
                if msg.contains("unavailable:") && msg.contains("mock zk backend unavailable")
        ));
    }

    #[test]
    fn zk_verifier_backend_unavailable_maps_to_indeterminate() {
        let mut backends = ZkBackendRegistry::new();
        backends.register(Arc::new(MockUnavailableBackend));
        let verifier = ZkVerifier::from_config(&router_config(), Arc::new(backends));
        let task = mock_task();
        let payload = br#"ZK:{"task_id":99,"worker":"worker-zk","proof_type":"zk","result_hash":"1111111111111111111111111111111111111111111111111111111111111111","zk_system":"groth16","backend_id":"mock-zk-unavailable","backend_version":"v1","vk_ref":"vk://trnm/dev/mock-groth16/v1","proof_encoding":"hex","proof":"01020304","public_inputs":{"order":["task_id","proof_type","worker","result_hash"],"values":["99","zk","worker-zk","1111111111111111111111111111111111111111111111111111111111111111"]},"meta":{"schema_version":"trnm.zk.payload.v0"}}"#;
        assert!(matches!(
            verifier.verify_proof(&task, payload),
            VerificationResult::Indeterminate(msg) if msg.contains("unavailable:") && msg.contains("mock zk backend unavailable")
        ));
    }

    #[test]
    fn zk_verifier_rejects_public_inputs_missing_proof_type_slot() {
        let verifier = ZkVerifier::default();
        let task = mock_task();
        let payload = br#"ZK:{"task_id":99,"worker":"worker-zk","proof_type":"zk","result_hash":"1111111111111111111111111111111111111111111111111111111111111111","vk_ref":"vk://trnm/dev/mock-groth16/v1","proof_encoding":"hex","proof":"01020304","public_inputs":{"order":["task_id","worker","result_hash"],"values":["99","worker-zk","1111111111111111111111111111111111111111111111111111111111111111"]}}"#;
        assert!(matches!(
            verifier.verify_proof(&task, payload),
            VerificationResult::Invalid(msg) if msg.contains("public_inputs mismatch")
        ));
    }

    #[test]
    fn zk_verifier_rejects_public_inputs_wrong_canonical_order() {
        let verifier = ZkVerifier::default();
        let task = mock_task();
        let payload = br#"ZK:{"task_id":99,"worker":"worker-zk","proof_type":"zk","result_hash":"1111111111111111111111111111111111111111111111111111111111111111","vk_ref":"vk://trnm/dev/mock-groth16/v1","proof_encoding":"hex","proof":"01020304","public_inputs":{"order":["proof_type","task_id","worker","result_hash"],"values":["zk","99","worker-zk","1111111111111111111111111111111111111111111111111111111111111111"]}}"#;
        assert!(matches!(
            verifier.verify_proof(&task, payload),
            VerificationResult::Invalid(msg) if msg.contains("public_inputs mismatch")
        ));
    }

    #[test]
    fn zk_verifier_invalid_proof_path_rejects_mapped_public_inputs() {
        let verifier = ZkVerifier::default();
        let task = mock_task();
        let payload = br#"ZK:{"task_id":99,"worker":"worker-zk","proof_type":"zk","result_hash":"1111111111111111111111111111111111111111111111111111111111111111","vk_ref":"vk://trnm/dev/mock-groth16/v1","proof_encoding":"hex","proof":"01020304","public_inputs":{"order":["task_id","proof_type","worker","result_hash"],"values":["99","zk","worker-zk","2222222222222222222222222222222222222222222222222222222222222222"]}}"#;
        assert!(
            matches!(verifier.verify_proof(&task, payload), VerificationResult::Invalid(msg) if msg.contains("public_inputs mismatch"))
        );
    }

    #[test]
    fn zk_verifier_rejects_unknown_vk_ref_fail_closed() {
        let mut backends = ZkBackendRegistry::new();
        backends.register(Arc::new(MockSuccessBackend));
        let verifier = ZkVerifier::from_config(&router_config(), Arc::new(backends));
        let task = mock_task();
        let payload = br#"ZK:{"task_id":99,"worker":"worker-zk","proof_type":"zk","result_hash":"1111111111111111111111111111111111111111111111111111111111111111","zk_system":"groth16","backend_id":"mock-zk","backend_version":"v1","vk_ref":"vk://trnm/dev/unknown-groth16/v1","proof_encoding":"hex","proof":"01020304","public_inputs":{"order":["task_id","proof_type","worker","result_hash"],"values":["99","zk","worker-zk","1111111111111111111111111111111111111111111111111111111111111111"]},"meta":{"schema_version":"trnm.zk.payload.v0"}}"#;
        assert!(matches!(
            verifier.verify_proof(&task, payload),
            VerificationResult::Invalid(msg)
                if msg.contains("malformed:") && msg.contains("unknown vk_ref")
        ));
    }

    #[test]
    fn zk_verifier_rejects_vk_ref_and_zk_system_mismatch() {
        let config = VerificationBackendConfig {
            zk_backend: ZkBackendKind::Noop,
            zk_features: ZkFeatureFlags {
                zk_platform_v0: true,
                zk_backend_router: true,
                zk_payload_v0_envelope: true,
                zk_explicit_backend_required: false,
                ..ZkFeatureFlags::default()
            },
            ..VerificationBackendConfig::default()
        };
        let verifier = ZkVerifier::from_config(&config, Arc::new(ZkBackendRegistry::new()));
        let task = mock_task();
        let payload = br#"ZK:{"task_id":99,"worker":"worker-zk","proof_type":"zk","result_hash":"1111111111111111111111111111111111111111111111111111111111111111","zk_system":"plonk","backend_version":"v1","vk_ref":"vk://trnm/dev/mock-groth16/v1","proof_encoding":"hex","proof":"01020304","public_inputs":{"order":["task_id","proof_type","worker","result_hash"],"values":["99","zk","worker-zk","1111111111111111111111111111111111111111111111111111111111111111"]},"meta":{"schema_version":"trnm.zk.payload.v0"}}"#;
        assert!(matches!(
            verifier.verify_proof(&task, payload),
            VerificationResult::Invalid(msg)
                if msg.contains("malformed:")
                    && msg.contains("requires zk_system 'groth16'")
                    && msg.contains("vk_ref")
        ));
    }

    #[test]
    fn zk_verifier_malformed_envelope_fails_closed_before_crypto() {
        let verifier = ZkVerifier::default();
        let task = mock_task();
        let payload = b"ZK:   \n\t";
        assert!(
            matches!(verifier.verify_proof(&task, payload), VerificationResult::Invalid(msg) if msg.contains("Invalid ZK proof envelope"))
        );
    }

    #[test]
    fn zk_verifier_enforces_v0_schema_when_feature_enabled() {
        let mut backends = ZkBackendRegistry::new();
        backends.register(Arc::new(MockSuccessBackend));
        let verifier = ZkVerifier::from_config(&router_config(), Arc::new(backends));
        let task = mock_task();
        let payload = br#"ZK:{"task_id":99,"worker":"worker-zk","proof_type":"zk","result_hash":"1111111111111111111111111111111111111111111111111111111111111111","zk_system":"groth16","backend_id":"mock-zk","backend_version":"v1","vk_ref":"vk://trnm/dev/mock-groth16/v1","proof_encoding":"hex","proof":"01020304","public_inputs":{"order":["task_id","proof_type","worker","result_hash"],"values":["99","zk","worker-zk","1111111111111111111111111111111111111111111111111111111111111111"]},"meta":{"schema_version":"legacy"}}"#;
        assert!(
            matches!(verifier.verify_proof(&task, payload), VerificationResult::Invalid(msg) if msg.contains("malformed:") && msg.contains("schema_version"))
        );
    }

    #[test]
    fn zk_verifier_requires_explicit_backend_id_when_feature_enabled() {
        let verifier =
            ZkVerifier::from_config(&router_config(), Arc::new(ZkBackendRegistry::new()));
        let task = mock_task();
        let payload = br#"ZK:{"task_id":99,"worker":"worker-zk","proof_type":"zk","result_hash":"1111111111111111111111111111111111111111111111111111111111111111","zk_system":"groth16","backend_version":"v1","vk_ref":"vk://trnm/dev/mock-groth16/v1","proof_encoding":"hex","proof":"01020304","public_inputs":{"order":["task_id","proof_type","worker","result_hash"],"values":["99","zk","worker-zk","1111111111111111111111111111111111111111111111111111111111111111"]},"meta":{"schema_version":"trnm.zk.payload.v0"}}"#;
        assert!(
            matches!(verifier.verify_proof(&task, payload), VerificationResult::Invalid(msg) if msg.contains("malformed:") && msg.contains("backend_id is required"))
        );
    }

    fn demo_task() -> TaskObject {
        let mut task = mock_task();
        let public_output = 81u64;
        let mut result_hash = [0u8; 32];
        result_hash[..8].copy_from_slice(&public_output.to_be_bytes());
        task.result_hash = Some(result_hash);
        task
    }

    #[cfg(feature = "real-zk-backend")]
    #[test]
    fn zk_verifier_accepts_valid_real_groth16_proof() {
        let verifier = ZkVerifier::default();
        let task = demo_task();
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

    #[cfg(feature = "real-zk-backend")]
    #[test]
    fn zk_verifier_rejects_malformed_real_groth16_proof_encoding() {
        let verifier = ZkVerifier::default();
        let task = demo_task();
        let proof = format!(
            "ZK:task_id=99,worker=worker-zk,proof_type=zk,result_hash=0000000000000051000000000000000000000000000000000000000000000000,backend={DEMO_BACKEND_ID},proof=zzzz"
        );

        assert!(matches!(
            verifier.verify_proof(&task, proof.as_bytes()),
            VerificationResult::Invalid(msg) if msg.contains("malformed")
        ));
    }

    #[cfg(feature = "real-zk-backend")]
    #[test]
    fn zk_verifier_rejects_cryptographically_invalid_real_groth16_proof() {
        let verifier = ZkVerifier::default();
        let task = demo_task();
        let other_public_output = 64u64;
        let wrong_proof_hex = demo_backend_proof_hex_for_public_output(other_public_output);
        let proof = format!(
            "ZK:task_id=99,worker=worker-zk,proof_type=zk,result_hash=0000000000000051000000000000000000000000000000000000000000000000,backend={DEMO_BACKEND_ID},proof={wrong_proof_hex}"
        );

        assert!(matches!(
            verifier.verify_proof(&task, proof.as_bytes()),
            VerificationResult::Invalid(msg) if msg.contains("cryptographic verification failed")
        ));
    }

    #[cfg(not(feature = "real-zk-backend"))]
    #[test]
    fn zk_verifier_reports_compiled_out_backend_for_demo_backend_id() {
        let verifier = ZkVerifier::default();
        let task = demo_task();

        assert!(matches!(
            verifier.verify_proof(
                &task,
                b"ZK:task_id=99,worker=worker-zk,proof_type=zk,result_hash=0000000000000051000000000000000000000000000000000000000000000000,backend=ark-groth16-bn254-demo,proof=abcd"
            ),
            VerificationResult::Indeterminate(msg)
                if msg.contains("support compiled out") && msg.contains("real-zk-backend")
        ));
    }
}
