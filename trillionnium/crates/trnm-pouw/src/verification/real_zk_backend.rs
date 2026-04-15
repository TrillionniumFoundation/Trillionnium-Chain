use ark_bn254::Bn254;
use ark_groth16::Proof;
use ark_serialize::CanonicalDeserialize;

use crate::verification::backend::{
    BackendExecutionError, BackendVerificationRequest, BackendVerificationSuccess, ZkBackend,
};

/// Optional real ZK backend wiring.
///
/// The backend is feature-gated so arkworks dependencies only compile when the
/// crate is built with `real-zk-backend`. For now we keep runtime behavior
/// conservative/fail-closed: the backend validates that the request is a ZK /
/// Groth16-shaped request and only then reports the route as unavailable rather
/// than silently accepting a proof with incomplete verifier-key plumbing.
pub struct RealZkBackend;

impl Default for RealZkBackend {
    fn default() -> Self {
        Self
    }
}

impl RealZkBackend {
    pub const fn backend_id_static() -> &'static str {
        "zk-groth16-arkworks"
    }

    fn ensure_groth16_request(
        request: &BackendVerificationRequest<'_>,
    ) -> Result<(), BackendExecutionError> {
        let payload = request
            .zk_payload
            .ok_or_else(|| BackendExecutionError::MalformedProof {
                backend: request.backend_label(Self::backend_id_static()),
                reason: "real zk backend requires canonical zk payload envelope".to_string(),
            })?;

        let Some(system) = payload.zk_system.as_deref() else {
            return Err(BackendExecutionError::MalformedProof {
                backend: request.backend_label(Self::backend_id_static()),
                reason: "real zk backend requires zk_system metadata".to_string(),
            });
        };

        if system != "groth16" {
            return Err(BackendExecutionError::InvalidProof {
                backend: request.backend_label(Self::backend_id_static()),
                reason: format!(
                    "real zk backend '{}' only supports groth16 payloads, got '{system}'",
                    Self::backend_id_static()
                ),
            });
        }

        let proof_bytes = payload.decode_proof_bytes()?;
        let _proof =
            Proof::<Bn254>::deserialize_compressed(proof_bytes.as_slice()).map_err(|err| {
                BackendExecutionError::MalformedProof {
                    backend: request.backend_label(Self::backend_id_static()),
                    reason: format!("invalid Groth16 proof encoding: {err}"),
                }
            })?;

        Ok(())
    }
}

impl ZkBackend for RealZkBackend {
    fn backend_id(&self) -> &str {
        Self::backend_id_static()
    }

    fn verify(
        &self,
        request: BackendVerificationRequest<'_>,
    ) -> Result<BackendVerificationSuccess, BackendExecutionError> {
        Self::ensure_groth16_request(&request)?;

        Err(BackendExecutionError::Unavailable {
            backend: request.backend_label(Self::backend_id_static()),
            reason: "arkworks Groth16 backend is compiled in but verifier-key resolution is not wired yet"
                .to_string(),
        })
    }
}
