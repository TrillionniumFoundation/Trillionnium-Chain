//! Proof-bound signer replay-floor facts for tombstone retention.
//!
//! The public fact is deliberately non-Clone and has no public constructor.
//! It is minted only after the durable application has freshly validated one
//! committed execution row, strictly verified the exact three-chain finality
//! proof, and found every signer-local nonce in the contiguous prefix.

use std::sync::Arc;

use trnm_consensus_types::FinalityProofV0;
use trnm_native_application::HeightV0;

use super::{
    error, DurableNativeApplicationV0, FinalizedNativeApplicationReadV0,
    NativeApplicationExecutionErrorCodeV0, NativeApplicationExecutionErrorV0,
};

/// Inert proof that one finalized native-application state permanently
/// contains every nonce in `1..=reject_nonce_through` for one application
/// signer identity.
///
/// It grants no Core, Safety, WAL, signer, storage-ack, or activation authority.
///
/// ```compile_fail
/// use trnm_native_execution_v0::VerifiedNativeSignerReplayFloorV1;
/// fn require_clone<T: Clone>() {}
/// require_clone::<VerifiedNativeSignerReplayFloorV1>();
/// ```
#[derive(Debug)]
#[must_use = "the replay-floor fact must remain joined to its native application owner"]
pub struct VerifiedNativeSignerReplayFloorV1 {
    owner_affinity: Arc<()>,
    store_id: [u8; 32],
    application_signer_id: String,
    reject_nonce_through: u64,
    finalized_height: u64,
    state_root: [u8; 32],
    finality_proof_digest: [u8; 32],
}

impl VerifiedNativeSignerReplayFloorV1 {
    pub fn belongs_to_application_v1(&self, application: &DurableNativeApplicationV0) -> bool {
        Arc::ptr_eq(&self.owner_affinity, &application.owner_affinity)
            && self.store_id == application.config.store_id
    }

    pub fn application_signer_id_v1(&self) -> &str {
        &self.application_signer_id
    }

    pub const fn reject_nonce_through_v1(&self) -> u64 {
        self.reject_nonce_through
    }

    pub const fn finalized_height_v1(&self) -> u64 {
        self.finalized_height
    }

    pub const fn state_root_v1(&self) -> [u8; 32] {
        self.state_root
    }

    pub const fn finality_proof_digest_v1(&self) -> [u8; 32] {
        self.finality_proof_digest
    }
}

fn contains_contiguous_signer_prefix_v1(
    read: &FinalizedNativeApplicationReadV0,
    application_signer_id: &str,
    reject_nonce_through: u64,
) -> bool {
    let mut expected = 1_u64;
    for (signer_id, nonce) in &read.replay_signer_nonces {
        if signer_id != application_signer_id {
            continue;
        }
        if *nonce < expected {
            continue;
        }
        if *nonce != expected {
            return false;
        }
        if *nonce == reject_nonce_through {
            return true;
        }
        let Some(next) = expected.checked_add(1) else {
            return false;
        };
        expected = next;
    }
    false
}

impl DurableNativeApplicationV0 {
    /// Strictly verify a finalized signer-local nonce prefix.
    ///
    /// The caller supplies only the signer identity and candidate floor. The
    /// finalized height, state root, proof digest, store affinity, and complete
    /// nonce set all come from the strictly verified durable application read.
    pub fn verify_finalized_signer_replay_floor_v1(
        &self,
        application_signer_id: &str,
        reject_nonce_through: u64,
        finalized_height: HeightV0,
        finality_proof: &FinalityProofV0,
        authenticated_parent_timestamp_ms: u64,
    ) -> Result<VerifiedNativeSignerReplayFloorV1, NativeApplicationExecutionErrorV0> {
        if application_signer_id.is_empty() || reject_nonce_through == 0 {
            return Err(error(
                NativeApplicationExecutionErrorCodeV0::BindingMismatch,
                "replay_floor.inputs",
            ));
        }
        let read = self.read_finalized_by_height_with_proof_v0(
            finalized_height,
            finality_proof,
            authenticated_parent_timestamp_ms,
        )?;
        if !contains_contiguous_signer_prefix_v1(&read, application_signer_id, reject_nonce_through)
        {
            return Err(error(
                NativeApplicationExecutionErrorCodeV0::BindingMismatch,
                "replay_floor.non_contiguous",
            ));
        }
        let finality_proof_digest = *finality_proof.id().as_bytes();
        if finality_proof_digest == [0; 32]
            || read.row.target_height == 0
            || read.row.target_state_root == [0; 32]
        {
            return Err(error(
                NativeApplicationExecutionErrorCodeV0::BindingMismatch,
                "replay_floor.finality_binding",
            ));
        }
        Ok(VerifiedNativeSignerReplayFloorV1 {
            owner_affinity: Arc::clone(&self.owner_affinity),
            store_id: read.row.store_id,
            application_signer_id: application_signer_id.to_owned(),
            reject_nonce_through,
            finalized_height: read.row.target_height,
            state_root: read.row.target_state_root,
            finality_proof_digest,
        })
    }
}
