// Deterministic, target-bound status projection for the external recovery
// owner.
//
// `PayloadReplayRecoveryOwnerV1::status` is intentionally a Rust enum: it is
// convenient for an in-process caller, but it does not carry enough context
// to safely hand a status response across a process boundary.  This
// projection adds the exact namespace digest and recovery target, plus a
// canonical digest over the complete snapshot.  A supervisor can therefore
// bind a response to the request it issued without trusting a path name or a
// caller-supplied "latest" value.
//
// The projection is candidate-only.  It reports neither Core authority nor a
// whole-node anti-rollback decision; the production and atomicity bits are
// deliberately hard-coded false and are included in the digest-bound bytes.

/// Stable schema identifier for the binary status projection.
pub const PAYLOAD_REPLAY_RECOVERY_STATUS_PROJECTION_SCHEMA_V1: &str =
    "trnm.payload-replay-recovery-status-projection.v1";

/// This projection is an externally callable candidate observation surface,
/// not a production authority.
pub const PAYLOAD_REPLAY_RECOVERY_STATUS_PROJECTION_CANDIDATE_V1: bool = true;

/// Production activation remains disabled until a real Node/Core owner and
/// whole-node anti-rollback protocol are independently proven.
pub const PAYLOAD_REPLAY_RECOVERY_STATUS_PROJECTION_PRODUCTION_ACTIVATION_V1: bool = false;

/// A status projection is immutable and binds one exact payload namespace and
/// target.  The status enum itself remains available through [`status`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PayloadReplayRecoveryStatusProjectionV1 {
    namespace_digest: [u8; 32],
    target: PayloadReplayRecoveryTargetV1,
    status: PayloadReplayRecoveryStatusV1,
    projection_digest: [u8; 32],
}

impl PayloadReplayRecoveryStatusProjectionV1 {
    fn from_parts(
        namespace_digest: [u8; 32],
        target: PayloadReplayRecoveryTargetV1,
        status: PayloadReplayRecoveryStatusV1,
    ) -> Self {
        let prefix = encode_projection_prefix(namespace_digest, target, status);
        let projection_digest = projection_digest(&prefix);
        Self {
            namespace_digest,
            target,
            status,
            projection_digest,
        }
    }

    /// The SHA-256 digest of the canonical projection prefix.  The digest is
    /// a projection identity, not a signature or a Core acknowledgement.
    pub const fn projection_digest(self) -> [u8; 32] {
        self.projection_digest
    }

    /// Exact namespace binding used by the payload WAL verifier.
    pub const fn namespace_digest(self) -> [u8; 32] {
        self.namespace_digest
    }

    /// Exact record/frame target selected by the recovery request.
    pub const fn target(self) -> PayloadReplayRecoveryTargetV1 {
        self.target
    }

    /// The target's publication/Core state at projection time.
    pub const fn status(self) -> PayloadReplayRecoveryStatusV1 {
        self.status
    }

    pub const fn status_kind(self) -> &'static str {
        self.status.kind()
    }

    pub const fn payload_publication_recoverable(self) -> bool {
        self.status.payload_publication_recoverable()
    }

    pub const fn core_acknowledged(self) -> bool {
        self.status.core_acknowledged()
    }

    /// Truth boundary carried by every projection.  These methods make it
    /// difficult for a generic status consumer to accidentally promote this
    /// candidate observation into production state.
    pub const fn candidate_only(self) -> bool {
        true
    }

    pub const fn production_activation(self) -> bool {
        false
    }

    pub const fn atomic_with_core(self) -> bool {
        false
    }

    /// Returns the canonical, self-checksummed bytes suitable for a bounded
    /// process hand-off or evidence attachment.  No filesystem path is
    /// included; endpoint identity remains the owner's separate fence.
    pub fn canonical_bytes(self) -> Vec<u8> {
        let mut bytes = encode_projection_prefix(self.namespace_digest, self.target, self.status);
        bytes.extend_from_slice(&self.projection_digest);
        bytes
    }

    /// Decode and verify a projection received from an external owner.
    ///
    /// The decoder is deliberately strict: it accepts one canonical fixed
    /// schema, checks the domain-separated digest before interpreting any
    /// fields, validates the complete target, and rejects trailing bytes or a
    /// truth-boundary mutation.  A successful decode proves integrity and
    /// request binding only; it does not grant Core or production authority.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, PayloadReplayRecoveryErrorV1> {
        const MIN_PREFIX_BYTES: usize = 202 + 1 + 3;
        const DIGEST_BYTES: usize = 32;
        if bytes.len() < MIN_PREFIX_BYTES + DIGEST_BYTES
            || bytes.len() > 512
            || bytes.len() < DIGEST_BYTES
        {
            return Err(PayloadReplayRecoveryErrorV1::InvalidRequest(
                "recovery status projection length is invalid",
            ));
        }
        let prefix_len = bytes.len() - DIGEST_BYTES;
        let prefix = &bytes[..prefix_len];
        let stored_digest: [u8; 32] = bytes[prefix_len..].try_into().map_err(|_| {
            PayloadReplayRecoveryErrorV1::InvalidRequest(
                "recovery status projection digest is truncated",
            )
        })?;
        if projection_digest(prefix) != stored_digest {
            return Err(PayloadReplayRecoveryErrorV1::InvalidRequest(
                "recovery status projection digest mismatch",
            ));
        }
        if prefix.get(..8) != Some(&PROJECTION_MAGIC_V1)
            || prefix.get(8) != Some(&PROJECTION_VERSION_V1)
            || prefix.get(9..12) != Some(&[0, 0, 0])
        {
            return Err(PayloadReplayRecoveryErrorV1::InvalidRequest(
                "recovery status projection header is invalid",
            ));
        }

        let mut cursor = 12usize;
        let namespace_digest = take_array::<32>(prefix, &mut cursor, "namespace digest")?;
        let record_index = take_u64(prefix, &mut cursor, "record index")?;
        let record_hash = take_array::<32>(prefix, &mut cursor, "record hash")?;
        let remote_id = take_array::<32>(prefix, &mut cursor, "remote id")?;
        let direction = match take_u8(prefix, &mut cursor, "direction")? {
            1 => PayloadReplayDirectionV1::Outbound,
            2 => PayloadReplayDirectionV1::Inbound,
            _ => {
                return Err(PayloadReplayRecoveryErrorV1::InvalidRequest(
                    "recovery status projection direction is invalid",
                ))
            }
        };
        let session_id = take_array::<32>(prefix, &mut cursor, "session id")?;
        let generation = take_u64(prefix, &mut cursor, "generation")?;
        let sequence = take_u64(prefix, &mut cursor, "sequence")?;
        let frame_kind = take_u8(prefix, &mut cursor, "frame kind")?;
        let payload_len = take_u32(prefix, &mut cursor, "payload length")?;
        let frame_fingerprint = take_array::<32>(prefix, &mut cursor, "frame fingerprint")?;
        let target = PayloadReplayRecoveryTargetV1::new(
            record_index,
            record_hash,
            remote_id,
            direction,
            session_id,
            generation,
            sequence,
            frame_kind,
            payload_len,
            frame_fingerprint,
        )?;

        let status = match take_u8(prefix, &mut cursor, "status tag")? {
            1 => PayloadReplayRecoveryStatusV1::RecoverableHeadLag {
                payload_record_count: take_u64(prefix, &mut cursor, "payload record count")?,
                payload_head_count: take_u64(prefix, &mut cursor, "payload head count")?,
                retained_temporary_count: take_u32(
                    prefix,
                    &mut cursor,
                    "retained temporary count",
                )?,
            },
            2 => PayloadReplayRecoveryStatusV1::RecoverableResidualTemporaries {
                payload_record_count: take_u64(prefix, &mut cursor, "payload record count")?,
                retained_temporary_count: take_u32(
                    prefix,
                    &mut cursor,
                    "retained temporary count",
                )?,
            },
            3 => PayloadReplayRecoveryStatusV1::AdmittedUnacknowledged {
                payload_record_count: take_u64(prefix, &mut cursor, "payload record count")?,
                payload_head_hash: take_array::<32>(prefix, &mut cursor, "payload head hash")?,
            },
            4 => PayloadReplayRecoveryStatusV1::CoreAcknowledged {
                payload_record_count: take_u64(prefix, &mut cursor, "payload record count")?,
                payload_head_hash: take_array::<32>(prefix, &mut cursor, "payload head hash")?,
                core_safety_revision: take_u64(prefix, &mut cursor, "Core safety revision")?,
                core_ack_digest: take_array::<32>(prefix, &mut cursor, "Core ack digest")?,
                acknowledgement_hash: take_array::<32>(
                    prefix,
                    &mut cursor,
                    "acknowledgement hash",
                )?,
            },
            _ => {
                return Err(PayloadReplayRecoveryErrorV1::InvalidRequest(
                    "recovery status projection status tag is invalid",
                ))
            }
        };

        // The three truth bytes are part of the signed/digested prefix.  Do
        // not accept a projection that omits or changes them.
        if prefix.get(cursor..cursor + 3) != Some(&[1, 0, 0]) {
            return Err(PayloadReplayRecoveryErrorV1::InvalidRequest(
                "recovery status projection truth boundary is invalid",
            ));
        }
        cursor = cursor.saturating_add(3);
        if cursor != prefix.len() {
            return Err(PayloadReplayRecoveryErrorV1::InvalidRequest(
                "recovery status projection has trailing fields",
            ));
        }

        let projection = Self {
            namespace_digest,
            target,
            status,
            projection_digest: stored_digest,
        };
        if projection.canonical_bytes() != bytes || !projection.is_self_consistent() {
            return Err(PayloadReplayRecoveryErrorV1::InvalidRequest(
                "recovery status projection is not canonical",
            ));
        }
        Ok(projection)
    }

    /// Verifies that the projection digest still matches its canonical bytes.
    /// This is an integrity check only and does not establish authority.
    pub fn is_self_consistent(self) -> bool {
        let prefix = encode_projection_prefix(self.namespace_digest, self.target, self.status);
        projection_digest(&prefix) == self.projection_digest
    }
}

fn take_bytes<'a>(
    bytes: &'a [u8],
    cursor: &mut usize,
    length: usize,
    field: &'static str,
) -> Result<&'a [u8], PayloadReplayRecoveryErrorV1> {
    let end = cursor
        .checked_add(length)
        .ok_or(PayloadReplayRecoveryErrorV1::InvalidRequest(
            "recovery status projection cursor overflow",
        ))?;
    let value = bytes
        .get(*cursor..end)
        .ok_or(PayloadReplayRecoveryErrorV1::InvalidRequest(field))?;
    *cursor = end;
    Ok(value)
}

fn take_array<const N: usize>(
    bytes: &[u8],
    cursor: &mut usize,
    field: &'static str,
) -> Result<[u8; N], PayloadReplayRecoveryErrorV1> {
    take_bytes(bytes, cursor, N, field)?
        .try_into()
        .map_err(|_| {
            PayloadReplayRecoveryErrorV1::InvalidRequest(
                "recovery status projection field has an invalid width",
            )
        })
}

fn take_u8(
    bytes: &[u8],
    cursor: &mut usize,
    field: &'static str,
) -> Result<u8, PayloadReplayRecoveryErrorV1> {
    Ok(take_array::<1>(bytes, cursor, field)?[0])
}

fn take_u32(
    bytes: &[u8],
    cursor: &mut usize,
    field: &'static str,
) -> Result<u32, PayloadReplayRecoveryErrorV1> {
    Ok(u32::from_be_bytes(take_array::<4>(bytes, cursor, field)?))
}

fn take_u64(
    bytes: &[u8],
    cursor: &mut usize,
    field: &'static str,
) -> Result<u64, PayloadReplayRecoveryErrorV1> {
    Ok(u64::from_be_bytes(take_array::<8>(bytes, cursor, field)?))
}

impl PayloadReplayRecoveryOwnerV1 {
    /// Produce a context-bound status snapshot for an external supervisor.
    ///
    /// The existing [`status`](Self::status) call performs endpoint identity
    /// validation and complete WAL/target verification.  This method reuses
    /// that path and adds a deterministic digest over the request binding and
    /// observed state; it does not alter recovery or acknowledgement state.
    pub fn status_projection(
        &self,
    ) -> Result<PayloadReplayRecoveryStatusProjectionV1, PayloadReplayRecoveryErrorV1> {
        let status = self.status()?;
        Ok(PayloadReplayRecoveryStatusProjectionV1::from_parts(
            self.payload.namespace_digest,
            self.target,
            status,
        ))
    }
}

const PROJECTION_MAGIC_V1: [u8; 8] = *b"TRNPRSP1";
const PROJECTION_VERSION_V1: u8 = 1;
const PROJECTION_DOMAIN_V1: &[u8] = b"trnm.poco-g1.payload-recovery-status-projection.v1";

fn encode_projection_prefix(
    namespace_digest: [u8; 32],
    target: PayloadReplayRecoveryTargetV1,
    status: PayloadReplayRecoveryStatusV1,
) -> Vec<u8> {
    // All fields are fixed-width and length-prefixed by the schema/domain
    // digest.  Keeping the full target here prevents a status for one frame
    // from being replayed as the status for another frame in the same WAL.
    let mut bytes = Vec::with_capacity(256);
    bytes.extend_from_slice(&PROJECTION_MAGIC_V1);
    bytes.push(PROJECTION_VERSION_V1);
    bytes.extend_from_slice(&[0; 3]);
    bytes.extend_from_slice(&namespace_digest);
    bytes.extend_from_slice(&target.record_index.to_be_bytes());
    bytes.extend_from_slice(&target.record_hash);
    bytes.extend_from_slice(&target.remote_id);
    bytes.push(target.direction as u8);
    bytes.extend_from_slice(&target.session_id);
    bytes.extend_from_slice(&target.generation.to_be_bytes());
    bytes.extend_from_slice(&target.sequence.to_be_bytes());
    bytes.push(target.frame_kind);
    bytes.extend_from_slice(&target.payload_len.to_be_bytes());
    bytes.extend_from_slice(&target.frame_fingerprint);

    match status {
        PayloadReplayRecoveryStatusV1::RecoverableHeadLag {
            payload_record_count,
            payload_head_count,
            retained_temporary_count,
        } => {
            bytes.push(1);
            bytes.extend_from_slice(&payload_record_count.to_be_bytes());
            bytes.extend_from_slice(&payload_head_count.to_be_bytes());
            bytes.extend_from_slice(&retained_temporary_count.to_be_bytes());
        }
        PayloadReplayRecoveryStatusV1::RecoverableResidualTemporaries {
            payload_record_count,
            retained_temporary_count,
        } => {
            bytes.push(2);
            bytes.extend_from_slice(&payload_record_count.to_be_bytes());
            bytes.extend_from_slice(&retained_temporary_count.to_be_bytes());
        }
        PayloadReplayRecoveryStatusV1::AdmittedUnacknowledged {
            payload_record_count,
            payload_head_hash,
        } => {
            bytes.push(3);
            bytes.extend_from_slice(&payload_record_count.to_be_bytes());
            bytes.extend_from_slice(&payload_head_hash);
        }
        PayloadReplayRecoveryStatusV1::CoreAcknowledged {
            payload_record_count,
            payload_head_hash,
            core_safety_revision,
            core_ack_digest,
            acknowledgement_hash,
        } => {
            bytes.push(4);
            bytes.extend_from_slice(&payload_record_count.to_be_bytes());
            bytes.extend_from_slice(&payload_head_hash);
            bytes.extend_from_slice(&core_safety_revision.to_be_bytes());
            bytes.extend_from_slice(&core_ack_digest);
            bytes.extend_from_slice(&acknowledgement_hash);
        }
    }

    // Bind the truth boundary itself so a generic decoder cannot omit these
    // fields while retaining the same digest.
    bytes.extend_from_slice(&[1, 0, 0]); // candidate_only, production, atomic_with_core
    bytes
}

fn projection_digest(prefix: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(PROJECTION_DOMAIN_V1);
    hasher.update((prefix.len() as u64).to_be_bytes());
    hasher.update(prefix);
    hasher.finalize().into()
}

#[cfg(test)]
mod projection_tests {
    use super::*;
    use crate::payload::{
        PayloadReplayDirectionV1, PayloadReplayFrameV1, PayloadReplayNamespaceV1,
        PayloadReplayStoreV1,
    };
    use crate::protocol::PeerLeaseDirectionV1;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;
    use std::{fs, path::PathBuf};
    use tempfile::TempDir;

    fn target(seed: u8) -> PayloadReplayRecoveryTargetV1 {
        PayloadReplayRecoveryTargetV1::new(
            1,
            [seed; 32],
            [seed.saturating_add(1); 32],
            PayloadReplayDirectionV1::Inbound,
            [seed.saturating_add(2); 32],
            1,
            0,
            1,
            0,
            [seed.saturating_add(3); 32],
        )
        .expect("valid projection target")
    }

    fn seeded_owner() -> (TempDir, PayloadReplayRecoveryOwnerV1) {
        let root = tempfile::Builder::new()
            .prefix("trnm-recovery-projection-")
            .tempdir()
            .expect("projection tempdir");
        #[cfg(unix)]
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700))
            .expect("private projection tempdir");
        let payload_path = root.path().join("frames.wal");
        let acknowledgement_root = root.path().join("core-acks");
        fs::create_dir(&acknowledgement_root).expect("ack root");
        #[cfg(unix)]
        fs::set_permissions(&acknowledgement_root, fs::Permissions::from_mode(0o700))
            .expect("private ack root");
        let namespace = PayloadReplayNamespaceV1::new([1; 32], 7, [2; 32], [3; 32], [4; 32])
            .expect("projection namespace");
        let frame = PayloadReplayFrameV1::new(
            namespace
                .scope_for([9; 32], PeerLeaseDirectionV1::Inbound)
                .expect("projection scope"),
            namespace.run_id_hash(),
            namespace.network_context_hash(),
            [5; 32],
            1,
            0,
            2,
            11,
            [10; 32],
        )
        .expect("projection frame");
        let receipt = {
            let mut store = PayloadReplayStoreV1::open(&payload_path, namespace)
                .expect("projection payload store");
            store.admit(&frame).expect("projection admission")
        };
        let target = PayloadReplayRecoveryTargetV1::from_admission(frame, receipt);
        let owner = PayloadReplayRecoveryOwnerV1::open(
            &payload_path,
            PathBuf::from(&acknowledgement_root),
            namespace,
            target,
        )
        .expect("projection owner");
        (root, owner)
    }

    #[test]
    fn projection_is_self_consistent_and_candidate_only() {
        let projection = PayloadReplayRecoveryStatusProjectionV1::from_parts(
            [7; 32],
            target(9),
            PayloadReplayRecoveryStatusV1::AdmittedUnacknowledged {
                payload_record_count: 1,
                payload_head_hash: [10; 32],
            },
        );
        assert!(projection.is_self_consistent());
        assert!(projection.candidate_only());
        assert!(!projection.production_activation());
        assert!(!projection.atomic_with_core());
        assert_eq!(projection.status_kind(), "admitted_unacknowledged");
        assert_eq!(
            projection.canonical_bytes().len(),
            8 + 1 + 3 + 32 + 8 + 32 + 32 + 1 + 32 + 8 + 8 + 1 + 4 + 32 + 1 + 8 + 32 + 3 + 32
        );
    }

    #[test]
    fn projection_digest_binds_target_and_status() {
        let status = PayloadReplayRecoveryStatusV1::AdmittedUnacknowledged {
            payload_record_count: 1,
            payload_head_hash: [10; 32],
        };
        let first = PayloadReplayRecoveryStatusProjectionV1::from_parts([7; 32], target(9), status);
        let other_target =
            PayloadReplayRecoveryStatusProjectionV1::from_parts([7; 32], target(11), status);
        let other_status = PayloadReplayRecoveryStatusProjectionV1::from_parts(
            [7; 32],
            target(9),
            PayloadReplayRecoveryStatusV1::CoreAcknowledged {
                payload_record_count: 1,
                payload_head_hash: [10; 32],
                core_safety_revision: 2,
                core_ack_digest: [12; 32],
                acknowledgement_hash: [13; 32],
            },
        );
        assert_ne!(first.projection_digest(), other_target.projection_digest());
        assert_ne!(first.projection_digest(), other_status.projection_digest());
    }

    #[test]
    fn owner_status_projection_reuses_endpoint_fence() {
        let (_root, owner) = seeded_owner();
        let projection = owner.status_projection().expect("status projection");
        assert_eq!(projection.target(), owner.target());
        assert_ne!(projection.namespace_digest(), [0; 32]);
        assert_eq!(projection.status_kind(), "admitted_unacknowledged");
        assert!(projection.is_self_consistent());
    }

    #[test]
    fn canonical_projection_round_trips_all_status_shapes() {
        let statuses = [
            PayloadReplayRecoveryStatusV1::RecoverableHeadLag {
                payload_record_count: 2,
                payload_head_count: 1,
                retained_temporary_count: 3,
            },
            PayloadReplayRecoveryStatusV1::RecoverableResidualTemporaries {
                payload_record_count: 2,
                retained_temporary_count: 3,
            },
            PayloadReplayRecoveryStatusV1::AdmittedUnacknowledged {
                payload_record_count: 2,
                payload_head_hash: [10; 32],
            },
            PayloadReplayRecoveryStatusV1::CoreAcknowledged {
                payload_record_count: 2,
                payload_head_hash: [10; 32],
                core_safety_revision: 9,
                core_ack_digest: [11; 32],
                acknowledgement_hash: [12; 32],
            },
        ];
        for status in statuses {
            let projection =
                PayloadReplayRecoveryStatusProjectionV1::from_parts([7; 32], target(9), status);
            let encoded = projection.canonical_bytes();
            let decoded = PayloadReplayRecoveryStatusProjectionV1::from_canonical_bytes(&encoded)
                .expect("canonical projection decode");
            assert_eq!(decoded, projection);
            assert!(decoded.is_self_consistent());
        }
    }

    #[test]
    fn projection_decoder_rejects_tamper_and_trailing_bytes() {
        let projection = PayloadReplayRecoveryStatusProjectionV1::from_parts(
            [7; 32],
            target(9),
            PayloadReplayRecoveryStatusV1::AdmittedUnacknowledged {
                payload_record_count: 1,
                payload_head_hash: [10; 32],
            },
        );
        let encoded = projection.canonical_bytes();
        let mut tampered = encoded.clone();
        tampered[20] ^= 1;
        assert!(PayloadReplayRecoveryStatusProjectionV1::from_canonical_bytes(&tampered).is_err());
        let mut trailing = encoded;
        trailing.push(0);
        assert!(PayloadReplayRecoveryStatusProjectionV1::from_canonical_bytes(&trailing).is_err());
    }
}
