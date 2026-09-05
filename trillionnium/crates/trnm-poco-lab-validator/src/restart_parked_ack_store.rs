//! Crash-safe private storage for one canonical direct-seven parked-Ack
//! certificate.
//!
//! The caller supplies independent nonzero raw SHA-256 anchors for the Ack,
//! RestartCut, and RestartPark artifacts. Before any filesystem mutation, the
//! typed Ack is strictly re-encoded/decoded and joined to those exact Cut/Park
//! certificates, the exact prior Cut/Park admission-set digest, FleetStart,
//! validator set, and one independently reconstructed local journal witness.
//! Publication is create-new and idempotent: exact response-loss successors
//! are reconciled while partial, foreign, or ambiguous states are preserved
//! and rejected.
//!
//! The returned non-Clone owner retains the exact dependency values and pins
//! both root and artifact identities. Fresh revalidation repeats the complete
//! stat/read/hash/strict-decode/semantic join. This store does not replace the
//! separately retained durable Cut/Park owners and does not itself inspect or
//! append a runtime journal.
//!
//! This module exposes no signer, network, timer, process-control, recovery,
//! Ready/Start, activation, or arbitrary filesystem-write authority.
//!
//! Root and artifact handles detect stable replacement, but publication child
//! operations remain pathname-based rather than directory-fd-relative. A
//! hostile same-UID concurrent rename-and-swap-back race is therefore not
//! claimed closed by this inert boundary.

use std::{
    ffi::OsStr,
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    os::unix::{
        ffi::OsStrExt,
        fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    },
    path::{Path, PathBuf},
    process,
    sync::atomic::{AtomicU64, Ordering},
};

use anyhow::{bail, ensure, Context, Result};
use sha2::{Digest, Sha256};
use trnm_consensus_types::{ValidatorId, ValidatorSet};

use crate::{
    fleet_barrier::FleetStartCertificateV1,
    restart_cut::{
        RestartCutCertificateV1, RestartParkCertificateV1, RestartParkRoleV1,
        RestartParkedAckCertificateV1, RestartParkedAckCommonV1, SignedRestartParkedAckV1,
        MAX_RESTART_PARKED_ACK_CERTIFICATE_BYTES_V1,
    },
};

const RESTART_PARKED_ACK_CERTIFICATE_FILE_V1: &str = "restart-parked-ack-certificate-v1.bin";
const RESTART_PARKED_ACK_CERTIFICATE_NEXT_V1: &str = "restart-parked-ack-certificate-v1.next";
const RESTART_PARKED_ACK_CERTIFICATE_SIDECARS_V1: [&str; 3] = [
    RESTART_PARKED_ACK_CERTIFICATE_NEXT_V1,
    "restart-parked-ack-certificate-v1.tmp",
    "restart-parked-ack-certificate-v1.lock",
];
const RESTART_PARKED_ACK_CERTIFICATE_WRITING_PREFIX_V1: &str =
    "restart-parked-ack-certificate-v1.writing.";
static RESTART_PARKED_ACK_WRITING_ATTEMPT_V1: AtomicU64 = AtomicU64::new(0);

/// Exact local durable journal facts attested by this validator's Ack.
///
/// This is data-only vocabulary. Constructing it grants no journal access and
/// does not prove that the referenced events exist; the later journal/store
/// join must reconstruct it from a freshly authenticated journal replay.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RestartParkedAckLocalWitnessV1 {
    role: RestartParkRoleV1,
    local_park_statement_sha256: [u8; 32],
    predecessor_sequence: u64,
    predecessor_sha256: [u8; 32],
    restart_cut_event_sequence: u64,
    restart_cut_event_sha256: [u8; 32],
    restart_park_event_sequence: u64,
    restart_park_event_sha256: [u8; 32],
}

impl RestartParkedAckLocalWitnessV1 {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        role: RestartParkRoleV1,
        local_park_statement_sha256: [u8; 32],
        predecessor_sequence: u64,
        predecessor_sha256: [u8; 32],
        restart_cut_event_sequence: u64,
        restart_cut_event_sha256: [u8; 32],
        restart_park_event_sequence: u64,
        restart_park_event_sha256: [u8; 32],
    ) -> Result<Self> {
        ensure!(
            local_park_statement_sha256 != [0; 32]
                && predecessor_sha256 != [0; 32]
                && restart_cut_event_sha256 != [0; 32]
                && restart_park_event_sha256 != [0; 32],
            "parked-Ack local witness contains a zero digest"
        );
        ensure!(
            predecessor_sequence > 0
                && restart_cut_event_sequence
                    == predecessor_sequence
                        .checked_add(1)
                        .context("parked-Ack predecessor sequence overflows before restart_cut")?
                && restart_park_event_sequence
                    == restart_cut_event_sequence
                        .checked_add(1)
                        .context("parked-Ack restart_cut sequence overflows before restart_park")?,
            "parked-Ack local witness is not the exact predecessor -> restart_cut -> restart_park chain"
        );
        Ok(Self {
            role,
            local_park_statement_sha256,
            predecessor_sequence,
            predecessor_sha256,
            restart_cut_event_sequence,
            restart_cut_event_sha256,
            restart_park_event_sequence,
            restart_park_event_sha256,
        })
    }

    pub(crate) const fn role_v1(self) -> RestartParkRoleV1 {
        self.role
    }

    pub(crate) const fn local_park_statement_sha256_v1(self) -> [u8; 32] {
        self.local_park_statement_sha256
    }

    pub(crate) const fn predecessor_sequence_v1(self) -> u64 {
        self.predecessor_sequence
    }

    pub(crate) const fn predecessor_sha256_v1(self) -> [u8; 32] {
        self.predecessor_sha256
    }

    pub(crate) const fn restart_cut_event_sequence_v1(self) -> u64 {
        self.restart_cut_event_sequence
    }

    pub(crate) const fn restart_cut_event_sha256_v1(self) -> [u8; 32] {
        self.restart_cut_event_sha256
    }

    pub(crate) const fn restart_park_event_sequence_v1(self) -> u64 {
        self.restart_park_event_sequence
    }

    pub(crate) const fn restart_park_event_sha256_v1(self) -> [u8; 32] {
        self.restart_park_event_sha256
    }
}

#[must_use = "stored parked-Ack ownership must be retained across the later composite join"]
pub(crate) struct StoredRestartParkedAckCertificateV1 {
    pinned: PinnedRestartParkedAckArtifactV1,
    value: RestartParkedAckCertificateV1,
    restart_cut_certificate: RestartCutCertificateV1,
    restart_cut_artifact_sha256: [u8; 32],
    restart_park_certificate: RestartParkCertificateV1,
    restart_park_artifact_sha256: [u8; 32],
    restart_cut_park_admission_set_sha256: [u8; 32],
    local_validator: ValidatorId,
    local_config_sha256: [u8; 32],
    local_witness: RestartParkedAckLocalWitnessV1,
    local_statement: SignedRestartParkedAckV1,
    artifact_sha256: [u8; 32],
}

impl std::fmt::Debug for StoredRestartParkedAckCertificateV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("StoredRestartParkedAckCertificateV1")
            .field("path", &self.pinned.path)
            .field("artifact_sha256", &self.artifact_sha256)
            .field(
                "restart_cut_body_sha256",
                &self.value.common().restart_cut_body_sha256(),
            )
            .field(
                "restart_cut_artifact_sha256",
                &self.restart_cut_artifact_sha256,
            )
            .field(
                "restart_park_artifact_sha256",
                &self.restart_park_artifact_sha256,
            )
            .field("local_validator", &self.local_validator)
            .field("local_config_sha256", &self.local_config_sha256)
            .finish_non_exhaustive()
    }
}

impl StoredRestartParkedAckCertificateV1 {
    pub(crate) const fn value_v1(&self) -> &RestartParkedAckCertificateV1 {
        &self.value
    }

    pub(crate) const fn common_v1(&self) -> &RestartParkedAckCommonV1 {
        self.value.common()
    }

    pub(crate) const fn restart_cut_certificate_v1(&self) -> &RestartCutCertificateV1 {
        &self.restart_cut_certificate
    }

    pub(crate) const fn restart_cut_artifact_sha256_v1(&self) -> [u8; 32] {
        self.restart_cut_artifact_sha256
    }

    pub(crate) const fn restart_park_certificate_v1(&self) -> &RestartParkCertificateV1 {
        &self.restart_park_certificate
    }

    pub(crate) const fn restart_park_artifact_sha256_v1(&self) -> [u8; 32] {
        self.restart_park_artifact_sha256
    }

    pub(crate) const fn restart_cut_park_admission_set_sha256_v1(&self) -> [u8; 32] {
        self.restart_cut_park_admission_set_sha256
    }

    pub(crate) const fn local_validator_v1(&self) -> ValidatorId {
        self.local_validator
    }

    pub(crate) const fn local_config_sha256_v1(&self) -> [u8; 32] {
        self.local_config_sha256
    }

    pub(crate) const fn local_witness_v1(&self) -> RestartParkedAckLocalWitnessV1 {
        self.local_witness
    }

    pub(crate) const fn local_statement_v1(&self) -> &SignedRestartParkedAckV1 {
        &self.local_statement
    }

    pub(crate) fn local_statement_sha256_v1(&self) -> [u8; 32] {
        self.local_statement.statement_sha256()
    }

    pub(crate) const fn artifact_sha256_v1(&self) -> [u8; 32] {
        self.artifact_sha256
    }

    pub(crate) fn statement_count_v1(&self) -> usize {
        self.value.statement_count()
    }

    pub(crate) fn path_v1(&self) -> &Path {
        &self.pinned.path
    }

    pub(crate) fn revalidate_fresh_v1(
        &self,
        fleet_start_certificate: &FleetStartCertificateV1,
        validator_set: &ValidatorSet,
    ) -> Result<()> {
        validate_expected_join_v1(
            self.artifact_sha256,
            &self.value,
            self.restart_cut_artifact_sha256,
            &self.restart_cut_certificate,
            self.restart_park_artifact_sha256,
            &self.restart_park_certificate,
            self.restart_cut_park_admission_set_sha256,
            self.local_validator,
            self.local_config_sha256,
            self.local_witness,
            fleet_start_certificate,
            validator_set,
        )?;
        ensure!(
            self.value.statement(self.local_validator) == Some(&self.local_statement),
            "retained parked-Ack local statement differs from retained certificate"
        );
        self.pinned.revalidate_held_v1()?;
        let (fresh, bytes, observed_sha256) = open_and_read_artifact_v1(&self.pinned.root_path)?;
        ensure!(
            fresh.same_identity_v1(&self.pinned),
            "parked-Ack path or open-file identity was replaced"
        );
        ensure!(
            observed_sha256 == self.artifact_sha256,
            "parked-Ack content address changed"
        );
        let decoded = RestartParkedAckCertificateV1::decode(
            &bytes,
            fleet_start_certificate,
            &self.restart_cut_certificate,
            &self.restart_park_certificate,
            self.restart_cut_park_admission_set_sha256,
            validator_set,
        )
        .map_err(|error| anyhow::anyhow!("fresh-decode parked-Ack certificate: {error}"))?;
        ensure!(
            decoded == self.value,
            "fresh parked-Ack certificate differs from retained typed value"
        );
        ensure!(
            decoded.statement(self.local_validator) == Some(&self.local_statement),
            "fresh parked-Ack local statement differs from retained exact statement"
        );
        validate_certificate_join_v1(
            observed_sha256,
            &decoded,
            self.restart_cut_artifact_sha256,
            &self.restart_cut_certificate,
            self.restart_park_artifact_sha256,
            &self.restart_park_certificate,
            self.restart_cut_park_admission_set_sha256,
            self.local_validator,
            self.local_config_sha256,
            self.local_witness,
            fleet_start_certificate,
            validator_set,
        )?;
        fresh.revalidate_held_v1()?;
        self.pinned.revalidate_held_v1()
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn persist_restart_parked_ack_certificate_v1(
    private_root: &Path,
    expected_artifact_sha256: [u8; 32],
    value: RestartParkedAckCertificateV1,
    expected_restart_cut_artifact_sha256: [u8; 32],
    expected_restart_cut_certificate: &RestartCutCertificateV1,
    expected_restart_park_artifact_sha256: [u8; 32],
    expected_restart_park_certificate: &RestartParkCertificateV1,
    expected_restart_cut_park_admission_set_sha256: [u8; 32],
    local_validator: ValidatorId,
    local_config_sha256: [u8; 32],
    local_witness: RestartParkedAckLocalWitnessV1,
    fleet_start_certificate: &FleetStartCertificateV1,
    validator_set: &ValidatorSet,
) -> Result<StoredRestartParkedAckCertificateV1> {
    validate_expected_join_v1(
        expected_artifact_sha256,
        &value,
        expected_restart_cut_artifact_sha256,
        expected_restart_cut_certificate,
        expected_restart_park_artifact_sha256,
        expected_restart_park_certificate,
        expected_restart_cut_park_admission_set_sha256,
        local_validator,
        local_config_sha256,
        local_witness,
        fleet_start_certificate,
        validator_set,
    )?;
    let bytes = value.encode();
    validate_encoded_bound_v1(&bytes)?;
    ensure!(
        sha256_v1(&bytes) == expected_artifact_sha256,
        "canonical parked-Ack certificate differs from expected content address"
    );
    publish_create_new_v1(private_root, &bytes)?;
    let stored = load_restart_parked_ack_certificate_v1(
        private_root,
        expected_artifact_sha256,
        expected_restart_cut_artifact_sha256,
        expected_restart_cut_certificate,
        expected_restart_park_artifact_sha256,
        expected_restart_park_certificate,
        expected_restart_cut_park_admission_set_sha256,
        local_validator,
        local_config_sha256,
        local_witness,
        fleet_start_certificate,
        validator_set,
    )?;
    ensure!(
        stored.value == value,
        "stored parked-Ack certificate differs from verified input"
    );
    Ok(stored)
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn load_restart_parked_ack_certificate_v1(
    private_root: &Path,
    expected_artifact_sha256: [u8; 32],
    expected_restart_cut_artifact_sha256: [u8; 32],
    expected_restart_cut_certificate: &RestartCutCertificateV1,
    expected_restart_park_artifact_sha256: [u8; 32],
    expected_restart_park_certificate: &RestartParkCertificateV1,
    expected_restart_cut_park_admission_set_sha256: [u8; 32],
    local_validator: ValidatorId,
    local_config_sha256: [u8; 32],
    local_witness: RestartParkedAckLocalWitnessV1,
    fleet_start_certificate: &FleetStartCertificateV1,
    validator_set: &ValidatorSet,
) -> Result<StoredRestartParkedAckCertificateV1> {
    ensure!(
        expected_artifact_sha256 != [0; 32],
        "expected parked-Ack certificate SHA-256 is zero"
    );
    let (pinned, bytes, observed_sha256) = open_and_read_artifact_v1(private_root)?;
    ensure!(
        observed_sha256 == expected_artifact_sha256,
        "parked-Ack SHA-256 differs from expected content address"
    );
    let value = RestartParkedAckCertificateV1::decode(
        &bytes,
        fleet_start_certificate,
        expected_restart_cut_certificate,
        expected_restart_park_certificate,
        expected_restart_cut_park_admission_set_sha256,
        validator_set,
    )
    .map_err(|error| anyhow::anyhow!("decode stored parked-Ack certificate: {error}"))?;
    validate_certificate_join_v1(
        observed_sha256,
        &value,
        expected_restart_cut_artifact_sha256,
        expected_restart_cut_certificate,
        expected_restart_park_artifact_sha256,
        expected_restart_park_certificate,
        expected_restart_cut_park_admission_set_sha256,
        local_validator,
        local_config_sha256,
        local_witness,
        fleet_start_certificate,
        validator_set,
    )?;
    let local_statement = value
        .statement(local_validator)
        .cloned()
        .context("stored parked-Ack certificate lacks exact local statement")?;
    pinned.revalidate_held_v1()?;
    Ok(StoredRestartParkedAckCertificateV1 {
        pinned,
        value,
        restart_cut_certificate: expected_restart_cut_certificate.clone(),
        restart_cut_artifact_sha256: expected_restart_cut_artifact_sha256,
        restart_park_certificate: expected_restart_park_certificate.clone(),
        restart_park_artifact_sha256: expected_restart_park_artifact_sha256,
        restart_cut_park_admission_set_sha256: expected_restart_cut_park_admission_set_sha256,
        local_validator,
        local_config_sha256,
        local_witness,
        local_statement,
        artifact_sha256: observed_sha256,
    })
}

#[allow(clippy::too_many_arguments)]
fn validate_expected_join_v1(
    expected_artifact_sha256: [u8; 32],
    expected_value: &RestartParkedAckCertificateV1,
    expected_restart_cut_artifact_sha256: [u8; 32],
    expected_restart_cut_certificate: &RestartCutCertificateV1,
    expected_restart_park_artifact_sha256: [u8; 32],
    expected_restart_park_certificate: &RestartParkCertificateV1,
    expected_restart_cut_park_admission_set_sha256: [u8; 32],
    local_validator: ValidatorId,
    local_config_sha256: [u8; 32],
    local_witness: RestartParkedAckLocalWitnessV1,
    fleet_start_certificate: &FleetStartCertificateV1,
    validator_set: &ValidatorSet,
) -> Result<()> {
    ensure!(
        expected_artifact_sha256 != [0; 32],
        "expected parked-Ack certificate SHA-256 is zero"
    );
    validate_certificate_join_v1(
        expected_artifact_sha256,
        expected_value,
        expected_restart_cut_artifact_sha256,
        expected_restart_cut_certificate,
        expected_restart_park_artifact_sha256,
        expected_restart_park_certificate,
        expected_restart_cut_park_admission_set_sha256,
        local_validator,
        local_config_sha256,
        local_witness,
        fleet_start_certificate,
        validator_set,
    )?;
    let canonical = expected_value.encode();
    validate_encoded_bound_v1(&canonical)?;
    ensure!(
        sha256_v1(&canonical) == expected_artifact_sha256,
        "expected typed parked-Ack certificate does not match expected content address"
    );
    let decoded = RestartParkedAckCertificateV1::decode(
        &canonical,
        fleet_start_certificate,
        expected_restart_cut_certificate,
        expected_restart_park_certificate,
        expected_restart_cut_park_admission_set_sha256,
        validator_set,
    )
    .map_err(|error| anyhow::anyhow!("exact-decode expected parked-Ack certificate: {error}"))?;
    ensure!(
        decoded == *expected_value,
        "expected parked-Ack certificate is not exact canonical wire"
    );
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn validate_certificate_join_v1(
    artifact_sha256: [u8; 32],
    certificate: &RestartParkedAckCertificateV1,
    expected_restart_cut_artifact_sha256: [u8; 32],
    expected_restart_cut_certificate: &RestartCutCertificateV1,
    expected_restart_park_artifact_sha256: [u8; 32],
    expected_restart_park_certificate: &RestartParkCertificateV1,
    expected_restart_cut_park_admission_set_sha256: [u8; 32],
    local_validator: ValidatorId,
    local_config_sha256: [u8; 32],
    local_witness: RestartParkedAckLocalWitnessV1,
    fleet_start_certificate: &FleetStartCertificateV1,
    validator_set: &ValidatorSet,
) -> Result<()> {
    ensure!(
        artifact_sha256 != [0; 32],
        "parked-Ack certificate content address is zero"
    );
    ensure!(
        expected_restart_cut_artifact_sha256 != [0; 32]
            && expected_restart_park_artifact_sha256 != [0; 32]
            && expected_restart_cut_park_admission_set_sha256 != [0; 32],
        "parked-Ack dependency content address is zero"
    );

    let restart_cut_bytes = expected_restart_cut_certificate.encode();
    ensure!(
        sha256_v1(&restart_cut_bytes) == expected_restart_cut_artifact_sha256,
        "exact RestartCut certificate differs from expected raw content address"
    );
    let verified_restart_cut = RestartCutCertificateV1::decode_verified(
        &restart_cut_bytes,
        fleet_start_certificate,
        validator_set,
    )
    .map_err(|error| anyhow::anyhow!("strictly verify exact RestartCut dependency: {error}"))?;
    ensure!(
        verified_restart_cut.certificate() == expected_restart_cut_certificate,
        "exact RestartCut dependency is not canonical"
    );

    let restart_park_bytes = expected_restart_park_certificate.encode();
    ensure!(
        sha256_v1(&restart_park_bytes) == expected_restart_park_artifact_sha256,
        "exact RestartPark certificate differs from expected raw content address"
    );
    let decoded_restart_park = RestartParkCertificateV1::decode(
        &restart_park_bytes,
        fleet_start_certificate,
        validator_set,
    )
    .map_err(|error| anyhow::anyhow!("strictly verify exact RestartPark dependency: {error}"))?;
    ensure!(
        decoded_restart_park == *expected_restart_park_certificate
            && verified_restart_cut.body() == expected_restart_park_certificate.body(),
        "exact RestartCut and RestartPark dependencies differ or are noncanonical"
    );

    certificate
        .verify(
            fleet_start_certificate,
            expected_restart_cut_certificate,
            expected_restart_park_certificate,
            expected_restart_cut_park_admission_set_sha256,
            validator_set,
        )
        .map_err(|error| anyhow::anyhow!("validate parked-Ack certificate join: {error}"))?;
    let common = certificate.common();
    ensure!(
        common.restart_cut_artifact_sha256() == expected_restart_cut_artifact_sha256
            && common.restart_park_artifact_sha256() == expected_restart_park_artifact_sha256
            && common.restart_cut_park_admission_set_sha256()
                == expected_restart_cut_park_admission_set_sha256
            && common.restart_cut_body_sha256() == verified_restart_cut.body().digest()
            && common.process_instance() == 1
            && common.validator_set_id() == validator_set.id(),
        "parked-Ack common facts differ from exact dependency identities"
    );
    ensure!(
        validator_set.validator(local_validator).is_some(),
        "parked-Ack local validator is absent from the exact validator set"
    );
    ensure!(
        local_config_sha256 != [0; 32],
        "parked-Ack local config SHA-256 is zero"
    );
    let local_ready = fleet_start_certificate
        .ready_set()
        .statement(local_validator)
        .context("FleetStart certificate lacks the local Ready statement")?;
    ensure!(
        local_ready.local_cut().config_sha256() == local_config_sha256,
        "FleetStart local config differs from expected parked-Ack binding"
    );
    let local_park_statement = expected_restart_park_certificate
        .statement(local_validator)
        .context("RestartPark certificate lacks the exact local statement")?;
    let expected_role = if local_validator == common.target_validator() {
        RestartParkRoleV1::Target
    } else {
        RestartParkRoleV1::Peer
    };
    ensure!(
        local_witness.role == expected_role
            && local_park_statement.origin() == local_validator
            && local_park_statement.local_park().local_validator() == local_validator
            && local_park_statement.local_park().role() == local_witness.role
            && local_park_statement.local_park().local_config_sha256() == local_config_sha256
            && local_park_statement.statement_sha256() == local_witness.local_park_statement_sha256,
        "RestartPark local statement differs from exact local parked-Ack witness"
    );

    let local_statement = certificate
        .statement(local_validator)
        .context("parked-Ack certificate lacks exact local signed statement")?;
    local_statement
        .verify(
            fleet_start_certificate,
            expected_restart_cut_certificate,
            expected_restart_park_certificate,
            expected_restart_cut_park_admission_set_sha256,
            validator_set,
        )
        .map_err(|error| anyhow::anyhow!("validate exact local parked-Ack statement: {error}"))?;
    ensure!(
        local_statement.origin() == local_validator
            && local_statement.common() == common
            && local_statement.role() == local_witness.role
            && local_statement.local_config_sha256() == local_config_sha256
            && local_statement.local_park_statement_sha256()
                == local_witness.local_park_statement_sha256
            && local_statement.predecessor_sequence() == local_witness.predecessor_sequence
            && local_statement.predecessor_sha256() == local_witness.predecessor_sha256
            && local_statement.restart_cut_event_sequence()
                == local_witness.restart_cut_event_sequence
            && local_statement.restart_cut_event_sha256() == local_witness.restart_cut_event_sha256
            && local_statement.restart_park_event_sequence()
                == local_witness.restart_park_event_sequence
            && local_statement.restart_park_event_sha256()
                == local_witness.restart_park_event_sha256,
        "parked-Ack certificate local statement differs from exact local journal witness"
    );
    Ok(())
}

fn validate_encoded_bound_v1(bytes: &[u8]) -> Result<()> {
    ensure!(
        !bytes.is_empty() && bytes.len() <= MAX_RESTART_PARKED_ACK_CERTIFICATE_BYTES_V1,
        "restart-parked-ack certificate canonical bytes cross the durable bound"
    );
    Ok(())
}

fn sha256_v1(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DirectoryIdentityV1 {
    device: u64,
    inode: u64,
    uid: u32,
    mode: u32,
}

impl DirectoryIdentityV1 {
    fn from_metadata_v1(metadata: &fs::Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            uid: metadata.uid(),
            mode: metadata.permissions().mode() & 0o7777,
        }
    }

    fn matches_metadata_v1(self, metadata: &fs::Metadata) -> bool {
        metadata.is_dir()
            && self.device == metadata.dev()
            && self.inode == metadata.ino()
            && self.uid == metadata.uid()
            && self.mode == metadata.permissions().mode() & 0o7777
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ArtifactIdentityV1 {
    device: u64,
    inode: u64,
    uid: u32,
    mode: u32,
    links: u64,
    length: u64,
    modified_seconds: i64,
    modified_nanoseconds: i64,
    changed_seconds: i64,
    changed_nanoseconds: i64,
}

impl ArtifactIdentityV1 {
    fn from_metadata_v1(metadata: &fs::Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            uid: metadata.uid(),
            mode: metadata.permissions().mode() & 0o7777,
            links: metadata.nlink(),
            length: metadata.len(),
            modified_seconds: metadata.mtime(),
            modified_nanoseconds: metadata.mtime_nsec(),
            changed_seconds: metadata.ctime(),
            changed_nanoseconds: metadata.ctime_nsec(),
        }
    }

    fn matches_metadata_v1(self, metadata: &fs::Metadata) -> bool {
        metadata.is_file()
            && self.device == metadata.dev()
            && self.inode == metadata.ino()
            && self.uid == metadata.uid()
            && self.mode == metadata.permissions().mode() & 0o7777
            && self.links == metadata.nlink()
            && self.length == metadata.len()
            && self.modified_seconds == metadata.mtime()
            && self.modified_nanoseconds == metadata.mtime_nsec()
            && self.changed_seconds == metadata.ctime()
            && self.changed_nanoseconds == metadata.ctime_nsec()
    }
}

struct PinnedRestartParkedAckArtifactV1 {
    root_path: PathBuf,
    path: PathBuf,
    root_file: File,
    artifact_file: File,
    root_identity: DirectoryIdentityV1,
    artifact_identity: ArtifactIdentityV1,
}

impl std::fmt::Debug for PinnedRestartParkedAckArtifactV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PinnedRestartParkedAckArtifactV1")
            .field("root_path", &self.root_path)
            .field("path", &self.path)
            .field("root_identity", &self.root_identity)
            .field("artifact_identity", &self.artifact_identity)
            .finish_non_exhaustive()
    }
}

impl PinnedRestartParkedAckArtifactV1 {
    fn same_identity_v1(&self, other: &Self) -> bool {
        self.root_path == other.root_path
            && self.path == other.path
            && self.root_identity == other.root_identity
            && self.artifact_identity == other.artifact_identity
    }

    fn revalidate_held_v1(&self) -> Result<()> {
        ensure_no_publication_sidecars_v1(&self.root_path)?;
        ensure!(
            self.path == self.root_path.join(RESTART_PARKED_ACK_CERTIFICATE_FILE_V1)
                && self.path.file_name()
                    == Some(OsStr::new(RESTART_PARKED_ACK_CERTIFICATE_FILE_V1)),
            "pinned restart parked ack artifact escaped its fixed private path"
        );

        let held_root = self
            .root_file
            .metadata()
            .context("inspect held restart parked ack private root")?;
        validate_private_root_metadata_v1(&held_root)?;
        ensure!(
            self.root_identity.matches_metadata_v1(&held_root),
            "held restart parked ack private root identity changed"
        );
        let (fresh_root_file, fresh_root_identity) = open_private_root_v1(&self.root_path)?;
        ensure!(
            fresh_root_identity == self.root_identity,
            "restart parked ack private root path was replaced"
        );
        drop(fresh_root_file);

        let held_artifact = self
            .artifact_file
            .metadata()
            .context("inspect held restart parked ack cut")?;
        validate_private_artifact_metadata_v1(&held_artifact)?;
        ensure!(
            self.artifact_identity.matches_metadata_v1(&held_artifact),
            "held restart parked ack cut identity changed"
        );
        let path_metadata = fs::symlink_metadata(&self.path)
            .context("reinspect pinned restart parked ack cut path")?;
        ensure!(
            !path_metadata.file_type().is_symlink(),
            "pinned restart parked ack cut path became a symlink"
        );
        validate_private_artifact_metadata_v1(&path_metadata)?;
        ensure!(
            self.artifact_identity.matches_metadata_v1(&path_metadata),
            "pinned restart parked ack cut path was replaced or mutated"
        );
        Ok(())
    }
}

fn effective_uid_v1() -> u32 {
    rustix::process::geteuid().as_raw()
}

fn writing_file_name_v1(process_id: u32, attempt: u64) -> String {
    format!("{RESTART_PARKED_ACK_CERTIFICATE_WRITING_PREFIX_V1}{process_id:08x}.{attempt:016x}")
}

fn next_writing_file_name_v1() -> String {
    writing_file_name_v1(
        process::id(),
        RESTART_PARKED_ACK_WRITING_ATTEMPT_V1.fetch_add(1, Ordering::Relaxed),
    )
}

fn is_lower_hex_digit_v1(byte: u8) -> bool {
    byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
}

fn writing_candidate_v1(name: &OsStr) -> Option<bool> {
    let name = name.as_bytes();
    let prefix = RESTART_PARKED_ACK_CERTIFICATE_WRITING_PREFIX_V1.as_bytes();
    if !name.starts_with(prefix) {
        return None;
    }
    let suffix = &name[prefix.len()..];
    Some(
        suffix.len() == 25
            && suffix[8] == b'.'
            && suffix[..8].iter().copied().all(is_lower_hex_digit_v1)
            && suffix[..8].iter().any(|byte| *byte != b'0')
            && suffix[9..].iter().copied().all(is_lower_hex_digit_v1),
    )
}

fn revalidate_publication_root_v1(
    private_root: &Path,
    root_file: &File,
    root_identity: DirectoryIdentityV1,
) -> Result<()> {
    let held_root = root_file
        .metadata()
        .context("reinspect held restart parked ack publication root")?;
    validate_private_root_metadata_v1(&held_root)?;
    ensure!(
        root_identity.matches_metadata_v1(&held_root),
        "restart parked ack private root changed during publication"
    );
    let path_root = fs::symlink_metadata(private_root)
        .context("reinspect restart parked ack publication root path")?;
    ensure!(
        !path_root.file_type().is_symlink() && root_identity.matches_metadata_v1(&path_root),
        "restart parked ack private root path was replaced during publication"
    );
    Ok(())
}

fn cleanup_one_interrupted_writing_candidate_v1(
    private_root: &Path,
    root_file: &File,
    root_identity: DirectoryIdentityV1,
    expected_bytes: &[u8],
    writing: &Path,
    next: &Path,
) -> Result<()> {
    let before = fs::symlink_metadata(writing).with_context(|| {
        format!(
            "inspect interrupted restart parked ack writing candidate {}",
            writing.display()
        )
    })?;
    let mode = before.permissions().mode() & 0o7777;
    ensure!(
        !before.file_type().is_symlink()
            && before.is_file()
            && before.uid() == effective_uid_v1()
            && mode & !0o600 == 0
            && matches!(before.nlink(), 1 | 2)
            && before.len() <= u64::try_from(expected_bytes.len()).unwrap_or(u64::MAX),
        "interrupted restart parked ack writing candidate has foreign metadata"
    );
    let expected_identity = ArtifactIdentityV1::from_metadata_v1(&before);

    let observed = if before.len() == 0 {
        Vec::new()
    } else {
        ensure!(
            mode == 0o600,
            "nonempty interrupted restart parked ack writing candidate has incomplete permissions"
        );
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(writing)
            .with_context(|| {
                format!(
                    "open interrupted restart parked ack writing candidate {}",
                    writing.display()
                )
            })?;
        let opened = file
            .metadata()
            .context("inspect opened interrupted restart parked ack writing candidate")?;
        ensure!(
            expected_identity.matches_metadata_v1(&opened),
            "interrupted restart parked ack writing candidate changed while opening"
        );
        let mut observed = Vec::with_capacity(
            usize::try_from(before.len()).context("writing candidate length overflows")?,
        );
        Read::by_ref(&mut file)
            .take(u64::try_from(expected_bytes.len()).unwrap_or(u64::MAX) + 1)
            .read_to_end(&mut observed)
            .context("read interrupted restart parked ack writing candidate")?;
        let after = file
            .metadata()
            .context("reinspect interrupted restart parked ack writing candidate")?;
        ensure!(
            expected_identity.matches_metadata_v1(&after),
            "interrupted restart parked ack writing candidate changed while reading"
        );
        observed
    };
    ensure!(
        expected_bytes.starts_with(&observed),
        "interrupted restart parked ack writing candidate is not an exact canonical prefix"
    );

    let next_exists = path_exists_no_follow_v1(next, "restart parked ack next candidate")?;
    match expected_identity.links {
        1 => ensure!(
            !next_exists,
            "unlinked restart parked ack writing candidate coexists with a foreign fixed candidate"
        ),
        2 => {
            ensure!(
                next_exists && observed == expected_bytes,
                "linked restart parked ack writing candidate is partial or lacks its exact fixed link"
            );
            let next_identity = validate_publication_candidate_v1(next, expected_bytes, 2)?;
            ensure!(
                next_identity == expected_identity,
                "linked restart parked ack writing and fixed candidates are different inodes"
            );
        }
        _ => unreachable!("writing candidate link count was checked above"),
    }

    let path_after = fs::symlink_metadata(writing)
        .context("reinspect interrupted restart parked ack writing candidate path")?;
    ensure!(
        expected_identity.matches_metadata_v1(&path_after),
        "interrupted restart parked ack writing candidate path was replaced"
    );
    revalidate_publication_root_v1(private_root, root_file, root_identity)?;
    fs::remove_file(writing)
        .context("remove authenticated interrupted restart parked ack writing candidate")?;
    root_file
        .sync_all()
        .context("fsync cleaned restart parked ack writing candidate")?;
    revalidate_publication_root_v1(private_root, root_file, root_identity)?;
    if expected_identity.links == 2 {
        validate_publication_candidate_v1(next, expected_bytes, 1)?;
    }
    Ok(())
}

fn cleanup_interrupted_writing_candidates_v1(
    private_root: &Path,
    root_file: &File,
    root_identity: DirectoryIdentityV1,
    expected_bytes: &[u8],
    next: &Path,
) -> Result<()> {
    let mut writing = None;
    for entry in fs::read_dir(private_root)
        .context("scan restart parked ack private root for interrupted writing candidates")?
    {
        let entry = entry.context("read restart parked ack private-root writing candidate")?;
        let name = entry.file_name();
        ensure!(
            !RESTART_PARKED_ACK_CERTIFICATE_SIDECARS_V1[1..]
                .iter()
                .any(|reserved| name == OsStr::new(reserved)),
            "forbidden restart parked ack publication sidecar is preserved: {}",
            entry.path().display()
        );
        let Some(canonical) = writing_candidate_v1(&name) else {
            continue;
        };
        let path = private_root.join(&name);
        ensure!(
            canonical,
            "malformed restart parked ack writing candidate is preserved: {}",
            path.display()
        );
        ensure!(
            writing.replace(path).is_none(),
            "multiple restart parked ack writing candidates are ambiguous and preserved"
        );
    }
    let Some(writing) = writing else {
        return Ok(());
    };
    let target = private_root.join(RESTART_PARKED_ACK_CERTIFICATE_FILE_V1);
    ensure!(
        !path_exists_no_follow_v1(&target, "restart parked ack target")?,
        "restart parked ack target coexists with an impossible writing candidate"
    );
    revalidate_publication_root_v1(private_root, root_file, root_identity)?;
    cleanup_one_interrupted_writing_candidate_v1(
        private_root,
        root_file,
        root_identity,
        expected_bytes,
        &writing,
        next,
    )
}

fn create_complete_writing_candidate_v1(private_root: &Path, bytes: &[u8]) -> Result<PathBuf> {
    let name = next_writing_file_name_v1();
    let writing = private_root.join(&name);
    ensure!(
        writing.parent() == Some(private_root)
            && writing.file_name() == Some(OsStr::new(&name))
            && writing_candidate_v1(OsStr::new(&name)) == Some(true),
        "restart parked ack writing candidate escaped its unique private path"
    );
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(&writing)
        .context("create-new unique restart parked ack writing candidate")?;
    file.set_permissions(fs::Permissions::from_mode(0o600))
        .context("chmod unique restart parked ack writing candidate")?;
    file.write_all(bytes)
        .context("write unique restart parked ack writing candidate")?;
    file.sync_all()
        .context("fsync unique restart parked ack writing candidate")?;
    drop(file);
    validate_publication_candidate_v1(&writing, bytes, 1)?;
    Ok(writing)
}

fn publish_complete_writing_candidate_v1(
    private_root: &Path,
    root_file: &File,
    root_identity: DirectoryIdentityV1,
    bytes: &[u8],
    writing: &Path,
    next: &Path,
) -> Result<()> {
    validate_publication_candidate_v1(writing, bytes, 1)?;
    match fs::hard_link(writing, next) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => {
            return Err(error)
                .context("link complete restart parked ack writing candidate no-replace")
        }
    }
    let writing_linked = validate_publication_candidate_v1(writing, bytes, 2)?;
    let next_metadata =
        fs::symlink_metadata(next).context("inspect linked fixed restart parked ack candidate")?;
    ensure!(
        !next_metadata.file_type().is_symlink()
            && writing_linked.matches_metadata_v1(&next_metadata),
        "restart parked ack writing candidate did not link to the exact fixed candidate inode"
    );
    root_file
        .sync_all()
        .context("fsync linked restart parked ack writing candidate")?;
    revalidate_publication_root_v1(private_root, root_file, root_identity)?;
    fs::remove_file(writing)
        .context("remove linked unique restart parked ack writing candidate")?;
    root_file
        .sync_all()
        .context("fsync fixed restart parked ack candidate publication")?;
    revalidate_publication_root_v1(private_root, root_file, root_identity)?;
    validate_publication_candidate_v1(next, bytes, 1)?;
    Ok(())
}

fn publish_create_new_v1(private_root: &Path, bytes: &[u8]) -> Result<()> {
    validate_encoded_bound_v1(bytes)?;
    let (root_file, root_identity) = open_private_root_v1(private_root)?;
    root_file
        .try_lock()
        .context("lock restart parked ack private root publication lifetime")?;
    let target = private_root.join(RESTART_PARKED_ACK_CERTIFICATE_FILE_V1);
    let next = private_root.join(RESTART_PARKED_ACK_CERTIFICATE_NEXT_V1);
    ensure!(
        target.parent() == Some(private_root)
            && target.file_name() == Some(OsStr::new(RESTART_PARKED_ACK_CERTIFICATE_FILE_V1))
            && next.parent() == Some(private_root)
            && next.file_name() == Some(OsStr::new(RESTART_PARKED_ACK_CERTIFICATE_NEXT_V1)),
        "restart parked ack artifact target escaped its fixed private path"
    );

    cleanup_interrupted_writing_candidates_v1(
        private_root,
        &root_file,
        root_identity,
        bytes,
        &next,
    )?;
    ensure_no_publication_sidecars_except_v1(
        private_root,
        Some(RESTART_PARKED_ACK_CERTIFICATE_NEXT_V1),
    )?;

    let target_exists = path_exists_no_follow_v1(&target, "restart parked ack target")?;
    let next_exists = path_exists_no_follow_v1(&next, "restart parked ack next candidate")?;
    if target_exists && !next_exists {
        validate_publication_candidate_v1(&target, bytes, 1)?;
        revalidate_publication_root_v1(private_root, &root_file, root_identity)?;
        drop(root_file);
        return Ok(());
    }

    if !next_exists {
        let writing = create_complete_writing_candidate_v1(private_root, bytes)?;
        publish_complete_writing_candidate_v1(
            private_root,
            &root_file,
            root_identity,
            bytes,
            &writing,
            &next,
        )?;
    }

    let next_identity =
        validate_publication_candidate_v1(&next, bytes, if target_exists { 2 } else { 1 })?;
    if target_exists {
        let target_metadata = fs::symlink_metadata(&target)
            .context("inspect restart parked ack response-loss target")?;
        ensure!(
            !target_metadata.file_type().is_symlink()
                && next_identity.matches_metadata_v1(&target_metadata),
            "restart parked ack target and publication candidate are not one exact response-loss inode"
        );
    } else {
        match fs::hard_link(&next, &target) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => {
                return Err(error).context("publish restart parked ack cut without replacement")
            }
        }
        let next_after_link = validate_publication_candidate_v1(&next, bytes, 2)?;
        let target_metadata =
            fs::symlink_metadata(&target).context("inspect published restart parked ack target")?;
        ensure!(
            !target_metadata.file_type().is_symlink()
                && next_after_link.matches_metadata_v1(&target_metadata),
            "restart parked ack no-replace publication did not create one exact linked target"
        );
    }

    root_file
        .sync_all()
        .context("fsync restart parked ack linked publication")?;
    fs::remove_file(&next).context("remove committed restart parked ack publication candidate")?;
    root_file
        .sync_all()
        .context("fsync restart parked ack final publication")?;
    revalidate_publication_root_v1(private_root, &root_file, root_identity)?;
    drop(root_file);
    ensure_no_publication_sidecars_v1(private_root)?;
    let (_, observed, _) = open_and_read_artifact_v1(private_root)?;
    ensure!(
        observed == bytes,
        "published restart parked ack cut differs from exact canonical input"
    );
    Ok(())
}

fn path_exists_no_follow_v1(path: &Path, label: &str) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error).with_context(|| format!("inspect {label} publication path")),
    }
}

fn validate_publication_candidate_v1(
    path: &Path,
    expected_bytes: &[u8],
    expected_links: u64,
) -> Result<ArtifactIdentityV1> {
    let before =
        fs::symlink_metadata(path).context("inspect restart parked ack publication candidate")?;
    ensure!(
        !before.file_type().is_symlink()
            && before.is_file()
            && before.permissions().mode() & 0o7777 == 0o600
            && before.uid() == effective_uid_v1()
            && before.nlink() == expected_links
            && before.len() == u64::try_from(expected_bytes.len()).unwrap_or(u64::MAX)
            && before.len()
                <= u64::try_from(MAX_RESTART_PARKED_ACK_CERTIFICATE_BYTES_V1).unwrap_or(u64::MAX),
        "restart parked ack publication candidate has invalid private metadata"
    );
    let expected_identity = ArtifactIdentityV1::from_metadata_v1(&before);
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .context("open restart parked ack publication candidate")?;
    let opened = file
        .metadata()
        .context("inspect opened restart parked ack publication candidate")?;
    ensure!(
        expected_identity.matches_metadata_v1(&opened),
        "restart parked ack publication candidate changed while opening"
    );
    let mut observed = Vec::with_capacity(expected_bytes.len());
    Read::by_ref(&mut file)
        .take(u64::try_from(MAX_RESTART_PARKED_ACK_CERTIFICATE_BYTES_V1).unwrap_or(u64::MAX) + 1)
        .read_to_end(&mut observed)
        .context("read restart parked ack publication candidate")?;
    let after = file
        .metadata()
        .context("reinspect restart parked ack publication candidate")?;
    let path_after = fs::symlink_metadata(path)
        .context("reinspect restart parked ack publication candidate path")?;
    ensure!(
        observed == expected_bytes
            && expected_identity.matches_metadata_v1(&after)
            && expected_identity.matches_metadata_v1(&path_after),
        "restart parked ack publication candidate is partial, mutated, or foreign"
    );
    Ok(expected_identity)
}

fn open_and_read_artifact_v1(
    private_root: &Path,
) -> Result<(PinnedRestartParkedAckArtifactV1, Vec<u8>, [u8; 32])> {
    let (root_file, root_identity) = open_private_root_v1(private_root)?;
    ensure_no_publication_sidecars_v1(private_root)?;
    let path = private_root.join(RESTART_PARKED_ACK_CERTIFICATE_FILE_V1);
    ensure!(
        path.parent() == Some(private_root)
            && path.file_name() == Some(OsStr::new(RESTART_PARKED_ACK_CERTIFICATE_FILE_V1)),
        "restart parked ack artifact path escaped its fixed private root"
    );

    let before = fs::symlink_metadata(&path).context("inspect restart parked ack cut path")?;
    ensure!(
        !before.file_type().is_symlink(),
        "restart parked ack cut path is a symlink"
    );
    validate_private_artifact_metadata_v1(&before)?;
    let expected_identity = ArtifactIdentityV1::from_metadata_v1(&before);

    let mut artifact_file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(&path)
        .context("open restart parked ack cut")?;
    let opened = artifact_file
        .metadata()
        .context("inspect opened restart parked ack cut")?;
    validate_private_artifact_metadata_v1(&opened)?;
    ensure!(
        expected_identity.matches_metadata_v1(&opened),
        "restart parked ack cut identity changed while opening"
    );

    artifact_file
        .seek(SeekFrom::Start(0))
        .context("seek restart parked ack cut")?;
    let mut bytes = Vec::with_capacity(
        usize::try_from(opened.len()).context("restart parked ack cut byte length overflows")?,
    );
    Read::by_ref(&mut artifact_file)
        .take(u64::try_from(MAX_RESTART_PARKED_ACK_CERTIFICATE_BYTES_V1).unwrap_or(u64::MAX) + 1)
        .read_to_end(&mut bytes)
        .context("read restart parked ack cut")?;
    ensure!(
        bytes.len() == usize::try_from(opened.len()).unwrap_or(usize::MAX)
            && bytes.len() <= MAX_RESTART_PARKED_ACK_CERTIFICATE_BYTES_V1,
        "restart parked ack cut byte length changed while reading"
    );
    let observed_sha256 = sha256_v1(&bytes);

    let after_handle = artifact_file
        .metadata()
        .context("reinspect opened restart parked ack cut")?;
    let after_path =
        fs::symlink_metadata(&path).context("reinspect restart parked ack cut path")?;
    ensure!(
        !after_path.file_type().is_symlink()
            && expected_identity.matches_metadata_v1(&after_handle)
            && expected_identity.matches_metadata_v1(&after_path),
        "restart parked ack cut identity changed during stat/read/hash"
    );
    let root_after = root_file
        .metadata()
        .context("reinspect restart parked ack private root after artifact read")?;
    ensure!(
        root_identity.matches_metadata_v1(&root_after),
        "restart parked ack private root changed during artifact read"
    );
    ensure_no_publication_sidecars_v1(private_root)?;

    Ok((
        PinnedRestartParkedAckArtifactV1 {
            root_path: private_root.to_path_buf(),
            path,
            root_file,
            artifact_file,
            root_identity,
            artifact_identity: expected_identity,
        },
        bytes,
        observed_sha256,
    ))
}

fn open_private_root_v1(root: &Path) -> Result<(File, DirectoryIdentityV1)> {
    ensure!(
        root.is_absolute(),
        "restart parked ack private root is not absolute"
    );
    let before = fs::symlink_metadata(root).context("inspect restart parked ack private root")?;
    ensure!(
        !before.file_type().is_symlink(),
        "restart parked ack private root is a symlink"
    );
    validate_private_root_metadata_v1(&before)?;
    let canonical =
        fs::canonicalize(root).context("canonicalize restart parked ack private root")?;
    ensure!(
        canonical == root,
        "restart parked ack private root has a symlink or non-canonical ancestor"
    );
    let expected = DirectoryIdentityV1::from_metadata_v1(&before);
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(root)
        .context("open restart parked ack private root")?;
    let opened = file
        .metadata()
        .context("inspect opened restart parked ack private root")?;
    validate_private_root_metadata_v1(&opened)?;
    let after = fs::symlink_metadata(root).context("reinspect restart parked ack private root")?;
    ensure!(
        !after.file_type().is_symlink()
            && expected.matches_metadata_v1(&opened)
            && expected.matches_metadata_v1(&after),
        "restart parked ack private root identity changed while opening"
    );
    Ok((file, expected))
}

fn validate_private_root_metadata_v1(metadata: &fs::Metadata) -> Result<()> {
    ensure!(
        metadata.is_dir()
            && metadata.uid() == effective_uid_v1()
            && metadata.permissions().mode() & 0o7777 == 0o700,
        "restart parked ack private root is not one effective-user-owned 0700 directory"
    );
    Ok(())
}

fn validate_private_artifact_metadata_v1(metadata: &fs::Metadata) -> Result<()> {
    ensure!(
        metadata.is_file()
            && metadata.permissions().mode() & 0o7777 == 0o600
            && metadata.nlink() == 1
            && metadata.uid() == effective_uid_v1()
            && metadata.len() > 0
            && metadata.len()
                <= u64::try_from(MAX_RESTART_PARKED_ACK_CERTIFICATE_BYTES_V1).unwrap_or(u64::MAX),
        "restart parked ack cut is not one exact effective-user-owned private regular file"
    );
    Ok(())
}

fn ensure_no_publication_sidecars_v1(root: &Path) -> Result<()> {
    ensure_no_publication_sidecars_except_v1(root, None)
}

fn ensure_no_publication_sidecars_except_v1(root: &Path, allowed: Option<&str>) -> Result<()> {
    for name in RESTART_PARKED_ACK_CERTIFICATE_SIDECARS_V1 {
        if allowed == Some(name) {
            continue;
        }
        let path = root.join(name);
        match fs::symlink_metadata(&path) {
            Ok(_) => bail!(
                "restart parked ack publication sidecar unexpectedly exists: {}",
                path.display()
            ),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error).with_context(|| {
                    format!("inspect restart parked ack sidecar {}", path.display())
                })
            }
        }
    }
    for entry in
        fs::read_dir(root).context("scan restart parked ack private root for writing sidecars")?
    {
        let entry = entry.context("read restart parked ack private-root sidecar entry")?;
        if writing_candidate_v1(&entry.file_name()).is_some() {
            bail!(
                "restart parked ack publication writing sidecar unexpectedly exists: {}",
                entry.path().display()
            );
        }
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use std::{
        fs,
        io::Write,
        os::unix::fs::{symlink, MetadataExt, OpenOptionsExt, PermissionsExt},
        path::Path,
    };

    use ed25519_dalek::{Signer, SigningKey};
    use tempfile::TempDir;
    use trnm_consensus_signer_journal::SignerWatermarkV0;
    use trnm_consensus_types::{
        BlockId, CertificateId, ChainId, ConsensusParametersV0, ConsensusPublicKey, Epoch,
        GenesisHash, Height, ProtocolVersion, QcRef, StateRoot, Validator, ValidatorId,
        ValidatorSet, View, VotingPower,
    };

    use crate::{
        fleet_barrier::{
            CommonCampaignContextV1, CommonChainCutV1, FleetBarrierTransportV1,
            FleetCampaignCapacitiesV1, FleetCampaignIdentityV1, FleetCampaignRequestV1,
            FleetMeshSessionDirectionV1, FleetMeshSessionSetV1, FleetMeshSessionV1,
            FleetReadySetV1, FleetStartCertificateV1, LocalReadyCutV1, SignedFleetReadyV1,
            SignedFleetStartV1,
        },
        restart_cut::{
            LocalRestartParkV1, RestartCutBodyV1, RestartCutCertificateV1, RestartCutStateV1,
            RestartParkCertificateV1, RestartParkRoleV1, RestartParkedAckCertificateV1,
            RestartParkedAckCommonV1, SignedLocalRestartParkV1, SignedRestartCutV1,
            SignedRestartParkedAckV1,
        },
    };

    use super::*;

    fn validator_fixture() -> (ValidatorSet, Vec<SigningKey>) {
        let keys = (0..7)
            .map(|index| SigningKey::from_bytes(&[0x31 + index; 32]))
            .collect::<Vec<_>>();
        let parameters = ConsensusParametersV0::reference_shadow_v0();
        let validators = keys
            .iter()
            .enumerate()
            .map(|(index, key)| {
                Validator::new(
                    ValidatorId::new([0x11 + u8::try_from(index).unwrap(); 32]),
                    ConsensusPublicKey::new(key.verifying_key().to_bytes()),
                    VotingPower::new(1).unwrap(),
                )
                .unwrap()
            })
            .collect();
        let set = ValidatorSet::new(
            GenesisHash::new([0x21; 32]),
            ChainId::new("trnm-poco-g3-restart-cut-test").unwrap(),
            ProtocolVersion::V0,
            Epoch::new(0),
            parameters.hash(),
            validators,
        )
        .unwrap();
        (set, keys)
    }

    fn campaign(set: &ValidatorSet) -> CommonCampaignContextV1 {
        CommonCampaignContextV1::new(
            FleetCampaignIdentityV1::new(
                "poco-g3-7-20260814T000000Z-89abcdef".to_owned(),
                set.chain_id(),
                *set.genesis_hash().as_bytes(),
                *set.id().as_bytes(),
                [0x41; 32],
                [0x42; 32],
                [0x43; 32],
                [0x44; 32],
                [0x45; 32],
                [0x46; 32],
                [0x47; 32],
                u32::try_from(set.validators().len()).unwrap(),
            )
            .unwrap(),
            FleetCampaignRequestV1::new(
                1,
                4,
                60,
                2,
                30,
                30,
                100,
                103,
                FleetBarrierTransportV1::Direct,
            )
            .unwrap(),
            FleetCampaignCapacitiesV1::new(4_096, 60, 163, 160, 60, 220, 8_192, 160, 161, 321, 108)
                .unwrap(),
            CommonChainCutV1::new(
                3, 4, 0, [0x50; 32], 3, 3, [0x51; 32], 1, [0x52; 32], 3, [0x53; 32], 3, [0x53; 32],
                [0x54; 32], 5, 2, 5,
            )
            .unwrap(),
        )
        .unwrap()
    }

    fn mesh_and_local_cut(
        set: &ValidatorSet,
        index: usize,
    ) -> (FleetMeshSessionSetV1, LocalReadyCutV1) {
        let local = set.validators()[index].id();
        let mut sessions = Vec::new();
        for (remote_index, remote) in set.validators().iter().enumerate() {
            if remote.id() == local {
                continue;
            }
            sessions.push(
                FleetMeshSessionV1::new(
                    FleetMeshSessionDirectionV1::Incoming,
                    remote.id(),
                    [0x20 + u8::try_from(remote_index * set.validators().len() + index).unwrap();
                        32],
                )
                .unwrap(),
            );
            sessions.push(
                FleetMeshSessionV1::new(
                    FleetMeshSessionDirectionV1::Outgoing,
                    remote.id(),
                    [0x20 + u8::try_from(index * set.validators().len() + remote_index).unwrap();
                        32],
                )
                .unwrap(),
            );
        }
        let mesh = FleetMeshSessionSetV1::new(local, sessions, set).unwrap();
        let local_cut = LocalReadyCutV1::new(
            local,
            [0x61 + u8::try_from(index).unwrap(); 32],
            1,
            10 + u64::try_from(index).unwrap(),
            [0x71 + u8::try_from(index).unwrap(); 32],
            &mesh,
            [0x91 + u8::try_from(index).unwrap(); 32],
            [0xa1 + u8::try_from(index).unwrap(); 32],
            [0xb1 + u8::try_from(index).unwrap(); 32],
            [0xc1 + u8::try_from(index).unwrap(); 32],
        )
        .unwrap();
        (mesh, local_cut)
    }

    fn fleet_start_certificate(
        set: &ValidatorSet,
        keys: &[SigningKey],
        campaign: &CommonCampaignContextV1,
        event_salt: u8,
    ) -> FleetStartCertificateV1 {
        let ready = keys
            .iter()
            .enumerate()
            .map(|(index, key)| {
                let (mesh, local_cut) = mesh_and_local_cut(set, index);
                SignedFleetReadyV1::new(campaign.clone(), local_cut, mesh, set, key).unwrap()
            })
            .collect::<Vec<_>>();
        let ready_set = FleetReadySetV1::new(campaign.clone(), ready.clone(), set).unwrap();
        let starts = ready
            .iter()
            .zip(keys)
            .enumerate()
            .map(|(index, (ready, key))| {
                SignedFleetStartV1::new(
                    ready,
                    &ready_set,
                    ready.local_cut().pre_ready_journal_sequence() + 1,
                    [event_salt + u8::try_from(index).unwrap(); 32],
                    set,
                    key,
                )
                .unwrap()
            })
            .collect();
        FleetStartCertificateV1::new(ready_set, starts, set).unwrap()
    }

    fn restart_state(set: &ValidatorSet) -> RestartCutStateV1 {
        RestartCutStateV1 {
            epoch: Epoch::new(0),
            current_view: View::new(10),
            direct_high_qc: QcRef::new(
                CertificateId::new([0x81; 32]),
                Epoch::new(0),
                View::new(9),
                Height::new(8),
                BlockId::new([0x82; 32]),
                set.id(),
            ),
            proposal_parent_height: Height::new(8),
            proposal_parent_block_id: BlockId::new([0x82; 32]),
            finalized_height: Height::new(6),
            finalized_block_id: BlockId::new([0x83; 32]),
            finalized_chain_root: [0x8f; 32],
            application_height: Height::new(6),
            application_block_id: BlockId::new([0x83; 32]),
            application_state_root: StateRoot::new([0x84; 32]),
            external_checkpoint_generation: 12,
            external_checkpoint_checksum: [0x85; 32],
            safety_revision: 13,
            safety_state_record_checksum: [0x8c; 32],
            safety_record_chain_checksum: [0x8d; 32],
            signer_watermark: SignerWatermarkV0::from_persisted_parts(
                [0x89; 32], [0x8a; 32], 6, [0x8b; 32],
            )
            .unwrap(),
            signer_durable_vote_intent_count: 2,
            signer_durable_timeout_intent_count: 1,
            signer_signed_vote_intent_count: 2,
            signer_signed_timeout_intent_count: 1,
            signer_inventory_digest: [0x8e; 32],
            pending_sign: None,
            replay_archive_context_sha256: [0x86; 32],
            replay_archive_head_sequence: 4,
            replay_archive_head_sha256: [0x87; 32],
            runtime_journal_head_sequence: 20,
            runtime_journal_head_sha256: [0x88; 32],
        }
    }

    fn restart_target_config_sha256(
        set: &ValidatorSet,
        start: &FleetStartCertificateV1,
    ) -> [u8; 32] {
        restart_local_config_sha256(set, start, 2)
    }

    fn restart_local_config_sha256(
        set: &ValidatorSet,
        start: &FleetStartCertificateV1,
        index: usize,
    ) -> [u8; 32] {
        start
            .ready_set()
            .statement(set.validators()[index].id())
            .expect("local Ready statement exists")
            .local_cut()
            .config_sha256()
    }

    fn restart_body(
        set: &ValidatorSet,
        campaign: &CommonCampaignContextV1,
        start: &FleetStartCertificateV1,
    ) -> RestartCutBodyV1 {
        RestartCutBodyV1::new(
            campaign.clone(),
            set.validators()[2].id(),
            restart_target_config_sha256(set, start),
            1,
            restart_state(set),
            start,
            set,
        )
        .unwrap()
    }

    fn peer_restart_state(set: &ValidatorSet, salt: u8) -> RestartCutStateV1 {
        let mut state = restart_state(set);
        state.external_checkpoint_checksum = [salt; 32];
        state.safety_revision += 1;
        state.safety_state_record_checksum = [salt.wrapping_add(1); 32];
        state.safety_record_chain_checksum = [salt.wrapping_add(2); 32];
        state.signer_watermark = SignerWatermarkV0::from_persisted_parts(
            [salt.wrapping_add(3); 32],
            [salt.wrapping_add(4); 32],
            6,
            [salt.wrapping_add(5); 32],
        )
        .unwrap();
        state.signer_inventory_digest = [salt.wrapping_add(6); 32];
        state.replay_archive_context_sha256 = [salt.wrapping_add(7); 32];
        state.replay_archive_head_sha256 = [salt.wrapping_add(8); 32];
        state.runtime_journal_head_sha256 = [salt.wrapping_add(9); 32];
        state
    }

    fn target_restart_park(
        set: &ValidatorSet,
        start: &FleetStartCertificateV1,
        body: &RestartCutBodyV1,
    ) -> LocalRestartParkV1 {
        LocalRestartParkV1::new(
            RestartParkRoleV1::Target,
            body.target_validator(),
            body.target_config_sha256(),
            body.process_instance(),
            body,
            body.state(),
            start,
            set,
        )
        .unwrap()
    }

    fn peer_restart_park(
        set: &ValidatorSet,
        start: &FleetStartCertificateV1,
        body: &RestartCutBodyV1,
        index: usize,
    ) -> LocalRestartParkV1 {
        assert_ne!(set.validators()[index].id(), body.target_validator());
        LocalRestartParkV1::new(
            RestartParkRoleV1::Peer,
            set.validators()[index].id(),
            restart_local_config_sha256(set, start, index),
            body.process_instance(),
            body,
            peer_restart_state(set, 0xa0 + u8::try_from(index).unwrap()),
            start,
            set,
        )
        .unwrap()
    }

    fn signed_park_statement(
        set: &ValidatorSet,
        keys: &[SigningKey],
        start: &FleetStartCertificateV1,
        body: &RestartCutBodyV1,
        park: LocalRestartParkV1,
    ) -> SignedLocalRestartParkV1 {
        let index = set
            .validators()
            .iter()
            .position(|validator| validator.id() == park.local_validator())
            .expect("park origin exists");
        let digest = SignedLocalRestartParkV1::signing_digest_for_parts(
            park.local_validator(),
            body,
            &park,
            start,
            set,
        )
        .unwrap();
        SignedLocalRestartParkV1::from_parts(
            park.local_validator(),
            body,
            park,
            keys[index].sign(&digest).to_bytes(),
            start,
            set,
        )
        .unwrap()
    }

    fn park_statements(
        set: &ValidatorSet,
        keys: &[SigningKey],
        start: &FleetStartCertificateV1,
        body: &RestartCutBodyV1,
    ) -> Vec<SignedLocalRestartParkV1> {
        set.validators()
            .iter()
            .enumerate()
            .map(|(index, validator)| {
                let park = if validator.id() == body.target_validator() {
                    target_restart_park(set, start, body)
                } else {
                    peer_restart_park(set, start, body, index)
                };
                signed_park_statement(set, keys, start, body, park)
            })
            .collect()
    }

    fn cut_statements(
        set: &ValidatorSet,
        keys: &[SigningKey],
        body: &RestartCutBodyV1,
    ) -> Vec<SignedRestartCutV1> {
        set.validators()
            .iter()
            .zip(keys)
            .map(|(validator, key)| {
                SignedRestartCutV1::new(validator.id(), body.clone(), set, key).unwrap()
            })
            .collect()
    }

    fn ack_statements(
        set: &ValidatorSet,
        keys: &[SigningKey],
        fleet_start: &FleetStartCertificateV1,
        cut: &RestartCutCertificateV1,
        park: &RestartParkCertificateV1,
        admission_set_sha256: [u8; 32],
    ) -> (RestartParkedAckCommonV1, Vec<SignedRestartParkedAckV1>) {
        let common =
            RestartParkedAckCommonV1::new(fleet_start, cut, park, admission_set_sha256, set)
                .unwrap();
        let statements = set
            .validators()
            .iter()
            .zip(keys)
            .enumerate()
            .map(|(index, (validator, key))| {
                let parked = park.statement(validator.id()).unwrap();
                let local_park = parked.local_park();
                let predecessor_sequence = local_park.local_state().runtime_journal_head_sequence;
                let predecessor_sha256 = local_park.local_state().runtime_journal_head_sha256;
                let restart_cut_event_sequence = predecessor_sequence + 1;
                let restart_cut_event_sha256 = [0x31 + u8::try_from(index).unwrap(); 32];
                let restart_park_event_sequence = restart_cut_event_sequence + 1;
                let restart_park_event_sha256 = [0x41 + u8::try_from(index).unwrap(); 32];
                let digest = SignedRestartParkedAckV1::signing_digest_for_parts(
                    common,
                    validator.id(),
                    local_park.role(),
                    local_park.local_config_sha256(),
                    parked.statement_sha256(),
                    predecessor_sequence,
                    predecessor_sha256,
                    restart_cut_event_sequence,
                    restart_cut_event_sha256,
                    restart_park_event_sequence,
                    restart_park_event_sha256,
                    fleet_start,
                    cut,
                    park,
                    admission_set_sha256,
                    set,
                )
                .unwrap();
                SignedRestartParkedAckV1::from_parts(
                    common,
                    validator.id(),
                    local_park.role(),
                    local_park.local_config_sha256(),
                    parked.statement_sha256(),
                    predecessor_sequence,
                    predecessor_sha256,
                    restart_cut_event_sequence,
                    restart_cut_event_sha256,
                    restart_park_event_sequence,
                    restart_park_event_sha256,
                    key.sign(&digest).to_bytes(),
                    fleet_start,
                    cut,
                    park,
                    admission_set_sha256,
                    set,
                )
                .unwrap()
            })
            .collect();
        (common, statements)
    }

    fn witness_for(
        certificate: &RestartParkedAckCertificateV1,
        local_validator: ValidatorId,
    ) -> RestartParkedAckLocalWitnessV1 {
        // This is deliberately only a data fixture for the inert store join.
        // It does not manufacture journal provenance: production end-to-end
        // tests must obtain these facts from the non-Clone journal commit
        // owner after freshly replaying the real journal.
        let statement = certificate.statement(local_validator).unwrap();
        RestartParkedAckLocalWitnessV1::new(
            statement.role(),
            statement.local_park_statement_sha256(),
            statement.predecessor_sequence(),
            statement.predecessor_sha256(),
            statement.restart_cut_event_sequence(),
            statement.restart_cut_event_sha256(),
            statement.restart_park_event_sequence(),
            statement.restart_park_event_sha256(),
        )
        .unwrap()
    }

    struct Fixture {
        set: ValidatorSet,
        fleet_start: FleetStartCertificateV1,
        cut: RestartCutCertificateV1,
        cut_artifact_sha256: [u8; 32],
        park: RestartParkCertificateV1,
        park_artifact_sha256: [u8; 32],
        admission_set_sha256: [u8; 32],
        certificate: RestartParkedAckCertificateV1,
        artifact_sha256: [u8; 32],
        local_validator: ValidatorId,
        local_config_sha256: [u8; 32],
        local_witness: RestartParkedAckLocalWitnessV1,
    }

    #[derive(Clone, Copy)]
    struct PersistTestInputs<'a> {
        artifact_sha256: [u8; 32],
        certificate: &'a RestartParkedAckCertificateV1,
        cut_artifact_sha256: [u8; 32],
        cut: &'a RestartCutCertificateV1,
        park_artifact_sha256: [u8; 32],
        park: &'a RestartParkCertificateV1,
        admission_set_sha256: [u8; 32],
        local_validator: ValidatorId,
        local_config_sha256: [u8; 32],
        local_witness: RestartParkedAckLocalWitnessV1,
        fleet_start: &'a FleetStartCertificateV1,
        set: &'a ValidatorSet,
    }

    impl<'a> PersistTestInputs<'a> {
        fn from_fixture(fixture: &'a Fixture) -> Self {
            Self {
                artifact_sha256: fixture.artifact_sha256,
                certificate: &fixture.certificate,
                cut_artifact_sha256: fixture.cut_artifact_sha256,
                cut: &fixture.cut,
                park_artifact_sha256: fixture.park_artifact_sha256,
                park: &fixture.park,
                admission_set_sha256: fixture.admission_set_sha256,
                local_validator: fixture.local_validator,
                local_config_sha256: fixture.local_config_sha256,
                local_witness: fixture.local_witness,
                fleet_start: &fixture.fleet_start,
                set: &fixture.set,
            }
        }
    }

    fn fixture_with_start_salt(start_salt: u8) -> Fixture {
        let (set, keys) = validator_fixture();
        let campaign = campaign(&set);
        let fleet_start = fleet_start_certificate(&set, &keys, &campaign, start_salt);
        let body = restart_body(&set, &campaign, &fleet_start);
        let cut =
            RestartCutCertificateV1::new(cut_statements(&set, &keys, &body), &fleet_start, &set)
                .unwrap();
        let park = RestartParkCertificateV1::new(
            body,
            park_statements(&set, &keys, &fleet_start, cut.body()),
            &fleet_start,
            &set,
        )
        .unwrap();
        let cut_artifact_sha256 = sha256_v1(&cut.encode());
        let park_artifact_sha256 = sha256_v1(&park.encode());
        let admission_set_sha256 = [0xad; 32];
        let (common, statements) =
            ack_statements(&set, &keys, &fleet_start, &cut, &park, admission_set_sha256);
        let certificate = RestartParkedAckCertificateV1::new(
            common,
            statements,
            &fleet_start,
            &cut,
            &park,
            admission_set_sha256,
            &set,
        )
        .unwrap();
        let artifact_sha256 = sha256_v1(&certificate.encode());
        let local_validator = cut.body().target_validator();
        let local_config_sha256 = cut.body().target_config_sha256();
        let local_witness = witness_for(&certificate, local_validator);
        Fixture {
            set,
            fleet_start,
            cut,
            cut_artifact_sha256,
            park,
            park_artifact_sha256,
            admission_set_sha256,
            certificate,
            artifact_sha256,
            local_validator,
            local_config_sha256,
            local_witness,
        }
    }

    fn fixture() -> Fixture {
        fixture_with_start_salt(0xd0)
    }

    fn other_validator_set(fixture: &Fixture) -> ValidatorSet {
        let mut validators = fixture.set.validators().to_vec();
        validators[6] = Validator::new(
            ValidatorId::new([0xf1; 32]),
            ConsensusPublicKey::new(
                SigningKey::from_bytes(&[0xf2; 32])
                    .verifying_key()
                    .to_bytes(),
            ),
            VotingPower::new(1).unwrap(),
        )
        .unwrap();
        ValidatorSet::new(
            fixture.set.genesis_hash(),
            fixture.set.chain_id(),
            fixture.set.protocol_version(),
            fixture.set.epoch(),
            fixture.set.consensus_parameters_hash(),
            validators,
        )
        .unwrap()
    }

    fn alternate_restart_cut_certificate(fixture: &Fixture) -> RestartCutCertificateV1 {
        let (same_set, keys) = validator_fixture();
        assert_eq!(same_set, fixture.set);
        let mut state = restart_state(&fixture.set);
        state.runtime_journal_head_sha256 = [0xf3; 32];
        let body = RestartCutBodyV1::new(
            campaign(&fixture.set),
            fixture.cut.body().target_validator(),
            fixture.cut.body().target_config_sha256(),
            fixture.cut.body().process_instance(),
            state,
            &fixture.fleet_start,
            &fixture.set,
        )
        .unwrap();
        RestartCutCertificateV1::new(
            cut_statements(&fixture.set, &keys, &body),
            &fixture.fleet_start,
            &fixture.set,
        )
        .unwrap()
    }

    fn alternate_restart_park_certificate(fixture: &Fixture) -> RestartParkCertificateV1 {
        let (same_set, keys) = validator_fixture();
        assert_eq!(same_set, fixture.set);
        let body = fixture.cut.body().clone();
        let statements = fixture
            .set
            .validators()
            .iter()
            .enumerate()
            .map(|(index, validator)| {
                let park = if validator.id() == body.target_validator() {
                    target_restart_park(&fixture.set, &fixture.fleet_start, &body)
                } else {
                    LocalRestartParkV1::new(
                        RestartParkRoleV1::Peer,
                        validator.id(),
                        restart_local_config_sha256(&fixture.set, &fixture.fleet_start, index),
                        body.process_instance(),
                        &body,
                        peer_restart_state(&fixture.set, 0xc0 + u8::try_from(index).unwrap()),
                        &fixture.fleet_start,
                        &fixture.set,
                    )
                    .unwrap()
                };
                signed_park_statement(&fixture.set, &keys, &fixture.fleet_start, &body, park)
            })
            .collect();
        RestartParkCertificateV1::new(body, statements, &fixture.fleet_start, &fixture.set).unwrap()
    }

    fn private_root() -> TempDir {
        let temporary = TempDir::new().unwrap();
        fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(temporary.path().canonicalize().unwrap(), temporary.path());
        temporary
    }

    fn write_test_artifact(root: &Path, name: &str, bytes: &[u8]) {
        let path = root.join(name);
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .unwrap();
        file.write_all(bytes).unwrap();
        file.sync_all().unwrap();
        File::open(root).unwrap().sync_all().unwrap();
    }

    fn assert_reserved_namespace_absent(root: &Path) {
        for fixed in [
            RESTART_PARKED_ACK_CERTIFICATE_FILE_V1,
            RESTART_PARKED_ACK_CERTIFICATE_NEXT_V1,
            RESTART_PARKED_ACK_CERTIFICATE_SIDECARS_V1[1],
            RESTART_PARKED_ACK_CERTIFICATE_SIDECARS_V1[2],
        ] {
            assert!(
                !root.join(fixed).exists(),
                "rejected parked-Ack publication left reserved path {fixed}"
            );
        }
        let writing = fs::read_dir(root)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .find(|name| {
                name.as_bytes()
                    .starts_with(RESTART_PARKED_ACK_CERTIFICATE_WRITING_PREFIX_V1.as_bytes())
            });
        assert!(
            writing.is_none(),
            "rejected parked-Ack publication left writing path {writing:?}"
        );
    }

    fn assert_prepublication_rejection(
        attempt: impl FnOnce(&Path) -> anyhow::Result<StoredRestartParkedAckCertificateV1>,
    ) {
        let root = private_root();
        assert!(attempt(root.path()).is_err());
        assert_reserved_namespace_absent(root.path());
    }

    fn assert_persist_inputs_rejected_without_publication(inputs: PersistTestInputs<'_>) {
        assert_prepublication_rejection(|root| {
            persist_restart_parked_ack_certificate_v1(
                root,
                inputs.artifact_sha256,
                inputs.certificate.clone(),
                inputs.cut_artifact_sha256,
                inputs.cut,
                inputs.park_artifact_sha256,
                inputs.park,
                inputs.admission_set_sha256,
                inputs.local_validator,
                inputs.local_config_sha256,
                inputs.local_witness,
                inputs.fleet_start,
                inputs.set,
            )
        });
    }

    fn persist_result(
        fixture: &Fixture,
        root: &Path,
    ) -> anyhow::Result<StoredRestartParkedAckCertificateV1> {
        persist_restart_parked_ack_certificate_v1(
            root,
            fixture.artifact_sha256,
            fixture.certificate.clone(),
            fixture.cut_artifact_sha256,
            &fixture.cut,
            fixture.park_artifact_sha256,
            &fixture.park,
            fixture.admission_set_sha256,
            fixture.local_validator,
            fixture.local_config_sha256,
            fixture.local_witness,
            &fixture.fleet_start,
            &fixture.set,
        )
    }

    fn persist(fixture: &Fixture, root: &Path) -> StoredRestartParkedAckCertificateV1 {
        persist_result(fixture, root).unwrap()
    }

    fn load(fixture: &Fixture, root: &Path) -> anyhow::Result<StoredRestartParkedAckCertificateV1> {
        load_restart_parked_ack_certificate_v1(
            root,
            fixture.artifact_sha256,
            fixture.cut_artifact_sha256,
            &fixture.cut,
            fixture.park_artifact_sha256,
            &fixture.park,
            fixture.admission_set_sha256,
            fixture.local_validator,
            fixture.local_config_sha256,
            fixture.local_witness,
            &fixture.fleet_start,
            &fixture.set,
        )
    }

    #[test]
    fn certificate_persists_loads_idempotently_and_fresh_revalidates() {
        let fixture = fixture();
        let root = private_root();
        let stored = persist(&fixture, root.path());
        assert_eq!(stored.value_v1(), &fixture.certificate);
        assert_eq!(stored.common_v1(), fixture.certificate.common());
        assert_eq!(stored.restart_cut_certificate_v1(), &fixture.cut);
        assert_eq!(stored.restart_park_certificate_v1(), &fixture.park);
        assert_eq!(
            stored.restart_cut_artifact_sha256_v1(),
            fixture.cut_artifact_sha256
        );
        assert_eq!(
            stored.restart_park_artifact_sha256_v1(),
            fixture.park_artifact_sha256
        );
        assert_eq!(
            stored.restart_cut_park_admission_set_sha256_v1(),
            fixture.admission_set_sha256
        );
        assert_eq!(stored.local_witness_v1(), fixture.local_witness);
        assert_eq!(stored.statement_count_v1(), 7);
        assert_eq!(stored.artifact_sha256_v1(), fixture.artifact_sha256);
        assert_eq!(
            stored.local_statement_v1(),
            fixture
                .certificate
                .statement(fixture.local_validator)
                .unwrap()
        );
        stored
            .revalidate_fresh_v1(&fixture.fleet_start, &fixture.set)
            .unwrap();

        let loaded = load(&fixture, root.path()).unwrap();
        loaded
            .revalidate_fresh_v1(&fixture.fleet_start, &fixture.set)
            .unwrap();
        let metadata = fs::symlink_metadata(stored.path_v1()).unwrap();
        assert_eq!(metadata.permissions().mode() & 0o7777, 0o600);
        assert_eq!(metadata.uid(), effective_uid_v1());
        assert_eq!(metadata.nlink(), 1);
        persist(&fixture, root.path())
            .revalidate_fresh_v1(&fixture.fleet_start, &fixture.set)
            .unwrap();

        let peer = fixture
            .set
            .validators()
            .iter()
            .map(|validator| validator.id())
            .find(|validator| *validator != fixture.local_validator)
            .unwrap();
        let peer_config = fixture
            .park
            .statement(peer)
            .unwrap()
            .local_park()
            .local_config_sha256();
        let peer_witness = witness_for(&fixture.certificate, peer);
        let peer_root = private_root();
        let peer_stored = persist_restart_parked_ack_certificate_v1(
            peer_root.path(),
            fixture.artifact_sha256,
            fixture.certificate.clone(),
            fixture.cut_artifact_sha256,
            &fixture.cut,
            fixture.park_artifact_sha256,
            &fixture.park,
            fixture.admission_set_sha256,
            peer,
            peer_config,
            peer_witness,
            &fixture.fleet_start,
            &fixture.set,
        )
        .unwrap();
        assert_eq!(
            peer_stored.local_witness_v1().role_v1(),
            RestartParkRoleV1::Peer
        );
        peer_stored
            .revalidate_fresh_v1(&fixture.fleet_start, &fixture.set)
            .unwrap();
    }

    #[test]
    fn all_external_dependency_and_local_witness_joins_are_required_before_publish() {
        let fixture = fixture();
        let alternate_cut = alternate_restart_cut_certificate(&fixture);
        let alternate_park = alternate_restart_park_certificate(&fixture);
        let wrong_start = fixture_with_start_salt(0xe0);
        let wrong_set = other_validator_set(&fixture);
        assert_ne!(alternate_cut, fixture.cut);
        assert_ne!(alternate_park, fixture.park);

        // Every poison attempt receives its own empty 0700 root and exercises
        // persist, not load. Rejection must therefore precede every mutation
        // of the complete reserved publication namespace.
        let baseline = PersistTestInputs::from_fixture(&fixture);

        for artifact_sha256 in [[0; 32], [0xee; 32]] {
            let mut inputs = baseline;
            inputs.artifact_sha256 = artifact_sha256;
            assert_persist_inputs_rejected_without_publication(inputs);
        }

        for cut_artifact_sha256 in [[0; 32], [0xed; 32]] {
            let mut inputs = baseline;
            inputs.cut_artifact_sha256 = cut_artifact_sha256;
            assert_persist_inputs_rejected_without_publication(inputs);
        }
        let mut inputs = baseline;
        inputs.cut_artifact_sha256 = sha256_v1(&alternate_cut.encode());
        inputs.cut = &alternate_cut;
        assert_persist_inputs_rejected_without_publication(inputs);

        for park_artifact_sha256 in [[0; 32], [0xec; 32]] {
            let mut inputs = baseline;
            inputs.park_artifact_sha256 = park_artifact_sha256;
            assert_persist_inputs_rejected_without_publication(inputs);
        }
        let mut inputs = baseline;
        inputs.park_artifact_sha256 = sha256_v1(&alternate_park.encode());
        inputs.park = &alternate_park;
        assert_persist_inputs_rejected_without_publication(inputs);

        for admission_set_sha256 in [[0; 32], [0xeb; 32]] {
            let mut inputs = baseline;
            inputs.admission_set_sha256 = admission_set_sha256;
            assert_persist_inputs_rejected_without_publication(inputs);
        }

        let mut inputs = baseline;
        inputs.fleet_start = &wrong_start.fleet_start;
        assert_persist_inputs_rejected_without_publication(inputs);

        let mut inputs = baseline;
        inputs.set = &wrong_set;
        assert_persist_inputs_rejected_without_publication(inputs);

        let mut inputs = baseline;
        inputs.local_validator = fixture
            .set
            .validators()
            .iter()
            .map(|validator| validator.id())
            .find(|validator| *validator != fixture.local_validator)
            .unwrap();
        assert_persist_inputs_rejected_without_publication(inputs);

        for local_config_sha256 in [[0; 32], [0xea; 32]] {
            let mut inputs = baseline;
            inputs.local_config_sha256 = local_config_sha256;
            assert_persist_inputs_rejected_without_publication(inputs);
        }

        let mut witness = fixture.local_witness;
        witness.role = RestartParkRoleV1::Peer;
        let mut inputs = baseline;
        inputs.local_witness = witness;
        assert_persist_inputs_rejected_without_publication(inputs);

        let mut witness = fixture.local_witness;
        witness.local_park_statement_sha256 = [0xe1; 32];
        let mut inputs = baseline;
        inputs.local_witness = witness;
        assert_persist_inputs_rejected_without_publication(inputs);

        let mut witness = fixture.local_witness;
        witness.predecessor_sequence += 10;
        let mut inputs = baseline;
        inputs.local_witness = witness;
        assert_persist_inputs_rejected_without_publication(inputs);

        let mut witness = fixture.local_witness;
        witness.predecessor_sha256 = [0xe2; 32];
        let mut inputs = baseline;
        inputs.local_witness = witness;
        assert_persist_inputs_rejected_without_publication(inputs);

        let mut witness = fixture.local_witness;
        witness.restart_cut_event_sequence += 10;
        let mut inputs = baseline;
        inputs.local_witness = witness;
        assert_persist_inputs_rejected_without_publication(inputs);

        let mut witness = fixture.local_witness;
        witness.restart_cut_event_sha256 = [0xe3; 32];
        let mut inputs = baseline;
        inputs.local_witness = witness;
        assert_persist_inputs_rejected_without_publication(inputs);

        let mut witness = fixture.local_witness;
        witness.restart_park_event_sequence += 10;
        let mut inputs = baseline;
        inputs.local_witness = witness;
        assert_persist_inputs_rejected_without_publication(inputs);

        let mut witness = fixture.local_witness;
        witness.restart_park_event_sha256 = [0xe4; 32];
        let mut inputs = baseline;
        inputs.local_witness = witness;
        assert_persist_inputs_rejected_without_publication(inputs);
    }

    #[test]
    fn publication_reconciles_exact_next_linked_and_writing_response_loss() {
        let fixture = fixture();
        let bytes = fixture.certificate.encode();

        let next_only = private_root();
        write_test_artifact(
            next_only.path(),
            RESTART_PARKED_ACK_CERTIFICATE_NEXT_V1,
            &bytes,
        );
        drop(persist(&fixture, next_only.path()));
        assert!(!next_only
            .path()
            .join(RESTART_PARKED_ACK_CERTIFICATE_NEXT_V1)
            .exists());

        let linked = private_root();
        let target = persist(&fixture, linked.path()).path_v1().to_path_buf();
        let next = linked.path().join(RESTART_PARKED_ACK_CERTIFICATE_NEXT_V1);
        fs::hard_link(&target, &next).unwrap();
        File::open(linked.path()).unwrap().sync_all().unwrap();
        drop(persist(&fixture, linked.path()));
        assert!(!next.exists());
        assert_eq!(fs::metadata(target).unwrap().nlink(), 1);

        for (attempt, prefix_length, incomplete_mode) in [
            (1u64, 0usize, Some(0o000)),
            (2, 1, None),
            (3, bytes.len() - 1, None),
            (4, bytes.len(), None),
        ] {
            let root = private_root();
            let writing_name = writing_file_name_v1(0x71a1, attempt);
            let writing = root.path().join(&writing_name);
            write_test_artifact(root.path(), &writing_name, &bytes[..prefix_length]);
            if let Some(mode) = incomplete_mode {
                fs::set_permissions(&writing, fs::Permissions::from_mode(mode)).unwrap();
            }
            drop(persist(&fixture, root.path()));
            assert!(!writing.exists());
        }

        let root = private_root();
        let writing_name = writing_file_name_v1(0x71a2, 9);
        let writing = root.path().join(&writing_name);
        let next = root.path().join(RESTART_PARKED_ACK_CERTIFICATE_NEXT_V1);
        write_test_artifact(root.path(), &writing_name, &bytes);
        fs::hard_link(&writing, &next).unwrap();
        File::open(root.path()).unwrap().sync_all().unwrap();
        drop(persist(&fixture, root.path()));
        assert!(!writing.exists());
        assert!(!next.exists());
    }

    #[test]
    fn foreign_partial_and_ambiguous_publication_states_are_preserved() {
        let fixture = fixture();
        let bytes = fixture.certificate.encode();

        let partial_next = private_root();
        write_test_artifact(
            partial_next.path(),
            RESTART_PARKED_ACK_CERTIFICATE_NEXT_V1,
            &bytes[..bytes.len() - 1],
        );
        assert!(persist_result(&fixture, partial_next.path()).is_err());
        assert!(partial_next
            .path()
            .join(RESTART_PARKED_ACK_CERTIFICATE_NEXT_V1)
            .exists());

        let separate = private_root();
        write_test_artifact(
            separate.path(),
            RESTART_PARKED_ACK_CERTIFICATE_FILE_V1,
            &bytes,
        );
        write_test_artifact(
            separate.path(),
            RESTART_PARKED_ACK_CERTIFICATE_NEXT_V1,
            &bytes,
        );
        assert!(persist_result(&fixture, separate.path()).is_err());
        assert!(separate
            .path()
            .join(RESTART_PARKED_ACK_CERTIFICATE_FILE_V1)
            .exists());
        assert!(separate
            .path()
            .join(RESTART_PARKED_ACK_CERTIFICATE_NEXT_V1)
            .exists());

        let writing_and_foreign_next = private_root();
        let writing = writing_file_name_v1(0x71a4, 11);
        write_test_artifact(writing_and_foreign_next.path(), &writing, &bytes);
        write_test_artifact(
            writing_and_foreign_next.path(),
            RESTART_PARKED_ACK_CERTIFICATE_NEXT_V1,
            b"foreign-next",
        );
        assert!(persist_result(&fixture, writing_and_foreign_next.path()).is_err());
        assert_eq!(
            fs::read(writing_and_foreign_next.path().join(&writing)).unwrap(),
            bytes
        );
        assert_eq!(
            fs::read(
                writing_and_foreign_next
                    .path()
                    .join(RESTART_PARKED_ACK_CERTIFICATE_NEXT_V1)
            )
            .unwrap(),
            b"foreign-next"
        );

        let three_links = private_root();
        let target = three_links
            .path()
            .join(RESTART_PARKED_ACK_CERTIFICATE_FILE_V1);
        let next = three_links
            .path()
            .join(RESTART_PARKED_ACK_CERTIFICATE_NEXT_V1);
        let third = three_links.path().join("foreign-third-link.bin");
        write_test_artifact(
            three_links.path(),
            RESTART_PARKED_ACK_CERTIFICATE_FILE_V1,
            &bytes,
        );
        fs::hard_link(&target, &next).unwrap();
        fs::hard_link(&target, &third).unwrap();
        File::open(three_links.path()).unwrap().sync_all().unwrap();
        assert!(persist_result(&fixture, three_links.path()).is_err());
        assert!(target.exists());
        assert!(next.exists());
        assert!(third.exists());
        assert_eq!(fs::metadata(&target).unwrap().nlink(), 3);

        let multiple = private_root();
        let first = writing_file_name_v1(0x71a5, 12);
        let second = writing_file_name_v1(0x71a6, 13);
        write_test_artifact(multiple.path(), &first, &bytes[..1]);
        write_test_artifact(multiple.path(), &second, &bytes[..2]);
        assert!(persist_result(&fixture, multiple.path()).is_err());
        assert!(multiple.path().join(first).exists());
        assert!(multiple.path().join(second).exists());

        let target_and_writing = private_root();
        let writing = writing_file_name_v1(0x71a7, 14);
        write_test_artifact(
            target_and_writing.path(),
            RESTART_PARKED_ACK_CERTIFICATE_FILE_V1,
            &bytes,
        );
        write_test_artifact(target_and_writing.path(), &writing, &bytes[..1]);
        assert!(persist_result(&fixture, target_and_writing.path()).is_err());
        assert_eq!(
            fs::read(
                target_and_writing
                    .path()
                    .join(RESTART_PARKED_ACK_CERTIFICATE_FILE_V1)
            )
            .unwrap(),
            bytes
        );
        assert!(target_and_writing.path().join(writing).exists());

        let malformed = private_root();
        let name = format!("{RESTART_PARKED_ACK_CERTIFICATE_WRITING_PREFIX_V1}malformed");
        write_test_artifact(malformed.path(), &name, &bytes[..1]);
        assert!(persist_result(&fixture, malformed.path()).is_err());
        assert!(malformed.path().join(name).exists());

        let forbidden = private_root();
        let writing = writing_file_name_v1(0x71a9, 16);
        write_test_artifact(forbidden.path(), &writing, &bytes[..1]);
        write_test_artifact(
            forbidden.path(),
            RESTART_PARKED_ACK_CERTIFICATE_SIDECARS_V1[1],
            b"foreign",
        );
        assert!(persist_result(&fixture, forbidden.path()).is_err());
        assert!(forbidden.path().join(writing).exists());
        assert!(forbidden
            .path()
            .join(RESTART_PARKED_ACK_CERTIFICATE_SIDECARS_V1[1])
            .exists());

        let forbidden_lock = private_root();
        write_test_artifact(
            forbidden_lock.path(),
            RESTART_PARKED_ACK_CERTIFICATE_SIDECARS_V1[2],
            b"foreign-lock",
        );
        assert!(persist_result(&fixture, forbidden_lock.path()).is_err());
        assert_eq!(
            fs::read(
                forbidden_lock
                    .path()
                    .join(RESTART_PARKED_ACK_CERTIFICATE_SIDECARS_V1[2])
            )
            .unwrap(),
            b"foreign-lock"
        );
    }

    #[test]
    fn fresh_revalidation_rejects_mutation_file_replacement_and_root_replacement() {
        let fixture = fixture();
        let mutation_root = private_root();
        let stored = persist(&fixture, mutation_root.path());
        let path = stored.path_v1().to_path_buf();
        let mut bytes = fs::read(&path).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 1;
        fs::write(&path, bytes).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(stored
            .revalidate_fresh_v1(&fixture.fleet_start, &fixture.set)
            .is_err());

        let replacement_root = private_root();
        let stored = persist(&fixture, replacement_root.path());
        let path = stored.path_v1().to_path_buf();
        let bytes = fs::read(&path).unwrap();
        fs::rename(
            &path,
            replacement_root.path().join("displaced-parked-ack.bin"),
        )
        .unwrap();
        write_test_artifact(
            replacement_root.path(),
            RESTART_PARKED_ACK_CERTIFICATE_FILE_V1,
            &bytes,
        );
        assert!(stored
            .revalidate_fresh_v1(&fixture.fleet_start, &fixture.set)
            .is_err());

        let parent = TempDir::new().unwrap();
        let live_root = parent.path().join("live-root");
        let displaced_root = parent.path().join("displaced-root");
        fs::create_dir(&live_root).unwrap();
        fs::set_permissions(&live_root, fs::Permissions::from_mode(0o700)).unwrap();
        let stored = persist(&fixture, &live_root);
        fs::rename(&live_root, &displaced_root).unwrap();
        fs::create_dir(&live_root).unwrap();
        fs::set_permissions(&live_root, fs::Permissions::from_mode(0o700)).unwrap();
        write_test_artifact(
            &live_root,
            RESTART_PARKED_ACK_CERTIFICATE_FILE_V1,
            &fixture.certificate.encode(),
        );
        assert!(stored
            .revalidate_fresh_v1(&fixture.fleet_start, &fixture.set)
            .is_err());
    }

    #[test]
    fn filesystem_policy_rejects_symlink_hardlink_modes_sizes_sidecars_and_ancestry() {
        let fixture = fixture();

        let symlink_root = private_root();
        symlink(
            "/dev/null",
            symlink_root
                .path()
                .join(RESTART_PARKED_ACK_CERTIFICATE_FILE_V1),
        )
        .unwrap();
        assert!(load(&fixture, symlink_root.path()).is_err());

        let hardlink_root = private_root();
        let stored = persist(&fixture, hardlink_root.path());
        fs::hard_link(
            stored.path_v1(),
            hardlink_root.path().join("foreign-hardlink.bin"),
        )
        .unwrap();
        assert!(stored
            .revalidate_fresh_v1(&fixture.fleet_start, &fixture.set)
            .is_err());

        let artifact_mode_root = private_root();
        let stored = persist(&fixture, artifact_mode_root.path());
        fs::set_permissions(stored.path_v1(), fs::Permissions::from_mode(0o640)).unwrap();
        assert!(stored
            .revalidate_fresh_v1(&fixture.fleet_start, &fixture.set)
            .is_err());

        let root_mode = private_root();
        fs::set_permissions(root_mode.path(), fs::Permissions::from_mode(0o750)).unwrap();
        assert!(persist_result(&fixture, root_mode.path()).is_err());

        let empty = private_root();
        write_test_artifact(empty.path(), RESTART_PARKED_ACK_CERTIFICATE_FILE_V1, &[]);
        assert!(load(&fixture, empty.path()).is_err());

        let oversized = private_root();
        write_test_artifact(
            oversized.path(),
            RESTART_PARKED_ACK_CERTIFICATE_FILE_V1,
            &vec![0u8; MAX_RESTART_PARKED_ACK_CERTIFICATE_BYTES_V1 + 1],
        );
        assert!(load(&fixture, oversized.path()).is_err());

        let sidecar_root = private_root();
        let stored = persist(&fixture, sidecar_root.path());
        symlink(
            RESTART_PARKED_ACK_CERTIFICATE_FILE_V1,
            sidecar_root
                .path()
                .join(RESTART_PARKED_ACK_CERTIFICATE_SIDECARS_V1[1]),
        )
        .unwrap();
        assert!(stored
            .revalidate_fresh_v1(&fixture.fleet_start, &fixture.set)
            .is_err());

        let root_symlink_parent = TempDir::new().unwrap();
        let real_parent = root_symlink_parent.path().join("real-parent");
        let real_root = real_parent.join("private-root");
        let alias_parent = root_symlink_parent.path().join("alias-parent");
        let alias_root = alias_parent.join("private-root");
        fs::create_dir(&real_parent).unwrap();
        fs::create_dir(&real_root).unwrap();
        fs::set_permissions(&real_root, fs::Permissions::from_mode(0o700)).unwrap();
        symlink(&real_parent, &alias_parent).unwrap();
        assert!(persist_result(&fixture, &alias_root).is_err());
    }

    #[test]
    fn exact_decode_rejects_trailing_bytes_even_with_matching_raw_sha() {
        let fixture = fixture();
        let root = private_root();
        let mut trailing = fixture.certificate.encode();
        trailing.push(0);
        assert!(RestartParkedAckCertificateV1::decode(
            &trailing,
            &fixture.fleet_start,
            &fixture.cut,
            &fixture.park,
            fixture.admission_set_sha256,
            &fixture.set,
        )
        .is_err());
        write_test_artifact(
            root.path(),
            RESTART_PARKED_ACK_CERTIFICATE_FILE_V1,
            &trailing,
        );
        assert!(load_restart_parked_ack_certificate_v1(
            root.path(),
            sha256_v1(&trailing),
            fixture.cut_artifact_sha256,
            &fixture.cut,
            fixture.park_artifact_sha256,
            &fixture.park,
            fixture.admission_set_sha256,
            fixture.local_validator,
            fixture.local_config_sha256,
            fixture.local_witness,
            &fixture.fleet_start,
            &fixture.set,
        )
        .is_err());
    }

    #[test]
    fn store_has_no_signer_journal_network_recovery_or_process_authority_surface() {
        let source = include_str!("restart_parked_ack_store.rs");
        let normal = &source[..source.find("#[cfg(test)]").unwrap()];
        for forbidden in [
            "SigningKey",
            "TcpStream",
            "UdpSocket",
            "RuntimeEventJournalV1",
            "RuntimeControl",
            "ProcessHost",
            "RecoveryReadySetV1",
            "RecoveryStartCertificateV1",
            "fn activate",
            "fn arm",
            "fn append",
            "fn sign",
            "Command::new",
            "kill(",
            "set_len(",
            "OpenOptions::new().truncate",
        ] {
            assert!(
                !normal.contains(forbidden),
                "normal parked-Ack store contains forbidden authority token {forbidden}"
            );
        }
        assert!(!normal.contains("pub fn "));
        assert!(!normal.contains("impl Clone for StoredRestartParkedAckCertificateV1"));
    }
}
