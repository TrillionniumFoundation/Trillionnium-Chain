//! Canonical N/N authorization for one bounded process-1 restart cut.
//!
//! A transport frame, a local control request, or one validator's observation
//! cannot authorize killing a validator process.  Every validator therefore
//! signs the same target-local durable cut, and the resulting certificate is
//! accepted only when it contains exactly one declaration from every member
//! of the frozen validator set.  The cut binds the complete fleet campaign,
//! the exact raw FleetStartCertificate artifact, and the target's consensus,
//! finalized-prefix, application, checkpoint, signer, replay-archive, and
//! runtime-journal heads.
//!
//! This module is deliberately inert.  It has no network, process-control,
//! journal-write, signer-activation, recovery, or runtime authority.

use std::collections::BTreeMap;

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};
use trnm_consensus_signer_journal::SignerWatermarkV0;
use trnm_consensus_types::{
    BlockId, CertificateId, Epoch, Height, QcRef, StateRoot, ValidatorId, ValidatorSet,
    ValidatorSetId, View,
};

use crate::fleet_barrier::{CommonCampaignContextV1, FleetStartCertificateV1};

const CUT_BODY_MAGIC_V1: &[u8; 8] = b"TRNMRCB1";
const RESTART_SHARED_CUT_MAGIC_V1: &[u8; 8] = b"TRNMRSC1";
const LOCAL_RESTART_PARK_MAGIC_V1: &[u8; 8] = b"TRNMRLP1";
const SIGNED_LOCAL_RESTART_PARK_MAGIC_V1: &[u8; 8] = b"TRNMRPS1";
const RESTART_PARK_CERTIFICATE_MAGIC_V1: &[u8; 8] = b"TRNMRPC1";
const RESTART_PARKED_ACK_COMMON_MAGIC_V1: &[u8; 8] = b"TRNMRAB1";
const SIGNED_RESTART_PARKED_ACK_MAGIC_V1: &[u8; 8] = b"TRNMRAK1";
const RESTART_PARKED_ACK_CERTIFICATE_MAGIC_V1: &[u8; 8] = b"TRNMRAC1";
const SIGNED_CUT_MAGIC_V1: &[u8; 8] = b"TRNMRCS1";
const RESTART_CUT_PARK_STATEMENT_MAGIC_V1: &[u8; 8] = b"TRNMRDP1";
const CUT_CERTIFICATE_MAGIC_V1: &[u8; 8] = b"TRNMRCC1";
// RestartCut has never been activated by a fault runner or accepted as G3
// evidence. This mandatory Core-chain binding therefore corrects the sole
// pre-activation v1 layout; candidate bytes emitted before the correction are
// intentionally rejected instead of receiving a compatibility decoder.
const WIRE_VERSION_V1: u16 = 1;
const CUT_SIGNING_DOMAIN_V1: &[u8] = b"trnm.poco-g3.restart-cut-signature.v1";
const CUT_BODY_DIGEST_DOMAIN_V1: &[u8] = b"trnm.poco-g3.restart-cut-body.v1";
const RESTART_SHARED_CUT_DIGEST_DOMAIN_V1: &[u8] = b"trnm.poco-g3.restart-shared-cut.v1";
const LOCAL_RESTART_PARK_DIGEST_DOMAIN_V1: &[u8] = b"trnm.poco-g3.local-restart-park.v1";
const LOCAL_RESTART_PARK_SIGNING_DOMAIN_V1: &[u8] = b"trnm.poco-g3.local-restart-park-signature.v1";
const SIGNED_LOCAL_RESTART_PARK_DIGEST_DOMAIN_V1: &[u8] =
    b"trnm.poco-g3.signed-local-restart-park.v1";
const RESTART_PARK_CERTIFICATE_DIGEST_DOMAIN_V1: &[u8] =
    b"trnm.poco-g3.restart-park-certificate.v1";
const RESTART_PARKED_ACK_COMMON_DIGEST_DOMAIN_V1: &[u8] =
    b"trnm.poco-g3.restart-parked-ack-common.v1";
const RESTART_PARKED_ACK_SIGNING_DOMAIN_V1: &[u8] = b"trnm.poco-g3.restart-parked-ack-signature.v1";
const RESTART_PARKED_ACK_STATEMENT_DIGEST_DOMAIN_V1: &[u8] =
    b"trnm.poco-g3.restart-parked-ack-statement.v1";
const RESTART_PARKED_ACK_CERTIFICATE_DIGEST_DOMAIN_V1: &[u8] =
    b"trnm.poco-g3.restart-parked-ack-certificate.v1";
const RESTART_PARKED_ACK_ADMISSION_SET_DOMAIN_V1: &[u8] =
    b"trnm.poco-g3.restart-parked-ack-admission-set.v1";
const CUT_STATEMENT_DIGEST_DOMAIN_V1: &[u8] = b"trnm.poco-g3.restart-cut-statement.v1";
const RESTART_CUT_PARK_STATEMENT_DIGEST_DOMAIN_V1: &[u8] =
    b"trnm.poco-g3.restart-cut-park-statement.v1";
const CUT_CERTIFICATE_DIGEST_DOMAIN_V1: &[u8] = b"trnm.poco-g3.restart-cut-certificate.v1";
const SIGNATURE_BYTES_V1: usize = 64;
pub const MAX_RESTART_CUT_BODY_BYTES_V1: usize = 16 * 1024;
pub const MAX_RESTART_SHARED_CUT_BYTES_V1: usize = 512;
pub const MAX_LOCAL_RESTART_PARK_BYTES_V1: usize = 8 * 1024;
pub const MAX_SIGNED_LOCAL_RESTART_PARK_BYTES_V1: usize = 16 * 1024;
pub const MAX_RESTART_PARK_CERTIFICATE_BYTES_V1: usize = 512 * 1024;
pub const MAX_RESTART_PARKED_ACK_COMMON_BYTES_V1: usize = 512;
pub const MAX_SIGNED_RESTART_PARKED_ACK_BYTES_V1: usize = 4 * 1024;
pub const MAX_RESTART_PARKED_ACK_CERTIFICATE_BYTES_V1: usize = 64 * 1024;
pub const MAX_SIGNED_RESTART_CUT_BYTES_V1: usize = 24 * 1024;
pub const MAX_RESTART_CUT_PARK_STATEMENT_BYTES_V1: usize = 64 * 1024;
pub const MAX_RESTART_CUT_CERTIFICATE_BYTES_V1: usize = 4 * 1024 * 1024;

/// Target-local state that must be observed at one clean, pending-sign-free
/// process-1 cut before any validator signs a RestartCut declaration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RestartCutStateV1 {
    pub(crate) epoch: Epoch,
    pub(crate) current_view: View,
    pub(crate) direct_high_qc: QcRef,
    pub(crate) proposal_parent_height: Height,
    pub(crate) proposal_parent_block_id: BlockId,
    pub(crate) finalized_height: Height,
    pub(crate) finalized_block_id: BlockId,
    /// Domain-separated Core commitment to the exact hash-linked finalized
    /// prefix ending at `finalized_block_id`.
    pub(crate) finalized_chain_root: [u8; 32],
    pub(crate) application_height: Height,
    pub(crate) application_block_id: BlockId,
    pub(crate) application_state_root: StateRoot,
    pub(crate) external_checkpoint_generation: u64,
    pub(crate) external_checkpoint_checksum: [u8; 32],
    pub(crate) safety_revision: u64,
    pub(crate) safety_state_record_checksum: [u8; 32],
    pub(crate) safety_record_chain_checksum: [u8; 32],
    pub(crate) signer_watermark: SignerWatermarkV0,
    pub(crate) signer_durable_vote_intent_count: u64,
    pub(crate) signer_durable_timeout_intent_count: u64,
    pub(crate) signer_signed_vote_intent_count: u64,
    pub(crate) signer_signed_timeout_intent_count: u64,
    pub(crate) signer_inventory_digest: [u8; 32],
    /// A valid restart cut requires this to be `None`.  The canonical wire
    /// still carries an explicit absence tag so omission cannot be ambiguous.
    pub(crate) pending_sign: Option<[u8; 32]>,
    pub(crate) replay_archive_context_sha256: [u8; 32],
    pub(crate) replay_archive_head_sequence: u64,
    pub(crate) replay_archive_head_sha256: [u8; 32],
    pub(crate) runtime_journal_head_sequence: u64,
    pub(crate) runtime_journal_head_sha256: [u8; 32],
}

/// The one common declaration signed by all validators for a target process.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestartCutBodyV1 {
    campaign: CommonCampaignContextV1,
    target_validator: ValidatorId,
    target_config_sha256: [u8; 32],
    fleet_start_certificate_sha256: [u8; 32],
    process_instance: u64,
    state: RestartCutStateV1,
}

impl RestartCutBodyV1 {
    /// Constructs inert canonical wire scalars after verifying the exact
    /// FleetStartCertificate whose raw artifact SHA-256 is embedded in the
    /// signed body.
    ///
    /// The constructor is crate-private so normal code can reach it only by
    /// consuming the runtime-issued local prepared owner. Decode remains a
    /// public, inert wire operation and grants no signing or process-control
    /// authority.
    pub(crate) fn new(
        campaign: CommonCampaignContextV1,
        target_validator: ValidatorId,
        target_config_sha256: [u8; 32],
        process_instance: u64,
        state: RestartCutStateV1,
        fleet_start_certificate: &FleetStartCertificateV1,
        validator_set: &ValidatorSet,
    ) -> Result<Self, RestartCutErrorV1> {
        fleet_start_certificate
            .verify(validator_set)
            .map_err(|_| RestartCutErrorV1::InvalidFleetStartCertificate)?;
        if fleet_start_certificate.ready_set().context() != &campaign {
            return Err(RestartCutErrorV1::WrongCampaign);
        }
        let fleet_start_certificate_sha256 =
            Sha256::digest(fleet_start_certificate.encode()).into();
        let value = Self {
            campaign,
            target_validator,
            target_config_sha256,
            fleet_start_certificate_sha256,
            process_instance,
            state,
        };
        value.validate_for_set(validator_set)?;
        value.validate_fleet_start_certificate(fleet_start_certificate, validator_set)?;
        Ok(value)
    }

    pub const fn campaign(&self) -> &CommonCampaignContextV1 {
        &self.campaign
    }

    pub fn run_id(&self) -> &str {
        self.campaign.identity().run_id()
    }

    pub const fn coordinator_manifest_sha256(&self) -> [u8; 32] {
        self.campaign.identity().coordinator_manifest_sha256()
    }

    pub const fn topology_sha256(&self) -> [u8; 32] {
        self.campaign.identity().topology_sha256()
    }

    pub const fn validator_set_id(&self) -> [u8; 32] {
        self.campaign.identity().validator_set_id()
    }

    pub const fn validator_set_sha256(&self) -> [u8; 32] {
        self.campaign.identity().validator_set_sha256()
    }

    pub const fn target_validator(&self) -> ValidatorId {
        self.target_validator
    }

    pub const fn target_config_sha256(&self) -> [u8; 32] {
        self.target_config_sha256
    }

    pub const fn fleet_start_certificate_sha256(&self) -> [u8; 32] {
        self.fleet_start_certificate_sha256
    }

    pub const fn process_instance(&self) -> u64 {
        self.process_instance
    }

    pub const fn state(&self) -> RestartCutStateV1 {
        self.state
    }

    /// Projects the target-local body onto the exact zero-delta state that all
    /// seven validators must independently hold before a restart barrier may
    /// advance.  The projection carries no signing or process authority.
    pub const fn shared_cut_v1(&self) -> RestartSharedCutV1 {
        RestartSharedCutV1::from_state(self.state)
    }

    pub const fn finalized_chain_root_v1(&self) -> [u8; 32] {
        self.state.finalized_chain_root
    }

    pub(crate) const fn runtime_journal_head_v1(&self) -> (u64, [u8; 32]) {
        (
            self.state.runtime_journal_head_sequence,
            self.state.runtime_journal_head_sha256,
        )
    }

    pub const fn pending_sign_is_none(&self) -> bool {
        self.state.pending_sign.is_none()
    }

    pub fn digest(&self) -> [u8; 32] {
        hash_canonical(CUT_BODY_DIGEST_DOMAIN_V1, &self.encode())
    }

    pub fn encode(&self) -> Vec<u8> {
        let campaign = self.campaign.encode();
        let mut output = Vec::with_capacity(1024);
        output.extend_from_slice(CUT_BODY_MAGIC_V1);
        output.extend_from_slice(&WIRE_VERSION_V1.to_be_bytes());
        put_bytes_u32(&mut output, &campaign);
        put_validator_id(&mut output, self.target_validator);
        output.extend_from_slice(&self.target_config_sha256);
        output.extend_from_slice(&self.fleet_start_certificate_sha256);
        output.extend_from_slice(&self.process_instance.to_be_bytes());
        encode_state(self.state, &mut output);
        assert!(output.len() <= MAX_RESTART_CUT_BODY_BYTES_V1);
        output
    }

    pub fn decode(bytes: &[u8], validator_set: &ValidatorSet) -> Result<Self, RestartCutErrorV1> {
        if bytes.is_empty() || bytes.len() > MAX_RESTART_CUT_BODY_BYTES_V1 {
            return Err(RestartCutErrorV1::TooLarge);
        }
        let mut cursor = RestartCursor::new(bytes);
        if cursor.take(8)? != CUT_BODY_MAGIC_V1
            || u16::from_be_bytes(cursor.array()?) != WIRE_VERSION_V1
        {
            return Err(RestartCutErrorV1::Malformed("cut body header"));
        }
        let campaign_length = u32::from_be_bytes(cursor.array()?) as usize;
        let campaign = CommonCampaignContextV1::decode(cursor.take(campaign_length)?)
            .map_err(|_| RestartCutErrorV1::Malformed("campaign context"))?;
        let target_validator = cursor.validator_id()?;
        let target_config_sha256 = cursor.array()?;
        let fleet_start_certificate_sha256 = cursor.array()?;
        let process_instance = u64::from_be_bytes(cursor.array()?);
        let state = decode_state(&mut cursor)?;
        cursor.finish()?;
        let value = Self {
            campaign,
            target_validator,
            target_config_sha256,
            fleet_start_certificate_sha256,
            process_instance,
            state,
        };
        value.validate_for_set(validator_set)?;
        if value.encode() != bytes {
            return Err(RestartCutErrorV1::NonCanonical);
        }
        Ok(value)
    }

    fn validate_for_set(&self, validator_set: &ValidatorSet) -> Result<(), RestartCutErrorV1> {
        let identity = self.campaign.identity();
        if identity.chain_id() != validator_set.chain_id()
            || identity.genesis_hash() != *validator_set.genesis_hash().as_bytes()
            || identity.validator_set_id() != *validator_set.id().as_bytes()
            || usize::try_from(identity.validator_count()).ok()
                != Some(validator_set.validators().len())
        {
            return Err(RestartCutErrorV1::WrongCampaign);
        }
        if !matches!(validator_set.validators().len(), 7 | 31 | 100) {
            return Err(RestartCutErrorV1::WrongCampaign);
        }
        if validator_set.validator(self.target_validator).is_none() {
            return Err(RestartCutErrorV1::UnknownTarget);
        }
        if self.process_instance != 1 {
            return Err(RestartCutErrorV1::Malformed("process instance"));
        }
        if self.target_config_sha256 == [0; 32] || self.fleet_start_certificate_sha256 == [0; 32] {
            return Err(RestartCutErrorV1::Malformed("restart binding digest"));
        }
        validate_state(
            self.state,
            self.campaign.initial_chain_cut().epoch(),
            validator_set,
        )
    }

    fn validate_fleet_start_certificate(
        &self,
        fleet_start_certificate: &FleetStartCertificateV1,
        validator_set: &ValidatorSet,
    ) -> Result<(), RestartCutErrorV1> {
        fleet_start_certificate
            .verify(validator_set)
            .map_err(|_| RestartCutErrorV1::InvalidFleetStartCertificate)?;
        let artifact_sha256: [u8; 32] = Sha256::digest(fleet_start_certificate.encode()).into();
        let target_ready = fleet_start_certificate
            .ready_set()
            .statement(self.target_validator)
            .ok_or(RestartCutErrorV1::InvalidFleetStartCertificate)?;
        if fleet_start_certificate.ready_set().context() != &self.campaign
            || artifact_sha256 != self.fleet_start_certificate_sha256
            || target_ready.local_cut().config_sha256() != self.target_config_sha256
        {
            return Err(RestartCutErrorV1::InvalidFleetStartCertificate);
        }
        Ok(())
    }
}

/// The exact zero-delta recovery tuple that every member of the direct-seven
/// fleet must independently hold while parked.  This is only canonical fact
/// vocabulary; possessing or decoding it grants no signing, network, process,
/// recovery, or activation authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RestartSharedCutV1 {
    epoch: Epoch,
    finalized_height: Height,
    finalized_block_id: BlockId,
    finalized_chain_root: [u8; 32],
    application_height: Height,
    application_block_id: BlockId,
    application_state_root: StateRoot,
}

impl RestartSharedCutV1 {
    pub(crate) const fn from_state(state: RestartCutStateV1) -> Self {
        Self {
            epoch: state.epoch,
            finalized_height: state.finalized_height,
            finalized_block_id: state.finalized_block_id,
            finalized_chain_root: state.finalized_chain_root,
            application_height: state.application_height,
            application_block_id: state.application_block_id,
            application_state_root: state.application_state_root,
        }
    }

    pub const fn epoch(&self) -> Epoch {
        self.epoch
    }

    pub const fn finalized_height(&self) -> Height {
        self.finalized_height
    }

    pub const fn finalized_block_id(&self) -> BlockId {
        self.finalized_block_id
    }

    pub const fn finalized_chain_root(&self) -> [u8; 32] {
        self.finalized_chain_root
    }

    pub const fn application_height(&self) -> Height {
        self.application_height
    }

    pub const fn application_block_id(&self) -> BlockId {
        self.application_block_id
    }

    pub const fn application_state_root(&self) -> StateRoot {
        self.application_state_root
    }

    pub fn digest(&self) -> [u8; 32] {
        hash_canonical(RESTART_SHARED_CUT_DIGEST_DOMAIN_V1, &self.encode())
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut output = Vec::with_capacity(192);
        output.extend_from_slice(RESTART_SHARED_CUT_MAGIC_V1);
        output.extend_from_slice(&WIRE_VERSION_V1.to_be_bytes());
        output.extend_from_slice(&self.epoch.get().to_be_bytes());
        output.extend_from_slice(&self.finalized_height.get().to_be_bytes());
        output.extend_from_slice(self.finalized_block_id.as_bytes());
        output.extend_from_slice(&self.finalized_chain_root);
        output.extend_from_slice(&self.application_height.get().to_be_bytes());
        output.extend_from_slice(self.application_block_id.as_bytes());
        output.extend_from_slice(self.application_state_root.as_bytes());
        assert!(output.len() <= MAX_RESTART_SHARED_CUT_BYTES_V1);
        output
    }

    pub fn decode(bytes: &[u8], validator_set: &ValidatorSet) -> Result<Self, RestartCutErrorV1> {
        if bytes.is_empty() || bytes.len() > MAX_RESTART_SHARED_CUT_BYTES_V1 {
            return Err(RestartCutErrorV1::TooLarge);
        }
        let mut cursor = RestartCursor::new(bytes);
        if cursor.take(8)? != RESTART_SHARED_CUT_MAGIC_V1
            || u16::from_be_bytes(cursor.array()?) != WIRE_VERSION_V1
        {
            return Err(RestartCutErrorV1::Malformed("shared cut header"));
        }
        let value = Self {
            epoch: Epoch::new(u64::from_be_bytes(cursor.array()?)),
            finalized_height: Height::new(u64::from_be_bytes(cursor.array()?)),
            finalized_block_id: BlockId::new(cursor.array()?),
            finalized_chain_root: cursor.array()?,
            application_height: Height::new(u64::from_be_bytes(cursor.array()?)),
            application_block_id: BlockId::new(cursor.array()?),
            application_state_root: StateRoot::new(cursor.array()?),
        };
        cursor.finish()?;
        value.validate_for_set(validator_set)?;
        if value.encode() != bytes {
            return Err(RestartCutErrorV1::NonCanonical);
        }
        Ok(value)
    }

    pub fn validate_for_set(&self, validator_set: &ValidatorSet) -> Result<(), RestartCutErrorV1> {
        if validator_set.validators().len() != 7 || self.epoch != validator_set.epoch() {
            return Err(RestartCutErrorV1::WrongCampaign);
        }
        if self.finalized_height.get() == 0
            || self.application_height != self.finalized_height
            || self.application_block_id != self.finalized_block_id
        {
            return Err(RestartCutErrorV1::Malformed("shared cut relation"));
        }
        if self.finalized_block_id == BlockId::ZERO
            || self.finalized_chain_root == [0; 32]
            || self.application_block_id == BlockId::ZERO
            || self.application_state_root == StateRoot::ZERO
        {
            return Err(RestartCutErrorV1::Malformed("shared cut digest"));
        }
        Ok(())
    }
}

/// The semantic role of one validator's independently captured park record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RestartParkRoleV1 {
    /// The validator named by the RestartCut body. Its local facts must equal
    /// every target-local field in that body byte-for-byte.
    Target,
    /// Any other validator in the frozen direct-seven set.
    Peer,
}

impl RestartParkRoleV1 {
    const fn wire_tag(self) -> u8 {
        match self {
            Self::Target => 1,
            Self::Peer => 2,
        }
    }

    fn from_wire_tag(tag: u8) -> Result<Self, RestartCutErrorV1> {
        match tag {
            1 => Ok(Self::Target),
            2 => Ok(Self::Peer),
            _ => Err(RestartCutErrorV1::Malformed("local park role")),
        }
    }
}

/// One validator's bounded, pending-sign-free durable state while it is
/// locally parked for a direct-seven zero-delta restart barrier.
///
/// This value is deliberately unsigned and inert. Later runtime tranches must
/// obtain any declaration authority from a consuming parked owner; this type
/// exposes no `SigningKey` method or process-control transition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LocalRestartParkV1 {
    role: RestartParkRoleV1,
    local_validator: ValidatorId,
    local_config_sha256: [u8; 32],
    process_instance: u64,
    restart_cut_body_sha256: [u8; 32],
    shared_cut: RestartSharedCutV1,
    local_state: RestartCutStateV1,
}

impl LocalRestartParkV1 {
    /// Captures canonical inert facts only after joining the exact RestartCut
    /// body and FleetStart artifact. Runtime code must still wrap this value in
    /// a non-Clone consuming parked owner before any later declaration issuer
    /// is introduced.
    #[allow(dead_code, clippy::too_many_arguments)]
    pub(crate) fn new(
        role: RestartParkRoleV1,
        local_validator: ValidatorId,
        local_config_sha256: [u8; 32],
        process_instance: u64,
        restart_cut_body: &RestartCutBodyV1,
        local_state: RestartCutStateV1,
        fleet_start_certificate: &FleetStartCertificateV1,
        validator_set: &ValidatorSet,
    ) -> Result<Self, RestartCutErrorV1> {
        let value = Self {
            role,
            local_validator,
            local_config_sha256,
            process_instance,
            restart_cut_body_sha256: restart_cut_body.digest(),
            shared_cut: restart_cut_body.shared_cut_v1(),
            local_state,
        };
        value.validate_for_restart_body(
            restart_cut_body,
            fleet_start_certificate,
            validator_set,
        )?;
        Ok(value)
    }

    pub const fn role(&self) -> RestartParkRoleV1 {
        self.role
    }

    pub const fn local_validator(&self) -> ValidatorId {
        self.local_validator
    }

    pub const fn local_config_sha256(&self) -> [u8; 32] {
        self.local_config_sha256
    }

    pub const fn process_instance(&self) -> u64 {
        self.process_instance
    }

    pub const fn restart_cut_body_sha256(&self) -> [u8; 32] {
        self.restart_cut_body_sha256
    }

    pub const fn shared_cut(&self) -> RestartSharedCutV1 {
        self.shared_cut
    }

    pub const fn local_state(&self) -> RestartCutStateV1 {
        self.local_state
    }

    pub fn digest(&self) -> [u8; 32] {
        hash_canonical(LOCAL_RESTART_PARK_DIGEST_DOMAIN_V1, &self.encode())
    }

    pub fn encode(&self) -> Vec<u8> {
        let shared_cut = self.shared_cut.encode();
        let mut output = Vec::with_capacity(1024);
        output.extend_from_slice(LOCAL_RESTART_PARK_MAGIC_V1);
        output.extend_from_slice(&WIRE_VERSION_V1.to_be_bytes());
        output.push(self.role.wire_tag());
        put_validator_id(&mut output, self.local_validator);
        output.extend_from_slice(&self.local_config_sha256);
        output.extend_from_slice(&self.process_instance.to_be_bytes());
        output.extend_from_slice(&self.restart_cut_body_sha256);
        put_bytes_u32(&mut output, &shared_cut);
        encode_state(self.local_state, &mut output);
        assert!(output.len() <= MAX_LOCAL_RESTART_PARK_BYTES_V1);
        output
    }

    pub fn decode(bytes: &[u8], validator_set: &ValidatorSet) -> Result<Self, RestartCutErrorV1> {
        if bytes.is_empty() || bytes.len() > MAX_LOCAL_RESTART_PARK_BYTES_V1 {
            return Err(RestartCutErrorV1::TooLarge);
        }
        let mut cursor = RestartCursor::new(bytes);
        if cursor.take(8)? != LOCAL_RESTART_PARK_MAGIC_V1
            || u16::from_be_bytes(cursor.array()?) != WIRE_VERSION_V1
        {
            return Err(RestartCutErrorV1::Malformed("local park header"));
        }
        let role = RestartParkRoleV1::from_wire_tag(cursor.byte()?)?;
        let local_validator = cursor.validator_id()?;
        let local_config_sha256 = cursor.array()?;
        let process_instance = u64::from_be_bytes(cursor.array()?);
        let restart_cut_body_sha256 = cursor.array()?;
        let shared_cut_length = u32::from_be_bytes(cursor.array()?) as usize;
        if shared_cut_length == 0 || shared_cut_length > MAX_RESTART_SHARED_CUT_BYTES_V1 {
            return Err(RestartCutErrorV1::TooLarge);
        }
        let shared_cut =
            RestartSharedCutV1::decode(cursor.take(shared_cut_length)?, validator_set)?;
        let local_state = decode_state(&mut cursor)?;
        cursor.finish()?;
        let value = Self {
            role,
            local_validator,
            local_config_sha256,
            process_instance,
            restart_cut_body_sha256,
            shared_cut,
            local_state,
        };
        value.validate_for_set(validator_set)?;
        if value.encode() != bytes {
            return Err(RestartCutErrorV1::NonCanonical);
        }
        Ok(value)
    }

    /// Validates intrinsic local facts, including the exact equality of this
    /// validator's finalized/application projection to the advertised shared
    /// cut. It does not authenticate a RestartCut body or FleetStart artifact.
    pub fn validate_for_set(&self, validator_set: &ValidatorSet) -> Result<(), RestartCutErrorV1> {
        self.shared_cut.validate_for_set(validator_set)?;
        if validator_set.validator(self.local_validator).is_none() {
            return Err(RestartCutErrorV1::UnknownOrigin);
        }
        if self.process_instance != 1 {
            return Err(RestartCutErrorV1::Malformed("local park process instance"));
        }
        if self.local_config_sha256 == [0; 32] || self.restart_cut_body_sha256 == [0; 32] {
            return Err(RestartCutErrorV1::Malformed("local park binding digest"));
        }
        validate_state(self.local_state, self.shared_cut.epoch.get(), validator_set)?;
        if RestartSharedCutV1::from_state(self.local_state) != self.shared_cut {
            return Err(RestartCutErrorV1::Malformed("local park shared cut"));
        }
        Ok(())
    }

    /// Rejoins the local park to the exact target body and the exact
    /// FleetStart-local configuration. Target parks must reproduce every body
    /// state field; peer parks must be authored by a different set member.
    pub fn validate_for_restart_body(
        &self,
        restart_cut_body: &RestartCutBodyV1,
        fleet_start_certificate: &FleetStartCertificateV1,
        validator_set: &ValidatorSet,
    ) -> Result<(), RestartCutErrorV1> {
        self.validate_for_set(validator_set)?;
        restart_cut_body.validate_for_set(validator_set)?;
        restart_cut_body
            .validate_fleet_start_certificate(fleet_start_certificate, validator_set)?;
        let local_ready = fleet_start_certificate
            .ready_set()
            .statement(self.local_validator)
            .ok_or(RestartCutErrorV1::InvalidFleetStartCertificate)?;
        if local_ready.local_cut().config_sha256() != self.local_config_sha256 {
            return Err(RestartCutErrorV1::InvalidFleetStartCertificate);
        }
        if self.process_instance != restart_cut_body.process_instance
            || self.restart_cut_body_sha256 != restart_cut_body.digest()
            || self.shared_cut != restart_cut_body.shared_cut_v1()
        {
            return Err(RestartCutErrorV1::DifferentCut);
        }
        match self.role {
            RestartParkRoleV1::Target
                if self.local_validator == restart_cut_body.target_validator
                    && self.local_config_sha256 == restart_cut_body.target_config_sha256
                    && self.local_state == restart_cut_body.state =>
            {
                Ok(())
            }
            RestartParkRoleV1::Peer
                if self.local_validator != restart_cut_body.target_validator =>
            {
                Ok(())
            }
            _ => Err(RestartCutErrorV1::Malformed("local park role relation")),
        }
    }

    /// Structural convenience only; unlike [`Self::validate_for_restart_body`]
    /// this does not authenticate FleetStart and must never gate authority.
    #[cfg(test)]
    pub(crate) fn has_target_park_shape_for(&self, restart_cut_body: &RestartCutBodyV1) -> bool {
        self.role == RestartParkRoleV1::Target
            && self.local_validator == restart_cut_body.target_validator
            && self.local_config_sha256 == restart_cut_body.target_config_sha256
            && self.process_instance == restart_cut_body.process_instance
            && self.restart_cut_body_sha256 == restart_cut_body.digest()
            && self.shared_cut == restart_cut_body.shared_cut_v1()
            && self.local_state == restart_cut_body.state
    }

    /// Structural convenience only; the authoritative fact join is
    /// [`Self::validate_for_restart_body`].
    #[cfg(test)]
    pub(crate) fn has_peer_park_shape_for(&self, restart_cut_body: &RestartCutBodyV1) -> bool {
        self.role == RestartParkRoleV1::Peer
            && self.local_validator != restart_cut_body.target_validator
            && self.process_instance == restart_cut_body.process_instance
            && self.restart_cut_body_sha256 == restart_cut_body.digest()
            && self.shared_cut == restart_cut_body.shared_cut_v1()
    }
}

/// One origin-authenticated statement over both the exact RestartCut body
/// digest and the origin's complete canonical local-park record.
///
/// This type intentionally has no constructor that accepts a `SigningKey`.
/// Runtime authority must later be issued only by consuming a parked runtime
/// owner; external code may obtain the inert canonical preimage and may submit
/// signature bytes to the strict verifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedLocalRestartParkV1 {
    origin: ValidatorId,
    restart_cut_body_sha256: [u8; 32],
    local_park_sha256: [u8; 32],
    local_park: LocalRestartParkV1,
    signature: [u8; SIGNATURE_BYTES_V1],
}

impl SignedLocalRestartParkV1 {
    /// Returns the complete canonical unsigned wire. It is inert data and does
    /// not expose a key, signer, or runtime transition.
    pub fn signing_preimage_for_parts(
        origin: ValidatorId,
        restart_cut_body: &RestartCutBodyV1,
        local_park: &LocalRestartParkV1,
        fleet_start_certificate: &FleetStartCertificateV1,
        validator_set: &ValidatorSet,
    ) -> Result<Vec<u8>, RestartCutErrorV1> {
        validate_local_restart_park_statement_parts(
            origin,
            restart_cut_body,
            local_park,
            fleet_start_certificate,
            validator_set,
        )?;
        encode_signed_local_restart_park_unsigned(
            origin,
            restart_cut_body.digest(),
            local_park.digest(),
            local_park,
        )
    }

    /// Returns the domain-separated digest that strict Ed25519 signs. The full
    /// preimage above carries the body digest, park digest, and complete park
    /// bytes, so none can be substituted independently.
    pub fn signing_digest_for_parts(
        origin: ValidatorId,
        restart_cut_body: &RestartCutBodyV1,
        local_park: &LocalRestartParkV1,
        fleet_start_certificate: &FleetStartCertificateV1,
        validator_set: &ValidatorSet,
    ) -> Result<[u8; 32], RestartCutErrorV1> {
        Ok(hash_canonical(
            LOCAL_RESTART_PARK_SIGNING_DOMAIN_V1,
            &Self::signing_preimage_for_parts(
                origin,
                restart_cut_body,
                local_park,
                fleet_start_certificate,
                validator_set,
            )?,
        ))
    }

    /// Builds only from externally supplied signature bytes and immediately
    /// performs all semantic joins plus strict Ed25519 verification.
    #[allow(clippy::too_many_arguments)]
    pub fn from_parts(
        origin: ValidatorId,
        restart_cut_body: &RestartCutBodyV1,
        local_park: LocalRestartParkV1,
        signature: [u8; SIGNATURE_BYTES_V1],
        fleet_start_certificate: &FleetStartCertificateV1,
        validator_set: &ValidatorSet,
    ) -> Result<Self, RestartCutErrorV1> {
        let value = Self {
            origin,
            restart_cut_body_sha256: restart_cut_body.digest(),
            local_park_sha256: local_park.digest(),
            local_park,
            signature,
        };
        value.verify(restart_cut_body, fleet_start_certificate, validator_set)?;
        Ok(value)
    }

    pub const fn origin(&self) -> ValidatorId {
        self.origin
    }

    pub const fn restart_cut_body_sha256(&self) -> [u8; 32] {
        self.restart_cut_body_sha256
    }

    pub const fn local_park_sha256(&self) -> [u8; 32] {
        self.local_park_sha256
    }

    pub const fn local_park(&self) -> &LocalRestartParkV1 {
        &self.local_park
    }

    pub fn statement_sha256(&self) -> [u8; 32] {
        hash_canonical(SIGNED_LOCAL_RESTART_PARK_DIGEST_DOMAIN_V1, &self.encode())
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut output = encode_signed_local_restart_park_unsigned(
            self.origin,
            self.restart_cut_body_sha256,
            self.local_park_sha256,
            &self.local_park,
        )
        .expect("validated local-park statement fits its wire bound");
        output.extend_from_slice(&self.signature);
        output
    }

    pub fn decode(
        bytes: &[u8],
        restart_cut_body: &RestartCutBodyV1,
        fleet_start_certificate: &FleetStartCertificateV1,
        validator_set: &ValidatorSet,
    ) -> Result<Self, RestartCutErrorV1> {
        if bytes.len() <= SIGNATURE_BYTES_V1 || bytes.len() > MAX_SIGNED_LOCAL_RESTART_PARK_BYTES_V1
        {
            return Err(RestartCutErrorV1::TooLarge);
        }
        let split = bytes.len() - SIGNATURE_BYTES_V1;
        let unsigned = &bytes[..split];
        let signature = bytes[split..]
            .try_into()
            .map_err(|_| RestartCutErrorV1::Malformed("local park signature"))?;
        let mut cursor = RestartCursor::new(unsigned);
        if cursor.take(8)? != SIGNED_LOCAL_RESTART_PARK_MAGIC_V1
            || u16::from_be_bytes(cursor.array()?) != WIRE_VERSION_V1
        {
            return Err(RestartCutErrorV1::Malformed("signed local park header"));
        }
        let origin = cursor.validator_id()?;
        let restart_cut_body_sha256 = cursor.array()?;
        let local_park_sha256 = cursor.array()?;
        let local_park_length = u32::from_be_bytes(cursor.array()?) as usize;
        if local_park_length == 0 || local_park_length > MAX_LOCAL_RESTART_PARK_BYTES_V1 {
            return Err(RestartCutErrorV1::TooLarge);
        }
        let local_park =
            LocalRestartParkV1::decode(cursor.take(local_park_length)?, validator_set)?;
        cursor.finish()?;
        let value = Self {
            origin,
            restart_cut_body_sha256,
            local_park_sha256,
            local_park,
            signature,
        };
        value.verify(restart_cut_body, fleet_start_certificate, validator_set)?;
        if value.encode() != bytes {
            return Err(RestartCutErrorV1::NonCanonical);
        }
        Ok(value)
    }

    pub fn verify(
        &self,
        restart_cut_body: &RestartCutBodyV1,
        fleet_start_certificate: &FleetStartCertificateV1,
        validator_set: &ValidatorSet,
    ) -> Result<(), RestartCutErrorV1> {
        validate_local_restart_park_statement_parts(
            self.origin,
            restart_cut_body,
            &self.local_park,
            fleet_start_certificate,
            validator_set,
        )?;
        if self.restart_cut_body_sha256 != restart_cut_body.digest()
            || self.restart_cut_body_sha256 != self.local_park.restart_cut_body_sha256
            || self.local_park_sha256 != self.local_park.digest()
        {
            return Err(RestartCutErrorV1::DifferentCut);
        }
        let validator = validator_set
            .validator(self.origin)
            .ok_or(RestartCutErrorV1::UnknownOrigin)?;
        let key = VerifyingKey::from_bytes(validator.consensus_key().as_bytes())
            .map_err(|_| RestartCutErrorV1::InvalidSignature)?;
        let unsigned = encode_signed_local_restart_park_unsigned(
            self.origin,
            self.restart_cut_body_sha256,
            self.local_park_sha256,
            &self.local_park,
        )?;
        key.verify_strict(
            &hash_canonical(LOCAL_RESTART_PARK_SIGNING_DOMAIN_V1, &unsigned),
            &Signature::from_bytes(&self.signature),
        )
        .map_err(|_| RestartCutErrorV1::InvalidSignature)
    }
}

/// Canonical direct-seven N/N set of independently signed local park records.
/// The exact RestartCut body is retained so independent verification never
/// trusts an unattached body digest or a synthesized common shared cut.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestartParkCertificateV1 {
    body: RestartCutBodyV1,
    shared_cut: RestartSharedCutV1,
    statements: Vec<SignedLocalRestartParkV1>,
}

impl RestartParkCertificateV1 {
    pub fn new(
        body: RestartCutBodyV1,
        statements: Vec<SignedLocalRestartParkV1>,
        fleet_start_certificate: &FleetStartCertificateV1,
        validator_set: &ValidatorSet,
    ) -> Result<Self, RestartCutErrorV1> {
        Self::from_statements(body, statements, fleet_start_certificate, validator_set)
    }

    fn from_statements(
        body: RestartCutBodyV1,
        statements: Vec<SignedLocalRestartParkV1>,
        fleet_start_certificate: &FleetStartCertificateV1,
        validator_set: &ValidatorSet,
    ) -> Result<Self, RestartCutErrorV1> {
        body.validate_for_set(validator_set)?;
        body.validate_fleet_start_certificate(fleet_start_certificate, validator_set)?;
        let shared_cut = body.shared_cut_v1();
        shared_cut.validate_for_set(validator_set)?;
        if statements.len() != 7 || validator_set.validators().len() != 7 {
            return Err(RestartCutErrorV1::Incomplete);
        }
        let mut canonical = BTreeMap::new();
        for statement in statements {
            statement.verify(&body, fleet_start_certificate, validator_set)?;
            let park = statement.local_park();
            if park.shared_cut != shared_cut
                || park.process_instance != body.process_instance
                || park.restart_cut_body_sha256 != body.digest()
            {
                return Err(RestartCutErrorV1::DifferentCut);
            }
            match park.role {
                RestartParkRoleV1::Target
                    if statement.origin == body.target_validator
                        && park.local_validator == body.target_validator => {}
                RestartParkRoleV1::Peer
                    if statement.origin != body.target_validator
                        && park.local_validator != body.target_validator => {}
                _ => {
                    return Err(RestartCutErrorV1::Malformed(
                        "park certificate role relation",
                    ));
                }
            }
            if canonical.insert(statement.origin, statement).is_some() {
                return Err(RestartCutErrorV1::DuplicateOrigin);
            }
        }
        if canonical.len() != 7
            || validator_set
                .validators()
                .iter()
                .any(|validator| !canonical.contains_key(&validator.id()))
        {
            return Err(RestartCutErrorV1::Incomplete);
        }
        Ok(Self {
            body,
            shared_cut,
            statements: canonical.into_values().collect(),
        })
    }

    pub const fn body(&self) -> &RestartCutBodyV1 {
        &self.body
    }

    pub const fn shared_cut(&self) -> RestartSharedCutV1 {
        self.shared_cut
    }

    pub fn statements(&self) -> &[SignedLocalRestartParkV1] {
        &self.statements
    }

    pub const fn statement_count(&self) -> usize {
        self.statements.len()
    }

    pub fn statement(&self, origin: ValidatorId) -> Option<&SignedLocalRestartParkV1> {
        self.statements
            .binary_search_by_key(&origin, SignedLocalRestartParkV1::origin)
            .ok()
            .and_then(|index| self.statements.get(index))
    }

    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut output = Vec::with_capacity(68 + self.statements.len() * 66);
        output.extend_from_slice(&self.body.digest());
        output.extend_from_slice(&self.shared_cut.digest());
        output.extend_from_slice(
            &u32::try_from(self.statements.len())
                .expect("direct-seven validator count fits u32")
                .to_be_bytes(),
        );
        for statement in &self.statements {
            put_validator_id(&mut output, statement.origin);
            output.extend_from_slice(&statement.statement_sha256());
        }
        output
    }

    pub fn digest(&self) -> [u8; 32] {
        hash_canonical(
            RESTART_PARK_CERTIFICATE_DIGEST_DOMAIN_V1,
            &self.canonical_bytes(),
        )
    }

    pub fn encode(&self) -> Vec<u8> {
        let body = self.body.encode();
        let shared_cut = self.shared_cut.encode();
        let statements = self
            .statements
            .iter()
            .map(SignedLocalRestartParkV1::encode)
            .collect::<Vec<_>>();
        let total = statements
            .iter()
            .try_fold(
                8usize + 2 + 4 + body.len() + 4 + shared_cut.len() + 4,
                |size, statement| size.checked_add(4 + statement.len()),
            )
            .expect("validated restart park certificate length does not overflow");
        assert!(total <= MAX_RESTART_PARK_CERTIFICATE_BYTES_V1);
        let mut output = Vec::with_capacity(total);
        output.extend_from_slice(RESTART_PARK_CERTIFICATE_MAGIC_V1);
        output.extend_from_slice(&WIRE_VERSION_V1.to_be_bytes());
        put_bytes_u32(&mut output, &body);
        put_bytes_u32(&mut output, &shared_cut);
        output.extend_from_slice(
            &u32::try_from(statements.len())
                .expect("direct-seven validator count fits u32")
                .to_be_bytes(),
        );
        for statement in statements {
            put_bytes_u32(&mut output, &statement);
        }
        output
    }

    pub fn decode(
        bytes: &[u8],
        fleet_start_certificate: &FleetStartCertificateV1,
        validator_set: &ValidatorSet,
    ) -> Result<Self, RestartCutErrorV1> {
        if bytes.is_empty() || bytes.len() > MAX_RESTART_PARK_CERTIFICATE_BYTES_V1 {
            return Err(RestartCutErrorV1::TooLarge);
        }
        let mut cursor = RestartCursor::new(bytes);
        if cursor.take(8)? != RESTART_PARK_CERTIFICATE_MAGIC_V1
            || u16::from_be_bytes(cursor.array()?) != WIRE_VERSION_V1
        {
            return Err(RestartCutErrorV1::Malformed("park certificate header"));
        }
        let body_length = u32::from_be_bytes(cursor.array()?) as usize;
        if body_length == 0 || body_length > MAX_RESTART_CUT_BODY_BYTES_V1 {
            return Err(RestartCutErrorV1::TooLarge);
        }
        let body = RestartCutBodyV1::decode(cursor.take(body_length)?, validator_set)?;
        let shared_cut_length = u32::from_be_bytes(cursor.array()?) as usize;
        if shared_cut_length == 0 || shared_cut_length > MAX_RESTART_SHARED_CUT_BYTES_V1 {
            return Err(RestartCutErrorV1::TooLarge);
        }
        let shared_cut =
            RestartSharedCutV1::decode(cursor.take(shared_cut_length)?, validator_set)?;
        let count = u32::from_be_bytes(cursor.array()?) as usize;
        if count != 7 || validator_set.validators().len() != 7 {
            return Err(RestartCutErrorV1::Incomplete);
        }
        let mut statements = Vec::with_capacity(count);
        for _ in 0..count {
            let length = u32::from_be_bytes(cursor.array()?) as usize;
            if length == 0 || length > MAX_SIGNED_LOCAL_RESTART_PARK_BYTES_V1 {
                return Err(RestartCutErrorV1::TooLarge);
            }
            statements.push(SignedLocalRestartParkV1::decode(
                cursor.take(length)?,
                &body,
                fleet_start_certificate,
                validator_set,
            )?);
        }
        cursor.finish()?;
        let value =
            Self::from_statements(body, statements, fleet_start_certificate, validator_set)?;
        if value.shared_cut != shared_cut {
            return Err(RestartCutErrorV1::DifferentCut);
        }
        if value.encode() != bytes {
            return Err(RestartCutErrorV1::NonCanonical);
        }
        Ok(value)
    }

    pub fn verify(
        &self,
        fleet_start_certificate: &FleetStartCertificateV1,
        validator_set: &ValidatorSet,
    ) -> Result<(), RestartCutErrorV1> {
        let rebuilt = Self::from_statements(
            self.body.clone(),
            self.statements.clone(),
            fleet_start_certificate,
            validator_set,
        )?;
        if rebuilt.body != self.body
            || rebuilt.shared_cut != self.shared_cut
            || rebuilt.encode() != self.encode()
        {
            return Err(RestartCutErrorV1::NonCanonical);
        }
        Ok(())
    }
}

/// Common immutable facts attested by every validator only after its exact
/// direct-seven Cut/Park pair and local park journal event are durable.
///
/// This value is inert wire vocabulary. In particular, a caller-supplied
/// admission-set digest is only authenticated when this common value is
/// carried by a strictly verified signed Ack and N/N certificate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RestartParkedAckCommonV1 {
    validator_set_id: ValidatorSetId,
    target_validator: ValidatorId,
    process_instance: u64,
    fleet_start_certificate_sha256: [u8; 32],
    restart_cut_body_sha256: [u8; 32],
    restart_cut_artifact_sha256: [u8; 32],
    restart_park_artifact_sha256: [u8; 32],
    restart_cut_park_admission_set_sha256: [u8; 32],
}

impl RestartParkedAckCommonV1 {
    pub fn new(
        fleet_start_certificate: &FleetStartCertificateV1,
        restart_cut_certificate: &RestartCutCertificateV1,
        restart_park_certificate: &RestartParkCertificateV1,
        restart_cut_park_admission_set_sha256: [u8; 32],
        validator_set: &ValidatorSet,
    ) -> Result<Self, RestartCutErrorV1> {
        let _verified_cut = restart_cut_certificate
            .clone()
            .verify_owned(fleet_start_certificate, validator_set)?;
        restart_park_certificate.verify(fleet_start_certificate, validator_set)?;
        if restart_cut_certificate.body() != restart_park_certificate.body() {
            return Err(RestartCutErrorV1::DifferentCut);
        }
        let value = Self {
            validator_set_id: validator_set.id(),
            target_validator: restart_cut_certificate.body().target_validator(),
            process_instance: restart_cut_certificate.body().process_instance(),
            fleet_start_certificate_sha256: Sha256::digest(fleet_start_certificate.encode()).into(),
            restart_cut_body_sha256: restart_cut_certificate.body().digest(),
            restart_cut_artifact_sha256: Sha256::digest(restart_cut_certificate.encode()).into(),
            restart_park_artifact_sha256: Sha256::digest(restart_park_certificate.encode()).into(),
            restart_cut_park_admission_set_sha256,
        };
        value.verify_exact(
            fleet_start_certificate,
            restart_cut_certificate,
            restart_park_certificate,
            restart_cut_park_admission_set_sha256,
            validator_set,
        )?;
        Ok(value)
    }

    pub const fn validator_set_id(&self) -> ValidatorSetId {
        self.validator_set_id
    }

    pub const fn target_validator(&self) -> ValidatorId {
        self.target_validator
    }

    pub const fn process_instance(&self) -> u64 {
        self.process_instance
    }

    pub const fn fleet_start_certificate_sha256(&self) -> [u8; 32] {
        self.fleet_start_certificate_sha256
    }

    pub const fn restart_cut_body_sha256(&self) -> [u8; 32] {
        self.restart_cut_body_sha256
    }

    pub const fn restart_cut_artifact_sha256(&self) -> [u8; 32] {
        self.restart_cut_artifact_sha256
    }

    pub const fn restart_park_artifact_sha256(&self) -> [u8; 32] {
        self.restart_park_artifact_sha256
    }

    pub const fn restart_cut_park_admission_set_sha256(&self) -> [u8; 32] {
        self.restart_cut_park_admission_set_sha256
    }

    pub fn digest(&self) -> [u8; 32] {
        hash_canonical(RESTART_PARKED_ACK_COMMON_DIGEST_DOMAIN_V1, &self.encode())
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut output = Vec::with_capacity(256);
        output.extend_from_slice(RESTART_PARKED_ACK_COMMON_MAGIC_V1);
        output.extend_from_slice(&WIRE_VERSION_V1.to_be_bytes());
        output.extend_from_slice(self.validator_set_id.as_bytes());
        put_validator_id(&mut output, self.target_validator);
        output.extend_from_slice(&self.process_instance.to_be_bytes());
        output.extend_from_slice(&self.fleet_start_certificate_sha256);
        output.extend_from_slice(&self.restart_cut_body_sha256);
        output.extend_from_slice(&self.restart_cut_artifact_sha256);
        output.extend_from_slice(&self.restart_park_artifact_sha256);
        output.extend_from_slice(&self.restart_cut_park_admission_set_sha256);
        assert!(output.len() <= MAX_RESTART_PARKED_ACK_COMMON_BYTES_V1);
        output
    }

    pub fn decode(bytes: &[u8], validator_set: &ValidatorSet) -> Result<Self, RestartCutErrorV1> {
        if bytes.is_empty() || bytes.len() > MAX_RESTART_PARKED_ACK_COMMON_BYTES_V1 {
            return Err(RestartCutErrorV1::TooLarge);
        }
        let mut cursor = RestartCursor::new(bytes);
        if cursor.take(8)? != RESTART_PARKED_ACK_COMMON_MAGIC_V1
            || u16::from_be_bytes(cursor.array()?) != WIRE_VERSION_V1
        {
            return Err(RestartCutErrorV1::Malformed("parked Ack common header"));
        }
        let value = Self {
            validator_set_id: ValidatorSetId::new(cursor.array()?),
            target_validator: cursor.validator_id()?,
            process_instance: u64::from_be_bytes(cursor.array()?),
            fleet_start_certificate_sha256: cursor.array()?,
            restart_cut_body_sha256: cursor.array()?,
            restart_cut_artifact_sha256: cursor.array()?,
            restart_park_artifact_sha256: cursor.array()?,
            restart_cut_park_admission_set_sha256: cursor.array()?,
        };
        cursor.finish()?;
        value.validate_for_set(validator_set)?;
        if value.encode() != bytes {
            return Err(RestartCutErrorV1::NonCanonical);
        }
        Ok(value)
    }

    pub fn verify_exact(
        &self,
        fleet_start_certificate: &FleetStartCertificateV1,
        restart_cut_certificate: &RestartCutCertificateV1,
        restart_park_certificate: &RestartParkCertificateV1,
        restart_cut_park_admission_set_sha256: [u8; 32],
        validator_set: &ValidatorSet,
    ) -> Result<(), RestartCutErrorV1> {
        self.validate_for_set(validator_set)?;
        let verified_cut = restart_cut_certificate
            .clone()
            .verify_owned(fleet_start_certificate, validator_set)?;
        restart_park_certificate.verify(fleet_start_certificate, validator_set)?;
        if verified_cut.body() != restart_park_certificate.body() {
            return Err(RestartCutErrorV1::DifferentCut);
        }
        let fleet_start_certificate_sha256: [u8; 32] =
            Sha256::digest(fleet_start_certificate.encode()).into();
        let restart_park_artifact_sha256: [u8; 32] =
            Sha256::digest(restart_park_certificate.encode()).into();
        if self.validator_set_id != validator_set.id()
            || self.target_validator != verified_cut.body().target_validator()
            || self.process_instance != verified_cut.body().process_instance()
            || self.process_instance != 1
            || self.fleet_start_certificate_sha256 != fleet_start_certificate_sha256
            || self.restart_cut_body_sha256 != verified_cut.body().digest()
            || self.restart_cut_artifact_sha256 != verified_cut.artifact_sha256()
            || self.restart_park_artifact_sha256 != restart_park_artifact_sha256
            || self.restart_cut_park_admission_set_sha256 != restart_cut_park_admission_set_sha256
        {
            return Err(RestartCutErrorV1::DifferentCut);
        }
        Ok(())
    }

    fn validate_for_set(&self, validator_set: &ValidatorSet) -> Result<(), RestartCutErrorV1> {
        validator_set
            .validate_shape()
            .map_err(|_| RestartCutErrorV1::WrongCampaign)?;
        if validator_set.validators().len() != 7 || self.validator_set_id != validator_set.id() {
            return Err(RestartCutErrorV1::WrongCampaign);
        }
        if validator_set.validator(self.target_validator).is_none() {
            return Err(RestartCutErrorV1::UnknownTarget);
        }
        if self.process_instance != 1 {
            return Err(RestartCutErrorV1::Malformed("parked Ack process instance"));
        }
        if self.fleet_start_certificate_sha256 == [0; 32]
            || self.restart_cut_body_sha256 == [0; 32]
            || self.restart_cut_artifact_sha256 == [0; 32]
            || self.restart_park_artifact_sha256 == [0; 32]
            || self.restart_cut_park_admission_set_sha256 == [0; 32]
        {
            return Err(RestartCutErrorV1::Malformed("parked Ack common digest"));
        }
        Ok(())
    }
}

/// One validator's strict signature over the exact common Cut/Park identity,
/// its own local Park statement, and the locally durable journal chain ending
/// at `restart_park` (`rpk1`).
///
/// This type intentionally exposes no constructor accepting a `SigningKey`.
/// Runtime authority must obtain the digest from a consuming, Ack-only signer
/// and submit only its resulting signature bytes to [`Self::from_parts`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedRestartParkedAckV1 {
    common: RestartParkedAckCommonV1,
    origin: ValidatorId,
    role: RestartParkRoleV1,
    local_config_sha256: [u8; 32],
    local_park_statement_sha256: [u8; 32],
    predecessor_sequence: u64,
    predecessor_sha256: [u8; 32],
    restart_cut_event_sequence: u64,
    restart_cut_event_sha256: [u8; 32],
    restart_park_event_sequence: u64,
    restart_park_event_sha256: [u8; 32],
    signature: [u8; SIGNATURE_BYTES_V1],
}

impl SignedRestartParkedAckV1 {
    #[allow(clippy::too_many_arguments)]
    pub fn signing_preimage_for_parts(
        common: RestartParkedAckCommonV1,
        origin: ValidatorId,
        role: RestartParkRoleV1,
        local_config_sha256: [u8; 32],
        local_park_statement_sha256: [u8; 32],
        predecessor_sequence: u64,
        predecessor_sha256: [u8; 32],
        restart_cut_event_sequence: u64,
        restart_cut_event_sha256: [u8; 32],
        restart_park_event_sequence: u64,
        restart_park_event_sha256: [u8; 32],
        fleet_start_certificate: &FleetStartCertificateV1,
        restart_cut_certificate: &RestartCutCertificateV1,
        restart_park_certificate: &RestartParkCertificateV1,
        restart_cut_park_admission_set_sha256: [u8; 32],
        validator_set: &ValidatorSet,
    ) -> Result<Vec<u8>, RestartCutErrorV1> {
        validate_restart_parked_ack_statement_parts(
            &common,
            origin,
            role,
            local_config_sha256,
            local_park_statement_sha256,
            predecessor_sequence,
            predecessor_sha256,
            restart_cut_event_sequence,
            restart_cut_event_sha256,
            restart_park_event_sequence,
            restart_park_event_sha256,
            fleet_start_certificate,
            restart_cut_certificate,
            restart_park_certificate,
            restart_cut_park_admission_set_sha256,
            validator_set,
        )?;
        encode_signed_restart_parked_ack_unsigned(
            common,
            origin,
            role,
            local_config_sha256,
            local_park_statement_sha256,
            predecessor_sequence,
            predecessor_sha256,
            restart_cut_event_sequence,
            restart_cut_event_sha256,
            restart_park_event_sequence,
            restart_park_event_sha256,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn signing_digest_for_parts(
        common: RestartParkedAckCommonV1,
        origin: ValidatorId,
        role: RestartParkRoleV1,
        local_config_sha256: [u8; 32],
        local_park_statement_sha256: [u8; 32],
        predecessor_sequence: u64,
        predecessor_sha256: [u8; 32],
        restart_cut_event_sequence: u64,
        restart_cut_event_sha256: [u8; 32],
        restart_park_event_sequence: u64,
        restart_park_event_sha256: [u8; 32],
        fleet_start_certificate: &FleetStartCertificateV1,
        restart_cut_certificate: &RestartCutCertificateV1,
        restart_park_certificate: &RestartParkCertificateV1,
        restart_cut_park_admission_set_sha256: [u8; 32],
        validator_set: &ValidatorSet,
    ) -> Result<[u8; 32], RestartCutErrorV1> {
        Ok(hash_canonical(
            RESTART_PARKED_ACK_SIGNING_DOMAIN_V1,
            &Self::signing_preimage_for_parts(
                common,
                origin,
                role,
                local_config_sha256,
                local_park_statement_sha256,
                predecessor_sequence,
                predecessor_sha256,
                restart_cut_event_sequence,
                restart_cut_event_sha256,
                restart_park_event_sequence,
                restart_park_event_sha256,
                fleet_start_certificate,
                restart_cut_certificate,
                restart_park_certificate,
                restart_cut_park_admission_set_sha256,
                validator_set,
            )?,
        ))
    }

    #[allow(clippy::too_many_arguments)]
    pub fn from_parts(
        common: RestartParkedAckCommonV1,
        origin: ValidatorId,
        role: RestartParkRoleV1,
        local_config_sha256: [u8; 32],
        local_park_statement_sha256: [u8; 32],
        predecessor_sequence: u64,
        predecessor_sha256: [u8; 32],
        restart_cut_event_sequence: u64,
        restart_cut_event_sha256: [u8; 32],
        restart_park_event_sequence: u64,
        restart_park_event_sha256: [u8; 32],
        signature: [u8; SIGNATURE_BYTES_V1],
        fleet_start_certificate: &FleetStartCertificateV1,
        restart_cut_certificate: &RestartCutCertificateV1,
        restart_park_certificate: &RestartParkCertificateV1,
        restart_cut_park_admission_set_sha256: [u8; 32],
        validator_set: &ValidatorSet,
    ) -> Result<Self, RestartCutErrorV1> {
        let value = Self {
            common,
            origin,
            role,
            local_config_sha256,
            local_park_statement_sha256,
            predecessor_sequence,
            predecessor_sha256,
            restart_cut_event_sequence,
            restart_cut_event_sha256,
            restart_park_event_sequence,
            restart_park_event_sha256,
            signature,
        };
        value.verify(
            fleet_start_certificate,
            restart_cut_certificate,
            restart_park_certificate,
            restart_cut_park_admission_set_sha256,
            validator_set,
        )?;
        Ok(value)
    }

    pub const fn common(&self) -> &RestartParkedAckCommonV1 {
        &self.common
    }

    pub const fn origin(&self) -> ValidatorId {
        self.origin
    }

    pub const fn role(&self) -> RestartParkRoleV1 {
        self.role
    }

    pub const fn local_config_sha256(&self) -> [u8; 32] {
        self.local_config_sha256
    }

    pub const fn local_park_statement_sha256(&self) -> [u8; 32] {
        self.local_park_statement_sha256
    }

    pub const fn predecessor_sequence(&self) -> u64 {
        self.predecessor_sequence
    }

    pub const fn predecessor_sha256(&self) -> [u8; 32] {
        self.predecessor_sha256
    }

    pub const fn restart_cut_event_sequence(&self) -> u64 {
        self.restart_cut_event_sequence
    }

    pub const fn restart_cut_event_sha256(&self) -> [u8; 32] {
        self.restart_cut_event_sha256
    }

    pub const fn restart_park_event_sequence(&self) -> u64 {
        self.restart_park_event_sequence
    }

    pub const fn restart_park_event_sha256(&self) -> [u8; 32] {
        self.restart_park_event_sha256
    }

    pub fn statement_sha256(&self) -> [u8; 32] {
        hash_canonical(
            RESTART_PARKED_ACK_STATEMENT_DIGEST_DOMAIN_V1,
            &self.encode(),
        )
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut output = encode_signed_restart_parked_ack_unsigned(
            self.common,
            self.origin,
            self.role,
            self.local_config_sha256,
            self.local_park_statement_sha256,
            self.predecessor_sequence,
            self.predecessor_sha256,
            self.restart_cut_event_sequence,
            self.restart_cut_event_sha256,
            self.restart_park_event_sequence,
            self.restart_park_event_sha256,
        )
        .expect("validated parked Ack statement fits its wire bound");
        output.extend_from_slice(&self.signature);
        output
    }

    pub fn decode(
        bytes: &[u8],
        fleet_start_certificate: &FleetStartCertificateV1,
        restart_cut_certificate: &RestartCutCertificateV1,
        restart_park_certificate: &RestartParkCertificateV1,
        restart_cut_park_admission_set_sha256: [u8; 32],
        validator_set: &ValidatorSet,
    ) -> Result<Self, RestartCutErrorV1> {
        if bytes.len() <= SIGNATURE_BYTES_V1 || bytes.len() > MAX_SIGNED_RESTART_PARKED_ACK_BYTES_V1
        {
            return Err(RestartCutErrorV1::TooLarge);
        }
        let split = bytes.len() - SIGNATURE_BYTES_V1;
        let unsigned = &bytes[..split];
        let signature = bytes[split..]
            .try_into()
            .map_err(|_| RestartCutErrorV1::Malformed("parked Ack signature"))?;
        let mut cursor = RestartCursor::new(unsigned);
        if cursor.take(8)? != SIGNED_RESTART_PARKED_ACK_MAGIC_V1
            || u16::from_be_bytes(cursor.array()?) != WIRE_VERSION_V1
        {
            return Err(RestartCutErrorV1::Malformed("signed parked Ack header"));
        }
        let common_length = u32::from_be_bytes(cursor.array()?) as usize;
        if common_length == 0 || common_length > MAX_RESTART_PARKED_ACK_COMMON_BYTES_V1 {
            return Err(RestartCutErrorV1::TooLarge);
        }
        let common = RestartParkedAckCommonV1::decode(cursor.take(common_length)?, validator_set)?;
        let value = Self {
            common,
            origin: cursor.validator_id()?,
            role: RestartParkRoleV1::from_wire_tag(cursor.byte()?)?,
            local_config_sha256: cursor.array()?,
            local_park_statement_sha256: cursor.array()?,
            predecessor_sequence: u64::from_be_bytes(cursor.array()?),
            predecessor_sha256: cursor.array()?,
            restart_cut_event_sequence: u64::from_be_bytes(cursor.array()?),
            restart_cut_event_sha256: cursor.array()?,
            restart_park_event_sequence: u64::from_be_bytes(cursor.array()?),
            restart_park_event_sha256: cursor.array()?,
            signature,
        };
        cursor.finish()?;
        value.verify(
            fleet_start_certificate,
            restart_cut_certificate,
            restart_park_certificate,
            restart_cut_park_admission_set_sha256,
            validator_set,
        )?;
        if value.encode() != bytes {
            return Err(RestartCutErrorV1::NonCanonical);
        }
        Ok(value)
    }

    pub fn verify(
        &self,
        fleet_start_certificate: &FleetStartCertificateV1,
        restart_cut_certificate: &RestartCutCertificateV1,
        restart_park_certificate: &RestartParkCertificateV1,
        restart_cut_park_admission_set_sha256: [u8; 32],
        validator_set: &ValidatorSet,
    ) -> Result<(), RestartCutErrorV1> {
        validate_restart_parked_ack_statement_parts(
            &self.common,
            self.origin,
            self.role,
            self.local_config_sha256,
            self.local_park_statement_sha256,
            self.predecessor_sequence,
            self.predecessor_sha256,
            self.restart_cut_event_sequence,
            self.restart_cut_event_sha256,
            self.restart_park_event_sequence,
            self.restart_park_event_sha256,
            fleet_start_certificate,
            restart_cut_certificate,
            restart_park_certificate,
            restart_cut_park_admission_set_sha256,
            validator_set,
        )?;
        let validator = validator_set
            .validator(self.origin)
            .ok_or(RestartCutErrorV1::UnknownOrigin)?;
        let key = VerifyingKey::from_bytes(validator.consensus_key().as_bytes())
            .map_err(|_| RestartCutErrorV1::InvalidSignature)?;
        let unsigned = encode_signed_restart_parked_ack_unsigned(
            self.common,
            self.origin,
            self.role,
            self.local_config_sha256,
            self.local_park_statement_sha256,
            self.predecessor_sequence,
            self.predecessor_sha256,
            self.restart_cut_event_sequence,
            self.restart_cut_event_sha256,
            self.restart_park_event_sequence,
            self.restart_park_event_sha256,
        )?;
        key.verify_strict(
            &hash_canonical(RESTART_PARKED_ACK_SIGNING_DOMAIN_V1, &unsigned),
            &Signature::from_bytes(&self.signature),
        )
        .map_err(|_| RestartCutErrorV1::InvalidSignature)
    }
}

/// Canonical origin-sorted direct-seven N/N parked acknowledgement set.
/// Verification is inseparable from the exact FleetStart, Cut, Park, and
/// prior Cut/Park admission-set identities supplied by the caller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestartParkedAckCertificateV1 {
    common: RestartParkedAckCommonV1,
    statements: Vec<SignedRestartParkedAckV1>,
}

impl RestartParkedAckCertificateV1 {
    pub fn new(
        common: RestartParkedAckCommonV1,
        statements: Vec<SignedRestartParkedAckV1>,
        fleet_start_certificate: &FleetStartCertificateV1,
        restart_cut_certificate: &RestartCutCertificateV1,
        restart_park_certificate: &RestartParkCertificateV1,
        restart_cut_park_admission_set_sha256: [u8; 32],
        validator_set: &ValidatorSet,
    ) -> Result<Self, RestartCutErrorV1> {
        Self::from_statements(
            common,
            statements,
            fleet_start_certificate,
            restart_cut_certificate,
            restart_park_certificate,
            restart_cut_park_admission_set_sha256,
            validator_set,
        )
    }

    fn from_statements(
        common: RestartParkedAckCommonV1,
        statements: Vec<SignedRestartParkedAckV1>,
        fleet_start_certificate: &FleetStartCertificateV1,
        restart_cut_certificate: &RestartCutCertificateV1,
        restart_park_certificate: &RestartParkCertificateV1,
        restart_cut_park_admission_set_sha256: [u8; 32],
        validator_set: &ValidatorSet,
    ) -> Result<Self, RestartCutErrorV1> {
        common.verify_exact(
            fleet_start_certificate,
            restart_cut_certificate,
            restart_park_certificate,
            restart_cut_park_admission_set_sha256,
            validator_set,
        )?;
        if statements.len() != 7 || validator_set.validators().len() != 7 {
            return Err(RestartCutErrorV1::Incomplete);
        }
        let mut canonical = BTreeMap::new();
        for statement in statements {
            statement.verify(
                fleet_start_certificate,
                restart_cut_certificate,
                restart_park_certificate,
                restart_cut_park_admission_set_sha256,
                validator_set,
            )?;
            if statement.common != common {
                return Err(RestartCutErrorV1::DifferentCut);
            }
            if canonical.insert(statement.origin, statement).is_some() {
                return Err(RestartCutErrorV1::DuplicateOrigin);
            }
        }
        if canonical.len() != 7
            || validator_set
                .validators()
                .iter()
                .any(|validator| !canonical.contains_key(&validator.id()))
        {
            return Err(RestartCutErrorV1::Incomplete);
        }
        Ok(Self {
            common,
            statements: canonical.into_values().collect(),
        })
    }

    pub const fn common(&self) -> &RestartParkedAckCommonV1 {
        &self.common
    }

    pub fn statements(&self) -> &[SignedRestartParkedAckV1] {
        &self.statements
    }

    pub const fn statement_count(&self) -> usize {
        self.statements.len()
    }

    pub fn statement(&self, origin: ValidatorId) -> Option<&SignedRestartParkedAckV1> {
        self.statements
            .binary_search_by_key(&origin, SignedRestartParkedAckV1::origin)
            .ok()
            .and_then(|index| self.statements.get(index))
    }

    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut output = Vec::with_capacity(64 + self.statements.len() * 64);
        output.extend_from_slice(&self.common.digest());
        output.extend_from_slice(
            &u32::try_from(self.statements.len())
                .expect("direct-seven parked Ack count fits u32")
                .to_be_bytes(),
        );
        for statement in &self.statements {
            put_validator_id(&mut output, statement.origin);
            output.extend_from_slice(&statement.statement_sha256());
        }
        output
    }

    pub fn digest(&self) -> [u8; 32] {
        hash_canonical(
            RESTART_PARKED_ACK_CERTIFICATE_DIGEST_DOMAIN_V1,
            &self.canonical_bytes(),
        )
    }

    pub fn encode(&self) -> Vec<u8> {
        let common = self.common.encode();
        let statements = self
            .statements
            .iter()
            .map(SignedRestartParkedAckV1::encode)
            .collect::<Vec<_>>();
        let total = statements
            .iter()
            .try_fold(8usize + 2 + 4 + common.len() + 4, |size, statement| {
                size.checked_add(4 + statement.len())
            })
            .expect("validated parked Ack certificate length does not overflow");
        assert!(total <= MAX_RESTART_PARKED_ACK_CERTIFICATE_BYTES_V1);
        let mut output = Vec::with_capacity(total);
        output.extend_from_slice(RESTART_PARKED_ACK_CERTIFICATE_MAGIC_V1);
        output.extend_from_slice(&WIRE_VERSION_V1.to_be_bytes());
        put_bytes_u32(&mut output, &common);
        output.extend_from_slice(
            &u32::try_from(statements.len())
                .expect("direct-seven parked Ack count fits u32")
                .to_be_bytes(),
        );
        for statement in statements {
            put_bytes_u32(&mut output, &statement);
        }
        output
    }

    pub fn decode(
        bytes: &[u8],
        fleet_start_certificate: &FleetStartCertificateV1,
        restart_cut_certificate: &RestartCutCertificateV1,
        restart_park_certificate: &RestartParkCertificateV1,
        restart_cut_park_admission_set_sha256: [u8; 32],
        validator_set: &ValidatorSet,
    ) -> Result<Self, RestartCutErrorV1> {
        if bytes.is_empty() || bytes.len() > MAX_RESTART_PARKED_ACK_CERTIFICATE_BYTES_V1 {
            return Err(RestartCutErrorV1::TooLarge);
        }
        let mut cursor = RestartCursor::new(bytes);
        if cursor.take(8)? != RESTART_PARKED_ACK_CERTIFICATE_MAGIC_V1
            || u16::from_be_bytes(cursor.array()?) != WIRE_VERSION_V1
        {
            return Err(RestartCutErrorV1::Malformed(
                "parked Ack certificate header",
            ));
        }
        let common_length = u32::from_be_bytes(cursor.array()?) as usize;
        if common_length == 0 || common_length > MAX_RESTART_PARKED_ACK_COMMON_BYTES_V1 {
            return Err(RestartCutErrorV1::TooLarge);
        }
        let common = RestartParkedAckCommonV1::decode(cursor.take(common_length)?, validator_set)?;
        let count = u32::from_be_bytes(cursor.array()?) as usize;
        if count != 7 || validator_set.validators().len() != 7 {
            return Err(RestartCutErrorV1::Incomplete);
        }
        let mut statements = Vec::with_capacity(count);
        for _ in 0..count {
            let length = u32::from_be_bytes(cursor.array()?) as usize;
            if length == 0 || length > MAX_SIGNED_RESTART_PARKED_ACK_BYTES_V1 {
                return Err(RestartCutErrorV1::TooLarge);
            }
            statements.push(SignedRestartParkedAckV1::decode(
                cursor.take(length)?,
                fleet_start_certificate,
                restart_cut_certificate,
                restart_park_certificate,
                restart_cut_park_admission_set_sha256,
                validator_set,
            )?);
        }
        cursor.finish()?;
        let value = Self::from_statements(
            common,
            statements,
            fleet_start_certificate,
            restart_cut_certificate,
            restart_park_certificate,
            restart_cut_park_admission_set_sha256,
            validator_set,
        )?;
        if value.encode() != bytes {
            return Err(RestartCutErrorV1::NonCanonical);
        }
        Ok(value)
    }

    pub fn verify(
        &self,
        fleet_start_certificate: &FleetStartCertificateV1,
        restart_cut_certificate: &RestartCutCertificateV1,
        restart_park_certificate: &RestartParkCertificateV1,
        restart_cut_park_admission_set_sha256: [u8; 32],
        validator_set: &ValidatorSet,
    ) -> Result<(), RestartCutErrorV1> {
        let rebuilt = Self::from_statements(
            self.common,
            self.statements.clone(),
            fleet_start_certificate,
            restart_cut_certificate,
            restart_park_certificate,
            restart_cut_park_admission_set_sha256,
            validator_set,
        )?;
        if rebuilt.encode() != self.encode() {
            return Err(RestartCutErrorV1::NonCanonical);
        }
        Ok(())
    }
}

/// Deterministic digest of the seven exact ParkedAck-phase transport message
/// IDs. The map must contain every direct-seven member exactly once.
pub(crate) fn restart_parked_ack_admission_set_sha256_for_ids_v1(
    message_ids: &BTreeMap<ValidatorId, [u8; 32]>,
    validator_set: &ValidatorSet,
) -> Result<[u8; 32], RestartCutErrorV1> {
    if validator_set.validators().len() != 7 || message_ids.len() != 7 {
        return Err(RestartCutErrorV1::Incomplete);
    }
    let mut hasher = Sha256::new();
    hasher.update(RESTART_PARKED_ACK_ADMISSION_SET_DOMAIN_V1);
    hasher.update(validator_set.id().as_bytes());
    hasher.update(
        u32::try_from(message_ids.len())
            .map_err(|_| RestartCutErrorV1::TooLarge)?
            .to_be_bytes(),
    );
    for validator in validator_set.validators() {
        let message_id = message_ids
            .get(&validator.id())
            .ok_or(RestartCutErrorV1::Incomplete)?;
        if *message_id == [0; 32] {
            return Err(RestartCutErrorV1::Incomplete);
        }
        hasher.update(validator.id().as_bytes());
        hasher.update(message_id);
    }
    Ok(hasher.finalize().into())
}

/// One origin-authenticated declaration of the exact common RestartCut body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedRestartCutV1 {
    origin: ValidatorId,
    body: RestartCutBodyV1,
    signature: [u8; SIGNATURE_BYTES_V1],
}

impl SignedRestartCutV1 {
    pub(crate) fn new(
        origin: ValidatorId,
        body: RestartCutBodyV1,
        validator_set: &ValidatorSet,
        key: &SigningKey,
    ) -> Result<Self, RestartCutErrorV1> {
        body.validate_for_set(validator_set)?;
        require_origin_key(origin, validator_set, key)?;
        let unsigned = encode_signed_cut_unsigned(origin, &body)?;
        Ok(Self {
            origin,
            body,
            signature: key
                .sign(&hash_canonical(CUT_SIGNING_DOMAIN_V1, &unsigned))
                .to_bytes(),
        })
    }

    pub const fn origin(&self) -> ValidatorId {
        self.origin
    }

    pub const fn body(&self) -> &RestartCutBodyV1 {
        &self.body
    }

    pub fn statement_sha256(&self) -> [u8; 32] {
        hash_canonical(CUT_STATEMENT_DIGEST_DOMAIN_V1, &self.encode())
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut output = encode_signed_cut_unsigned(self.origin, &self.body)
            .expect("validated RestartCut statement fits its wire bound");
        output.extend_from_slice(&self.signature);
        output
    }

    pub fn decode(bytes: &[u8], validator_set: &ValidatorSet) -> Result<Self, RestartCutErrorV1> {
        if bytes.len() <= SIGNATURE_BYTES_V1 || bytes.len() > MAX_SIGNED_RESTART_CUT_BYTES_V1 {
            return Err(RestartCutErrorV1::TooLarge);
        }
        let split = bytes.len() - SIGNATURE_BYTES_V1;
        let unsigned = &bytes[..split];
        let signature: [u8; SIGNATURE_BYTES_V1] = bytes[split..]
            .try_into()
            .map_err(|_| RestartCutErrorV1::Malformed("signature"))?;
        let mut cursor = RestartCursor::new(unsigned);
        if cursor.take(8)? != SIGNED_CUT_MAGIC_V1
            || u16::from_be_bytes(cursor.array()?) != WIRE_VERSION_V1
        {
            return Err(RestartCutErrorV1::Malformed("signed cut header"));
        }
        let origin = cursor.validator_id()?;
        let body_length = u32::from_be_bytes(cursor.array()?) as usize;
        let body = RestartCutBodyV1::decode(cursor.take(body_length)?, validator_set)?;
        cursor.finish()?;
        let value = Self {
            origin,
            body,
            signature,
        };
        value.verify(validator_set)?;
        if value.encode() != bytes {
            return Err(RestartCutErrorV1::NonCanonical);
        }
        Ok(value)
    }

    pub fn verify(&self, validator_set: &ValidatorSet) -> Result<(), RestartCutErrorV1> {
        self.body.validate_for_set(validator_set)?;
        let validator = validator_set
            .validator(self.origin)
            .ok_or(RestartCutErrorV1::UnknownOrigin)?;
        let key = VerifyingKey::from_bytes(validator.consensus_key().as_bytes())
            .map_err(|_| RestartCutErrorV1::InvalidSignature)?;
        let unsigned = encode_signed_cut_unsigned(self.origin, &self.body)?;
        key.verify_strict(
            &hash_canonical(CUT_SIGNING_DOMAIN_V1, &unsigned),
            &Signature::from_bytes(&self.signature),
        )
        .map_err(|_| RestartCutErrorV1::InvalidSignature)
    }

    /// Authenticates both the declaration signature and the exact durable
    /// FleetStartCertificate whose target-local config digest is embedded in
    /// the common cut. Operational peers must use this join before signing a
    /// target's RestartCut; signature-only [`Self::verify`] remains an inert
    /// wire check.
    pub fn verify_with_fleet_start_certificate(
        &self,
        fleet_start_certificate: &FleetStartCertificateV1,
        validator_set: &ValidatorSet,
    ) -> Result<(), RestartCutErrorV1> {
        self.verify(validator_set)?;
        self.body
            .validate_fleet_start_certificate(fleet_start_certificate, validator_set)
    }

    /// Consumes one declaration into the only carrier peers may use as a
    /// RestartPrepare authorization. The declaration must be authored by the
    /// target itself and joined to the exact FleetStartCertificate.
    pub fn verify_target_prepare_owned(
        self,
        fleet_start_certificate: &FleetStartCertificateV1,
        validator_set: &ValidatorSet,
    ) -> Result<VerifiedRestartPrepareV1, RestartCutErrorV1> {
        self.verify_with_fleet_start_certificate(fleet_start_certificate, validator_set)?;
        if self.origin != self.body.target_validator {
            return Err(RestartCutErrorV1::PrepareOriginIsNotTarget);
        }
        Ok(VerifiedRestartPrepareV1 { declaration: self })
    }
}

/// The single Cut-phase payload for one validator in the direct-seven park
/// protocol. It retains the existing RestartCut declaration and the same
/// origin's complete local-park statement, so the fixed five-phase ingress
/// does not need a second Cut slot or a fifth phase.
///
/// Construction is verification-only: this type has no signing-key input and
/// grants no signer, journal, network, process-control, or activation power.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestartCutParkStatementV1 {
    cut: SignedRestartCutV1,
    park: SignedLocalRestartParkV1,
}

impl RestartCutParkStatementV1 {
    pub fn new(
        cut: SignedRestartCutV1,
        park: SignedLocalRestartParkV1,
        fleet_start_certificate: &FleetStartCertificateV1,
        validator_set: &ValidatorSet,
    ) -> Result<Self, RestartCutErrorV1> {
        let value = Self { cut, park };
        value.verify(fleet_start_certificate, validator_set)?;
        Ok(value)
    }

    pub const fn origin(&self) -> ValidatorId {
        self.cut.origin
    }

    pub const fn body(&self) -> &RestartCutBodyV1 {
        &self.cut.body
    }

    pub const fn cut(&self) -> &SignedRestartCutV1 {
        &self.cut
    }

    pub const fn park(&self) -> &SignedLocalRestartParkV1 {
        &self.park
    }

    pub fn statement_sha256(&self) -> [u8; 32] {
        hash_canonical(RESTART_CUT_PARK_STATEMENT_DIGEST_DOMAIN_V1, &self.encode())
    }

    pub fn encode(&self) -> Vec<u8> {
        let cut = self.cut.encode();
        let park = self.park.encode();
        let total = 8usize
            .checked_add(2 + 4 + cut.len() + 4 + park.len())
            .expect("validated dual Cut/Park statement length does not overflow");
        assert!(total <= MAX_RESTART_CUT_PARK_STATEMENT_BYTES_V1);
        let mut output = Vec::with_capacity(total);
        output.extend_from_slice(RESTART_CUT_PARK_STATEMENT_MAGIC_V1);
        output.extend_from_slice(&WIRE_VERSION_V1.to_be_bytes());
        put_bytes_u32(&mut output, &cut);
        put_bytes_u32(&mut output, &park);
        output
    }

    pub fn decode(
        bytes: &[u8],
        fleet_start_certificate: &FleetStartCertificateV1,
        validator_set: &ValidatorSet,
    ) -> Result<Self, RestartCutErrorV1> {
        if bytes.is_empty() || bytes.len() > MAX_RESTART_CUT_PARK_STATEMENT_BYTES_V1 {
            return Err(RestartCutErrorV1::TooLarge);
        }
        let mut cursor = RestartCursor::new(bytes);
        if cursor.take(8)? != RESTART_CUT_PARK_STATEMENT_MAGIC_V1
            || u16::from_be_bytes(cursor.array()?) != WIRE_VERSION_V1
        {
            return Err(RestartCutErrorV1::Malformed(
                "dual Cut/Park statement header",
            ));
        }
        let cut_length = u32::from_be_bytes(cursor.array()?) as usize;
        if cut_length == 0 || cut_length > MAX_SIGNED_RESTART_CUT_BYTES_V1 {
            return Err(RestartCutErrorV1::TooLarge);
        }
        let cut = SignedRestartCutV1::decode(cursor.take(cut_length)?, validator_set)?;
        let park_length = u32::from_be_bytes(cursor.array()?) as usize;
        if park_length == 0 || park_length > MAX_SIGNED_LOCAL_RESTART_PARK_BYTES_V1 {
            return Err(RestartCutErrorV1::TooLarge);
        }
        let park = SignedLocalRestartParkV1::decode(
            cursor.take(park_length)?,
            cut.body(),
            fleet_start_certificate,
            validator_set,
        )?;
        cursor.finish()?;
        let value = Self::new(cut, park, fleet_start_certificate, validator_set)?;
        if value.encode() != bytes {
            return Err(RestartCutErrorV1::NonCanonical);
        }
        Ok(value)
    }

    pub fn verify(
        &self,
        fleet_start_certificate: &FleetStartCertificateV1,
        validator_set: &ValidatorSet,
    ) -> Result<(), RestartCutErrorV1> {
        if validator_set.validators().len() != 7 {
            return Err(RestartCutErrorV1::WrongCampaign);
        }
        self.cut
            .verify_with_fleet_start_certificate(fleet_start_certificate, validator_set)?;
        if self.cut.origin != self.park.origin
            || self.park.local_park.local_validator != self.cut.origin
        {
            return Err(RestartCutErrorV1::Malformed(
                "dual Cut/Park origin relation",
            ));
        }
        self.park
            .verify(&self.cut.body, fleet_start_certificate, validator_set)?;
        Ok(())
    }
}

/// Non-Clone proof that one target signed its own exact, FleetStart-bound
/// RestartPrepare declaration. This carrier grants no process-control or
/// restart authority; it can only be consumed into one local co-signature of
/// the same common cut.
#[must_use = "a verified target RestartPrepare may be consumed exactly once"]
pub struct VerifiedRestartPrepareV1 {
    declaration: SignedRestartCutV1,
}

impl std::fmt::Debug for VerifiedRestartPrepareV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("VerifiedRestartPrepareV1")
            .field("target_validator", &self.declaration.body.target_validator)
            .field("process_instance", &self.declaration.body.process_instance)
            .field("body_digest", &self.declaration.body.digest())
            .finish_non_exhaustive()
    }
}

impl VerifiedRestartPrepareV1 {
    pub const fn target_declaration(&self) -> &SignedRestartCutV1 {
        &self.declaration
    }

    pub const fn body(&self) -> &RestartCutBodyV1 {
        &self.declaration.body
    }

    /// Emits one local declaration over exactly the verified target body.
    /// The carrier is consumed so an operational state machine cannot reuse
    /// one admitted prepare to drive multiple local signing transitions.
    pub fn into_local_declaration(
        self,
        local_validator: ValidatorId,
        validator_set: &ValidatorSet,
        key: &SigningKey,
    ) -> Result<SignedRestartCutV1, RestartCutErrorV1> {
        SignedRestartCutV1::new(local_validator, self.declaration.body, validator_set, key)
    }
}

/// Canonical full N/N certificate.  The wire statements are retained so an
/// independent verifier can recheck every signature rather than trusting a
/// compact digest projection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestartCutCertificateV1 {
    body: RestartCutBodyV1,
    statements: Vec<SignedRestartCutV1>,
}

impl RestartCutCertificateV1 {
    pub fn new(
        statements: Vec<SignedRestartCutV1>,
        fleet_start_certificate: &FleetStartCertificateV1,
        validator_set: &ValidatorSet,
    ) -> Result<Self, RestartCutErrorV1> {
        let value = Self::from_statements(statements, validator_set)?;
        value
            .body
            .validate_fleet_start_certificate(fleet_start_certificate, validator_set)?;
        Ok(value)
    }

    fn from_statements(
        statements: Vec<SignedRestartCutV1>,
        validator_set: &ValidatorSet,
    ) -> Result<Self, RestartCutErrorV1> {
        let first_body = statements
            .first()
            .ok_or(RestartCutErrorV1::Incomplete)?
            .body
            .clone();
        first_body.validate_for_set(validator_set)?;
        let mut canonical = BTreeMap::new();
        for statement in statements {
            statement.verify(validator_set)?;
            if statement.body != first_body {
                return Err(RestartCutErrorV1::DifferentCut);
            }
            if canonical.insert(statement.origin, statement).is_some() {
                return Err(RestartCutErrorV1::DuplicateOrigin);
            }
        }
        if canonical.len() != validator_set.validators().len()
            || validator_set
                .validators()
                .iter()
                .any(|validator| !canonical.contains_key(&validator.id()))
        {
            return Err(RestartCutErrorV1::Incomplete);
        }
        Ok(Self {
            body: first_body,
            statements: canonical.into_values().collect(),
        })
    }

    pub const fn body(&self) -> &RestartCutBodyV1 {
        &self.body
    }

    pub fn statements(&self) -> &[SignedRestartCutV1] {
        &self.statements
    }

    pub const fn statement_count(&self) -> usize {
        self.statements.len()
    }

    pub fn statement(&self, origin: ValidatorId) -> Option<&SignedRestartCutV1> {
        self.statements
            .binary_search_by_key(&origin, SignedRestartCutV1::origin)
            .ok()
            .and_then(|index| self.statements.get(index))
    }

    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut output = Vec::with_capacity(68 + self.statements.len() * 96);
        output.extend_from_slice(&self.body.digest());
        output.extend_from_slice(
            &u32::try_from(self.statements.len())
                .expect("validator count is u32-bound")
                .to_be_bytes(),
        );
        for statement in &self.statements {
            put_validator_id(&mut output, statement.origin);
            output.extend_from_slice(&statement.statement_sha256());
        }
        output
    }

    pub fn digest(&self) -> [u8; 32] {
        hash_canonical(CUT_CERTIFICATE_DIGEST_DOMAIN_V1, &self.canonical_bytes())
    }

    pub fn encode(&self) -> Vec<u8> {
        let encoded = self
            .statements
            .iter()
            .map(SignedRestartCutV1::encode)
            .collect::<Vec<_>>();
        let total = encoded
            .iter()
            .try_fold(8usize + 2 + 4, |size, statement| {
                size.checked_add(4 + statement.len())
            })
            .expect("validated RestartCut certificate length does not overflow");
        assert!(total <= MAX_RESTART_CUT_CERTIFICATE_BYTES_V1);
        let mut output = Vec::with_capacity(total);
        output.extend_from_slice(CUT_CERTIFICATE_MAGIC_V1);
        output.extend_from_slice(&WIRE_VERSION_V1.to_be_bytes());
        output.extend_from_slice(
            &u32::try_from(encoded.len())
                .expect("validator count is u32-bound")
                .to_be_bytes(),
        );
        for statement in encoded {
            put_bytes_u32(&mut output, &statement);
        }
        output
    }

    /// Decodes and authenticates all N statements, but does not issue the
    /// verified carrier until the separately supplied FleetStartCertificate
    /// artifact has also been joined by [`Self::verify_owned`].
    pub fn decode(bytes: &[u8], validator_set: &ValidatorSet) -> Result<Self, RestartCutErrorV1> {
        if bytes.is_empty() || bytes.len() > MAX_RESTART_CUT_CERTIFICATE_BYTES_V1 {
            return Err(RestartCutErrorV1::TooLarge);
        }
        if !matches!(validator_set.validators().len(), 7 | 31 | 100) {
            return Err(RestartCutErrorV1::WrongCampaign);
        }
        let mut cursor = RestartCursor::new(bytes);
        if cursor.take(8)? != CUT_CERTIFICATE_MAGIC_V1
            || u16::from_be_bytes(cursor.array()?) != WIRE_VERSION_V1
        {
            return Err(RestartCutErrorV1::Malformed("cut certificate header"));
        }
        let count = u32::from_be_bytes(cursor.array()?) as usize;
        if count != validator_set.validators().len() {
            return Err(RestartCutErrorV1::Incomplete);
        }
        let mut statements = Vec::with_capacity(count);
        for _ in 0..count {
            let length = u32::from_be_bytes(cursor.array()?) as usize;
            if length == 0 || length > MAX_SIGNED_RESTART_CUT_BYTES_V1 {
                return Err(RestartCutErrorV1::TooLarge);
            }
            statements.push(SignedRestartCutV1::decode(
                cursor.take(length)?,
                validator_set,
            )?);
        }
        cursor.finish()?;
        let value = Self::from_statements(statements, validator_set)?;
        if value.encode() != bytes {
            return Err(RestartCutErrorV1::NonCanonical);
        }
        Ok(value)
    }

    pub fn verify_owned(
        self,
        fleet_start_certificate: &FleetStartCertificateV1,
        validator_set: &ValidatorSet,
    ) -> Result<VerifiedRestartCutCertificateV1, RestartCutErrorV1> {
        let rebuilt = Self::from_statements(self.statements.clone(), validator_set)?;
        if rebuilt.encode() != self.encode() || rebuilt.body != self.body {
            return Err(RestartCutErrorV1::NonCanonical);
        }
        self.body
            .validate_fleet_start_certificate(fleet_start_certificate, validator_set)?;
        let artifact_sha256 = Sha256::digest(self.encode()).into();
        Ok(VerifiedRestartCutCertificateV1 {
            certificate: self,
            artifact_sha256,
        })
    }

    pub fn decode_verified(
        bytes: &[u8],
        fleet_start_certificate: &FleetStartCertificateV1,
        validator_set: &ValidatorSet,
    ) -> Result<VerifiedRestartCutCertificateV1, RestartCutErrorV1> {
        Self::decode(bytes, validator_set)?.verify_owned(fleet_start_certificate, validator_set)
    }
}

/// Non-Clone proof that all N declarations, their common cut, and the exact
/// raw FleetStartCertificate artifact have been authenticated together.
#[must_use = "the verified RestartCut carrier is the only N/N process-kill authorization"]
pub struct VerifiedRestartCutCertificateV1 {
    certificate: RestartCutCertificateV1,
    artifact_sha256: [u8; 32],
}

impl std::fmt::Debug for VerifiedRestartCutCertificateV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("VerifiedRestartCutCertificateV1")
            .field("target_validator", &self.certificate.body.target_validator)
            .field("process_instance", &self.certificate.body.process_instance)
            .field("statement_count", &self.certificate.statements.len())
            .field("artifact_sha256", &self.artifact_sha256)
            .finish_non_exhaustive()
    }
}

impl VerifiedRestartCutCertificateV1 {
    pub const fn certificate(&self) -> &RestartCutCertificateV1 {
        &self.certificate
    }

    pub const fn body(&self) -> &RestartCutBodyV1 {
        &self.certificate.body
    }

    pub const fn artifact_sha256(&self) -> [u8; 32] {
        self.artifact_sha256
    }

    pub fn into_certificate(self) -> RestartCutCertificateV1 {
        self.certificate
    }
}

fn validate_state(
    state: RestartCutStateV1,
    campaign_epoch: u64,
    validator_set: &ValidatorSet,
) -> Result<(), RestartCutErrorV1> {
    let expected_current_view = state
        .direct_high_qc
        .view()
        .get()
        .checked_add(1)
        .ok_or(RestartCutErrorV1::Malformed("restart state relation"))?;
    let durable_total = state
        .signer_durable_vote_intent_count
        .checked_add(state.signer_durable_timeout_intent_count)
        .ok_or(RestartCutErrorV1::Malformed("restart state relation"))?;
    let signed_total = state
        .signer_signed_vote_intent_count
        .checked_add(state.signer_signed_timeout_intent_count)
        .ok_or(RestartCutErrorV1::Malformed("restart state relation"))?;
    let signer_event_total = durable_total
        .checked_add(signed_total)
        .ok_or(RestartCutErrorV1::Malformed("restart state relation"))?;

    if state.epoch.get() != campaign_epoch
        || state.direct_high_qc.epoch() != state.epoch
        || state.direct_high_qc.validator_set_id() != validator_set.id()
        || state.current_view.get() != expected_current_view
        || state.proposal_parent_height != state.direct_high_qc.height()
        || state.proposal_parent_block_id != state.direct_high_qc.block_id()
        || state.application_height != state.finalized_height
        || state.application_block_id != state.finalized_block_id
        || state.direct_high_qc.height() < state.finalized_height
        || state.finalized_height.get() == 0
        || state.external_checkpoint_generation == 0
        || state.safety_revision == 0
        || state.pending_sign.is_some()
        || state.signer_durable_vote_intent_count != state.signer_signed_vote_intent_count
        || state.signer_durable_timeout_intent_count != state.signer_signed_timeout_intent_count
        || state.signer_watermark.sequence() != signer_event_total
        || state.replay_archive_head_sequence == 0
        || state.runtime_journal_head_sequence == 0
    {
        return Err(RestartCutErrorV1::Malformed("restart state relation"));
    }
    if state.direct_high_qc.qc_digest() == CertificateId::ZERO
        || state.direct_high_qc.block_id() == BlockId::ZERO
        || state.direct_high_qc.validator_set_id() == ValidatorSetId::ZERO
        || state.proposal_parent_block_id == BlockId::ZERO
        || state.finalized_block_id == BlockId::ZERO
        || state.application_block_id == BlockId::ZERO
        || state.application_state_root == StateRoot::ZERO
        || [
            state.external_checkpoint_checksum,
            state.safety_state_record_checksum,
            state.safety_record_chain_checksum,
            state.signer_watermark.scope(),
            state.signer_watermark.journal_id(),
            state.signer_watermark.chain_checksum(),
            state.signer_inventory_digest,
            state.finalized_chain_root,
            state.replay_archive_context_sha256,
            state.replay_archive_head_sha256,
            state.runtime_journal_head_sha256,
        ]
        .contains(&[0; 32])
    {
        return Err(RestartCutErrorV1::Malformed("restart state digest"));
    }
    Ok(())
}

fn encode_state(state: RestartCutStateV1, output: &mut Vec<u8>) {
    output.extend_from_slice(&state.epoch.get().to_be_bytes());
    output.extend_from_slice(&state.current_view.get().to_be_bytes());
    output.push(1); // exact direct ordinary high-QC reference
    output.extend_from_slice(state.direct_high_qc.qc_digest().as_bytes());
    output.extend_from_slice(&state.direct_high_qc.epoch().get().to_be_bytes());
    output.extend_from_slice(&state.direct_high_qc.view().get().to_be_bytes());
    output.extend_from_slice(&state.direct_high_qc.height().get().to_be_bytes());
    output.extend_from_slice(state.direct_high_qc.block_id().as_bytes());
    output.extend_from_slice(state.direct_high_qc.validator_set_id().as_bytes());
    output.extend_from_slice(&state.proposal_parent_height.get().to_be_bytes());
    output.extend_from_slice(state.proposal_parent_block_id.as_bytes());
    output.extend_from_slice(&state.finalized_height.get().to_be_bytes());
    output.extend_from_slice(state.finalized_block_id.as_bytes());
    output.extend_from_slice(&state.finalized_chain_root);
    output.extend_from_slice(&state.application_height.get().to_be_bytes());
    output.extend_from_slice(state.application_block_id.as_bytes());
    output.extend_from_slice(state.application_state_root.as_bytes());
    output.extend_from_slice(&state.external_checkpoint_generation.to_be_bytes());
    output.extend_from_slice(&state.external_checkpoint_checksum);
    output.extend_from_slice(&state.safety_revision.to_be_bytes());
    output.extend_from_slice(&state.safety_state_record_checksum);
    output.extend_from_slice(&state.safety_record_chain_checksum);
    output.extend_from_slice(&state.signer_watermark.scope());
    output.extend_from_slice(&state.signer_watermark.journal_id());
    output.extend_from_slice(&state.signer_watermark.sequence().to_be_bytes());
    output.extend_from_slice(&state.signer_watermark.chain_checksum());
    output.extend_from_slice(&state.signer_durable_vote_intent_count.to_be_bytes());
    output.extend_from_slice(&state.signer_durable_timeout_intent_count.to_be_bytes());
    output.extend_from_slice(&state.signer_signed_vote_intent_count.to_be_bytes());
    output.extend_from_slice(&state.signer_signed_timeout_intent_count.to_be_bytes());
    output.extend_from_slice(&state.signer_inventory_digest);
    match state.pending_sign {
        None => output.push(0),
        Some(fingerprint) => {
            output.push(1);
            output.extend_from_slice(&fingerprint);
        }
    }
    output.extend_from_slice(&state.replay_archive_context_sha256);
    output.extend_from_slice(&state.replay_archive_head_sequence.to_be_bytes());
    output.extend_from_slice(&state.replay_archive_head_sha256);
    output.extend_from_slice(&state.runtime_journal_head_sequence.to_be_bytes());
    output.extend_from_slice(&state.runtime_journal_head_sha256);
}

fn decode_state(cursor: &mut RestartCursor<'_>) -> Result<RestartCutStateV1, RestartCutErrorV1> {
    let epoch = Epoch::new(u64::from_be_bytes(cursor.array()?));
    let current_view = View::new(u64::from_be_bytes(cursor.array()?));
    if cursor.byte()? != 1 {
        return Err(RestartCutErrorV1::Malformed("direct high-QC tag"));
    }
    let direct_high_qc = QcRef::new(
        CertificateId::new(cursor.array()?),
        Epoch::new(u64::from_be_bytes(cursor.array()?)),
        View::new(u64::from_be_bytes(cursor.array()?)),
        Height::new(u64::from_be_bytes(cursor.array()?)),
        BlockId::new(cursor.array()?),
        ValidatorSetId::new(cursor.array()?),
    );
    let proposal_parent_height = Height::new(u64::from_be_bytes(cursor.array()?));
    let proposal_parent_block_id = BlockId::new(cursor.array()?);
    let finalized_height = Height::new(u64::from_be_bytes(cursor.array()?));
    let finalized_block_id = BlockId::new(cursor.array()?);
    let finalized_chain_root = cursor.array()?;
    let application_height = Height::new(u64::from_be_bytes(cursor.array()?));
    let application_block_id = BlockId::new(cursor.array()?);
    let application_state_root = StateRoot::new(cursor.array()?);
    let external_checkpoint_generation = u64::from_be_bytes(cursor.array()?);
    let external_checkpoint_checksum = cursor.array()?;
    let safety_revision = u64::from_be_bytes(cursor.array()?);
    let safety_state_record_checksum = cursor.array()?;
    let safety_record_chain_checksum = cursor.array()?;
    let signer_watermark = SignerWatermarkV0::from_persisted_parts(
        cursor.array()?,
        cursor.array()?,
        u64::from_be_bytes(cursor.array()?),
        cursor.array()?,
    )
    .map_err(|_| RestartCutErrorV1::Malformed("signer watermark"))?;
    let signer_durable_vote_intent_count = u64::from_be_bytes(cursor.array()?);
    let signer_durable_timeout_intent_count = u64::from_be_bytes(cursor.array()?);
    let signer_signed_vote_intent_count = u64::from_be_bytes(cursor.array()?);
    let signer_signed_timeout_intent_count = u64::from_be_bytes(cursor.array()?);
    let signer_inventory_digest = cursor.array()?;
    let pending_sign = match cursor.byte()? {
        0 => None,
        1 => Some(cursor.array()?),
        _ => return Err(RestartCutErrorV1::Malformed("pending-sign tag")),
    };
    Ok(RestartCutStateV1 {
        epoch,
        current_view,
        direct_high_qc,
        proposal_parent_height,
        proposal_parent_block_id,
        finalized_height,
        finalized_block_id,
        finalized_chain_root,
        application_height,
        application_block_id,
        application_state_root,
        external_checkpoint_generation,
        external_checkpoint_checksum,
        safety_revision,
        safety_state_record_checksum,
        safety_record_chain_checksum,
        signer_watermark,
        signer_durable_vote_intent_count,
        signer_durable_timeout_intent_count,
        signer_signed_vote_intent_count,
        signer_signed_timeout_intent_count,
        signer_inventory_digest,
        pending_sign,
        replay_archive_context_sha256: cursor.array()?,
        replay_archive_head_sequence: u64::from_be_bytes(cursor.array()?),
        replay_archive_head_sha256: cursor.array()?,
        runtime_journal_head_sequence: u64::from_be_bytes(cursor.array()?),
        runtime_journal_head_sha256: cursor.array()?,
    })
}

fn validate_local_restart_park_statement_parts(
    origin: ValidatorId,
    restart_cut_body: &RestartCutBodyV1,
    local_park: &LocalRestartParkV1,
    fleet_start_certificate: &FleetStartCertificateV1,
    validator_set: &ValidatorSet,
) -> Result<(), RestartCutErrorV1> {
    if origin != local_park.local_validator {
        return Err(RestartCutErrorV1::Malformed("local park statement origin"));
    }
    local_park.validate_for_restart_body(restart_cut_body, fleet_start_certificate, validator_set)
}

fn encode_signed_local_restart_park_unsigned(
    origin: ValidatorId,
    restart_cut_body_sha256: [u8; 32],
    local_park_sha256: [u8; 32],
    local_park: &LocalRestartParkV1,
) -> Result<Vec<u8>, RestartCutErrorV1> {
    let local_park = local_park.encode();
    let mut output = Vec::with_capacity(local_park.len() + 128);
    output.extend_from_slice(SIGNED_LOCAL_RESTART_PARK_MAGIC_V1);
    output.extend_from_slice(&WIRE_VERSION_V1.to_be_bytes());
    put_validator_id(&mut output, origin);
    output.extend_from_slice(&restart_cut_body_sha256);
    output.extend_from_slice(&local_park_sha256);
    put_bytes_u32(&mut output, &local_park);
    if output.len() + SIGNATURE_BYTES_V1 > MAX_SIGNED_LOCAL_RESTART_PARK_BYTES_V1 {
        return Err(RestartCutErrorV1::TooLarge);
    }
    Ok(output)
}

#[allow(clippy::too_many_arguments)]
fn validate_restart_parked_ack_statement_parts(
    common: &RestartParkedAckCommonV1,
    origin: ValidatorId,
    role: RestartParkRoleV1,
    local_config_sha256: [u8; 32],
    local_park_statement_sha256: [u8; 32],
    predecessor_sequence: u64,
    predecessor_sha256: [u8; 32],
    restart_cut_event_sequence: u64,
    restart_cut_event_sha256: [u8; 32],
    restart_park_event_sequence: u64,
    restart_park_event_sha256: [u8; 32],
    fleet_start_certificate: &FleetStartCertificateV1,
    restart_cut_certificate: &RestartCutCertificateV1,
    restart_park_certificate: &RestartParkCertificateV1,
    restart_cut_park_admission_set_sha256: [u8; 32],
    validator_set: &ValidatorSet,
) -> Result<(), RestartCutErrorV1> {
    common.verify_exact(
        fleet_start_certificate,
        restart_cut_certificate,
        restart_park_certificate,
        restart_cut_park_admission_set_sha256,
        validator_set,
    )?;
    let local_park_statement = restart_park_certificate
        .statement(origin)
        .ok_or(RestartCutErrorV1::UnknownOrigin)?;
    let local_park = local_park_statement.local_park();
    if local_park.local_validator() != origin
        || local_park.role() != role
        || local_park.local_config_sha256() != local_config_sha256
        || local_park_statement.statement_sha256() != local_park_statement_sha256
    {
        return Err(RestartCutErrorV1::Malformed(
            "parked Ack local Park relation",
        ));
    }
    match role {
        RestartParkRoleV1::Target if origin == common.target_validator => {}
        RestartParkRoleV1::Peer if origin != common.target_validator => {}
        _ => {
            return Err(RestartCutErrorV1::Malformed("parked Ack role relation"));
        }
    }
    let local_state = local_park.local_state();
    let expected_restart_cut_event_sequence = predecessor_sequence
        .checked_add(1)
        .ok_or(RestartCutErrorV1::Malformed("parked Ack journal sequence"))?;
    let expected_restart_park_event_sequence = restart_cut_event_sequence
        .checked_add(1)
        .ok_or(RestartCutErrorV1::Malformed("parked Ack journal sequence"))?;
    if predecessor_sequence != local_state.runtime_journal_head_sequence
        || predecessor_sha256 != local_state.runtime_journal_head_sha256
        || restart_cut_event_sequence != expected_restart_cut_event_sequence
        || restart_park_event_sequence != expected_restart_park_event_sequence
        || local_config_sha256 == [0; 32]
        || local_park_statement_sha256 == [0; 32]
        || predecessor_sha256 == [0; 32]
        || restart_cut_event_sha256 == [0; 32]
        || restart_park_event_sha256 == [0; 32]
    {
        return Err(RestartCutErrorV1::Malformed("parked Ack journal chain"));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn encode_signed_restart_parked_ack_unsigned(
    common: RestartParkedAckCommonV1,
    origin: ValidatorId,
    role: RestartParkRoleV1,
    local_config_sha256: [u8; 32],
    local_park_statement_sha256: [u8; 32],
    predecessor_sequence: u64,
    predecessor_sha256: [u8; 32],
    restart_cut_event_sequence: u64,
    restart_cut_event_sha256: [u8; 32],
    restart_park_event_sequence: u64,
    restart_park_event_sha256: [u8; 32],
) -> Result<Vec<u8>, RestartCutErrorV1> {
    let common = common.encode();
    let mut output = Vec::with_capacity(common.len() + 320);
    output.extend_from_slice(SIGNED_RESTART_PARKED_ACK_MAGIC_V1);
    output.extend_from_slice(&WIRE_VERSION_V1.to_be_bytes());
    put_bytes_u32(&mut output, &common);
    put_validator_id(&mut output, origin);
    output.push(role.wire_tag());
    output.extend_from_slice(&local_config_sha256);
    output.extend_from_slice(&local_park_statement_sha256);
    output.extend_from_slice(&predecessor_sequence.to_be_bytes());
    output.extend_from_slice(&predecessor_sha256);
    output.extend_from_slice(&restart_cut_event_sequence.to_be_bytes());
    output.extend_from_slice(&restart_cut_event_sha256);
    output.extend_from_slice(&restart_park_event_sequence.to_be_bytes());
    output.extend_from_slice(&restart_park_event_sha256);
    if output.len() + SIGNATURE_BYTES_V1 > MAX_SIGNED_RESTART_PARKED_ACK_BYTES_V1 {
        return Err(RestartCutErrorV1::TooLarge);
    }
    Ok(output)
}

fn encode_signed_cut_unsigned(
    origin: ValidatorId,
    body: &RestartCutBodyV1,
) -> Result<Vec<u8>, RestartCutErrorV1> {
    let body = body.encode();
    let mut output = Vec::with_capacity(body.len() + 64);
    output.extend_from_slice(SIGNED_CUT_MAGIC_V1);
    output.extend_from_slice(&WIRE_VERSION_V1.to_be_bytes());
    put_validator_id(&mut output, origin);
    put_bytes_u32(&mut output, &body);
    if output.len() + SIGNATURE_BYTES_V1 > MAX_SIGNED_RESTART_CUT_BYTES_V1 {
        return Err(RestartCutErrorV1::TooLarge);
    }
    Ok(output)
}

fn require_origin_key(
    origin: ValidatorId,
    validator_set: &ValidatorSet,
    key: &SigningKey,
) -> Result<(), RestartCutErrorV1> {
    let validator = validator_set
        .validator(origin)
        .ok_or(RestartCutErrorV1::UnknownOrigin)?;
    if validator.consensus_key().as_bytes() != &key.verifying_key().to_bytes() {
        return Err(RestartCutErrorV1::OriginKeyMismatch);
    }
    Ok(())
}

fn hash_canonical(domain: &[u8], canonical: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update((canonical.len() as u64).to_be_bytes());
    hasher.update(canonical);
    hasher.finalize().into()
}

fn put_bytes_u32(output: &mut Vec<u8>, value: &[u8]) {
    output.extend_from_slice(
        &u32::try_from(value.len())
            .expect("bounded RestartCut field fits u32")
            .to_be_bytes(),
    );
    output.extend_from_slice(value);
}

fn put_validator_id(output: &mut Vec<u8>, value: ValidatorId) {
    output.extend_from_slice(
        &u16::try_from(value.as_bytes().len())
            .expect("validated ValidatorId fits u16")
            .to_be_bytes(),
    );
    output.extend_from_slice(value.as_bytes());
}

struct RestartCursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> RestartCursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], RestartCutErrorV1> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(RestartCutErrorV1::TooLarge)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(RestartCutErrorV1::Malformed("truncated payload"))?;
        self.offset = end;
        Ok(value)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], RestartCutErrorV1> {
        self.take(N)?
            .try_into()
            .map_err(|_| RestartCutErrorV1::Malformed("array"))
    }

    fn byte(&mut self) -> Result<u8, RestartCutErrorV1> {
        self.take(1)?
            .first()
            .copied()
            .ok_or(RestartCutErrorV1::Malformed("byte"))
    }

    fn validator_id(&mut self) -> Result<ValidatorId, RestartCutErrorV1> {
        let length = u16::from_be_bytes(self.array()?) as usize;
        ValidatorId::from_bytes(self.take(length)?)
            .map_err(|_| RestartCutErrorV1::Malformed("validator ID"))
    }

    fn finish(self) -> Result<(), RestartCutErrorV1> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(RestartCutErrorV1::Malformed("trailing payload"))
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RestartCutErrorV1 {
    Malformed(&'static str),
    TooLarge,
    WrongCampaign,
    UnknownTarget,
    UnknownOrigin,
    OriginKeyMismatch,
    InvalidSignature,
    InvalidFleetStartCertificate,
    WrongProtocolPhase,
    AuthenticatedOriginMismatch,
    DifferentAdmissionMap,
    PrepareOriginIsNotTarget,
    DuplicateOrigin,
    Incomplete,
    DifferentCut,
    NonCanonical,
}

impl std::fmt::Display for RestartCutErrorV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Malformed(field) => write!(formatter, "malformed RestartCut field: {field}"),
            Self::TooLarge => formatter.write_str("RestartCut payload crosses its bound"),
            Self::WrongCampaign => formatter.write_str("RestartCut campaign differs"),
            Self::UnknownTarget => {
                formatter.write_str("RestartCut target is outside validator set")
            }
            Self::UnknownOrigin => {
                formatter.write_str("RestartCut signer is outside validator set")
            }
            Self::OriginKeyMismatch => {
                formatter.write_str("RestartCut signer key differs from origin")
            }
            Self::InvalidSignature => formatter.write_str("RestartCut signature is invalid"),
            Self::InvalidFleetStartCertificate => {
                formatter.write_str("RestartCut FleetStartCertificate binding is invalid")
            }
            Self::WrongProtocolPhase => {
                formatter.write_str("restart statement occupied the wrong protocol phase")
            }
            Self::AuthenticatedOriginMismatch => formatter.write_str(
                "restart statement author differs from its authenticated transport origin",
            ),
            Self::DifferentAdmissionMap => formatter.write_str(
                "restart statements came from different bounded admission-map instances",
            ),
            Self::PrepareOriginIsNotTarget => {
                formatter.write_str("RestartPrepare declaration is not authored by its target")
            }
            Self::DuplicateOrigin => formatter.write_str("RestartCut signer is duplicated"),
            Self::Incomplete => formatter.write_str("RestartCut certificate is not N/N complete"),
            Self::DifferentCut => formatter.write_str("RestartCut declarations differ"),
            Self::NonCanonical => formatter.write_str("RestartCut wire is non-canonical"),
        }
    }
}

impl std::error::Error for RestartCutErrorV1 {}

#[cfg(test)]
mod tests {
    use std::{
        fs::{self, File},
        io::Write,
        os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
        path::Path,
    };

    use tempfile::TempDir;

    use crate::{
        fleet_barrier::{
            CommonChainCutV1, FleetBarrierTransportV1, FleetCampaignCapacitiesV1,
            FleetCampaignIdentityV1, FleetCampaignRequestV1, FleetMeshSessionDirectionV1,
            FleetMeshSessionSetV1, FleetMeshSessionV1, FleetReadySetV1, LocalReadyCutV1,
            SignedFleetReadyV1, SignedFleetStartV1,
        },
        frame::AuthenticatedFrame,
        restart_cut_store::{
            load_restart_cut_at_test_root_v1, persist_restart_cut_at_test_root_v1,
        },
        restart_park_protocol::{
            AdmittedRestartCutParkV1, AdmittedRestartPrepareV1, OriginatedRestartCutParkV1,
            OriginatedRestartPrepareV1, VerifiedRestartCutParkCertificatesV1,
        },
        restart_protocol::{
            AdmittedRestartProtocolMessageV1, BoundedRestartProtocolIngressV1,
            RestartProtocolPhaseV1,
        },
    };
    use trnm_consensus_types::{
        ChainId, ConsensusParametersV0, ConsensusPublicKey, GenesisHash, ProtocolVersion,
        Validator, VotingPower,
    };

    use super::*;

    const RESTART_PROTOCOL_TEST_RUN_ID: &str = "poco-g3-7-20260818T010000Z-b1c2d3e4";

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

    fn admit_restart_message(
        ingress: &mut BoundedRestartProtocolIngressV1,
        origin: ValidatorId,
        key: &SigningKey,
        phase: RestartProtocolPhaseV1,
        payload: Vec<u8>,
    ) -> AdmittedRestartProtocolMessageV1 {
        let bytes = AuthenticatedFrame {
            sender: origin,
            session: [0x51; 32],
            sequence: 0,
            kind: phase.frame_kind(),
            payload,
        }
        .encode(RESTART_PROTOCOL_TEST_RUN_ID, key)
        .unwrap();
        ingress
            .admit_verified_signed_frame_bytes_v1(&bytes)
            .unwrap()
            .action
            .unwrap()
            .into_admitted_message_v1()
    }

    fn admitted_dual_barrier(
        set: &ValidatorSet,
        keys: &[SigningKey],
        start: &FleetStartCertificateV1,
        target_prepare: &SignedRestartCutV1,
        statements: &[RestartCutParkStatementV1],
    ) -> (AdmittedRestartPrepareV1, Vec<AdmittedRestartCutParkV1>) {
        let mut ingress = BoundedRestartProtocolIngressV1::new(
            RESTART_PROTOCOL_TEST_RUN_ID,
            set.validators()[0].id(),
            set.clone(),
        )
        .unwrap();
        let prepare = AdmittedRestartPrepareV1::new(
            admit_restart_message(
                &mut ingress,
                target_prepare.origin(),
                &keys[set
                    .validators()
                    .iter()
                    .position(|validator| validator.id() == target_prepare.origin())
                    .unwrap()],
                RestartProtocolPhaseV1::Prepare,
                target_prepare.encode(),
            ),
            start,
            set,
        )
        .unwrap();
        let statements = statements
            .iter()
            .map(|statement| {
                AdmittedRestartCutParkV1::new(
                    admit_restart_message(
                        &mut ingress,
                        statement.origin(),
                        &keys[set
                            .validators()
                            .iter()
                            .position(|validator| validator.id() == statement.origin())
                            .unwrap()],
                        RestartProtocolPhaseV1::Cut,
                        statement.encode(),
                    ),
                    start,
                    set,
                )
                .unwrap()
            })
            .collect();
        (prepare, statements)
    }

    fn private_restart_cut_root() -> TempDir {
        let temporary = TempDir::new().unwrap();
        fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(temporary.path().canonicalize().unwrap(), temporary.path());
        temporary
    }

    fn write_restart_cut_test_artifact(root: &Path, name: &str, bytes: &[u8]) {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(root.join(name))
            .unwrap();
        file.write_all(bytes).unwrap();
        file.sync_all().unwrap();
        File::open(root).unwrap().sync_all().unwrap();
    }

    fn restart_cut_writing_name(process_id: u32, attempt: u64) -> String {
        format!("restart-cut-certificate.writing.{process_id:08x}.{attempt:016x}")
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

    fn restart_cut_and_park_certificates(
        set: &ValidatorSet,
        keys: &[SigningKey],
        start: &FleetStartCertificateV1,
        body: &RestartCutBodyV1,
    ) -> (RestartCutCertificateV1, RestartParkCertificateV1) {
        let cut = RestartCutCertificateV1::new(statements(set, keys, body), start, set).unwrap();
        let park = RestartParkCertificateV1::new(
            body.clone(),
            park_statements(set, keys, start, body),
            start,
            set,
        )
        .unwrap();
        (cut, park)
    }

    fn parked_ack_statements(
        set: &ValidatorSet,
        keys: &[SigningKey],
        start: &FleetStartCertificateV1,
        cut: &RestartCutCertificateV1,
        park: &RestartParkCertificateV1,
        prior_admission_set_sha256: [u8; 32],
    ) -> (RestartParkedAckCommonV1, Vec<SignedRestartParkedAckV1>) {
        let common =
            RestartParkedAckCommonV1::new(start, cut, park, prior_admission_set_sha256, set)
                .unwrap();
        let statements = set
            .validators()
            .iter()
            .enumerate()
            .map(|(index, validator)| {
                let local_park_statement = park.statement(validator.id()).unwrap();
                let local_park = local_park_statement.local_park();
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
                    local_park_statement.statement_sha256(),
                    predecessor_sequence,
                    predecessor_sha256,
                    restart_cut_event_sequence,
                    restart_cut_event_sha256,
                    restart_park_event_sequence,
                    restart_park_event_sha256,
                    start,
                    cut,
                    park,
                    prior_admission_set_sha256,
                    set,
                )
                .unwrap();
                SignedRestartParkedAckV1::from_parts(
                    common,
                    validator.id(),
                    local_park.role(),
                    local_park.local_config_sha256(),
                    local_park_statement.statement_sha256(),
                    predecessor_sequence,
                    predecessor_sha256,
                    restart_cut_event_sequence,
                    restart_cut_event_sha256,
                    restart_park_event_sequence,
                    restart_park_event_sha256,
                    keys[index].sign(&digest).to_bytes(),
                    start,
                    cut,
                    park,
                    prior_admission_set_sha256,
                    set,
                )
                .unwrap()
            })
            .collect();
        (common, statements)
    }

    fn encode_parked_ack_certificate_in_statement_order(
        common: RestartParkedAckCommonV1,
        statements: &[SignedRestartParkedAckV1],
    ) -> Vec<u8> {
        let mut output = Vec::new();
        output.extend_from_slice(RESTART_PARKED_ACK_CERTIFICATE_MAGIC_V1);
        output.extend_from_slice(&WIRE_VERSION_V1.to_be_bytes());
        put_bytes_u32(&mut output, &common.encode());
        output.extend_from_slice(&(statements.len() as u32).to_be_bytes());
        for statement in statements {
            put_bytes_u32(&mut output, &statement.encode());
        }
        output
    }

    fn encode_park_certificate_in_statement_order(
        body: &RestartCutBodyV1,
        shared_cut: RestartSharedCutV1,
        statements: &[SignedLocalRestartParkV1],
    ) -> Vec<u8> {
        let mut output = Vec::new();
        output.extend_from_slice(RESTART_PARK_CERTIFICATE_MAGIC_V1);
        output.extend_from_slice(&WIRE_VERSION_V1.to_be_bytes());
        put_bytes_u32(&mut output, &body.encode());
        put_bytes_u32(&mut output, &shared_cut.encode());
        output.extend_from_slice(&(statements.len() as u32).to_be_bytes());
        for statement in statements {
            put_bytes_u32(&mut output, &statement.encode());
        }
        output
    }

    fn statements(
        set: &ValidatorSet,
        keys: &[SigningKey],
        body: &RestartCutBodyV1,
    ) -> Vec<SignedRestartCutV1> {
        keys.iter()
            .enumerate()
            .map(|(index, key)| {
                SignedRestartCutV1::new(set.validators()[index].id(), body.clone(), set, key)
                    .unwrap()
            })
            .collect()
    }

    fn dual_statements(
        set: &ValidatorSet,
        keys: &[SigningKey],
        start: &FleetStartCertificateV1,
        body: &RestartCutBodyV1,
    ) -> Vec<RestartCutParkStatementV1> {
        statements(set, keys, body)
            .into_iter()
            .zip(park_statements(set, keys, start, body))
            .map(|(cut, park)| RestartCutParkStatementV1::new(cut, park, start, set).unwrap())
            .collect()
    }

    #[test]
    fn signed_local_park_roundtrips_from_public_preimage_and_strict_signature_parts() {
        let (set, keys) = validator_fixture();
        let campaign = campaign(&set);
        let start = fleet_start_certificate(&set, &keys, &campaign, 0xd0);
        let body = restart_body(&set, &campaign, &start);
        let park = target_restart_park(&set, &start, &body);
        let origin = park.local_validator();
        let key_index = set
            .validators()
            .iter()
            .position(|validator| validator.id() == origin)
            .unwrap();
        let preimage = SignedLocalRestartParkV1::signing_preimage_for_parts(
            origin, &body, &park, &start, &set,
        )
        .unwrap();
        let digest =
            SignedLocalRestartParkV1::signing_digest_for_parts(origin, &body, &park, &start, &set)
                .unwrap();
        assert_eq!(
            digest,
            hash_canonical(LOCAL_RESTART_PARK_SIGNING_DOMAIN_V1, &preimage)
        );
        let body_digest = body.digest();
        let park_digest = park.digest();
        let park_bytes = park.encode();
        assert!(preimage
            .windows(body_digest.len())
            .any(|window| window == &body_digest[..]));
        assert!(preimage
            .windows(park_digest.len())
            .any(|window| window == &park_digest[..]));
        assert!(preimage
            .windows(park_bytes.len())
            .any(|window| window == park_bytes.as_slice()));

        let statement = SignedLocalRestartParkV1::from_parts(
            origin,
            &body,
            park,
            keys[key_index].sign(&digest).to_bytes(),
            &start,
            &set,
        )
        .unwrap();
        assert_eq!(statement.origin(), origin);
        assert_eq!(statement.restart_cut_body_sha256(), body.digest());
        assert_eq!(statement.local_park_sha256(), park.digest());
        assert_eq!(statement.local_park(), &park);
        assert_ne!(statement.statement_sha256(), [0; 32]);
        statement.verify(&body, &start, &set).unwrap();
        assert_eq!(
            SignedLocalRestartParkV1::decode(&statement.encode(), &body, &start, &set,).unwrap(),
            statement
        );
    }

    #[test]
    fn strict_local_park_signature_binds_body_digest_full_park_bytes_and_park_digest() {
        let (set, keys) = validator_fixture();
        let campaign = campaign(&set);
        let start = fleet_start_certificate(&set, &keys, &campaign, 0xd0);
        let body = restart_body(&set, &campaign, &start);
        let target = target_restart_park(&set, &start, &body);
        let statement = signed_park_statement(&set, &keys, &start, &body, target);

        let mut bit_flipped = statement.encode();
        *bit_flipped.last_mut().unwrap() ^= 1;
        assert_eq!(
            SignedLocalRestartParkV1::decode(&bit_flipped, &body, &start, &set),
            Err(RestartCutErrorV1::InvalidSignature)
        );

        assert_eq!(
            SignedLocalRestartParkV1::from_parts(
                target.local_validator(),
                &body,
                target,
                [0xff; SIGNATURE_BYTES_V1],
                &start,
                &set,
            ),
            Err(RestartCutErrorV1::InvalidSignature)
        );

        let target_digest = SignedLocalRestartParkV1::signing_digest_for_parts(
            target.local_validator(),
            &body,
            &target,
            &start,
            &set,
        )
        .unwrap();
        assert_eq!(
            SignedLocalRestartParkV1::from_parts(
                target.local_validator(),
                &body,
                target,
                keys[0].sign(&target_digest).to_bytes(),
                &start,
                &set,
            ),
            Err(RestartCutErrorV1::InvalidSignature)
        );

        let peer = peer_restart_park(&set, &start, &body, 4);
        let peer_statement = signed_park_statement(&set, &keys, &start, &body, peer);
        let mut changed_peer = peer;
        changed_peer.local_state.safety_state_record_checksum = [0xe1; 32];
        changed_peer
            .validate_for_restart_body(&body, &start, &set)
            .unwrap();
        assert_ne!(changed_peer.encode(), peer.encode());
        assert_ne!(changed_peer.digest(), peer.digest());
        let changed_digest = SignedLocalRestartParkV1::signing_digest_for_parts(
            changed_peer.local_validator(),
            &body,
            &changed_peer,
            &start,
            &set,
        )
        .unwrap();
        let original_digest = SignedLocalRestartParkV1::signing_digest_for_parts(
            peer.local_validator(),
            &body,
            &peer,
            &start,
            &set,
        )
        .unwrap();
        assert_ne!(changed_digest, original_digest);
        assert_eq!(
            SignedLocalRestartParkV1::from_parts(
                changed_peer.local_validator(),
                &body,
                changed_peer,
                peer_statement.signature,
                &start,
                &set,
            ),
            Err(RestartCutErrorV1::InvalidSignature)
        );

        let mut changed_state = restart_state(&set);
        changed_state.runtime_journal_head_sha256 = [0xe2; 32];
        let changed_body = RestartCutBodyV1::new(
            campaign,
            body.target_validator(),
            body.target_config_sha256(),
            body.process_instance(),
            changed_state,
            &start,
            &set,
        )
        .unwrap();
        let changed_target = target_restart_park(&set, &start, &changed_body);
        assert_ne!(changed_body.digest(), body.digest());
        assert_eq!(
            SignedLocalRestartParkV1::from_parts(
                changed_target.local_validator(),
                &changed_body,
                changed_target,
                statement.signature,
                &start,
                &set,
            ),
            Err(RestartCutErrorV1::InvalidSignature)
        );

        let mut wrong_park_digest = statement.clone();
        wrong_park_digest.local_park_sha256 = [0xe3; 32];
        assert_eq!(
            wrong_park_digest.verify(&body, &start, &set),
            Err(RestartCutErrorV1::DifferentCut)
        );

        let mut wrong_body_digest = statement;
        wrong_body_digest.restart_cut_body_sha256 = [0xe4; 32];
        assert_eq!(
            wrong_body_digest.verify(&body, &start, &set),
            Err(RestartCutErrorV1::DifferentCut)
        );
    }

    #[test]
    fn restart_park_certificate_roundtrips_canonical_direct_seven_target_and_peers() {
        let (set, keys) = validator_fixture();
        let campaign = campaign(&set);
        let start = fleet_start_certificate(&set, &keys, &campaign, 0xd0);
        let body = restart_body(&set, &campaign, &start);
        let statements = park_statements(&set, &keys, &start, &body);
        let certificate = RestartParkCertificateV1::new(
            body.clone(),
            statements.into_iter().rev().collect(),
            &start,
            &set,
        )
        .unwrap();

        assert_eq!(certificate.body(), &body);
        assert_eq!(certificate.shared_cut(), body.shared_cut_v1());
        assert_eq!(certificate.statement_count(), 7);
        assert_ne!(certificate.digest(), [0; 32]);
        for (index, validator) in set.validators().iter().enumerate() {
            let statement = certificate.statement(validator.id()).unwrap();
            assert_eq!(statement.origin(), validator.id());
            assert_eq!(
                statement.local_park().local_config_sha256(),
                restart_local_config_sha256(&set, &start, index)
            );
            if validator.id() == body.target_validator() {
                assert_eq!(statement.local_park().role(), RestartParkRoleV1::Target);
                assert!(statement.local_park().has_target_park_shape_for(&body));
            } else {
                assert_eq!(statement.local_park().role(), RestartParkRoleV1::Peer);
                assert!(statement.local_park().has_peer_park_shape_for(&body));
            }
        }
        certificate.verify(&start, &set).unwrap();
        let encoded = certificate.encode();
        assert_eq!(
            RestartParkCertificateV1::decode(&encoded, &start, &set).unwrap(),
            certificate
        );
    }

    #[test]
    fn restart_park_certificate_rejects_missing_duplicate_role_config_process_body_and_shared_cut()
    {
        let (set, keys) = validator_fixture();
        let campaign = campaign(&set);
        let start = fleet_start_certificate(&set, &keys, &campaign, 0xd0);
        let body = restart_body(&set, &campaign, &start);
        let canonical = park_statements(&set, &keys, &start, &body);

        assert_eq!(
            RestartParkCertificateV1::new(body.clone(), canonical[..6].to_vec(), &start, &set,),
            Err(RestartCutErrorV1::Incomplete)
        );

        let mut duplicate = canonical.clone();
        duplicate[6] = duplicate[0].clone();
        assert_eq!(
            RestartParkCertificateV1::new(body.clone(), duplicate, &start, &set),
            Err(RestartCutErrorV1::DuplicateOrigin)
        );

        let target_index = canonical
            .iter()
            .position(|statement| statement.origin() == body.target_validator())
            .unwrap();
        let peer_index = canonical
            .iter()
            .position(|statement| statement.origin() != body.target_validator())
            .unwrap();

        let mut alternate_state = restart_state(&set);
        alternate_state.runtime_journal_head_sha256 = [0xd1; 32];
        let alternate_body = RestartCutBodyV1::new(
            campaign.clone(),
            body.target_validator(),
            body.target_config_sha256(),
            body.process_instance(),
            alternate_state,
            &start,
            &set,
        )
        .unwrap();
        let alternate = park_statements(&set, &keys, &start, &alternate_body);
        alternate[peer_index]
            .verify(&alternate_body, &start, &set)
            .unwrap();
        let mut valid_but_different_body = canonical.clone();
        valid_but_different_body[peer_index] = alternate[peer_index].clone();
        assert!(RestartParkCertificateV1::new(
            body.clone(),
            valid_but_different_body,
            &start,
            &set,
        )
        .is_err());

        let different_start = fleet_start_certificate(&set, &keys, &campaign, 0xe0);
        let different_start_body = restart_body(&set, &campaign, &different_start);
        let different_start_statements =
            park_statements(&set, &keys, &different_start, &different_start_body);
        different_start_statements[peer_index]
            .verify(&different_start_body, &different_start, &set)
            .unwrap();
        let mut valid_but_different_start = canonical.clone();
        valid_but_different_start[peer_index] = different_start_statements[peer_index].clone();
        assert!(RestartParkCertificateV1::new(
            body.clone(),
            valid_but_different_start,
            &start,
            &set,
        )
        .is_err());
        assert!(RestartParkCertificateV1::new(
            body.clone(),
            canonical.clone(),
            &different_start,
            &set,
        )
        .is_err());

        let mut wrong_target_role = canonical.clone();
        wrong_target_role[target_index].local_park.role = RestartParkRoleV1::Peer;
        assert!(
            RestartParkCertificateV1::new(body.clone(), wrong_target_role, &start, &set,).is_err()
        );

        let mut wrong_peer_role = canonical.clone();
        wrong_peer_role[peer_index].local_park.role = RestartParkRoleV1::Target;
        assert!(
            RestartParkCertificateV1::new(body.clone(), wrong_peer_role, &start, &set,).is_err()
        );

        let mut wrong_config = canonical.clone();
        wrong_config[peer_index].local_park.local_config_sha256 = [0xe5; 32];
        assert!(RestartParkCertificateV1::new(body.clone(), wrong_config, &start, &set,).is_err());

        let mut wrong_process = canonical.clone();
        wrong_process[peer_index].local_park.process_instance = 2;
        assert!(RestartParkCertificateV1::new(body.clone(), wrong_process, &start, &set,).is_err());

        let mut wrong_body = canonical.clone();
        wrong_body[peer_index].restart_cut_body_sha256 = [0xe6; 32];
        assert!(RestartParkCertificateV1::new(body.clone(), wrong_body, &start, &set,).is_err());

        let mut wrong_origin = canonical.clone();
        wrong_origin[peer_index].origin = body.target_validator();
        assert!(RestartParkCertificateV1::new(body.clone(), wrong_origin, &start, &set,).is_err());

        let mut wrong_shared = canonical.clone();
        wrong_shared[peer_index]
            .local_park
            .shared_cut
            .finalized_chain_root = [0xe7; 32];
        wrong_shared[peer_index]
            .local_park
            .local_state
            .finalized_chain_root = [0xe7; 32];
        wrong_shared[peer_index].local_park_sha256 = wrong_shared[peer_index].local_park.digest();
        assert!(RestartParkCertificateV1::new(body.clone(), wrong_shared, &start, &set,).is_err());

        let certificate = RestartParkCertificateV1::new(body, canonical, &start, &set).unwrap();
        let mut wrong_certificate_shared = certificate.clone();
        wrong_certificate_shared.shared_cut.finalized_chain_root = [0xe8; 32];
        assert_eq!(
            wrong_certificate_shared.verify(&start, &set),
            Err(RestartCutErrorV1::NonCanonical)
        );
    }

    #[test]
    fn park_statement_and_certificate_wire_fail_closed_on_order_truncation_and_trailing_bytes() {
        let (set, keys) = validator_fixture();
        let campaign = campaign(&set);
        let start = fleet_start_certificate(&set, &keys, &campaign, 0xd0);
        let body = restart_body(&set, &campaign, &start);
        let statements = park_statements(&set, &keys, &start, &body);
        let statement = statements[0].clone();
        let certificate =
            RestartParkCertificateV1::new(body.clone(), statements.clone(), &start, &set).unwrap();

        let mut truncated_statement = statement.encode();
        truncated_statement.pop();
        assert!(
            SignedLocalRestartParkV1::decode(&truncated_statement, &body, &start, &set,).is_err()
        );

        let mut trailing_statement = statement.encode();
        trailing_statement.insert(trailing_statement.len() - SIGNATURE_BYTES_V1, 0);
        assert_eq!(
            SignedLocalRestartParkV1::decode(&trailing_statement, &body, &start, &set),
            Err(RestartCutErrorV1::Malformed("trailing payload"))
        );

        let mut obsolete_statement = statement.encode();
        obsolete_statement[8..10].copy_from_slice(&0u16.to_be_bytes());
        assert!(
            SignedLocalRestartParkV1::decode(&obsolete_statement, &body, &start, &set,).is_err()
        );

        let mut reversed = statements;
        reversed.reverse();
        let noncanonical =
            encode_park_certificate_in_statement_order(&body, body.shared_cut_v1(), &reversed);
        assert_eq!(
            RestartParkCertificateV1::decode(&noncanonical, &start, &set),
            Err(RestartCutErrorV1::NonCanonical)
        );

        let mut truncated_certificate = certificate.encode();
        truncated_certificate.pop();
        assert!(RestartParkCertificateV1::decode(&truncated_certificate, &start, &set,).is_err());

        let mut trailing_certificate = certificate.encode();
        trailing_certificate.push(0);
        assert_eq!(
            RestartParkCertificateV1::decode(&trailing_certificate, &start, &set),
            Err(RestartCutErrorV1::Malformed("trailing payload"))
        );
    }

    #[test]
    fn parked_ack_statement_and_certificate_roundtrip_exact_direct_seven_artifacts_and_journal_chain(
    ) {
        let (set, keys) = validator_fixture();
        let campaign = campaign(&set);
        let start = fleet_start_certificate(&set, &keys, &campaign, 0xd0);
        let body = restart_body(&set, &campaign, &start);
        let (cut, park) = restart_cut_and_park_certificates(&set, &keys, &start, &body);
        let prior_admission_set_sha256 = [0xd8; 32];
        let (common, mut statements) =
            parked_ack_statements(&set, &keys, &start, &cut, &park, prior_admission_set_sha256);

        assert_eq!(common.validator_set_id(), set.id());
        assert_eq!(common.target_validator(), body.target_validator());
        assert_eq!(common.process_instance(), 1);
        assert_eq!(
            common.fleet_start_certificate_sha256(),
            <[u8; 32]>::from(Sha256::digest(start.encode()))
        );
        assert_eq!(common.restart_cut_body_sha256(), body.digest());
        assert_eq!(
            common.restart_cut_artifact_sha256(),
            <[u8; 32]>::from(Sha256::digest(cut.encode()))
        );
        assert_eq!(
            common.restart_park_artifact_sha256(),
            <[u8; 32]>::from(Sha256::digest(park.encode()))
        );
        assert_eq!(
            common.restart_cut_park_admission_set_sha256(),
            prior_admission_set_sha256
        );
        assert_ne!(common.digest(), [0; 32]);
        assert_eq!(
            RestartParkedAckCommonV1::decode(&common.encode(), &set).unwrap(),
            common
        );
        common
            .verify_exact(&start, &cut, &park, prior_admission_set_sha256, &set)
            .unwrap();

        for statement in &statements {
            let local_park_statement = park.statement(statement.origin()).unwrap();
            let local_park = local_park_statement.local_park();
            assert_eq!(statement.common(), &common);
            assert_eq!(statement.role(), local_park.role());
            assert_eq!(
                statement.local_config_sha256(),
                local_park.local_config_sha256()
            );
            assert_eq!(
                statement.local_park_statement_sha256(),
                local_park_statement.statement_sha256()
            );
            assert_eq!(
                statement.predecessor_sequence(),
                local_park.local_state().runtime_journal_head_sequence
            );
            assert_eq!(
                statement.predecessor_sha256(),
                local_park.local_state().runtime_journal_head_sha256
            );
            assert_eq!(
                statement.restart_cut_event_sequence(),
                statement.predecessor_sequence() + 1
            );
            assert_eq!(
                statement.restart_park_event_sequence(),
                statement.restart_cut_event_sequence() + 1
            );
            assert_ne!(statement.restart_cut_event_sha256(), [0; 32]);
            assert_ne!(statement.restart_park_event_sha256(), [0; 32]);
            assert_ne!(statement.statement_sha256(), [0; 32]);
            statement
                .verify(&start, &cut, &park, prior_admission_set_sha256, &set)
                .unwrap();
            assert_eq!(
                SignedRestartParkedAckV1::decode(
                    &statement.encode(),
                    &start,
                    &cut,
                    &park,
                    prior_admission_set_sha256,
                    &set,
                )
                .unwrap(),
                *statement
            );
        }

        statements.reverse();
        let certificate = RestartParkedAckCertificateV1::new(
            common,
            statements,
            &start,
            &cut,
            &park,
            prior_admission_set_sha256,
            &set,
        )
        .unwrap();
        assert_eq!(certificate.common(), &common);
        assert_eq!(certificate.statement_count(), 7);
        assert_ne!(certificate.digest(), [0; 32]);
        for validator in set.validators() {
            assert_eq!(
                certificate.statement(validator.id()).unwrap().origin(),
                validator.id()
            );
        }
        certificate
            .verify(&start, &cut, &park, prior_admission_set_sha256, &set)
            .unwrap();
        assert_eq!(
            RestartParkedAckCertificateV1::decode(
                &certificate.encode(),
                &start,
                &cut,
                &park,
                prior_admission_set_sha256,
                &set,
            )
            .unwrap(),
            certificate
        );

        let message_ids = set
            .validators()
            .iter()
            .enumerate()
            .map(|(index, validator)| (validator.id(), [0x71 + u8::try_from(index).unwrap(); 32]))
            .collect::<BTreeMap<_, _>>();
        let admission_set_sha256 =
            restart_parked_ack_admission_set_sha256_for_ids_v1(&message_ids, &set).unwrap();
        assert_ne!(admission_set_sha256, [0; 32]);
        assert_eq!(
            restart_parked_ack_admission_set_sha256_for_ids_v1(&message_ids, &set).unwrap(),
            admission_set_sha256
        );
    }

    #[test]
    fn parked_ack_certificate_rejects_scalar_signature_artifact_chain_and_membership_mutants() {
        let (set, keys) = validator_fixture();
        let campaign = campaign(&set);
        let start = fleet_start_certificate(&set, &keys, &campaign, 0xd0);
        let body = restart_body(&set, &campaign, &start);
        let (cut, park) = restart_cut_and_park_certificates(&set, &keys, &start, &body);
        let prior_admission_set_sha256 = [0xd8; 32];
        let (common, statements) =
            parked_ack_statements(&set, &keys, &start, &cut, &park, prior_admission_set_sha256);
        let certificate = RestartParkedAckCertificateV1::new(
            common,
            statements.clone(),
            &start,
            &cut,
            &park,
            prior_admission_set_sha256,
            &set,
        )
        .unwrap();

        assert_eq!(
            RestartParkedAckCertificateV1::new(
                common,
                statements[..6].to_vec(),
                &start,
                &cut,
                &park,
                prior_admission_set_sha256,
                &set,
            ),
            Err(RestartCutErrorV1::Incomplete)
        );
        let mut duplicate = statements.clone();
        duplicate[6] = duplicate[0].clone();
        assert_eq!(
            RestartParkedAckCertificateV1::new(
                common,
                duplicate,
                &start,
                &cut,
                &park,
                prior_admission_set_sha256,
                &set,
            ),
            Err(RestartCutErrorV1::DuplicateOrigin)
        );

        let mut wrong = statements[0].clone();
        wrong.signature[0] ^= 1;
        assert_eq!(
            wrong.verify(&start, &cut, &park, prior_admission_set_sha256, &set),
            Err(RestartCutErrorV1::InvalidSignature)
        );
        let mut wrong = statements[0].clone();
        wrong.local_config_sha256 = [0xe1; 32];
        assert!(wrong
            .verify(&start, &cut, &park, prior_admission_set_sha256, &set)
            .is_err());
        let mut wrong = statements[0].clone();
        wrong.local_park_statement_sha256 = [0xe2; 32];
        assert!(wrong
            .verify(&start, &cut, &park, prior_admission_set_sha256, &set)
            .is_err());
        let mut wrong = statements[0].clone();
        wrong.predecessor_sequence += 1;
        assert!(wrong
            .verify(&start, &cut, &park, prior_admission_set_sha256, &set)
            .is_err());
        let mut wrong = statements[0].clone();
        wrong.predecessor_sha256 = [0; 32];
        assert!(wrong
            .verify(&start, &cut, &park, prior_admission_set_sha256, &set)
            .is_err());
        let mut wrong = statements[0].clone();
        wrong.restart_cut_event_sequence += 1;
        assert!(wrong
            .verify(&start, &cut, &park, prior_admission_set_sha256, &set)
            .is_err());
        let mut wrong = statements[0].clone();
        wrong.restart_cut_event_sha256 = [0; 32];
        assert!(wrong
            .verify(&start, &cut, &park, prior_admission_set_sha256, &set)
            .is_err());
        let mut wrong = statements[0].clone();
        wrong.restart_park_event_sequence += 1;
        assert!(wrong
            .verify(&start, &cut, &park, prior_admission_set_sha256, &set)
            .is_err());
        let mut wrong = statements[0].clone();
        wrong.restart_park_event_sha256 = [0; 32];
        assert!(wrong
            .verify(&start, &cut, &park, prior_admission_set_sha256, &set)
            .is_err());
        let mut wrong = statements[0].clone();
        wrong.origin = ValidatorId::new([0xee; 32]);
        assert_eq!(
            wrong.verify(&start, &cut, &park, prior_admission_set_sha256, &set),
            Err(RestartCutErrorV1::UnknownOrigin)
        );

        let target_index = statements
            .iter()
            .position(|statement| statement.origin() == body.target_validator())
            .unwrap();
        let mut wrong = statements[target_index].clone();
        wrong.role = RestartParkRoleV1::Peer;
        assert!(wrong
            .verify(&start, &cut, &park, prior_admission_set_sha256, &set)
            .is_err());

        let mut wrong_common_certificate = certificate.clone();
        wrong_common_certificate.common.restart_cut_artifact_sha256 = [0xe3; 32];
        assert!(wrong_common_certificate
            .verify(&start, &cut, &park, prior_admission_set_sha256, &set,)
            .is_err());
        assert!(certificate
            .verify(&start, &cut, &park, [0xe4; 32], &set)
            .is_err());
        let different_start = fleet_start_certificate(&set, &keys, &campaign, 0xe0);
        assert!(certificate
            .verify(
                &different_start,
                &cut,
                &park,
                prior_admission_set_sha256,
                &set,
            )
            .is_err());

        let mut message_ids = set
            .validators()
            .iter()
            .map(|validator| (validator.id(), [0x91; 32]))
            .collect::<BTreeMap<_, _>>();
        message_ids.remove(&set.validators()[0].id());
        assert_eq!(
            restart_parked_ack_admission_set_sha256_for_ids_v1(&message_ids, &set),
            Err(RestartCutErrorV1::Incomplete)
        );
        message_ids.insert(set.validators()[0].id(), [0; 32]);
        assert_eq!(
            restart_parked_ack_admission_set_sha256_for_ids_v1(&message_ids, &set),
            Err(RestartCutErrorV1::Incomplete)
        );
    }

    #[test]
    fn parked_ack_wire_rejects_noncanonical_truncated_trailing_and_oversized_bytes_without_raw_key_api(
    ) {
        let (set, keys) = validator_fixture();
        let campaign = campaign(&set);
        let start = fleet_start_certificate(&set, &keys, &campaign, 0xd0);
        let body = restart_body(&set, &campaign, &start);
        let (cut, park) = restart_cut_and_park_certificates(&set, &keys, &start, &body);
        let prior_admission_set_sha256 = [0xd8; 32];
        let (common, statements) =
            parked_ack_statements(&set, &keys, &start, &cut, &park, prior_admission_set_sha256);
        let certificate = RestartParkedAckCertificateV1::new(
            common,
            statements.clone(),
            &start,
            &cut,
            &park,
            prior_admission_set_sha256,
            &set,
        )
        .unwrap();

        let mut common_trailing = common.encode();
        common_trailing.push(0);
        assert_eq!(
            RestartParkedAckCommonV1::decode(&common_trailing, &set),
            Err(RestartCutErrorV1::Malformed("trailing payload"))
        );

        let mut statement_truncated = statements[0].encode();
        statement_truncated.pop();
        assert!(SignedRestartParkedAckV1::decode(
            &statement_truncated,
            &start,
            &cut,
            &park,
            prior_admission_set_sha256,
            &set,
        )
        .is_err());
        let mut statement_trailing = statements[0].encode();
        statement_trailing.insert(statement_trailing.len() - SIGNATURE_BYTES_V1, 0);
        assert_eq!(
            SignedRestartParkedAckV1::decode(
                &statement_trailing,
                &start,
                &cut,
                &park,
                prior_admission_set_sha256,
                &set,
            ),
            Err(RestartCutErrorV1::Malformed("trailing payload"))
        );

        let mut reversed = statements;
        reversed.reverse();
        assert_eq!(
            RestartParkedAckCertificateV1::decode(
                &encode_parked_ack_certificate_in_statement_order(common, &reversed),
                &start,
                &cut,
                &park,
                prior_admission_set_sha256,
                &set,
            ),
            Err(RestartCutErrorV1::NonCanonical)
        );
        let mut certificate_truncated = certificate.encode();
        certificate_truncated.pop();
        assert!(RestartParkedAckCertificateV1::decode(
            &certificate_truncated,
            &start,
            &cut,
            &park,
            prior_admission_set_sha256,
            &set,
        )
        .is_err());
        let mut certificate_trailing = certificate.encode();
        certificate_trailing.push(0);
        assert_eq!(
            RestartParkedAckCertificateV1::decode(
                &certificate_trailing,
                &start,
                &cut,
                &park,
                prior_admission_set_sha256,
                &set,
            ),
            Err(RestartCutErrorV1::Malformed("trailing payload"))
        );
        assert_eq!(
            RestartParkedAckCertificateV1::decode(
                &vec![0; MAX_RESTART_PARKED_ACK_CERTIFICATE_BYTES_V1 + 1],
                &start,
                &cut,
                &park,
                prior_admission_set_sha256,
                &set,
            ),
            Err(RestartCutErrorV1::TooLarge)
        );

        let source = include_str!("restart_cut.rs");
        let implementation = source
            .split("impl SignedRestartParkedAckV1 {")
            .nth(1)
            .unwrap()
            .split("/// Canonical origin-sorted direct-seven")
            .next()
            .unwrap();
        assert!(!implementation.contains("SigningKey"));
        assert!(!implementation.contains(".sign("));
        assert!(implementation.contains("signing_digest_for_parts"));
        assert!(implementation.contains("from_parts"));
        assert!(implementation.contains("verify_strict("));
    }

    #[test]
    fn local_park_statement_normal_api_has_no_raw_signing_key_constructor() {
        let source = include_str!("restart_cut.rs");
        let implementation = source
            .split("impl SignedLocalRestartParkV1 {")
            .nth(1)
            .unwrap()
            .split("/// Canonical direct-seven N/N")
            .next()
            .unwrap();
        assert!(!implementation.contains("SigningKey"));
        assert!(!implementation.contains(".sign("));
        assert!(implementation.contains("signing_preimage_for_parts"));
        assert!(implementation.contains("from_parts"));
        assert!(implementation.contains("verify_strict("));
    }

    #[test]
    fn shared_cut_is_the_canonical_direct_seven_body_projection() {
        let (set, keys) = validator_fixture();
        let campaign = campaign(&set);
        let start = fleet_start_certificate(&set, &keys, &campaign, 0xd0);
        let body = restart_body(&set, &campaign, &start);
        let shared = body.shared_cut_v1();

        assert_eq!(shared.epoch(), set.epoch());
        assert_eq!(shared.finalized_height(), Height::new(6));
        assert_eq!(shared.finalized_block_id(), BlockId::new([0x83; 32]));
        assert_eq!(shared.finalized_chain_root(), [0x8f; 32]);
        assert_eq!(shared.application_height(), Height::new(6));
        assert_eq!(shared.application_block_id(), BlockId::new([0x83; 32]));
        assert_eq!(shared.application_state_root(), StateRoot::new([0x84; 32]));
        assert_ne!(shared.digest(), [0; 32]);
        shared.validate_for_set(&set).unwrap();
        assert_eq!(
            RestartSharedCutV1::decode(&shared.encode(), &set).unwrap(),
            shared
        );

        let mut wrong_epoch = shared;
        wrong_epoch.epoch = Epoch::new(1);
        assert!(wrong_epoch.validate_for_set(&set).is_err());

        let mut zero_height = shared;
        zero_height.finalized_height = Height::new(0);
        zero_height.application_height = Height::new(0);
        assert!(zero_height.validate_for_set(&set).is_err());

        let mut wrong_application_height = shared;
        wrong_application_height.application_height = Height::new(7);
        assert!(wrong_application_height.validate_for_set(&set).is_err());

        let mut wrong_application_block = shared;
        wrong_application_block.application_block_id = BlockId::new([0xe1; 32]);
        assert!(wrong_application_block.validate_for_set(&set).is_err());

        let mut zero_finalized_block = shared;
        zero_finalized_block.finalized_block_id = BlockId::ZERO;
        zero_finalized_block.application_block_id = BlockId::ZERO;
        assert!(zero_finalized_block.validate_for_set(&set).is_err());

        let mut zero_chain_root = shared;
        zero_chain_root.finalized_chain_root = [0; 32];
        assert!(zero_chain_root.validate_for_set(&set).is_err());

        let mut zero_application_root = shared;
        zero_application_root.application_state_root = StateRoot::ZERO;
        assert!(zero_application_root.validate_for_set(&set).is_err());
    }

    #[test]
    fn target_and_peer_local_parks_roundtrip_and_rejoin_exact_body_and_config() {
        let (set, keys) = validator_fixture();
        let campaign = campaign(&set);
        let start = fleet_start_certificate(&set, &keys, &campaign, 0xd0);
        let body = restart_body(&set, &campaign, &start);
        let target = target_restart_park(&set, &start, &body);
        let peer = peer_restart_park(&set, &start, &body, 4);

        assert_eq!(target.role(), RestartParkRoleV1::Target);
        assert_eq!(target.local_validator(), body.target_validator());
        assert_eq!(target.local_config_sha256(), body.target_config_sha256());
        assert_eq!(target.process_instance(), body.process_instance());
        assert_eq!(target.restart_cut_body_sha256(), body.digest());
        assert_eq!(target.shared_cut(), body.shared_cut_v1());
        assert_eq!(target.local_state(), body.state());
        assert!(target.has_target_park_shape_for(&body));
        assert!(!target.has_peer_park_shape_for(&body));
        assert!(peer.has_peer_park_shape_for(&body));
        assert!(!peer.has_target_park_shape_for(&body));
        assert_ne!(peer.local_state(), body.state());
        assert_eq!(peer.shared_cut(), target.shared_cut());
        assert_ne!(target.digest(), peer.digest());

        for park in [target, peer] {
            park.validate_for_set(&set).unwrap();
            park.validate_for_restart_body(&body, &start, &set).unwrap();
            assert_eq!(
                LocalRestartParkV1::decode(&park.encode(), &set).unwrap(),
                park
            );
        }
    }

    #[test]
    fn local_park_role_config_process_body_and_shared_cut_mutants_fail_closed() {
        let (set, keys) = validator_fixture();
        let campaign = campaign(&set);
        let start = fleet_start_certificate(&set, &keys, &campaign, 0xd0);
        let body = restart_body(&set, &campaign, &start);
        let target = target_restart_park(&set, &start, &body);
        let peer = peer_restart_park(&set, &start, &body, 4);

        let mut wrong_target_role = target;
        wrong_target_role.role = RestartParkRoleV1::Peer;
        assert!(wrong_target_role
            .validate_for_restart_body(&body, &start, &set)
            .is_err());

        let mut wrong_peer_role = peer;
        wrong_peer_role.role = RestartParkRoleV1::Target;
        assert!(wrong_peer_role
            .validate_for_restart_body(&body, &start, &set)
            .is_err());

        let mut wrong_config = target;
        wrong_config.local_config_sha256 = [0xe1; 32];
        assert!(wrong_config
            .validate_for_restart_body(&body, &start, &set)
            .is_err());

        let mut wrong_process = target;
        wrong_process.process_instance = 2;
        assert!(wrong_process.validate_for_set(&set).is_err());

        let mut wrong_body_digest = target;
        wrong_body_digest.restart_cut_body_sha256 = [0xe2; 32];
        assert!(wrong_body_digest
            .validate_for_restart_body(&body, &start, &set)
            .is_err());

        let mut wrong_shared = target;
        wrong_shared.shared_cut.finalized_chain_root = [0xe3; 32];
        assert!(wrong_shared.validate_for_set(&set).is_err());

        let mut internally_consistent_other_shared = target;
        internally_consistent_other_shared
            .shared_cut
            .finalized_chain_root = [0xe4; 32];
        internally_consistent_other_shared
            .local_state
            .finalized_chain_root = [0xe4; 32];
        internally_consistent_other_shared
            .validate_for_set(&set)
            .unwrap();
        assert!(internally_consistent_other_shared
            .validate_for_restart_body(&body, &start, &set)
            .is_err());
    }

    #[test]
    fn target_local_durable_journal_safety_checkpoint_signer_and_archive_are_exact() {
        let (set, keys) = validator_fixture();
        let campaign = campaign(&set);
        let start = fleet_start_certificate(&set, &keys, &campaign, 0xd0);
        let body = restart_body(&set, &campaign, &start);
        let target = target_restart_park(&set, &start, &body);

        let mut journal = target;
        journal.local_state.runtime_journal_head_sha256 = [0xf1; 32];
        journal.validate_for_set(&set).unwrap();
        assert!(journal
            .validate_for_restart_body(&body, &start, &set)
            .is_err());

        let mut safety = target;
        safety.local_state.safety_revision += 1;
        safety.local_state.safety_state_record_checksum = [0xf2; 32];
        safety.validate_for_set(&set).unwrap();
        assert!(safety
            .validate_for_restart_body(&body, &start, &set)
            .is_err());

        let mut checkpoint = target;
        checkpoint.local_state.external_checkpoint_generation += 1;
        checkpoint.local_state.external_checkpoint_checksum = [0xf3; 32];
        checkpoint.validate_for_set(&set).unwrap();
        assert!(checkpoint
            .validate_for_restart_body(&body, &start, &set)
            .is_err());

        let mut signer = target;
        signer.local_state.signer_inventory_digest = [0xf4; 32];
        signer.validate_for_set(&set).unwrap();
        assert!(signer
            .validate_for_restart_body(&body, &start, &set)
            .is_err());

        let mut archive = target;
        archive.local_state.replay_archive_head_sha256 = [0xf5; 32];
        archive.validate_for_set(&set).unwrap();
        assert!(archive
            .validate_for_restart_body(&body, &start, &set)
            .is_err());

        let mut zero_journal = target;
        zero_journal.local_state.runtime_journal_head_sequence = 0;
        assert!(zero_journal.validate_for_set(&set).is_err());

        let mut pending_sign = target;
        pending_sign.local_state.pending_sign = Some([0xf6; 32]);
        assert!(pending_sign.validate_for_set(&set).is_err());

        let mut inconsistent_signer = target;
        inconsistent_signer
            .local_state
            .signer_signed_vote_intent_count += 1;
        assert!(inconsistent_signer.validate_for_set(&set).is_err());

        let mut zero_archive = target;
        zero_archive.local_state.replay_archive_context_sha256 = [0; 32];
        assert!(zero_archive.validate_for_set(&set).is_err());
    }

    #[test]
    fn shared_cut_and_local_park_reject_old_truncated_trailing_and_unknown_role_wire() {
        let (set, keys) = validator_fixture();
        let campaign = campaign(&set);
        let start = fleet_start_certificate(&set, &keys, &campaign, 0xd0);
        let body = restart_body(&set, &campaign, &start);
        let shared = body.shared_cut_v1();
        let park = target_restart_park(&set, &start, &body);
        let shared_bytes = shared.encode();
        let park_bytes = park.encode();

        for cutoff in 0..shared_bytes.len() {
            assert!(RestartSharedCutV1::decode(&shared_bytes[..cutoff], &set).is_err());
        }
        for cutoff in 0..park_bytes.len() {
            assert!(LocalRestartParkV1::decode(&park_bytes[..cutoff], &set).is_err());
        }

        let mut trailing_shared = shared_bytes.clone();
        trailing_shared.push(0);
        assert_eq!(
            RestartSharedCutV1::decode(&trailing_shared, &set),
            Err(RestartCutErrorV1::Malformed("trailing payload"))
        );

        let mut trailing_park = park_bytes.clone();
        trailing_park.push(0);
        assert_eq!(
            LocalRestartParkV1::decode(&trailing_park, &set),
            Err(RestartCutErrorV1::Malformed("trailing payload"))
        );

        let mut obsolete_shared_version = shared_bytes;
        obsolete_shared_version[8..10].copy_from_slice(&0u16.to_be_bytes());
        assert!(RestartSharedCutV1::decode(&obsolete_shared_version, &set).is_err());

        let mut obsolete_park_version = park_bytes.clone();
        obsolete_park_version[8..10].copy_from_slice(&0u16.to_be_bytes());
        assert!(LocalRestartParkV1::decode(&obsolete_park_version, &set).is_err());

        let mut unknown_role = park_bytes;
        unknown_role[10] = 3;
        assert_eq!(
            LocalRestartParkV1::decode(&unknown_role, &set),
            Err(RestartCutErrorV1::Malformed("local park role"))
        );

        assert!(RestartSharedCutV1::decode(&body.encode(), &set).is_err());
        assert!(LocalRestartParkV1::decode(&body.encode(), &set).is_err());
    }

    #[test]
    fn signed_cut_roundtrips_into_canonical_n_of_n_verified_carrier() {
        let (set, keys) = validator_fixture();
        let campaign = campaign(&set);
        let start = fleet_start_certificate(&set, &keys, &campaign, 0xd0);
        let body = restart_body(&set, &campaign, &start);
        assert_eq!(body.run_id(), campaign.identity().run_id());
        assert_eq!(body.coordinator_manifest_sha256(), [0x43; 32]);
        assert_eq!(body.topology_sha256(), [0x42; 32]);
        assert_eq!(body.validator_set_sha256(), [0x41; 32]);
        assert_eq!(body.target_config_sha256(), [0x63; 32]);
        assert_eq!(body.state(), restart_state(&set));
        assert_eq!(body.finalized_chain_root_v1(), [0x8f; 32]);
        assert!(body.pending_sign_is_none());
        assert_eq!(
            RestartCutBodyV1::decode(&body.encode(), &set).unwrap(),
            body
        );

        let statements = statements(&set, &keys, &body);
        for statement in &statements {
            assert_eq!(
                SignedRestartCutV1::decode(&statement.encode(), &set).unwrap(),
                *statement
            );
        }
        let certificate =
            RestartCutCertificateV1::new(statements.into_iter().rev().collect(), &start, &set)
                .unwrap();
        assert_eq!(certificate.statements().len(), set.validators().len());
        assert_eq!(
            certificate.statements()[0].origin(),
            set.validators()[0].id()
        );
        assert_ne!(certificate.digest(), [0; 32]);
        let encoded = certificate.encode();
        let decoded = RestartCutCertificateV1::decode(&encoded, &set).unwrap();
        assert_eq!(decoded, certificate);
        let verified = RestartCutCertificateV1::decode_verified(&encoded, &start, &set).unwrap();
        assert_eq!(verified.body(), &body);
        let expected_artifact_sha256: [u8; 32] = Sha256::digest(&encoded).into();
        assert_eq!(verified.artifact_sha256(), expected_artifact_sha256);
        assert_ne!(verified.artifact_sha256(), certificate.digest());
    }

    #[test]
    fn dual_cut_park_statement_roundtrips_and_binds_exact_origin_body_and_role() {
        let (set, keys) = validator_fixture();
        let campaign = campaign(&set);
        let start = fleet_start_certificate(&set, &keys, &campaign, 0xd0);
        let body = restart_body(&set, &campaign, &start);
        let dual = dual_statements(&set, &keys, &start, &body);

        for statement in &dual {
            statement.verify(&start, &set).unwrap();
            assert_eq!(statement.cut().origin(), statement.origin());
            assert_eq!(statement.park().origin(), statement.origin());
            assert_eq!(statement.body(), &body);
            assert_ne!(statement.statement_sha256(), [0; 32]);
            let bytes = statement.encode();
            assert_eq!(
                RestartCutParkStatementV1::decode(&bytes, &start, &set).unwrap(),
                *statement
            );
        }

        assert!(RestartCutParkStatementV1::new(
            dual[0].cut().clone(),
            dual[1].park().clone(),
            &start,
            &set,
        )
        .is_err());

        let mut trailing = dual[0].encode();
        trailing.push(0);
        assert_eq!(
            RestartCutParkStatementV1::decode(&trailing, &start, &set),
            Err(RestartCutErrorV1::Malformed("trailing payload"))
        );
        let mut obsolete = dual[0].encode();
        obsolete[8..10].copy_from_slice(&0u16.to_be_bytes());
        assert!(RestartCutParkStatementV1::decode(&obsolete, &start, &set).is_err());
    }

    #[test]
    fn seven_dual_cut_park_statements_form_both_exact_certificates() {
        let (set, keys) = validator_fixture();
        let campaign = campaign(&set);
        let start = fleet_start_certificate(&set, &keys, &campaign, 0xd0);
        let body = restart_body(&set, &campaign, &start);
        let dual = dual_statements(&set, &keys, &start, &body);
        let target_prepare = dual
            .iter()
            .find(|statement| statement.origin() == body.target_validator())
            .unwrap()
            .cut()
            .clone();
        let mut reversed = dual.clone();
        reversed.reverse();
        let (admitted_prepare, admitted_cut) =
            admitted_dual_barrier(&set, &keys, &start, &target_prepare, &reversed);
        let verified =
            VerifiedRestartCutParkCertificatesV1::new(admitted_prepare, admitted_cut, &start, &set)
                .unwrap();
        verified.revalidate_v1(&start, &set).unwrap();
        assert_eq!(verified.body_v1(), &body);
        assert_ne!(verified.prepare_message_id_v1(), [0; 32]);
        assert_ne!(verified.admission_set_sha256_v1(), [0; 32]);
        assert_eq!(verified.statement_count_v1(), 7);
        for validator in set.validators() {
            assert_ne!(
                verified.statement_message_id_v1(validator.id()).unwrap(),
                [0; 32]
            );
        }
        assert_ne!(
            verified
                .statement_message_id_v1(body.target_validator())
                .unwrap(),
            verified.prepare_message_id_v1()
        );
        let expected_cut_sha256 = RestartCutCertificateV1::new(
            dual.iter()
                .map(|statement| statement.cut().clone())
                .collect(),
            &start,
            &set,
        )
        .unwrap()
        .verify_owned(&start, &set)
        .unwrap()
        .artifact_sha256();
        let expected_park_sha256: [u8; 32] = Sha256::digest(
            RestartParkCertificateV1::new(
                body.clone(),
                dual.iter()
                    .map(|statement| statement.park().clone())
                    .collect(),
                &start,
                &set,
            )
            .unwrap()
            .encode(),
        )
        .into();
        assert_eq!(verified.cut_artifact_sha256_v1(), expected_cut_sha256);
        assert_eq!(verified.park_artifact_sha256_v1(), expected_park_sha256);

        let (incomplete_prepare, mut incomplete) =
            admitted_dual_barrier(&set, &keys, &start, &target_prepare, &dual);
        incomplete.pop();
        assert_eq!(
            VerifiedRestartCutParkCertificatesV1::new(
                incomplete_prepare,
                incomplete,
                &start,
                &set,
            )
            .unwrap_err(),
            RestartCutErrorV1::Incomplete
        );
        let (duplicate_prepare, mut duplicate) =
            admitted_dual_barrier(&set, &keys, &start, &target_prepare, &dual);
        duplicate.pop();
        let mut second_ingress = BoundedRestartProtocolIngressV1::new(
            RESTART_PROTOCOL_TEST_RUN_ID,
            set.validators()[0].id(),
            set.clone(),
        )
        .unwrap();
        duplicate.push(
            AdmittedRestartCutParkV1::new(
                admit_restart_message(
                    &mut second_ingress,
                    dual[0].origin(),
                    &keys[0],
                    RestartProtocolPhaseV1::Cut,
                    dual[0].encode(),
                ),
                &start,
                &set,
            )
            .unwrap(),
        );
        assert_eq!(
            VerifiedRestartCutParkCertificatesV1::new(duplicate_prepare, duplicate, &start, &set,)
                .unwrap_err(),
            RestartCutErrorV1::DifferentAdmissionMap
        );
        let peer_prepare = dual
            .iter()
            .find(|statement| statement.origin() != body.target_validator())
            .unwrap()
            .cut()
            .clone();
        let mut peer_prepare_ingress = BoundedRestartProtocolIngressV1::new(
            RESTART_PROTOCOL_TEST_RUN_ID,
            set.validators()[0].id(),
            set.clone(),
        )
        .unwrap();
        let peer_index = set
            .validators()
            .iter()
            .position(|validator| validator.id() == peer_prepare.origin())
            .unwrap();
        assert_eq!(
            AdmittedRestartPrepareV1::new(
                admit_restart_message(
                    &mut peer_prepare_ingress,
                    peer_prepare.origin(),
                    &keys[peer_index],
                    RestartProtocolPhaseV1::Prepare,
                    peer_prepare.encode(),
                ),
                &start,
                &set,
            )
            .unwrap_err(),
            RestartCutErrorV1::PrepareOriginIsNotTarget
        );

        let mut wrong_phase_ingress = BoundedRestartProtocolIngressV1::new(
            RESTART_PROTOCOL_TEST_RUN_ID,
            set.validators()[0].id(),
            set.clone(),
        )
        .unwrap();
        let target_index = set
            .validators()
            .iter()
            .position(|validator| validator.id() == target_prepare.origin())
            .unwrap();
        assert_eq!(
            AdmittedRestartPrepareV1::new(
                admit_restart_message(
                    &mut wrong_phase_ingress,
                    target_prepare.origin(),
                    &keys[target_index],
                    RestartProtocolPhaseV1::Cut,
                    target_prepare.encode(),
                ),
                &start,
                &set,
            )
            .unwrap_err(),
            RestartCutErrorV1::WrongProtocolPhase
        );

        let mut wrong_origin_ingress = BoundedRestartProtocolIngressV1::new(
            RESTART_PROTOCOL_TEST_RUN_ID,
            set.validators()[0].id(),
            set.clone(),
        )
        .unwrap();
        assert_eq!(
            AdmittedRestartCutParkV1::new(
                admit_restart_message(
                    &mut wrong_origin_ingress,
                    dual[1].origin(),
                    &keys[1],
                    RestartProtocolPhaseV1::Cut,
                    dual[0].encode(),
                ),
                &start,
                &set,
            )
            .unwrap_err(),
            RestartCutErrorV1::AuthenticatedOriginMismatch
        );
    }

    #[test]
    fn local_origin_reservations_join_the_same_phase_bound_dual_barrier() {
        let (set, keys) = validator_fixture();
        let campaign = campaign(&set);
        let start = fleet_start_certificate(&set, &keys, &campaign, 0xd0);
        let body = restart_body(&set, &campaign, &start);
        let dual = dual_statements(&set, &keys, &start, &body);
        let target = body.target_validator();
        let target_prepare = dual
            .iter()
            .find(|statement| statement.origin() == target)
            .unwrap()
            .cut()
            .clone();
        let mut ingress =
            BoundedRestartProtocolIngressV1::new(RESTART_PROTOCOL_TEST_RUN_ID, target, set.clone())
                .unwrap();
        let prepare_reservation = ingress
            .reserve_originated_statement_v1(
                RestartProtocolPhaseV1::Prepare,
                &target_prepare.encode(),
                None,
            )
            .unwrap();
        let originated_prepare =
            OriginatedRestartPrepareV1::new(prepare_reservation, target_prepare, &start, &set)
                .unwrap();

        let mut remote = Vec::new();
        let mut originated_cut = None;
        for statement in dual.clone() {
            if statement.origin() == target {
                let reservation = ingress
                    .reserve_originated_statement_v1(
                        RestartProtocolPhaseV1::Cut,
                        &statement.encode(),
                        None,
                    )
                    .unwrap();
                originated_cut = Some(
                    OriginatedRestartCutParkV1::new_test_only(reservation, statement, &start, &set)
                        .unwrap(),
                );
            } else {
                let index = set
                    .validators()
                    .iter()
                    .position(|validator| validator.id() == statement.origin())
                    .unwrap();
                remote.push(
                    AdmittedRestartCutParkV1::new(
                        admit_restart_message(
                            &mut ingress,
                            statement.origin(),
                            &keys[index],
                            RestartProtocolPhaseV1::Cut,
                            statement.encode(),
                        ),
                        &start,
                        &set,
                    )
                    .unwrap(),
                );
            }
        }
        let verified = VerifiedRestartCutParkCertificatesV1::new_with_originated_prepare_v1(
            originated_prepare,
            remote,
            originated_cut.unwrap(),
            &start,
            &set,
        )
        .unwrap();
        verified.revalidate_v1(&start, &set).unwrap();
        assert_eq!(verified.body_v1(), &body);
        assert_ne!(verified.admission_set_sha256_v1(), [0; 32]);

        let stored_root = TempDir::new().unwrap();
        fs::set_permissions(stored_root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let stored = verified
            .persist_target_at_test_root_v1(
                stored_root.path(),
                target,
                body.target_config_sha256(),
                &start,
                &set,
            )
            .unwrap();
        stored.revalidate_fresh_v1().unwrap();
        assert_eq!(stored.body_v1(), &body);
        assert_ne!(stored.cut_artifact_sha256_v1(), [0; 32]);
        assert_ne!(stored.park_artifact_sha256_v1(), [0; 32]);
        assert_ne!(stored.admission_set_sha256_v1(), [0; 32]);
        assert_eq!(stored.statement_count_v1(), 7);
        assert_eq!(stored.local_role_v1(), RestartParkRoleV1::Target);

        let mut mismatch_ingress =
            BoundedRestartProtocolIngressV1::new(RESTART_PROTOCOL_TEST_RUN_ID, target, set.clone())
                .unwrap();
        let target_statement = dual
            .iter()
            .find(|statement| statement.origin() == target)
            .unwrap();
        let foreign_statement = dual
            .iter()
            .find(|statement| statement.origin() != target)
            .unwrap();
        let reservation = mismatch_ingress
            .reserve_originated_statement_v1(
                RestartProtocolPhaseV1::Cut,
                &target_statement.encode(),
                None,
            )
            .unwrap();
        assert!(OriginatedRestartCutParkV1::new_test_only(
            reservation,
            foreign_statement.clone(),
            &start,
            &set,
        )
        .is_err());
    }

    #[test]
    fn pre_activation_v1_rejects_the_pre_chain_root_candidate_layout() {
        let (set, keys) = validator_fixture();
        let campaign = campaign(&set);
        let start = fleet_start_certificate(&set, &keys, &campaign, 0xd0);
        let body = restart_body(&set, &campaign, &start);
        let mut obsolete_candidate = body.encode();
        let marker = [0x8f; 32];
        let root_offset = obsolete_candidate
            .windows(marker.len())
            .position(|window| window == marker)
            .expect("canonical v1 body carries the finalized chain root");
        obsolete_candidate.drain(root_offset..root_offset + marker.len());

        assert!(RestartCutBodyV1::decode(&obsolete_candidate, &set).is_err());
    }

    #[test]
    fn verified_cut_publishes_once_and_fresh_reopens_from_private_storage() {
        let (set, keys) = validator_fixture();
        let campaign = campaign(&set);
        let start = fleet_start_certificate(&set, &keys, &campaign, 0xd0);
        let body = restart_body(&set, &campaign, &start);
        let certificate =
            RestartCutCertificateV1::new(statements(&set, &keys, &body), &start, &set).unwrap();
        let target = body.target_validator();
        let target_config = body.target_config_sha256();
        let target_prepare = certificate.statement(target).unwrap().clone();
        let non_target_prepare = certificate
            .statements()
            .iter()
            .find(|statement| statement.origin() != target)
            .unwrap()
            .clone();
        let expected_sha256: [u8; 32] = Sha256::digest(certificate.encode()).into();
        let wrong_start = fleet_start_certificate(&set, &keys, &campaign, 0xe0);
        let poison_root = private_restart_cut_root();
        assert!(persist_restart_cut_at_test_root_v1(
            poison_root.path(),
            target,
            target_config,
            &set,
            &wrong_start,
            certificate.clone().verify_owned(&start, &set).unwrap(),
        )
        .is_err());
        assert!(!poison_root
            .path()
            .join("restart-cut-certificate.bin")
            .exists());
        assert!(!poison_root
            .path()
            .join("restart-cut-certificate.next")
            .exists());
        let temporary = TempDir::new().unwrap();
        fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o700)).unwrap();

        let stored = persist_restart_cut_at_test_root_v1(
            temporary.path(),
            target,
            target_config,
            &set,
            &start,
            certificate.clone().verify_owned(&start, &set).unwrap(),
        )
        .unwrap();
        assert_eq!(stored.body_v1(), &body);
        assert!(stored.contains_exact_target_prepare_v1(&target_prepare));
        assert!(!stored.contains_exact_target_prepare_v1(&non_target_prepare));
        assert_eq!(stored.artifact_sha256_v1(), expected_sha256);
        assert_eq!(
            stored.path_v1(),
            temporary.path().join("restart-cut-certificate.bin")
        );
        let metadata = fs::symlink_metadata(stored.path_v1()).unwrap();
        assert!(metadata.is_file());
        assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
        drop(stored.into_verified_v1());

        let retry = persist_restart_cut_at_test_root_v1(
            temporary.path(),
            target,
            target_config,
            &set,
            &start,
            certificate.clone().verify_owned(&start, &set).unwrap(),
        )
        .unwrap();
        assert_eq!(retry.artifact_sha256_v1(), expected_sha256);
        drop(retry);

        assert!(persist_restart_cut_at_test_root_v1(
            temporary.path(),
            target,
            [0xee; 32],
            &set,
            &start,
            certificate.clone().verify_owned(&start, &set).unwrap(),
        )
        .is_err());
        let reopened =
            load_restart_cut_at_test_root_v1(temporary.path(), target, target_config, &set, &start)
                .unwrap();
        assert_eq!(reopened.body_v1(), &body);
        assert!(reopened.contains_exact_target_prepare_v1(&target_prepare));
        drop(reopened);

        let next = temporary.path().join("restart-cut-certificate.next");
        std::os::unix::fs::symlink("restart-cut-certificate.bin", &next).unwrap();
        assert!(load_restart_cut_at_test_root_v1(
            temporary.path(),
            target,
            target_config,
            &set,
            &start,
        )
        .is_err());
    }

    #[test]
    fn restart_cut_store_reconciles_exact_writing_next_and_linked_crash_windows() {
        let (set, keys) = validator_fixture();
        let campaign = campaign(&set);
        let start = fleet_start_certificate(&set, &keys, &campaign, 0xd0);
        let body = restart_body(&set, &campaign, &start);
        let certificate =
            RestartCutCertificateV1::new(statements(&set, &keys, &body), &start, &set).unwrap();
        let bytes = certificate.encode();
        let target = body.target_validator();
        let target_config = body.target_config_sha256();

        let next_only = private_restart_cut_root();
        write_restart_cut_test_artifact(next_only.path(), "restart-cut-certificate.next", &bytes);
        drop(
            persist_restart_cut_at_test_root_v1(
                next_only.path(),
                target,
                target_config,
                &set,
                &start,
                certificate.clone().verify_owned(&start, &set).unwrap(),
            )
            .unwrap(),
        );
        assert!(!next_only
            .path()
            .join("restart-cut-certificate.next")
            .exists());
        assert_eq!(
            fs::read(next_only.path().join("restart-cut-certificate.bin")).unwrap(),
            bytes
        );

        let linked_final = private_restart_cut_root();
        let stored = persist_restart_cut_at_test_root_v1(
            linked_final.path(),
            target,
            target_config,
            &set,
            &start,
            certificate.clone().verify_owned(&start, &set).unwrap(),
        )
        .unwrap();
        let final_path = stored.path_v1().to_path_buf();
        drop(stored);
        let next_path = linked_final.path().join("restart-cut-certificate.next");
        fs::hard_link(&final_path, &next_path).unwrap();
        File::open(linked_final.path()).unwrap().sync_all().unwrap();
        drop(
            persist_restart_cut_at_test_root_v1(
                linked_final.path(),
                target,
                target_config,
                &set,
                &start,
                certificate.clone().verify_owned(&start, &set).unwrap(),
            )
            .unwrap(),
        );
        assert!(!next_path.exists());
        assert_eq!(fs::metadata(final_path).unwrap().nlink(), 1);

        for (attempt, prefix_length, incomplete_mode) in [
            (1u64, 0usize, Some(0o000)),
            (2, 1, None),
            (3, bytes.len() - 1, None),
            (4, bytes.len(), None),
        ] {
            let root = private_restart_cut_root();
            let writing_name = restart_cut_writing_name(0x71a1, attempt);
            let writing = root.path().join(&writing_name);
            write_restart_cut_test_artifact(root.path(), &writing_name, &bytes[..prefix_length]);
            if let Some(mode) = incomplete_mode {
                fs::set_permissions(&writing, fs::Permissions::from_mode(mode)).unwrap();
            }
            drop(
                persist_restart_cut_at_test_root_v1(
                    root.path(),
                    target,
                    target_config,
                    &set,
                    &start,
                    certificate.clone().verify_owned(&start, &set).unwrap(),
                )
                .unwrap(),
            );
            assert!(!writing.exists());
            assert_eq!(
                fs::read(root.path().join("restart-cut-certificate.bin")).unwrap(),
                bytes
            );
        }

        let linked_writing = private_restart_cut_root();
        let writing_name = restart_cut_writing_name(0x71a2, 9);
        let writing = linked_writing.path().join(&writing_name);
        let next = linked_writing.path().join("restart-cut-certificate.next");
        write_restart_cut_test_artifact(linked_writing.path(), &writing_name, &bytes);
        fs::hard_link(&writing, &next).unwrap();
        File::open(linked_writing.path())
            .unwrap()
            .sync_all()
            .unwrap();
        drop(
            persist_restart_cut_at_test_root_v1(
                linked_writing.path(),
                target,
                target_config,
                &set,
                &start,
                certificate.verify_owned(&start, &set).unwrap(),
            )
            .unwrap(),
        );
        assert!(!writing.exists());
        assert!(!next.exists());
    }

    #[test]
    fn restart_cut_store_preserves_partial_foreign_and_ambiguous_publication_states() {
        let (set, keys) = validator_fixture();
        let campaign = campaign(&set);
        let start = fleet_start_certificate(&set, &keys, &campaign, 0xd0);
        let body = restart_body(&set, &campaign, &start);
        let certificate =
            RestartCutCertificateV1::new(statements(&set, &keys, &body), &start, &set).unwrap();
        let bytes = certificate.encode();
        let target = body.target_validator();
        let target_config = body.target_config_sha256();

        let partial_next = private_restart_cut_root();
        let partial = bytes[..bytes.len() - 1].to_vec();
        write_restart_cut_test_artifact(
            partial_next.path(),
            "restart-cut-certificate.next",
            &partial,
        );
        assert!(persist_restart_cut_at_test_root_v1(
            partial_next.path(),
            target,
            target_config,
            &set,
            &start,
            certificate.clone().verify_owned(&start, &set).unwrap(),
        )
        .is_err());
        assert_eq!(
            fs::read(partial_next.path().join("restart-cut-certificate.next")).unwrap(),
            partial
        );

        let mutant_writing = private_restart_cut_root();
        let writing_name = restart_cut_writing_name(0x71a3, 10);
        let mut mutant = bytes[..bytes.len() - 1].to_vec();
        mutant[0] ^= 1;
        write_restart_cut_test_artifact(mutant_writing.path(), &writing_name, &mutant);
        assert!(persist_restart_cut_at_test_root_v1(
            mutant_writing.path(),
            target,
            target_config,
            &set,
            &start,
            certificate.clone().verify_owned(&start, &set).unwrap(),
        )
        .is_err());
        assert_eq!(
            fs::read(mutant_writing.path().join(&writing_name)).unwrap(),
            mutant
        );

        let separate_writing = private_restart_cut_root();
        let writing_name = restart_cut_writing_name(0x71a4, 11);
        write_restart_cut_test_artifact(separate_writing.path(), &writing_name, &bytes);
        write_restart_cut_test_artifact(
            separate_writing.path(),
            "restart-cut-certificate.next",
            &bytes,
        );
        assert!(persist_restart_cut_at_test_root_v1(
            separate_writing.path(),
            target,
            target_config,
            &set,
            &start,
            certificate.clone().verify_owned(&start, &set).unwrap(),
        )
        .is_err());
        assert!(separate_writing.path().join(&writing_name).exists());
        assert!(separate_writing
            .path()
            .join("restart-cut-certificate.next")
            .exists());

        let separate_final = private_restart_cut_root();
        write_restart_cut_test_artifact(
            separate_final.path(),
            "restart-cut-certificate.bin",
            &bytes,
        );
        write_restart_cut_test_artifact(
            separate_final.path(),
            "restart-cut-certificate.next",
            &bytes,
        );
        assert!(persist_restart_cut_at_test_root_v1(
            separate_final.path(),
            target,
            target_config,
            &set,
            &start,
            certificate.clone().verify_owned(&start, &set).unwrap(),
        )
        .is_err());
        assert!(separate_final
            .path()
            .join("restart-cut-certificate.bin")
            .exists());
        assert!(separate_final
            .path()
            .join("restart-cut-certificate.next")
            .exists());

        let malformed = private_restart_cut_root();
        let malformed_name = "restart-cut-certificate.writing.bad";
        write_restart_cut_test_artifact(malformed.path(), malformed_name, &bytes);
        assert!(persist_restart_cut_at_test_root_v1(
            malformed.path(),
            target,
            target_config,
            &set,
            &start,
            certificate.clone().verify_owned(&start, &set).unwrap(),
        )
        .is_err());
        assert!(malformed.path().join(malformed_name).exists());

        let multiple = private_restart_cut_root();
        let first = restart_cut_writing_name(0x71a5, 12);
        let second = restart_cut_writing_name(0x71a6, 13);
        write_restart_cut_test_artifact(multiple.path(), &first, &bytes[..1]);
        write_restart_cut_test_artifact(multiple.path(), &second, &bytes[..2]);
        assert!(persist_restart_cut_at_test_root_v1(
            multiple.path(),
            target,
            target_config,
            &set,
            &start,
            certificate.clone().verify_owned(&start, &set).unwrap(),
        )
        .is_err());
        assert!(multiple.path().join(first).exists());
        assert!(multiple.path().join(second).exists());

        let target_and_writing = private_restart_cut_root();
        let writing = restart_cut_writing_name(0x71a7, 14);
        write_restart_cut_test_artifact(
            target_and_writing.path(),
            "restart-cut-certificate.bin",
            &bytes,
        );
        write_restart_cut_test_artifact(target_and_writing.path(), &writing, &bytes[..1]);
        assert!(persist_restart_cut_at_test_root_v1(
            target_and_writing.path(),
            target,
            target_config,
            &set,
            &start,
            certificate.clone().verify_owned(&start, &set).unwrap(),
        )
        .is_err());
        assert!(target_and_writing
            .path()
            .join("restart-cut-certificate.bin")
            .exists());
        assert!(target_and_writing.path().join(writing).exists());

        let valid_and_malformed = private_restart_cut_root();
        let valid = restart_cut_writing_name(0x71a8, 15);
        let malformed = "restart-cut-certificate.writing.malformed";
        write_restart_cut_test_artifact(valid_and_malformed.path(), &valid, &bytes[..1]);
        write_restart_cut_test_artifact(valid_and_malformed.path(), malformed, &bytes[..1]);
        assert!(persist_restart_cut_at_test_root_v1(
            valid_and_malformed.path(),
            target,
            target_config,
            &set,
            &start,
            certificate.clone().verify_owned(&start, &set).unwrap(),
        )
        .is_err());
        assert!(valid_and_malformed.path().join(valid).exists());
        assert!(valid_and_malformed.path().join(malformed).exists());

        let writing_and_forbidden = private_restart_cut_root();
        let writing = restart_cut_writing_name(0x71a9, 16);
        write_restart_cut_test_artifact(writing_and_forbidden.path(), &writing, &bytes[..1]);
        write_restart_cut_test_artifact(
            writing_and_forbidden.path(),
            "restart-cut-certificate.tmp",
            b"foreign",
        );
        assert!(persist_restart_cut_at_test_root_v1(
            writing_and_forbidden.path(),
            target,
            target_config,
            &set,
            &start,
            certificate.verify_owned(&start, &set).unwrap(),
        )
        .is_err());
        assert!(writing_and_forbidden.path().join(writing).exists());
        assert!(writing_and_forbidden
            .path()
            .join("restart-cut-certificate.tmp")
            .exists());
    }

    #[test]
    fn restart_cut_store_rejects_partial_publish_conflict_tamper_and_alias() {
        let (set, keys) = validator_fixture();
        let campaign = campaign(&set);
        let start = fleet_start_certificate(&set, &keys, &campaign, 0xd0);
        let body = restart_body(&set, &campaign, &start);
        let certificate =
            RestartCutCertificateV1::new(statements(&set, &keys, &body), &start, &set).unwrap();
        let target = body.target_validator();
        let target_config = body.target_config_sha256();

        let partial = TempDir::new().unwrap();
        fs::set_permissions(partial.path(), fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(
            partial.path().join("restart-cut-certificate.next"),
            b"partial-publication",
        )
        .unwrap();
        assert!(persist_restart_cut_at_test_root_v1(
            partial.path(),
            target,
            target_config,
            &set,
            &start,
            certificate.clone().verify_owned(&start, &set).unwrap(),
        )
        .is_err());
        assert!(!partial.path().join("restart-cut-certificate.bin").exists());

        let published = TempDir::new().unwrap();
        fs::set_permissions(published.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let stored = persist_restart_cut_at_test_root_v1(
            published.path(),
            target,
            target_config,
            &set,
            &start,
            certificate.clone().verify_owned(&start, &set).unwrap(),
        )
        .unwrap();
        let path = stored.path_v1().to_owned();
        drop(stored);

        let mut conflicting_state = restart_state(&set);
        conflicting_state.runtime_journal_head_sha256 = [0xe8; 32];
        let conflicting_body = RestartCutBodyV1::new(
            campaign,
            target,
            target_config,
            1,
            conflicting_state,
            &start,
            &set,
        )
        .unwrap();
        let conflicting =
            RestartCutCertificateV1::new(statements(&set, &keys, &conflicting_body), &start, &set)
                .unwrap();
        assert!(persist_restart_cut_at_test_root_v1(
            published.path(),
            target,
            target_config,
            &set,
            &start,
            conflicting.verify_owned(&start, &set).unwrap(),
        )
        .is_err());

        let alias = published.path().join("restart-cut-certificate.alias");
        fs::hard_link(&path, &alias).unwrap();
        assert!(load_restart_cut_at_test_root_v1(
            published.path(),
            target,
            target_config,
            &set,
            &start,
        )
        .is_err());
        fs::remove_file(alias).unwrap();

        let original = fs::read(&path).unwrap();
        let mut tampered = original.clone();
        *tampered.last_mut().unwrap() ^= 1;
        fs::write(&path, tampered).unwrap();
        assert!(load_restart_cut_at_test_root_v1(
            published.path(),
            target,
            target_config,
            &set,
            &start,
        )
        .is_err());
        fs::write(path, original).unwrap();
    }

    #[test]
    fn restart_cut_store_pins_same_bytes_root_and_private_filesystem_identity() {
        let (set, keys) = validator_fixture();
        let campaign = campaign(&set);
        let start = fleet_start_certificate(&set, &keys, &campaign, 0xd0);
        let body = restart_body(&set, &campaign, &start);
        let certificate =
            RestartCutCertificateV1::new(statements(&set, &keys, &body), &start, &set).unwrap();
        let bytes = certificate.encode();
        let target = body.target_validator();
        let target_config = body.target_config_sha256();

        let replacement_root = private_restart_cut_root();
        let stored = persist_restart_cut_at_test_root_v1(
            replacement_root.path(),
            target,
            target_config,
            &set,
            &start,
            certificate.clone().verify_owned(&start, &set).unwrap(),
        )
        .unwrap();
        let path = stored.path_v1().to_path_buf();
        fs::rename(&path, replacement_root.path().join("displaced-cut.bin")).unwrap();
        write_restart_cut_test_artifact(
            replacement_root.path(),
            "restart-cut-certificate.bin",
            &bytes,
        );
        assert!(stored.revalidate_fresh_readback_v1().is_err());

        let root_parent = TempDir::new().unwrap();
        let live_root = root_parent.path().join("live");
        let displaced_root = root_parent.path().join("displaced");
        fs::create_dir(&live_root).unwrap();
        fs::set_permissions(&live_root, fs::Permissions::from_mode(0o700)).unwrap();
        let stored = persist_restart_cut_at_test_root_v1(
            &live_root,
            target,
            target_config,
            &set,
            &start,
            certificate.clone().verify_owned(&start, &set).unwrap(),
        )
        .unwrap();
        fs::rename(&live_root, &displaced_root).unwrap();
        fs::create_dir(&live_root).unwrap();
        fs::set_permissions(&live_root, fs::Permissions::from_mode(0o700)).unwrap();
        write_restart_cut_test_artifact(&live_root, "restart-cut-certificate.bin", &bytes);
        assert!(stored.revalidate_fresh_readback_v1().is_err());

        let hardlink_root = private_restart_cut_root();
        let stored = persist_restart_cut_at_test_root_v1(
            hardlink_root.path(),
            target,
            target_config,
            &set,
            &start,
            certificate.clone().verify_owned(&start, &set).unwrap(),
        )
        .unwrap();
        fs::hard_link(
            stored.path_v1(),
            hardlink_root.path().join("foreign-hardlink.bin"),
        )
        .unwrap();
        assert!(stored.revalidate_fresh_readback_v1().is_err());

        let artifact_mode_root = private_restart_cut_root();
        let stored = persist_restart_cut_at_test_root_v1(
            artifact_mode_root.path(),
            target,
            target_config,
            &set,
            &start,
            certificate.clone().verify_owned(&start, &set).unwrap(),
        )
        .unwrap();
        fs::set_permissions(stored.path_v1(), fs::Permissions::from_mode(0o640)).unwrap();
        assert!(stored.revalidate_fresh_readback_v1().is_err());

        let root_mode = private_restart_cut_root();
        fs::set_permissions(root_mode.path(), fs::Permissions::from_mode(0o750)).unwrap();
        assert!(persist_restart_cut_at_test_root_v1(
            root_mode.path(),
            target,
            target_config,
            &set,
            &start,
            certificate.clone().verify_owned(&start, &set).unwrap(),
        )
        .is_err());

        let symlink_artifact = private_restart_cut_root();
        std::os::unix::fs::symlink(
            "/dev/null",
            symlink_artifact.path().join("restart-cut-certificate.bin"),
        )
        .unwrap();
        assert!(load_restart_cut_at_test_root_v1(
            symlink_artifact.path(),
            target,
            target_config,
            &set,
            &start,
        )
        .is_err());

        let nonregular_next = private_restart_cut_root();
        fs::create_dir(nonregular_next.path().join("restart-cut-certificate.next")).unwrap();
        assert!(persist_restart_cut_at_test_root_v1(
            nonregular_next.path(),
            target,
            target_config,
            &set,
            &start,
            certificate.clone().verify_owned(&start, &set).unwrap(),
        )
        .is_err());
        assert!(nonregular_next
            .path()
            .join("restart-cut-certificate.next")
            .is_dir());

        let symlink_parent = TempDir::new().unwrap();
        let real_parent = symlink_parent.path().join("real-parent");
        let real_root = real_parent.join("private-root");
        let alias_parent = symlink_parent.path().join("alias-parent");
        let alias_root = alias_parent.join("private-root");
        fs::create_dir(&real_parent).unwrap();
        fs::create_dir(&real_root).unwrap();
        fs::set_permissions(&real_root, fs::Permissions::from_mode(0o700)).unwrap();
        std::os::unix::fs::symlink(&real_parent, &alias_parent).unwrap();
        assert!(persist_restart_cut_at_test_root_v1(
            &alias_root,
            target,
            target_config,
            &set,
            &start,
            certificate.verify_owned(&start, &set).unwrap(),
        )
        .is_err());
    }

    #[test]
    fn exact_parent_view_application_safety_and_signer_relations_fail_closed() {
        let (set, keys) = validator_fixture();
        let campaign = campaign(&set);
        let start = fleet_start_certificate(&set, &keys, &campaign, 0xd0);
        let construct = |state| {
            RestartCutBodyV1::new(
                campaign.clone(),
                set.validators()[2].id(),
                restart_target_config_sha256(&set, &start),
                1,
                state,
                &start,
                &set,
            )
        };
        let relation_error = Err(RestartCutErrorV1::Malformed("restart state relation"));

        let mut wrong_view = restart_state(&set);
        wrong_view.current_view = View::new(11);
        assert_eq!(construct(wrong_view), relation_error);

        let mut wrong_parent_height = restart_state(&set);
        wrong_parent_height.proposal_parent_height = Height::new(7);
        assert_eq!(construct(wrong_parent_height), relation_error);

        let mut wrong_parent_block = restart_state(&set);
        wrong_parent_block.proposal_parent_block_id = BlockId::new([0xe1; 32]);
        assert_eq!(construct(wrong_parent_block), relation_error);

        let mut wrong_application_height = restart_state(&set);
        wrong_application_height.application_height = Height::new(7);
        assert_eq!(construct(wrong_application_height), relation_error);

        let mut wrong_application_block = restart_state(&set);
        wrong_application_block.application_block_id = BlockId::new([0xe2; 32]);
        assert_eq!(construct(wrong_application_block), relation_error);

        let mut high_qc_below_finalized = restart_state(&set);
        high_qc_below_finalized.direct_high_qc = QcRef::new(
            CertificateId::new([0x81; 32]),
            Epoch::new(0),
            View::new(9),
            Height::new(5),
            BlockId::new([0x82; 32]),
            set.id(),
        );
        high_qc_below_finalized.proposal_parent_height = Height::new(5);
        assert_eq!(construct(high_qc_below_finalized), relation_error);

        let mut zero_safety_revision = restart_state(&set);
        zero_safety_revision.safety_revision = 0;
        assert_eq!(construct(zero_safety_revision), relation_error);

        let mut swapped_durable_distribution = restart_state(&set);
        swapped_durable_distribution.signer_durable_vote_intent_count = 1;
        swapped_durable_distribution.signer_durable_timeout_intent_count = 2;
        assert_eq!(construct(swapped_durable_distribution), relation_error);

        let mut swapped_signed_distribution = restart_state(&set);
        swapped_signed_distribution.signer_signed_vote_intent_count = 1;
        swapped_signed_distribution.signer_signed_timeout_intent_count = 2;
        assert_eq!(construct(swapped_signed_distribution), relation_error);

        let mut wrong_watermark = restart_state(&set);
        wrong_watermark.signer_watermark =
            SignerWatermarkV0::from_persisted_parts([0x89; 32], [0x8a; 32], 5, [0x8b; 32]).unwrap();
        assert_eq!(construct(wrong_watermark), relation_error);

        let mut zero_safety_digest = restart_state(&set);
        zero_safety_digest.safety_state_record_checksum = [0; 32];
        assert_eq!(
            construct(zero_safety_digest),
            Err(RestartCutErrorV1::Malformed("restart state digest"))
        );

        let mut zero_finalized_chain_root = restart_state(&set);
        zero_finalized_chain_root.finalized_chain_root = [0; 32];
        assert_eq!(
            construct(zero_finalized_chain_root),
            Err(RestartCutErrorV1::Malformed("restart state digest"))
        );

        let mut zero_inventory_digest = restart_state(&set);
        zero_inventory_digest.signer_inventory_digest = [0; 32];
        assert_eq!(
            construct(zero_inventory_digest),
            Err(RestartCutErrorV1::Malformed("restart state digest"))
        );
    }

    #[test]
    fn checked_view_and_signer_inventory_arithmetic_rejects_overflow() {
        let (set, keys) = validator_fixture();
        let campaign = campaign(&set);
        let start = fleet_start_certificate(&set, &keys, &campaign, 0xd0);
        let construct = |state| {
            RestartCutBodyV1::new(
                campaign.clone(),
                set.validators()[2].id(),
                restart_target_config_sha256(&set, &start),
                1,
                state,
                &start,
                &set,
            )
        };
        let relation_error = Err(RestartCutErrorV1::Malformed("restart state relation"));

        let mut view_overflow = restart_state(&set);
        view_overflow.direct_high_qc = QcRef::new(
            CertificateId::new([0x81; 32]),
            Epoch::new(0),
            View::new(u64::MAX),
            Height::new(8),
            BlockId::new([0x82; 32]),
            set.id(),
        );
        view_overflow.current_view = View::new(u64::MAX);
        assert_eq!(construct(view_overflow), relation_error);

        let mut durable_sum_overflow = restart_state(&set);
        durable_sum_overflow.signer_durable_vote_intent_count = u64::MAX;
        durable_sum_overflow.signer_durable_timeout_intent_count = 1;
        durable_sum_overflow.signer_signed_vote_intent_count = u64::MAX;
        durable_sum_overflow.signer_signed_timeout_intent_count = 1;
        assert_eq!(construct(durable_sum_overflow), relation_error);

        let mut signed_sum_overflow = restart_state(&set);
        signed_sum_overflow.signer_durable_vote_intent_count = u64::MAX;
        signed_sum_overflow.signer_durable_timeout_intent_count = 0;
        signed_sum_overflow.signer_signed_vote_intent_count = u64::MAX;
        signed_sum_overflow.signer_signed_timeout_intent_count = 1;
        assert_eq!(construct(signed_sum_overflow), relation_error);

        let mut event_sum_overflow = restart_state(&set);
        let half_plus_one = u64::MAX / 2 + 1;
        event_sum_overflow.signer_durable_vote_intent_count = half_plus_one;
        event_sum_overflow.signer_durable_timeout_intent_count = 0;
        event_sum_overflow.signer_signed_vote_intent_count = half_plus_one;
        event_sum_overflow.signer_signed_timeout_intent_count = 0;
        assert_eq!(construct(event_sum_overflow), relation_error);
    }

    #[test]
    fn core_chain_safety_and_signer_digest_substitution_changes_the_exact_common_cut() {
        let (set, keys) = validator_fixture();
        let campaign = campaign(&set);
        let start = fleet_start_certificate(&set, &keys, &campaign, 0xd0);
        let body = restart_body(&set, &campaign, &start);
        let canonical = statements(&set, &keys, &body);

        let mut chain_substituted_state = restart_state(&set);
        chain_substituted_state.finalized_chain_root = [0xe2; 32];
        let chain_substituted_body = RestartCutBodyV1::new(
            campaign.clone(),
            set.validators()[2].id(),
            restart_target_config_sha256(&set, &start),
            1,
            chain_substituted_state,
            &start,
            &set,
        )
        .unwrap();
        assert_ne!(chain_substituted_body.digest(), body.digest());

        let mut substituted_state = chain_substituted_state;
        substituted_state.safety_record_chain_checksum = [0xe3; 32];
        substituted_state.signer_inventory_digest = [0xe4; 32];
        let substituted_body = RestartCutBodyV1::new(
            campaign,
            set.validators()[2].id(),
            restart_target_config_sha256(&set, &start),
            1,
            substituted_state,
            &start,
            &set,
        )
        .unwrap();
        assert_ne!(substituted_body.digest(), body.digest());

        let mut divergent = canonical;
        divergent[3] =
            SignedRestartCutV1::new(set.validators()[3].id(), substituted_body, &set, &keys[3])
                .unwrap();
        assert_eq!(
            RestartCutCertificateV1::new(divergent, &start, &set),
            Err(RestartCutErrorV1::DifferentCut)
        );
    }

    #[test]
    fn signature_origin_completeness_and_common_cut_fail_closed() {
        let (set, keys) = validator_fixture();
        let campaign = campaign(&set);
        let start = fleet_start_certificate(&set, &keys, &campaign, 0xd0);
        let body = restart_body(&set, &campaign, &start);
        let canonical = statements(&set, &keys, &body);

        let prepare = canonical[2]
            .clone()
            .verify_target_prepare_owned(&start, &set)
            .unwrap();
        assert_eq!(prepare.body(), &body);
        let local_declaration = prepare
            .into_local_declaration(set.validators()[4].id(), &set, &keys[4])
            .unwrap();
        assert_eq!(local_declaration.origin(), set.validators()[4].id());
        assert_eq!(local_declaration.body(), &body);
        assert_eq!(
            canonical[0]
                .clone()
                .verify_target_prepare_owned(&start, &set)
                .unwrap_err(),
            RestartCutErrorV1::PrepareOriginIsNotTarget
        );

        let mut mutated = canonical[0].encode();
        *mutated.last_mut().unwrap() ^= 1;
        assert_eq!(
            SignedRestartCutV1::decode(&mutated, &set),
            Err(RestartCutErrorV1::InvalidSignature)
        );
        assert_eq!(
            SignedRestartCutV1::new(set.validators()[0].id(), body.clone(), &set, &keys[1],),
            Err(RestartCutErrorV1::OriginKeyMismatch)
        );
        assert_eq!(
            RestartCutCertificateV1::new(canonical[..6].to_vec(), &start, &set),
            Err(RestartCutErrorV1::Incomplete)
        );
        let mut duplicate = canonical.clone();
        duplicate[6] = duplicate[0].clone();
        assert_eq!(
            RestartCutCertificateV1::new(duplicate, &start, &set),
            Err(RestartCutErrorV1::DuplicateOrigin)
        );

        let mut different_state = restart_state(&set);
        different_state.runtime_journal_head_sha256 = [0xf1; 32];
        let different_body = RestartCutBodyV1::new(
            campaign,
            set.validators()[2].id(),
            restart_target_config_sha256(&set, &start),
            1,
            different_state,
            &start,
            &set,
        )
        .unwrap();
        let mut divergent = canonical;
        divergent[3] =
            SignedRestartCutV1::new(set.validators()[3].id(), different_body, &set, &keys[3])
                .unwrap();
        assert_eq!(
            RestartCutCertificateV1::new(divergent, &start, &set),
            Err(RestartCutErrorV1::DifferentCut)
        );
    }

    #[test]
    fn pending_sign_wrong_process_wrong_high_qc_and_wrong_start_artifact_fail_closed() {
        let (set, keys) = validator_fixture();
        let campaign = campaign(&set);
        let start = fleet_start_certificate(&set, &keys, &campaign, 0xd0);
        assert_eq!(
            RestartCutBodyV1::new(
                campaign.clone(),
                set.validators()[2].id(),
                [0xee; 32],
                1,
                restart_state(&set),
                &start,
                &set,
            ),
            Err(RestartCutErrorV1::InvalidFleetStartCertificate)
        );
        let mut pending = restart_state(&set);
        pending.pending_sign = Some([0x91; 32]);
        assert_eq!(
            RestartCutBodyV1::new(
                campaign.clone(),
                set.validators()[2].id(),
                restart_target_config_sha256(&set, &start),
                1,
                pending,
                &start,
                &set,
            ),
            Err(RestartCutErrorV1::Malformed("restart state relation"))
        );
        assert_eq!(
            RestartCutBodyV1::new(
                campaign.clone(),
                set.validators()[2].id(),
                restart_target_config_sha256(&set, &start),
                2,
                restart_state(&set),
                &start,
                &set,
            ),
            Err(RestartCutErrorV1::Malformed("process instance"))
        );
        let mut wrong_qc = restart_state(&set);
        wrong_qc.direct_high_qc = QcRef::new(
            CertificateId::new([0x81; 32]),
            Epoch::new(0),
            View::new(9),
            Height::new(8),
            BlockId::new([0x82; 32]),
            ValidatorSetId::new([0xee; 32]),
        );
        assert_eq!(
            RestartCutBodyV1::new(
                campaign.clone(),
                set.validators()[2].id(),
                restart_target_config_sha256(&set, &start),
                1,
                wrong_qc,
                &start,
                &set,
            ),
            Err(RestartCutErrorV1::Malformed("restart state relation"))
        );

        let body = restart_body(&set, &campaign, &start);
        let certificate =
            RestartCutCertificateV1::new(statements(&set, &keys, &body), &start, &set).unwrap();
        let different_start = fleet_start_certificate(&set, &keys, &campaign, 0xe0);
        let target_declaration = certificate
            .statement(set.validators()[2].id())
            .expect("target declaration exists");
        target_declaration
            .verify_with_fleet_start_certificate(&start, &set)
            .unwrap();
        assert_eq!(
            target_declaration
                .verify_with_fleet_start_certificate(&different_start, &set)
                .unwrap_err(),
            RestartCutErrorV1::InvalidFleetStartCertificate
        );
        assert_eq!(
            certificate
                .verify_owned(&different_start, &set)
                .unwrap_err(),
            RestartCutErrorV1::InvalidFleetStartCertificate
        );
    }

    #[test]
    fn noncanonical_order_tags_truncation_and_trailing_bytes_are_rejected() {
        let (set, keys) = validator_fixture();
        let campaign = campaign(&set);
        let start = fleet_start_certificate(&set, &keys, &campaign, 0xd0);
        let body = restart_body(&set, &campaign, &start);
        let declarations = statements(&set, &keys, &body);
        let certificate = RestartCutCertificateV1::new(declarations.clone(), &start, &set).unwrap();

        let mut noncanonical = Vec::new();
        noncanonical.extend_from_slice(CUT_CERTIFICATE_MAGIC_V1);
        noncanonical.extend_from_slice(&WIRE_VERSION_V1.to_be_bytes());
        noncanonical.extend_from_slice(&(declarations.len() as u32).to_be_bytes());
        for declaration in declarations.iter().rev() {
            put_bytes_u32(&mut noncanonical, &declaration.encode());
        }
        assert_eq!(
            RestartCutCertificateV1::decode(&noncanonical, &set),
            Err(RestartCutErrorV1::NonCanonical)
        );

        let mut trailing = certificate.encode();
        trailing.push(0);
        assert_eq!(
            RestartCutCertificateV1::decode(&trailing, &set),
            Err(RestartCutErrorV1::Malformed("trailing payload"))
        );

        let encoded_body = body.encode();
        let mut body_cursor = RestartCursor::new(&encoded_body);
        body_cursor.take(8).unwrap();
        body_cursor.take(2).unwrap();
        let campaign_length = u32::from_be_bytes(body_cursor.array().unwrap()) as usize;
        body_cursor.take(campaign_length).unwrap();
        body_cursor.validator_id().unwrap();
        body_cursor.take(32 + 32 + 8 + 8 + 8).unwrap();
        let direct_high_qc_tag_offset = body_cursor.offset;
        assert_eq!(encoded_body[direct_high_qc_tag_offset], 1);
        let mut absent_high_qc = encoded_body.clone();
        absent_high_qc[direct_high_qc_tag_offset] = 0;
        assert_eq!(
            RestartCutBodyV1::decode(&absent_high_qc, &set),
            Err(RestartCutErrorV1::Malformed("direct high-QC tag"))
        );

        let inventory_marker = [0x8e; 32];
        let inventory_offset = encoded_body
            .windows(inventory_marker.len())
            .position(|window| window == inventory_marker)
            .unwrap();
        let pending_sign_tag_offset = inventory_offset + inventory_marker.len();
        assert_eq!(encoded_body[pending_sign_tag_offset], 0);
        let mut invalid_pending_tag = encoded_body.clone();
        invalid_pending_tag[pending_sign_tag_offset] = 2;
        assert_eq!(
            RestartCutBodyV1::decode(&invalid_pending_tag, &set),
            Err(RestartCutErrorV1::Malformed("pending-sign tag"))
        );

        let mut truncated_body = encoded_body.clone();
        truncated_body.pop();
        assert_eq!(
            RestartCutBodyV1::decode(&truncated_body, &set),
            Err(RestartCutErrorV1::Malformed("truncated payload"))
        );

        let mut trailing_body = encoded_body;
        trailing_body.push(0);
        assert_eq!(
            RestartCutBodyV1::decode(&trailing_body, &set),
            Err(RestartCutErrorV1::Malformed("trailing payload"))
        );
    }
}
