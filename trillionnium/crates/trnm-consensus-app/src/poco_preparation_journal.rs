//! Durable, application-private checkpoint preparation journal.
//!
//! This sidecar is deliberately separate from the application state database:
//! it is not part of `STORE_SCHEMA_SQL`, AppHash/JMT state, ABCI snapshots, or
//! state-sync replacement. Every mutation uses `BEGIN IMMEDIATE` with SQLite
//! `synchronous=FULL`. A conflicting transition binding or a second value for
//! one `(transition, kind, height, view)` slot durably records a halt before
//! returning an error.
//! The canonical file identity and persistent journal ID share a process-local
//! writer/halt state across independent opens and reject path or schema drift.
//! Cross-process signing safety remains outside this verifier-only sidecar.
//!
//! Stored replay records are comparison material only. Reopening this journal
//! never recreates checkpoint, proposal, vote, finality, handoff, activation,
//! or signing authority. A host must reconstruct all strict in-memory
//! authorities and reserve the exact same record again before it can obtain a
//! fresh opaque durable capability.

use std::{
    collections::BTreeMap,
    env,
    fs::{self, File},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc, Mutex, OnceLock,
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{anyhow, bail, ensure, Context, Result};
use rusqlite::{params, Connection, OptionalExtension, Transaction, TransactionBehavior};
use trnm_consensus_crypto::StrictEd25519Verifier;
use trnm_consensus_types::{
    decode_application_payload_v0_exact, decode_block_header_v0_exact,
    decode_consensus_parameters_v0_exact, decode_double_vote_evidence_v0_exact,
    decode_execution_receipt_commitment_v0_exact, decode_next_epoch_commitment_v0_exact,
    decode_validator_set_v0_exact, BlockBodyV0, BlockId, BlockKind, ChainId,
    ConsensusParametersHash, ConsensusParametersV0, Epoch, EpochGeometryV0, EvidenceRoot,
    ExecutionReceiptsV0, GenesisHash, Height, NextEpochCommitmentHash, PayloadDigest,
    ProtocolVersion, ReceiptsRoot, StateRoot, ValidatorId, ValidatorSet, ValidatorSetId, View,
};
use trnm_finality_types::hash_domain;

use crate::{
    native_execution::native_checkpoint_execution_authorization_id_v0,
    poco_checkpoint::PocoScheduledCutoffAuthorizationPreimageV0,
};

const JOURNAL_SCHEMA_VERSION: &str = "1";
const MAX_REPLAY_RECORD_BYTES: usize = 64 * 1024 * 1024;
const MAX_REPLAY_FIELD_BYTES: usize = 16 * 1024 * 1024;
const MAX_REPLAY_LIST_ITEMS: usize = 1_000_000;

// These domains identify application-private storage records only. They are
// not wire objects, consensus certificates, or aggregate handoff proofs.
const TRANSITION_KEY_DOMAIN_V0: &str = "trnm.poco-bft.preparation-transition-key.v0";
const BINDING_CHECKSUM_DOMAIN_V0: &str = "trnm.poco-bft.preparation-binding-record.v0";
const PREPARATION_CHECKSUM_DOMAIN_V0: &str = "trnm.poco-bft.preparation-replay-record.v0";
const BOUND_CHECKSUM_DOMAIN_V0: &str = "trnm.poco-bft.bound-preparation-record.v0";
const CONFLICT_CHECKSUM_DOMAIN_V0: &str = "trnm.poco-bft.preparation-conflict.v0";
const PREPARATION_AUTHORIZATION_DOMAIN_V0: &str = "trnm.poco-bft.prepared-checkpoint-header.v0";
const HEADER_AUTHORIZATION_DOMAIN_V0: &str = "trnm.poco-bft.authorized-checkpoint-header.v0";
const JOURNAL_ID_DOMAIN_V0: &str = "trnm.poco-bft.preparation-journal-id.v0";

static JOURNAL_ID_SEQUENCE: AtomicU64 = AtomicU64::new(0);
static PROCESS_JOURNAL_REGISTRY: OnceLock<Mutex<Vec<Arc<PocoPreparationJournalSharedStateV0>>>> =
    OnceLock::new();

type StoredPreparationRowV0 = (Vec<u8>, Vec<u8>, Option<Vec<u8>>, Option<Vec<u8>>, i64);

struct DecodedPocoPreparationTransitionV0 {
    old_validator_set: ValidatorSet,
    old_parameters: ConsensusParametersV0,
}

const JOURNAL_SCHEMA_SQL: &str = "
    CREATE TABLE metadata (
        key TEXT PRIMARY KEY NOT NULL,
        value TEXT NOT NULL
    ) STRICT;
    CREATE TABLE transition_bindings (
        transition_key BLOB PRIMARY KEY NOT NULL CHECK(length(transition_key)=32),
        binding_record BLOB NOT NULL
            CHECK(length(binding_record)>0 AND length(binding_record)<=67108864),
        binding_checksum BLOB NOT NULL CHECK(length(binding_checksum)=32)
    ) STRICT;
    CREATE TABLE preparations (
        transition_key BLOB NOT NULL CHECK(length(transition_key)=32),
        block_kind INTEGER NOT NULL CHECK(block_kind=1),
        height_be BLOB NOT NULL CHECK(length(height_be)=8),
        view_be BLOB NOT NULL CHECK(length(view_be)=8),
        preparation_record BLOB NOT NULL
            CHECK(length(preparation_record)>0 AND length(preparation_record)<=67108864),
        preparation_checksum BLOB NOT NULL CHECK(length(preparation_checksum)=32),
        bound_record BLOB
            CHECK(bound_record IS NULL OR
                (length(bound_record)>0 AND length(bound_record)<=67108864)),
        bound_checksum BLOB CHECK(bound_checksum IS NULL OR length(bound_checksum)=32),
        phase INTEGER NOT NULL CHECK(phase IN (0,1)),
        PRIMARY KEY (transition_key, block_kind, height_be, view_be),
        FOREIGN KEY (transition_key) REFERENCES transition_bindings(transition_key),
        CHECK(
            (phase=0 AND bound_record IS NULL AND bound_checksum IS NULL) OR
            (phase=1 AND bound_record IS NOT NULL AND bound_checksum IS NOT NULL)
        )
    ) STRICT;
    CREATE TABLE safety_halt (
        singleton INTEGER PRIMARY KEY NOT NULL CHECK(singleton=1),
        reason TEXT NOT NULL CHECK(length(reason)>0),
        conflict_checksum BLOB NOT NULL CHECK(length(conflict_checksum)=32)
    ) STRICT;
";

/// Immutable facts that identify and bind one epoch checkpoint transition.
///
/// The transition key intentionally covers only chain/epoch/checkpoint
/// identity. Configuration, cutoff, commitment, and authority facts live in
/// the binding record so that any attempt to change them for a later view of
/// the same transition becomes a durable conflict.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PocoPreparationTransitionBindingV0 {
    pub(crate) genesis_hash: GenesisHash,
    pub(crate) chain_id: ChainId,
    pub(crate) protocol_version: ProtocolVersion,
    pub(crate) old_epoch: Epoch,
    pub(crate) checkpoint_height: Height,
    pub(crate) cutoff_height: Height,
    pub(crate) cutoff_state_root: StateRoot,
    pub(crate) cutoff_entries_root: [u8; 32],
    pub(crate) cutoff_entry_count: u32,
    pub(crate) old_validator_set_id: ValidatorSetId,
    pub(crate) old_parameters_hash: ConsensusParametersHash,
    pub(crate) new_validator_set_id: ValidatorSetId,
    pub(crate) new_parameters_hash: ConsensusParametersHash,
    pub(crate) commitment_hash: NextEpochCommitmentHash,
    pub(crate) scheduled_cutoff_authorization_id: [u8; 32],
    pub(crate) commitment_authorization_id: [u8; 32],
    pub(crate) scheduled_cutoff_canonical_bytes: Vec<u8>,
    pub(crate) old_validator_set_cev0: Vec<u8>,
    pub(crate) old_parameters_cev0: Vec<u8>,
    pub(crate) new_validator_set_cev0: Vec<u8>,
    pub(crate) new_parameters_cev0: Vec<u8>,
    pub(crate) commitment_cev0: Vec<u8>,
}

impl PocoPreparationTransitionBindingV0 {
    fn transition_key(&self) -> [u8; 32] {
        hash_domain(
            TRANSITION_KEY_DOMAIN_V0,
            &[
                self.genesis_hash.as_bytes(),
                self.chain_id.as_bytes(),
                &self.protocol_version.get().to_be_bytes(),
                &self.old_epoch.get().to_be_bytes(),
                &self.checkpoint_height.get().to_be_bytes(),
            ],
        )
    }

    fn validate_shape(&self) -> Result<()> {
        ensure!(
            !self.genesis_hash.is_zero()
                && !self.old_validator_set_id.is_zero()
                && !self.old_parameters_hash.is_zero()
                && !self.new_validator_set_id.is_zero()
                && !self.new_parameters_hash.is_zero()
                && !self.commitment_hash.is_zero()
                && self.scheduled_cutoff_authorization_id != [0; 32]
                && self.commitment_authorization_id != [0; 32],
            "preparation transition binding contains a zero consensus identifier"
        );
        ensure!(
            self.cutoff_height.get() < self.checkpoint_height.get(),
            "preparation cutoff is not before checkpoint"
        );
        ensure!(
            self.cutoff_entry_count > 0,
            "preparation cutoff manifest is empty"
        );
        for (label, value) in [
            (
                "scheduled cutoff",
                self.scheduled_cutoff_canonical_bytes.as_slice(),
            ),
            ("old validator set", self.old_validator_set_cev0.as_slice()),
            ("old parameters", self.old_parameters_cev0.as_slice()),
            ("new validator set", self.new_validator_set_cev0.as_slice()),
            ("new parameters", self.new_parameters_cev0.as_slice()),
            ("commitment", self.commitment_cev0.as_slice()),
        ] {
            ensure!(
                !value.is_empty(),
                "preparation {label} replay bytes are empty"
            );
            ensure!(
                value.len() <= MAX_REPLAY_FIELD_BYTES,
                "preparation {label} replay bytes exceed storage bound"
            );
        }
        Ok(())
    }

    fn decode_semantics(&self) -> Result<DecodedPocoPreparationTransitionV0> {
        self.validate_shape()?;
        let old_validator_set = decode_validator_set_v0_exact(&self.old_validator_set_cev0)
            .map_err(|error| anyhow!("decode replay old validator set: {error:?}"))?;
        let old_parameters = decode_consensus_parameters_v0_exact(&self.old_parameters_cev0)
            .map_err(|error| anyhow!("decode replay old parameters: {error:?}"))?;
        let new_validator_set = decode_validator_set_v0_exact(&self.new_validator_set_cev0)
            .map_err(|error| anyhow!("decode replay new validator set: {error:?}"))?;
        let new_parameters = decode_consensus_parameters_v0_exact(&self.new_parameters_cev0)
            .map_err(|error| anyhow!("decode replay new parameters: {error:?}"))?;
        let commitment = decode_next_epoch_commitment_v0_exact(&self.commitment_cev0)
            .map_err(|error| anyhow!("decode replay next-epoch commitment: {error:?}"))?;

        old_validator_set
            .validate_against_parameters(&old_parameters)
            .map_err(|error| anyhow!("validate replay old configuration: {error:?}"))?;
        new_validator_set
            .validate_against_parameters(&new_parameters)
            .map_err(|error| anyhow!("validate replay new configuration: {error:?}"))?;
        commitment
            .validate_same_version_context(
                &old_validator_set,
                &old_parameters,
                &new_validator_set,
                &new_parameters,
            )
            .map_err(|error| anyhow!("validate replay next-epoch context: {error:?}"))?;
        let commitment_fields = commitment.fields();
        ensure!(
            old_validator_set.genesis_hash() == self.genesis_hash
                && old_validator_set.chain_id() == self.chain_id
                && old_validator_set.protocol_version() == self.protocol_version
                && old_validator_set.epoch() == self.old_epoch
                && old_validator_set.id() == self.old_validator_set_id
                && old_parameters.hash() == self.old_parameters_hash
                && new_validator_set.id() == self.new_validator_set_id
                && new_parameters.hash() == self.new_parameters_hash
                && commitment.id() == self.commitment_hash
                && commitment_fields.snapshot_cutoff_height == self.cutoff_height
                && commitment_fields.snapshot_state_root == self.cutoff_state_root,
            "decoded replay configuration differs from transition binding"
        );

        let scheduled_cutoff = PocoScheduledCutoffAuthorizationPreimageV0::decode_exact(
            &self.scheduled_cutoff_canonical_bytes,
        )?;
        scheduled_cutoff.validate_against(&old_validator_set, &old_parameters)?;
        ensure!(
            scheduled_cutoff.genesis_hash == self.genesis_hash
                && scheduled_cutoff.chain_id == self.chain_id
                && scheduled_cutoff.protocol_version == self.protocol_version
                && scheduled_cutoff.epoch == self.old_epoch
                && scheduled_cutoff.checkpoint_height == self.checkpoint_height
                && scheduled_cutoff.cutoff_height == self.cutoff_height
                && scheduled_cutoff.cutoff_state_root == self.cutoff_state_root
                && scheduled_cutoff.cutoff_entries_root == self.cutoff_entries_root
                && scheduled_cutoff.cutoff_entry_count == self.cutoff_entry_count
                && scheduled_cutoff.old_validator_set_id == self.old_validator_set_id
                && scheduled_cutoff.old_parameters_hash == self.old_parameters_hash
                && scheduled_cutoff.authorization_id()? == self.scheduled_cutoff_authorization_id,
            "scheduled-cutoff replay differs from transition binding"
        );

        Ok(DecodedPocoPreparationTransitionV0 {
            old_validator_set,
            old_parameters,
        })
    }

    fn validate(&self) -> Result<()> {
        self.decode_semantics().map(|_| ())
    }

    fn canonical_bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let mut encoder = ReplayEncoder::new();
        encoder.u16(0);
        encoder.fixed(self.genesis_hash.as_bytes());
        encoder.bytes(self.chain_id.as_bytes())?;
        encoder.u32(self.protocol_version.get());
        encoder.u64(self.old_epoch.get());
        encoder.u64(self.checkpoint_height.get());
        encoder.u64(self.cutoff_height.get());
        encoder.fixed(self.cutoff_state_root.as_bytes());
        encoder.fixed(&self.cutoff_entries_root);
        encoder.u32(self.cutoff_entry_count);
        encoder.fixed(self.old_validator_set_id.as_bytes());
        encoder.fixed(self.old_parameters_hash.as_bytes());
        encoder.fixed(self.new_validator_set_id.as_bytes());
        encoder.fixed(self.new_parameters_hash.as_bytes());
        encoder.fixed(self.commitment_hash.as_bytes());
        encoder.fixed(&self.scheduled_cutoff_authorization_id);
        encoder.fixed(&self.commitment_authorization_id);
        encoder.bytes(&self.scheduled_cutoff_canonical_bytes)?;
        encoder.bytes(&self.old_validator_set_cev0)?;
        encoder.bytes(&self.old_parameters_cev0)?;
        encoder.bytes(&self.new_validator_set_cev0)?;
        encoder.bytes(&self.new_parameters_cev0)?;
        encoder.bytes(&self.commitment_cev0)?;
        encoder.finish()
    }

    fn decode_exact(bytes: &[u8]) -> Result<Self> {
        let mut decoder = ReplayDecoder::new(bytes)?;
        ensure!(decoder.u16()? == 0, "unsupported transition replay version");
        let value = Self {
            genesis_hash: GenesisHash::new(decoder.fixed32()?),
            chain_id: ChainId::from_bytes(&decoder.bytes()?)
                .map_err(|error| anyhow!("decode transition chain ID: {error:?}"))?,
            protocol_version: ProtocolVersion::new(decoder.u32()?)
                .map_err(|error| anyhow!("decode transition protocol version: {error:?}"))?,
            old_epoch: Epoch::new(decoder.u64()?),
            checkpoint_height: Height::new(decoder.u64()?),
            cutoff_height: Height::new(decoder.u64()?),
            cutoff_state_root: StateRoot::new(decoder.fixed32()?),
            cutoff_entries_root: decoder.fixed32()?,
            cutoff_entry_count: decoder.u32()?,
            old_validator_set_id: ValidatorSetId::new(decoder.fixed32()?),
            old_parameters_hash: ConsensusParametersHash::new(decoder.fixed32()?),
            new_validator_set_id: ValidatorSetId::new(decoder.fixed32()?),
            new_parameters_hash: ConsensusParametersHash::new(decoder.fixed32()?),
            commitment_hash: NextEpochCommitmentHash::new(decoder.fixed32()?),
            scheduled_cutoff_authorization_id: decoder.fixed32()?,
            commitment_authorization_id: decoder.fixed32()?,
            scheduled_cutoff_canonical_bytes: decoder.bytes()?,
            old_validator_set_cev0: decoder.bytes()?,
            old_parameters_cev0: decoder.bytes()?,
            new_validator_set_cev0: decoder.bytes()?,
            new_parameters_cev0: decoder.bytes()?,
            commitment_cev0: decoder.bytes()?,
        };
        decoder.finish()?;
        value.validate()?;
        ensure!(
            value.canonical_bytes()? == bytes,
            "non-canonical transition replay record"
        );
        Ok(value)
    }
}

/// Header fields retained in the durable replay record. The record has no
/// CometBFT hash and no signature or vote authorization.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PocoCheckpointPreparationReplayFieldsV0 {
    pub(crate) genesis_hash: GenesisHash,
    pub(crate) chain_id: ChainId,
    pub(crate) protocol_version: ProtocolVersion,
    pub(crate) epoch: Epoch,
    pub(crate) view: View,
    pub(crate) height: Height,
    pub(crate) parent_id: BlockId,
    pub(crate) proposer_id: ValidatorId,
    pub(crate) validator_set_id: ValidatorSetId,
    pub(crate) consensus_parameters_hash: ConsensusParametersHash,
    pub(crate) payload_root: PayloadDigest,
    pub(crate) state_root: StateRoot,
    pub(crate) receipts_root: ReceiptsRoot,
    pub(crate) evidence_root: EvidenceRoot,
    pub(crate) timestamp_ms: u64,
    pub(crate) next_epoch_commitment_hash: NextEpochCommitmentHash,
    pub(crate) transaction_count: u32,
    pub(crate) evidence_count: u32,
}

/// Recomputes the private preparation seal from one exact replay-field view.
/// This helper is shared by the live pre-header path and durable validation;
/// it cannot construct either authority.
pub(crate) fn poco_checkpoint_preparation_authorization_id_v0(
    commitment_authorization_id: [u8; 32],
    native_execution_authorization_id: [u8; 32],
    certified_parent_cev0: &[u8],
    fields: &PocoCheckpointPreparationReplayFieldsV0,
) -> [u8; 32] {
    hash_domain(
        PREPARATION_AUTHORIZATION_DOMAIN_V0,
        &[
            &commitment_authorization_id,
            &native_execution_authorization_id,
            certified_parent_cev0,
            fields.genesis_hash.as_bytes(),
            fields.chain_id.as_bytes(),
            &fields.protocol_version.get().to_be_bytes(),
            &fields.epoch.get().to_be_bytes(),
            &fields.view.get().to_be_bytes(),
            &fields.height.get().to_be_bytes(),
            fields.parent_id.as_bytes(),
            fields.proposer_id.as_bytes(),
            fields.validator_set_id.as_bytes(),
            fields.consensus_parameters_hash.as_bytes(),
            fields.payload_root.as_bytes(),
            fields.state_root.as_bytes(),
            fields.receipts_root.as_bytes(),
            fields.evidence_root.as_bytes(),
            &fields.timestamp_ms.to_be_bytes(),
            fields.next_epoch_commitment_hash.as_bytes(),
            &fields.transaction_count.to_be_bytes(),
            &fields.evidence_count.to_be_bytes(),
        ],
    )
}

/// Recomputes the private exact-header authorization seal. The digest is
/// inert comparison material and never restores the opaque header authority.
pub(crate) fn poco_checkpoint_header_authorization_id_v0(
    preparation_id: [u8; 32],
    header_cev0: &[u8],
    native_block_id: BlockId,
) -> [u8; 32] {
    hash_domain(
        HEADER_AUTHORIZATION_DOMAIN_V0,
        &[&preparation_id, header_cev0, native_block_id.as_bytes()],
    )
}

/// Exact comparison material needed to replay one checkpoint preparation
/// after reconstructing its strict in-memory authorities.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PocoCheckpointPreparationReplayRecordV0 {
    binding: PocoPreparationTransitionBindingV0,
    fields: PocoCheckpointPreparationReplayFieldsV0,
    preparation_id: [u8; 32],
    native_execution_authorization_id: [u8; 32],
    checkpoint_parent_header_cev0: Vec<u8>,
    certified_checkpoint_parent_cev0: Vec<u8>,
    payload_cev0: Vec<u8>,
    evidence_cev0: Vec<Vec<u8>>,
    receipts_cev0: Vec<Vec<u8>>,
}

impl PocoCheckpointPreparationReplayRecordV0 {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        binding: PocoPreparationTransitionBindingV0,
        fields: PocoCheckpointPreparationReplayFieldsV0,
        preparation_id: [u8; 32],
        native_execution_authorization_id: [u8; 32],
        checkpoint_parent_header_cev0: Vec<u8>,
        certified_checkpoint_parent_cev0: Vec<u8>,
        payload_cev0: Vec<u8>,
        evidence_cev0: Vec<Vec<u8>>,
        receipts_cev0: Vec<Vec<u8>>,
    ) -> Result<Self> {
        let value = Self {
            binding,
            fields,
            preparation_id,
            native_execution_authorization_id,
            checkpoint_parent_header_cev0,
            certified_checkpoint_parent_cev0,
            payload_cev0,
            evidence_cev0,
            receipts_cev0,
        };
        value.validate()?;
        Ok(value)
    }

    pub(crate) const fn preparation_id(&self) -> [u8; 32] {
        self.preparation_id
    }

    pub(crate) const fn fields(&self) -> &PocoCheckpointPreparationReplayFieldsV0 {
        &self.fields
    }

    fn transition_key(&self) -> [u8; 32] {
        self.binding.transition_key()
    }

    fn slot(&self) -> PocoPreparationSlotV0 {
        PocoPreparationSlotV0 {
            transition_key: self.transition_key(),
            block_kind: BlockKind::EpochCheckpoint as u8,
            height: self.fields.height,
            view: self.fields.view,
        }
    }

    fn validate(&self) -> Result<()> {
        let decoded_transition = self.binding.decode_semantics()?;
        let old_validator_set = &decoded_transition.old_validator_set;
        let old_parameters = &decoded_transition.old_parameters;
        ensure!(
            self.fields.genesis_hash == self.binding.genesis_hash
                && self.fields.chain_id == self.binding.chain_id
                && self.fields.protocol_version == self.binding.protocol_version
                && self.fields.epoch == self.binding.old_epoch
                && self.fields.height == self.binding.checkpoint_height
                && self.fields.validator_set_id == self.binding.old_validator_set_id
                && self.fields.consensus_parameters_hash == self.binding.old_parameters_hash
                && self.fields.next_epoch_commitment_hash == self.binding.commitment_hash,
            "preparation replay fields differ from transition binding"
        );
        ensure!(
            !self.fields.parent_id.is_zero()
                && !self.fields.payload_root.is_zero()
                && !self.fields.state_root.is_zero()
                && !self.fields.receipts_root.is_zero()
                && !self.fields.evidence_root.is_zero()
                && !self.fields.proposer_id.is_zero()
                && self.preparation_id != [0; 32]
                && self.native_execution_authorization_id != [0; 32],
            "preparation replay fields contain a zero identifier/root"
        );
        ensure!(
            self.fields.transaction_count as usize == self.receipts_cev0.len(),
            "preparation transaction/receipt count mismatch"
        );
        ensure!(
            self.fields.evidence_count as usize == self.evidence_cev0.len(),
            "preparation evidence count mismatch"
        );
        for (label, bytes) in [
            (
                "checkpoint parent header",
                self.checkpoint_parent_header_cev0.as_slice(),
            ),
            (
                "certified checkpoint parent",
                self.certified_checkpoint_parent_cev0.as_slice(),
            ),
            ("payload", self.payload_cev0.as_slice()),
        ] {
            ensure!(
                !bytes.is_empty(),
                "preparation {label} replay bytes are empty"
            );
            ensure!(
                bytes.len() <= MAX_REPLAY_FIELD_BYTES,
                "preparation {label} replay bytes exceed storage bound"
            );
        }
        ensure!(
            self.evidence_cev0.len() <= MAX_REPLAY_LIST_ITEMS
                && self.receipts_cev0.len() <= MAX_REPLAY_LIST_ITEMS,
            "preparation replay list exceeds storage bound"
        );
        for bytes in self.evidence_cev0.iter().chain(&self.receipts_cev0) {
            ensure!(
                !bytes.is_empty() && bytes.len() <= MAX_REPLAY_FIELD_BYTES,
                "preparation replay list item is empty or oversized"
            );
        }
        let parent = decode_block_header_v0_exact(&self.checkpoint_parent_header_cev0)
            .map_err(|error| anyhow!("decode replay checkpoint parent header: {error:?}"))?;
        ensure!(
            parent.id() == self.fields.parent_id
                && parent.genesis_hash() == self.fields.genesis_hash
                && parent.chain_id() == self.fields.chain_id
                && parent.protocol_version() == self.fields.protocol_version
                && parent.epoch() == self.fields.epoch
                && parent.validator_set_id() == self.fields.validator_set_id
                && parent.consensus_parameters_hash() == self.fields.consensus_parameters_hash
                && parent.height().get().checked_add(1) == Some(self.fields.height.get()),
            "preparation replay checkpoint parent differs from frozen header fields"
        );
        let geometry = EpochGeometryV0::new(self.fields.epoch, old_parameters)
            .map_err(|error| anyhow!("invalid replay checkpoint geometry: {error:?}"))?;
        ensure!(
            geometry.checkpoint_height() == self.fields.height
                && geometry
                    .expected_block_kind(parent.height())
                    .map_err(|error| anyhow!("replay checkpoint parent schedule: {error:?}"))?
                    == BlockKind::Regular
                && parent.block_kind() == BlockKind::Regular
                && parent.next_epoch_commitment_hash().is_none(),
            "preparation replay parent/checkpoint geometry is invalid"
        );
        ensure!(
            self.certified_checkpoint_parent_cev0
                .starts_with(&self.checkpoint_parent_header_cev0),
            "certified checkpoint parent does not retain the exact parent header prefix"
        );
        ensure!(
            self.fields.view.get() > parent.view().get(),
            "replay checkpoint view does not advance beyond parent view"
        );
        let validators = old_validator_set.validators();
        let leader_index = self
            .fields
            .view
            .get()
            .saturating_sub(1)
            .checked_rem(u64::try_from(validators.len()).context("validator count exceeds u64")?)
            .context("replay checkpoint leader schedule has no validators")?;
        let leader_index =
            usize::try_from(leader_index).context("replay leader index exceeds usize")?;
        ensure!(
            validators[leader_index].id() == self.fields.proposer_id,
            "replay checkpoint proposer is not the scheduled old-set leader"
        );
        let maximum_timestamp = parent
            .timestamp_ms()
            .checked_add(old_parameters.max_block_time_step_ms())
            .context("replay checkpoint maximum timestamp overflow")?;
        ensure!(
            self.fields.timestamp_ms > parent.timestamp_ms()
                && self.fields.timestamp_ms <= maximum_timestamp,
            "replay checkpoint timestamp is outside the parent-relative bound"
        );

        let payload = decode_application_payload_v0_exact(&self.payload_cev0, old_parameters)
            .map_err(|error| anyhow!("decode replay checkpoint payload: {error:?}"))?;
        ensure!(
            payload.transaction_count() == self.fields.transaction_count,
            "decoded replay transaction count differs from frozen fields"
        );
        let evidence = self
            .evidence_cev0
            .iter()
            .map(|bytes| {
                decode_double_vote_evidence_v0_exact(bytes, old_validator_set)
                    .map_err(|error| anyhow!("decode replay checkpoint evidence: {error:?}"))
            })
            .collect::<Result<Vec<_>>>()?;
        let body = BlockBodyV0::new(payload, evidence)
            .map_err(|error| anyhow!("construct replay checkpoint body: {error:?}"))?;
        body.verify_evidence(old_validator_set, &StrictEd25519Verifier)
            .map_err(|error| anyhow!("strict replay checkpoint evidence: {error:?}"))?;
        let receipts = self
            .receipts_cev0
            .iter()
            .map(|bytes| {
                decode_execution_receipt_commitment_v0_exact(bytes, old_parameters)
                    .map_err(|error| anyhow!("decode replay checkpoint receipt: {error:?}"))
            })
            .collect::<Result<Vec<_>>>()?;
        let receipts = ExecutionReceiptsV0::new(body.application_payload(), receipts)
            .map_err(|error| anyhow!("construct replay checkpoint receipts: {error:?}"))?;
        receipts
            .validate_max_bytes(old_parameters.max_block_bytes())
            .map_err(|error| anyhow!("validate replay checkpoint receipt size: {error:?}"))?;
        let payload_root = body
            .payload_root()
            .map_err(|error| anyhow!("compute replay payload root: {error:?}"))?;
        let evidence_root = body
            .evidence_root()
            .map_err(|error| anyhow!("compute replay evidence root: {error:?}"))?;
        let receipts_root = receipts
            .receipts_root()
            .map_err(|error| anyhow!("compute replay receipts root: {error:?}"))?;
        ensure!(
            payload_root == self.fields.payload_root
                && evidence_root == self.fields.evidence_root
                && receipts_root == self.fields.receipts_root,
            "recomputed replay body/receipt roots differ from frozen fields"
        );
        let receipts_cev0 = receipts
            .try_cev0_bytes()
            .map_err(|error| anyhow!("encode replay checkpoint receipts: {error:?}"))?;
        ensure!(
            native_checkpoint_execution_authorization_id_v0(
                parent.height(),
                parent.state_root(),
                self.fields.height,
                self.fields.state_root,
                payload_root,
                receipts_root,
                &self.payload_cev0,
                &receipts_cev0,
            ) == self.native_execution_authorization_id,
            "recomputed replay native execution authorization ID differs from stored ID"
        );
        ensure!(
            poco_checkpoint_preparation_authorization_id_v0(
                self.binding.commitment_authorization_id,
                self.native_execution_authorization_id,
                &self.certified_checkpoint_parent_cev0,
                &self.fields,
            ) == self.preparation_id,
            "recomputed replay preparation authorization ID differs from stored ID"
        );
        Ok(())
    }

    fn canonical_bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        self.storage_bytes()
    }

    fn storage_bytes(&self) -> Result<Vec<u8>> {
        let binding_bytes = self.binding.canonical_bytes()?;
        let mut encoder = ReplayEncoder::new();
        encoder.u16(0);
        encoder.bytes(&binding_bytes)?;
        encoder.fixed(self.fields.genesis_hash.as_bytes());
        encoder.bytes(self.fields.chain_id.as_bytes())?;
        encoder.u32(self.fields.protocol_version.get());
        encoder.u64(self.fields.epoch.get());
        encoder.u8(BlockKind::EpochCheckpoint as u8);
        encoder.u64(self.fields.view.get());
        encoder.u64(self.fields.height.get());
        encoder.fixed(self.fields.parent_id.as_bytes());
        encoder.bytes(self.fields.proposer_id.as_bytes())?;
        encoder.fixed(self.fields.validator_set_id.as_bytes());
        encoder.fixed(self.fields.consensus_parameters_hash.as_bytes());
        encoder.fixed(self.fields.payload_root.as_bytes());
        encoder.fixed(self.fields.state_root.as_bytes());
        encoder.fixed(self.fields.receipts_root.as_bytes());
        encoder.fixed(self.fields.evidence_root.as_bytes());
        encoder.u64(self.fields.timestamp_ms);
        encoder.fixed(self.fields.next_epoch_commitment_hash.as_bytes());
        encoder.u32(self.fields.transaction_count);
        encoder.u32(self.fields.evidence_count);
        encoder.fixed(&self.preparation_id);
        encoder.fixed(&self.native_execution_authorization_id);
        encoder.bytes(&self.checkpoint_parent_header_cev0)?;
        encoder.bytes(&self.certified_checkpoint_parent_cev0)?;
        encoder.bytes(&self.payload_cev0)?;
        encoder.bytes_list(&self.evidence_cev0)?;
        encoder.bytes_list(&self.receipts_cev0)?;
        encoder.finish()
    }

    fn decode_exact(bytes: &[u8]) -> Result<Self> {
        let mut decoder = ReplayDecoder::new(bytes)?;
        ensure!(
            decoder.u16()? == 0,
            "unsupported preparation replay version"
        );
        let binding = PocoPreparationTransitionBindingV0::decode_exact(&decoder.bytes()?)?;
        let genesis_hash = GenesisHash::new(decoder.fixed32()?);
        let chain_id = ChainId::from_bytes(&decoder.bytes()?)
            .map_err(|error| anyhow!("decode preparation chain ID: {error:?}"))?;
        let protocol_version = ProtocolVersion::new(decoder.u32()?)
            .map_err(|error| anyhow!("decode preparation protocol version: {error:?}"))?;
        let epoch = Epoch::new(decoder.u64()?);
        ensure!(
            decoder.u8()? == BlockKind::EpochCheckpoint as u8,
            "preparation replay block kind is not checkpoint"
        );
        let fields = PocoCheckpointPreparationReplayFieldsV0 {
            genesis_hash,
            chain_id,
            protocol_version,
            epoch,
            view: View::new(decoder.u64()?),
            height: Height::new(decoder.u64()?),
            parent_id: BlockId::new(decoder.fixed32()?),
            proposer_id: ValidatorId::from_bytes(&decoder.bytes()?)
                .map_err(|error| anyhow!("decode preparation proposer ID: {error:?}"))?,
            validator_set_id: ValidatorSetId::new(decoder.fixed32()?),
            consensus_parameters_hash: ConsensusParametersHash::new(decoder.fixed32()?),
            payload_root: PayloadDigest::new(decoder.fixed32()?),
            state_root: StateRoot::new(decoder.fixed32()?),
            receipts_root: ReceiptsRoot::new(decoder.fixed32()?),
            evidence_root: EvidenceRoot::new(decoder.fixed32()?),
            timestamp_ms: decoder.u64()?,
            next_epoch_commitment_hash: NextEpochCommitmentHash::new(decoder.fixed32()?),
            transaction_count: decoder.u32()?,
            evidence_count: decoder.u32()?,
        };
        let value = Self {
            binding,
            fields,
            preparation_id: decoder.fixed32()?,
            native_execution_authorization_id: decoder.fixed32()?,
            checkpoint_parent_header_cev0: decoder.bytes()?,
            certified_checkpoint_parent_cev0: decoder.bytes()?,
            payload_cev0: decoder.bytes()?,
            evidence_cev0: decoder.bytes_list()?,
            receipts_cev0: decoder.bytes_list()?,
        };
        decoder.finish()?;
        value.validate()?;
        ensure!(
            value.canonical_bytes()? == bytes,
            "non-canonical preparation replay record"
        );
        Ok(value)
    }
}

/// Inert database comparison view. Its private inner record intentionally has
/// no crate-visible accessor or conversion into the fresh record accepted by
/// [`PocoPreparationJournalV0::reserve`]. A caller must reconstruct the live
/// pre-header authority and let the checkpoint-header module build a new
/// record before idempotent reservation can be retried.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PocoCheckpointPreparationReplayViewV0 {
    record: PocoCheckpointPreparationReplayRecordV0,
}

/// Exact native-header facts stored only after the prepared tuple has bound.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PocoCheckpointBoundReplayRecordV0 {
    header_cev0: Vec<u8>,
    native_block_id: BlockId,
    header_authorization_id: [u8; 32],
}

impl PocoCheckpointBoundReplayRecordV0 {
    pub(crate) fn new(
        header_cev0: Vec<u8>,
        native_block_id: BlockId,
        header_authorization_id: [u8; 32],
    ) -> Result<Self> {
        let value = Self {
            header_cev0,
            native_block_id,
            header_authorization_id,
        };
        ensure!(
            !value.header_cev0.is_empty() && value.header_cev0.len() <= MAX_REPLAY_FIELD_BYTES,
            "bound checkpoint header replay bytes are empty or oversized"
        );
        ensure!(
            !value.native_block_id.is_zero(),
            "bound checkpoint native BlockId is zero"
        );
        Ok(value)
    }

    fn validate_against(
        &self,
        preparation: &PocoCheckpointPreparationReplayRecordV0,
    ) -> Result<()> {
        let header = decode_block_header_v0_exact(&self.header_cev0)
            .map_err(|error| anyhow!("decode bound checkpoint header: {error:?}"))?;
        let fields = preparation.fields();
        ensure!(
            header.block_kind() == BlockKind::EpochCheckpoint
                && header.id() == self.native_block_id
                && header.genesis_hash() == fields.genesis_hash
                && header.chain_id() == fields.chain_id
                && header.protocol_version() == fields.protocol_version
                && header.epoch() == fields.epoch
                && header.view() == fields.view
                && header.height() == fields.height
                && header.parent_id() == fields.parent_id
                && header.proposer_id() == fields.proposer_id
                && header.validator_set_id() == fields.validator_set_id
                && header.consensus_parameters_hash() == fields.consensus_parameters_hash
                && header.payload_root() == fields.payload_root
                && header.state_root() == fields.state_root
                && header.receipts_root() == fields.receipts_root
                && header.evidence_root() == fields.evidence_root
                && header.timestamp_ms() == fields.timestamp_ms
                && header.next_epoch_commitment_hash() == Some(fields.next_epoch_commitment_hash),
            "bound checkpoint header differs from durable preparation"
        );
        let expected_authorization_id = poco_checkpoint_header_authorization_id_v0(
            preparation.preparation_id,
            &self.header_cev0,
            self.native_block_id,
        );
        ensure!(
            self.header_authorization_id == expected_authorization_id,
            "bound checkpoint authorization ID differs from exact header"
        );
        Ok(())
    }

    fn canonical_bytes(
        &self,
        preparation: &PocoCheckpointPreparationReplayRecordV0,
    ) -> Result<Vec<u8>> {
        self.validate_against(preparation)?;
        self.storage_bytes()
    }

    fn storage_bytes(&self) -> Result<Vec<u8>> {
        let mut encoder = ReplayEncoder::new();
        encoder.u16(0);
        encoder.bytes(&self.header_cev0)?;
        encoder.fixed(self.native_block_id.as_bytes());
        encoder.fixed(&self.header_authorization_id);
        encoder.finish()
    }

    fn decode_exact(
        bytes: &[u8],
        preparation: &PocoCheckpointPreparationReplayRecordV0,
    ) -> Result<Self> {
        let mut decoder = ReplayDecoder::new(bytes)?;
        ensure!(decoder.u16()? == 0, "unsupported bound replay version");
        let value = Self {
            header_cev0: decoder.bytes()?,
            native_block_id: BlockId::new(decoder.fixed32()?),
            header_authorization_id: decoder.fixed32()?,
        };
        decoder.finish()?;
        value.validate_against(preparation)?;
        ensure!(
            value.canonical_bytes(preparation)? == bytes,
            "non-canonical bound replay record"
        );
        Ok(value)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PocoPreparationSlotV0 {
    transition_key: [u8; 32],
    block_kind: u8,
    height: Height,
    view: View,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct PocoPreparationJournalFileIdentityV0 {
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
    #[cfg(not(unix))]
    canonical_path: PathBuf,
}

#[derive(Debug)]
struct PocoPreparationJournalSharedStateV0 {
    database_path: PathBuf,
    file_identity: PocoPreparationJournalFileIdentityV0,
    journal_id: [u8; 32],
    writer: Mutex<()>,
    sticky_halt: AtomicBool,
}

/// Opaque proof that one exact preparation record is present in this exact
/// sidecar. It is not serializable and is not restored directly from SQLite.
#[derive(Clone, Debug)]
pub(crate) struct PocoPreparationReservationV0 {
    journal_path: PathBuf,
    journal_id: [u8; 32],
    slot: PocoPreparationSlotV0,
    preparation_id: [u8; 32],
    preparation_checksum: [u8; 32],
}

/// Independent SQLite sidecar for checkpoint-preparation safety state.
#[derive(Clone, Debug)]
pub(crate) struct PocoPreparationJournalV0 {
    database_path: PathBuf,
    shared: Arc<PocoPreparationJournalSharedStateV0>,
}

impl PocoPreparationJournalV0 {
    pub(crate) fn open(database_path: impl AsRef<Path>) -> Result<Self> {
        let requested_path = canonical_journal_path(database_path.as_ref())?;
        let registry = PROCESS_JOURNAL_REGISTRY.get_or_init(|| Mutex::new(Vec::new()));
        let mut registry = registry
            .lock()
            .map_err(|_| anyhow!("PoCO preparation journal process registry lock poisoned"))?;
        let observed_identity = journal_file_identity_if_present(&requested_path)?;

        let mut matching_state = None;
        for state in registry.iter() {
            let path_matches = state.database_path == requested_path;
            let registered_identity = journal_file_identity_if_present(&state.database_path)?;
            if registered_identity.as_ref() != Some(&state.file_identity) {
                state.sticky_halt.store(true, Ordering::Release);
                if path_matches {
                    bail!(
                        "PoCO preparation journal path now identifies a different or missing file"
                    );
                }
                continue;
            }
            let identity_matches = observed_identity
                .as_ref()
                .is_some_and(|identity| identity == &state.file_identity);
            if path_matches && !identity_matches {
                state.sticky_halt.store(true, Ordering::Release);
                bail!("PoCO preparation journal path now identifies a different or missing file");
            }
            if path_matches || identity_matches {
                matching_state = Some(Arc::clone(state));
                break;
            }
        }

        if let Some(shared) = matching_state {
            let _writer = shared
                .writer
                .lock()
                .map_err(|_| anyhow!("PoCO preparation journal writer lock poisoned"))?;
            let journal = Self {
                database_path: shared.database_path.clone(),
                shared: Arc::clone(&shared),
            };
            let connection = journal.connect()?;
            if let Err(error) = validate_database(&connection) {
                journal.shared.sticky_halt.store(true, Ordering::Release);
                return Err(error);
            }
            if durable_halt_present(&connection)? {
                journal.shared.sticky_halt.store(true, Ordering::Release);
            }
            return Ok(journal);
        }

        let initialize = observed_identity.is_none();
        let journal_id = if initialize {
            new_journal_id(&requested_path)?
        } else {
            [0; 32]
        };
        let mut connection = Connection::open(&requested_path).with_context(|| {
            format!("open PoCO preparation journal {}", requested_path.display())
        })?;
        configure_connection(&connection, initialize)?;
        if initialize {
            let transaction =
                connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
            transaction.execute_batch(JOURNAL_SCHEMA_SQL)?;
            ensure!(
                transaction.execute(
                    "INSERT INTO metadata(key, value) VALUES ('schema_version', ?1)",
                    params![JOURNAL_SCHEMA_VERSION],
                )? == 1,
                "failed to install PoCO preparation journal schema version"
            );
            ensure!(
                transaction.execute(
                    "INSERT INTO metadata(key, value) VALUES ('journal_id', ?1)",
                    params![hex::encode(journal_id)],
                )? == 1,
                "failed to install PoCO preparation journal identity"
            );
            transaction.commit()?;
            sync_parent_directory(&requested_path)?;
        }
        validate_database(&connection)?;
        let stored_journal_id = read_journal_id(&connection)?;
        if initialize {
            ensure!(
                stored_journal_id == journal_id,
                "new PoCO preparation journal identity changed during initialization"
            );
        }
        let file_identity = journal_file_identity(&requested_path)?;
        let canonical_path = fs::canonicalize(&requested_path).with_context(|| {
            format!(
                "canonicalize PoCO preparation journal {}",
                requested_path.display()
            )
        })?;
        let durable_halt = durable_halt_present(&connection)?;
        let shared = Arc::new(PocoPreparationJournalSharedStateV0 {
            database_path: canonical_path.clone(),
            file_identity,
            journal_id: stored_journal_id,
            writer: Mutex::new(()),
            sticky_halt: AtomicBool::new(durable_halt),
        });
        registry.push(Arc::clone(&shared));
        Ok(Self {
            database_path: canonical_path,
            shared,
        })
    }

    pub(crate) fn path(&self) -> &Path {
        &self.database_path
    }

    pub(crate) fn reserve(
        &self,
        record: &PocoCheckpointPreparationReplayRecordV0,
    ) -> Result<PocoPreparationReservationV0> {
        self.ensure_not_sticky_halted()?;
        record.validate()?;
        let binding_record = record.binding.canonical_bytes()?;
        let binding_checksum = hash_domain(BINDING_CHECKSUM_DOMAIN_V0, &[&binding_record]);
        let preparation_record = record.canonical_bytes()?;
        let preparation_checksum =
            hash_domain(PREPARATION_CHECKSUM_DOMAIN_V0, &[&preparation_record]);
        let slot = record.slot();
        let _writer = self
            .shared
            .writer
            .lock()
            .map_err(|_| anyhow!("PoCO preparation journal writer lock poisoned"))?;
        let mut connection = self.connect()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        validate_transaction_environment(&transaction, &self.shared)?;
        ensure_not_halted(&transaction, &self.shared.sticky_halt)?;

        let stored_binding: Option<(Vec<u8>, Vec<u8>)> = transaction
            .query_row(
                "SELECT binding_record, binding_checksum
                 FROM transition_bindings WHERE transition_key=?1",
                params![slot.transition_key.as_slice()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        if let Some((stored_record, stored_checksum)) = stored_binding {
            if stored_record != binding_record
                || stored_checksum.as_slice() != binding_checksum.as_slice()
            {
                return commit_halt(
                    transaction,
                    &self.shared.sticky_halt,
                    "conflicting checkpoint transition binding",
                    &[
                        stored_checksum.as_slice(),
                        binding_checksum.as_slice(),
                        &slot.transition_key,
                    ],
                );
            }
        } else {
            let inserted = transaction.execute(
                "INSERT INTO transition_bindings(
                    transition_key, binding_record, binding_checksum
                 ) VALUES (?1, ?2, ?3)",
                params![
                    slot.transition_key.as_slice(),
                    binding_record.as_slice(),
                    binding_checksum.as_slice()
                ],
            )?;
            if inserted != 1 {
                return commit_halt(
                    transaction,
                    &self.shared.sticky_halt,
                    "checkpoint transition binding insert did not affect one row",
                    &[&slot.transition_key, binding_checksum.as_slice()],
                );
            }
        }
        let binding_readback: (Vec<u8>, Vec<u8>) = transaction.query_row(
            "SELECT binding_record, binding_checksum
             FROM transition_bindings WHERE transition_key=?1",
            params![slot.transition_key.as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        if binding_readback.0 != binding_record
            || binding_readback.1.as_slice() != binding_checksum.as_slice()
        {
            return commit_halt(
                transaction,
                &self.shared.sticky_halt,
                "checkpoint transition binding readback differs from requested record",
                &[
                    binding_readback.1.as_slice(),
                    binding_checksum.as_slice(),
                    &slot.transition_key,
                ],
            );
        }

        let height = slot.height.get().to_be_bytes();
        let view = slot.view.get().to_be_bytes();
        let stored_preparation: Option<(Vec<u8>, Vec<u8>)> = transaction
            .query_row(
                "SELECT preparation_record, preparation_checksum
                 FROM preparations
                 WHERE transition_key=?1 AND block_kind=?2
                   AND height_be=?3 AND view_be=?4",
                params![
                    slot.transition_key.as_slice(),
                    i64::from(slot.block_kind),
                    height.as_slice(),
                    view.as_slice()
                ],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        if let Some((stored_record, stored_checksum)) = stored_preparation {
            if stored_record != preparation_record
                || stored_checksum.as_slice() != preparation_checksum.as_slice()
            {
                return commit_halt(
                    transaction,
                    &self.shared.sticky_halt,
                    "conflicting checkpoint preparation for occupied slot",
                    &[
                        stored_checksum.as_slice(),
                        preparation_checksum.as_slice(),
                        &slot.transition_key,
                        &height,
                        &view,
                    ],
                );
            }
        } else {
            let inserted = transaction.execute(
                "INSERT INTO preparations(
                    transition_key, block_kind, height_be, view_be,
                    preparation_record, preparation_checksum,
                    bound_record, bound_checksum, phase
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, NULL, NULL, 0)",
                params![
                    slot.transition_key.as_slice(),
                    i64::from(slot.block_kind),
                    height.as_slice(),
                    view.as_slice(),
                    preparation_record.as_slice(),
                    preparation_checksum.as_slice()
                ],
            )?;
            if inserted != 1 {
                return commit_halt(
                    transaction,
                    &self.shared.sticky_halt,
                    "checkpoint preparation insert did not affect one row",
                    &[
                        &slot.transition_key,
                        &height,
                        &view,
                        preparation_checksum.as_slice(),
                    ],
                );
            }
        }
        let preparation_readback: (Vec<u8>, Vec<u8>) = transaction.query_row(
            "SELECT preparation_record, preparation_checksum
             FROM preparations
             WHERE transition_key=?1 AND block_kind=?2
               AND height_be=?3 AND view_be=?4",
            params![
                slot.transition_key.as_slice(),
                i64::from(slot.block_kind),
                height.as_slice(),
                view.as_slice()
            ],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        if preparation_readback.0 != preparation_record
            || preparation_readback.1.as_slice() != preparation_checksum.as_slice()
        {
            return commit_halt(
                transaction,
                &self.shared.sticky_halt,
                "checkpoint preparation readback differs from requested record",
                &[
                    preparation_readback.1.as_slice(),
                    preparation_checksum.as_slice(),
                    &slot.transition_key,
                    &height,
                    &view,
                ],
            );
        }
        transaction.commit()?;
        Ok(PocoPreparationReservationV0 {
            journal_path: self.database_path.clone(),
            journal_id: self.shared.journal_id,
            slot,
            preparation_id: record.preparation_id,
            preparation_checksum,
        })
    }

    pub(crate) fn bind(
        &self,
        reservation: &PocoPreparationReservationV0,
        bound: &PocoCheckpointBoundReplayRecordV0,
    ) -> Result<()> {
        self.ensure_not_sticky_halted()?;
        ensure!(
            reservation.journal_path == self.database_path
                && reservation.journal_id == self.shared.journal_id,
            "preparation reservation belongs to another sidecar"
        );
        let _writer = self
            .shared
            .writer
            .lock()
            .map_err(|_| anyhow!("PoCO preparation journal writer lock poisoned"))?;
        let mut connection = self.connect()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        validate_transaction_environment(&transaction, &self.shared)?;
        ensure_not_halted(&transaction, &self.shared.sticky_halt)?;
        let height = reservation.slot.height.get().to_be_bytes();
        let view = reservation.slot.view.get().to_be_bytes();
        let stored: Option<StoredPreparationRowV0> = transaction
            .query_row(
                "SELECT preparation_record, preparation_checksum,
                            bound_record, bound_checksum, phase
                     FROM preparations
                     WHERE transition_key=?1 AND block_kind=?2
                       AND height_be=?3 AND view_be=?4",
                params![
                    reservation.slot.transition_key.as_slice(),
                    i64::from(reservation.slot.block_kind),
                    height.as_slice(),
                    view.as_slice()
                ],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                    ))
                },
            )
            .optional()?;
        let Some((
            preparation_bytes,
            preparation_checksum,
            stored_bound,
            stored_bound_checksum,
            phase,
        )) = stored
        else {
            bail!("preparation reservation slot is absent from sidecar");
        };
        if preparation_checksum.as_slice() != reservation.preparation_checksum.as_slice()
            || hash_domain(PREPARATION_CHECKSUM_DOMAIN_V0, &[&preparation_bytes])
                != reservation.preparation_checksum
        {
            return commit_halt(
                transaction,
                &self.shared.sticky_halt,
                "preparation reservation checksum differs from durable slot",
                &[
                    preparation_checksum.as_slice(),
                    &reservation.preparation_checksum,
                    &reservation.slot.transition_key,
                    &height,
                    &view,
                ],
            );
        }
        let preparation =
            PocoCheckpointPreparationReplayRecordV0::decode_exact(&preparation_bytes)?;
        if preparation.preparation_id() != reservation.preparation_id {
            return commit_halt(
                transaction,
                &self.shared.sticky_halt,
                "preparation reservation ID differs from durable slot",
                &[
                    &preparation.preparation_id(),
                    &reservation.preparation_id,
                    &reservation.slot.transition_key,
                ],
            );
        }
        let bound_record = bound.storage_bytes()?;
        let bound_checksum = hash_domain(BOUND_CHECKSUM_DOMAIN_V0, &[&bound_record]);
        match (phase, stored_bound, stored_bound_checksum) {
            (0, None, None) => {
                bound.validate_against(&preparation)?;
                let updated = transaction.execute(
                    "UPDATE preparations
                     SET bound_record=?1, bound_checksum=?2, phase=1
                     WHERE transition_key=?3 AND block_kind=?4
                       AND height_be=?5 AND view_be=?6 AND phase=0",
                    params![
                        bound_record.as_slice(),
                        bound_checksum.as_slice(),
                        reservation.slot.transition_key.as_slice(),
                        i64::from(reservation.slot.block_kind),
                        height.as_slice(),
                        view.as_slice()
                    ],
                )?;
                if updated != 1 {
                    return commit_halt(
                        transaction,
                        &self.shared.sticky_halt,
                        "checkpoint bound update did not affect one row",
                        &[
                            &reservation.slot.transition_key,
                            &height,
                            &view,
                            &bound_checksum,
                        ],
                    );
                }
            }
            (1, Some(stored_record), Some(stored_checksum))
                if stored_record == bound_record
                    && stored_checksum.as_slice() == bound_checksum.as_slice() =>
            {
                PocoCheckpointBoundReplayRecordV0::decode_exact(&stored_record, &preparation)?;
            }
            (stored_phase, stored_record, stored_checksum) => {
                let stored_checksum = stored_checksum.unwrap_or_default();
                let stored_record_checksum = stored_record
                    .as_deref()
                    .map(|bytes| hash_domain(BOUND_CHECKSUM_DOMAIN_V0, &[bytes]))
                    .unwrap_or([0; 32]);
                return commit_halt(
                    transaction,
                    &self.shared.sticky_halt,
                    "conflicting checkpoint header binding for occupied slot",
                    &[
                        &stored_phase.to_be_bytes(),
                        stored_checksum.as_slice(),
                        &stored_record_checksum,
                        &bound_checksum,
                        &reservation.slot.transition_key,
                        &height,
                        &view,
                    ],
                );
            }
        }
        let bound_readback: StoredPreparationRowV0 = transaction.query_row(
            "SELECT preparation_record, preparation_checksum,
                    bound_record, bound_checksum, phase
             FROM preparations
             WHERE transition_key=?1 AND block_kind=?2
               AND height_be=?3 AND view_be=?4",
            params![
                reservation.slot.transition_key.as_slice(),
                i64::from(reservation.slot.block_kind),
                height.as_slice(),
                view.as_slice()
            ],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            },
        )?;
        if bound_readback.0 != preparation_bytes
            || bound_readback.1.as_slice() != reservation.preparation_checksum.as_slice()
            || bound_readback.2.as_deref() != Some(bound_record.as_slice())
            || bound_readback.3.as_deref() != Some(bound_checksum.as_slice())
            || bound_readback.4 != 1
        {
            let observed_bound_checksum = bound_readback.3.unwrap_or_default();
            return commit_halt(
                transaction,
                &self.shared.sticky_halt,
                "checkpoint bound readback differs from requested record",
                &[
                    bound_readback.1.as_slice(),
                    observed_bound_checksum.as_slice(),
                    &reservation.preparation_checksum,
                    &bound_checksum,
                    &reservation.slot.transition_key,
                    &height,
                    &view,
                ],
            );
        }
        transaction.commit()?;
        Ok(())
    }

    /// Returns durable comparison records in deterministic slot order. These
    /// records are inert and cannot be converted into an opaque reservation.
    pub(crate) fn replay_records(&self) -> Result<Vec<PocoCheckpointPreparationReplayViewV0>> {
        self.ensure_not_sticky_halted()?;
        let _writer = self
            .shared
            .writer
            .lock()
            .map_err(|_| anyhow!("PoCO preparation journal writer lock poisoned"))?;
        let connection = self.connect()?;
        ensure_not_halted_connection(&connection, &self.shared.sticky_halt)?;
        let mut statement = connection.prepare(
            "SELECT preparation_record FROM preparations
             ORDER BY transition_key, block_kind, height_be, view_be",
        )?;
        let rows = statement.query_map([], |row| row.get::<_, Vec<u8>>(0))?;
        let mut records = Vec::new();
        for row in rows {
            records.push(PocoCheckpointPreparationReplayViewV0 {
                record: PocoCheckpointPreparationReplayRecordV0::decode_exact(&row?)?,
            });
        }
        Ok(records)
    }

    pub(crate) fn is_halted(&self) -> Result<bool> {
        if self.shared.sticky_halt.load(Ordering::Acquire) {
            return Ok(true);
        }
        let _writer = self
            .shared
            .writer
            .lock()
            .map_err(|_| anyhow!("PoCO preparation journal writer lock poisoned"))?;
        let connection = self.connect()?;
        let halted = durable_halt_present(&connection)?;
        if halted {
            self.shared.sticky_halt.store(true, Ordering::Release);
        }
        Ok(halted)
    }

    fn connect(&self) -> Result<Connection> {
        let result = (|| {
            ensure!(
                journal_file_identity(&self.database_path)? == self.shared.file_identity,
                "PoCO preparation journal file identity changed before reconnect"
            );
            let connection = Connection::open(&self.database_path).with_context(|| {
                format!(
                    "open existing PoCO preparation journal {}",
                    self.database_path.display()
                )
            })?;
            configure_connection(&connection, false)?;
            validate_canonical_schema(&connection)?;
            validate_metadata(&connection)?;
            ensure!(
                read_journal_id(&connection)? == self.shared.journal_id,
                "PoCO preparation journal identity changed during reconnect"
            );
            ensure!(
                journal_file_identity(&self.database_path)? == self.shared.file_identity,
                "PoCO preparation journal file identity changed during reconnect"
            );
            Ok(connection)
        })();
        if result.is_err() {
            self.shared.sticky_halt.store(true, Ordering::Release);
        }
        result
    }

    fn ensure_not_sticky_halted(&self) -> Result<()> {
        ensure!(
            !self.shared.sticky_halt.load(Ordering::Acquire),
            "PoCO preparation journal is sticky-halted"
        );
        Ok(())
    }
}

/// Derives a sidecar path that is distinct from both the state file and the
/// application store's `<state extension>.sqlite3` path.
pub(crate) fn poco_preparation_sidecar_path_v0(application_state_path: &Path) -> PathBuf {
    let extension = application_state_path
        .extension()
        .and_then(|value| value.to_str())
        .map(|value| format!("{value}.poco-preparation.sqlite3"))
        .unwrap_or_else(|| "poco-preparation.sqlite3".to_owned());
    application_state_path.with_extension(extension)
}

fn canonical_journal_path(path: &Path) -> Result<PathBuf> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        env::current_dir()
            .context("resolve current directory for PoCO preparation journal")?
            .join(path)
    };
    let file_name = absolute
        .file_name()
        .context("PoCO preparation journal path has no file name")?;
    let parent = absolute
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    fs::create_dir_all(parent).with_context(|| {
        format!(
            "create PoCO preparation journal directory {}",
            parent.display()
        )
    })?;
    let canonical_parent = fs::canonicalize(parent).with_context(|| {
        format!(
            "canonicalize PoCO preparation journal directory {}",
            parent.display()
        )
    })?;
    let candidate = canonical_parent.join(file_name);
    if candidate.exists() {
        fs::canonicalize(&candidate).with_context(|| {
            format!(
                "canonicalize existing PoCO preparation journal {}",
                candidate.display()
            )
        })
    } else {
        Ok(candidate)
    }
}

fn journal_file_identity_if_present(
    path: &Path,
) -> Result<Option<PocoPreparationJournalFileIdentityV0>> {
    match fs::metadata(path) {
        Ok(metadata) => Ok(Some(journal_file_identity_from_metadata(path, &metadata)?)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => {
            Err(error).with_context(|| format!("stat PoCO preparation journal {}", path.display()))
        }
    }
}

fn journal_file_identity(path: &Path) -> Result<PocoPreparationJournalFileIdentityV0> {
    let metadata = fs::metadata(path)
        .with_context(|| format!("stat PoCO preparation journal {}", path.display()))?;
    journal_file_identity_from_metadata(path, &metadata)
}

fn journal_file_identity_from_metadata(
    path: &Path,
    metadata: &fs::Metadata,
) -> Result<PocoPreparationJournalFileIdentityV0> {
    ensure!(
        metadata.is_file(),
        "PoCO preparation journal path is not a regular file"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let _ = path;
        Ok(PocoPreparationJournalFileIdentityV0 {
            device: metadata.dev(),
            inode: metadata.ino(),
        })
    }
    #[cfg(not(unix))]
    {
        Ok(PocoPreparationJournalFileIdentityV0 {
            canonical_path: fs::canonicalize(path).with_context(|| {
                format!(
                    "canonicalize PoCO preparation journal identity {}",
                    path.display()
                )
            })?,
        })
    }
}

fn new_journal_id(path: &Path) -> Result<[u8; 32]> {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock precedes Unix epoch while creating journal identity")?;
    let sequence = JOURNAL_ID_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let process_id = std::process::id().to_be_bytes();
    let seconds = elapsed.as_secs().to_be_bytes();
    let nanos = elapsed.subsec_nanos().to_be_bytes();
    let sequence = sequence.to_be_bytes();
    let journal_id = hash_domain(
        JOURNAL_ID_DOMAIN_V0,
        &[
            path.to_string_lossy().as_bytes(),
            &process_id,
            &seconds,
            &nanos,
            &sequence,
        ],
    );
    ensure!(
        journal_id != [0; 32],
        "derived zero PoCO preparation journal identity"
    );
    Ok(journal_id)
}

fn configure_connection(connection: &Connection, initialize: bool) -> Result<()> {
    connection.busy_timeout(Duration::from_secs(5))?;
    if initialize {
        connection.execute_batch("PRAGMA journal_mode=WAL;")?;
    }
    connection.execute_batch(
        "
        PRAGMA synchronous=FULL;
        PRAGMA foreign_keys=ON;
        PRAGMA trusted_schema=OFF;
        ",
    )?;
    let journal_mode: String = connection.query_row("PRAGMA journal_mode", [], |row| row.get(0))?;
    ensure!(
        journal_mode.eq_ignore_ascii_case("wal"),
        "PoCO preparation journal is not in WAL mode"
    );
    let synchronous: i64 = connection.query_row("PRAGMA synchronous", [], |row| row.get(0))?;
    ensure!(
        synchronous == 2,
        "PoCO preparation journal is not synchronous=FULL"
    );
    Ok(())
}

fn validate_database(connection: &Connection) -> Result<()> {
    validate_canonical_schema(connection)?;
    validate_schema_version(connection)?;
    validate_metadata(connection)?;
    let integrity: String = connection.query_row("PRAGMA integrity_check", [], |row| row.get(0))?;
    ensure!(
        integrity == "ok",
        "PoCO preparation journal integrity failure"
    );
    let mut foreign_keys = connection.prepare("PRAGMA foreign_key_check")?;
    ensure!(
        foreign_keys.query([])?.next()?.is_none(),
        "PoCO preparation journal foreign-key failure"
    );

    let mut bindings = connection.prepare(
        "SELECT transition_key, binding_record, binding_checksum
         FROM transition_bindings ORDER BY transition_key",
    )?;
    let mut rows = bindings.query([])?;
    let mut binding_records = BTreeMap::new();
    while let Some(row) = rows.next()? {
        let transition_key: Vec<u8> = row.get(0)?;
        let binding_record: Vec<u8> = row.get(1)?;
        let binding_checksum: Vec<u8> = row.get(2)?;
        let binding = PocoPreparationTransitionBindingV0::decode_exact(&binding_record)?;
        ensure!(
            transition_key.as_slice() == binding.transition_key().as_slice()
                && binding_checksum.as_slice()
                    == hash_domain(BINDING_CHECKSUM_DOMAIN_V0, &[&binding_record]).as_slice(),
            "PoCO preparation transition row checksum/key mismatch"
        );
        ensure!(
            binding_records
                .insert(binding.transition_key(), binding_record)
                .is_none(),
            "duplicate decoded PoCO preparation transition binding"
        );
    }

    let mut preparations = connection.prepare(
        "SELECT transition_key, block_kind, height_be, view_be,
                preparation_record, preparation_checksum,
                bound_record, bound_checksum, phase
         FROM preparations
         ORDER BY transition_key, block_kind, height_be, view_be",
    )?;
    let mut rows = preparations.query([])?;
    while let Some(row) = rows.next()? {
        let transition_key: Vec<u8> = row.get(0)?;
        let block_kind: i64 = row.get(1)?;
        let height: Vec<u8> = row.get(2)?;
        let view: Vec<u8> = row.get(3)?;
        let preparation_record: Vec<u8> = row.get(4)?;
        let preparation_checksum: Vec<u8> = row.get(5)?;
        let bound_record: Option<Vec<u8>> = row.get(6)?;
        let bound_checksum: Option<Vec<u8>> = row.get(7)?;
        let phase: i64 = row.get(8)?;
        let preparation =
            PocoCheckpointPreparationReplayRecordV0::decode_exact(&preparation_record)?;
        let slot = preparation.slot();
        let canonical_binding = preparation.binding.canonical_bytes()?;
        ensure!(
            transition_key.as_slice() == slot.transition_key.as_slice()
                && block_kind == i64::from(slot.block_kind)
                && height.as_slice() == slot.height.get().to_be_bytes().as_slice()
                && view.as_slice() == slot.view.get().to_be_bytes().as_slice()
                && preparation_checksum.as_slice()
                    == hash_domain(PREPARATION_CHECKSUM_DOMAIN_V0, &[&preparation_record])
                        .as_slice()
                && binding_records
                    .get(&slot.transition_key)
                    .is_some_and(|stored| stored == &canonical_binding),
            "PoCO preparation slot row checksum/key mismatch"
        );
        match (phase, bound_record, bound_checksum) {
            (0, None, None) => {}
            (1, Some(bound_record), Some(bound_checksum)) => {
                ensure!(
                    bound_checksum.as_slice()
                        == hash_domain(BOUND_CHECKSUM_DOMAIN_V0, &[&bound_record]).as_slice(),
                    "PoCO bound preparation checksum mismatch"
                );
                PocoCheckpointBoundReplayRecordV0::decode_exact(&bound_record, &preparation)?;
            }
            _ => bail!("PoCO preparation phase/bound record mismatch"),
        }
    }

    let halt_count: i64 =
        connection.query_row("SELECT COUNT(*) FROM safety_halt", [], |row| row.get(0))?;
    ensure!(halt_count <= 1, "multiple PoCO preparation halt rows");
    Ok(())
}

fn validate_canonical_schema(connection: &Connection) -> Result<()> {
    let canonical = Connection::open_in_memory()?;
    canonical.execute_batch(JOURNAL_SCHEMA_SQL)?;
    let expected = journal_schema_objects(&canonical)?;
    let actual = journal_schema_objects(connection)?;
    ensure!(
        actual == expected,
        "PoCO preparation journal schema differs from the canonical allowlist"
    );
    Ok(())
}

fn journal_schema_objects(connection: &Connection) -> Result<BTreeMap<(String, String), String>> {
    let mut objects = BTreeMap::new();
    let mut statement = connection.prepare(
        "SELECT type, name, sql
         FROM sqlite_schema
         WHERE name NOT LIKE 'sqlite_%'
         ORDER BY type, name",
    )?;
    let rows = statement.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, Option<String>>(2)?,
        ))
    })?;
    for row in rows {
        let (kind, name, sql) = row?;
        let sql = sql
            .context("PoCO preparation journal schema object has no CREATE statement")?
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ");
        ensure!(
            objects.insert((kind, name), sql).is_none(),
            "PoCO preparation journal has a duplicate schema object"
        );
    }
    Ok(objects)
}

fn validate_metadata(connection: &Connection) -> Result<()> {
    let mut statement = connection.prepare("SELECT key, value FROM metadata ORDER BY key")?;
    let rows = statement.query_map([], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
    })?;
    let metadata = rows.collect::<rusqlite::Result<BTreeMap<_, _>>>()?;
    ensure!(
        metadata.len() == 2
            && metadata.get("schema_version").map(String::as_str) == Some(JOURNAL_SCHEMA_VERSION)
            && metadata.contains_key("journal_id"),
        "PoCO preparation journal metadata differs from the canonical allowlist"
    );
    read_journal_id(connection)?;
    Ok(())
}

fn validate_schema_version(connection: &Connection) -> Result<()> {
    let schema: Option<String> = connection
        .query_row(
            "SELECT value FROM metadata WHERE key='schema_version'",
            [],
            |row| row.get(0),
        )
        .optional()
        .context("read PoCO preparation journal schema version")?;
    ensure!(
        schema.as_deref() == Some(JOURNAL_SCHEMA_VERSION),
        "unsupported or missing PoCO preparation journal schema version"
    );
    Ok(())
}

fn read_journal_id(connection: &Connection) -> Result<[u8; 32]> {
    let encoded: Option<String> = connection
        .query_row(
            "SELECT value FROM metadata WHERE key='journal_id'",
            [],
            |row| row.get(0),
        )
        .optional()
        .context("read PoCO preparation journal identity")?;
    let encoded = encoded.context("missing PoCO preparation journal identity")?;
    ensure!(
        encoded.len() == 64,
        "PoCO preparation journal identity is not 32-byte hex"
    );
    let decoded = hex::decode(&encoded).context("decode PoCO preparation journal identity")?;
    let journal_id: [u8; 32] = decoded
        .try_into()
        .map_err(|_| anyhow!("PoCO preparation journal identity is not 32 bytes"))?;
    ensure!(
        journal_id != [0; 32] && hex::encode(journal_id) == encoded,
        "PoCO preparation journal identity is zero or non-canonical"
    );
    Ok(journal_id)
}

fn validate_transaction_environment(
    transaction: &Transaction<'_>,
    shared: &PocoPreparationJournalSharedStateV0,
) -> Result<()> {
    let result = (|| {
        validate_canonical_schema(transaction)?;
        validate_metadata(transaction)?;
        ensure!(
            read_journal_id(transaction)? == shared.journal_id,
            "PoCO preparation journal identity changed inside write transaction"
        );
        Ok(())
    })();
    if result.is_err() {
        shared.sticky_halt.store(true, Ordering::Release);
    }
    result
}

fn ensure_not_halted(transaction: &Transaction<'_>, sticky_halt: &AtomicBool) -> Result<()> {
    ensure!(
        !sticky_halt.load(Ordering::Acquire),
        "PoCO preparation journal is sticky-halted"
    );
    if transaction
        .query_row(
            "SELECT 1 FROM safety_halt WHERE singleton=1",
            [],
            |_| Ok(()),
        )
        .optional()?
        .is_some()
    {
        sticky_halt.store(true, Ordering::Release);
        bail!("PoCO preparation journal is durably halted");
    }
    Ok(())
}

fn ensure_not_halted_connection(connection: &Connection, sticky_halt: &AtomicBool) -> Result<()> {
    ensure!(
        !sticky_halt.load(Ordering::Acquire),
        "PoCO preparation journal is sticky-halted"
    );
    if durable_halt_present(connection)? {
        sticky_halt.store(true, Ordering::Release);
        bail!("PoCO preparation journal is durably halted");
    }
    Ok(())
}

fn durable_halt_present(connection: &Connection) -> Result<bool> {
    Ok(connection
        .query_row(
            "SELECT 1 FROM safety_halt WHERE singleton=1",
            [],
            |_| Ok(()),
        )
        .optional()?
        .is_some())
}

fn commit_halt<T>(
    transaction: Transaction<'_>,
    sticky_halt: &AtomicBool,
    reason: &'static str,
    conflict_parts: &[&[u8]],
) -> Result<T> {
    // The in-memory halt is set before touching SQLite. If the durable write
    // or commit itself fails (disk full, I/O error, lost filesystem), every
    // independently opened handle registered for this file in this process
    // still fails closed for the remainder of its life. Cross-process signing
    // remains a separate signer-journal boundary and is not authorized here.
    sticky_halt.store(true, Ordering::Release);
    let conflict_checksum = hash_domain(CONFLICT_CHECKSUM_DOMAIN_V0, conflict_parts);
    let inserted = transaction.execute(
        "INSERT OR IGNORE INTO safety_halt(singleton, reason, conflict_checksum)
         VALUES (1, ?1, ?2)",
        params![reason, conflict_checksum.as_slice()],
    )?;
    ensure!(
        inserted == 1,
        "PoCO preparation halt insertion did not affect one row"
    );
    let readback: (String, Vec<u8>) = transaction.query_row(
        "SELECT reason, conflict_checksum FROM safety_halt WHERE singleton=1",
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    ensure!(
        readback.0 == reason && readback.1.as_slice() == conflict_checksum.as_slice(),
        "PoCO preparation halt readback differs from requested halt"
    );
    transaction.commit()?;
    bail!("{reason}; PoCO preparation journal durably halted")
}

fn sync_parent_directory(path: &Path) -> Result<()> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    File::open(parent)
        .with_context(|| format!("open journal parent directory {}", parent.display()))?
        .sync_all()
        .with_context(|| format!("sync journal parent directory {}", parent.display()))
}

struct ReplayEncoder {
    bytes: Vec<u8>,
}

impl ReplayEncoder {
    fn new() -> Self {
        Self { bytes: Vec::new() }
    }

    fn u8(&mut self, value: u8) {
        self.bytes.push(value);
    }

    fn u16(&mut self, value: u16) {
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }

    fn u32(&mut self, value: u32) {
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }

    fn u64(&mut self, value: u64) {
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }

    fn fixed(&mut self, value: &[u8; 32]) {
        self.bytes.extend_from_slice(value);
    }

    fn bytes(&mut self, value: &[u8]) -> Result<()> {
        ensure!(
            value.len() <= MAX_REPLAY_FIELD_BYTES,
            "replay field exceeds storage bound"
        );
        self.u32(u32::try_from(value.len()).context("replay field length exceeds u32")?);
        self.bytes.extend_from_slice(value);
        Ok(())
    }

    fn bytes_list(&mut self, values: &[Vec<u8>]) -> Result<()> {
        ensure!(
            values.len() <= MAX_REPLAY_LIST_ITEMS,
            "replay list exceeds storage bound"
        );
        self.u32(u32::try_from(values.len()).context("replay list length exceeds u32")?);
        for value in values {
            self.bytes(value)?;
        }
        Ok(())
    }

    fn finish(self) -> Result<Vec<u8>> {
        ensure!(
            !self.bytes.is_empty() && self.bytes.len() <= MAX_REPLAY_RECORD_BYTES,
            "replay record is empty or exceeds storage bound"
        );
        Ok(self.bytes)
    }
}

struct ReplayDecoder<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> ReplayDecoder<'a> {
    fn new(bytes: &'a [u8]) -> Result<Self> {
        ensure!(
            !bytes.is_empty() && bytes.len() <= MAX_REPLAY_RECORD_BYTES,
            "replay record is empty or exceeds storage bound"
        );
        Ok(Self { bytes, offset: 0 })
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8]> {
        let end = self
            .offset
            .checked_add(length)
            .context("replay decoder offset overflow")?;
        ensure!(end <= self.bytes.len(), "truncated replay record");
        let value = &self.bytes[self.offset..end];
        self.offset = end;
        Ok(value)
    }

    fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_be_bytes(self.take(2)?.try_into().unwrap()))
    }

    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().unwrap()))
    }

    fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_be_bytes(self.take(8)?.try_into().unwrap()))
    }

    fn fixed32(&mut self) -> Result<[u8; 32]> {
        Ok(self.take(32)?.try_into().unwrap())
    }

    fn bytes(&mut self) -> Result<Vec<u8>> {
        let length = usize::try_from(self.u32()?).context("replay field length exceeds usize")?;
        ensure!(
            length <= MAX_REPLAY_FIELD_BYTES,
            "replay field exceeds storage bound"
        );
        Ok(self.take(length)?.to_vec())
    }

    fn bytes_list(&mut self) -> Result<Vec<Vec<u8>>> {
        let count = usize::try_from(self.u32()?).context("replay list count exceeds usize")?;
        ensure!(
            count <= MAX_REPLAY_LIST_ITEMS,
            "replay list exceeds storage bound"
        );
        let mut values = Vec::with_capacity(count);
        for _ in 0..count {
            values.push(self.bytes()?);
        }
        Ok(values)
    }

    fn finish(&self) -> Result<()> {
        ensure!(
            self.offset == self.bytes.len(),
            "trailing bytes in replay record"
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::{
        sync::{atomic::AtomicU64, Barrier},
        time::{SystemTime, UNIX_EPOCH},
    };

    use super::*;
    use serde_json::Value;
    use trnm_consensus_types::{decode_finality_proof_v0_exact, BlockHeader};

    static TEST_DIRECTORY_SEQUENCE: AtomicU64 = AtomicU64::new(0);
    const CHECKPOINT_HANDOFF_VECTOR: &str = include_str!(
        "../../../../docs/protocol/poco-bft-v0/vectors/poco-authenticated-checkpoint-handoff-v0.json"
    );

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            let sequence = TEST_DIRECTORY_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let path = std::env::temp_dir().join(format!(
                "trnm-poco-preparation-journal-{}-{now}-{sequence}",
                std::process::id()
            ));
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }

        fn join(&self, value: &str) -> PathBuf {
            self.0.join(value)
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn vector_hex(value: &Value, path: &[&str]) -> Vec<u8> {
        let value = path
            .iter()
            .fold(value, |value, field| &value[*field])
            .as_str()
            .unwrap();
        hex::decode(value).unwrap()
    }

    fn vector_hash(value: &Value, path: &[&str]) -> [u8; 32] {
        vector_hex(value, path).try_into().unwrap()
    }

    fn fixture(view: u64) -> PocoCheckpointPreparationReplayRecordV0 {
        let vector: Value = serde_json::from_str(CHECKPOINT_HANDOFF_VECTOR).unwrap();
        let scenario = &vector["positive"];
        let old_validator_set_cev0 =
            vector_hex(scenario, &["preheader", "old_validator_set_cev0_hex"]);
        let old_parameters_cev0 = vector_hex(scenario, &["preheader", "old_parameters_cev0_hex"]);
        let new_validator_set_cev0 =
            vector_hex(scenario, &["preheader", "new_validator_set_cev0_hex"]);
        let new_parameters_cev0 = vector_hex(scenario, &["preheader", "new_parameters_cev0_hex"]);
        let commitment_cev0 = vector_hex(scenario, &["preheader", "commitment_cev0_hex"]);
        let old_validator_set = decode_validator_set_v0_exact(&old_validator_set_cev0).unwrap();
        let old_parameters = decode_consensus_parameters_v0_exact(&old_parameters_cev0).unwrap();
        let new_validator_set = decode_validator_set_v0_exact(&new_validator_set_cev0).unwrap();
        let new_parameters = decode_consensus_parameters_v0_exact(&new_parameters_cev0).unwrap();
        let commitment = decode_next_epoch_commitment_v0_exact(&commitment_cev0).unwrap();
        let cutoff_parent_cev0 =
            vector_hex(scenario, &["cutoff", "raw_cutoff_parent_header_cev0_hex"]);
        let cutoff_parent = decode_block_header_v0_exact(&cutoff_parent_cev0).unwrap();
        let raw_h1 = vector_hex(scenario, &["cutoff", "raw_h1_finality_proof_cev0_hex"]);
        let h1 = decode_finality_proof_v0_exact(
            &raw_h1,
            &old_validator_set,
            &old_parameters,
            cutoff_parent.timestamp_ms(),
        )
        .unwrap();
        let parent = h1.grandchild().header().clone();
        let certified_parent_cev0 = h1.grandchild().try_cev0_bytes().unwrap();
        assert_eq!(
            parent.try_cev0_bytes().unwrap(),
            vector_hex(
                scenario,
                &["preheader", "checkpoint_parent_header_cev0_hex"]
            )
        );
        let checkpoint_header =
            decode_block_header_v0_exact(&vector_hex(scenario, &["checkpoint", "header_cev0_hex"]))
                .unwrap();
        let cutoff_height = Height::new(scenario["cutoff"]["height"].as_u64().unwrap());
        let cutoff_state_root =
            StateRoot::new(vector_hash(scenario, &["cutoff", "state_root_hex"]));
        let cutoff_entries_root = vector_hash(scenario, &["cutoff", "entries_root_hex"]);
        let cutoff_entry_count =
            u32::try_from(scenario["cutoff"]["entry_count"].as_u64().unwrap()).unwrap();
        let scheduled_cutoff = PocoScheduledCutoffAuthorizationPreimageV0 {
            genesis_hash: old_validator_set.genesis_hash(),
            chain_id: old_validator_set.chain_id(),
            protocol_profile_hash: *old_parameters.hash().as_bytes(),
            protocol_version: old_validator_set.protocol_version(),
            epoch: old_validator_set.epoch(),
            checkpoint_height: checkpoint_header.height(),
            cutoff_height,
            cutoff_state_root,
            cutoff_entries_root,
            cutoff_entry_count,
            old_validator_set_id: old_validator_set.id(),
            old_parameters_hash: old_parameters.hash(),
        };
        let binding = PocoPreparationTransitionBindingV0 {
            genesis_hash: parent.genesis_hash(),
            chain_id: parent.chain_id(),
            protocol_version: parent.protocol_version(),
            old_epoch: parent.epoch(),
            checkpoint_height: checkpoint_header.height(),
            cutoff_height,
            cutoff_state_root,
            cutoff_entries_root,
            cutoff_entry_count,
            old_validator_set_id: parent.validator_set_id(),
            old_parameters_hash: parent.consensus_parameters_hash(),
            new_validator_set_id: new_validator_set.id(),
            new_parameters_hash: new_parameters.hash(),
            commitment_hash: commitment.id(),
            scheduled_cutoff_authorization_id: scheduled_cutoff.authorization_id().unwrap(),
            commitment_authorization_id: vector_hash(
                scenario,
                &["preheader", "authorization_id_hex"],
            ),
            scheduled_cutoff_canonical_bytes: scheduled_cutoff.canonical_bytes().unwrap(),
            old_validator_set_cev0,
            old_parameters_cev0,
            new_validator_set_cev0,
            new_parameters_cev0,
            commitment_cev0,
        };
        let leader_index = usize::try_from(
            view.saturating_sub(1) % u64::try_from(old_validator_set.validators().len()).unwrap(),
        )
        .unwrap();
        let fields = PocoCheckpointPreparationReplayFieldsV0 {
            genesis_hash: checkpoint_header.genesis_hash(),
            chain_id: checkpoint_header.chain_id(),
            protocol_version: checkpoint_header.protocol_version(),
            epoch: checkpoint_header.epoch(),
            view: View::new(view),
            height: checkpoint_header.height(),
            parent_id: parent.id(),
            proposer_id: old_validator_set.validators()[leader_index].id(),
            validator_set_id: checkpoint_header.validator_set_id(),
            consensus_parameters_hash: checkpoint_header.consensus_parameters_hash(),
            payload_root: checkpoint_header.payload_root(),
            state_root: checkpoint_header.state_root(),
            receipts_root: checkpoint_header.receipts_root(),
            evidence_root: checkpoint_header.evidence_root(),
            timestamp_ms: checkpoint_header.timestamp_ms(),
            next_epoch_commitment_hash: commitment.id(),
            transaction_count: 0,
            evidence_count: 0,
        };
        let native_execution_authorization_id = vector_hash(
            scenario,
            &["checkpoint", "native_execution_authorization_id_hex"],
        );
        let preparation_id = poco_checkpoint_preparation_authorization_id_v0(
            binding.commitment_authorization_id,
            native_execution_authorization_id,
            &certified_parent_cev0,
            &fields,
        );
        PocoCheckpointPreparationReplayRecordV0::new(
            binding,
            fields,
            preparation_id,
            native_execution_authorization_id,
            parent.try_cev0_bytes().unwrap(),
            certified_parent_cev0,
            vector_hex(scenario, &["checkpoint", "application_payload_cev0_hex"]),
            Vec::new(),
            Vec::new(),
        )
        .unwrap()
    }

    fn bound_fixture(
        record: &PocoCheckpointPreparationReplayRecordV0,
    ) -> PocoCheckpointBoundReplayRecordV0 {
        let fields = record.fields();
        let header = BlockHeader::new(
            fields.genesis_hash,
            fields.chain_id,
            fields.protocol_version,
            fields.epoch,
            fields.view,
            fields.height,
            BlockKind::EpochCheckpoint,
            fields.parent_id,
            fields.proposer_id,
            fields.validator_set_id,
            fields.consensus_parameters_hash,
            fields.payload_root,
            fields.state_root,
            fields.receipts_root,
            fields.evidence_root,
            fields.timestamp_ms,
            Some(fields.next_epoch_commitment_hash),
        )
        .unwrap();
        let bytes = header.try_cev0_bytes().unwrap();
        let authorization_id = poco_checkpoint_header_authorization_id_v0(
            record.preparation_id(),
            &bytes,
            header.id(),
        );
        PocoCheckpointBoundReplayRecordV0::new(bytes, header.id(), authorization_id).unwrap()
    }

    fn replace_preparation_record(path: &Path, record: &[u8]) {
        let checksum = hash_domain(PREPARATION_CHECKSUM_DOMAIN_V0, &[record]);
        let connection = Connection::open(path).unwrap();
        assert_eq!(
            connection
                .execute(
                    "UPDATE preparations
                     SET preparation_record=?1, preparation_checksum=?2",
                    params![record, checksum.as_slice()],
                )
                .unwrap(),
            1
        );
    }

    fn replace_bound_preparation_records(
        path: &Path,
        preparation: &PocoCheckpointPreparationReplayRecordV0,
        bound: &PocoCheckpointBoundReplayRecordV0,
    ) {
        let preparation_record = preparation.storage_bytes().unwrap();
        let preparation_checksum =
            hash_domain(PREPARATION_CHECKSUM_DOMAIN_V0, &[&preparation_record]);
        let bound_record = bound.storage_bytes().unwrap();
        let bound_checksum = hash_domain(BOUND_CHECKSUM_DOMAIN_V0, &[&bound_record]);
        let connection = Connection::open(path).unwrap();
        assert_eq!(
            connection
                .execute(
                    "UPDATE preparations
                     SET preparation_record=?1, preparation_checksum=?2,
                         bound_record=?3, bound_checksum=?4, phase=1",
                    params![
                        preparation_record,
                        preparation_checksum.as_slice(),
                        bound_record,
                        bound_checksum.as_slice(),
                    ],
                )
                .unwrap(),
            1
        );
    }

    fn substitute_cutoff_entries_root(
        record: &mut PocoCheckpointPreparationReplayRecordV0,
        root: [u8; 32],
    ) {
        record.binding.cutoff_entries_root = root;
        let mut scheduled = PocoScheduledCutoffAuthorizationPreimageV0::decode_exact(
            &record.binding.scheduled_cutoff_canonical_bytes,
        )
        .unwrap();
        scheduled.cutoff_entries_root = root;
        record.binding.scheduled_cutoff_authorization_id = scheduled.authorization_id().unwrap();
        record.binding.scheduled_cutoff_canonical_bytes = scheduled.canonical_bytes().unwrap();
    }

    #[test]
    fn restart_reserve_and_bind_are_idempotent() {
        let directory = TestDirectory::new();
        let path = directory.join("preparation.sqlite3");
        let record = fixture(31);
        let bound = bound_fixture(&record);
        let journal = PocoPreparationJournalV0::open(&path).unwrap();
        let reservation = journal.reserve(&record).unwrap();
        journal.bind(&reservation, &bound).unwrap();
        drop(journal);

        let reopened = PocoPreparationJournalV0::open(&path).unwrap();
        assert_eq!(
            reopened.replay_records().unwrap(),
            vec![PocoCheckpointPreparationReplayViewV0 {
                record: record.clone()
            }]
        );
        let reservation = reopened.reserve(&record).unwrap();
        reopened.bind(&reservation, &bound).unwrap();
        assert!(!reopened.is_halted().unwrap());
    }

    #[test]
    fn same_slot_conflict_durably_halts() {
        let directory = TestDirectory::new();
        let path = directory.join("preparation.sqlite3");
        let journal = PocoPreparationJournalV0::open(&path).unwrap();
        let independent = PocoPreparationJournalV0::open(&path).unwrap();
        assert!(Arc::ptr_eq(&journal.shared, &independent.shared));
        let record = fixture(31);
        journal.reserve(&record).unwrap();
        let mut conflict = record.clone();
        conflict.fields.timestamp_ms = conflict.fields.timestamp_ms.checked_add(1).unwrap();
        conflict.preparation_id = poco_checkpoint_preparation_authorization_id_v0(
            conflict.binding.commitment_authorization_id,
            conflict.native_execution_authorization_id,
            &conflict.certified_checkpoint_parent_cev0,
            &conflict.fields,
        );
        assert!(journal.reserve(&conflict).is_err());
        assert!(journal.is_halted().unwrap());
        assert!(independent.is_halted().unwrap());
        assert!(independent.reserve(&record).is_err());
        drop(journal);

        let reopened = PocoPreparationJournalV0::open(&path).unwrap();
        assert!(reopened.is_halted().unwrap());
        assert!(reopened.reserve(&record).is_err());
    }

    #[test]
    fn concurrent_independent_opens_share_one_journal_identity() {
        let directory = TestDirectory::new();
        let path = directory.join("preparation.sqlite3");
        let barrier = Arc::new(Barrier::new(4));
        let mut handles = Vec::new();
        for _ in 0..4 {
            let path = path.clone();
            let barrier = Arc::clone(&barrier);
            handles.push(std::thread::spawn(move || {
                barrier.wait();
                let journal = PocoPreparationJournalV0::open(path).unwrap();
                (journal.shared.journal_id, journal.path().to_path_buf())
            }));
        }
        let opened = handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect::<Vec<_>>();
        assert!(opened.windows(2).all(|pair| pair[0] == pair[1]));
    }

    #[test]
    fn higher_view_is_allowed_under_the_same_transition_binding() {
        let directory = TestDirectory::new();
        let journal =
            PocoPreparationJournalV0::open(directory.join("preparation.sqlite3")).unwrap();
        journal.reserve(&fixture(31)).unwrap();
        journal.reserve(&fixture(32)).unwrap();
        assert_eq!(journal.replay_records().unwrap().len(), 2);
        assert!(!journal.is_halted().unwrap());
    }

    #[test]
    fn transition_binding_splice_durably_halts_even_at_higher_view() {
        let directory = TestDirectory::new();
        let path = directory.join("preparation.sqlite3");
        let journal = PocoPreparationJournalV0::open(&path).unwrap();
        journal.reserve(&fixture(31)).unwrap();
        let mut splice = fixture(32);
        substitute_cutoff_entries_root(&mut splice, [32; 32]);
        assert!(journal.reserve(&splice).is_err());
        assert!(journal.is_halted().unwrap());
        drop(journal);
        assert!(PocoPreparationJournalV0::open(path)
            .unwrap()
            .is_halted()
            .unwrap());
    }

    #[test]
    fn conflicting_bound_header_durably_halts() {
        let directory = TestDirectory::new();
        let path = directory.join("preparation.sqlite3");
        let journal = PocoPreparationJournalV0::open(&path).unwrap();
        let record = fixture(31);
        let reservation = journal.reserve(&record).unwrap();
        journal.bind(&reservation, &bound_fixture(&record)).unwrap();
        let mut other = bound_fixture(&record);
        other.header_authorization_id = [33; 32];
        assert!(journal.bind(&reservation, &other).is_err());
        assert!(journal.is_halted().unwrap());
    }

    #[test]
    fn corrupt_and_future_schema_databases_fail_closed() {
        let directory = TestDirectory::new();
        let corrupt = directory.join("corrupt.sqlite3");
        fs::write(&corrupt, b"not a sqlite database").unwrap();
        assert!(PocoPreparationJournalV0::open(corrupt).is_err());

        let future = directory.join("future.sqlite3");
        drop(PocoPreparationJournalV0::open(&future).unwrap());
        let connection = Connection::open(&future).unwrap();
        connection
            .execute(
                "UPDATE metadata SET value='2' WHERE key='schema_version'",
                [],
            )
            .unwrap();
        drop(connection);
        assert!(PocoPreparationJournalV0::open(future).is_err());
    }

    #[test]
    fn checksum_consistent_semantic_payload_corruption_fails_closed() {
        let directory = TestDirectory::new();
        let path = directory.join("semantic-payload.sqlite3");
        let record = fixture(31);
        let journal = PocoPreparationJournalV0::open(&path).unwrap();
        journal.reserve(&record).unwrap();
        drop(journal);

        let mut corrupt = record;
        corrupt.payload_cev0.push(0);
        replace_preparation_record(&path, &corrupt.storage_bytes().unwrap());
        assert!(PocoPreparationJournalV0::open(path).is_err());
    }

    #[test]
    fn checksum_and_preparation_id_consistent_root_corruption_fails_closed() {
        let directory = TestDirectory::new();
        let path = directory.join("semantic-root.sqlite3");
        let record = fixture(31);
        let journal = PocoPreparationJournalV0::open(&path).unwrap();
        journal.reserve(&record).unwrap();
        drop(journal);

        let mut corrupt = record;
        corrupt.fields.receipts_root = ReceiptsRoot::new([35; 32]);
        corrupt.preparation_id = poco_checkpoint_preparation_authorization_id_v0(
            corrupt.binding.commitment_authorization_id,
            corrupt.native_execution_authorization_id,
            &corrupt.certified_checkpoint_parent_cev0,
            &corrupt.fields,
        );
        replace_preparation_record(&path, &corrupt.storage_bytes().unwrap());
        assert!(PocoPreparationJournalV0::open(path).is_err());
    }

    #[test]
    fn checksum_and_preparation_id_consistent_state_and_native_id_corruption_fails_closed() {
        let directory = TestDirectory::new();
        let path = directory.join("semantic-state-native-seal.sqlite3");
        let record = fixture(31);
        let journal = PocoPreparationJournalV0::open(&path).unwrap();
        let reservation = journal.reserve(&record).unwrap();
        journal.bind(&reservation, &bound_fixture(&record)).unwrap();
        drop(journal);

        let mut corrupt = record;
        corrupt.fields.state_root = StateRoot::new([36; 32]);
        corrupt.native_execution_authorization_id = [37; 32];
        corrupt.preparation_id = poco_checkpoint_preparation_authorization_id_v0(
            corrupt.binding.commitment_authorization_id,
            corrupt.native_execution_authorization_id,
            &corrupt.certified_checkpoint_parent_cev0,
            &corrupt.fields,
        );
        let corrupt_bound = bound_fixture(&corrupt);
        replace_bound_preparation_records(&path, &corrupt, &corrupt_bound);
        assert!(PocoPreparationJournalV0::open(path).is_err());
    }

    #[test]
    fn checksum_consistent_embedded_binding_substitution_fails_closed() {
        let directory = TestDirectory::new();
        let path = directory.join("embedded-binding.sqlite3");
        let record = fixture(31);
        let journal = PocoPreparationJournalV0::open(&path).unwrap();
        journal.reserve(&record).unwrap();
        drop(journal);

        let mut substituted = record;
        substitute_cutoff_entries_root(&mut substituted, [34; 32]);
        let bytes = substituted.storage_bytes().unwrap();
        replace_preparation_record(&path, &bytes);
        assert!(PocoPreparationJournalV0::open(path).is_err());
    }

    #[test]
    fn extra_schema_objects_and_live_trigger_drift_fail_closed() {
        let directory = TestDirectory::new();
        let trigger_path = directory.join("trigger.sqlite3");
        drop(PocoPreparationJournalV0::open(&trigger_path).unwrap());
        let connection = Connection::open(&trigger_path).unwrap();
        connection
            .execute_batch(
                "CREATE TRIGGER erase_preparation_halt
                 AFTER INSERT ON safety_halt
                 BEGIN
                    DELETE FROM safety_halt WHERE singleton=NEW.singleton;
                 END;",
            )
            .unwrap();
        drop(connection);
        assert!(PocoPreparationJournalV0::open(&trigger_path).is_err());

        let live_path = directory.join("live.sqlite3");
        let first = PocoPreparationJournalV0::open(&live_path).unwrap();
        let second = PocoPreparationJournalV0::open(&live_path).unwrap();
        let connection = Connection::open(&live_path).unwrap();
        connection
            .execute_batch("CREATE TABLE unexpected_schema_drift(value INTEGER) STRICT;")
            .unwrap();
        drop(connection);
        assert!(first.reserve(&fixture(31)).is_err());
        assert!(first.is_halted().unwrap());
        assert!(second.is_halted().unwrap());
    }

    #[test]
    fn failed_halt_persistence_sticky_halts_independent_handles() {
        let directory = TestDirectory::new();
        let path = directory.join("preparation.sqlite3");
        let first = PocoPreparationJournalV0::open(&path).unwrap();
        let second = PocoPreparationJournalV0::open(&path).unwrap();
        let mut connection = Connection::open_in_memory().unwrap();
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap();
        let result: Result<()> = commit_halt(
            transaction,
            &first.shared.sticky_halt,
            "synthetic halt persistence failure",
            &[b"conflict"],
        );
        assert!(result.is_err());
        assert!(first.is_halted().unwrap());
        assert!(second.is_halted().unwrap());
        drop(first);
        drop(second);
        let reopened = PocoPreparationJournalV0::open(&path).unwrap();
        assert!(reopened.is_halted().unwrap());
    }

    #[test]
    fn cross_sidecar_reservation_and_file_replacement_fail_closed() {
        let directory = TestDirectory::new();
        let left_path = directory.join("left.sqlite3");
        let right_path = directory.join("right.sqlite3");
        let replacement_path = directory.join("replacement.sqlite3");
        let left = PocoPreparationJournalV0::open(&left_path).unwrap();
        let independent_left = PocoPreparationJournalV0::open(&left_path).unwrap();
        let right = PocoPreparationJournalV0::open(&right_path).unwrap();
        let record = fixture(31);
        let reservation = left.reserve(&record).unwrap();
        assert!(right.bind(&reservation, &bound_fixture(&record)).is_err());

        drop(PocoPreparationJournalV0::open(&replacement_path).unwrap());
        let displaced_path = directory.join("displaced.sqlite3");
        fs::rename(&left_path, &displaced_path).unwrap();
        fs::rename(&replacement_path, &left_path).unwrap();
        assert!(left.reserve(&record).is_err());
        assert!(left.is_halted().unwrap());
        assert!(independent_left.is_halted().unwrap());
    }

    #[cfg(unix)]
    #[test]
    fn symlink_alias_reuses_the_same_process_state() {
        use std::os::unix::fs::symlink;

        let directory = TestDirectory::new();
        let path = directory.join("preparation.sqlite3");
        let alias = directory.join("preparation-alias.sqlite3");
        let first = PocoPreparationJournalV0::open(&path).unwrap();
        symlink(&path, &alias).unwrap();
        let second = PocoPreparationJournalV0::open(&alias).unwrap();
        assert!(Arc::ptr_eq(&first.shared, &second.shared));
        assert_eq!(first.path(), second.path());
    }

    #[test]
    fn sidecar_path_is_independent_from_state_and_application_store() {
        let state = Path::new("/tmp/trnm-app-state.json");
        let app_store = state.with_extension("json.sqlite3");
        let sidecar = poco_preparation_sidecar_path_v0(state);
        assert_ne!(sidecar, state);
        assert_ne!(sidecar, app_store);
        assert_eq!(
            sidecar,
            Path::new("/tmp/trnm-app-state.json.poco-preparation.sqlite3")
        );
    }
}
