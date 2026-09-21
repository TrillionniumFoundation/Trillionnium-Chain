//! Journal10 consumes exact codec2 provenance and an actual immediate source
//! owner. It persists comparison facts only; no ACK, signer or live Core API.
#[path = "epoch_journal_record_storage_v3.rs"]
mod record_storage;
#[path = "epoch_journal_v3.rs"]
pub(crate) mod v3;
use record_storage::RecordStorageV3;

use crate::epoch_journal_physical_v2::{
    JournalBoundsV2, JournalLayoutV2, PhysicalJournalErrorV2, PhysicalJournalV2,
};
use crate::epoch_preparation_sqlite_v1::EpochPreparationStoreErrorV1;
use crate::{
    decode_transition_context_v0_exact, encode_transition_context_v0,
    validate_transition_context_against_state_v0, EpochJournalErrorV1, EpochSafetyHeadPinV1,
    EpochSafetyJournalProfileV1, OldEpochSafetyHeadPinV1, OldEpochSafetyJournalProfileV1,
    SafetyStoreErrorV0, SafetyTransitionContextV0, SqliteEpochSafetyJournalV1,
    SqliteOldEpochSafetyJournalV1,
};
use rusqlite::{params, Connection};
use sha2::{Digest, Sha256};
use std::{
    path::{Path, PathBuf},
    sync::Arc,
};
use trnm_consensus_core::{
    decode_epoch_safety_record_v1_exact, decode_epoch_safety_record_v2_exact,
    decode_old_epoch_boundary_safety_record_v1_exact, encode_epoch_safety_record_parts_v2,
    encode_epoch_safety_record_v1, encode_epoch_safety_record_v2,
    encode_old_epoch_boundary_safety_record_v1, epoch_safety_record_context_ref_v1,
    epoch_safety_record_context_ref_v2, old_epoch_boundary_record_context_ref_v1, Core, CoreConfig,
    CoreError, EpochCoreStateV1, EpochSafetyRecordPartsV2, EpochSafetyStateRecordContextV1,
    EpochSafetyStateRecordContextV2, PreparedEpochCoreActivationV2, SafetyState,
    SafetyStatePersistenceBindingV0, SafetyStatePersistenceV0, SafetyStateRecordContextV0,
    SafetyStateRecordErrorV0, SafetyStateRecordLimitsV0, StrictEpochCoreRecoveryV1,
    StrictEpochCoreRecoveryV2, StrictOldEpochTerminalRecoveryV1, UnverifiedSafetyStateRecordV0,
};
use trnm_consensus_crypto::StrictEd25519Verifier;
use trnm_consensus_types::{
    Cev0AdmissionBudgetV0, MAX_CEV0_INTRINSIC_SIGNATURE_WORK_UNITS_V0, MAX_CEV0_ROOT_BYTES_V0,
    MAX_CEV0_TC_AGGREGATE_SIGNATURE_SHARES,
};

const MAX_RECORD: usize = 256 * 1024 * 1024;
const MAX_CONTEXT: usize = 1024 * 1024;

#[derive(Debug)]
pub enum EpochJournalErrorV2 {
    Namespace(EpochPreparationStoreErrorV1),
    Sqlite(rusqlite::Error),
    Source(SafetyStoreErrorV0),
    OldJournal(crate::OldEpochJournalErrorV1),
    Journal9(EpochJournalErrorV1),
    Record(SafetyStateRecordErrorV0),
    Core(CoreError),
    Invalid(&'static str),
    Fenced,
}
impl std::fmt::Display for EpochJournalErrorV2 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "epoch journal10: {self:?}")
    }
}
impl std::error::Error for EpochJournalErrorV2 {}
macro_rules! convert {
    ($source:ty, $variant:ident) => {
        impl From<$source> for EpochJournalErrorV2 {
            fn from(error: $source) -> Self {
                Self::$variant(error)
            }
        }
    };
}
convert!(EpochPreparationStoreErrorV1, Namespace);
convert!(rusqlite::Error, Sqlite);
convert!(SafetyStoreErrorV0, Source);
convert!(crate::OldEpochJournalErrorV1, OldJournal);
convert!(EpochJournalErrorV1, Journal9);
convert!(SafetyStateRecordErrorV0, Record);
convert!(CoreError, Core);
impl From<PhysicalJournalErrorV2> for EpochJournalErrorV2 {
    fn from(error: PhysicalJournalErrorV2) -> Self {
        match error {
            PhysicalJournalErrorV2::Namespace(e) => Self::Namespace(e),
            PhysicalJournalErrorV2::Sqlite(e) => Self::Sqlite(e),
            PhysicalJournalErrorV2::Invalid(e) => Self::Invalid(e),
            PhysicalJournalErrorV2::Fenced => Self::Fenced,
        }
    }
}
type Result<T> = std::result::Result<T, EpochJournalErrorV2>;
fn invalid<T>(reason: &'static str) -> Result<T> {
    Err(EpochJournalErrorV2::Invalid(reason))
}
fn digest(domain: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(domain);
    for part in parts {
        hash.update((part.len() as u64).to_be_bytes());
        hash.update(part);
    }
    hash.finalize().into()
}
fn recovery_budget() -> Cev0AdmissionBudgetV0 {
    Cev0AdmissionBudgetV0::with_limits(
        MAX_CEV0_ROOT_BYTES_V0,
        MAX_CEV0_INTRINSIC_SIGNATURE_WORK_UNITS_V0,
        MAX_CEV0_TC_AGGREGATE_SIGNATURE_SHARES,
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EpochSafetySourceKindV2 {
    Journal8,
    Journal9,
    Journal10,
}
impl EpochSafetySourceKindV2 {
    const fn tag(self) -> u8 {
        match self {
            Self::Journal8 => 0,
            Self::Journal9 => 1,
            Self::Journal10 => 2,
        }
    }
}
/// Flat immediate-source description. The earlier journal profile is committed
/// by reference, never recursively copied into each later profile/SQLite row.
#[derive(Debug, Clone)]
struct SourceDescriptorV2 {
    kind: EpochSafetySourceKindV2,
    config: CoreConfig,
    limits: SafetyStateRecordLimitsV0,
    generation: u64,
    profile_ref: [u8; 32],
    verifier_ref: [u8; 32],
    epoch: Option<EpochCoreStateV1>,
}
enum SourceContextV2<'a> {
    Old(Box<SafetyStateRecordContextV0<'a>>),
    Legacy(Box<EpochSafetyStateRecordContextV1<'a>>),
    Full(Box<EpochSafetyStateRecordContextV2<'a>>),
}
enum SourceRecoveryV2 {
    Old(Box<StrictOldEpochTerminalRecoveryV1>),
    Legacy(Box<StrictEpochCoreRecoveryV1>),
    Full(Box<StrictEpochCoreRecoveryV2>),
}
impl SourceRecoveryV2 {
    fn prepare(
        &self,
        target: &EpochSafetyStateRecordContextV2<'_>,
    ) -> Result<PreparedEpochCoreActivationV2> {
        Ok(match self {
            Self::Old(old) => old.prepare_epoch_activation_v2(target)?,
            Self::Legacy(old) => old.prepare_next_epoch_v2(target)?,
            Self::Full(old) => old.prepare_next_epoch_v2(target)?,
        })
    }
}
impl SourceDescriptorV2 {
    fn context(&self) -> Result<SourceContextV2<'_>> {
        Ok(match self.kind {
            EpochSafetySourceKindV2::Journal8 => {
                if self.epoch.is_some() {
                    return invalid("journal8 source has epoch provenance");
                }
                SourceContextV2::Old(Box::new(SafetyStateRecordContextV0::new(
                    &self.config,
                    self.verifier_ref,
                    self.limits,
                )?))
            }
            EpochSafetySourceKindV2::Journal9 => {
                let epoch = self
                    .epoch
                    .as_ref()
                    .ok_or(EpochJournalErrorV2::Invalid("missing source epoch"))?;
                if epoch.preparation_record_v2().is_some() {
                    return invalid("journal9 source is not codec1");
                }
                SourceContextV2::Legacy(Box::new(EpochSafetyStateRecordContextV1::new(
                    &self.config,
                    epoch.strict_context()?,
                    epoch.checkpoint_artifact(),
                    self.generation,
                    self.limits,
                )?))
            }
            EpochSafetySourceKindV2::Journal10 => {
                let epoch = self
                    .epoch
                    .as_ref()
                    .ok_or(EpochJournalErrorV2::Invalid("missing source epoch"))?;
                SourceContextV2::Full(Box::new(EpochSafetyStateRecordContextV2::new(
                    &self.config,
                    epoch.recover_preparation_v2(&mut recovery_budget())?,
                    epoch.checkpoint_artifact(),
                    self.generation,
                    self.limits,
                )?))
            }
        })
    }
}
impl SourceContextV2<'_> {
    fn context_ref(&self) -> Result<[u8; 32]> {
        Ok(match self {
            Self::Old(c) => old_epoch_boundary_record_context_ref_v1(c)?,
            Self::Legacy(c) => epoch_safety_record_context_ref_v1(c)?,
            Self::Full(c) => epoch_safety_record_context_ref_v2(c)?,
        })
    }
    fn encode(&self, state: &SafetyState) -> Result<Vec<u8>> {
        Ok(match self {
            Self::Old(c) => encode_old_epoch_boundary_safety_record_v1(state, c)?,
            Self::Legacy(c) => encode_epoch_safety_record_v1(state, c)?,
            Self::Full(c) => encode_epoch_safety_record_v2(state, c)?,
        })
    }
    fn decode(&self, bytes: &[u8]) -> Result<UnverifiedSafetyStateRecordV0> {
        Ok(match self {
            Self::Old(c) => decode_old_epoch_boundary_safety_record_v1_exact(bytes, c)?,
            Self::Legacy(c) => decode_epoch_safety_record_v1_exact(bytes, c)?,
            Self::Full(c) => decode_epoch_safety_record_v2_exact(bytes, c)?,
        })
    }
    fn recover(
        &self,
        record: &UnverifiedSafetyStateRecordV0,
        generation: u64,
    ) -> Result<SourceRecoveryV2> {
        let checksum = record.record_checksum();
        Ok(match self {
            Self::Old(c) => SourceRecoveryV2::Old(Box::new(
                Core::prepare_old_epoch_terminal_recovery_v1(record, c, checksum, generation)?,
            )),
            Self::Legacy(c) => SourceRecoveryV2::Legacy(Box::new(Core::prepare_epoch_recovery_v1(
                record, c, checksum,
            )?)),
            Self::Full(c) => SourceRecoveryV2::Full(Box::new(Core::prepare_epoch_recovery_v2(
                record, c, checksum,
            )?)),
        })
    }
}

#[derive(Debug, Clone)]
pub struct EpochSafetyJournalProfileV2 {
    storage: RecordStorageV3,
    config: CoreConfig,
    limits: SafetyStateRecordLimitsV0,
    epoch: EpochCoreStateV1,
    source: SourceDescriptorV2,
    generation: u64,
    max_db: u64,
    max_row: usize,
    binding: [u8; 32],
}
impl EpochSafetyJournalProfileV2 {
    pub fn from_journal8_v2(
        source: &OldEpochSafetyJournalProfileV1,
        target: &EpochSafetyStateRecordContextV2<'_>,
    ) -> Result<Self> {
        let context = source.context()?;
        Self::new(
            SourceDescriptorV2 {
                kind: EpochSafetySourceKindV2::Journal8,
                config: context.core_config().clone(),
                limits: context.limits(),
                generation: source.owner_generation_v1(),
                profile_ref: source.profile_ref_v1(),
                verifier_ref: context.verifier_profile_ref(),
                epoch: None,
            },
            target,
        )
    }
    pub fn from_journal9_v2(
        source: &EpochSafetyJournalProfileV1,
        target: &EpochSafetyStateRecordContextV2<'_>,
    ) -> Result<Self> {
        let context = source.context()?;
        Self::new(
            SourceDescriptorV2 {
                kind: EpochSafetySourceKindV2::Journal9,
                config: context.core_config().clone(),
                limits: context.limits(),
                generation: source.owner_generation_v1(),
                profile_ref: source.profile_ref_v1(),
                verifier_ref: [0; 32],
                epoch: Some(context.epoch().clone()),
            },
            target,
        )
    }
    pub fn from_journal10_v2(
        source: &Self,
        target: &EpochSafetyStateRecordContextV2<'_>,
    ) -> Result<Self> {
        Self::new(
            SourceDescriptorV2 {
                kind: EpochSafetySourceKindV2::Journal10,
                config: source.config.clone(),
                limits: source.limits,
                generation: source.generation,
                profile_ref: source.binding,
                verifier_ref: [0; 32],
                epoch: Some(source.epoch.clone()),
            },
            target,
        )
    }
    fn new(
        source: SourceDescriptorV2,
        context: &EpochSafetyStateRecordContextV2<'_>,
    ) -> Result<Self> {
        let activation = context.runtime().activation();
        if source.config.validator_set() != activation.old_validator_set()
            || source.config.consensus_parameters() != activation.old_consensus_parameters()
            || source.config.local_validator() != context.core_config().local_validator()
            || source.generation.checked_add(1) != Some(context.epoch().owner_generation())
            || source.profile_ref == [0; 32]
            || context.epoch().preparation_record_v2().is_none()
            || source.limits.maximum_record_bytes() > MAX_RECORD
            || context.limits().maximum_record_bytes() > MAX_RECORD
        {
            return invalid("source/target profile or capacity mismatch");
        }
        let limits = context.limits();
        let max_row = limits
            .maximum_record_bytes()
            .max(source.limits.maximum_record_bytes())
            .checked_add(MAX_CONTEXT)
            .ok_or(EpochJournalErrorV2::Invalid("row capacity overflow"))?;
        max_row
            .checked_add(4096)
            .and_then(|n| i32::try_from(n).ok())
            .ok_or(EpochJournalErrorV2::Invalid("SQLite row capacity"))?;
        let max_db = (limits.maximum_record_bytes() as u64)
            .checked_mul(6)
            .and_then(|n| {
                n.checked_add(source.limits.maximum_record_bytes() as u64 * 2 + 16 * 1024 * 1024)
            })
            .ok_or(EpochJournalErrorV2::Invalid("database capacity"))?;
        let generation = context.epoch().owner_generation();
        let storage = RecordStorageV3::Full;
        let binding = digest(
            storage.profile_domain(),
            &[
                &[source.kind.tag()],
                &source.profile_ref,
                &source.context()?.context_ref()?,
                &epoch_safety_record_context_ref_v2(context)?,
                &generation.to_be_bytes(),
                &(max_row as u64).to_be_bytes(),
                &max_db.to_be_bytes(),
            ],
        );
        Ok(Self {
            storage,
            config: context.core_config().clone(),
            limits,
            epoch: context.epoch().clone(),
            source,
            generation,
            max_db,
            max_row,
            binding,
        })
    }
    fn context(&self) -> Result<EpochSafetyStateRecordContextV2<'_>> {
        Ok(EpochSafetyStateRecordContextV2::new(
            &self.config,
            self.epoch.recover_preparation_v2(&mut recovery_budget())?,
            self.epoch.checkpoint_artifact(),
            self.generation,
            self.limits,
        )?)
    }
    pub const fn owner_generation_v2(&self) -> u64 {
        self.generation
    }
    pub const fn profile_ref_v2(&self) -> [u8; 32] {
        self.binding
    }
    pub fn context_ref_v2(&self) -> Result<[u8; 32]> {
        Ok(epoch_safety_record_context_ref_v2(&self.context()?)?)
    }
    pub const fn source_kind_v2(&self) -> EpochSafetySourceKindV2 {
        self.source.kind
    }
    fn bounds(&self) -> JournalBoundsV2 {
        JournalBoundsV2 {
            max_row: self.max_row,
            max_db: self.max_db,
        }
    }
    fn check_state(&self, state: &SafetyState) -> Result<()> {
        if state.epoch_state_v1() != Some(&self.epoch) {
            return invalid("epoch state context mismatch");
        }
        Core::validate_persisted_state_v0(&self.config, state, &StrictEd25519Verifier)?;
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EpochSafetyHeadPinV2 {
    pub journal_id: [u8; 32],
    pub revision: u64,
    pub chain_checksum: [u8; 32],
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EpochSafetySourcePinV2 {
    pub kind: EpochSafetySourceKindV2,
    pub journal_id: [u8; 32],
    pub revision: u64,
    pub chain_checksum: [u8; 32],
}
#[doc(hidden)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EpochJournalCutV2 {
    AfterWriteBeforeCommit,
    AfterCommitBeforeSync,
    AfterSyncBeforeReadback,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EpochSafetyMigrationSourceV2 {
    pin: EpochSafetySourcePinV2,
    record_checksum: [u8; 32],
    context_ref: [u8; 32],
    profile_ref: [u8; 32],
    initial_revision: u64,
}
impl EpochSafetyMigrationSourceV2 {
    pub const fn pin_v2(&self) -> EpochSafetySourcePinV2 {
        self.pin
    }
    pub const fn state_record_checksum_v2(&self) -> [u8; 32] {
        self.record_checksum
    }
    pub const fn context_ref_v2(&self) -> [u8; 32] {
        self.context_ref
    }
    pub const fn profile_ref_v2(&self) -> [u8; 32] {
        self.profile_ref
    }
    pub const fn initial_revision_v2(&self) -> u64 {
        self.initial_revision
    }
}

/// The source is an actual open journal owner, never a caller-created receipt.
pub enum EpochSafetySourceOwnerV2<'a> {
    Journal8(&'a SqliteOldEpochSafetyJournalV1, OldEpochSafetyHeadPinV1),
    Journal9(&'a SqliteEpochSafetyJournalV1, EpochSafetyHeadPinV1),
    Journal10(&'a SqliteEpochSafetyJournalV2, EpochSafetyHeadPinV2),
}
struct SourceReadV2 {
    state: Box<SafetyState>,
    transition: SafetyTransitionContextV0,
    pin: EpochSafetySourcePinV2,
    record_checksum: [u8; 32],
    context_ref: [u8; 32],
    profile_ref: [u8; 32],
    generation: u64,
    path: PathBuf,
    recovery: SourceRecoveryV2,
}
impl EpochSafetySourceOwnerV2<'_> {
    fn read(&self) -> Result<SourceReadV2> {
        match self {
            Self::Journal8(owner, pin) => {
                let (head, recovery) = owner.prepare_terminal_recovery_v1(*pin)?;
                if !head.belongs_to_store_at_path_v1(owner, owner.path_v1()) {
                    return invalid("foreign source8 owner");
                }
                Ok(SourceReadV2 {
                    state: Box::new(head.state_v1().clone()),
                    transition: head.transition_context_v1().clone(),
                    pin: EpochSafetySourcePinV2 {
                        kind: EpochSafetySourceKindV2::Journal8,
                        journal_id: pin.journal_id,
                        revision: pin.revision,
                        chain_checksum: pin.chain_checksum,
                    },
                    record_checksum: head.state_record_checksum_v1(),
                    context_ref: head.context_ref_v1(),
                    profile_ref: owner.immutable_profile_ref_v1(),
                    generation: head.owner_generation_v1(),
                    path: owner.path_v1().to_path_buf(),
                    recovery: SourceRecoveryV2::Old(Box::new(recovery)),
                })
            }
            Self::Journal9(owner, pin) => {
                let (head, recovery) = owner.prepare_recovery_v1(*pin)?;
                if !head.belongs_to_store_at_path_v1(owner, owner.path_v1()) {
                    return invalid("foreign source9 owner");
                }
                Ok(SourceReadV2 {
                    state: Box::new(head.state_v1().clone()),
                    transition: head.transition_context_v1().clone(),
                    pin: EpochSafetySourcePinV2 {
                        kind: EpochSafetySourceKindV2::Journal9,
                        journal_id: pin.journal_id,
                        revision: pin.revision,
                        chain_checksum: pin.chain_checksum,
                    },
                    record_checksum: head.state_record_checksum_v1(),
                    context_ref: head.context_ref_v1(),
                    profile_ref: owner.immutable_profile_ref_v1(),
                    generation: head.owner_generation_v1(),
                    path: owner.path_v1().to_path_buf(),
                    recovery: SourceRecoveryV2::Legacy(Box::new(recovery)),
                })
            }
            Self::Journal10(owner, pin) => {
                let (head, recovery) = owner.prepare_recovery_v2(*pin)?;
                if !head.belongs_to_store_at_path_v2(owner, owner.path_v2()) {
                    return invalid("foreign source10 owner");
                }
                Ok(SourceReadV2 {
                    state: Box::new(head.state_v2().clone()),
                    transition: head.transition_context_v2().clone(),
                    pin: EpochSafetySourcePinV2 {
                        kind: EpochSafetySourceKindV2::Journal10,
                        journal_id: pin.journal_id,
                        revision: pin.revision,
                        chain_checksum: pin.chain_checksum,
                    },
                    record_checksum: head.state_record_checksum_v2(),
                    context_ref: head.context_ref_v2(),
                    profile_ref: owner.profile.binding,
                    generation: head.owner_generation_v2(),
                    path: owner.path_v2().to_path_buf(),
                    recovery: SourceRecoveryV2::Full(Box::new(recovery)),
                })
            }
        }
    }
}

/// Non-Clone fresh owner comparison facts. No method acknowledges Core work.
pub struct ConfirmedEpochSafetyHeadV2 {
    record: Box<UnverifiedSafetyStateRecordV0>,
    transition: SafetyTransitionContextV0,
    pin: EpochSafetyHeadPinV2,
    context_ref: [u8; 32],
    generation: u64,
    origin: [u8; 32],
    source: EpochSafetyMigrationSourceV2,
    owner: Arc<()>,
}
impl ConfirmedEpochSafetyHeadV2 {
    pub fn state_v2(&self) -> &SafetyState {
        self.record.state()
    }
    pub const fn revision_v2(&self) -> u64 {
        self.pin.revision
    }
    pub fn state_record_checksum_v2(&self) -> [u8; 32] {
        self.record.record_checksum()
    }
    pub const fn chain_checksum_v2(&self) -> [u8; 32] {
        self.pin.chain_checksum
    }
    pub const fn journal_id_v2(&self) -> [u8; 32] {
        self.pin.journal_id
    }
    pub const fn context_ref_v2(&self) -> [u8; 32] {
        self.context_ref
    }
    pub const fn owner_generation_v2(&self) -> u64 {
        self.generation
    }
    pub const fn pin_v2(&self) -> EpochSafetyHeadPinV2 {
        self.pin
    }
    pub const fn transition_context_v2(&self) -> &SafetyTransitionContextV0 {
        &self.transition
    }
    pub const fn migration_source_v2(&self) -> &EpochSafetyMigrationSourceV2 {
        &self.source
    }
    pub fn into_unverified_record_v2(self) -> UnverifiedSafetyStateRecordV0 {
        *self.record
    }
    pub fn belongs_to_store_at_path_v2(
        &self,
        store: &SqliteEpochSafetyJournalV2,
        path: &Path,
    ) -> bool {
        Arc::ptr_eq(&self.owner, &store.owner)
            && store.path_v2() == path
            && store.fresh_read_v2(self.pin).is_ok_and(|fresh| {
                fresh.state_record_checksum_v2() == self.state_record_checksum_v2()
                    && fresh.transition_context_v2() == self.transition_context_v2()
            })
    }
}

pub struct SqliteEpochSafetyJournalV2 {
    physical: PhysicalJournalV2,
    profile: EpochSafetyJournalProfileV2,
    owner: Arc<()>,
    binding: Option<SafetyStatePersistenceBindingV0>,
}
impl SqliteEpochSafetyJournalV2 {
    pub fn initialize_from_source_v2(
        path: impl AsRef<Path>,
        profile: EpochSafetyJournalProfileV2,
        source: EpochSafetySourceOwnerV2<'_>,
        prepared: &PreparedEpochCoreActivationV2,
    ) -> Result<(Self, ConfirmedEpochSafetyHeadV2)> {
        Self::initialize_with_observer_v2(path, profile, source, prepared, |_, _| Ok(()))
    }
    #[doc(hidden)]
    pub fn initialize_with_observer_v2(
        path: impl AsRef<Path>,
        profile: EpochSafetyJournalProfileV2,
        source: EpochSafetySourceOwnerV2<'_>,
        prepared: &PreparedEpochCoreActivationV2,
        mut observer: impl FnMut(EpochJournalCutV2, EpochSafetyHeadPinV2) -> Result<()>,
    ) -> Result<(Self, ConfirmedEpochSafetyHeadV2)> {
        let actual = source.read()?;
        let source_context = profile.source.context()?;
        let target_context = profile.context()?;
        if actual.pin.kind != profile.source.kind
            || actual.profile_ref != profile.source.profile_ref
            || actual.context_ref != source_context.context_ref()?
            || actual.generation != profile.source.generation
            || prepared.predecessor() != actual.state.as_ref()
            || prepared.config() != &profile.config
        {
            return invalid("activation source owner/profile/context/predecessor mismatch");
        }
        let independent = actual.recovery.prepare(&target_context)?;
        let request = prepared.initial_persistence_v2();
        let binding = prepared.persistence_binding_v2();
        if !binding.accepts(request)
            || request.state() != prepared.state()
            || prepared.state() != independent.state()
            || request.barrier() != independent.initial_persistence_v2().barrier()
        {
            return invalid("activation request differs from exact terminal successor");
        }
        profile.check_state(request.state())?;
        let source_record = source_context.encode(&actual.state)?;
        if source_context.decode(&source_record)?.record_checksum() != actual.record_checksum {
            return invalid("source exact record");
        }
        let source_transition = encode_transition_context_v0(&actual.transition)?;
        if source_transition.len() > MAX_CONTEXT {
            return invalid("source transition capacity");
        }
        let record = encode_epoch_safety_record_parts_v2(request.state(), &target_context)?;
        let transition = SafetyTransitionContextV0::Ordinary;
        validate_request_manifest(request, &transition)?;
        validate_transition_context_against_state_v0(&transition, request.state())?;
        let transition_bytes = encode_transition_context_v0(&transition)?;
        drop(source_context);
        drop(target_context);
        let physical = PhysicalJournalV2::create_new(
            path.as_ref(),
            profile.storage.layout(),
            profile.binding,
            profile.bounds(),
            Some(&actual.path),
        )?;
        let journal_id = physical.journal_id();
        let revision = request.state().revision();
        let origin = origin_hash(
            &profile,
            journal_id,
            actual.pin.journal_id,
            actual.pin.chain_checksum,
            &source_record,
            &source_transition,
            revision,
        );
        let chain = chain_hash(
            profile.storage,
            origin,
            origin,
            revision,
            record.record_bytes(),
            &transition_bytes,
        );
        let expected = EpochSafetyHeadPinV2 {
            journal_id,
            revision,
            chain_checksum: chain,
        };
        let mut store = Self {
            physical,
            profile,
            owner: Arc::new(()),
            binding: Some(binding),
        };
        {
            let tx = store.physical.immediate_transaction()?;
            store.profile.storage.layout().initialize_schema(&tx)?;
            store.profile.storage.initialize_prefix(&tx, &record)?;
            tx.execute("INSERT INTO epoch_metadata(singleton,journal,profile,source_kind,source_journal,source_chain,source_record,source_transition,origin,first_revision) VALUES(1,?1,?2,?3,?4,?5,?6,?7,?8,?9)",
                params![journal_id.as_slice(), store.profile.binding.as_slice(), actual.pin.kind.tag(),
                    actual.pin.journal_id.as_slice(), actual.pin.chain_checksum.as_slice(), source_record,
                    source_transition, origin.as_slice(), revision])?;
            store.profile.storage.insert_record(
                &tx,
                (revision, origin, chain),
                &record,
                &transition_bytes,
            )?;
            tx.execute(
                "INSERT INTO epoch_head VALUES(1,?1,?2)",
                params![revision, chain.as_slice()],
            )?;
            observer(EpochJournalCutV2::AfterWriteBeforeCommit, expected)?;
            tx.commit()?;
        }
        observer(EpochJournalCutV2::AfterCommitBeforeSync, expected)?;
        store.physical.close_and_sync()?;
        observer(EpochJournalCutV2::AfterSyncBeforeReadback, expected)?;
        let after = source.read()?;
        if after.pin != actual.pin
            || after.state != actual.state
            || after.transition != actual.transition
            || after.record_checksum != actual.record_checksum
            || after.profile_ref != actual.profile_ref
            || after.context_ref != actual.context_ref
            || after.generation != actual.generation
            || after.path != actual.path
        {
            return invalid("source changed during explicit migration");
        }
        let confirmed = store.fresh_read_v2(expected)?;
        Ok((store, confirmed))
    }
    pub fn open_existing_v2(
        path: impl AsRef<Path>,
        profile: EpochSafetyJournalProfileV2,
        expected: EpochSafetyHeadPinV2,
    ) -> Result<Self> {
        let physical = PhysicalJournalV2::open_existing(
            path.as_ref(),
            profile.storage.layout(),
            profile.binding,
            profile.bounds(),
            expected.journal_id,
        )?;
        let store = Self {
            physical,
            profile,
            owner: Arc::new(()),
            binding: None,
        };
        store.fresh_read_v2(expected)?;
        Ok(store)
    }
    pub fn path_v2(&self) -> &Path {
        self.physical.path()
    }
    pub fn fresh_read_v2(
        &self,
        expected: EpochSafetyHeadPinV2,
    ) -> Result<ConfirmedEpochSafetyHeadV2> {
        self.physical.require_namespace()?;
        let connection = self.physical.open_read_connection()?;
        let result = self.read_head(&connection, expected);
        self.physical.close_read_connection(connection)?;
        result
    }
    pub fn prepare_recovery_v2(
        &self,
        expected: EpochSafetyHeadPinV2,
    ) -> Result<(ConfirmedEpochSafetyHeadV2, StrictEpochCoreRecoveryV2)> {
        let confirmed = self.fresh_read_v2(expected)?;
        let recovery = Core::prepare_epoch_recovery_v2(
            &confirmed.record,
            &self.profile.context()?,
            confirmed.state_record_checksum_v2(),
        )?;
        self.physical.require_namespace()?;
        Ok((confirmed, recovery))
    }

    /// Default-off trusted-host plumbing for the exact initial codec2 cut.
    /// Both actual reads precede installing the sole new process affinity.
    /// The returned driver still waits for its initial ACK; M15 must join
    /// native state, retired/new custody and the independent external cut
    /// before supplying it. This method emits no ACK, callback or signature.
    #[cfg(feature = "candidate-epoch-host-v2")]
    pub fn prepare_candidate_host_initial_recovery_v2(
        &mut self,
        expected: EpochSafetyHeadPinV2,
    ) -> Result<(
        ConfirmedEpochSafetyHeadV2,
        trnm_consensus_core::PendingEpochHostDriverV2,
    )> {
        self.physical.require_namespace()?;
        if self.binding.is_some() {
            return invalid("journal already bound; recovery cannot duplicate a live driver");
        }
        let (confirmed, recovery) = self.prepare_recovery_v2(expected)?;
        if confirmed.revision_v2() != confirmed.source.initial_revision
            || confirmed.transition_context_v2() != &SafetyTransitionContextV0::ordinary()
        {
            return invalid("candidate epoch recovery supports only the exact initial cut");
        }
        let driver = recovery.into_candidate_host_initial_pending_v2()?;
        let request = driver.initial_persistence_v2();
        let binding = driver.persistence_binding_v2();
        if !driver.activation_persistence_pending_v2()
            || !binding.accepts(request)
            || driver.state() != confirmed.state_v2()
            || request.state() != confirmed.state_v2()
            || request.barrier().get() != confirmed.revision_v2()
        {
            return invalid("strict initial driver differs from fresh journal cut");
        }
        validate_request_manifest(request, confirmed.transition_context_v2())?;
        let fresh = self.fresh_read_v2(expected)?;
        if fresh.pin != confirmed.pin
            || fresh.state_v2() != confirmed.state_v2()
            || fresh.state_record_checksum_v2() != confirmed.state_record_checksum_v2()
            || fresh.transition != confirmed.transition
            || fresh.context_ref != confirmed.context_ref
            || fresh.generation != confirmed.generation
            || fresh.origin != confirmed.origin
            || fresh.source != confirmed.source
        {
            return invalid("journal changed during initial recovery binding");
        }
        self.binding = Some(binding);
        Ok((fresh, driver))
    }

    pub fn confirm_exact_request_v2(
        &self,
        expected: EpochSafetyHeadPinV2,
        request: &SafetyStatePersistenceV0,
        transition: &SafetyTransitionContextV0,
    ) -> Result<ConfirmedEpochSafetyHeadV2> {
        if !self
            .binding
            .as_ref()
            .is_some_and(|binding| binding.accepts(request))
        {
            return invalid("exact confirmation requires this journal's bound Core request");
        }
        validate_request_manifest(request, transition)?;
        let confirmed = self.fresh_read_v2(expected)?;
        if confirmed.state_v2() != request.state()
            || confirmed.revision_v2() != request.barrier().get()
            || confirmed.transition_context_v2() != transition
        {
            return invalid("fresh journal cut differs from exact Core request/manifest");
        }
        Ok(confirmed)
    }
    pub fn persist_exact_v2(
        &mut self,
        expected: EpochSafetyHeadPinV2,
        request: &SafetyStatePersistenceV0,
        transition: &SafetyTransitionContextV0,
    ) -> Result<ConfirmedEpochSafetyHeadV2> {
        self.persist_with_observer_v2(expected, request, transition, |_| Ok(()))
    }
    #[doc(hidden)]
    pub fn persist_with_observer_v2(
        &mut self,
        expected: EpochSafetyHeadPinV2,
        request: &SafetyStatePersistenceV0,
        transition: &SafetyTransitionContextV0,
        mut observer: impl FnMut(EpochJournalCutV2) -> Result<()>,
    ) -> Result<ConfirmedEpochSafetyHeadV2> {
        self.persist_with_pin_observer_v2(expected, request, transition, |cut, _pin| observer(cut))
    }
    /// Exposes the actual producer-calculated successor pin at each real
    /// transaction cut, for independently pinned crash reconciliation tests.
    /// Observing the pin neither confirms durability nor acknowledges Core.
    #[doc(hidden)]
    pub fn persist_with_pin_observer_v2(
        &mut self,
        expected: EpochSafetyHeadPinV2,
        request: &SafetyStatePersistenceV0,
        transition: &SafetyTransitionContextV0,
        mut observer: impl FnMut(EpochJournalCutV2, EpochSafetyHeadPinV2) -> Result<()>,
    ) -> Result<ConfirmedEpochSafetyHeadV2> {
        self.physical.require_namespace()?;
        if !self
            .binding
            .as_ref()
            .is_some_and(|binding| binding.accepts(request))
        {
            return invalid("journal is not bound to this live Core");
        }
        self.profile.check_state(request.state())?;
        validate_request_manifest(request, transition)?;
        validate_transition_context_against_state_v0(transition, request.state())?;
        let record =
            encode_epoch_safety_record_parts_v2(request.state(), &self.profile.context()?)?;
        let transition_bytes = encode_transition_context_v0(transition)?;
        if transition_bytes.len() > MAX_CONTEXT {
            return invalid("transition capacity");
        }
        let result = self.persist_inner(
            expected,
            request,
            transition,
            &record,
            &transition_bytes,
            &mut observer,
        );
        if result.is_err() {
            self.physical.fence();
        }
        result
    }
    fn persist_inner(
        &mut self,
        expected: EpochSafetyHeadPinV2,
        request: &SafetyStatePersistenceV0,
        transition: &SafetyTransitionContextV0,
        record: &EpochSafetyRecordPartsV2,
        transition_bytes: &[u8],
        observer: &mut impl FnMut(EpochJournalCutV2, EpochSafetyHeadPinV2) -> Result<()>,
    ) -> Result<ConfirmedEpochSafetyHeadV2> {
        let head = self.fresh_read_v2(expected)?;
        if head.state_v2() == request.state() && head.transition_context_v2() == transition {
            self.physical.close_and_sync()?;
            return self.fresh_read_v2(expected);
        }
        Core::validate_persisted_successor_v0(
            &self.profile.config,
            head.state_v2(),
            request.state(),
            &StrictEd25519Verifier,
        )?;
        if (head.state_v2().application_applied() != request.state().application_applied())
            != request.native_finalization_applied_v0().is_some()
        {
            return invalid("application watermark requires exact Core manifest");
        }
        if let Some(manifest) = request.native_finalization_applied_v0() {
            crate::sqlite::validate_native_finalization_applied_predecessor_v0(
                request.state().revision(),
                manifest,
                head.state_v2(),
                request.state(),
            )?;
        }
        let revision = request.state().revision();
        let chain = chain_hash(
            self.profile.storage,
            head.origin,
            expected.chain_checksum,
            revision,
            record.record_bytes(),
            transition_bytes,
        );
        let next = EpochSafetyHeadPinV2 {
            journal_id: self.physical.journal_id(),
            revision,
            chain_checksum: chain,
        };
        self.physical.open_writer()?;
        {
            let tx = self.physical.immediate_transaction()?;
            let active: (u64, [u8; 32]) = tx.query_row(
                "SELECT revision,chain FROM epoch_head WHERE singleton=1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )?;
            if active != (expected.revision, expected.chain_checksum) {
                return invalid("head changed before transaction");
            }
            self.profile.storage.insert_record(
                &tx,
                (revision, expected.chain_checksum, chain),
                record,
                transition_bytes,
            )?;
            if tx.execute("UPDATE epoch_head SET revision=?1,chain=?2 WHERE singleton=1 AND revision=?3 AND chain=?4", params![revision,chain.as_slice(),expected.revision,expected.chain_checksum.as_slice()])? != 1 { return invalid("head CAS"); }
            tx.execute(
                "DELETE FROM epoch_records WHERE revision < ?1",
                [expected.revision],
            )?;
            observer(EpochJournalCutV2::AfterWriteBeforeCommit, next)?;
            tx.commit()?;
        }
        observer(EpochJournalCutV2::AfterCommitBeforeSync, next)?;
        self.physical.close_and_sync()?;
        observer(EpochJournalCutV2::AfterSyncBeforeReadback, next)?;
        self.fresh_read_v2(next)
    }
    fn read_head(
        &self,
        c: &Connection,
        expected: EpochSafetyHeadPinV2,
    ) -> Result<ConfirmedEpochSafetyHeadV2> {
        self.physical.check_schema(c)?;
        self.profile
            .storage
            .screen_source(c, self.profile.source.limits.maximum_record_bytes())?;
        // Query scalar lengths before allocating untrusted persistent blobs.
        let sizes:(i64,i64)=c.query_row("SELECT length(source_record),length(source_transition) FROM epoch_metadata WHERE singleton=1",[],|r|Ok((r.get(0)?,r.get(1)?)))?;
        if sizes.0 <= 0
            || sizes.0 as u64 > self.profile.source.limits.maximum_record_bytes() as u64
            || sizes.1 <= 0
            || sizes.1 as usize > MAX_CONTEXT
        {
            return invalid("source blob bounds");
        }
        let m=c.query_row("SELECT journal,profile,source_journal,source_chain,source_record,source_transition,origin,first_revision,source_kind FROM epoch_metadata WHERE singleton=1",[],|r|Ok(Metadata{journal:r.get(0)?,profile:r.get(1)?,source_journal:r.get(2)?,source_chain:r.get(3)?,source_record:r.get(4)?,source_transition:r.get(5)?,origin:r.get(6)?,first_revision:r.get(7)?,source_kind:r.get(8)?}))?;
        if m.journal != self.physical.journal_id()
            || m.profile != self.profile.binding
            || m.source_kind != self.profile.source.kind.tag()
            || expected.journal_id != self.physical.journal_id()
            || m.origin
                != origin_hash(
                    &self.profile,
                    self.physical.journal_id(),
                    m.source_journal,
                    m.source_chain,
                    &m.source_record,
                    &m.source_transition,
                    m.first_revision,
                )
        {
            return invalid("metadata profile/source binding");
        }
        // Reconstruct each strict context once for this fresh snapshot, never
        // recursively open earlier journals or replace them with cached flags.
        let source_context = self.profile.source.context()?;
        let target_context = self.profile.context()?;
        let source = source_context.decode(&m.source_record)?;
        let source_recovery = source_context.recover(&source, self.profile.source.generation)?;
        let expected_initial = source_recovery.prepare(&target_context)?;
        let source_transition = decode_transition_context_v0_exact(&m.source_transition)?;
        validate_transition_context_against_state_v0(&source_transition, source.state())?;
        if source.state().revision().checked_add(1) != Some(m.first_revision) {
            return invalid("migration origin revision");
        }
        let head: (u64, [u8; 32]) = c.query_row(
            "SELECT revision,chain FROM epoch_head WHERE singleton=1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        if head != (expected.revision, expected.chain_checksum) || head.0 < m.first_revision {
            return invalid("active head differs from independently expected cut");
        }
        let count: i64 = c.query_row("SELECT count(*) FROM epoch_records", [], |r| r.get(0))?;
        if count != if head.0 == m.first_revision { 1 } else { 2 } {
            return invalid("retained record count");
        }
        let prefix = self.profile.storage.read_prefix(c, &target_context)?;
        let coordinates = self.profile.storage.coordinates(
            c,
            prefix.len(),
            self.profile.limits.maximum_record_bytes(),
        )?;
        let mut previous: Option<(UnverifiedSafetyStateRecordV0, [u8; 32])> = None;
        let mut result = None;
        for (index, (revision, predecessor, chain, record_len, context_len)) in
            coordinates.into_iter().enumerate()
        {
            if record_len <= 0
                || record_len as usize > self.profile.limits.maximum_record_bytes()
                || context_len <= 0
                || context_len as usize > MAX_CONTEXT
                || revision != head.0 - (count as u64 - 1) + index as u64
            {
                return invalid("retained record bounds or revision");
            }
            let (record_bytes, transition_bytes) =
                self.profile
                    .storage
                    .read_record(c, revision, &prefix, record_len as usize)?;
            if chain
                != chain_hash(
                    self.profile.storage,
                    m.origin,
                    predecessor,
                    revision,
                    &record_bytes,
                    &transition_bytes,
                )
            {
                return invalid("retained chain checksum");
            }
            let record = decode_epoch_safety_record_v2_exact(&record_bytes, &target_context)?;
            self.profile.check_state(record.state())?;
            self.profile.storage.verify_exact_parts(
                c,
                revision,
                record.state(),
                &target_context,
            )?;
            if record.state().revision() != revision {
                return invalid("record revision");
            }
            let transition = decode_transition_context_v0_exact(&transition_bytes)?;
            validate_transition_context_against_state_v0(&transition, record.state())?;
            if revision == m.first_revision {
                if predecessor != m.origin {
                    return invalid("migration predecessor");
                }
                if record.state() != expected_initial.state()
                    || transition != SafetyTransitionContextV0::Ordinary
                {
                    return invalid("initial epoch record differs from exact strict activation");
                }
            }
            if let Some((before, before_chain)) = &previous {
                if predecessor != *before_chain {
                    return invalid("retained predecessor link");
                }
                Core::validate_persisted_successor_v0(
                    &self.profile.config,
                    before.state(),
                    record.state(),
                    &StrictEd25519Verifier,
                )?;
                if (before.state().application_applied() != record.state().application_applied())
                    != transition
                        .native_finalization_applied_transition()
                        .is_some()
                {
                    return invalid("retained application watermark lacks context");
                }
                if let Some(facts) = transition.native_finalization_applied_transition() {
                    crate::sqlite::validate_persisted_native_finalization_applied_pair_v0(
                        facts,
                        before.state(),
                        record.state(),
                    )?;
                }
            }
            if revision == head.0 {
                if chain != head.1 {
                    return invalid("head chain differs from record");
                }
                result = Some(ConfirmedEpochSafetyHeadV2 {
                    record: Box::new(record.clone()),
                    transition,
                    pin: expected,
                    context_ref: epoch_safety_record_context_ref_v2(&target_context)?,
                    generation: self.profile.generation,
                    origin: m.origin,
                    source: EpochSafetyMigrationSourceV2 {
                        pin: EpochSafetySourcePinV2 {
                            kind: self.profile.source.kind,
                            journal_id: m.source_journal,
                            revision: source.state().revision(),
                            chain_checksum: m.source_chain,
                        },
                        record_checksum: source.record_checksum(),
                        context_ref: source_context.context_ref()?,
                        profile_ref: self.profile.source.profile_ref,
                        initial_revision: m.first_revision,
                    },
                    owner: Arc::clone(&self.owner),
                });
            }
            previous = Some((record, chain));
        }
        result.ok_or(EpochJournalErrorV2::Invalid("missing head record"))
    }
}
struct Metadata {
    journal: [u8; 32],
    profile: [u8; 32],
    source_kind: u8,
    source_journal: [u8; 32],
    source_chain: [u8; 32],
    source_record: Vec<u8>,
    source_transition: Vec<u8>,
    origin: [u8; 32],
    first_revision: u64,
}
fn origin_hash(
    profile: &EpochSafetyJournalProfileV2,
    journal: [u8; 32],
    source_journal: [u8; 32],
    source_chain: [u8; 32],
    source_record: &[u8],
    source_transition: &[u8],
    first_revision: u64,
) -> [u8; 32] {
    digest(
        profile.storage.origin_domain(),
        &[
            &profile.binding,
            &journal,
            &[profile.source.kind.tag()],
            &source_journal,
            &source_chain,
            source_record,
            source_transition,
            &first_revision.to_be_bytes(),
        ],
    )
}
fn chain_hash(
    storage: RecordStorageV3,
    origin: [u8; 32],
    previous: [u8; 32],
    revision: u64,
    record: &[u8],
    transition: &[u8],
) -> [u8; 32] {
    digest(
        storage.chain_domain(),
        &[
            &origin,
            &previous,
            &revision.to_be_bytes(),
            record,
            transition,
        ],
    )
}
fn validate_request_manifest(
    request: &SafetyStatePersistenceV0,
    transition: &SafetyTransitionContextV0,
) -> Result<()> {
    Ok(crate::epoch_journal_v1::validate_request_manifest(
        request, transition,
    )?)
}
