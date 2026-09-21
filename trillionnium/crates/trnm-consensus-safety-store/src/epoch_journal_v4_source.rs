//! Exact physical source dispatch; no codec or schema fallback.
use super::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EpochSafetySourceKindV4 {
    Journal8,
    Journal9,
    Journal10,
    Journal11,
    Journal12,
}
impl EpochSafetySourceKindV4 {
    pub(super) const fn from_physical(kind: PhysicalSourceKindV4) -> Self {
        match kind {
            PhysicalSourceKindV4::Journal8 => Self::Journal8,
            PhysicalSourceKindV4::Journal9 => Self::Journal9,
            PhysicalSourceKindV4::Journal10 => Self::Journal10,
            PhysicalSourceKindV4::Journal11 => Self::Journal11,
            PhysicalSourceKindV4::Journal12 => Self::Journal12,
        }
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EpochSafetySourcePinV4 {
    pub kind: EpochSafetySourceKindV4,
    pub journal_id: [u8; 32],
    pub revision: u64,
    pub chain_checksum: [u8; 32],
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EpochSafetyMigrationSourceV4(SourceFactsV4);
impl EpochSafetyMigrationSourceV4 {
    pub(super) const fn from_facts(facts: SourceFactsV4) -> Self {
        Self(facts)
    }
    pub const fn pin_v4(&self) -> EpochSafetySourcePinV4 {
        EpochSafetySourcePinV4 {
            kind: EpochSafetySourceKindV4::from_physical(self.0.pin.kind),
            journal_id: self.0.pin.journal_id,
            revision: self.0.pin.revision,
            chain_checksum: self.0.pin.chain_checksum,
        }
    }
    pub const fn state_record_checksum_v4(&self) -> [u8; 32] {
        self.0.record_checksum
    }
    pub const fn context_ref_v4(&self) -> [u8; 32] {
        self.0.context_ref
    }
    pub const fn profile_ref_v4(&self) -> [u8; 32] {
        self.0.profile_ref
    }
    pub const fn initial_revision_v4(&self) -> u64 {
        self.0.initial_revision
    }
}

/// Independently pinned actual owners, including this same stable Journal12
/// format. No scalar or captured diagnostic carrier can replace a live owner.
pub enum EpochSafetySourceOwnerV4<'a> {
    Journal8(&'a SqliteOldEpochSafetyJournalV1, OldEpochSafetyHeadPinV1),
    Journal9(&'a SqliteEpochSafetyJournalV1, EpochSafetyHeadPinV1),
    Journal10(&'a SqliteEpochSafetyJournalV2, EpochSafetyHeadPinV2),
    Journal11(&'a v3::SqliteEpochSafetyJournalV3, v3::EpochSafetyHeadPinV3),
    Journal12(&'a SqliteEpochSafetyJournalV4, EpochSafetyHeadPinV4),
}
impl EpochSafetySourceOwnerV4<'_> {
    pub(in crate::epoch_journal_v2) fn read(&self) -> Result<SourceReadV2> {
        match self {
            Self::Journal8(owner, pin) => EpochSafetySourceOwnerV2::Journal8(owner, *pin).read(),
            Self::Journal9(owner, pin) => EpochSafetySourceOwnerV2::Journal9(owner, *pin).read(),
            Self::Journal10(owner, pin) => EpochSafetySourceOwnerV2::Journal10(owner, *pin).read(),
            Self::Journal11(owner, pin) => {
                // Capture grants no successor authority. The independent strict
                // recovery below still has to produce exactly PreparedNextV2.
                let capture = owner
                    .capture_successor_source_v3(*pin)
                    .map_err(|error| error.0)?;
                let read = read_prefix_source(
                    &owner.0,
                    EpochSafetyHeadPinV2 {
                        journal_id: pin.journal_id,
                        revision: pin.revision,
                        chain_checksum: pin.chain_checksum,
                    },
                    PhysicalSourceKindV4::Journal11,
                )?;
                if read.original_record.as_deref() != Some(capture.record_bytes_v3())
                    || read.state.as_ref() != capture.state_v3()
                    || read.record_checksum != capture.state_record_checksum_v3()
                    || read.transition != *capture.transition_context_v3()
                    || read.profile_ref != capture.profile_ref_v3()
                    || read.context_ref != capture.context_ref_v3()
                    || read.generation != capture.owner_generation_v3()
                    || read.origin != Some(capture.origin_ref_v3())
                    || !capture.belongs_to_store_at_path_v3(owner, owner.path_v3())
                {
                    return invalid(
                        "Journal11 capture changed before strict successor source read",
                    );
                }
                Ok(read)
            }
            Self::Journal12(owner, pin) => {
                read_prefix_source(&owner.0, pin.inner(), PhysicalSourceKindV4::Journal12)
            }
        }
    }
}

#[inline(never)]
fn read_prefix_source(
    owner: &SqliteEpochSafetyJournalV2,
    pin: EpochSafetyHeadPinV2,
    kind: PhysicalSourceKindV4,
) -> Result<SourceReadV2> {
    let storage = match kind {
        PhysicalSourceKindV4::Journal11 => RecordStorageV3::PrefixOnce,
        PhysicalSourceKindV4::Journal12 => RecordStorageV3::SuccessorPrefixOnce,
        _ => return invalid("prefix source physical discriminator"),
    };
    if owner.profile.storage != storage {
        return invalid("prefix source owner layout mismatch");
    }
    let (head, recovery) = owner.prepare_recovery_v2(pin)?;
    let context = owner.profile.context()?;
    let parts = encode_epoch_safety_record_parts_v2(head.state_v2(), &context)?;
    if parts.record_bytes().last_chunk::<32>() != Some(&head.state_record_checksum_v2())
        || head.state_v2() != recovery.state()
    {
        return invalid("prefix source canonical record/recovery mismatch");
    }
    drop(context);
    let fresh = owner.fresh_read_v2(pin)?;
    if fresh.pin != head.pin
        || fresh.state_v2() != head.state_v2()
        || fresh.state_record_checksum_v2() != head.state_record_checksum_v2()
        || fresh.transition != head.transition
        || fresh.context_ref != head.context_ref
        || fresh.generation != head.generation
        || fresh.origin != head.origin
        || fresh.source != head.source
        || !Arc::ptr_eq(&fresh.owner, &head.owner)
        || !Arc::ptr_eq(&head.owner, &owner.owner)
    {
        return invalid("prefix source changed between strict reads");
    }
    owner.physical.require_namespace()?;
    Ok(SourceReadV2 {
        state: Box::new(head.state_v2().clone()),
        transition: head.transition.clone(),
        pin: SourcePinV4 {
            kind,
            journal_id: pin.journal_id,
            revision: pin.revision,
            chain_checksum: pin.chain_checksum,
        },
        record_checksum: head.state_record_checksum_v2(),
        context_ref: head.context_ref,
        profile_ref: owner.profile.binding,
        generation: head.generation,
        path: owner.path_v2().to_path_buf(),
        recovery: SourceRecoveryV2::Full(Box::new(recovery)),
        original_record: Some(parts.into_bytes()),
        origin: Some(head.origin),
        owner: Some(Arc::clone(&head.owner)),
    })
}
