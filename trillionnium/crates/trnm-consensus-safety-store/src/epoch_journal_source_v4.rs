// Private source identities shared by the closed physical journal layouts.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PhysicalSourceKindV4 {
    Journal8,
    Journal9,
    Journal10,
    Journal11,
    Journal12,
}
impl PhysicalSourceKindV4 {
    const fn tag(self) -> u8 {
        match self {
            Self::Journal8 => 0,
            Self::Journal9 => 1,
            Self::Journal10 => 2,
            Self::Journal11 => 3,
            Self::Journal12 => 4,
        }
    }
    const fn legacy(self) -> Option<EpochSafetySourceKindV2> {
        match self {
            Self::Journal8 => Some(EpochSafetySourceKindV2::Journal8),
            Self::Journal9 => Some(EpochSafetySourceKindV2::Journal9),
            Self::Journal10 => Some(EpochSafetySourceKindV2::Journal10),
            Self::Journal11 | Self::Journal12 => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SourcePinV4 {
    kind: PhysicalSourceKindV4,
    journal_id: [u8; 32],
    revision: u64,
    chain_checksum: [u8; 32],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SourceFactsV4 {
    pin: SourcePinV4,
    record_checksum: [u8; 32],
    context_ref: [u8; 32],
    profile_ref: [u8; 32],
    initial_revision: u64,
    // Preserve the existing borrowed V2/V3 getter without reinterpreting a new
    // physical source as Journal10. Only legacy-layout constructors expose it.
    legacy: Option<EpochSafetyMigrationSourceV2>,
}
impl SourceFactsV4 {
    fn new(
        pin: SourcePinV4,
        record_checksum: [u8; 32],
        context_ref: [u8; 32],
        profile_ref: [u8; 32],
        initial_revision: u64,
    ) -> Self {
        let legacy = pin.kind.legacy().map(|kind| EpochSafetyMigrationSourceV2 {
            pin: EpochSafetySourcePinV2 {
                kind,
                journal_id: pin.journal_id,
                revision: pin.revision,
                chain_checksum: pin.chain_checksum,
            },
            record_checksum,
            context_ref,
            profile_ref,
            initial_revision,
        });
        Self {
            pin,
            record_checksum,
            context_ref,
            profile_ref,
            initial_revision,
            legacy,
        }
    }
}

enum SourceReaderV4<'a> {
    Legacy(EpochSafetySourceOwnerV2<'a>),
    Successor(v4::EpochSafetySourceOwnerV4<'a>),
}
impl SourceReaderV4<'_> {
    fn read(&self) -> Result<SourceReadV2> {
        match self {
            Self::Legacy(source) => source.read(),
            Self::Successor(source) => source.read(),
        }
    }
}
