use crate::{
    WholeNodeCheckpointChecksumV1, WholeNodeCheckpointErrorV1, WholeNodeCheckpointGenerationV1,
    WholeNodeCheckpointPhaseV1, WholeNodeCheckpointResultV1, WholeNodeCheckpointScopeV1,
    WholeNodeCheckpointV1,
};

const CHECKPOINT_REF_MAGIC_V1: &[u8; 8] = b"TRNMWR01";

/// Frozen exact schema for the unique public whole-node checkpoint reference.
pub const WHOLE_NODE_CHECKPOINT_REF_SCHEMA_V1: u16 = 1;

/// Exact fixed length of one canonical reference.
pub const WHOLE_NODE_CHECKPOINT_REF_BYTES_V1: usize = 8 + 2 + 32 + 8 + 1 + 32 + 32;

/// Unique public cross-crate reference to one checkpoint record.
///
/// This type owns the `{scope, generation, phase, predecessor checksum,
/// checksum}` taxonomy shared by future consumers. It is data only: matching
/// a reference neither loads a record nor proves persistence, CAS application,
/// freshness, or authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct WholeNodeCheckpointRefV1 {
    scope: WholeNodeCheckpointScopeV1,
    generation: WholeNodeCheckpointGenerationV1,
    phase: WholeNodeCheckpointPhaseV1,
    predecessor_checksum: Option<WholeNodeCheckpointChecksumV1>,
    checksum: WholeNodeCheckpointChecksumV1,
}

impl WholeNodeCheckpointRefV1 {
    pub fn new(
        scope: WholeNodeCheckpointScopeV1,
        generation: WholeNodeCheckpointGenerationV1,
        phase: WholeNodeCheckpointPhaseV1,
        predecessor_checksum: Option<WholeNodeCheckpointChecksumV1>,
        checksum: WholeNodeCheckpointChecksumV1,
    ) -> WholeNodeCheckpointResultV1<Self> {
        if generation == WholeNodeCheckpointGenerationV1::ZERO {
            if phase != WholeNodeCheckpointPhaseV1::Commissioned || predecessor_checksum.is_some() {
                return Err(WholeNodeCheckpointErrorV1::InvalidField(
                    "generation-zero checkpoint reference",
                ));
            }
        } else if phase == WholeNodeCheckpointPhaseV1::Commissioned
            || predecessor_checksum.is_none()
        {
            return Err(WholeNodeCheckpointErrorV1::InvalidField(
                "noninitial checkpoint reference",
            ));
        }
        Ok(Self {
            scope,
            generation,
            phase,
            predecessor_checksum,
            checksum,
        })
    }

    pub const fn scope(&self) -> WholeNodeCheckpointScopeV1 {
        self.scope
    }

    pub const fn generation(&self) -> WholeNodeCheckpointGenerationV1 {
        self.generation
    }

    pub const fn phase(&self) -> WholeNodeCheckpointPhaseV1 {
        self.phase
    }

    pub const fn predecessor_checksum(&self) -> Option<WholeNodeCheckpointChecksumV1> {
        self.predecessor_checksum
    }

    /// Returns the fixed-width encoding of the predecessor field. Generation
    /// zero uses the unique all-zero representation.
    pub const fn canonical_predecessor_checksum_bytes(&self) -> [u8; 32] {
        match self.predecessor_checksum {
            None => [0; 32],
            Some(checksum) => *checksum.as_bytes(),
        }
    }

    pub const fn checksum(&self) -> WholeNodeCheckpointChecksumV1 {
        self.checksum
    }

    pub fn validate_successor_of(&self, predecessor: &Self) -> WholeNodeCheckpointResultV1<()> {
        if self.scope != predecessor.scope {
            return Err(WholeNodeCheckpointErrorV1::InvalidSuccessor(
                "checkpoint reference scope",
            ));
        }
        if self.generation != predecessor.generation.checked_next()? {
            return Err(WholeNodeCheckpointErrorV1::InvalidSuccessor(
                "checkpoint reference generation",
            ));
        }
        if self.predecessor_checksum != Some(predecessor.checksum) {
            return Err(WholeNodeCheckpointErrorV1::InvalidSuccessor(
                "checkpoint reference predecessor checksum",
            ));
        }
        let phase_order_valid = matches!(
            (predecessor.phase, self.phase),
            (
                WholeNodeCheckpointPhaseV1::Commissioned,
                WholeNodeCheckpointPhaseV1::AppValidated
            ) | (
                WholeNodeCheckpointPhaseV1::SignatureCommitted,
                WholeNodeCheckpointPhaseV1::AppValidated
            ) | (
                WholeNodeCheckpointPhaseV1::EpochActive,
                WholeNodeCheckpointPhaseV1::AppValidated
            ) | (
                WholeNodeCheckpointPhaseV1::AppValidated,
                WholeNodeCheckpointPhaseV1::SafetyPrepared
            ) | (
                WholeNodeCheckpointPhaseV1::SafetyPrepared,
                WholeNodeCheckpointPhaseV1::SignatureCommitted
            ) | (
                WholeNodeCheckpointPhaseV1::Commissioned,
                WholeNodeCheckpointPhaseV1::EpochActivationPrepared
            ) | (
                WholeNodeCheckpointPhaseV1::SignatureCommitted,
                WholeNodeCheckpointPhaseV1::EpochActivationPrepared
            ) | (
                WholeNodeCheckpointPhaseV1::EpochActive,
                WholeNodeCheckpointPhaseV1::EpochActivationPrepared
            ) | (
                WholeNodeCheckpointPhaseV1::EpochActivationPrepared,
                WholeNodeCheckpointPhaseV1::EpochActive
            )
        );
        if !phase_order_valid {
            return Err(WholeNodeCheckpointErrorV1::InvalidSuccessor(
                "checkpoint reference phase order",
            ));
        }
        Ok(())
    }

    pub fn exact_bytes(&self) -> [u8; WHOLE_NODE_CHECKPOINT_REF_BYTES_V1] {
        let mut encoded = [0u8; WHOLE_NODE_CHECKPOINT_REF_BYTES_V1];
        encoded[..8].copy_from_slice(CHECKPOINT_REF_MAGIC_V1);
        encoded[8..10].copy_from_slice(&WHOLE_NODE_CHECKPOINT_REF_SCHEMA_V1.to_be_bytes());
        encoded[10..42].copy_from_slice(self.scope.as_bytes());
        encoded[42..50].copy_from_slice(&self.generation.get().to_be_bytes());
        encoded[50] = self.phase.tag();
        encoded[51..83].copy_from_slice(&self.canonical_predecessor_checksum_bytes());
        encoded[83..115].copy_from_slice(self.checksum.as_bytes());
        encoded
    }
}

impl From<&WholeNodeCheckpointV1> for WholeNodeCheckpointRefV1 {
    fn from(record: &WholeNodeCheckpointV1) -> Self {
        Self {
            scope: record.scope(),
            generation: record.generation(),
            phase: record.phase(),
            predecessor_checksum: record.predecessor_checksum(),
            checksum: record.checkpoint_checksum(),
        }
    }
}

impl WholeNodeCheckpointV1 {
    /// Projects the unique public data reference for this exact record.
    pub fn checkpoint_ref(&self) -> WholeNodeCheckpointRefV1 {
        WholeNodeCheckpointRefV1::from(self)
    }
}

/// Strictly decodes the unique fixed-width reference representation.
pub fn decode_whole_node_checkpoint_ref_v1_exact(
    encoded: &[u8],
) -> WholeNodeCheckpointResultV1<WholeNodeCheckpointRefV1> {
    if encoded.len() != WHOLE_NODE_CHECKPOINT_REF_BYTES_V1 {
        return Err(WholeNodeCheckpointErrorV1::InvalidField(
            "checkpoint reference length",
        ));
    }
    if &encoded[..8] != CHECKPOINT_REF_MAGIC_V1 {
        return Err(WholeNodeCheckpointErrorV1::WrongMagic);
    }
    if u16::from_be_bytes([encoded[8], encoded[9]]) != WHOLE_NODE_CHECKPOINT_REF_SCHEMA_V1 {
        return Err(WholeNodeCheckpointErrorV1::UnsupportedSchema);
    }
    let scope = WholeNodeCheckpointScopeV1::from_exact_bytes(
        encoded[10..42]
            .try_into()
            .map_err(|_| WholeNodeCheckpointErrorV1::UnexpectedEnd)?,
    )?;
    let generation = WholeNodeCheckpointGenerationV1::new(u64::from_be_bytes(
        encoded[42..50]
            .try_into()
            .map_err(|_| WholeNodeCheckpointErrorV1::UnexpectedEnd)?,
    ));
    let phase = WholeNodeCheckpointPhaseV1::from_tag(encoded[50])?;
    let predecessor_bytes: [u8; 32] = encoded[51..83]
        .try_into()
        .map_err(|_| WholeNodeCheckpointErrorV1::UnexpectedEnd)?;
    let predecessor_checksum = if predecessor_bytes == [0; 32] {
        None
    } else {
        Some(WholeNodeCheckpointChecksumV1::from_exact_bytes(
            predecessor_bytes,
        )?)
    };
    let checksum = WholeNodeCheckpointChecksumV1::from_exact_bytes(
        encoded[83..115]
            .try_into()
            .map_err(|_| WholeNodeCheckpointErrorV1::UnexpectedEnd)?,
    )?;
    let value =
        WholeNodeCheckpointRefV1::new(scope, generation, phase, predecessor_checksum, checksum)?;
    if value.exact_bytes().as_slice() != encoded {
        return Err(WholeNodeCheckpointErrorV1::NonCanonicalEncoding);
    }
    Ok(value)
}
