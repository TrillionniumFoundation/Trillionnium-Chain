//! Private G2 candidate-to-Order materialization host.
//!
//! The host owns one linear, crash-audited control flow:
//!
//! `F_c -> S -> O_c -> P_m -> F_m -> B_m -> A_m -> G`.
//!
//! `F_c` is exact candidate Order finality, `S` is recoverable five-plane
//! source apply, `O_c` is the durable global terminal checkpoint, `P_m` is an
//! inert canonical-parent materialization plan, `F_m` is later Order finality,
//! `B_m` is the private owner/finality/membership binding permit, `A_m` is the
//! canonical Order-state apply, and `G` is the private in-process completion
//! owner.  Every durable record is data only.  Decoding the phase journal can
//! never recreate a global owner, verified finality, canonical write permit,
//! applied owner, signer, Core effect, or network authority.
//!
//! The SQLite journal is deliberately a separate namespace.  It uses a full
//! checksummed successor history, `BEGIN IMMEDIATE` compare-and-swap, mandatory
//! fresh readback, exact replay, sidecar/file-identity checks, and an external
//! head pin on reopen.  A coherent rollback of the whole journal file is not
//! self-detecting; the caller must retain the returned pin outside this
//! namespace.  The host therefore refuses reopen without an exact trusted pin.
//!
//! Recovery after canonical Order-state commit is explicit and
//! context-bearing. The host must freshly recover the global terminal owner,
//! resupply both verified finalities and the exact header template, reconstruct
//! the inert plan from the fresh-audited predecessor, and consume those
//! authorities through Order-state's no-write applied-owner recovery. Journal
//! receipt/root facts alone remain unable to recreate authority.

use std::{
    error::Error,
    ffi::OsString,
    fmt,
    fs::{self, OpenOptions},
    path::{Path, PathBuf},
};

use rusqlite::{params, Connection, OpenFlags, TransactionBehavior};
use sha2::{Digest, Sha256};
use trnm_poco_global_execution_v1::{
    GlobalExecutionSourcesV1, Hash32V1, PocoGlobalExecutionStoreV1, PreVoteExecutionReadyV1,
    WholeNodeFinalizationOwnerV1,
};
use trnm_poco_order_application_v1::{
    GlobalExecutionBindingInputV1, OrderApplicationOperationV1, OrderHeaderTemplateV1,
    PreparedOrderBlockV1,
};
use trnm_poco_order_finality_verifier_v1::VerifiedOrderFinalityV1;
use trnm_poco_order_state_v1::{
    AppliedFinalizedOrderStateOwnerV1, CanonicalFinalizedOrderApplyPermitV1,
    CanonicalOrderStateHeadPinV1, OrderStateMembershipProofV1, PocoCanonicalOrderStateStoreV1,
};
use trnm_poco_order_types_v1::{
    decode_block_header_v1, derive_block_id_v1, BlockHeaderV1, BlockIdV1, BlockKindV1,
    Cev1EncodeV1, ParentBlockRefV1, ProtocolContextV1,
};

const JOURNAL_SCHEMA_V1: u16 = 1;
const SQLITE_APPLICATION_ID_V1: i64 = 0x5452_4732;
const SQLITE_USER_VERSION_V1: i64 = 1;
const JOURNAL_FILE_NAME_V1: &str = "g2-order-commit-v1.sqlite";
const MAX_JOURNAL_RECORD_BYTES_V1: usize = 128 * 1024;
const RECORD_DOMAIN_V1: &str = "trnm.poco-ai.node-g2-order-commit-record.v1";
const CONTEXT_DOMAIN_V1: &str = "trnm.poco-ai.node-g2-order-commit-context.v1";
const COMPLETION_DOMAIN_V1: &str = "trnm.poco-ai.node-g2-order-commit-completion.v1";
const META_SQL_V1: &str = concat!(
    "CREATE TABLE g2_order_commit_metadata_v1 (",
    "singleton INTEGER PRIMARY KEY CHECK(singleton=1),",
    "journal_id BLOB NOT NULL CHECK(typeof(journal_id)='blob' AND length(journal_id)=32),",
    "scope BLOB NOT NULL CHECK(typeof(scope)='blob' AND length(scope)=32),",
    "head_sequence BLOB NOT NULL CHECK(typeof(head_sequence)='blob' AND length(head_sequence)=8),",
    "head_phase INTEGER NOT NULL CHECK(head_phase BETWEEN 0 AND 7),",
    "head_checksum BLOB NOT NULL CHECK(typeof(head_checksum)='blob' AND length(head_checksum)=32),",
    "fenced INTEGER NOT NULL CHECK(fenced IN(0,1))",
    ") STRICT"
);
const HISTORY_SQL_V1: &str = concat!(
    "CREATE TABLE g2_order_commit_history_v1 (",
    "sequence BLOB PRIMARY KEY CHECK(typeof(sequence)='blob' AND length(sequence)=8),",
    "phase INTEGER NOT NULL CHECK(phase BETWEEN 0 AND 7),",
    "predecessor_checksum BLOB NOT NULL CHECK(typeof(predecessor_checksum)='blob' AND length(predecessor_checksum)=32),",
    "checksum BLOB NOT NULL UNIQUE CHECK(typeof(checksum)='blob' AND length(checksum)=32),",
    "record BLOB NOT NULL CHECK(typeof(record)='blob' AND length(record)>0 AND length(record)<=131072)",
    ") STRICT, WITHOUT ROWID"
);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum PocoNodeG2OrderCommitErrorCodeV1 {
    InvalidNamespace,
    JournalUnavailable,
    JournalSchemaMismatch,
    JournalTamper,
    JournalRollback,
    JournalFork,
    JournalNotApplied,
    JournalThirdState,
    WrongPhase,
    CandidateFinalityMismatch,
    MaterializationFinalityMismatch,
    GlobalStoreMismatch,
    CanonicalStoreMismatch,
    PlanMismatch,
    UpstreamRejected,
    ArithmeticOverflow,
}

#[derive(Debug)]
pub(super) struct PocoNodeG2OrderCommitErrorV1 {
    code: PocoNodeG2OrderCommitErrorCodeV1,
    detail: String,
}

impl PocoNodeG2OrderCommitErrorV1 {
    pub(super) const fn code_v1(&self) -> PocoNodeG2OrderCommitErrorCodeV1 {
        self.code
    }
}

impl fmt::Display for PocoNodeG2OrderCommitErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "G2 Order-commit host rejected: {}", self.detail)
    }
}

impl Error for PocoNodeG2OrderCommitErrorV1 {}

type ResultV1<T> = Result<T, PocoNodeG2OrderCommitErrorV1>;

fn reject<T>(code: PocoNodeG2OrderCommitErrorCodeV1, detail: impl Into<String>) -> ResultV1<T> {
    Err(PocoNodeG2OrderCommitErrorV1 {
        code,
        detail: detail.into(),
    })
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub(super) enum PocoNodeG2OrderCommitPhaseV1 {
    CandidateFinality = 0,
    SourcesApplied = 1,
    CandidateOwnerCheckpointed = 2,
    MaterializationPrepared = 3,
    MaterializationFinality = 4,
    MaterializationBound = 5,
    MaterializationApplied = 6,
    Complete = 7,
}

impl PocoNodeG2OrderCommitPhaseV1 {
    const fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::CandidateFinality),
            1 => Some(Self::SourcesApplied),
            2 => Some(Self::CandidateOwnerCheckpointed),
            3 => Some(Self::MaterializationPrepared),
            4 => Some(Self::MaterializationFinality),
            5 => Some(Self::MaterializationBound),
            6 => Some(Self::MaterializationApplied),
            7 => Some(Self::Complete),
            _ => None,
        }
    }

    const fn successor(self) -> Option<Self> {
        Self::from_u8(self as u8 + 1)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct FinalityFactsV1 {
    context_digest: [u8; 32],
    pinned_trust_sha256: [u8; 32],
    proof_id: [u8; 32],
    epoch: u64,
    height: u64,
    block_id: [u8; 32],
    post_state_root: [u8; 32],
}

impl FinalityFactsV1 {
    fn from_verified(finality: &VerifiedOrderFinalityV1) -> Self {
        Self {
            context_digest: verified_context_digest_v1(finality),
            pinned_trust_sha256: finality.pinned_trust_sha256(),
            proof_id: finality.proof_id(),
            epoch: finality.epoch(),
            height: finality.finalized_height(),
            block_id: finality.finalized_block_id(),
            post_state_root: finality.finalized_post_state_root(),
        }
    }

    fn matches_verified(&self, finality: &VerifiedOrderFinalityV1) -> bool {
        self == &Self::from_verified(finality)
    }

    fn validate(&self) -> bool {
        self.context_digest != [0; 32]
            && self.pinned_trust_sha256 != [0; 32]
            && self.proof_id != [0; 32]
            && self.height > 0
            && self.block_id != [0; 32]
            && self.post_state_root != [0; 32]
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct CanonicalPinFactsV1 {
    store_id: [u8; 32],
    height: u64,
    block_id: [u8; 32],
    state_root: [u8; 32],
    history_checksum: [u8; 32],
}

impl CanonicalPinFactsV1 {
    fn from_pin(pin: &CanonicalOrderStateHeadPinV1) -> Self {
        Self {
            store_id: pin.store_id(),
            height: pin.height(),
            block_id: pin.block_id().to_bytes(),
            state_root: pin.state_root(),
            history_checksum: pin.history_checksum(),
        }
    }

    fn matches_pin(&self, pin: &CanonicalOrderStateHeadPinV1) -> bool {
        self == &Self::from_pin(pin)
    }

    fn to_external_trusted_pin_v1(&self) -> ResultV1<CanonicalOrderStateHeadPinV1> {
        CanonicalOrderStateHeadPinV1::from_external_trusted_parts_v1(
            self.store_id,
            self.height,
            BlockIdV1::new(self.block_id),
            self.state_root,
            self.history_checksum,
        )
        .map_err(|cause| upstream_v1("external canonical pin", cause))
    }

    fn validate(&self) -> bool {
        self.store_id != [0; 32]
            && self.height > 0
            && self.block_id != [0; 32]
            && self.state_root != [0; 32]
            && self.history_checksum != [0; 32]
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct MaterializationPlanFactsV1 {
    header_cev1: Vec<u8>,
    block_id: [u8; 32],
    plan_digest: [u8; 32],
    post_state_root: [u8; 32],
}

impl MaterializationPlanFactsV1 {
    fn from_prepared(prepared: &PreparedOrderBlockV1) -> Self {
        Self {
            header_cev1: prepared.header().to_cev1_bytes(),
            block_id: prepared.block_id().to_bytes(),
            plan_digest: prepared.plan_digest(),
            post_state_root: prepared.post_state_root(),
        }
    }

    fn matches_prepared(&self, prepared: &PreparedOrderBlockV1) -> bool {
        self == &Self::from_prepared(prepared)
    }
}

/// Cloneable journal head pin.  This is rollback-detection data only.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct PocoNodeG2OrderCommitJournalPinV1 {
    journal_id: [u8; 32],
    scope: [u8; 32],
    sequence: u64,
    phase: PocoNodeG2OrderCommitPhaseV1,
    checksum: [u8; 32],
}

impl PocoNodeG2OrderCommitJournalPinV1 {
    /// Reconstitute data authenticated by a separate process-owner namespace.
    /// The returned pin is only an exact selector for a full journal audit; it
    /// cannot recreate any upstream linear authority.
    pub(super) fn from_external_trusted_parts_v1(
        journal_id: [u8; 32],
        scope: [u8; 32],
        sequence: u64,
        phase: PocoNodeG2OrderCommitPhaseV1,
        checksum: [u8; 32],
    ) -> ResultV1<Self> {
        let pin = Self {
            journal_id,
            scope,
            sequence,
            phase,
            checksum,
        };
        pin.validate_v1()?;
        Ok(pin)
    }

    pub(super) const fn journal_id_v1(&self) -> [u8; 32] {
        self.journal_id
    }

    pub(super) const fn scope_v1(&self) -> [u8; 32] {
        self.scope
    }

    pub(super) const fn phase_v1(&self) -> PocoNodeG2OrderCommitPhaseV1 {
        self.phase
    }

    pub(super) const fn sequence_v1(&self) -> u64 {
        self.sequence
    }

    pub(super) const fn checksum_v1(&self) -> [u8; 32] {
        self.checksum
    }

    fn validate_v1(&self) -> ResultV1<()> {
        if self.journal_id == [0; 32]
            || self.scope == [0; 32]
            || self.checksum == [0; 32]
            || self.sequence != u64::from(self.phase as u8)
        {
            return reject(
                PocoNodeG2OrderCommitErrorCodeV1::JournalTamper,
                "external G2 journal pin is zero or phase-inconsistent",
            );
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct JournalRecordV1 {
    journal_id: [u8; 32],
    scope: [u8; 32],
    sequence: u64,
    phase: PocoNodeG2OrderCommitPhaseV1,
    predecessor_checksum: [u8; 32],
    prepared_generation: u64,
    prepared_checkpoint_checksum: [u8; 32],
    candidate_height: u64,
    candidate_block_id: [u8; 32],
    candidate_composite_root: [u8; 32],
    candidate_finality: FinalityFactsV1,
    canonical_parent: CanonicalPinFactsV1,
    final_execution_root: Option<[u8; 32]>,
    terminal_generation: Option<u64>,
    terminal_checkpoint_checksum: Option<[u8; 32]>,
    materialization_plan: Option<MaterializationPlanFactsV1>,
    materialization_finality: Option<FinalityFactsV1>,
    materialized_pin: Option<CanonicalPinFactsV1>,
    materialized_membership_proof_digest: Option<[u8; 32]>,
    completion_digest: Option<[u8; 32]>,
    checksum: [u8; 32],
}

impl JournalRecordV1 {
    fn candidate_finality(
        journal_id: [u8; 32],
        scope: [u8; 32],
        ready: &PreVoteExecutionReadyV1,
        finality: &VerifiedOrderFinalityV1,
        parent: &CanonicalOrderStateHeadPinV1,
    ) -> ResultV1<Self> {
        let mut record = Self {
            journal_id,
            scope,
            sequence: 0,
            phase: PocoNodeG2OrderCommitPhaseV1::CandidateFinality,
            predecessor_checksum: [0; 32],
            prepared_generation: ready.checkpoint_generation(),
            prepared_checkpoint_checksum: ready.checkpoint_checksum().0,
            candidate_height: ready.candidate_height(),
            candidate_block_id: ready.candidate_block_id().0,
            candidate_composite_root: ready.candidate_composite_root().0,
            candidate_finality: FinalityFactsV1::from_verified(finality),
            canonical_parent: CanonicalPinFactsV1::from_pin(parent),
            final_execution_root: None,
            terminal_generation: None,
            terminal_checkpoint_checksum: None,
            materialization_plan: None,
            materialization_finality: None,
            materialized_pin: None,
            materialized_membership_proof_digest: None,
            completion_digest: None,
            checksum: [0; 32],
        };
        record.reseal()?;
        record.validate()?;
        Ok(record)
    }

    fn successor(&self, phase: PocoNodeG2OrderCommitPhaseV1) -> ResultV1<Self> {
        if self.phase.successor() != Some(phase) {
            return reject(
                PocoNodeG2OrderCommitErrorCodeV1::WrongPhase,
                "journal successor skips or repeats a phase",
            );
        }
        let mut target = self.clone();
        target.sequence =
            self.sequence
                .checked_add(1)
                .ok_or_else(|| PocoNodeG2OrderCommitErrorV1 {
                    code: PocoNodeG2OrderCommitErrorCodeV1::ArithmeticOverflow,
                    detail: "journal sequence overflows".to_owned(),
                })?;
        target.phase = phase;
        target.predecessor_checksum = self.checksum;
        target.checksum = [0; 32];
        Ok(target)
    }

    fn reseal(&mut self) -> ResultV1<()> {
        self.checksum = digest_v1(RECORD_DOMAIN_V1, &self.encode_prefix()?);
        Ok(())
    }

    fn pin(&self) -> PocoNodeG2OrderCommitJournalPinV1 {
        PocoNodeG2OrderCommitJournalPinV1 {
            journal_id: self.journal_id,
            scope: self.scope,
            sequence: self.sequence,
            phase: self.phase,
            checksum: self.checksum,
        }
    }

    fn validate(&self) -> ResultV1<()> {
        if self.journal_id == [0; 32]
            || self.scope == [0; 32]
            || self.sequence != u64::from(self.phase as u8)
            || self.prepared_checkpoint_checksum == [0; 32]
            || self.candidate_height == 0
            || self.candidate_block_id == [0; 32]
            || self.candidate_composite_root == [0; 32]
            || !self.candidate_finality.validate()
            || self.candidate_finality.height != self.candidate_height
            || self.candidate_finality.block_id != self.candidate_block_id
            || !self.canonical_parent.validate()
        {
            return reject(
                PocoNodeG2OrderCommitErrorCodeV1::JournalTamper,
                "journal base candidate/finality/parent facts are invalid",
            );
        }
        let at_least = |phase| self.phase >= phase;
        if self.final_execution_root.is_some()
            != at_least(PocoNodeG2OrderCommitPhaseV1::SourcesApplied)
            || self.terminal_generation.is_some()
                != at_least(PocoNodeG2OrderCommitPhaseV1::CandidateOwnerCheckpointed)
            || self.terminal_checkpoint_checksum.is_some()
                != at_least(PocoNodeG2OrderCommitPhaseV1::CandidateOwnerCheckpointed)
            || self.materialization_plan.is_some()
                != at_least(PocoNodeG2OrderCommitPhaseV1::MaterializationPrepared)
            || self.materialization_finality.is_some()
                != at_least(PocoNodeG2OrderCommitPhaseV1::MaterializationFinality)
            || self.materialized_pin.is_some()
                != at_least(PocoNodeG2OrderCommitPhaseV1::MaterializationApplied)
            || self.materialized_membership_proof_digest.is_some()
                != at_least(PocoNodeG2OrderCommitPhaseV1::MaterializationApplied)
            || self.completion_digest.is_some() != at_least(PocoNodeG2OrderCommitPhaseV1::Complete)
            || self.final_execution_root == Some([0; 32])
            || self.terminal_generation == Some(0)
            || self.terminal_checkpoint_checksum == Some([0; 32])
            || self.materialized_membership_proof_digest == Some([0; 32])
            || self.completion_digest == Some([0; 32])
        {
            return reject(
                PocoNodeG2OrderCommitErrorCodeV1::JournalTamper,
                "journal phase inventory is incomplete, early, or zero",
            );
        }
        if let Some(plan) = &self.materialization_plan {
            self.validate_plan(plan)?;
        }
        if let Some(finality) = &self.materialization_finality {
            let plan =
                self.materialization_plan
                    .as_ref()
                    .ok_or_else(|| PocoNodeG2OrderCommitErrorV1 {
                        code: PocoNodeG2OrderCommitErrorCodeV1::JournalTamper,
                        detail: "materialization finality has no exact plan".to_owned(),
                    })?;
            let header = decode_block_header_v1(&plan.header_cev1).map_err(|_| {
                PocoNodeG2OrderCommitErrorV1 {
                    code: PocoNodeG2OrderCommitErrorCodeV1::JournalTamper,
                    detail: "materialization header cannot be decoded".to_owned(),
                }
            })?;
            if !finality.validate()
                || finality.context_digest != self.candidate_finality.context_digest
                || finality.pinned_trust_sha256 != self.candidate_finality.pinned_trust_sha256
                || finality.epoch != header.epoch
                || finality.height <= self.candidate_height
                || finality.height != header.height
                || finality.block_id != plan.block_id
                || finality.post_state_root != plan.post_state_root
            {
                return reject(
                    PocoNodeG2OrderCommitErrorCodeV1::JournalTamper,
                    "materialization finality differs from exact strict-later plan",
                );
            }
        }
        if let Some(pin) = &self.materialized_pin {
            let plan =
                self.materialization_plan
                    .as_ref()
                    .ok_or_else(|| PocoNodeG2OrderCommitErrorV1 {
                        code: PocoNodeG2OrderCommitErrorCodeV1::JournalTamper,
                        detail: "materialized pin has no exact plan".to_owned(),
                    })?;
            let header = decode_block_header_v1(&plan.header_cev1).map_err(|_| {
                PocoNodeG2OrderCommitErrorV1 {
                    code: PocoNodeG2OrderCommitErrorCodeV1::JournalTamper,
                    detail: "materialized plan header cannot be decoded".to_owned(),
                }
            })?;
            if !pin.validate()
                || pin.store_id != self.canonical_parent.store_id
                || pin.height != header.height
                || pin.block_id != plan.block_id
                || pin.state_root != plan.post_state_root
            {
                return reject(
                    PocoNodeG2OrderCommitErrorCodeV1::JournalTamper,
                    "materialized canonical pin differs from exact plan/store",
                );
            }
        }
        if self.phase == PocoNodeG2OrderCommitPhaseV1::Complete
            && self.completion_digest != Some(completion_digest_v1(self)?)
        {
            return reject(
                PocoNodeG2OrderCommitErrorCodeV1::JournalTamper,
                "G completion digest differs from exact A_m lineage",
            );
        }
        if self.checksum != digest_v1(RECORD_DOMAIN_V1, &self.encode_prefix()?) {
            return reject(
                PocoNodeG2OrderCommitErrorCodeV1::JournalTamper,
                "journal record checksum differs",
            );
        }
        Ok(())
    }

    fn validate_plan(&self, plan: &MaterializationPlanFactsV1) -> ResultV1<()> {
        if plan.header_cev1.is_empty()
            || plan.header_cev1.len() > 65_536
            || plan.block_id == [0; 32]
            || plan.plan_digest == [0; 32]
            || plan.post_state_root == [0; 32]
        {
            return reject(
                PocoNodeG2OrderCommitErrorCodeV1::JournalTamper,
                "materialization plan has a zero or over-bound fact",
            );
        }
        let header = decode_block_header_v1(&plan.header_cev1).map_err(|_| {
            PocoNodeG2OrderCommitErrorV1 {
                code: PocoNodeG2OrderCommitErrorCodeV1::JournalTamper,
                detail: "materialization header fails exact CEV1 decode".to_owned(),
            }
        })?;
        if header.to_cev1_bytes() != plan.header_cev1
            || derive_block_id_v1(&header).to_bytes() != plan.block_id
            || header.post_state_root != plan.post_state_root
            || self.canonical_parent.height.checked_add(1) != Some(header.height)
            || header.parent
                != ParentBlockRefV1::V1Block(BlockIdV1::new(self.canonical_parent.block_id))
            || header.block_kind != BlockKindV1::Ordinary
            || protocol_context_digest_v1(&header.context) != self.candidate_finality.context_digest
        {
            return reject(
                PocoNodeG2OrderCommitErrorCodeV1::JournalTamper,
                "materialization header/BlockId/root/parent/context differs",
            );
        }
        Ok(())
    }

    fn validate_successor(&self, target: &Self) -> ResultV1<()> {
        self.validate()?;
        target.validate()?;
        if self.phase.successor() != Some(target.phase)
            || self.sequence.checked_add(1) != Some(target.sequence)
            || target.predecessor_checksum != self.checksum
            || self.journal_id != target.journal_id
            || self.scope != target.scope
            || self.prepared_generation != target.prepared_generation
            || self.prepared_checkpoint_checksum != target.prepared_checkpoint_checksum
            || self.candidate_height != target.candidate_height
            || self.candidate_block_id != target.candidate_block_id
            || self.candidate_composite_root != target.candidate_composite_root
            || self.candidate_finality != target.candidate_finality
            || self.canonical_parent != target.canonical_parent
            || (self.final_execution_root.is_some()
                && self.final_execution_root != target.final_execution_root)
            || (self.terminal_generation.is_some()
                && self.terminal_generation != target.terminal_generation)
            || (self.terminal_checkpoint_checksum.is_some()
                && self.terminal_checkpoint_checksum != target.terminal_checkpoint_checksum)
            || (self.materialization_plan.is_some()
                && self.materialization_plan != target.materialization_plan)
            || (self.materialization_finality.is_some()
                && self.materialization_finality != target.materialization_finality)
            || (self.materialized_pin.is_some() && self.materialized_pin != target.materialized_pin)
            || (self.materialized_membership_proof_digest.is_some()
                && self.materialized_membership_proof_digest
                    != target.materialized_membership_proof_digest)
        {
            return reject(
                PocoNodeG2OrderCommitErrorCodeV1::JournalFork,
                "journal target is not the exact immutable next phase",
            );
        }
        Ok(())
    }

    fn encode_prefix(&self) -> ResultV1<Vec<u8>> {
        let mut out = Vec::with_capacity(
            1024 + self
                .materialization_plan
                .as_ref()
                .map_or(0, |p| p.header_cev1.len()),
        );
        put_u16(&mut out, JOURNAL_SCHEMA_V1);
        put_hash(&mut out, self.journal_id);
        put_hash(&mut out, self.scope);
        put_u64(&mut out, self.sequence);
        out.push(self.phase as u8);
        put_hash(&mut out, self.predecessor_checksum);
        put_u64(&mut out, self.prepared_generation);
        put_hash(&mut out, self.prepared_checkpoint_checksum);
        put_u64(&mut out, self.candidate_height);
        put_hash(&mut out, self.candidate_block_id);
        put_hash(&mut out, self.candidate_composite_root);
        encode_finality(&mut out, &self.candidate_finality);
        encode_pin(&mut out, &self.canonical_parent);
        put_option_hash(&mut out, self.final_execution_root);
        put_option_u64(&mut out, self.terminal_generation);
        put_option_hash(&mut out, self.terminal_checkpoint_checksum);
        match &self.materialization_plan {
            Some(plan) => {
                out.push(1);
                put_bytes(&mut out, &plan.header_cev1)?;
                put_hash(&mut out, plan.block_id);
                put_hash(&mut out, plan.plan_digest);
                put_hash(&mut out, plan.post_state_root);
            }
            None => out.push(0),
        }
        put_option_finality(&mut out, self.materialization_finality.as_ref());
        put_option_pin(&mut out, self.materialized_pin.as_ref());
        put_option_hash(&mut out, self.materialized_membership_proof_digest);
        put_option_hash(&mut out, self.completion_digest);
        if out.len() + 32 > MAX_JOURNAL_RECORD_BYTES_V1 {
            return reject(
                PocoNodeG2OrderCommitErrorCodeV1::JournalTamper,
                "journal record exceeds bounded encoding",
            );
        }
        Ok(out)
    }

    fn encode(&self) -> ResultV1<Vec<u8>> {
        let mut out = self.encode_prefix()?;
        put_hash(&mut out, self.checksum);
        Ok(out)
    }

    fn decode_exact(raw: &[u8]) -> ResultV1<Self> {
        if raw.len() < 571 || raw.len() > MAX_JOURNAL_RECORD_BYTES_V1 {
            return reject(
                PocoNodeG2OrderCommitErrorCodeV1::JournalTamper,
                "journal record length is outside the exact bound",
            );
        }
        let mut cursor = CursorV1::new(raw);
        if cursor.u16()? != JOURNAL_SCHEMA_V1 {
            return reject(
                PocoNodeG2OrderCommitErrorCodeV1::JournalTamper,
                "journal record schema differs",
            );
        }
        let journal_id = cursor.hash()?;
        let scope = cursor.hash()?;
        let sequence = cursor.u64()?;
        let phase = PocoNodeG2OrderCommitPhaseV1::from_u8(cursor.u8()?).ok_or_else(|| {
            PocoNodeG2OrderCommitErrorV1 {
                code: PocoNodeG2OrderCommitErrorCodeV1::JournalTamper,
                detail: "journal phase is unsupported".to_owned(),
            }
        })?;
        let predecessor_checksum = cursor.hash()?;
        let prepared_generation = cursor.u64()?;
        let prepared_checkpoint_checksum = cursor.hash()?;
        let candidate_height = cursor.u64()?;
        let candidate_block_id = cursor.hash()?;
        let candidate_composite_root = cursor.hash()?;
        let candidate_finality = cursor.finality()?;
        let canonical_parent = cursor.pin()?;
        let final_execution_root = cursor.option_hash()?;
        let terminal_generation = cursor.option_u64()?;
        let terminal_checkpoint_checksum = cursor.option_hash()?;
        let materialization_plan = match cursor.option_tag()? {
            false => None,
            true => Some(MaterializationPlanFactsV1 {
                header_cev1: cursor.bytes(65_536)?.to_vec(),
                block_id: cursor.hash()?,
                plan_digest: cursor.hash()?,
                post_state_root: cursor.hash()?,
            }),
        };
        let materialization_finality = cursor.option_finality()?;
        let materialized_pin = cursor.option_pin()?;
        let materialized_membership_proof_digest = cursor.option_hash()?;
        let completion_digest = cursor.option_hash()?;
        let checksum = cursor.hash()?;
        if cursor.remaining() != 0 {
            return reject(
                PocoNodeG2OrderCommitErrorCodeV1::JournalTamper,
                "journal record has trailing bytes",
            );
        }
        let record = Self {
            journal_id,
            scope,
            sequence,
            phase,
            predecessor_checksum,
            prepared_generation,
            prepared_checkpoint_checksum,
            candidate_height,
            candidate_block_id,
            candidate_composite_root,
            candidate_finality,
            canonical_parent,
            final_execution_root,
            terminal_generation,
            terminal_checkpoint_checksum,
            materialization_plan,
            materialization_finality,
            materialized_pin,
            materialized_membership_proof_digest,
            completion_digest,
            checksum,
        };
        if record.encode()? != raw {
            return reject(
                PocoNodeG2OrderCommitErrorCodeV1::JournalTamper,
                "journal record does not round-trip exactly",
            );
        }
        record.validate()?;
        Ok(record)
    }
}

/// Three explicitly disjoint store namespaces owned by the future process
/// commissioner.  Paths are private configuration, not store authority.
#[derive(Clone, Debug)]
pub(super) struct PocoNodeG2OrderCommitNamespacesV1 {
    journal_directory: PathBuf,
    global_execution_directory: PathBuf,
    canonical_order_directory: PathBuf,
}

impl PocoNodeG2OrderCommitNamespacesV1 {
    pub(super) fn new(
        journal_directory: impl Into<PathBuf>,
        global_execution_directory: impl Into<PathBuf>,
        canonical_order_directory: impl Into<PathBuf>,
    ) -> ResultV1<Self> {
        let journal_directory = canonical_private_directory_v1(&journal_directory.into())?;
        let global_execution_directory =
            canonical_private_directory_v1(&global_execution_directory.into())?;
        let canonical_order_directory =
            canonical_private_directory_v1(&canonical_order_directory.into())?;
        let directories = [
            &journal_directory,
            &global_execution_directory,
            &canonical_order_directory,
        ];
        for (index, left) in directories.iter().enumerate() {
            for right in directories.iter().skip(index + 1) {
                if left == right || left.starts_with(right) || right.starts_with(left) {
                    return reject(
                        PocoNodeG2OrderCommitErrorCodeV1::InvalidNamespace,
                        "G2 journal/global/canonical namespaces overlap or nest",
                    );
                }
            }
        }
        Ok(Self {
            journal_directory,
            global_execution_directory,
            canonical_order_directory,
        })
    }

    fn journal_path(&self) -> PathBuf {
        self.journal_directory.join(JOURNAL_FILE_NAME_V1)
    }

    fn revalidate(&self) -> ResultV1<()> {
        let observed = Self::new(
            self.journal_directory.clone(),
            self.global_execution_directory.clone(),
            self.canonical_order_directory.clone(),
        )?;
        if observed.journal_directory != self.journal_directory
            || observed.global_execution_directory != self.global_execution_directory
            || observed.canonical_order_directory != self.canonical_order_directory
        {
            return reject(
                PocoNodeG2OrderCommitErrorCodeV1::InvalidNamespace,
                "G2 namespace identity changed",
            );
        }
        Ok(())
    }
}

#[cfg(unix)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct JournalFileIdentityV1 {
    device: u64,
    inode: u64,
    owner: u32,
    links: u64,
    mode: u32,
}

#[cfg(not(unix))]
#[derive(Clone, Debug, Eq, PartialEq)]
struct JournalFileIdentityV1 {
    canonical_path: PathBuf,
}

#[derive(Debug)]
struct SqliteG2OrderCommitJournalV1 {
    path: PathBuf,
    journal_id: [u8; 32],
    scope: [u8; 32],
    file_identity: JournalFileIdentityV1,
}

#[cfg_attr(not(test), allow(dead_code))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum JournalFaultV1 {
    BeforeCommit,
    AfterCommitBeforeReturn,
}

impl SqliteG2OrderCommitJournalV1 {
    fn initialize_new(
        namespaces: &PocoNodeG2OrderCommitNamespacesV1,
        initial: &JournalRecordV1,
    ) -> ResultV1<Self> {
        namespaces.revalidate()?;
        initial.validate()?;
        if initial.phase != PocoNodeG2OrderCommitPhaseV1::CandidateFinality
            || initial.sequence != 0
            || initial.predecessor_checksum != [0; 32]
        {
            return reject(
                PocoNodeG2OrderCommitErrorCodeV1::JournalTamper,
                "new G2 journal requires the exact F_c anchor",
            );
        }
        let path = namespaces.journal_path();
        validate_journal_path_v1(&path, false)?;
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .map_err(|cause| unavailable_v1(format!("cannot create G2 journal: {cause}")))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).map_err(|cause| {
                unavailable_v1(format!("cannot set G2 journal permissions: {cause}"))
            })?;
        }
        drop(file);
        let mut connection = open_rw_raw_v1(&path)?;
        configure_rw_v1(&connection)?;
        connection
            .pragma_update(None, "application_id", SQLITE_APPLICATION_ID_V1)
            .map_err(sqlite_unavailable_v1)?;
        connection
            .pragma_update(None, "user_version", SQLITE_USER_VERSION_V1)
            .map_err(sqlite_unavailable_v1)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_unavailable_v1)?;
        transaction
            .execute_batch(META_SQL_V1)
            .map_err(sqlite_unavailable_v1)?;
        transaction
            .execute_batch(HISTORY_SQL_V1)
            .map_err(sqlite_unavailable_v1)?;
        transaction
            .execute(
                "INSERT INTO g2_order_commit_history_v1(sequence,phase,predecessor_checksum,checksum,record) VALUES(?1,0,?2,?3,?4)",
                params![
                    &initial.sequence.to_be_bytes()[..],
                    &initial.predecessor_checksum[..],
                    &initial.checksum[..],
                    initial.encode()?,
                ],
            )
            .map_err(sqlite_unavailable_v1)?;
        transaction
            .execute(
                "INSERT INTO g2_order_commit_metadata_v1(singleton,journal_id,scope,head_sequence,head_phase,head_checksum,fenced) VALUES(1,?1,?2,?3,0,?4,0)",
                params![
                    &initial.journal_id[..],
                    &initial.scope[..],
                    &initial.sequence.to_be_bytes()[..],
                    &initial.checksum[..],
                ],
            )
            .map_err(sqlite_unavailable_v1)?;
        transaction.commit().map_err(sqlite_unavailable_v1)?;
        drop(connection);
        reject_sidecars_v1(&path)?;
        let journal = Self {
            file_identity: journal_file_identity_v1(&path)?,
            path,
            journal_id: initial.journal_id,
            scope: initial.scope,
        };
        if journal.audit_fresh_v1()? != *initial {
            return reject(
                PocoNodeG2OrderCommitErrorCodeV1::JournalTamper,
                "fresh G2 journal readback differs from F_c anchor",
            );
        }
        Ok(journal)
    }

    fn open_existing(
        namespaces: &PocoNodeG2OrderCommitNamespacesV1,
        trusted_pin: &PocoNodeG2OrderCommitJournalPinV1,
    ) -> ResultV1<Self> {
        namespaces.revalidate()?;
        trusted_pin.validate_v1()?;
        let path = namespaces.journal_path();
        validate_journal_path_v1(&path, true)?;
        let journal = Self {
            file_identity: journal_file_identity_v1(&path)?,
            path,
            journal_id: trusted_pin.journal_id,
            scope: trusted_pin.scope,
        };
        let observed = journal.audit_fresh_v1()?;
        if observed.pin() != *trusted_pin {
            return reject(
                PocoNodeG2OrderCommitErrorCodeV1::JournalRollback,
                "fresh G2 journal head differs from external trusted pin",
            );
        }
        Ok(journal)
    }

    fn head_v1(&self) -> ResultV1<JournalRecordV1> {
        self.audit_fresh_v1()
    }

    fn advance_v1(
        &self,
        expected: &JournalRecordV1,
        target: &JournalRecordV1,
    ) -> ResultV1<JournalRecordV1> {
        self.advance_inner_v1(expected, target, None)
    }

    #[cfg(test)]
    fn advance_with_fault_v1(
        &self,
        expected: &JournalRecordV1,
        target: &JournalRecordV1,
        fault: JournalFaultV1,
    ) -> ResultV1<JournalRecordV1> {
        self.advance_inner_v1(expected, target, Some(fault))
    }

    fn advance_inner_v1(
        &self,
        expected: &JournalRecordV1,
        target: &JournalRecordV1,
        #[cfg_attr(not(test), allow(unused_variables))] fault: Option<JournalFaultV1>,
    ) -> ResultV1<JournalRecordV1> {
        expected.validate_successor(target)?;
        self.validate_identity_v1()?;
        let mut connection = open_rw_raw_v1(&self.path)?;
        configure_rw_v1(&connection)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_unavailable_v1)?;
        let observed = audit_connection_v1(&transaction, self.journal_id, self.scope)?;
        if observed == *target {
            drop(transaction);
            drop(connection);
            return self.audit_fresh_v1();
        }
        if observed != *expected {
            return reject(
                PocoNodeG2OrderCommitErrorCodeV1::JournalFork,
                "G2 journal CAS source is neither exact expected nor target",
            );
        }
        transaction
            .execute(
                "INSERT INTO g2_order_commit_history_v1(sequence,phase,predecessor_checksum,checksum,record) VALUES(?1,?2,?3,?4,?5)",
                params![
                    &target.sequence.to_be_bytes()[..],
                    i64::from(target.phase as u8),
                    &target.predecessor_checksum[..],
                    &target.checksum[..],
                    target.encode()?,
                ],
            )
            .map_err(sqlite_unavailable_v1)?;
        let changed = transaction
            .execute(
                "UPDATE g2_order_commit_metadata_v1 SET head_sequence=?1,head_phase=?2,head_checksum=?3 WHERE singleton=1 AND fenced=0 AND journal_id=?4 AND scope=?5 AND head_sequence=?6 AND head_phase=?7 AND head_checksum=?8",
                params![
                    &target.sequence.to_be_bytes()[..],
                    i64::from(target.phase as u8),
                    &target.checksum[..],
                    &target.journal_id[..],
                    &target.scope[..],
                    &expected.sequence.to_be_bytes()[..],
                    i64::from(expected.phase as u8),
                    &expected.checksum[..],
                ],
            )
            .map_err(sqlite_unavailable_v1)?;
        if changed != 1 {
            return reject(
                PocoNodeG2OrderCommitErrorCodeV1::JournalFork,
                "G2 journal metadata CAS changed no row",
            );
        }
        #[cfg(test)]
        if matches!(fault, Some(JournalFaultV1::BeforeCommit)) {
            drop(transaction);
            drop(connection);
            let fresh = self.audit_fresh_v1()?;
            if fresh == *expected {
                return reject(
                    PocoNodeG2OrderCommitErrorCodeV1::JournalNotApplied,
                    "injected journal loss before commit was proven not applied",
                );
            }
            return reject(
                PocoNodeG2OrderCommitErrorCodeV1::JournalThirdState,
                "precommit loss observed a third journal state",
            );
        }
        let commit_result = transaction.commit();
        drop(connection);
        #[cfg(test)]
        let commit_result = if matches!(fault, Some(JournalFaultV1::AfterCommitBeforeReturn)) {
            Err(rusqlite::Error::ExecuteReturnedResults)
        } else {
            commit_result
        };
        let fresh = self.audit_fresh_v1()?;
        if fresh == *target {
            let _ = commit_result;
            return Ok(fresh);
        }
        if fresh == *expected {
            let _ = commit_result;
            return reject(
                PocoNodeG2OrderCommitErrorCodeV1::JournalNotApplied,
                "G2 journal CAS was proven not applied",
            );
        }
        reject(
            PocoNodeG2OrderCommitErrorCodeV1::JournalThirdState,
            "G2 journal CAS fresh readback is neither source nor target",
        )
    }

    fn audit_fresh_v1(&self) -> ResultV1<JournalRecordV1> {
        self.validate_identity_v1()?;
        reject_sidecars_v1(&self.path)?;
        let connection = open_ro_v1(&self.path)?;
        let head = audit_connection_v1(&connection, self.journal_id, self.scope)?;
        drop(connection);
        self.validate_identity_v1()?;
        reject_sidecars_v1(&self.path)?;
        Ok(head)
    }

    fn validate_identity_v1(&self) -> ResultV1<()> {
        if journal_file_identity_v1(&self.path)? != self.file_identity {
            return reject(
                PocoNodeG2OrderCommitErrorCodeV1::JournalUnavailable,
                "G2 journal file identity changed",
            );
        }
        Ok(())
    }
}

fn audit_connection_v1(
    connection: &Connection,
    expected_journal_id: [u8; 32],
    expected_scope: [u8; 32],
) -> ResultV1<JournalRecordV1> {
    validate_schema_v1(connection)?;
    let metadata = connection
        .query_row(
            "SELECT journal_id,scope,head_sequence,head_phase,head_checksum,fenced FROM g2_order_commit_metadata_v1 WHERE singleton=1",
            [],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, Vec<u8>>(4)?,
                    row.get::<_, i64>(5)?,
                ))
            },
        )
        .map_err(sqlite_unavailable_v1)?;
    let journal_id = exact_hash_v1(&metadata.0, "journal ID")?;
    let scope = exact_hash_v1(&metadata.1, "scope")?;
    let head_sequence = exact_u64_v1(&metadata.2, "head sequence")?;
    let head_phase = u8::try_from(metadata.3)
        .ok()
        .and_then(PocoNodeG2OrderCommitPhaseV1::from_u8)
        .ok_or_else(|| PocoNodeG2OrderCommitErrorV1 {
            code: PocoNodeG2OrderCommitErrorCodeV1::JournalTamper,
            detail: "journal metadata phase is invalid".to_owned(),
        })?;
    let head_checksum = exact_hash_v1(&metadata.4, "head checksum")?;
    if journal_id != expected_journal_id
        || scope != expected_scope
        || journal_id == [0; 32]
        || scope == [0; 32]
        || metadata.5 != 0
    {
        return reject(
            PocoNodeG2OrderCommitErrorCodeV1::JournalTamper,
            "journal metadata identity differs or is fenced",
        );
    }

    let mut statement = connection
        .prepare(
            "SELECT sequence,phase,predecessor_checksum,checksum,record FROM g2_order_commit_history_v1 ORDER BY sequence",
        )
        .map_err(sqlite_unavailable_v1)?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, Vec<u8>>(2)?,
                row.get::<_, Vec<u8>>(3)?,
                row.get::<_, Vec<u8>>(4)?,
            ))
        })
        .map_err(sqlite_unavailable_v1)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(sqlite_unavailable_v1)?;
    if rows.is_empty() || rows.len() > 8 {
        return reject(
            PocoNodeG2OrderCommitErrorCodeV1::JournalTamper,
            "journal history count is outside the exact phase bound",
        );
    }
    let mut predecessor: Option<JournalRecordV1> = None;
    for row in rows {
        let sequence = exact_u64_v1(&row.0, "history sequence")?;
        let phase = u8::try_from(row.1)
            .ok()
            .and_then(PocoNodeG2OrderCommitPhaseV1::from_u8)
            .ok_or_else(|| PocoNodeG2OrderCommitErrorV1 {
                code: PocoNodeG2OrderCommitErrorCodeV1::JournalTamper,
                detail: "journal history phase is invalid".to_owned(),
            })?;
        let predecessor_checksum = exact_hash_v1(&row.2, "history predecessor")?;
        let checksum = exact_hash_v1(&row.3, "history checksum")?;
        let record = JournalRecordV1::decode_exact(&row.4)?;
        if sequence != record.sequence
            || phase != record.phase
            || predecessor_checksum != record.predecessor_checksum
            || checksum != record.checksum
            || record.journal_id != journal_id
            || record.scope != scope
        {
            return reject(
                PocoNodeG2OrderCommitErrorCodeV1::JournalTamper,
                "journal row columns differ from exact record",
            );
        }
        match predecessor.as_ref() {
            None => {
                if sequence != 0
                    || phase != PocoNodeG2OrderCommitPhaseV1::CandidateFinality
                    || predecessor_checksum != [0; 32]
                {
                    return reject(
                        PocoNodeG2OrderCommitErrorCodeV1::JournalTamper,
                        "journal history does not begin at exact F_c anchor",
                    );
                }
            }
            Some(previous) => previous.validate_successor(&record)?,
        }
        predecessor = Some(record);
    }
    let head = predecessor.expect("nonempty journal history checked above");
    if head.sequence != head_sequence || head.phase != head_phase || head.checksum != head_checksum
    {
        return reject(
            PocoNodeG2OrderCommitErrorCodeV1::JournalTamper,
            "journal metadata head differs from complete history tail",
        );
    }
    Ok(head)
}

fn validate_schema_v1(connection: &Connection) -> ResultV1<()> {
    let application_id = connection
        .query_row("PRAGMA application_id", [], |row| row.get::<_, i64>(0))
        .map_err(sqlite_unavailable_v1)?;
    let user_version = connection
        .query_row("PRAGMA user_version", [], |row| row.get::<_, i64>(0))
        .map_err(sqlite_unavailable_v1)?;
    if application_id != SQLITE_APPLICATION_ID_V1 || user_version != SQLITE_USER_VERSION_V1 {
        return reject(
            PocoNodeG2OrderCommitErrorCodeV1::JournalSchemaMismatch,
            "journal SQLite application/schema version differs",
        );
    }
    let mut statement = connection
        .prepare("SELECT name,sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' ORDER BY name")
        .map_err(sqlite_unavailable_v1)?;
    let actual = statement
        .query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })
        .map_err(sqlite_unavailable_v1)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(sqlite_unavailable_v1)?;
    let expected = vec![
        (
            "g2_order_commit_history_v1".to_owned(),
            HISTORY_SQL_V1.to_owned(),
        ),
        (
            "g2_order_commit_metadata_v1".to_owned(),
            META_SQL_V1.to_owned(),
        ),
    ];
    if actual != expected {
        return reject(
            PocoNodeG2OrderCommitErrorCodeV1::JournalSchemaMismatch,
            "journal SQLite schema inventory differs",
        );
    }
    Ok(())
}

fn canonical_private_directory_v1(path: &Path) -> ResultV1<PathBuf> {
    if !path.is_absolute() || path.as_os_str().is_empty() {
        return reject(
            PocoNodeG2OrderCommitErrorCodeV1::InvalidNamespace,
            "G2 namespace directory must be nonempty and absolute",
        );
    }
    let metadata = fs::symlink_metadata(path).map_err(|cause| PocoNodeG2OrderCommitErrorV1 {
        code: PocoNodeG2OrderCommitErrorCodeV1::InvalidNamespace,
        detail: format!("G2 namespace metadata unavailable: {cause}"),
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return reject(
            PocoNodeG2OrderCommitErrorCodeV1::InvalidNamespace,
            "G2 namespace must be a direct directory",
        );
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o777 != 0o700 {
            return reject(
                PocoNodeG2OrderCommitErrorCodeV1::InvalidNamespace,
                "G2 namespace directory mode must be exactly 0700",
            );
        }
    }
    let canonical = fs::canonicalize(path).map_err(|cause| PocoNodeG2OrderCommitErrorV1 {
        code: PocoNodeG2OrderCommitErrorCodeV1::InvalidNamespace,
        detail: format!("G2 namespace cannot canonicalize: {cause}"),
    })?;
    if canonical != path {
        return reject(
            PocoNodeG2OrderCommitErrorCodeV1::InvalidNamespace,
            "G2 namespace path must already be canonical",
        );
    }
    Ok(canonical)
}

fn validate_journal_path_v1(path: &Path, must_exist: bool) -> ResultV1<()> {
    let parent = path.parent().ok_or_else(|| PocoNodeG2OrderCommitErrorV1 {
        code: PocoNodeG2OrderCommitErrorCodeV1::InvalidNamespace,
        detail: "journal path has no parent".to_owned(),
    })?;
    canonical_private_directory_v1(parent)?;
    if path.file_name().and_then(|name| name.to_str()) != Some(JOURNAL_FILE_NAME_V1)
        || path.is_symlink()
        || path.exists() != must_exist
    {
        return reject(
            PocoNodeG2OrderCommitErrorCodeV1::InvalidNamespace,
            "journal path name, symlink, or existence differs",
        );
    }
    Ok(())
}

#[cfg(unix)]
fn journal_file_identity_v1(path: &Path) -> ResultV1<JournalFileIdentityV1> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let metadata = fs::symlink_metadata(path)
        .map_err(|cause| unavailable_v1(format!("journal metadata unavailable: {cause}")))?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.permissions().mode() & 0o777 != 0o600
    {
        return reject(
            PocoNodeG2OrderCommitErrorCodeV1::JournalUnavailable,
            "journal file type/link-count/mode is invalid",
        );
    }
    Ok(JournalFileIdentityV1 {
        device: metadata.dev(),
        inode: metadata.ino(),
        owner: metadata.uid(),
        links: metadata.nlink(),
        mode: metadata.permissions().mode() & 0o777,
    })
}

#[cfg(not(unix))]
fn journal_file_identity_v1(path: &Path) -> ResultV1<JournalFileIdentityV1> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|cause| unavailable_v1(format!("journal metadata unavailable: {cause}")))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return reject(
            PocoNodeG2OrderCommitErrorCodeV1::JournalUnavailable,
            "journal target is not a direct regular file",
        );
    }
    Ok(JournalFileIdentityV1 {
        canonical_path: fs::canonicalize(path)
            .map_err(|cause| unavailable_v1(format!("journal path unavailable: {cause}")))?,
    })
}

fn reject_sidecars_v1(path: &Path) -> ResultV1<()> {
    for suffix in ["-journal", "-wal", "-shm"] {
        let mut sidecar = OsString::from(path.as_os_str());
        sidecar.push(suffix);
        if fs::symlink_metadata(PathBuf::from(sidecar)).is_ok() {
            return reject(
                PocoNodeG2OrderCommitErrorCodeV1::JournalUnavailable,
                format!("journal SQLite sidecar {suffix} is forbidden"),
            );
        }
    }
    Ok(())
}

fn open_rw_raw_v1(path: &Path) -> ResultV1<Connection> {
    let connection = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(sqlite_unavailable_v1)?;
    connection
        .busy_timeout(std::time::Duration::from_secs(2))
        .map_err(sqlite_unavailable_v1)?;
    Ok(connection)
}

fn open_ro_v1(path: &Path) -> ResultV1<Connection> {
    let bytes = path.as_os_str().as_encoded_bytes();
    let mut uri = String::from("file:");
    for byte in bytes {
        if byte.is_ascii_alphanumeric() || matches!(*byte, b'/' | b'.' | b'_' | b'-') {
            uri.push(char::from(*byte));
        } else {
            uri.push_str(&format!("%{byte:02X}"));
        }
    }
    uri.push_str("?mode=ro");
    let connection = Connection::open_with_flags(
        uri,
        OpenFlags::SQLITE_OPEN_READ_ONLY
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_URI,
    )
    .map_err(sqlite_unavailable_v1)?;
    connection
        .busy_timeout(std::time::Duration::from_secs(2))
        .map_err(sqlite_unavailable_v1)?;
    Ok(connection)
}

fn configure_rw_v1(connection: &Connection) -> ResultV1<()> {
    connection
        .pragma_update(None, "journal_mode", "DELETE")
        .map_err(sqlite_unavailable_v1)?;
    connection
        .pragma_update(None, "synchronous", "FULL")
        .map_err(sqlite_unavailable_v1)?;
    connection
        .pragma_update(None, "foreign_keys", true)
        .map_err(sqlite_unavailable_v1)?;
    Ok(())
}

fn sqlite_unavailable_v1(cause: rusqlite::Error) -> PocoNodeG2OrderCommitErrorV1 {
    unavailable_v1(format!("journal SQLite unavailable: {cause}"))
}

fn unavailable_v1(detail: impl Into<String>) -> PocoNodeG2OrderCommitErrorV1 {
    PocoNodeG2OrderCommitErrorV1 {
        code: PocoNodeG2OrderCommitErrorCodeV1::JournalUnavailable,
        detail: detail.into(),
    }
}

fn verified_context_digest_v1(finality: &VerifiedOrderFinalityV1) -> [u8; 32] {
    let mut encoded = Vec::new();
    put_u16(&mut encoded, JOURNAL_SCHEMA_V1);
    put_bytes_infallible(&mut encoded, finality.chain_id().as_bytes());
    put_hash(&mut encoded, finality.genesis_hash());
    encoded.extend_from_slice(&finality.protocol_version().to_le_bytes());
    put_hash(&mut encoded, finality.stack_profile_hash());
    digest_v1(CONTEXT_DOMAIN_V1, &encoded)
}

fn protocol_context_digest_v1(context: &ProtocolContextV1) -> [u8; 32] {
    let mut encoded = Vec::new();
    put_u16(&mut encoded, JOURNAL_SCHEMA_V1);
    put_bytes_infallible(&mut encoded, context.chain_id.as_bytes());
    put_hash(&mut encoded, context.genesis_hash);
    encoded.extend_from_slice(&context.protocol_version.to_le_bytes());
    put_hash(&mut encoded, context.stack_profile_hash);
    digest_v1(CONTEXT_DOMAIN_V1, &encoded)
}

fn template_matches_header_v1(template: &OrderHeaderTemplateV1, header: &BlockHeaderV1) -> bool {
    template.schema_version == header.schema_version
        && template.context == header.context
        && template.epoch == header.epoch
        && template.view == header.view
        && template.height == header.height
        && template.block_kind == header.block_kind
        && template.parent == header.parent
        && template.proposer_id == header.proposer_id
        && template.epoch_descriptor_id == header.epoch_descriptor_id
        && template.justify_qc_id == header.justify_qc_id
        && template.timeout_certificate_id == header.timeout_certificate_id
        && template.next_epoch_descriptor_id == header.next_epoch_descriptor_id
        && template.upgrade_plan_id == header.upgrade_plan_id
        && template.epoch_handoff_id == header.epoch_handoff_id
}

fn membership_proof_digest_v1(proof: &OrderStateMembershipProofV1) -> [u8; 32] {
    let mut encoded = Vec::with_capacity(256 * 32 + proof.value_bytes().len() + 160);
    put_u16(&mut encoded, JOURNAL_SCHEMA_V1);
    put_u64(&mut encoded, proof.height());
    put_hash(&mut encoded, proof.state_root());
    put_u16(&mut encoded, proof.state_tree_version());
    put_u16(&mut encoded, proof.object_kind());
    put_hash(&mut encoded, proof.object_id());
    put_u64(&mut encoded, proof.object_version());
    put_hash(&mut encoded, proof.state_key());
    put_bytes_infallible(&mut encoded, proof.value_bytes());
    encoded.extend_from_slice(
        &u32::try_from(proof.siblings().len())
            .expect("bounded membership sibling count fits u32")
            .to_le_bytes(),
    );
    for sibling in proof.siblings() {
        put_hash(&mut encoded, *sibling);
    }
    digest_v1("trnm.poco-ai.node-g2-order-membership-proof.v1", &encoded)
}

fn completion_digest_v1(record: &JournalRecordV1) -> ResultV1<[u8; 32]> {
    let mut predecessor = record.clone();
    predecessor.completion_digest = None;
    predecessor.checksum = [0; 32];
    Ok(digest_v1(
        COMPLETION_DOMAIN_V1,
        &predecessor.encode_prefix()?,
    ))
}

fn digest_v1(domain: &str, bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(
        u32::try_from(domain.len())
            .expect("static G2 journal domain length fits u32")
            .to_le_bytes(),
    );
    hasher.update(domain.as_bytes());
    hasher.update(bytes);
    hasher.finalize().into()
}

fn exact_hash_v1(raw: &[u8], label: &str) -> ResultV1<[u8; 32]> {
    raw.try_into().map_err(|_| PocoNodeG2OrderCommitErrorV1 {
        code: PocoNodeG2OrderCommitErrorCodeV1::JournalTamper,
        detail: format!("journal {label} is not exactly 32 bytes"),
    })
}

fn exact_u64_v1(raw: &[u8], label: &str) -> ResultV1<u64> {
    let bytes: [u8; 8] = raw.try_into().map_err(|_| PocoNodeG2OrderCommitErrorV1 {
        code: PocoNodeG2OrderCommitErrorCodeV1::JournalTamper,
        detail: format!("journal {label} is not exactly 8 bytes"),
    })?;
    Ok(u64::from_be_bytes(bytes))
}

fn encode_finality(out: &mut Vec<u8>, value: &FinalityFactsV1) {
    put_hash(out, value.context_digest);
    put_hash(out, value.pinned_trust_sha256);
    put_hash(out, value.proof_id);
    put_u64(out, value.epoch);
    put_u64(out, value.height);
    put_hash(out, value.block_id);
    put_hash(out, value.post_state_root);
}

fn encode_pin(out: &mut Vec<u8>, value: &CanonicalPinFactsV1) {
    put_hash(out, value.store_id);
    put_u64(out, value.height);
    put_hash(out, value.block_id);
    put_hash(out, value.state_root);
    put_hash(out, value.history_checksum);
}

fn put_option_finality(out: &mut Vec<u8>, value: Option<&FinalityFactsV1>) {
    match value {
        Some(value) => {
            out.push(1);
            encode_finality(out, value);
        }
        None => out.push(0),
    }
}

fn put_option_pin(out: &mut Vec<u8>, value: Option<&CanonicalPinFactsV1>) {
    match value {
        Some(value) => {
            out.push(1);
            encode_pin(out, value);
        }
        None => out.push(0),
    }
}

fn put_option_hash(out: &mut Vec<u8>, value: Option<[u8; 32]>) {
    match value {
        Some(value) => {
            out.push(1);
            put_hash(out, value);
        }
        None => out.push(0),
    }
}

fn put_option_u64(out: &mut Vec<u8>, value: Option<u64>) {
    match value {
        Some(value) => {
            out.push(1);
            put_u64(out, value);
        }
        None => out.push(0),
    }
}

fn put_u16(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn put_u64(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn put_hash(out: &mut Vec<u8>, value: [u8; 32]) {
    out.extend_from_slice(&value);
}

fn put_bytes(out: &mut Vec<u8>, value: &[u8]) -> ResultV1<()> {
    let length = u32::try_from(value.len()).map_err(|_| PocoNodeG2OrderCommitErrorV1 {
        code: PocoNodeG2OrderCommitErrorCodeV1::JournalTamper,
        detail: "journal byte field exceeds u32".to_owned(),
    })?;
    out.extend_from_slice(&length.to_le_bytes());
    out.extend_from_slice(value);
    Ok(())
}

fn put_bytes_infallible(out: &mut Vec<u8>, value: &[u8]) {
    out.extend_from_slice(
        &u32::try_from(value.len())
            .expect("bounded protocol context bytes fit u32")
            .to_le_bytes(),
    );
    out.extend_from_slice(value);
}

struct CursorV1<'a> {
    raw: &'a [u8],
    offset: usize,
}

impl<'a> CursorV1<'a> {
    const fn new(raw: &'a [u8]) -> Self {
        Self { raw, offset: 0 }
    }

    fn remaining(&self) -> usize {
        self.raw.len().saturating_sub(self.offset)
    }

    fn take(&mut self, length: usize) -> ResultV1<&'a [u8]> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or_else(|| PocoNodeG2OrderCommitErrorV1 {
                code: PocoNodeG2OrderCommitErrorCodeV1::ArithmeticOverflow,
                detail: "journal decode cursor overflows".to_owned(),
            })?;
        let value = self
            .raw
            .get(self.offset..end)
            .ok_or_else(|| PocoNodeG2OrderCommitErrorV1 {
                code: PocoNodeG2OrderCommitErrorCodeV1::JournalTamper,
                detail: "journal record is truncated".to_owned(),
            })?;
        self.offset = end;
        Ok(value)
    }

    fn array<const N: usize>(&mut self) -> ResultV1<[u8; N]> {
        self.take(N)?
            .try_into()
            .map_err(|_| PocoNodeG2OrderCommitErrorV1 {
                code: PocoNodeG2OrderCommitErrorCodeV1::JournalTamper,
                detail: "journal fixed-width field is truncated".to_owned(),
            })
    }

    fn u8(&mut self) -> ResultV1<u8> {
        Ok(self.array::<1>()?[0])
    }

    fn u16(&mut self) -> ResultV1<u16> {
        Ok(u16::from_le_bytes(self.array()?))
    }

    fn u32(&mut self) -> ResultV1<u32> {
        Ok(u32::from_le_bytes(self.array()?))
    }

    fn u64(&mut self) -> ResultV1<u64> {
        Ok(u64::from_le_bytes(self.array()?))
    }

    fn hash(&mut self) -> ResultV1<[u8; 32]> {
        self.array()
    }

    fn bytes(&mut self, maximum: usize) -> ResultV1<&'a [u8]> {
        let length = usize::try_from(self.u32()?).map_err(|_| PocoNodeG2OrderCommitErrorV1 {
            code: PocoNodeG2OrderCommitErrorCodeV1::JournalTamper,
            detail: "journal byte length cannot fit usize".to_owned(),
        })?;
        if length > maximum {
            return reject(
                PocoNodeG2OrderCommitErrorCodeV1::JournalTamper,
                "journal byte field exceeds bound",
            );
        }
        self.take(length)
    }

    fn option_tag(&mut self) -> ResultV1<bool> {
        match self.u8()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => reject(
                PocoNodeG2OrderCommitErrorCodeV1::JournalTamper,
                "journal option tag is noncanonical",
            ),
        }
    }

    fn finality(&mut self) -> ResultV1<FinalityFactsV1> {
        Ok(FinalityFactsV1 {
            context_digest: self.hash()?,
            pinned_trust_sha256: self.hash()?,
            proof_id: self.hash()?,
            epoch: self.u64()?,
            height: self.u64()?,
            block_id: self.hash()?,
            post_state_root: self.hash()?,
        })
    }

    fn pin(&mut self) -> ResultV1<CanonicalPinFactsV1> {
        Ok(CanonicalPinFactsV1 {
            store_id: self.hash()?,
            height: self.u64()?,
            block_id: self.hash()?,
            state_root: self.hash()?,
            history_checksum: self.hash()?,
        })
    }

    fn option_hash(&mut self) -> ResultV1<Option<[u8; 32]>> {
        self.option_tag()?.then(|| self.hash()).transpose()
    }

    fn option_u64(&mut self) -> ResultV1<Option<u64>> {
        self.option_tag()?.then(|| self.u64()).transpose()
    }

    fn option_finality(&mut self) -> ResultV1<Option<FinalityFactsV1>> {
        self.option_tag()?.then(|| self.finality()).transpose()
    }

    fn option_pin(&mut self) -> ResultV1<Option<CanonicalPinFactsV1>> {
        self.option_tag()?.then(|| self.pin()).transpose()
    }
}

#[derive(Debug)]
// These variants retain linear authority owners by value. Boxing them would
// add a new allocation/failure and owner-indirection boundary to the recovery
// state machine solely to optimize this private test-support enum's size.
#[allow(clippy::large_enum_variant)]
enum InMemoryAuthorityV1 {
    Recoverable,
    CandidateReady(PreVoteExecutionReadyV1),
    CandidateOwner(WholeNodeFinalizationOwnerV1),
    MaterializationPreview {
        owner: WholeNodeFinalizationOwnerV1,
        prepared: PreparedOrderBlockV1,
        parent: CanonicalOrderStateHeadPinV1,
    },
    MaterializationPermit(CanonicalFinalizedOrderApplyPermitV1),
    Applied(AppliedFinalizedOrderStateOwnerV1),
    FailedClosed,
}

/// Private, non-Clone Node host.  It is crate-visible only so the future
/// process owner can contain it; no raw constructor is exported downstream.
#[derive(Debug)]
#[must_use = "the private G2 phase host retains linear upstream authority"]
pub(super) struct PocoNodeG2OrderCommitHostV1<'a> {
    journal: SqliteG2OrderCommitJournalV1,
    current: JournalRecordV1,
    global: &'a PocoGlobalExecutionStoreV1,
    canonical_order: &'a PocoCanonicalOrderStateStoreV1,
    authority: InMemoryAuthorityV1,
}

/// Private terminal owner for an uninterrupted or retained-permit recovery
/// path.  Journal facts alone can never construct this non-Clone type.
#[derive(Debug)]
#[must_use = "the completed G2 owner must be handed to the next private process owner"]
pub(super) struct PocoNodeG2OrderCommitCompletedV1 {
    applied: AppliedFinalizedOrderStateOwnerV1,
    journal_pin: PocoNodeG2OrderCommitJournalPinV1,
}

impl PocoNodeG2OrderCommitCompletedV1 {
    pub(super) fn into_parts_v1(
        self,
    ) -> (
        AppliedFinalizedOrderStateOwnerV1,
        PocoNodeG2OrderCommitJournalPinV1,
    ) {
        (self.applied, self.journal_pin)
    }
}

impl<'a> PocoNodeG2OrderCommitHostV1<'a> {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn commission_v1(
        namespaces: &PocoNodeG2OrderCommitNamespacesV1,
        journal_id: [u8; 32],
        scope: [u8; 32],
        global: &'a PocoGlobalExecutionStoreV1,
        canonical_order: &'a PocoCanonicalOrderStateStoreV1,
        ready: PreVoteExecutionReadyV1,
        candidate_finality: &VerifiedOrderFinalityV1,
        expected_parent: CanonicalOrderStateHeadPinV1,
    ) -> ResultV1<Self> {
        if journal_id == [0; 32] || scope == [0; 32] {
            return reject(
                PocoNodeG2OrderCommitErrorCodeV1::JournalTamper,
                "G2 journal ID and scope must be nonzero",
            );
        }
        validate_ready_finality_v1(&ready, candidate_finality)?;
        let global_facts = global
            .fresh_checkpoint_facts_v1()
            .map_err(|cause| upstream_v1("global prepared checkpoint", cause))?;
        if global_facts.generation() != ready.checkpoint_generation()
            || global_facts.checksum() != ready.checkpoint_checksum()
            || global_facts.final_execution_root().is_some()
        {
            return reject(
                PocoNodeG2OrderCommitErrorCodeV1::GlobalStoreMismatch,
                "global store does not retain exact unfinalized prepared candidate",
            );
        }
        let observed_parent = canonical_order
            .fresh_head_pin_v1()
            .map_err(|cause| upstream_v1("canonical parent readback", cause))?;
        if observed_parent != expected_parent {
            return reject(
                PocoNodeG2OrderCommitErrorCodeV1::CanonicalStoreMismatch,
                "canonical Order head differs from commissioned parent pin",
            );
        }
        let _authenticated_parent = canonical_order
            .recover_order_application_parent_v1(&expected_parent)
            .map_err(|cause| upstream_v1("canonical parent fresh audit", cause))?;
        let initial = JournalRecordV1::candidate_finality(
            journal_id,
            scope,
            &ready,
            candidate_finality,
            &expected_parent,
        )?;
        let journal = SqliteG2OrderCommitJournalV1::initialize_new(namespaces, &initial)?;
        Ok(Self {
            journal,
            current: initial,
            global,
            canonical_order,
            authority: InMemoryAuthorityV1::CandidateReady(ready),
        })
    }

    pub(super) fn reopen_v1(
        namespaces: &PocoNodeG2OrderCommitNamespacesV1,
        global: &'a PocoGlobalExecutionStoreV1,
        canonical_order: &'a PocoCanonicalOrderStateStoreV1,
        trusted_journal_pin: &PocoNodeG2OrderCommitJournalPinV1,
    ) -> ResultV1<Self> {
        let journal = SqliteG2OrderCommitJournalV1::open_existing(namespaces, trusted_journal_pin)?;
        let current = journal.head_v1()?;
        validate_external_store_heads_v1(global, canonical_order, &current)?;
        Ok(Self {
            journal,
            current,
            global,
            canonical_order,
            authority: InMemoryAuthorityV1::Recoverable,
        })
    }

    pub(super) const fn phase_v1(&self) -> PocoNodeG2OrderCommitPhaseV1 {
        self.current.phase
    }

    pub(super) fn journal_pin_v1(&self) -> PocoNodeG2OrderCommitJournalPinV1 {
        self.current.pin()
    }

    pub(super) fn apply_sources_v1(
        &mut self,
        candidate_finality: &VerifiedOrderFinalityV1,
        sources: &mut GlobalExecutionSourcesV1<'_>,
    ) -> ResultV1<bool> {
        self.require_candidate_finality_v1(candidate_finality)?;
        match self.current.phase {
            PocoNodeG2OrderCommitPhaseV1::CandidateFinality => {}
            PocoNodeG2OrderCommitPhaseV1::SourcesApplied => {
                self.ensure_candidate_owner_v1(candidate_finality, sources)?;
                return Ok(true);
            }
            _ => {
                return reject(
                    PocoNodeG2OrderCommitErrorCodeV1::WrongPhase,
                    "source apply requires F_c or exact S replay",
                )
            }
        }

        let authority = std::mem::replace(&mut self.authority, InMemoryAuthorityV1::FailedClosed);
        let owner = match authority {
            InMemoryAuthorityV1::CandidateOwner(owner) => owner,
            InMemoryAuthorityV1::CandidateReady(ready) => {
                match self.global.apply_finalized_candidate_and_issue_owner_v1(
                    &ready,
                    candidate_finality,
                    sources,
                ) {
                    Ok(owner) => owner,
                    Err(cause) => {
                        self.authority = InMemoryAuthorityV1::CandidateReady(ready);
                        return Err(upstream_v1("five-plane source apply", cause));
                    }
                }
            }
            InMemoryAuthorityV1::Recoverable => {
                let ready = match self.global.recover_prepared_ready_v1(
                    self.current.prepared_generation,
                    Hash32V1(self.current.prepared_checkpoint_checksum),
                    Hash32V1(self.current.candidate_block_id),
                ) {
                    Ok(ready) => ready,
                    Err(cause) => {
                        self.authority = InMemoryAuthorityV1::Recoverable;
                        return Err(upstream_v1("prepared candidate recovery", cause));
                    }
                };
                match self.global.apply_finalized_candidate_and_issue_owner_v1(
                    &ready,
                    candidate_finality,
                    sources,
                ) {
                    Ok(owner) => owner,
                    Err(cause) => {
                        self.authority = InMemoryAuthorityV1::Recoverable;
                        return Err(upstream_v1("recoverable five-plane source apply", cause));
                    }
                }
            }
            other => {
                self.authority = other;
                return reject(
                    PocoNodeG2OrderCommitErrorCodeV1::WrongPhase,
                    "in-memory authority cannot execute source apply",
                );
            }
        };
        self.validate_owner_v1(&owner)?;
        let mut target = self
            .current
            .successor(PocoNodeG2OrderCommitPhaseV1::SourcesApplied)?;
        target.final_execution_root = Some(owner.final_execution_root().0);
        target.reseal()?;
        target.validate()?;
        self.authority = InMemoryAuthorityV1::CandidateOwner(owner);
        self.advance_journal_v1(target)?;
        Ok(false)
    }

    pub(super) fn checkpoint_candidate_owner_v1(
        &mut self,
        candidate_finality: &VerifiedOrderFinalityV1,
        sources: &mut GlobalExecutionSourcesV1<'_>,
    ) -> ResultV1<bool> {
        self.require_candidate_finality_v1(candidate_finality)?;
        match self.current.phase {
            PocoNodeG2OrderCommitPhaseV1::SourcesApplied
            | PocoNodeG2OrderCommitPhaseV1::CandidateOwnerCheckpointed => {}
            _ => {
                return reject(
                    PocoNodeG2OrderCommitErrorCodeV1::WrongPhase,
                    "candidate owner checkpoint requires S or exact O_c replay",
                )
            }
        }
        let replay = self.current.phase == PocoNodeG2OrderCommitPhaseV1::CandidateOwnerCheckpointed;
        let owner = self.take_or_recover_owner_v1(candidate_finality, sources)?;
        let finalized = match self.global.finalize_terminal_facts_v1(&owner) {
            Ok(finalized) => finalized,
            Err(cause) => {
                self.authority = InMemoryAuthorityV1::CandidateOwner(owner);
                return Err(upstream_v1("global terminal checkpoint", cause));
            }
        };
        if finalized.candidate_height() != self.current.candidate_height
            || finalized.candidate_block_id().0 != self.current.candidate_block_id
            || finalized.final_execution_root().0
                != self.current.final_execution_root.ok_or_else(|| {
                    PocoNodeG2OrderCommitErrorV1 {
                        code: PocoNodeG2OrderCommitErrorCodeV1::JournalTamper,
                        detail: "S record has no final execution root".to_owned(),
                    }
                })?
        {
            self.authority = InMemoryAuthorityV1::CandidateOwner(owner);
            return reject(
                PocoNodeG2OrderCommitErrorCodeV1::GlobalStoreMismatch,
                "global terminal readback differs from exact candidate owner",
            );
        }
        self.authority = InMemoryAuthorityV1::CandidateOwner(owner);
        if replay {
            if self.current.terminal_generation != Some(finalized.checkpoint_generation())
                || self.current.terminal_checkpoint_checksum
                    != Some(finalized.checkpoint_checksum().0)
            {
                return reject(
                    PocoNodeG2OrderCommitErrorCodeV1::GlobalStoreMismatch,
                    "replayed global checkpoint differs from O_c journal",
                );
            }
            return Ok(true);
        }
        let mut target = self
            .current
            .successor(PocoNodeG2OrderCommitPhaseV1::CandidateOwnerCheckpointed)?;
        target.terminal_generation = Some(finalized.checkpoint_generation());
        target.terminal_checkpoint_checksum = Some(finalized.checkpoint_checksum().0);
        target.reseal()?;
        target.validate()?;
        self.advance_journal_v1(target)?;
        Ok(false)
    }

    pub(super) fn prepare_materialization_v1(
        &mut self,
        candidate_finality: &VerifiedOrderFinalityV1,
        sources: &mut GlobalExecutionSourcesV1<'_>,
        template: OrderHeaderTemplateV1,
    ) -> ResultV1<bool> {
        self.require_candidate_finality_v1(candidate_finality)?;
        match self.current.phase {
            PocoNodeG2OrderCommitPhaseV1::CandidateOwnerCheckpointed
            | PocoNodeG2OrderCommitPhaseV1::MaterializationPrepared => {}
            _ => {
                return reject(
                    PocoNodeG2OrderCommitErrorCodeV1::WrongPhase,
                    "materialization preview requires O_c or exact P_m replay",
                )
            }
        }
        let replay = self.current.phase == PocoNodeG2OrderCommitPhaseV1::MaterializationPrepared;
        if replay {
            if let InMemoryAuthorityV1::MaterializationPreview { prepared, .. } = &self.authority {
                if self.current.materialization_plan.as_ref()
                    != Some(&MaterializationPlanFactsV1::from_prepared(prepared))
                    || !template_matches_header_v1(&template, prepared.header())
                {
                    return reject(
                        PocoNodeG2OrderCommitErrorCodeV1::PlanMismatch,
                        "retained P_m authority or replay template differs",
                    );
                }
                return Ok(true);
            }
        }
        let owner = self.take_or_recover_owner_v1(candidate_finality, sources)?;
        let (prepared, parent) =
            match self.build_materialization_plan_v1(&owner, candidate_finality, template) {
                Ok(value) => value,
                Err(cause) => {
                    self.authority = InMemoryAuthorityV1::CandidateOwner(owner);
                    return Err(cause);
                }
            };
        let plan = MaterializationPlanFactsV1::from_prepared(&prepared);
        if replay {
            if self.current.materialization_plan.as_ref() != Some(&plan) {
                self.authority = InMemoryAuthorityV1::CandidateOwner(owner);
                return reject(
                    PocoNodeG2OrderCommitErrorCodeV1::PlanMismatch,
                    "recovered materialization plan differs from durable P_m",
                );
            }
        } else {
            let mut target = self
                .current
                .successor(PocoNodeG2OrderCommitPhaseV1::MaterializationPrepared)?;
            target.materialization_plan = Some(plan);
            target.reseal()?;
            target.validate()?;
            self.authority = InMemoryAuthorityV1::MaterializationPreview {
                owner,
                prepared,
                parent,
            };
            self.advance_journal_v1(target)?;
            return Ok(false);
        }
        self.authority = InMemoryAuthorityV1::MaterializationPreview {
            owner,
            prepared,
            parent,
        };
        Ok(true)
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn bind_materialization_v1(
        &mut self,
        candidate_finality: &VerifiedOrderFinalityV1,
        sources: &mut GlobalExecutionSourcesV1<'_>,
        template: OrderHeaderTemplateV1,
        materialization_finality: VerifiedOrderFinalityV1,
    ) -> ResultV1<bool> {
        self.require_candidate_finality_v1(candidate_finality)?;
        match self.current.phase {
            PocoNodeG2OrderCommitPhaseV1::MaterializationPrepared
            | PocoNodeG2OrderCommitPhaseV1::MaterializationFinality
            | PocoNodeG2OrderCommitPhaseV1::MaterializationBound => {}
            _ => {
                return reject(
                    PocoNodeG2OrderCommitErrorCodeV1::WrongPhase,
                    "materialization bind requires P_m/F_m/B_m",
                )
            }
        }
        let supplied_finality = FinalityFactsV1::from_verified(&materialization_finality);
        self.validate_materialization_finality_v1(&supplied_finality)?;
        if self.current.phase >= PocoNodeG2OrderCommitPhaseV1::MaterializationFinality
            && self.current.materialization_finality.as_ref() != Some(&supplied_finality)
        {
            return reject(
                PocoNodeG2OrderCommitErrorCodeV1::MaterializationFinalityMismatch,
                "supplied later finality differs from durable F_m",
            );
        }
        if self.current.phase == PocoNodeG2OrderCommitPhaseV1::MaterializationPrepared {
            let mut target = self
                .current
                .successor(PocoNodeG2OrderCommitPhaseV1::MaterializationFinality)?;
            target.materialization_finality = Some(supplied_finality.clone());
            target.reseal()?;
            target.validate()?;
            self.advance_journal_v1(target)?;
        }
        if self.current.phase == PocoNodeG2OrderCommitPhaseV1::MaterializationBound
            && matches!(
                &self.authority,
                InMemoryAuthorityV1::MaterializationPermit(_)
            )
        {
            return Ok(true);
        }

        if !matches!(
            &self.authority,
            InMemoryAuthorityV1::MaterializationPreview { .. }
        ) {
            self.rebuild_preview_v1(candidate_finality, sources, template)?;
        }
        let authority = std::mem::replace(&mut self.authority, InMemoryAuthorityV1::Recoverable);
        let InMemoryAuthorityV1::MaterializationPreview {
            owner,
            prepared,
            parent,
        } = authority
        else {
            self.authority = authority;
            return reject(
                PocoNodeG2OrderCommitErrorCodeV1::WrongPhase,
                "materialization preview authority is unavailable",
            );
        };
        let permit = self
            .canonical_order
            .issue_finalized_prepared_order_apply_v1(
                owner,
                materialization_finality,
                prepared,
                &parent,
            )
            .map_err(|cause| upstream_v1("owner/finality/membership binding", cause))?;
        self.authority = InMemoryAuthorityV1::MaterializationPermit(permit);
        if self.current.phase == PocoNodeG2OrderCommitPhaseV1::MaterializationFinality {
            let mut target = self
                .current
                .successor(PocoNodeG2OrderCommitPhaseV1::MaterializationBound)?;
            target.reseal()?;
            target.validate()?;
            self.advance_journal_v1(target)?;
            Ok(false)
        } else {
            Ok(true)
        }
    }

    pub(super) fn apply_materialization_v1(&mut self) -> ResultV1<bool> {
        match self.current.phase {
            PocoNodeG2OrderCommitPhaseV1::MaterializationBound => {}
            PocoNodeG2OrderCommitPhaseV1::MaterializationApplied => {
                return match &self.authority {
                    InMemoryAuthorityV1::Applied(_) => Ok(true),
                    _ => reject(
                        PocoNodeG2OrderCommitErrorCodeV1::WrongPhase,
                        "durable A_m requires explicit context-bearing applied-owner recovery",
                    ),
                }
            }
            _ => {
                return reject(
                    PocoNodeG2OrderCommitErrorCodeV1::WrongPhase,
                    "canonical materialization apply requires B_m",
                )
            }
        }
        let authority = std::mem::replace(&mut self.authority, InMemoryAuthorityV1::FailedClosed);
        let InMemoryAuthorityV1::MaterializationPermit(permit) = authority else {
            self.authority = authority;
            return reject(
                PocoNodeG2OrderCommitErrorCodeV1::WrongPhase,
                "canonical materialization permit is unavailable; rebind verified finality",
            );
        };
        let applied = match self
            .canonical_order
            .apply_finalized_prepared_order_block_v1(permit)
        {
            Ok(applied) => applied,
            Err(failure) => {
                let detail = format!("canonical apply failed: {}", failure.cause());
                self.authority =
                    InMemoryAuthorityV1::MaterializationPermit(failure.into_retry_permit());
                return reject(PocoNodeG2OrderCommitErrorCodeV1::UpstreamRejected, detail);
            }
        };
        let (materialized, membership_proof_digest) =
            match self.validated_applied_facts_v1(&applied) {
                Ok(facts) => facts,
                Err(cause) => {
                    self.authority = InMemoryAuthorityV1::Applied(applied);
                    return Err(cause);
                }
            };
        self.authority = InMemoryAuthorityV1::Applied(applied);
        let mut target = self
            .current
            .successor(PocoNodeG2OrderCommitPhaseV1::MaterializationApplied)?;
        target.materialized_pin = Some(materialized);
        target.materialized_membership_proof_digest = Some(membership_proof_digest);
        target.reseal()?;
        target.validate()?;
        self.advance_journal_v1(target)?;
        Ok(false)
    }

    /// Rebuild the linear applied owner after process loss at B_m/A_m/G.
    ///
    /// This is intentionally not a journal-only reopen. The caller must
    /// resupply exact candidate finality, live five-plane recovery sources,
    /// the durable materialization header template, and exact later finality.
    /// The canonical store then replays its private seal against a freshly
    /// reconstructed predecessor and performs no write.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn recover_applied_materialization_v1(
        &mut self,
        candidate_finality: &VerifiedOrderFinalityV1,
        sources: &mut GlobalExecutionSourcesV1<'_>,
        template: OrderHeaderTemplateV1,
        materialization_finality: VerifiedOrderFinalityV1,
    ) -> ResultV1<bool> {
        self.require_candidate_finality_v1(candidate_finality)?;
        if !matches!(
            self.current.phase,
            PocoNodeG2OrderCommitPhaseV1::MaterializationBound
                | PocoNodeG2OrderCommitPhaseV1::MaterializationApplied
                | PocoNodeG2OrderCommitPhaseV1::Complete
        ) {
            return reject(
                PocoNodeG2OrderCommitErrorCodeV1::WrongPhase,
                "applied-owner recovery requires exact B_m, A_m, or G",
            );
        }
        let supplied_finality = FinalityFactsV1::from_verified(&materialization_finality);
        self.validate_materialization_finality_v1(&supplied_finality)?;
        if self.current.materialization_finality.as_ref() != Some(&supplied_finality) {
            return reject(
                PocoNodeG2OrderCommitErrorCodeV1::MaterializationFinalityMismatch,
                "recovery finality differs from durable F_m",
            );
        }
        let durable_plan = self.current.materialization_plan.as_ref().ok_or_else(|| {
            PocoNodeG2OrderCommitErrorV1 {
                code: PocoNodeG2OrderCommitErrorCodeV1::JournalTamper,
                detail: "applied-owner recovery has no durable P_m".to_owned(),
            }
        })?;
        let durable_header = decode_block_header_v1(&durable_plan.header_cev1).map_err(|_| {
            PocoNodeG2OrderCommitErrorV1 {
                code: PocoNodeG2OrderCommitErrorCodeV1::JournalTamper,
                detail: "applied-owner recovery P_m header cannot decode".to_owned(),
            }
        })?;
        if !template_matches_header_v1(&template, &durable_header) {
            return reject(
                PocoNodeG2OrderCommitErrorCodeV1::PlanMismatch,
                "recovery header template differs from durable P_m",
            );
        }
        let expected_parent = self.current.canonical_parent.to_external_trusted_pin_v1()?;
        let expected_target = self
            .canonical_order
            .fresh_head_pin_v1()
            .map_err(|cause| upstream_v1("canonical recovery target readback", cause))?;
        let observed_target = CanonicalPinFactsV1::from_pin(&expected_target);
        if observed_target.store_id != self.current.canonical_parent.store_id
            || observed_target.height != durable_header.height
            || observed_target.block_id != durable_plan.block_id
            || observed_target.state_root != durable_plan.post_state_root
            || self
                .current
                .materialized_pin
                .as_ref()
                .is_some_and(|pin| pin != &observed_target)
        {
            return reject(
                PocoNodeG2OrderCommitErrorCodeV1::CanonicalStoreMismatch,
                "fresh canonical recovery target differs from durable P_m/A_m",
            );
        }
        if matches!(&self.authority, InMemoryAuthorityV1::Applied(_)) {
            let authority =
                std::mem::replace(&mut self.authority, InMemoryAuthorityV1::FailedClosed);
            let applied = match authority {
                InMemoryAuthorityV1::Applied(applied) => applied,
                other => {
                    self.authority = other;
                    return reject(
                        PocoNodeG2OrderCommitErrorCodeV1::WrongPhase,
                        "retained applied authority changed during recovery",
                    );
                }
            };
            let (materialized, membership_proof_digest) =
                match self.validated_applied_facts_v1(&applied) {
                    Ok(facts) => facts,
                    Err(cause) => {
                        self.authority = InMemoryAuthorityV1::Applied(applied);
                        return Err(cause);
                    }
                };
            self.authority = InMemoryAuthorityV1::Applied(applied);
            if self.current.phase >= PocoNodeG2OrderCommitPhaseV1::MaterializationApplied {
                if self.current.materialized_pin.as_ref() != Some(&materialized)
                    || self.current.materialized_membership_proof_digest
                        != Some(membership_proof_digest)
                {
                    return reject(
                        PocoNodeG2OrderCommitErrorCodeV1::JournalFork,
                        "retained applied receipt differs from durable A_m",
                    );
                }
                return Ok(true);
            }
            let mut target = self
                .current
                .successor(PocoNodeG2OrderCommitPhaseV1::MaterializationApplied)?;
            target.materialized_pin = Some(materialized);
            target.materialized_membership_proof_digest = Some(membership_proof_digest);
            target.reseal()?;
            target.validate()?;
            self.advance_journal_v1(target)?;
            return Ok(false);
        }

        let owner = self.take_or_recover_owner_v1(candidate_finality, sources)?;
        let context = ProtocolContextV1 {
            schema_version: JOURNAL_SCHEMA_V1,
            genesis_hash: candidate_finality.genesis_hash(),
            chain_id: candidate_finality.chain_id().to_owned(),
            protocol_version: candidate_finality.protocol_version(),
            stack_profile_hash: candidate_finality.stack_profile_hash(),
        };
        let binding = match GlobalExecutionBindingInputV1::new(
            context,
            owner.candidate_height(),
            BlockIdV1::new(owner.candidate_block_id().0),
            owner.candidate_composite_root().0,
            owner.final_execution_root().0,
        ) {
            Ok(binding) => binding,
            Err(cause) => {
                self.authority = InMemoryAuthorityV1::CandidateOwner(owner);
                return Err(upstream_v1("recovery execution-binding input", cause));
            }
        };
        let prepared = match self
            .canonical_order
            .recover_committed_prepared_order_block_v1(
                &expected_parent,
                &expected_target,
                template,
                &[OrderApplicationOperationV1::CreateGlobalExecutionBinding(
                    binding,
                )],
            ) {
            Ok(prepared) => prepared,
            Err(cause) => {
                self.authority = InMemoryAuthorityV1::CandidateOwner(owner);
                return Err(upstream_v1(
                    "committed materialization plan recovery",
                    cause,
                ));
            }
        };
        if self.current.materialization_plan.as_ref()
            != Some(&MaterializationPlanFactsV1::from_prepared(&prepared))
        {
            self.authority = InMemoryAuthorityV1::CandidateOwner(owner);
            return reject(
                PocoNodeG2OrderCommitErrorCodeV1::PlanMismatch,
                "recovered committed plan differs from durable P_m",
            );
        }
        self.authority = InMemoryAuthorityV1::Recoverable;
        let applied = match self
            .canonical_order
            .recover_applied_finalized_order_state_owner_v1(
                owner,
                materialization_finality,
                prepared,
                &expected_parent,
                &expected_target,
            ) {
            Ok(applied) => applied,
            Err(cause) => {
                return Err(upstream_v1("canonical applied-owner recovery", cause));
            }
        };
        let (materialized, membership_proof_digest) =
            match self.validated_applied_facts_v1(&applied) {
                Ok(facts) => facts,
                Err(cause) => {
                    self.authority = InMemoryAuthorityV1::Applied(applied);
                    return Err(cause);
                }
            };
        if self.current.phase >= PocoNodeG2OrderCommitPhaseV1::MaterializationApplied {
            if self.current.materialized_pin.as_ref() != Some(&materialized)
                || self.current.materialized_membership_proof_digest
                    != Some(membership_proof_digest)
            {
                self.authority = InMemoryAuthorityV1::Applied(applied);
                return reject(
                    PocoNodeG2OrderCommitErrorCodeV1::JournalFork,
                    "recovered applied receipt differs from durable A_m",
                );
            }
            self.authority = InMemoryAuthorityV1::Applied(applied);
            return Ok(true);
        }

        self.authority = InMemoryAuthorityV1::Applied(applied);
        let mut target = self
            .current
            .successor(PocoNodeG2OrderCommitPhaseV1::MaterializationApplied)?;
        target.materialized_pin = Some(materialized);
        target.materialized_membership_proof_digest = Some(membership_proof_digest);
        target.reseal()?;
        target.validate()?;
        self.advance_journal_v1(target)?;
        Ok(false)
    }

    pub(super) fn complete_v1(&mut self) -> ResultV1<PocoNodeG2OrderCommitCompletedV1> {
        match self.current.phase {
            PocoNodeG2OrderCommitPhaseV1::MaterializationApplied => {
                let mut target = self
                    .current
                    .successor(PocoNodeG2OrderCommitPhaseV1::Complete)?;
                target.completion_digest = Some(completion_digest_v1(&target)?);
                target.reseal()?;
                target.validate()?;
                self.advance_journal_v1(target)?;
            }
            PocoNodeG2OrderCommitPhaseV1::Complete => {}
            _ => {
                return reject(
                    PocoNodeG2OrderCommitErrorCodeV1::WrongPhase,
                    "G completion requires exact A_m",
                )
            }
        }
        let authority = std::mem::replace(&mut self.authority, InMemoryAuthorityV1::FailedClosed);
        let InMemoryAuthorityV1::Applied(applied) = authority else {
            return reject(
                PocoNodeG2OrderCommitErrorCodeV1::WrongPhase,
                "G journal facts require explicit context-bearing applied-owner recovery",
            );
        };
        Ok(PocoNodeG2OrderCommitCompletedV1 {
            applied,
            journal_pin: self.current.pin(),
        })
    }

    fn advance_journal_v1(&mut self, target: JournalRecordV1) -> ResultV1<()> {
        let observed = self.journal.advance_v1(&self.current, &target)?;
        if observed != target {
            return reject(
                PocoNodeG2OrderCommitErrorCodeV1::JournalThirdState,
                "journal mandatory target readback differs",
            );
        }
        self.current = observed;
        Ok(())
    }

    fn require_candidate_finality_v1(
        &self,
        candidate_finality: &VerifiedOrderFinalityV1,
    ) -> ResultV1<()> {
        if !self
            .current
            .candidate_finality
            .matches_verified(candidate_finality)
        {
            return reject(
                PocoNodeG2OrderCommitErrorCodeV1::CandidateFinalityMismatch,
                "candidate finality differs from durable F_c",
            );
        }
        Ok(())
    }

    fn validate_owner_v1(&self, owner: &WholeNodeFinalizationOwnerV1) -> ResultV1<()> {
        if owner.candidate_height() != self.current.candidate_height
            || owner.candidate_block_id().0 != self.current.candidate_block_id
            || owner.candidate_composite_root().0 != self.current.candidate_composite_root
            || owner.final_execution_root().0 == [0; 32]
            || self
                .current
                .final_execution_root
                .is_some_and(|root| root != owner.final_execution_root().0)
        {
            return reject(
                PocoNodeG2OrderCommitErrorCodeV1::GlobalStoreMismatch,
                "global terminal owner differs from journal candidate facts",
            );
        }
        Ok(())
    }

    fn ensure_candidate_owner_v1(
        &mut self,
        candidate_finality: &VerifiedOrderFinalityV1,
        sources: &mut GlobalExecutionSourcesV1<'_>,
    ) -> ResultV1<()> {
        if matches!(&self.authority, InMemoryAuthorityV1::CandidateOwner(_)) {
            return Ok(());
        }
        let owner = self
            .global
            .recover_finalization_owner_v1(candidate_finality, sources)
            .map_err(|cause| upstream_v1("global terminal-owner recovery", cause))?;
        self.validate_owner_v1(&owner)?;
        self.authority = InMemoryAuthorityV1::CandidateOwner(owner);
        Ok(())
    }

    fn take_or_recover_owner_v1(
        &mut self,
        candidate_finality: &VerifiedOrderFinalityV1,
        sources: &mut GlobalExecutionSourcesV1<'_>,
    ) -> ResultV1<WholeNodeFinalizationOwnerV1> {
        let authority = std::mem::replace(&mut self.authority, InMemoryAuthorityV1::Recoverable);
        match authority {
            InMemoryAuthorityV1::CandidateOwner(owner) => Ok(owner),
            InMemoryAuthorityV1::Recoverable => {
                let owner = self
                    .global
                    .recover_finalization_owner_v1(candidate_finality, sources)
                    .map_err(|cause| upstream_v1("global terminal-owner recovery", cause))?;
                self.validate_owner_v1(&owner)?;
                Ok(owner)
            }
            other => {
                self.authority = other;
                reject(
                    PocoNodeG2OrderCommitErrorCodeV1::WrongPhase,
                    "candidate terminal owner is not the current linear authority",
                )
            }
        }
    }

    fn build_materialization_plan_v1(
        &self,
        owner: &WholeNodeFinalizationOwnerV1,
        candidate_finality: &VerifiedOrderFinalityV1,
        template: OrderHeaderTemplateV1,
    ) -> ResultV1<(PreparedOrderBlockV1, CanonicalOrderStateHeadPinV1)> {
        self.validate_owner_v1(owner)?;
        let parent = self
            .canonical_order
            .fresh_head_pin_v1()
            .map_err(|cause| upstream_v1("canonical parent readback", cause))?;
        if !self.current.canonical_parent.matches_pin(&parent) {
            return reject(
                PocoNodeG2OrderCommitErrorCodeV1::CanonicalStoreMismatch,
                "canonical parent differs from durable F_c pin",
            );
        }
        let recovered = self
            .canonical_order
            .recover_order_application_parent_v1(&parent)
            .map_err(|cause| upstream_v1("canonical parent recovery", cause))?;
        let context = ProtocolContextV1 {
            schema_version: JOURNAL_SCHEMA_V1,
            genesis_hash: candidate_finality.genesis_hash(),
            chain_id: candidate_finality.chain_id().to_owned(),
            protocol_version: candidate_finality.protocol_version(),
            stack_profile_hash: candidate_finality.stack_profile_hash(),
        };
        if protocol_context_digest_v1(&context) != self.current.candidate_finality.context_digest
            || template.context != context
        {
            return reject(
                PocoNodeG2OrderCommitErrorCodeV1::PlanMismatch,
                "materialization template context differs from candidate finality",
            );
        }
        let binding = GlobalExecutionBindingInputV1::new(
            context,
            owner.candidate_height(),
            BlockIdV1::new(owner.candidate_block_id().0),
            owner.candidate_composite_root().0,
            owner.final_execution_root().0,
        )
        .map_err(|cause| upstream_v1("inert execution-binding input", cause))?;
        let prepared = self
            .canonical_order
            .preview_next_from_recovered_parent_v1(
                &recovered,
                template,
                &[OrderApplicationOperationV1::CreateGlobalExecutionBinding(
                    binding,
                )],
            )
            .map_err(|cause| upstream_v1("canonical materialization preview", cause))?;
        Ok((prepared, parent))
    }

    fn rebuild_preview_v1(
        &mut self,
        candidate_finality: &VerifiedOrderFinalityV1,
        sources: &mut GlobalExecutionSourcesV1<'_>,
        template: OrderHeaderTemplateV1,
    ) -> ResultV1<()> {
        let owner = self.take_or_recover_owner_v1(candidate_finality, sources)?;
        let (prepared, parent) =
            match self.build_materialization_plan_v1(&owner, candidate_finality, template) {
                Ok(value) => value,
                Err(cause) => {
                    self.authority = InMemoryAuthorityV1::CandidateOwner(owner);
                    return Err(cause);
                }
            };
        if self.current.materialization_plan.as_ref()
            != Some(&MaterializationPlanFactsV1::from_prepared(&prepared))
        {
            self.authority = InMemoryAuthorityV1::CandidateOwner(owner);
            return reject(
                PocoNodeG2OrderCommitErrorCodeV1::PlanMismatch,
                "rebuilt materialization plan differs from durable P_m",
            );
        }
        self.authority = InMemoryAuthorityV1::MaterializationPreview {
            owner,
            prepared,
            parent,
        };
        Ok(())
    }

    fn validate_materialization_finality_v1(&self, finality: &FinalityFactsV1) -> ResultV1<()> {
        let plan = self.current.materialization_plan.as_ref().ok_or_else(|| {
            PocoNodeG2OrderCommitErrorV1 {
                code: PocoNodeG2OrderCommitErrorCodeV1::PlanMismatch,
                detail: "materialization finality has no durable plan".to_owned(),
            }
        })?;
        let header = decode_block_header_v1(&plan.header_cev1).map_err(|_| {
            PocoNodeG2OrderCommitErrorV1 {
                code: PocoNodeG2OrderCommitErrorCodeV1::PlanMismatch,
                detail: "durable materialization header cannot decode".to_owned(),
            }
        })?;
        if !finality.validate()
            || finality.context_digest != self.current.candidate_finality.context_digest
            || finality.pinned_trust_sha256 != self.current.candidate_finality.pinned_trust_sha256
            || finality.epoch != header.epoch
            || finality.height != header.height
            || finality.block_id != plan.block_id
            || finality.post_state_root != plan.post_state_root
            || finality.height <= self.current.candidate_height
        {
            return reject(
                PocoNodeG2OrderCommitErrorCodeV1::MaterializationFinalityMismatch,
                "later verified finality differs from exact materialization header/root",
            );
        }
        Ok(())
    }

    fn validated_applied_facts_v1(
        &self,
        applied: &AppliedFinalizedOrderStateOwnerV1,
    ) -> ResultV1<(CanonicalPinFactsV1, [u8; 32])> {
        let expected_receipt = match (
            self.current.materialization_finality.as_ref(),
            self.current.materialization_plan.as_ref(),
        ) {
            (Some(finality), Some(plan)) => (
                finality.pinned_trust_sha256,
                finality.proof_id,
                plan.plan_digest,
            ),
            _ => {
                return reject(
                    PocoNodeG2OrderCommitErrorCodeV1::JournalTamper,
                    "B_m/A_m lacks durable materialization finality or plan",
                )
            }
        };
        if applied.receipt().pinned_trust_sha256() != expected_receipt.0
            || applied.receipt().order_proof_id() != expected_receipt.1
            || applied.receipt().plan_digest() != expected_receipt.2
            || applied.receipt().observed_head_pin() != applied.receipt().pin()
        {
            return reject(
                PocoNodeG2OrderCommitErrorCodeV1::CanonicalStoreMismatch,
                "canonical receipt proof/trust/plan/head differs from exact B_m",
            );
        }
        let materialized = CanonicalPinFactsV1::from_pin(applied.receipt().pin());
        self.validate_materialized_pin_v1(&materialized)?;
        Ok((
            materialized,
            membership_proof_digest_v1(applied.receipt().proof()),
        ))
    }

    fn validate_materialized_pin_v1(&self, pin: &CanonicalPinFactsV1) -> ResultV1<()> {
        let plan = self.current.materialization_plan.as_ref().ok_or_else(|| {
            PocoNodeG2OrderCommitErrorV1 {
                code: PocoNodeG2OrderCommitErrorCodeV1::PlanMismatch,
                detail: "materialized pin has no durable plan".to_owned(),
            }
        })?;
        let header = decode_block_header_v1(&plan.header_cev1).map_err(|_| {
            PocoNodeG2OrderCommitErrorV1 {
                code: PocoNodeG2OrderCommitErrorCodeV1::PlanMismatch,
                detail: "materialized plan header cannot decode".to_owned(),
            }
        })?;
        if !pin.validate()
            || pin.store_id != self.current.canonical_parent.store_id
            || pin.height != header.height
            || pin.block_id != plan.block_id
            || pin.state_root != plan.post_state_root
        {
            return reject(
                PocoNodeG2OrderCommitErrorCodeV1::CanonicalStoreMismatch,
                "fresh materialized pin differs from exact plan/store",
            );
        }
        Ok(())
    }
}

fn validate_ready_finality_v1(
    ready: &PreVoteExecutionReadyV1,
    finality: &VerifiedOrderFinalityV1,
) -> ResultV1<()> {
    if ready.candidate_height() != finality.finalized_height()
        || ready.candidate_block_id().0 != finality.finalized_block_id()
        || ready.candidate_composite_root().0 == [0; 32]
        || !FinalityFactsV1::from_verified(finality).validate()
    {
        return reject(
            PocoNodeG2OrderCommitErrorCodeV1::CandidateFinalityMismatch,
            "verified F_c does not name the exact prepared candidate",
        );
    }
    Ok(())
}

fn validate_external_store_heads_v1(
    global: &PocoGlobalExecutionStoreV1,
    canonical_order: &PocoCanonicalOrderStateStoreV1,
    record: &JournalRecordV1,
) -> ResultV1<()> {
    let global_facts = global
        .fresh_checkpoint_facts_v1()
        .map_err(|cause| upstream_v1("global reopen", cause))?;
    if record.phase < PocoNodeG2OrderCommitPhaseV1::CandidateOwnerCheckpointed {
        let prepared_or_exact_terminal = (global_facts.generation() == record.prepared_generation
            && global_facts.checksum().0 == record.prepared_checkpoint_checksum
            && global_facts.final_execution_root().is_none())
            || (record.phase == PocoNodeG2OrderCommitPhaseV1::SourcesApplied
                && global_facts.generation()
                    == record.prepared_generation.checked_add(1).ok_or_else(|| {
                        PocoNodeG2OrderCommitErrorV1 {
                            code: PocoNodeG2OrderCommitErrorCodeV1::ArithmeticOverflow,
                            detail: "global terminal generation overflows".to_owned(),
                        }
                    })?
                && global_facts.final_execution_root().map(|root| root.0)
                    == record.final_execution_root);
        if !prepared_or_exact_terminal {
            return reject(
                PocoNodeG2OrderCommitErrorCodeV1::GlobalStoreMismatch,
                "global reopen differs from prepared/S journal cut",
            );
        }
    } else if global_facts.generation()
        != record
            .terminal_generation
            .ok_or_else(|| PocoNodeG2OrderCommitErrorV1 {
                code: PocoNodeG2OrderCommitErrorCodeV1::JournalTamper,
                detail: "O_c record has no terminal generation".to_owned(),
            })?
        || global_facts.checksum().0
            != record
                .terminal_checkpoint_checksum
                .ok_or_else(|| PocoNodeG2OrderCommitErrorV1 {
                    code: PocoNodeG2OrderCommitErrorCodeV1::JournalTamper,
                    detail: "O_c record has no terminal checksum".to_owned(),
                })?
        || global_facts.final_execution_root().map(|root| root.0) != record.final_execution_root
    {
        return reject(
            PocoNodeG2OrderCommitErrorCodeV1::GlobalStoreMismatch,
            "global terminal reopen differs from durable O_c",
        );
    }
    let canonical = canonical_order
        .fresh_head_pin_v1()
        .map_err(|cause| upstream_v1("canonical reopen", cause))?;
    let committed_after_bound =
        if record.phase == PocoNodeG2OrderCommitPhaseV1::MaterializationBound
            && !record.canonical_parent.matches_pin(&canonical)
        {
            let plan = record.materialization_plan.as_ref().ok_or_else(|| {
                PocoNodeG2OrderCommitErrorV1 {
                    code: PocoNodeG2OrderCommitErrorCodeV1::JournalTamper,
                    detail: "B_m record has no materialization plan".to_owned(),
                }
            })?;
            let header = decode_block_header_v1(&plan.header_cev1).map_err(|_| {
                PocoNodeG2OrderCommitErrorV1 {
                    code: PocoNodeG2OrderCommitErrorCodeV1::JournalTamper,
                    detail: "B_m materialization header cannot decode".to_owned(),
                }
            })?;
            if canonical.store_id() == record.canonical_parent.store_id
                && canonical.height() == header.height
                && canonical.block_id().to_bytes() == plan.block_id
                && canonical.state_root() == plan.post_state_root
            {
                true
            } else {
                return reject(
                    PocoNodeG2OrderCommitErrorCodeV1::CanonicalStoreMismatch,
                    "canonical head after B_m is neither parent nor exact committed target",
                );
            }
        } else {
            false
        };
    let expected = if record.phase < PocoNodeG2OrderCommitPhaseV1::MaterializationApplied {
        &record.canonical_parent
    } else {
        record
            .materialized_pin
            .as_ref()
            .ok_or_else(|| PocoNodeG2OrderCommitErrorV1 {
                code: PocoNodeG2OrderCommitErrorCodeV1::JournalTamper,
                detail: "A_m record has no materialized pin".to_owned(),
            })?
    };
    if !committed_after_bound && !expected.matches_pin(&canonical) {
        return reject(
            PocoNodeG2OrderCommitErrorCodeV1::CanonicalStoreMismatch,
            "canonical Order reopen differs from durable parent/materialized pin",
        );
    }
    Ok(())
}

fn upstream_v1(label: &str, cause: impl fmt::Display) -> PocoNodeG2OrderCommitErrorV1 {
    PocoNodeG2OrderCommitErrorV1 {
        code: PocoNodeG2OrderCommitErrorCodeV1::UpstreamRejected,
        detail: format!("{label} rejected: {cause}"),
    }
}

#[cfg(test)]
mod tests {
    use tempfile::TempDir;
    use trnm_poco_order_types_v1::{
        empty_ordered_root_v1, EpochDescriptorIdV1, QuorumCertificateIdV1,
    };

    use super::*;

    const JOURNAL_ID: [u8; 32] = [0x11; 32];
    const SCOPE: [u8; 32] = [0x22; 32];

    fn private_directory(path: &Path) {
        fs::create_dir(path).expect("create isolated test namespace");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(path, fs::Permissions::from_mode(0o700))
                .expect("set isolated namespace mode");
        }
    }

    fn namespaces() -> (TempDir, PocoNodeG2OrderCommitNamespacesV1) {
        let temp = tempfile::tempdir().expect("G2 journal tempdir");
        let journal = temp.path().join("journal");
        let global = temp.path().join("global");
        let canonical = temp.path().join("canonical");
        private_directory(&journal);
        private_directory(&global);
        private_directory(&canonical);
        let namespaces = PocoNodeG2OrderCommitNamespacesV1::new(journal, global, canonical)
            .expect("three disjoint private namespaces");
        (temp, namespaces)
    }

    fn context() -> ProtocolContextV1 {
        ProtocolContextV1 {
            schema_version: 1,
            genesis_hash: [0x31; 32],
            chain_id: "trnm-g2-order-host-test".to_owned(),
            protocol_version: 1,
            stack_profile_hash: [0x32; 32],
        }
    }

    fn materialization_header(parent: &CanonicalPinFactsV1) -> BlockHeaderV1 {
        BlockHeaderV1 {
            schema_version: 1,
            context: context(),
            epoch: 1,
            view: 21,
            height: parent.height + 1,
            block_kind: BlockKindV1::Ordinary,
            parent: ParentBlockRefV1::V1Block(BlockIdV1::new(parent.block_id)),
            proposer_id: b"validator-a".to_vec(),
            epoch_descriptor_id: EpochDescriptorIdV1::new([0x41; 32]),
            justify_qc_id: Some(QuorumCertificateIdV1::new([0x42; 32])),
            timeout_certificate_id: None,
            batch_refs_root: empty_ordered_root_v1(0),
            protocol_objects_root: empty_ordered_root_v1(1),
            post_state_root: [0x43; 32],
            transaction_execution_receipts_root: empty_ordered_root_v1(2),
            evidence_root: empty_ordered_root_v1(3),
            consumption_rollups_root: empty_ordered_root_v1(4),
            settlement_root: empty_ordered_root_v1(5),
            resource_usage_root: empty_ordered_root_v1(6),
            next_epoch_descriptor_id: None,
            upgrade_plan_id: None,
            epoch_handoff_id: None,
        }
    }

    fn synthetic_anchor() -> JournalRecordV1 {
        let canonical_parent = CanonicalPinFactsV1 {
            store_id: [0x51; 32],
            height: 10,
            block_id: [0x52; 32],
            state_root: [0x53; 32],
            history_checksum: [0x54; 32],
        };
        let mut record = JournalRecordV1 {
            journal_id: JOURNAL_ID,
            scope: SCOPE,
            sequence: 0,
            phase: PocoNodeG2OrderCommitPhaseV1::CandidateFinality,
            predecessor_checksum: [0; 32],
            prepared_generation: 1,
            prepared_checkpoint_checksum: [0x61; 32],
            candidate_height: 9,
            candidate_block_id: [0x62; 32],
            candidate_composite_root: [0x63; 32],
            candidate_finality: FinalityFactsV1 {
                context_digest: protocol_context_digest_v1(&context()),
                pinned_trust_sha256: [0x64; 32],
                proof_id: [0x65; 32],
                epoch: 1,
                height: 9,
                block_id: [0x62; 32],
                post_state_root: [0x66; 32],
            },
            canonical_parent,
            final_execution_root: None,
            terminal_generation: None,
            terminal_checkpoint_checksum: None,
            materialization_plan: None,
            materialization_finality: None,
            materialized_pin: None,
            materialized_membership_proof_digest: None,
            completion_digest: None,
            checksum: [0; 32],
        };
        record.reseal().expect("seal synthetic F_c");
        record.validate().expect("validate synthetic F_c");
        record
    }

    fn synthetic_successor(
        source: &JournalRecordV1,
        phase: PocoNodeG2OrderCommitPhaseV1,
    ) -> JournalRecordV1 {
        let mut target = source.successor(phase).expect("exact next synthetic phase");
        match phase {
            PocoNodeG2OrderCommitPhaseV1::SourcesApplied => {
                target.final_execution_root = Some([0x71; 32]);
            }
            PocoNodeG2OrderCommitPhaseV1::CandidateOwnerCheckpointed => {
                target.terminal_generation = Some(2);
                target.terminal_checkpoint_checksum = Some([0x72; 32]);
            }
            PocoNodeG2OrderCommitPhaseV1::MaterializationPrepared => {
                let header = materialization_header(&target.canonical_parent);
                target.materialization_plan = Some(MaterializationPlanFactsV1 {
                    header_cev1: header.to_cev1_bytes(),
                    block_id: derive_block_id_v1(&header).to_bytes(),
                    plan_digest: [0x73; 32],
                    post_state_root: header.post_state_root,
                });
            }
            PocoNodeG2OrderCommitPhaseV1::MaterializationFinality => {
                let plan = target
                    .materialization_plan
                    .as_ref()
                    .expect("P_m precedes F_m");
                let header =
                    decode_block_header_v1(&plan.header_cev1).expect("decode synthetic P_m");
                target.materialization_finality = Some(FinalityFactsV1 {
                    context_digest: protocol_context_digest_v1(&header.context),
                    pinned_trust_sha256: target.candidate_finality.pinned_trust_sha256,
                    proof_id: [0x75; 32],
                    epoch: header.epoch,
                    height: header.height,
                    block_id: plan.block_id,
                    post_state_root: plan.post_state_root,
                });
            }
            PocoNodeG2OrderCommitPhaseV1::MaterializationBound => {}
            PocoNodeG2OrderCommitPhaseV1::MaterializationApplied => {
                let plan = target
                    .materialization_plan
                    .as_ref()
                    .expect("P_m precedes A_m");
                let header =
                    decode_block_header_v1(&plan.header_cev1).expect("decode synthetic P_m");
                target.materialized_pin = Some(CanonicalPinFactsV1 {
                    store_id: target.canonical_parent.store_id,
                    height: header.height,
                    block_id: plan.block_id,
                    state_root: plan.post_state_root,
                    history_checksum: [0x76; 32],
                });
                target.materialized_membership_proof_digest = Some([0x77; 32]);
            }
            PocoNodeG2OrderCommitPhaseV1::Complete => {
                target.completion_digest =
                    Some(completion_digest_v1(&target).expect("derive synthetic G digest"));
            }
            PocoNodeG2OrderCommitPhaseV1::CandidateFinality => {
                panic!("F_c is the journal anchor, not a successor")
            }
        }
        target.reseal().expect("seal synthetic phase");
        source
            .validate_successor(&target)
            .expect("validate synthetic exact successor");
        target
    }

    fn advance_to(
        journal: &SqliteG2OrderCommitJournalV1,
        mut current: JournalRecordV1,
        target_phase: PocoNodeG2OrderCommitPhaseV1,
    ) -> JournalRecordV1 {
        while current.phase < target_phase {
            let next = synthetic_successor(
                &current,
                current.phase.successor().expect("bounded phase successor"),
            );
            current = journal
                .advance_v1(&current, &next)
                .expect("advance synthetic journal");
        }
        current
    }

    #[test]
    fn phase_journal_recovers_every_crash_exact_retry_and_response_loss() {
        let (_temp, namespaces) = namespaces();
        let anchor = synthetic_anchor();
        let mut journal = SqliteG2OrderCommitJournalV1::initialize_new(&namespaces, &anchor)
            .expect("initialize F_c journal");
        let mut current = anchor;
        while let Some(phase) = current.phase.successor() {
            let target = synthetic_successor(&current, phase);
            assert_eq!(
                journal
                    .advance_with_fault_v1(&current, &target, JournalFaultV1::BeforeCommit)
                    .expect_err("each precommit crash is proven not applied")
                    .code_v1(),
                PocoNodeG2OrderCommitErrorCodeV1::JournalNotApplied,
            );
            assert_eq!(
                journal.head_v1().expect("head after precommit crash"),
                current
            );
            let observed = journal
                .advance_with_fault_v1(&current, &target, JournalFaultV1::AfterCommitBeforeReturn)
                .expect("fresh target resolves postcommit response loss");
            assert_eq!(observed, target);
            assert_eq!(
                journal
                    .advance_v1(&current, &target)
                    .expect("exact target replay"),
                target
            );
            let trusted = target.pin();
            let trusted = PocoNodeG2OrderCommitJournalPinV1::from_external_trusted_parts_v1(
                trusted.journal_id_v1(),
                trusted.scope_v1(),
                trusted.sequence_v1(),
                trusted.phase_v1(),
                trusted.checksum_v1(),
            )
            .expect("externally authenticated pin parts round-trip");
            drop(journal);
            journal = SqliteG2OrderCommitJournalV1::open_existing(&namespaces, &trusted)
                .expect("fresh reopen after every phase");
            current = target;
        }
        assert_eq!(current.phase, PocoNodeG2OrderCommitPhaseV1::Complete);
    }

    #[test]
    fn phase_journal_rejects_fork_finality_root_and_store_substitution() {
        let (_temp, namespaces) = namespaces();
        let anchor = synthetic_anchor();
        let journal = SqliteG2OrderCommitJournalV1::initialize_new(&namespaces, &anchor)
            .expect("initialize mutation journal");

        let source_target =
            synthetic_successor(&anchor, PocoNodeG2OrderCommitPhaseV1::SourcesApplied);
        let mut fork = source_target.clone();
        fork.candidate_block_id[0] ^= 1;
        fork.candidate_finality.block_id = fork.candidate_block_id;
        fork.reseal().expect("reseal candidate fork");
        fork.validate()
            .expect("candidate fork is internally coherent");
        assert_eq!(
            anchor
                .validate_successor(&fork)
                .expect_err("candidate fork differs from F_c")
                .code_v1(),
            PocoNodeG2OrderCommitErrorCodeV1::JournalFork,
        );

        let mut root = source_target.clone();
        root.candidate_composite_root[0] ^= 1;
        root.reseal().expect("reseal root substitution");
        root.validate()
            .expect("root substitution is structurally valid");
        assert_eq!(
            anchor
                .validate_successor(&root)
                .expect_err("candidate composite root substitution rejects")
                .code_v1(),
            PocoNodeG2OrderCommitErrorCodeV1::JournalFork,
        );

        let mut foreign_store = source_target.clone();
        foreign_store.canonical_parent.store_id[0] ^= 1;
        foreign_store.reseal().expect("reseal store substitution");
        foreign_store
            .validate()
            .expect("foreign store tuple is structurally valid");
        assert_eq!(
            anchor
                .validate_successor(&foreign_store)
                .expect_err("canonical store substitution rejects")
                .code_v1(),
            PocoNodeG2OrderCommitErrorCodeV1::JournalFork,
        );

        let fm = advance_to(
            &journal,
            anchor,
            PocoNodeG2OrderCommitPhaseV1::MaterializationFinality,
        );
        let bm = synthetic_successor(&fm, PocoNodeG2OrderCommitPhaseV1::MaterializationBound);
        let mut finality = bm.clone();
        finality
            .materialization_finality
            .as_mut()
            .expect("F_m retained")
            .proof_id[0] ^= 1;
        finality.reseal().expect("reseal finality substitution");
        finality
            .validate()
            .expect("alternate proof ID is structurally valid");
        assert_eq!(
            fm.validate_successor(&finality)
                .expect_err("durable F_m proof substitution rejects")
                .code_v1(),
            PocoNodeG2OrderCommitErrorCodeV1::JournalFork,
        );

        let mut plan_root = bm;
        let plan = plan_root
            .materialization_plan
            .as_mut()
            .expect("P_m retained");
        let mut header = decode_block_header_v1(&plan.header_cev1).expect("decode P_m");
        header.post_state_root[0] ^= 1;
        plan.header_cev1 = header.to_cev1_bytes();
        plan.block_id = derive_block_id_v1(&header).to_bytes();
        plan.post_state_root = header.post_state_root;
        let substituted_block_id = plan.block_id;
        let substituted_root = plan.post_state_root;
        let materialization_finality = plan_root
            .materialization_finality
            .as_mut()
            .expect("F_m retained");
        materialization_finality.block_id = substituted_block_id;
        materialization_finality.post_state_root = substituted_root;
        plan_root.reseal().expect("reseal plan-root substitution");
        plan_root
            .validate()
            .expect("forked plan is internally coherent");
        assert_eq!(
            fm.validate_successor(&plan_root)
                .expect_err("P_m header/root substitution rejects")
                .code_v1(),
            PocoNodeG2OrderCommitErrorCodeV1::JournalFork,
        );
    }

    #[test]
    fn external_pin_refuses_coherent_journal_rollback_and_namespace_overlap() {
        let (_temp, namespaces) = namespaces();
        let anchor = synthetic_anchor();
        let journal = SqliteG2OrderCommitJournalV1::initialize_new(&namespaces, &anchor)
            .expect("initialize rollback journal");
        let source_target =
            synthetic_successor(&anchor, PocoNodeG2OrderCommitPhaseV1::SourcesApplied);
        let source_target = journal
            .advance_v1(&anchor, &source_target)
            .expect("commit S before rollback");
        let trusted = source_target.pin();
        drop(journal);

        let connection = Connection::open(namespaces.journal_path())
            .expect("open raw coherent rollback connection");
        connection
            .execute(
                "DELETE FROM g2_order_commit_history_v1 WHERE sequence=?1",
                params![&source_target.sequence.to_be_bytes()[..]],
            )
            .expect("remove S history tail");
        connection
            .execute(
                "UPDATE g2_order_commit_metadata_v1 SET head_sequence=?1,head_phase=0,head_checksum=?2 WHERE singleton=1",
                params![&anchor.sequence.to_be_bytes()[..], &anchor.checksum[..]],
            )
            .expect("rewind metadata to coherent F_c");
        drop(connection);
        assert_eq!(
            SqliteG2OrderCommitJournalV1::open_existing(&namespaces, &trusted)
                .expect_err("external S pin refuses coherent F_c rollback")
                .code_v1(),
            PocoNodeG2OrderCommitErrorCodeV1::JournalRollback,
        );

        assert_eq!(
            PocoNodeG2OrderCommitNamespacesV1::new(
                namespaces.journal_directory.clone(),
                namespaces.journal_directory.clone(),
                namespaces.canonical_order_directory.clone(),
            )
            .expect_err("equal journal/global namespace rejects")
            .code_v1(),
            PocoNodeG2OrderCommitErrorCodeV1::InvalidNamespace,
        );
    }

    #[test]
    fn record_codec_and_applied_authority_boundary_fail_closed() {
        let mut current = synthetic_anchor();
        while let Some(phase) = current.phase.successor() {
            current = synthetic_successor(&current, phase);
            let encoded = current.encode().expect("encode phase record");
            assert_eq!(
                JournalRecordV1::decode_exact(&encoded).expect("exact phase decode"),
                current
            );
            let mut tampered = encoded;
            let middle = tampered.len() / 2;
            tampered[middle] ^= 1;
            assert_eq!(
                JournalRecordV1::decode_exact(&tampered)
                    .expect_err("record byte substitution rejects")
                    .code_v1(),
                PocoNodeG2OrderCommitErrorCodeV1::JournalTamper,
            );
        }
        let boundary = reject::<()>(
            PocoNodeG2OrderCommitErrorCodeV1::WrongPhase,
            "durable A_m/G facts require explicit finality/source/template recovery context",
        )
        .expect_err("raw applied-authority reconstruction stays unavailable");
        assert_eq!(
            boundary.code_v1(),
            PocoNodeG2OrderCommitErrorCodeV1::WrongPhase,
        );
    }
}

#[cfg(any(test, feature = "g2-process-test-support"))]
#[path = "g2_order_commit_v1_real_e2e.rs"]
pub(crate) mod real_e2e_tests;
