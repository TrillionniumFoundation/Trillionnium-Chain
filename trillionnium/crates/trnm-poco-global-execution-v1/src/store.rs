use std::{
    collections::BTreeSet,
    ffi::OsString,
    fs::{self, OpenOptions},
    path::{Path, PathBuf},
    time::Duration,
};

use rusqlite::{params, Connection, OpenFlags, OptionalExtension, TransactionBehavior};
use trnm_poco_agent_market_v1::{
    Hash32V1 as AgentHash32V1, KernelTransitionReceiptV1, OrderFinalizedExecutionContextV1,
    PocoAgentMarketStoreV1, ProtocolContextV1 as AgentProtocolContextV1,
};
use trnm_poco_consumption_settlement_v1::{
    ConsumptionOrderFinalizedExecutionContextV1, ConsumptionSettlementStoreV1,
    ConsumptionTransitionReceiptV1,
};
use trnm_poco_da_v1::PocoDaStoreV1;
use trnm_poco_mvcc_fee_v1::MvccFeeStoreV1;
use trnm_poco_order_finality_verifier_v1::{
    derive_global_execution_binding_create_material_v1, GlobalExecutionBindingCreateMaterialV1,
    VerifiedOrderFinalityV1, VerifiedOrderStateExecutionBindingV1,
};
use trnm_poco_verify_challenge_v1::{
    VerifyChallengeStoreV1, VerifyOrderFinalizedExecutionContextV1, VerifyTransitionReceiptV1,
};

use crate::{
    codec::{canonical_bytes, digest_value, strict_decode},
    error::{error, GlobalExecutionErrorCodeV1, GlobalExecutionResultV1},
    types::{
        CandidateCompositeCommitmentBodyV1, CheckpointBodyV1, CheckpointRecordV1, PlaneHeadV1,
        PlaneTerminalFactsV1, SourceCutV1, WholeNodeFinalizationBodyV1,
    },
    CandidateCompositeCommitmentV1, CandidateExecutionContextV1, GlobalExecutionBatchV1, Hash32V1,
    PreVoteProposalV1, WholeNodeFinalExecutionCommitmentV1,
};

const STORE_SCHEMA_VERSION_V1: u16 = 1;
const SQLITE_APPLICATION_ID_V1: i64 = 0x5452_4745;
const SQLITE_USER_VERSION_V1: i64 = 1;
const MAX_BATCH_ITEM_BYTES_V1: usize = 4 * 1024 * 1024;
const MAX_COMMANDS_PER_PLANE_V1: usize = 256;
const META_SQL: &str = "CREATE TABLE global_execution_metadata_v1 (singleton INTEGER PRIMARY KEY CHECK(singleton=1),generation BLOB NOT NULL CHECK(typeof(generation)='blob' AND length(generation)=8),checkpoint_checksum BLOB NOT NULL CHECK(typeof(checkpoint_checksum)='blob' AND length(checkpoint_checksum)=32),fenced INTEGER NOT NULL CHECK(fenced IN(0,1)),record BLOB NOT NULL CHECK(typeof(record)='blob' AND length(record)>0 AND length(record)<=4194304)) STRICT";
const CHECKPOINTS_SQL: &str = "CREATE TABLE global_execution_checkpoints_v1 (generation BLOB PRIMARY KEY CHECK(typeof(generation)='blob' AND length(generation)=8),checkpoint_checksum BLOB NOT NULL UNIQUE CHECK(typeof(checkpoint_checksum)='blob' AND length(checkpoint_checksum)=32),record_kind INTEGER NOT NULL CHECK(record_kind IN(0,1,2)),record BLOB NOT NULL CHECK(typeof(record)='blob' AND length(record)>0 AND length(record)<=4194304)) STRICT, WITHOUT ROWID";
const PREPARED_SQL: &str = "CREATE TABLE global_execution_prepared_v1 (candidate_block_id BLOB PRIMARY KEY CHECK(typeof(candidate_block_id)='blob' AND length(candidate_block_id)=32),generation BLOB NOT NULL UNIQUE CHECK(typeof(generation)='blob' AND length(generation)=8),candidate_composite_root BLOB NOT NULL CHECK(typeof(candidate_composite_root)='blob' AND length(candidate_composite_root)=32),checkpoint_checksum BLOB NOT NULL CHECK(typeof(checkpoint_checksum)='blob' AND length(checkpoint_checksum)=32),commitment BLOB NOT NULL CHECK(typeof(commitment)='blob' AND length(commitment)>0 AND length(commitment)<=4194304)) STRICT, WITHOUT ROWID";
const FINALIZED_SQL: &str = "CREATE TABLE global_execution_finalized_v1 (candidate_block_id BLOB PRIMARY KEY CHECK(typeof(candidate_block_id)='blob' AND length(candidate_block_id)=32),generation BLOB NOT NULL UNIQUE CHECK(typeof(generation)='blob' AND length(generation)=8),prepared_generation BLOB NOT NULL UNIQUE CHECK(typeof(prepared_generation)='blob' AND length(prepared_generation)=8),prepared_checkpoint_checksum BLOB NOT NULL UNIQUE CHECK(typeof(prepared_checkpoint_checksum)='blob' AND length(prepared_checkpoint_checksum)=32),candidate_composite_root BLOB NOT NULL CHECK(typeof(candidate_composite_root)='blob' AND length(candidate_composite_root)=32),final_execution_root BLOB NOT NULL UNIQUE CHECK(typeof(final_execution_root)='blob' AND length(final_execution_root)=32),checkpoint_checksum BLOB NOT NULL UNIQUE CHECK(typeof(checkpoint_checksum)='blob' AND length(checkpoint_checksum)=32),commitment BLOB NOT NULL CHECK(typeof(commitment)='blob' AND length(commitment)>0 AND length(commitment)<=4194304)) STRICT, WITHOUT ROWID";

type PreparedEvidenceRowV1 = (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>);
type FinalizedEvidenceRowV1 = (
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
);

/// Exclusive process-owner borrows for every source participating in one
/// candidate cut.  The mutable references prevent same-process concurrent
/// writes while preview/CAS/readback runs.  External writers are detected by
/// mandatory fresh source sampling and permanently fence the checkpoint.
pub struct GlobalExecutionSourcesV1<'a> {
    pub da: &'a mut PocoDaStoreV1,
    pub agent_market: &'a mut PocoAgentMarketStoreV1,
    pub verify_challenge: &'a mut VerifyChallengeStoreV1,
    pub mvcc_fee: &'a mut MvccFeeStoreV1,
    pub consumption_settlement: &'a mut ConsumptionSettlementStoreV1,
}

/// Fresh whole-node validation checkpoint facts used to form the next exact
/// compare-and-swap request.
#[derive(Debug)]
pub struct GlobalExecutionCheckpointFactsV1 {
    generation: u64,
    checksum: Hash32V1,
    source_cut_digest: Hash32V1,
    final_execution_root: Option<Hash32V1>,
}

impl GlobalExecutionCheckpointFactsV1 {
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    pub const fn checksum(&self) -> Hash32V1 {
        self.checksum
    }

    pub const fn source_cut_digest(&self) -> Hash32V1 {
        self.source_cut_digest
    }

    pub const fn final_execution_root(&self) -> Option<Hash32V1> {
        self.final_execution_root
    }
}

/// Successful candidate execution plus exact whole-node CAS target readback.
///
/// Fields are private, there is no decoder or constructor, and this type does
/// not implement `Clone` or `Copy`.
#[derive(Debug)]
pub struct PreVoteExecutionReadyV1 {
    checkpoint_generation: u64,
    checkpoint_checksum: Hash32V1,
    commitment: CandidateCompositeCommitmentV1,
}

impl PreVoteExecutionReadyV1 {
    pub const fn checkpoint_generation(&self) -> u64 {
        self.checkpoint_generation
    }

    pub const fn checkpoint_checksum(&self) -> Hash32V1 {
        self.checkpoint_checksum
    }

    pub const fn candidate_composite_root(&self) -> Hash32V1 {
        self.commitment.candidate_composite_root()
    }

    pub const fn candidate_height(&self) -> u64 {
        self.commitment.candidate_height()
    }

    pub const fn candidate_block_id(&self) -> Hash32V1 {
        self.commitment.candidate_block_id()
    }

    pub const fn commitment(&self) -> &CandidateCompositeCommitmentV1 {
        &self.commitment
    }
}

/// Sole crate-owned authority for one exact terminal-facts CAS.
///
/// The fields are private, there is no public constructor or decoder, and the
/// type deliberately implements neither `Clone` nor `Copy`. The sole
/// normal-build issuer requires an exact prepared carrier, independently
/// verified Order finality, recoverable source-plane apply, and fresh terminal
/// readback; pre-vote or comparison data alone cannot mint this authority.
#[must_use = "the sole terminal-facts CAS owner must not be discarded"]
#[derive(Debug)]
pub struct WholeNodeFinalizationOwnerV1 {
    commitment: WholeNodeFinalExecutionCommitmentV1,
}

impl WholeNodeFinalizationOwnerV1 {
    pub const fn final_execution_root(&self) -> Hash32V1 {
        self.commitment.final_execution_root()
    }

    pub const fn candidate_height(&self) -> u64 {
        self.commitment.candidate_height()
    }

    pub const fn candidate_block_id(&self) -> Hash32V1 {
        self.commitment.candidate_block_id()
    }

    /// Exposes only the exact inert candidate composite commitment retained by
    /// this non-Clone owner. The fact is needed to deterministically rebuild a
    /// later Order application plan after process recovery; it grants no
    /// source-plane, finalization, Order-state, signer, or Node authority.
    pub const fn candidate_composite_root(&self) -> Hash32V1 {
        self.commitment.candidate_composite_root()
    }

    /// Derives the exact public tag-50 value for a strictly later Order
    /// height while retaining this linear terminal owner.
    ///
    /// The returned material is inert. It cannot authorize a state write;
    /// the authoritative Order-state crate must consume `self` into its
    /// private write permit before the material can enter a canonical state
    /// transition.
    pub fn derive_order_binding_create_material_v1(
        &self,
        materialized_at_height: u64,
    ) -> GlobalExecutionResultV1<GlobalExecutionBindingCreateMaterialV1> {
        derive_inert_order_binding_create_material_v1(self, materialized_at_height)
    }

    /// Consumes this exact terminal owner only after a later finalized Order
    /// state has cryptographically proved the registered tag-50 binding.
    ///
    /// This method cannot issue the proof carrier and accepts no raw claim,
    /// header, root, or decoded commitment. The Order-state writer retains the
    /// owner across materialization and supplies the independently verified
    /// carrier only after later-height finality.
    pub fn bind_verified_order_state_v1(
        self,
        binding: VerifiedOrderStateExecutionBindingV1,
    ) -> GlobalExecutionResultV1<Self> {
        bind_existing_finalization_owner_to_verified_order_state_v1(self, binding)
    }

    #[cfg(test)]
    pub(crate) fn test_mutate_terminal_root_v1(&mut self) {
        self.commitment.body.plane_terminals[1]
            .terminal_state_or_metadata_root
            .0[0] ^= 1;
        self.commitment = seal_final_execution(self.commitment.body.clone())
            .expect("test terminal mutation remains encodable");
    }

    #[cfg(test)]
    pub(crate) fn test_mutate_candidate_fork_v1(&mut self) {
        self.commitment.body.candidate_block_id.0[0] ^= 1;
        for terminal in &mut self.commitment.body.plane_terminals[1..] {
            terminal.terminal_order_block_id = self.commitment.body.candidate_block_id;
        }
        self.commitment = seal_final_execution(self.commitment.body.clone())
            .expect("test fork mutation remains encodable");
    }

    #[cfg(test)]
    pub(crate) fn test_mutate_prepared_checksum_v1(&mut self) {
        self.commitment.body.prepared_checkpoint_checksum.0[0] ^= 1;
        self.commitment = seal_final_execution(self.commitment.body.clone())
            .expect("test stale mutation remains encodable");
    }
}

/// Derive cloneable tag-50 bytes from an existing linear terminal owner.
///
/// This is deliberately an inert seam, not the missing Order-state writer: it
/// borrows rather than consumes the owner and returns public data that cannot
/// authorize a JMT mutation. A future Node-private writer must consume the
/// owner, prove exact parent-key absence, atomically insert this material, and
/// fresh-read the resulting canonical state before any positive issuer exists.
#[allow(dead_code)]
pub(crate) fn derive_inert_order_binding_create_material_v1(
    owner: &WholeNodeFinalizationOwnerV1,
    materialized_at_height: u64,
) -> GlobalExecutionResultV1<GlobalExecutionBindingCreateMaterialV1> {
    validate_final_execution_commitment(&owner.commitment)?;
    let context = &owner.commitment.body.context;
    derive_global_execution_binding_create_material_v1(
        &context.chain_id,
        context.genesis_hash.0,
        context.protocol_version,
        context.stack_profile_hash.0,
        owner.commitment.candidate_height(),
        owner.commitment.candidate_block_id().0,
        owner.commitment.candidate_composite_root().0,
        owner.commitment.final_execution_root().0,
        materialized_at_height,
    )
    .map_err(|_| {
        error(
            GlobalExecutionErrorCodeV1::FinalizationOwnerMismatch,
            "terminal owner cannot derive exact later-height tag-50 material",
        )
    })
}

/// Capability-preserving seam for a future Node-private normal owner path.
///
/// This is crate-private and deliberately has no caller today. The required
/// binding capability has no reachable positive issuer until an authoritative
/// tag-50 Order-state writer exists. The bounded direct Ordinary ancestry
/// verifier is present, but cannot substitute for that mutation authority. It also
/// consumes an already-issued, non-Clone
/// finalization owner rather than treating the public, deserializable terminal
/// commitment as authority. Keeping both capabilities linear prevents raw
/// Order bytes, a bare post-state root, or a locally computed execution digest
/// from becoming finalization authority by substitution.
#[allow(dead_code)]
pub(crate) fn bind_existing_finalization_owner_to_verified_order_state_v1(
    owner: WholeNodeFinalizationOwnerV1,
    binding: VerifiedOrderStateExecutionBindingV1,
) -> GlobalExecutionResultV1<WholeNodeFinalizationOwnerV1> {
    let commitment = &owner.commitment;
    validate_final_execution_commitment(commitment)?;
    if commitment.body.context.chain_id.as_str() != binding.chain_id()
        || commitment.body.context.genesis_hash.0 != binding.genesis_hash()
        || commitment.body.context.protocol_version != binding.protocol_version()
        || commitment.body.context.stack_profile_hash.0 != binding.stack_profile_hash()
        || commitment.candidate_height() != binding.candidate_height()
        || commitment.candidate_block_id().0 != binding.candidate_block_id()
        || commitment.candidate_composite_root().0 != binding.candidate_composite_root()
        || commitment.final_execution_root().0 != binding.final_execution_root()
    {
        return Err(error(
            GlobalExecutionErrorCodeV1::FinalizationOwnerMismatch,
            "verified Order-state binding differs from exact terminal commitment",
        ));
    }
    Ok(owner)
}

/// Freshly reauthenticated result of one exact terminal-facts CAS.
///
/// This carrier is local checkpoint evidence only. It is not a Node permit,
/// an Order-finality proof, or an application-state membership proof.
#[derive(Debug)]
pub struct WholeNodeFinalizedV1 {
    checkpoint_generation: u64,
    checkpoint_checksum: Hash32V1,
    replay: bool,
    commitment: WholeNodeFinalExecutionCommitmentV1,
}

impl WholeNodeFinalizedV1 {
    pub const fn checkpoint_generation(&self) -> u64 {
        self.checkpoint_generation
    }

    pub const fn checkpoint_checksum(&self) -> Hash32V1 {
        self.checkpoint_checksum
    }

    pub const fn is_replay(&self) -> bool {
        self.replay
    }

    pub const fn final_execution_root(&self) -> Hash32V1 {
        self.commitment.final_execution_root()
    }

    pub const fn candidate_height(&self) -> u64 {
        self.commitment.candidate_height()
    }

    pub const fn candidate_block_id(&self) -> Hash32V1 {
        self.commitment.candidate_block_id()
    }

    pub const fn commitment(&self) -> &WholeNodeFinalExecutionCommitmentV1 {
        &self.commitment
    }
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum WholeNodeFinalizationFaultV1 {
    BeforeCommit,
    AfterCommitBeforeReturn,
}

#[cfg_attr(not(test), allow(dead_code))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WholeNodeFinalizationFaultInternalV1 {
    BeforeCommit,
    AfterCommitBeforeReturn,
}

#[derive(Clone, Debug)]
pub struct PocoGlobalExecutionStoreV1 {
    path: PathBuf,
    scope: Hash32V1,
    context: CandidateExecutionContextV1,
}

impl PocoGlobalExecutionStoreV1 {
    /// Initialize a new independent whole-node validation sequence from an
    /// exact five-plane fresh source cut.
    pub fn initialize_new(
        path: impl Into<PathBuf>,
        scope: Hash32V1,
        context: CandidateExecutionContextV1,
        sources: &mut GlobalExecutionSourcesV1<'_>,
    ) -> GlobalExecutionResultV1<Self> {
        validate_context(&context)?;
        if scope == Hash32V1([0; 32]) {
            return Err(error(
                GlobalExecutionErrorCodeV1::InvalidContext,
                "whole-node scope must be nonzero",
            ));
        }
        let path = validate_path(&path.into(), false)?;
        let source_cut = sample_source_cut(sources, &context)?;
        let body = CheckpointBodyV1 {
            schema_version: STORE_SCHEMA_VERSION_V1,
            scope,
            generation: 0,
            predecessor_checksum: Hash32V1([0; 32]),
            source_cut,
            prepared: None,
            finalized: None,
        };
        let anchor = seal_checkpoint(body)?;

        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .map_err(|cause| unavailable(cause.to_string()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
                .map_err(|cause| unavailable(cause.to_string()))?;
        }
        drop(file);
        let mut connection = open_rw_raw(&path)?;
        configure_rw(&connection)?;
        connection.pragma_update(None, "application_id", SQLITE_APPLICATION_ID_V1)?;
        connection.pragma_update(None, "user_version", SQLITE_USER_VERSION_V1)?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        transaction.execute_batch(META_SQL)?;
        transaction.execute_batch(CHECKPOINTS_SQL)?;
        transaction.execute_batch(PREPARED_SQL)?;
        transaction.execute_batch(FINALIZED_SQL)?;
        transaction.execute(
            "INSERT INTO global_execution_metadata_v1(singleton,generation,checkpoint_checksum,fenced,record) VALUES(1,?1,?2,0,?3)",
            params![
                &anchor.body.generation.to_be_bytes()[..],
                &anchor.checksum.0[..],
                canonical_bytes(&anchor)?,
            ],
        )?;
        transaction.execute(
            "INSERT INTO global_execution_checkpoints_v1(generation,checkpoint_checksum,record_kind,record) VALUES(?1,?2,0,?3)",
            params![
                &anchor.body.generation.to_be_bytes()[..],
                &anchor.checksum.0[..],
                canonical_bytes(&anchor)?,
            ],
        )?;
        transaction.commit()?;
        drop(connection);
        reject_sidecars(&path)?;
        let store = Self {
            path,
            scope,
            context,
        };
        let observed = store.load_checkpoint()?;
        if observed != anchor {
            return Err(error(
                GlobalExecutionErrorCodeV1::CheckpointTamper,
                "fresh anchor readback differs",
            ));
        }
        Ok(store)
    }

    pub fn open_existing(
        path: impl Into<PathBuf>,
        scope: Hash32V1,
        context: CandidateExecutionContextV1,
    ) -> GlobalExecutionResultV1<Self> {
        validate_context(&context)?;
        let store = Self {
            path: validate_path(&path.into(), true)?,
            scope,
            context,
        };
        let checkpoint = store.load_checkpoint()?;
        if checkpoint.body.scope != scope || checkpoint.body.source_cut.context != store.context {
            return Err(error(
                GlobalExecutionErrorCodeV1::InvalidContext,
                "checkpoint scope/context differs",
            ));
        }
        Ok(store)
    }

    pub fn fresh_checkpoint_facts_v1(
        &self,
    ) -> GlobalExecutionResultV1<GlobalExecutionCheckpointFactsV1> {
        let checkpoint = self.load_checkpoint()?;
        Ok(GlobalExecutionCheckpointFactsV1 {
            generation: checkpoint.body.generation,
            checksum: checkpoint.checksum,
            source_cut_digest: checkpoint.body.source_cut.digest,
            final_execution_root: checkpoint
                .body
                .finalized
                .as_ref()
                .map(WholeNodeFinalExecutionCommitmentV1::final_execution_root),
        })
    }

    /// Reissue the exact non-Clone prepared carrier after process loss.
    ///
    /// Public expected facts only select an already authenticated durable row;
    /// they cannot create or replace it. `load_checkpoint` audits the complete
    /// predecessor chain and `load_prepared` independently rejoins the indexed
    /// prepared record before this recovery issuer returns.
    pub fn recover_prepared_ready_v1(
        &self,
        expected_generation: u64,
        expected_checksum: Hash32V1,
        expected_candidate_block_id: Hash32V1,
    ) -> GlobalExecutionResultV1<PreVoteExecutionReadyV1> {
        let checkpoint = self.load_checkpoint()?;
        if checkpoint.body.generation != expected_generation
            || checkpoint.checksum != expected_checksum
            || checkpoint.body.finalized.is_some()
        {
            return Err(error(
                GlobalExecutionErrorCodeV1::RecoveryMismatch,
                "prepared recovery selector differs from the exact unfinalized checkpoint",
            ));
        }
        let commitment = checkpoint.body.prepared.as_ref().ok_or_else(|| {
            error(
                GlobalExecutionErrorCodeV1::RecoveryMismatch,
                "prepared recovery checkpoint has no candidate commitment",
            )
        })?;
        if commitment.candidate_block_id() != expected_candidate_block_id
            || self.load_prepared(checkpoint.body.generation, checkpoint.checksum, commitment)?
                != Some(commitment.clone())
        {
            return Err(error(
                GlobalExecutionErrorCodeV1::RecoveryMismatch,
                "prepared recovery row differs from authenticated checkpoint history",
            ));
        }
        Ok(PreVoteExecutionReadyV1 {
            checkpoint_generation: checkpoint.body.generation,
            checkpoint_checksum: checkpoint.checksum,
            commitment: commitment.clone(),
        })
    }

    /// Deterministically preview one exact candidate without advancing the
    /// whole-node checkpoint or issuing any authority carrier.
    ///
    /// The proposal's `expected_candidate_composite_root` is deliberately not
    /// trusted by this read-only operation. The caller must copy the returned
    /// root into the proposal and then call [`Self::prepare_before_vote_v1`],
    /// which recomputes the complete preview against fresh DA and five-plane
    /// sources before its CAS.
    pub fn preview_candidate_commitment_v1(
        &self,
        proposal: &PreVoteProposalV1,
        sources: &mut GlobalExecutionSourcesV1<'_>,
    ) -> GlobalExecutionResultV1<CandidateCompositeCommitmentV1> {
        let (_, _, commitment) = self.preview_candidate_commitment_inner_v1(proposal, sources)?;
        Ok(commitment)
    }

    fn preview_candidate_commitment_inner_v1(
        &self,
        proposal: &PreVoteProposalV1,
        sources: &mut GlobalExecutionSourcesV1<'_>,
    ) -> GlobalExecutionResultV1<(
        CheckpointRecordV1,
        SourceCutV1,
        CandidateCompositeCommitmentV1,
    )> {
        self.validate_proposal_for_preview(proposal)?;
        let checkpoint = self.load_checkpoint()?;
        if checkpoint.body.finalized.is_some() {
            return Err(error(
                GlobalExecutionErrorCodeV1::FinalizationStale,
                "terminal whole-node checkpoint cannot prepare another candidate",
            ));
        }
        if checkpoint.body.generation != proposal.expected_checkpoint_generation
            || checkpoint.checksum != proposal.expected_checkpoint_checksum
        {
            return Err(error(
                GlobalExecutionErrorCodeV1::CheckpointStale,
                "proposal checkpoint source differs from fresh head",
            ));
        }
        let initial_cut = sample_source_cut(sources, &self.context)?;
        if initial_cut != checkpoint.body.source_cut {
            return Err(error(
                GlobalExecutionErrorCodeV1::SourceCutMismatch,
                "five-plane source cut differs from checkpoint anchor",
            ));
        }

        let da_before = sources
            .da
            .fresh_certified_batch_readback(proposal.batch_id)
            .map_err(|cause| plane_error(GlobalExecutionErrorCodeV1::DaRejected, cause))?;
        let da_facts = da_before.batch();
        if da_facts.certificate_id() != proposal.availability_certificate_id
            || da_facts.obligation_status() != 0
        {
            return Err(error(
                GlobalExecutionErrorCodeV1::DaRejected,
                "proposal DA certificate/active obligation differs",
            ));
        }
        let certified = sources
            .da
            .certified_batch(proposal.batch_id)
            .map_err(|cause| plane_error(GlobalExecutionErrorCodeV1::DaRejected, cause))?;
        if certified.certificate().certificate_id() != proposal.availability_certificate_id {
            return Err(error(
                GlobalExecutionErrorCodeV1::DaRejected,
                "fresh certificate identity differs",
            ));
        }
        let total_length = certified.certificate().envelope().uncompressed_bytes();
        let retrieval = sources
            .da
            .retrieve(proposal.batch_id, 0, total_length)
            .map_err(|cause| plane_error(GlobalExecutionErrorCodeV1::DaRejected, cause))?;
        let transaction_items = decode_complete_retrieval_v1(
            proposal.availability_certificate_id,
            retrieval.certificate().certificate_id(),
            certified.certificate().envelope().item_count(),
            total_length,
            retrieval.offset(),
            retrieval.total_length(),
            retrieval.bytes(),
        )?;
        let batch: GlobalExecutionBatchV1 = strict_decode(&transaction_items[0])?;
        validate_batch(&batch, proposal)?;

        let agent_parent = sources
            .agent_market
            .fresh_readback()
            .map_err(|cause| plane_error(GlobalExecutionErrorCodeV1::AgentMarketRejected, cause))?;
        let verify_parent = sources.verify_challenge.fresh_readback().map_err(|cause| {
            plane_error(GlobalExecutionErrorCodeV1::VerifyChallengeRejected, cause)
        })?;
        let mvcc_parent = sources
            .mvcc_fee
            .fresh_readback()
            .map_err(|cause| plane_error(GlobalExecutionErrorCodeV1::MvccFeeRejected, cause))?;
        let settlement_parent =
            sources
                .consumption_settlement
                .fresh_readback()
                .map_err(|cause| {
                    plane_error(
                        GlobalExecutionErrorCodeV1::ConsumptionSettlementRejected,
                        cause,
                    )
                })?;
        let candidate_agent_block = AgentHash32V1(batch.candidate_block_id.0);
        let agent = sources
            .agent_market
            .preview_before_vote_v1(
                &agent_parent,
                batch.candidate_height,
                candidate_agent_block,
                &batch.agent_market_commands,
            )
            .map_err(|cause| plane_error(GlobalExecutionErrorCodeV1::AgentMarketRejected, cause))?;
        let verify = sources
            .verify_challenge
            .preview_before_vote_v1(
                &verify_parent,
                batch.candidate_height,
                candidate_agent_block,
                &batch.verify_challenge_commands,
            )
            .map_err(|cause| {
                plane_error(GlobalExecutionErrorCodeV1::VerifyChallengeRejected, cause)
            })?;
        let mvcc = sources
            .mvcc_fee
            .preview_before_vote_v1(&mvcc_parent, &batch.mvcc_fee_block)
            .map_err(|cause| plane_error(GlobalExecutionErrorCodeV1::MvccFeeRejected, cause))?;
        let settlement = sources
            .consumption_settlement
            .preview_before_vote_v1(
                &settlement_parent,
                batch.candidate_height,
                candidate_agent_block,
                &batch.consumption_settlement_commands,
            )
            .map_err(|cause| {
                plane_error(
                    GlobalExecutionErrorCodeV1::ConsumptionSettlementRejected,
                    cause,
                )
            })?;

        let source_cut_digest = initial_cut.digest;
        let body = CandidateCompositeCommitmentBodyV1 {
            schema_version: STORE_SCHEMA_VERSION_V1,
            context: self.context.clone(),
            candidate_height: batch.candidate_height,
            candidate_block_id: batch.candidate_block_id,
            source_cut_digest,
            da_batch_id: proposal.batch_id,
            da_certificate_id: proposal.availability_certificate_id,
            da_obligation_id: da_facts.obligation_id(),
            da_obligation_version: da_facts.obligation_version(),
            retrieved_batch_digest: digest_value(
                "trnm.poco-ai.global-execution-retrieved-batch.candidate.v1",
                &transaction_items,
            )?,
            agent_market_candidate_root: Hash32V1(agent.candidate_post_state_root().0),
            agent_market_receipts_root: digest_value(
                "trnm.poco-ai.global-execution-agent-receipts.candidate.v1",
                &agent.candidate_receipts(),
            )?,
            verify_challenge_candidate_root: Hash32V1(verify.candidate_post_state_root().0),
            verify_challenge_receipts_root: digest_value(
                "trnm.poco-ai.global-execution-verify-receipts.candidate.v1",
                &verify.candidate_receipts(),
            )?,
            mvcc_fee_candidate_root: Hash32V1(mvcc.candidate_post_state_root().0),
            mvcc_receipts_root: Hash32V1(mvcc.candidate_receipt().receipts_root.0),
            mvcc_resource_totals_root: Hash32V1(mvcc.candidate_receipt().resource_totals_root.0),
            mvcc_fee_deltas_root: Hash32V1(mvcc.candidate_receipt().fee_deltas_root.0),
            mvcc_resolution_root: Hash32V1(mvcc.candidate_receipt().mvcc_resolution_root.0),
            consumption_settlement_candidate_root: Hash32V1(
                settlement.candidate_post_state_root().0,
            ),
            consumption_settlement_receipts_root: digest_value(
                "trnm.poco-ai.global-execution-settlement-receipts.candidate.v1",
                &settlement.candidate_receipts(),
            )?,
        };
        let commitment = CandidateCompositeCommitmentV1 {
            candidate_composite_root: digest_value(
                "trnm.poco-ai.global-execution-composite-root.candidate.v1",
                &body,
            )?,
            body,
        };
        let da_after = sources
            .da
            .fresh_certified_batch_readback(proposal.batch_id)
            .map_err(|cause| plane_error(GlobalExecutionErrorCodeV1::DaRejected, cause))?;
        if da_after != da_before {
            return Err(error(
                GlobalExecutionErrorCodeV1::DaSourceChanged,
                "DA head/certificate changed across complete retrieval and preview",
            ));
        }
        if sample_source_cut(sources, &self.context)? != initial_cut {
            return Err(error(
                GlobalExecutionErrorCodeV1::SourceCutMismatch,
                "five-plane source changed across deterministic preview",
            ));
        }

        Ok((checkpoint, initial_cut, commitment))
    }

    /// Complete retrieval and deterministic preview before advancing one exact
    /// whole-node validation CAS.  Only the mandatory fresh target readback can
    /// create the returned carrier.
    pub fn prepare_before_vote_v1(
        &self,
        proposal: &PreVoteProposalV1,
        sources: &mut GlobalExecutionSourcesV1<'_>,
    ) -> GlobalExecutionResultV1<PreVoteExecutionReadyV1> {
        self.validate_proposal(proposal)?;
        let (checkpoint, initial_cut, commitment) =
            self.preview_candidate_commitment_inner_v1(proposal, sources)?;
        if commitment.candidate_composite_root != proposal.expected_candidate_composite_root {
            return Err(error(
                GlobalExecutionErrorCodeV1::CandidateCompositeRootMismatch,
                "proposal candidate composite root differs from fresh deterministic preview",
            ));
        }

        let target = CheckpointRecordV1 {
            body: CheckpointBodyV1 {
                schema_version: STORE_SCHEMA_VERSION_V1,
                scope: self.scope,
                generation: checkpoint.body.generation.checked_add(1).ok_or_else(|| {
                    error(
                        GlobalExecutionErrorCodeV1::ArithmeticOverflow,
                        "checkpoint generation overflows",
                    )
                })?,
                predecessor_checksum: checkpoint.checksum,
                source_cut: initial_cut.clone(),
                prepared: Some(commitment.clone()),
                finalized: None,
            },
            checksum: Hash32V1([0; 32]),
        };
        let target = seal_checkpoint(target.body)?;
        self.compare_and_advance(&checkpoint, &target)?;

        if sample_source_cut(sources, &self.context)? != initial_cut {
            self.fence_checkpoint()?;
            return Err(error(
                GlobalExecutionErrorCodeV1::SourceCutMismatch,
                "five-plane source changed across whole-node CAS; checkpoint fenced",
            ));
        }
        let observed = self.load_checkpoint()?;
        if observed != target
            || self.load_prepared(observed.body.generation, observed.checksum, &commitment)?
                != Some(commitment.clone())
        {
            self.fence_checkpoint()?;
            return Err(error(
                GlobalExecutionErrorCodeV1::CheckpointRace,
                "mandatory checkpoint target readback differs; checkpoint fenced",
            ));
        }
        Ok(PreVoteExecutionReadyV1 {
            checkpoint_generation: observed.body.generation,
            checkpoint_checksum: observed.checksum,
            commitment,
        })
    }

    /// Apply one exactly prepared candidate after its block has been proven
    /// Order-finalized, then mint the sole terminal-checkpoint owner from
    /// authenticated fresh readbacks of all five planes.
    ///
    /// The global prepared checkpoint is the durable recovery intent. Source
    /// planes are advanced in deterministic order and every operation/block is
    /// exact-replayable, so a process loss between databases resumes toward
    /// the same terminal cut. No owner exists while a plane is partial or a
    /// terminal root, receipt root, sequence, Order tip, DA fact, or journal
    /// tail differs from the pre-vote commitment.
    pub fn apply_finalized_candidate_and_issue_owner_v1(
        &self,
        ready: &PreVoteExecutionReadyV1,
        order: &VerifiedOrderFinalityV1,
        sources: &mut GlobalExecutionSourcesV1<'_>,
    ) -> GlobalExecutionResultV1<WholeNodeFinalizationOwnerV1> {
        let checkpoint = self.load_checkpoint()?;
        if checkpoint.body.generation != ready.checkpoint_generation
            || checkpoint.checksum != ready.checkpoint_checksum
            || checkpoint.body.prepared.as_ref() != Some(&ready.commitment)
            || checkpoint.body.finalized.is_some()
        {
            return Err(error(
                GlobalExecutionErrorCodeV1::FinalizationOwnerMismatch,
                "finalized apply requires the exact fresh prepared checkpoint",
            ));
        }
        let prepared = checkpoint.body.prepared.as_ref().ok_or_else(|| {
            error(
                GlobalExecutionErrorCodeV1::FinalizationOwnerMismatch,
                "finalized apply has no prepared candidate",
            )
        })?;
        if order.chain_id() != self.context.chain_id
            || order.genesis_hash() != self.context.genesis_hash.0
            || order.protocol_version() != self.context.protocol_version
            || order.stack_profile_hash() != self.context.stack_profile_hash.0
            || order.finalized_height() != prepared.candidate_height()
            || order.finalized_block_id() != prepared.candidate_block_id().0
        {
            return Err(error(
                GlobalExecutionErrorCodeV1::FinalizationOwnerMismatch,
                "verified Order finality does not name the exact prepared candidate",
            ));
        }

        let da_before = sources
            .da
            .fresh_certified_batch_readback(prepared.body.da_batch_id)
            .map_err(|cause| plane_error(GlobalExecutionErrorCodeV1::DaRejected, cause))?;
        let da_facts = da_before.batch();
        if da_facts.certificate_id() != prepared.body.da_certificate_id
            || da_facts.obligation_id() != prepared.body.da_obligation_id
            || da_facts.obligation_version() != prepared.body.da_obligation_version
            || da_facts.obligation_status() != 0
        {
            return Err(error(
                GlobalExecutionErrorCodeV1::DaRejected,
                "finalized apply DA source differs from prepared certificate/obligation",
            ));
        }
        let certified = sources
            .da
            .certified_batch(prepared.body.da_batch_id)
            .map_err(|cause| plane_error(GlobalExecutionErrorCodeV1::DaRejected, cause))?;
        if certified.certificate().certificate_id() != prepared.body.da_certificate_id {
            return Err(error(
                GlobalExecutionErrorCodeV1::DaRejected,
                "finalized apply certificate identity differs",
            ));
        }
        let total_length = certified.certificate().envelope().uncompressed_bytes();
        let retrieval = sources
            .da
            .retrieve(prepared.body.da_batch_id, 0, total_length)
            .map_err(|cause| plane_error(GlobalExecutionErrorCodeV1::DaRejected, cause))?;
        let transaction_items = decode_complete_retrieval_v1(
            prepared.body.da_certificate_id,
            retrieval.certificate().certificate_id(),
            certified.certificate().envelope().item_count(),
            total_length,
            retrieval.offset(),
            retrieval.total_length(),
            retrieval.bytes(),
        )?;
        if digest_value(
            "trnm.poco-ai.global-execution-retrieved-batch.candidate.v1",
            &transaction_items,
        )? != prepared.body.retrieved_batch_digest
        {
            return Err(error(
                GlobalExecutionErrorCodeV1::DaSourceChanged,
                "finalized apply retrieved bytes differ from prepared digest",
            ));
        }
        let batch: GlobalExecutionBatchV1 = strict_decode(&transaction_items[0])?;
        let replay_proposal = PreVoteProposalV1 {
            schema_version: STORE_SCHEMA_VERSION_V1,
            context: self.context.clone(),
            scope: self.scope,
            expected_checkpoint_generation: ready.checkpoint_generation,
            expected_checkpoint_checksum: ready.checkpoint_checksum,
            candidate_height: prepared.candidate_height(),
            candidate_block_id: prepared.candidate_block_id(),
            batch_id: prepared.body.da_batch_id,
            availability_certificate_id: prepared.body.da_certificate_id,
            expected_candidate_composite_root: prepared.candidate_composite_root(),
        };
        validate_batch(&batch, &replay_proposal)?;

        let source_cut = &checkpoint.body.source_cut;
        validate_order_source_parent_v1(order, source_cut, prepared, &batch)?;
        let candidate_height = prepared.candidate_height();
        let candidate_block_id = prepared.candidate_block_id();
        let mvcc_execution_block_id = batch.mvcc_execution_block_id();
        let candidate_agent_block = AgentHash32V1(candidate_block_id.0);
        let protocol_context = AgentProtocolContextV1 {
            chain_id: self.context.chain_id.clone(),
            genesis_hash: AgentHash32V1(self.context.genesis_hash.0),
            protocol_version: self.context.protocol_version,
            stack_profile_hash: AgentHash32V1(self.context.stack_profile_hash.0),
        };

        let agent_source = terminal_source_v1(source_cut, 1)?;
        let agent_before = sources
            .agent_market
            .fresh_readback()
            .map_err(|cause| plane_error(GlobalExecutionErrorCodeV1::AgentMarketRejected, cause))?;
        validate_ordered_plane_progress_v1(
            agent_source,
            agent_before.store_id().0,
            agent_before.sequence(),
            agent_before.order_height(),
            agent_before.order_block_id().0,
            candidate_height,
            candidate_block_id,
            batch.agent_market_commands.len(),
        )?;
        let mut agent_receipts: Vec<KernelTransitionReceiptV1> =
            Vec::with_capacity(batch.agent_market_commands.len());
        if batch.agent_market_commands.is_empty() {
            sources
                .agent_market
                .advance_empty_order_finalized_v1(&OrderFinalizedExecutionContextV1 {
                    schema_version: STORE_SCHEMA_VERSION_V1,
                    context: protocol_context.clone(),
                    expected_order_height: agent_source.order_height,
                    expected_order_block_id: AgentHash32V1(agent_source.order_block_id.0),
                    order_height: candidate_height,
                    order_block_id: candidate_agent_block,
                })
                .map_err(|cause| {
                    plane_error(GlobalExecutionErrorCodeV1::AgentMarketRejected, cause)
                })?;
        } else {
            let resumed_at_target = agent_before.order_height() == candidate_height
                && agent_before.order_block_id() == candidate_agent_block;
            for (index, command) in batch.agent_market_commands.iter().enumerate() {
                let source_parent = index == 0 && !resumed_at_target;
                let outcome = sources
                    .agent_market
                    .execute_order_finalized(
                        &OrderFinalizedExecutionContextV1 {
                            schema_version: STORE_SCHEMA_VERSION_V1,
                            context: protocol_context.clone(),
                            expected_order_height: if source_parent {
                                agent_source.order_height
                            } else {
                                candidate_height
                            },
                            expected_order_block_id: if source_parent {
                                AgentHash32V1(agent_source.order_block_id.0)
                            } else {
                                candidate_agent_block
                            },
                            order_height: candidate_height,
                            order_block_id: candidate_agent_block,
                        },
                        command,
                    )
                    .map_err(|cause| {
                        plane_error(GlobalExecutionErrorCodeV1::AgentMarketRejected, cause)
                    })?;
                agent_receipts.push(outcome.receipt().clone());
            }
        }
        let agent_after = sources
            .agent_market
            .fresh_readback()
            .map_err(|cause| plane_error(GlobalExecutionErrorCodeV1::AgentMarketRejected, cause))?;
        let agent_receipts_root = digest_value(
            "trnm.poco-ai.global-execution-agent-receipts.candidate.v1",
            &agent_receipts,
        )?;
        validate_ordered_plane_target_v1(
            agent_source,
            agent_after.store_id().0,
            agent_after.sequence(),
            agent_after.order_height(),
            agent_after.order_block_id().0,
            agent_after.durable_state_root().0,
            agent_after.durable_journal_root().0,
            candidate_height,
            candidate_block_id,
            batch.agent_market_commands.len(),
            prepared.body.agent_market_candidate_root,
            agent_receipts_root,
            prepared.body.agent_market_receipts_root,
        )?;

        let verify_source = terminal_source_v1(source_cut, 2)?;
        let verify_before = sources.verify_challenge.fresh_readback().map_err(|cause| {
            plane_error(GlobalExecutionErrorCodeV1::VerifyChallengeRejected, cause)
        })?;
        validate_ordered_plane_progress_v1(
            verify_source,
            verify_before.store_id().0,
            verify_before.sequence(),
            verify_before.order_height(),
            verify_before.order_block_id().0,
            candidate_height,
            candidate_block_id,
            batch.verify_challenge_commands.len(),
        )?;
        let mut verify_receipts: Vec<VerifyTransitionReceiptV1> =
            Vec::with_capacity(batch.verify_challenge_commands.len());
        if batch.verify_challenge_commands.is_empty() {
            sources
                .verify_challenge
                .advance_empty_order_finalized_v1(&VerifyOrderFinalizedExecutionContextV1 {
                    schema_version: STORE_SCHEMA_VERSION_V1,
                    context: protocol_context.clone(),
                    expected_order_height: verify_source.order_height,
                    expected_order_block_id: AgentHash32V1(verify_source.order_block_id.0),
                    order_height: candidate_height,
                    order_block_id: candidate_agent_block,
                })
                .map_err(|cause| {
                    plane_error(GlobalExecutionErrorCodeV1::VerifyChallengeRejected, cause)
                })?;
        } else {
            let resumed_at_target = verify_before.order_height() == candidate_height
                && verify_before.order_block_id() == candidate_agent_block;
            for (index, command) in batch.verify_challenge_commands.iter().enumerate() {
                let source_parent = index == 0 && !resumed_at_target;
                let outcome = sources
                    .verify_challenge
                    .execute_order_finalized(
                        &VerifyOrderFinalizedExecutionContextV1 {
                            schema_version: STORE_SCHEMA_VERSION_V1,
                            context: protocol_context.clone(),
                            expected_order_height: if source_parent {
                                verify_source.order_height
                            } else {
                                candidate_height
                            },
                            expected_order_block_id: if source_parent {
                                AgentHash32V1(verify_source.order_block_id.0)
                            } else {
                                candidate_agent_block
                            },
                            order_height: candidate_height,
                            order_block_id: candidate_agent_block,
                        },
                        command,
                    )
                    .map_err(|cause| {
                        plane_error(GlobalExecutionErrorCodeV1::VerifyChallengeRejected, cause)
                    })?;
                verify_receipts.push(outcome.receipt().clone());
            }
        }
        let verify_after = sources.verify_challenge.fresh_readback().map_err(|cause| {
            plane_error(GlobalExecutionErrorCodeV1::VerifyChallengeRejected, cause)
        })?;
        let verify_receipts_root = digest_value(
            "trnm.poco-ai.global-execution-verify-receipts.candidate.v1",
            &verify_receipts,
        )?;
        validate_ordered_plane_target_v1(
            verify_source,
            verify_after.store_id().0,
            verify_after.sequence(),
            verify_after.order_height(),
            verify_after.order_block_id().0,
            verify_after.durable_state_root().0,
            verify_after.durable_journal_root().0,
            candidate_height,
            candidate_block_id,
            batch.verify_challenge_commands.len(),
            prepared.body.verify_challenge_candidate_root,
            verify_receipts_root,
            prepared.body.verify_challenge_receipts_root,
        )?;

        let mvcc_source = terminal_source_v1(source_cut, 3)?;
        let mvcc_before = sources
            .mvcc_fee
            .fresh_readback()
            .map_err(|cause| plane_error(GlobalExecutionErrorCodeV1::MvccFeeRejected, cause))?;
        validate_mvcc_progress_v1(
            mvcc_source,
            &mvcc_before,
            candidate_height,
            mvcc_execution_block_id,
        )?;
        let mvcc_outcome = sources
            .mvcc_fee
            .execute_block(&batch.mvcc_fee_block)
            .map_err(|cause| plane_error(GlobalExecutionErrorCodeV1::MvccFeeRejected, cause))?;
        let mvcc_receipt = mvcc_outcome.confirmed.receipt();
        let mvcc_after = sources
            .mvcc_fee
            .fresh_readback()
            .map_err(|cause| plane_error(GlobalExecutionErrorCodeV1::MvccFeeRejected, cause))?;
        if mvcc_after.store_id().0 != mvcc_source.store_id.0
            || mvcc_after.height() != candidate_height
            || mvcc_after.block_id().0 != mvcc_execution_block_id.0
            || mvcc_after.durable_state_root().0 != prepared.body.mvcc_fee_candidate_root.0
            || mvcc_after.durable_journal_root().0 == [0; 32]
            || mvcc_receipt.final_state_root.0 != prepared.body.mvcc_fee_candidate_root.0
            || mvcc_receipt.receipts_root.0 != prepared.body.mvcc_receipts_root.0
            || mvcc_receipt.resource_totals_root.0 != prepared.body.mvcc_resource_totals_root.0
            || mvcc_receipt.fee_deltas_root.0 != prepared.body.mvcc_fee_deltas_root.0
            || mvcc_receipt.mvcc_resolution_root.0 != prepared.body.mvcc_resolution_root.0
        {
            return Err(error(
                GlobalExecutionErrorCodeV1::MvccFeeRejected,
                "MVCC/Fee terminal readback differs from prepared candidate",
            ));
        }

        let settlement_source = terminal_source_v1(source_cut, 4)?;
        let settlement_before =
            sources
                .consumption_settlement
                .fresh_readback()
                .map_err(|cause| {
                    plane_error(
                        GlobalExecutionErrorCodeV1::ConsumptionSettlementRejected,
                        cause,
                    )
                })?;
        validate_ordered_plane_progress_v1(
            settlement_source,
            settlement_before.store_id().0,
            settlement_before.sequence(),
            settlement_before.order_height(),
            settlement_before.order_block_id().0,
            candidate_height,
            candidate_block_id,
            batch.consumption_settlement_commands.len(),
        )?;
        let mut settlement_receipts: Vec<ConsumptionTransitionReceiptV1> =
            Vec::with_capacity(batch.consumption_settlement_commands.len());
        if batch.consumption_settlement_commands.is_empty() {
            sources
                .consumption_settlement
                .advance_empty_order_finalized_v1(&ConsumptionOrderFinalizedExecutionContextV1 {
                    schema_version: STORE_SCHEMA_VERSION_V1,
                    context: protocol_context.clone(),
                    expected_order_height: settlement_source.order_height,
                    expected_order_block_id: AgentHash32V1(settlement_source.order_block_id.0),
                    order_height: candidate_height,
                    order_block_id: candidate_agent_block,
                })
                .map_err(|cause| {
                    plane_error(
                        GlobalExecutionErrorCodeV1::ConsumptionSettlementRejected,
                        cause,
                    )
                })?;
        } else {
            for (index, command) in batch.consumption_settlement_commands.iter().enumerate() {
                let source_parent = index == 0;
                let outcome = sources
                    .consumption_settlement
                    .execute_order_finalized(
                        &ConsumptionOrderFinalizedExecutionContextV1 {
                            schema_version: STORE_SCHEMA_VERSION_V1,
                            context: protocol_context.clone(),
                            expected_order_height: if source_parent {
                                settlement_source.order_height
                            } else {
                                candidate_height
                            },
                            expected_order_block_id: if source_parent {
                                AgentHash32V1(settlement_source.order_block_id.0)
                            } else {
                                candidate_agent_block
                            },
                            order_height: candidate_height,
                            order_block_id: candidate_agent_block,
                        },
                        command,
                    )
                    .map_err(|cause| {
                        plane_error(
                            GlobalExecutionErrorCodeV1::ConsumptionSettlementRejected,
                            cause,
                        )
                    })?;
                settlement_receipts.push(outcome.receipt().clone());
            }
        }
        let settlement_after =
            sources
                .consumption_settlement
                .fresh_readback()
                .map_err(|cause| {
                    plane_error(
                        GlobalExecutionErrorCodeV1::ConsumptionSettlementRejected,
                        cause,
                    )
                })?;
        let settlement_receipts_root = digest_value(
            "trnm.poco-ai.global-execution-settlement-receipts.candidate.v1",
            &settlement_receipts,
        )?;
        validate_ordered_plane_target_v1(
            settlement_source,
            settlement_after.store_id().0,
            settlement_after.sequence(),
            settlement_after.order_height(),
            settlement_after.order_block_id().0,
            settlement_after.durable_state_root().0,
            settlement_after.durable_journal_root().0,
            candidate_height,
            candidate_block_id,
            batch.consumption_settlement_commands.len(),
            prepared.body.consumption_settlement_candidate_root,
            settlement_receipts_root,
            prepared.body.consumption_settlement_receipts_root,
        )?;

        let da_after = sources
            .da
            .fresh_certified_batch_readback(prepared.body.da_batch_id)
            .map_err(|cause| plane_error(GlobalExecutionErrorCodeV1::DaRejected, cause))?;
        if da_after != da_before {
            return Err(error(
                GlobalExecutionErrorCodeV1::DaSourceChanged,
                "DA source changed across finalized source-plane apply",
            ));
        }
        let (_, da_receipts_root) = expected_terminal_roots_v1(prepared, 0)?;
        let plane_terminals = vec![
            PlaneTerminalFactsV1 {
                plane_tag: 0,
                store_id: source_cut.plane_heads[0].store_id,
                source_sequence_or_height: source_cut.plane_heads[0].sequence_or_height,
                source_state_or_metadata_root: source_cut.plane_heads[0].state_or_metadata_root,
                source_journal_root: source_cut.plane_heads[0].journal_root,
                terminal_sequence_or_height: source_cut.plane_heads[0].sequence_or_height,
                terminal_order_height: 0,
                terminal_order_block_id: Hash32V1([0; 32]),
                terminal_state_or_metadata_root: source_cut.plane_heads[0].state_or_metadata_root,
                terminal_receipts_root: da_receipts_root,
                terminal_journal_root: source_cut.plane_heads[0].journal_root,
            },
            ordered_terminal_v1(
                agent_source,
                agent_after.sequence(),
                agent_after.durable_state_root().0,
                agent_receipts_root,
                agent_after.durable_journal_root().0,
                candidate_height,
                candidate_block_id,
            ),
            ordered_terminal_v1(
                verify_source,
                verify_after.sequence(),
                verify_after.durable_state_root().0,
                verify_receipts_root,
                verify_after.durable_journal_root().0,
                candidate_height,
                candidate_block_id,
            ),
            ordered_terminal_v1(
                mvcc_source,
                mvcc_after.height(),
                mvcc_after.durable_state_root().0,
                Hash32V1(mvcc_receipt.receipts_root.0),
                mvcc_after.durable_journal_root().0,
                candidate_height,
                candidate_block_id,
            ),
            ordered_terminal_v1(
                settlement_source,
                settlement_after.sequence(),
                settlement_after.durable_state_root().0,
                settlement_receipts_root,
                settlement_after.durable_journal_root().0,
                candidate_height,
                candidate_block_id,
            ),
        ];
        let body = WholeNodeFinalizationBodyV1 {
            schema_version: STORE_SCHEMA_VERSION_V1,
            context: self.context.clone(),
            scope: self.scope,
            prepared_checkpoint_generation: checkpoint.body.generation,
            prepared_checkpoint_checksum: checkpoint.checksum,
            candidate_height,
            candidate_block_id,
            candidate_composite_root: prepared.candidate_composite_root(),
            source_cut_digest: prepared.source_cut_digest(),
            plane_terminals,
        };
        let owner = WholeNodeFinalizationOwnerV1 {
            commitment: seal_final_execution(body)?,
        };
        validate_finalization_binding(
            &owner.commitment,
            source_cut,
            prepared,
            self.scope,
            &self.context,
        )?;
        Ok(owner)
    }

    /// Recover the sole terminal owner after process loss.
    ///
    /// For an unfinalized prepared checkpoint this reconstructs the exact
    /// prepared carrier from authenticated local history and drives the
    /// existing recoverable source-plane apply. For an already finalized
    /// checkpoint it independently verifies target Order finality and every
    /// source plane's fresh terminal head before reissuing the owner. Decoded
    /// terminal commitments or caller-supplied roots alone never authorize
    /// recovery.
    pub fn recover_finalization_owner_v1(
        &self,
        order: &VerifiedOrderFinalityV1,
        sources: &mut GlobalExecutionSourcesV1<'_>,
    ) -> GlobalExecutionResultV1<WholeNodeFinalizationOwnerV1> {
        let checkpoint = self.load_checkpoint()?;
        let prepared = checkpoint.body.prepared.as_ref().ok_or_else(|| {
            error(
                GlobalExecutionErrorCodeV1::RecoveryMismatch,
                "terminal-owner recovery requires an authenticated prepared candidate",
            )
        })?;
        validate_recovery_order_v1(order, prepared, &self.context)?;
        match checkpoint.body.finalized.as_ref() {
            None => {
                if self.load_prepared(checkpoint.body.generation, checkpoint.checksum, prepared)?
                    != Some(prepared.clone())
                {
                    return Err(error(
                        GlobalExecutionErrorCodeV1::RecoveryMismatch,
                        "terminal-owner recovery prepared row differs",
                    ));
                }
                let ready = PreVoteExecutionReadyV1 {
                    checkpoint_generation: checkpoint.body.generation,
                    checkpoint_checksum: checkpoint.checksum,
                    commitment: prepared.clone(),
                };
                self.apply_finalized_candidate_and_issue_owner_v1(&ready, order, sources)
            }
            Some(finalized) => {
                if self.load_finalized(
                    checkpoint.body.generation,
                    checkpoint.checksum,
                    finalized,
                )? != Some(finalized.clone())
                {
                    return Err(error(
                        GlobalExecutionErrorCodeV1::RecoveryMismatch,
                        "terminal-owner recovery finalized row differs",
                    ));
                }
                validate_recovered_terminal_sources_v1(
                    sources,
                    order,
                    &checkpoint.body.source_cut,
                    prepared,
                    finalized,
                    self.scope,
                    &self.context,
                )?;
                Ok(WholeNodeFinalizationOwnerV1 {
                    commitment: finalized.clone(),
                })
            }
        }
    }

    /// Atomically persist one exact externally authenticated terminal cut.
    ///
    /// The required owner can only come from the exact verified-finality
    /// source-plane apply path. This method itself does not execute or mutate
    /// a source plane and does not interpret comparison data as a Node permit,
    /// Order proof, or application-state membership proof.
    pub fn finalize_terminal_facts_v1(
        &self,
        owner: &WholeNodeFinalizationOwnerV1,
    ) -> GlobalExecutionResultV1<WholeNodeFinalizedV1> {
        self.finalize_terminal_facts_inner_v1(owner, None)
    }

    fn finalize_terminal_facts_inner_v1(
        &self,
        owner: &WholeNodeFinalizationOwnerV1,
        #[cfg_attr(not(test), allow(unused_variables))] fault: Option<
            WholeNodeFinalizationFaultInternalV1,
        >,
    ) -> GlobalExecutionResultV1<WholeNodeFinalizedV1> {
        validate_final_execution_commitment(&owner.commitment)?;
        let checkpoint = self.load_checkpoint()?;
        if checkpoint.body.finalized.as_ref() == Some(&owner.commitment) {
            let expected_generation = owner
                .commitment
                .prepared_checkpoint_generation()
                .checked_add(1)
                .ok_or_else(|| {
                    error(
                        GlobalExecutionErrorCodeV1::ArithmeticOverflow,
                        "terminal checkpoint generation overflows",
                    )
                })?;
            if checkpoint.body.generation != expected_generation
                || checkpoint.body.predecessor_checksum
                    != owner.commitment.prepared_checkpoint_checksum()
                || self.load_finalized(
                    checkpoint.body.generation,
                    checkpoint.checksum,
                    &owner.commitment,
                )? != Some(owner.commitment.clone())
            {
                return Err(error(
                    GlobalExecutionErrorCodeV1::FinalizationTamper,
                    "replayed terminal checkpoint differs from exact durable target",
                ));
            }
            return Ok(WholeNodeFinalizedV1 {
                checkpoint_generation: checkpoint.body.generation,
                checkpoint_checksum: checkpoint.checksum,
                replay: true,
                commitment: owner.commitment.clone(),
            });
        }
        if checkpoint.body.finalized.is_some() {
            return Err(error(
                GlobalExecutionErrorCodeV1::FinalizationConflict,
                "another terminal cut already owns the checkpoint",
            ));
        }
        if checkpoint.body.generation != owner.commitment.prepared_checkpoint_generation()
            || checkpoint.checksum != owner.commitment.prepared_checkpoint_checksum()
        {
            return Err(error(
                GlobalExecutionErrorCodeV1::FinalizationStale,
                "terminal owner names a stale prepared checkpoint",
            ));
        }
        let prepared = checkpoint.body.prepared.as_ref().ok_or_else(|| {
            error(
                GlobalExecutionErrorCodeV1::FinalizationOwnerMismatch,
                "terminal owner has no prepared candidate",
            )
        })?;
        validate_finalization_binding(
            &owner.commitment,
            &checkpoint.body.source_cut,
            prepared,
            self.scope,
            &self.context,
        )?;
        let target = seal_checkpoint(CheckpointBodyV1 {
            schema_version: STORE_SCHEMA_VERSION_V1,
            scope: self.scope,
            generation: checkpoint.body.generation.checked_add(1).ok_or_else(|| {
                error(
                    GlobalExecutionErrorCodeV1::ArithmeticOverflow,
                    "terminal checkpoint generation overflows",
                )
            })?,
            predecessor_checksum: checkpoint.checksum,
            source_cut: checkpoint.body.source_cut.clone(),
            prepared: Some(prepared.clone()),
            finalized: Some(owner.commitment.clone()),
        })?;
        self.compare_and_finalize(&checkpoint, &target, &owner.commitment, fault)?;
        let observed = self.load_checkpoint()?;
        if observed != target
            || self.load_finalized(
                observed.body.generation,
                observed.checksum,
                &owner.commitment,
            )? != Some(owner.commitment.clone())
        {
            self.fence_checkpoint()?;
            return Err(error(
                GlobalExecutionErrorCodeV1::CheckpointRace,
                "mandatory terminal checkpoint readback differs; checkpoint fenced",
            ));
        }
        Ok(WholeNodeFinalizedV1 {
            checkpoint_generation: observed.body.generation,
            checkpoint_checksum: observed.checksum,
            replay: false,
            commitment: owner.commitment.clone(),
        })
    }

    #[cfg(test)]
    pub(crate) fn issue_test_finalization_owner_v1(
        &self,
        ready: &PreVoteExecutionReadyV1,
    ) -> GlobalExecutionResultV1<WholeNodeFinalizationOwnerV1> {
        let checkpoint = self.load_checkpoint()?;
        if checkpoint.body.generation != ready.checkpoint_generation
            || checkpoint.checksum != ready.checkpoint_checksum
            || checkpoint.body.prepared.as_ref() != Some(&ready.commitment)
            || checkpoint.body.finalized.is_some()
        {
            return Err(error(
                GlobalExecutionErrorCodeV1::FinalizationOwnerMismatch,
                "test issuer requires the exact fresh prepared checkpoint",
            ));
        }
        let body = WholeNodeFinalizationBodyV1 {
            schema_version: STORE_SCHEMA_VERSION_V1,
            context: self.context.clone(),
            scope: self.scope,
            prepared_checkpoint_generation: checkpoint.body.generation,
            prepared_checkpoint_checksum: checkpoint.checksum,
            candidate_height: ready.commitment.candidate_height(),
            candidate_block_id: ready.commitment.candidate_block_id(),
            candidate_composite_root: ready.commitment.candidate_composite_root(),
            source_cut_digest: ready.commitment.source_cut_digest(),
            plane_terminals: test_plane_terminals_v1(
                &checkpoint.body.source_cut,
                &ready.commitment,
            )?,
        };
        Ok(WholeNodeFinalizationOwnerV1 {
            commitment: seal_final_execution(body)?,
        })
    }

    #[cfg(test)]
    pub(crate) fn finalize_terminal_facts_with_fault_v1(
        &self,
        owner: &WholeNodeFinalizationOwnerV1,
        fault: WholeNodeFinalizationFaultV1,
    ) -> GlobalExecutionResultV1<WholeNodeFinalizedV1> {
        let internal = match fault {
            WholeNodeFinalizationFaultV1::BeforeCommit => {
                WholeNodeFinalizationFaultInternalV1::BeforeCommit
            }
            WholeNodeFinalizationFaultV1::AfterCommitBeforeReturn => {
                WholeNodeFinalizationFaultInternalV1::AfterCommitBeforeReturn
            }
        };
        self.finalize_terminal_facts_inner_v1(owner, Some(internal))
    }

    fn validate_proposal(&self, proposal: &PreVoteProposalV1) -> GlobalExecutionResultV1<()> {
        self.validate_proposal_for_preview(proposal)?;
        if proposal.expected_candidate_composite_root == Hash32V1([0; 32]) {
            return Err(error(
                GlobalExecutionErrorCodeV1::InvalidContext,
                "pre-vote proposal expected composite root is invalid",
            ));
        }
        Ok(())
    }

    fn validate_proposal_for_preview(
        &self,
        proposal: &PreVoteProposalV1,
    ) -> GlobalExecutionResultV1<()> {
        validate_context(&proposal.context)?;
        if proposal.schema_version != STORE_SCHEMA_VERSION_V1
            || proposal.context != self.context
            || proposal.scope != self.scope
            || proposal.expected_checkpoint_checksum == Hash32V1([0; 32])
            || proposal.candidate_height == 0
            || proposal.candidate_block_id == Hash32V1([0; 32])
        {
            return Err(error(
                GlobalExecutionErrorCodeV1::InvalidContext,
                "pre-vote proposal preview context/binding is invalid",
            ));
        }
        Ok(())
    }

    fn compare_and_advance(
        &self,
        expected: &CheckpointRecordV1,
        target: &CheckpointRecordV1,
    ) -> GlobalExecutionResultV1<()> {
        if target.body.generation != expected.body.generation.saturating_add(1)
            || target.body.predecessor_checksum != expected.checksum
            || target.body.source_cut != expected.body.source_cut
            || target.body.prepared.is_none()
        {
            return Err(error(
                GlobalExecutionErrorCodeV1::CheckpointTamper,
                "checkpoint target is not the exact validation successor",
            ));
        }
        let mut connection = self.open_rw_verified()?;
        let result = (|| -> GlobalExecutionResultV1<()> {
            let transaction =
                connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
            let (current, fenced) = load_metadata_from(&transaction)?;
            if fenced {
                return Err(error(
                    GlobalExecutionErrorCodeV1::CheckpointFenced,
                    "whole-node checkpoint is permanently fenced",
                ));
            }
            if current != *expected {
                return Err(error(
                    GlobalExecutionErrorCodeV1::CheckpointStale,
                    "whole-node CAS source differs",
                ));
            }
            let commitment = target.body.prepared.as_ref().expect("checked prepared");
            transaction.execute(
                "INSERT INTO global_execution_prepared_v1(candidate_block_id,generation,candidate_composite_root,checkpoint_checksum,commitment) VALUES(?1,?2,?3,?4,?5)",
                params![
                    &commitment.body.candidate_block_id.0[..],
                    &target.body.generation.to_be_bytes()[..],
                    &commitment.candidate_composite_root.0[..],
                    &target.checksum.0[..],
                    canonical_bytes(commitment)?,
                ],
            )?;
            transaction.execute(
                "INSERT INTO global_execution_checkpoints_v1(generation,checkpoint_checksum,record_kind,record) VALUES(?1,?2,1,?3)",
                params![
                    &target.body.generation.to_be_bytes()[..],
                    &target.checksum.0[..],
                    canonical_bytes(target)?,
                ],
            )?;
            let changed = transaction.execute(
                "UPDATE global_execution_metadata_v1 SET generation=?1,checkpoint_checksum=?2,record=?3 WHERE singleton=1 AND fenced=0 AND generation=?4 AND checkpoint_checksum=?5 AND record=?6",
                params![
                    &target.body.generation.to_be_bytes()[..],
                    &target.checksum.0[..],
                    canonical_bytes(target)?,
                    &expected.body.generation.to_be_bytes()[..],
                    &expected.checksum.0[..],
                    canonical_bytes(expected)?,
                ],
            )?;
            if changed != 1 {
                return Err(error(
                    GlobalExecutionErrorCodeV1::CheckpointStale,
                    "whole-node CAS compare did not apply",
                ));
            }
            transaction.commit()?;
            Ok(())
        })();
        drop(connection);
        reject_sidecars(&self.path)?;
        let observed = self.load_checkpoint();
        match observed {
            Ok(value) if value == *target => Ok(()),
            Ok(value) if value == *expected => Err(result.err().unwrap_or_else(|| {
                error(
                    GlobalExecutionErrorCodeV1::CheckpointRace,
                    "CAS reported success but target was not applied",
                )
            })),
            _ => {
                let _ = self.fence_checkpoint();
                Err(error(
                    GlobalExecutionErrorCodeV1::CheckpointRace,
                    "checkpoint is neither exact source nor target",
                ))
            }
        }
    }

    fn compare_and_finalize(
        &self,
        expected: &CheckpointRecordV1,
        target: &CheckpointRecordV1,
        commitment: &WholeNodeFinalExecutionCommitmentV1,
        fault: Option<WholeNodeFinalizationFaultInternalV1>,
    ) -> GlobalExecutionResultV1<()> {
        if expected.body.finalized.is_some()
            || target.body.generation != expected.body.generation.saturating_add(1)
            || target.body.predecessor_checksum != expected.checksum
            || target.body.source_cut != expected.body.source_cut
            || target.body.prepared != expected.body.prepared
            || target.body.finalized.as_ref() != Some(commitment)
        {
            return Err(error(
                GlobalExecutionErrorCodeV1::FinalizationTamper,
                "terminal checkpoint target is not the exact prepared successor",
            ));
        }
        let mut connection = self.open_rw_verified()?;
        let result = (|| -> GlobalExecutionResultV1<()> {
            let transaction =
                connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
            let (current, fenced) = load_metadata_from(&transaction)?;
            if fenced {
                return Err(error(
                    GlobalExecutionErrorCodeV1::CheckpointFenced,
                    "whole-node checkpoint is permanently fenced",
                ));
            }
            if current != *expected {
                return Err(error(
                    GlobalExecutionErrorCodeV1::FinalizationStale,
                    "terminal checkpoint CAS source differs",
                ));
            }
            transaction.execute(
                "INSERT INTO global_execution_finalized_v1(candidate_block_id,generation,prepared_generation,prepared_checkpoint_checksum,candidate_composite_root,final_execution_root,checkpoint_checksum,commitment) VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",
                params![
                    &commitment.body.candidate_block_id.0[..],
                    &target.body.generation.to_be_bytes()[..],
                    &commitment.body.prepared_checkpoint_generation.to_be_bytes()[..],
                    &commitment.body.prepared_checkpoint_checksum.0[..],
                    &commitment.body.candidate_composite_root.0[..],
                    &commitment.final_execution_root.0[..],
                    &target.checksum.0[..],
                    canonical_bytes(commitment)?,
                ],
            )?;
            transaction.execute(
                "INSERT INTO global_execution_checkpoints_v1(generation,checkpoint_checksum,record_kind,record) VALUES(?1,?2,2,?3)",
                params![
                    &target.body.generation.to_be_bytes()[..],
                    &target.checksum.0[..],
                    canonical_bytes(target)?,
                ],
            )?;
            let changed = transaction.execute(
                "UPDATE global_execution_metadata_v1 SET generation=?1,checkpoint_checksum=?2,record=?3 WHERE singleton=1 AND fenced=0 AND generation=?4 AND checkpoint_checksum=?5 AND record=?6",
                params![
                    &target.body.generation.to_be_bytes()[..],
                    &target.checksum.0[..],
                    canonical_bytes(target)?,
                    &expected.body.generation.to_be_bytes()[..],
                    &expected.checksum.0[..],
                    canonical_bytes(expected)?,
                ],
            )?;
            if changed != 1 {
                return Err(error(
                    GlobalExecutionErrorCodeV1::FinalizationStale,
                    "terminal checkpoint CAS compare did not apply",
                ));
            }
            if matches!(
                fault,
                Some(WholeNodeFinalizationFaultInternalV1::BeforeCommit)
            ) {
                return Err(error(
                    GlobalExecutionErrorCodeV1::CheckpointRace,
                    "terminal checkpoint transaction interrupted before commit",
                ));
            }
            transaction.commit()?;
            if matches!(
                fault,
                Some(WholeNodeFinalizationFaultInternalV1::AfterCommitBeforeReturn)
            ) {
                return Err(error(
                    GlobalExecutionErrorCodeV1::CheckpointRace,
                    "terminal checkpoint committed before acknowledgement loss",
                ));
            }
            Ok(())
        })();
        drop(connection);
        reject_sidecars(&self.path)?;
        let observed = self.load_checkpoint();
        match observed {
            Ok(value) if value == *target => Ok(()),
            Ok(value) if value == *expected => Err(result.err().unwrap_or_else(|| {
                error(
                    GlobalExecutionErrorCodeV1::CheckpointRace,
                    "terminal CAS reported success but target was not applied",
                )
            })),
            _ => {
                let _ = self.fence_checkpoint();
                Err(error(
                    GlobalExecutionErrorCodeV1::CheckpointRace,
                    "terminal checkpoint is neither exact source nor target",
                ))
            }
        }
    }

    fn load_checkpoint(&self) -> GlobalExecutionResultV1<CheckpointRecordV1> {
        reject_sidecars(&self.path)?;
        let connection = open_ro(&self.path)?;
        verify_schema(&connection)?;
        let (record, fenced) = load_metadata_from(&connection)?;
        if fenced {
            return Err(error(
                GlobalExecutionErrorCodeV1::CheckpointFenced,
                "whole-node checkpoint is permanently fenced",
            ));
        }
        audit_checkpoint(&record)?;
        audit_checkpoint_history(&connection, &record)?;
        if record.body.scope != self.scope || record.body.source_cut.context != self.context {
            return Err(error(
                GlobalExecutionErrorCodeV1::InvalidContext,
                "checkpoint scope/context differs",
            ));
        }
        if let Some(commitment) = &record.body.prepared {
            let (prepared_generation, prepared_checksum) = record
                .body
                .finalized
                .as_ref()
                .map(|finalized| {
                    (
                        finalized.body.prepared_checkpoint_generation,
                        finalized.body.prepared_checkpoint_checksum,
                    )
                })
                .unwrap_or((record.body.generation, record.checksum));
            if self
                .load_prepared_from(
                    &connection,
                    prepared_generation,
                    prepared_checksum,
                    commitment,
                )?
                .as_ref()
                != Some(commitment)
            {
                return Err(error(
                    GlobalExecutionErrorCodeV1::CheckpointTamper,
                    "checkpoint target has no exact prepared row",
                ));
            }
        }
        if let Some(commitment) = &record.body.finalized {
            if self
                .load_finalized_from(
                    &connection,
                    record.body.generation,
                    record.checksum,
                    commitment,
                )?
                .as_ref()
                != Some(commitment)
            {
                return Err(error(
                    GlobalExecutionErrorCodeV1::FinalizationTamper,
                    "terminal checkpoint has no exact finalized row",
                ));
            }
        }
        Ok(record)
    }

    fn load_prepared(
        &self,
        expected_generation: u64,
        expected_checkpoint_checksum: Hash32V1,
        commitment: &CandidateCompositeCommitmentV1,
    ) -> GlobalExecutionResultV1<Option<CandidateCompositeCommitmentV1>> {
        reject_sidecars(&self.path)?;
        let connection = open_ro(&self.path)?;
        verify_schema(&connection)?;
        self.load_prepared_from(
            &connection,
            expected_generation,
            expected_checkpoint_checksum,
            commitment,
        )
    }

    fn load_prepared_from(
        &self,
        connection: &Connection,
        expected_generation: u64,
        expected_checkpoint_checksum: Hash32V1,
        expected: &CandidateCompositeCommitmentV1,
    ) -> GlobalExecutionResultV1<Option<CandidateCompositeCommitmentV1>> {
        let row: Option<PreparedEvidenceRowV1> = connection
            .query_row(
                "SELECT generation,candidate_composite_root,checkpoint_checksum,commitment FROM global_execution_prepared_v1 WHERE candidate_block_id=?1",
                params![&expected.body.candidate_block_id.0[..]],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .optional()?;
        row.map(|(generation, root, checkpoint_checksum, raw)| {
            let value: CandidateCompositeCommitmentV1 = strict_decode(&raw)?;
            validate_commitment(&value)?;
            if value != *expected
                || root != value.candidate_composite_root.0
                || generation != expected_generation.to_be_bytes()
                || checkpoint_checksum != expected_checkpoint_checksum.0
            {
                return Err(error(
                    GlobalExecutionErrorCodeV1::CheckpointTamper,
                    "prepared row metadata differs from canonical commitment",
                ));
            }
            Ok(value)
        })
        .transpose()
    }

    fn load_finalized(
        &self,
        expected_generation: u64,
        expected_checkpoint_checksum: Hash32V1,
        commitment: &WholeNodeFinalExecutionCommitmentV1,
    ) -> GlobalExecutionResultV1<Option<WholeNodeFinalExecutionCommitmentV1>> {
        reject_sidecars(&self.path)?;
        let connection = open_ro(&self.path)?;
        verify_schema(&connection)?;
        self.load_finalized_from(
            &connection,
            expected_generation,
            expected_checkpoint_checksum,
            commitment,
        )
    }

    fn load_finalized_from(
        &self,
        connection: &Connection,
        expected_generation: u64,
        expected_checkpoint_checksum: Hash32V1,
        expected: &WholeNodeFinalExecutionCommitmentV1,
    ) -> GlobalExecutionResultV1<Option<WholeNodeFinalExecutionCommitmentV1>> {
        let row: Option<FinalizedEvidenceRowV1> = connection
                .query_row(
                    "SELECT generation,prepared_generation,prepared_checkpoint_checksum,candidate_composite_root,final_execution_root,checkpoint_checksum,commitment FROM global_execution_finalized_v1 WHERE candidate_block_id=?1",
                    params![&expected.body.candidate_block_id.0[..]],
                    |row| {
                        Ok((
                            row.get(0)?,
                            row.get(1)?,
                            row.get(2)?,
                            row.get(3)?,
                            row.get(4)?,
                            row.get(5)?,
                            row.get(6)?,
                        ))
                    },
                )
                .optional()?;
        row.map(
            |(
                generation,
                prepared_generation,
                prepared_checksum,
                composite_root,
                final_root,
                checkpoint_checksum,
                raw,
            )| {
                let value: WholeNodeFinalExecutionCommitmentV1 = strict_decode(&raw)?;
                validate_final_execution_commitment(&value)?;
                if value != *expected
                    || generation != expected_generation.to_be_bytes()
                    || prepared_generation
                        != value.body.prepared_checkpoint_generation.to_be_bytes()
                    || prepared_checksum != value.body.prepared_checkpoint_checksum.0
                    || composite_root != value.body.candidate_composite_root.0
                    || final_root != value.final_execution_root.0
                    || checkpoint_checksum != expected_checkpoint_checksum.0
                {
                    return Err(error(
                        GlobalExecutionErrorCodeV1::FinalizationTamper,
                        "finalized row metadata differs from canonical terminal commitment",
                    ));
                }
                Ok(value)
            },
        )
        .transpose()
    }

    fn open_rw_verified(&self) -> GlobalExecutionResultV1<Connection> {
        let read_only = open_ro(&self.path)?;
        verify_schema(&read_only)?;
        let (record, fenced) = load_metadata_from(&read_only)?;
        if fenced {
            return Err(error(
                GlobalExecutionErrorCodeV1::CheckpointFenced,
                "whole-node checkpoint is permanently fenced",
            ));
        }
        audit_checkpoint(&record)?;
        audit_checkpoint_history(&read_only, &record)?;
        drop(read_only);
        reject_sidecars(&self.path)?;
        let connection = open_rw_raw(&self.path)?;
        configure_rw(&connection)?;
        verify_schema(&connection)?;
        Ok(connection)
    }

    fn fence_checkpoint(&self) -> GlobalExecutionResultV1<()> {
        let read_only = open_ro(&self.path)?;
        verify_schema(&read_only)?;
        drop(read_only);
        let connection = open_rw_raw(&self.path)?;
        configure_rw(&connection)?;
        connection.execute(
            "UPDATE global_execution_metadata_v1 SET fenced=1 WHERE singleton=1",
            [],
        )?;
        drop(connection);
        reject_sidecars(&self.path)
    }
}

pub(crate) fn decode_complete_retrieval_v1(
    expected_certificate_id: trnm_poco_da_v1::AvailabilityCertificateIdV1,
    observed_certificate_id: trnm_poco_da_v1::AvailabilityCertificateIdV1,
    envelope_item_count: u32,
    expected_total_length: u64,
    observed_offset: u64,
    observed_total_length: u64,
    bytes: &[u8],
) -> GlobalExecutionResultV1<Vec<Vec<u8>>> {
    if observed_offset != 0
        || observed_total_length != expected_total_length
        || bytes.len()
            != usize::try_from(expected_total_length).map_err(|_| {
                error(
                    GlobalExecutionErrorCodeV1::ArithmeticOverflow,
                    "retrieved DA length exceeds usize",
                )
            })?
        || observed_certificate_id != expected_certificate_id
        || bytes.len() > MAX_BATCH_ITEM_BYTES_V1
    {
        return Err(error(
            GlobalExecutionErrorCodeV1::DaRejected,
            "complete local DA retrieval differs from certificate envelope",
        ));
    }
    let transaction_items: Vec<Vec<u8>> = strict_decode(bytes)?;
    if transaction_items.len() != 1
        || envelope_item_count != 1
        || transaction_items[0].is_empty()
        || transaction_items[0].len() > MAX_BATCH_ITEM_BYTES_V1
    {
        return Err(error(
            GlobalExecutionErrorCodeV1::NonCanonicalBatch,
            "candidate DA batch must contain exactly one bounded global item",
        ));
    }
    Ok(transaction_items)
}

fn validate_batch(
    batch: &GlobalExecutionBatchV1,
    proposal: &PreVoteProposalV1,
) -> GlobalExecutionResultV1<()> {
    let total_commands = batch
        .agent_market_commands
        .len()
        .checked_add(batch.verify_challenge_commands.len())
        .and_then(|value| value.checked_add(batch.consumption_settlement_commands.len()))
        .and_then(|value| value.checked_add(batch.mvcc_fee_block.transactions.len()))
        .ok_or_else(|| {
            error(
                GlobalExecutionErrorCodeV1::ArithmeticOverflow,
                "candidate command count overflows",
            )
        })?;
    if batch.schema_version != STORE_SCHEMA_VERSION_V1
        || batch.context != proposal.context
        || batch.candidate_height != proposal.candidate_height
        || batch.candidate_block_id != proposal.candidate_block_id
        || batch.mvcc_execution_block_id() == Hash32V1([0; 32])
        || batch.mvcc_execution_block_id() == proposal.candidate_block_id
        || batch.mvcc_fee_block.height != proposal.candidate_height
        || batch.agent_market_commands.len() > MAX_COMMANDS_PER_PLANE_V1
        || batch.verify_challenge_commands.len() > MAX_COMMANDS_PER_PLANE_V1
        || batch.mvcc_fee_block.transactions.len() > MAX_COMMANDS_PER_PLANE_V1
        || batch.consumption_settlement_commands.len() > MAX_COMMANDS_PER_PLANE_V1
        || total_commands == 0
    {
        return Err(error(
            GlobalExecutionErrorCodeV1::InvalidBounds,
            "candidate batch context/count/Order-or-MVCC block binding is invalid",
        ));
    }
    Ok(())
}

pub(crate) fn sample_source_cut(
    sources: &mut GlobalExecutionSourcesV1<'_>,
    expected_context: &CandidateExecutionContextV1,
) -> GlobalExecutionResultV1<SourceCutV1> {
    let da = sources
        .da
        .fresh_readback()
        .map_err(|cause| plane_error(GlobalExecutionErrorCodeV1::DaRejected, cause))?;
    let agent = sources
        .agent_market
        .fresh_readback()
        .map_err(|cause| plane_error(GlobalExecutionErrorCodeV1::AgentMarketRejected, cause))?;
    let verify = sources
        .verify_challenge
        .fresh_readback()
        .map_err(|cause| plane_error(GlobalExecutionErrorCodeV1::VerifyChallengeRejected, cause))?;
    let mvcc = sources
        .mvcc_fee
        .fresh_readback()
        .map_err(|cause| plane_error(GlobalExecutionErrorCodeV1::MvccFeeRejected, cause))?;
    let settlement = sources
        .consumption_settlement
        .fresh_readback()
        .map_err(|cause| {
            plane_error(
                GlobalExecutionErrorCodeV1::ConsumptionSettlementRejected,
                cause,
            )
        })?;
    require_da_context(da.context(), expected_context)?;
    require_agent_context(agent.context(), expected_context)?;
    require_agent_context(verify.context(), expected_context)?;
    require_mvcc_context(mvcc.context(), expected_context)?;
    require_agent_context(settlement.context(), expected_context)?;
    let expected_tip = (agent.order_height(), agent.order_block_id().0);
    if (verify.order_height(), verify.order_block_id().0) != expected_tip
        || (settlement.order_height(), settlement.order_block_id().0) != expected_tip
        || mvcc.height() != expected_tip.0
    {
        return Err(error(
            GlobalExecutionErrorCodeV1::SourceCutMismatch,
            "Order-tracking plane parents or MVCC execution height are not one exact cut",
        ));
    }
    let mut plane_heads = vec![
        PlaneHeadV1 {
            plane_tag: 0,
            store_schema_version: da.store_schema_version(),
            store_id: Hash32V1(*da.store_id().as_bytes()),
            sequence_or_height: da.sequence(),
            order_height: 0,
            order_block_id: Hash32V1([0; 32]),
            state_or_metadata_root: Hash32V1(*da.durable_metadata_root().as_bytes()),
            journal_root: Hash32V1(*da.attestation_journal_tail_root().as_bytes()),
        },
        PlaneHeadV1 {
            plane_tag: 1,
            store_schema_version: agent.store_schema_version(),
            store_id: Hash32V1(agent.store_id().0),
            sequence_or_height: agent.sequence(),
            order_height: agent.order_height(),
            order_block_id: Hash32V1(agent.order_block_id().0),
            state_or_metadata_root: Hash32V1(agent.durable_state_root().0),
            journal_root: Hash32V1(agent.durable_journal_root().0),
        },
        PlaneHeadV1 {
            plane_tag: 2,
            store_schema_version: verify.store_schema_version(),
            store_id: Hash32V1(verify.store_id().0),
            sequence_or_height: verify.sequence(),
            order_height: verify.order_height(),
            order_block_id: Hash32V1(verify.order_block_id().0),
            state_or_metadata_root: Hash32V1(verify.durable_state_root().0),
            journal_root: Hash32V1(verify.durable_journal_root().0),
        },
        PlaneHeadV1 {
            plane_tag: 3,
            store_schema_version: mvcc.store_schema_version(),
            store_id: Hash32V1(mvcc.store_id().0),
            sequence_or_height: mvcc.height(),
            order_height: mvcc.height(),
            order_block_id: Hash32V1(mvcc.block_id().0),
            state_or_metadata_root: Hash32V1(mvcc.durable_state_root().0),
            journal_root: Hash32V1(mvcc.durable_journal_root().0),
        },
        PlaneHeadV1 {
            plane_tag: 4,
            store_schema_version: settlement.store_schema_version(),
            store_id: Hash32V1(settlement.store_id().0),
            sequence_or_height: settlement.sequence(),
            order_height: settlement.order_height(),
            order_block_id: Hash32V1(settlement.order_block_id().0),
            state_or_metadata_root: Hash32V1(settlement.durable_state_root().0),
            journal_root: Hash32V1(settlement.durable_journal_root().0),
        },
    ];
    plane_heads.sort_by_key(|head| head.plane_tag);
    let store_ids = plane_heads
        .iter()
        .map(|head| head.store_id)
        .collect::<BTreeSet<_>>();
    if store_ids.len() != plane_heads.len() || store_ids.contains(&Hash32V1([0; 32])) {
        return Err(error(
            GlobalExecutionErrorCodeV1::SourceCutMismatch,
            "source store identities are zero or overlap",
        ));
    }
    let digest = digest_value(
        "trnm.poco-ai.global-execution-source-cut.candidate.v1",
        &(STORE_SCHEMA_VERSION_V1, expected_context, &plane_heads),
    )?;
    Ok(SourceCutV1 {
        schema_version: STORE_SCHEMA_VERSION_V1,
        context: expected_context.clone(),
        plane_heads,
        digest,
    })
}

fn validate_context(context: &CandidateExecutionContextV1) -> GlobalExecutionResultV1<()> {
    if context.schema_version != STORE_SCHEMA_VERSION_V1
        || context.protocol_version != 1
        || context.chain_id.is_empty()
        || context.chain_id.len() > 128
        || !context.chain_id.is_ascii()
        || context.genesis_hash == Hash32V1([0; 32])
        || context.stack_profile_hash == Hash32V1([0; 32])
    {
        return Err(error(
            GlobalExecutionErrorCodeV1::InvalidContext,
            "candidate execution context is invalid",
        ));
    }
    Ok(())
}

fn require_da_context(
    actual: &trnm_poco_da_v1::ProtocolContextV1,
    expected: &CandidateExecutionContextV1,
) -> GlobalExecutionResultV1<()> {
    if actual.chain_id() != expected.chain_id
        || *actual.genesis_hash().as_bytes() != expected.genesis_hash.0
        || actual.protocol_version() != expected.protocol_version
        || *actual.stack_profile_hash().as_bytes() != expected.stack_profile_hash.0
    {
        return Err(error(
            GlobalExecutionErrorCodeV1::InvalidContext,
            "DA context differs from candidate context",
        ));
    }
    Ok(())
}

fn require_agent_context(
    actual: &trnm_poco_agent_market_v1::ProtocolContextV1,
    expected: &CandidateExecutionContextV1,
) -> GlobalExecutionResultV1<()> {
    if actual.chain_id != expected.chain_id
        || actual.genesis_hash.0 != expected.genesis_hash.0
        || actual.protocol_version != expected.protocol_version
        || actual.stack_profile_hash.0 != expected.stack_profile_hash.0
    {
        return Err(error(
            GlobalExecutionErrorCodeV1::InvalidContext,
            "ordered plane context differs from candidate context",
        ));
    }
    Ok(())
}

fn require_mvcc_context(
    actual: &trnm_poco_mvcc_fee_v1::ProtocolContextV1,
    expected: &CandidateExecutionContextV1,
) -> GlobalExecutionResultV1<()> {
    if actual.chain_id != expected.chain_id.as_bytes()
        || actual.genesis_hash.0 != expected.genesis_hash.0
        || actual.protocol_id != b"trnm-poco-ai-native-v1"
        || actual.protocol_version != expected.protocol_version
        || actual.profile_hash.0 != expected.stack_profile_hash.0
    {
        return Err(error(
            GlobalExecutionErrorCodeV1::InvalidContext,
            "MVCC/Fee context differs from candidate context",
        ));
    }
    Ok(())
}

fn seal_checkpoint(body: CheckpointBodyV1) -> GlobalExecutionResultV1<CheckpointRecordV1> {
    let checksum = digest_value(
        "trnm.poco-ai.global-execution-checkpoint.candidate.v1",
        &body,
    )?;
    Ok(CheckpointRecordV1 { body, checksum })
}

fn audit_checkpoint(record: &CheckpointRecordV1) -> GlobalExecutionResultV1<()> {
    if record.body.schema_version != STORE_SCHEMA_VERSION_V1
        || record.body.scope == Hash32V1([0; 32])
        || record.body.source_cut.schema_version != STORE_SCHEMA_VERSION_V1
        || record.body.source_cut.plane_heads.len() != 5
        || record
            .body
            .source_cut
            .plane_heads
            .iter()
            .enumerate()
            .any(|(index, head)| usize::from(head.plane_tag) != index)
        || seal_checkpoint(record.body.clone())? != *record
    {
        return Err(error(
            GlobalExecutionErrorCodeV1::CheckpointTamper,
            "checkpoint record is invalid",
        ));
    }
    let expected_source_digest = digest_value(
        "trnm.poco-ai.global-execution-source-cut.candidate.v1",
        &(
            STORE_SCHEMA_VERSION_V1,
            &record.body.source_cut.context,
            &record.body.source_cut.plane_heads,
        ),
    )?;
    if record.body.source_cut.digest != expected_source_digest {
        return Err(error(
            GlobalExecutionErrorCodeV1::CheckpointTamper,
            "source-cut digest differs",
        ));
    }
    if record.body.generation == 0 {
        if record.body.predecessor_checksum != Hash32V1([0; 32])
            || record.body.prepared.is_some()
            || record.body.finalized.is_some()
        {
            return Err(error(
                GlobalExecutionErrorCodeV1::CheckpointTamper,
                "anchor checkpoint contains successor fields",
            ));
        }
    } else if record.body.predecessor_checksum == Hash32V1([0; 32])
        || record.body.prepared.is_none()
    {
        return Err(error(
            GlobalExecutionErrorCodeV1::CheckpointTamper,
            "successor checkpoint is incomplete",
        ));
    }
    if let Some(commitment) = &record.body.prepared {
        validate_commitment(commitment)?;
        if commitment.source_cut_digest() != record.body.source_cut.digest {
            return Err(error(
                GlobalExecutionErrorCodeV1::CheckpointTamper,
                "prepared commitment names another source cut",
            ));
        }
    }
    if let Some(finalized) = &record.body.finalized {
        let prepared = record.body.prepared.as_ref().ok_or_else(|| {
            error(
                GlobalExecutionErrorCodeV1::FinalizationTamper,
                "terminal checkpoint has no prepared commitment",
            )
        })?;
        validate_finalization_binding(
            finalized,
            &record.body.source_cut,
            prepared,
            record.body.scope,
            &record.body.source_cut.context,
        )?;
        if record.body.generation
            != finalized
                .body
                .prepared_checkpoint_generation
                .checked_add(1)
                .ok_or_else(|| {
                    error(
                        GlobalExecutionErrorCodeV1::ArithmeticOverflow,
                        "terminal checkpoint generation overflows",
                    )
                })?
            || record.body.predecessor_checksum != finalized.body.prepared_checkpoint_checksum
        {
            return Err(error(
                GlobalExecutionErrorCodeV1::FinalizationTamper,
                "terminal checkpoint does not directly succeed its prepared tip",
            ));
        }
    }
    Ok(())
}

fn validate_commitment(commitment: &CandidateCompositeCommitmentV1) -> GlobalExecutionResultV1<()> {
    if commitment.body.schema_version != STORE_SCHEMA_VERSION_V1
        || commitment.body.candidate_height == 0
        || commitment.body.candidate_block_id == Hash32V1([0; 32])
        || commitment.body.source_cut_digest == Hash32V1([0; 32])
        || digest_value(
            "trnm.poco-ai.global-execution-composite-root.candidate.v1",
            &commitment.body,
        )? != commitment.candidate_composite_root
    {
        return Err(error(
            GlobalExecutionErrorCodeV1::CheckpointTamper,
            "candidate composite commitment is invalid",
        ));
    }
    Ok(())
}

fn seal_final_execution(
    body: WholeNodeFinalizationBodyV1,
) -> GlobalExecutionResultV1<WholeNodeFinalExecutionCommitmentV1> {
    let final_execution_root = digest_value(
        "trnm.poco-ai.global-execution-terminal-cut.candidate.v1",
        &body,
    )?;
    Ok(WholeNodeFinalExecutionCommitmentV1 {
        body,
        final_execution_root,
    })
}

fn validate_final_execution_commitment(
    commitment: &WholeNodeFinalExecutionCommitmentV1,
) -> GlobalExecutionResultV1<()> {
    let body = &commitment.body;
    validate_context(&body.context)?;
    if body.schema_version != STORE_SCHEMA_VERSION_V1
        || body.scope == Hash32V1([0; 32])
        || body.prepared_checkpoint_generation == 0
        || body.prepared_checkpoint_checksum == Hash32V1([0; 32])
        || body.candidate_height == 0
        || body.candidate_block_id == Hash32V1([0; 32])
        || body.candidate_composite_root == Hash32V1([0; 32])
        || body.source_cut_digest == Hash32V1([0; 32])
        || body.plane_terminals.len() != 5
        || seal_final_execution(body.clone())? != *commitment
    {
        return Err(error(
            GlobalExecutionErrorCodeV1::FinalizationTamper,
            "terminal execution commitment is malformed",
        ));
    }
    Ok(())
}

fn validate_finalization_binding(
    finalized: &WholeNodeFinalExecutionCommitmentV1,
    source_cut: &SourceCutV1,
    prepared: &CandidateCompositeCommitmentV1,
    expected_scope: Hash32V1,
    expected_context: &CandidateExecutionContextV1,
) -> GlobalExecutionResultV1<()> {
    validate_final_execution_commitment(finalized)?;
    let body = &finalized.body;
    if body.scope != expected_scope
        || &body.context != expected_context
        || body.candidate_height != prepared.candidate_height()
        || body.candidate_block_id != prepared.candidate_block_id()
        || body.candidate_composite_root != prepared.candidate_composite_root()
        || body.source_cut_digest != prepared.source_cut_digest()
        || body.source_cut_digest != source_cut.digest
    {
        return Err(error(
            GlobalExecutionErrorCodeV1::FinalizationOwnerMismatch,
            "terminal owner differs from the exact prepared candidate",
        ));
    }
    for (index, (source, terminal)) in source_cut
        .plane_heads
        .iter()
        .zip(&body.plane_terminals)
        .enumerate()
    {
        let tag = u8::try_from(index).map_err(|_| {
            error(
                GlobalExecutionErrorCodeV1::ArithmeticOverflow,
                "terminal plane index exceeds u8",
            )
        })?;
        let (mut expected_state, expected_receipts) = expected_terminal_roots_v1(prepared, tag)?;
        if tag == 0 {
            expected_state = source.state_or_metadata_root;
        }
        if terminal.plane_tag != tag
            || source.plane_tag != tag
            || terminal.store_id != source.store_id
            || terminal.source_sequence_or_height != source.sequence_or_height
            || terminal.source_state_or_metadata_root != source.state_or_metadata_root
            || terminal.source_journal_root != source.journal_root
            || terminal.terminal_sequence_or_height < source.sequence_or_height
            || terminal.terminal_state_or_metadata_root != expected_state
            || terminal.terminal_receipts_root != expected_receipts
            || terminal.terminal_journal_root == Hash32V1([0; 32])
        {
            return Err(error(
                GlobalExecutionErrorCodeV1::FinalizationOwnerMismatch,
                "terminal plane fact differs from source or prepared commitment",
            ));
        }
        if tag == 0 {
            if terminal.terminal_order_height != 0
                || terminal.terminal_order_block_id != Hash32V1([0; 32])
                || terminal.terminal_sequence_or_height != source.sequence_or_height
                || terminal.terminal_journal_root != source.journal_root
            {
                return Err(error(
                    GlobalExecutionErrorCodeV1::FinalizationOwnerMismatch,
                    "DA terminal fact must retain the certified source head",
                ));
            }
        } else if terminal.terminal_order_height != prepared.candidate_height()
            || terminal.terminal_order_block_id != prepared.candidate_block_id()
        {
            return Err(error(
                GlobalExecutionErrorCodeV1::FinalizationOwnerMismatch,
                "ordered plane terminal fact names another candidate",
            ));
        }
    }
    Ok(())
}

fn validate_recovery_order_v1(
    order: &VerifiedOrderFinalityV1,
    prepared: &CandidateCompositeCommitmentV1,
    expected_context: &CandidateExecutionContextV1,
) -> GlobalExecutionResultV1<()> {
    if order.chain_id() != expected_context.chain_id
        || order.genesis_hash() != expected_context.genesis_hash.0
        || order.protocol_version() != expected_context.protocol_version
        || order.stack_profile_hash() != expected_context.stack_profile_hash.0
        || order.finalized_height() != prepared.candidate_height()
        || order.finalized_block_id() != prepared.candidate_block_id().0
    {
        return Err(error(
            GlobalExecutionErrorCodeV1::RecoveryMismatch,
            "terminal-owner recovery Order finality differs from prepared candidate",
        ));
    }
    Ok(())
}

fn recover_exact_prepared_batch_v1(
    da: &mut PocoDaStoreV1,
    prepared: &CandidateCompositeCommitmentV1,
    expected_scope: Hash32V1,
    expected_context: &CandidateExecutionContextV1,
) -> GlobalExecutionResultV1<GlobalExecutionBatchV1> {
    let before = da
        .fresh_certified_batch_readback(prepared.body.da_batch_id)
        .map_err(|cause| plane_error(GlobalExecutionErrorCodeV1::DaRejected, cause))?;
    let facts = before.batch();
    if facts.certificate_id() != prepared.body.da_certificate_id
        || facts.obligation_id() != prepared.body.da_obligation_id
        || facts.obligation_version() != prepared.body.da_obligation_version
        || facts.obligation_status() != 0
    {
        return Err(error(
            GlobalExecutionErrorCodeV1::RecoveryMismatch,
            "prepared batch recovery DA certificate or obligation differs",
        ));
    }
    let certified = da
        .certified_batch(prepared.body.da_batch_id)
        .map_err(|cause| plane_error(GlobalExecutionErrorCodeV1::DaRejected, cause))?;
    if certified.certificate().certificate_id() != prepared.body.da_certificate_id {
        return Err(error(
            GlobalExecutionErrorCodeV1::RecoveryMismatch,
            "prepared batch recovery certificate identity differs",
        ));
    }
    let total_length = certified.certificate().envelope().uncompressed_bytes();
    let retrieval = da
        .retrieve(prepared.body.da_batch_id, 0, total_length)
        .map_err(|cause| plane_error(GlobalExecutionErrorCodeV1::DaRejected, cause))?;
    let transaction_items = decode_complete_retrieval_v1(
        prepared.body.da_certificate_id,
        retrieval.certificate().certificate_id(),
        certified.certificate().envelope().item_count(),
        total_length,
        retrieval.offset(),
        retrieval.total_length(),
        retrieval.bytes(),
    )?;
    if digest_value(
        "trnm.poco-ai.global-execution-retrieved-batch.candidate.v1",
        &transaction_items,
    )? != prepared.body.retrieved_batch_digest
    {
        return Err(error(
            GlobalExecutionErrorCodeV1::RecoveryMismatch,
            "prepared batch recovery bytes differ from the durable digest",
        ));
    }
    let batch: GlobalExecutionBatchV1 = strict_decode(&transaction_items[0])?;
    let replay = PreVoteProposalV1 {
        schema_version: STORE_SCHEMA_VERSION_V1,
        context: expected_context.clone(),
        scope: expected_scope,
        expected_checkpoint_generation: 0,
        expected_checkpoint_checksum: Hash32V1([0; 32]),
        candidate_height: prepared.candidate_height(),
        candidate_block_id: prepared.candidate_block_id(),
        batch_id: prepared.body.da_batch_id,
        availability_certificate_id: prepared.body.da_certificate_id,
        expected_candidate_composite_root: prepared.candidate_composite_root(),
    };
    validate_batch(&batch, &replay)?;
    let after = da
        .fresh_certified_batch_readback(prepared.body.da_batch_id)
        .map_err(|cause| plane_error(GlobalExecutionErrorCodeV1::DaRejected, cause))?;
    if after != before {
        return Err(error(
            GlobalExecutionErrorCodeV1::DaSourceChanged,
            "DA source changed across exact prepared batch recovery",
        ));
    }
    Ok(batch)
}

fn validate_recovered_terminal_sources_v1(
    sources: &mut GlobalExecutionSourcesV1<'_>,
    order: &VerifiedOrderFinalityV1,
    source_cut: &SourceCutV1,
    prepared: &CandidateCompositeCommitmentV1,
    finalized: &WholeNodeFinalExecutionCommitmentV1,
    expected_scope: Hash32V1,
    expected_context: &CandidateExecutionContextV1,
) -> GlobalExecutionResultV1<()> {
    validate_finalization_binding(
        finalized,
        source_cut,
        prepared,
        expected_scope,
        expected_context,
    )?;
    let exact_batch =
        recover_exact_prepared_batch_v1(sources.da, prepared, expected_scope, expected_context)?;
    validate_order_source_parent_v1(order, source_cut, prepared, &exact_batch)?;
    let mvcc_execution_block_id = exact_batch.mvcc_execution_block_id();
    let da_certified = sources
        .da
        .fresh_certified_batch_readback(prepared.body.da_batch_id)
        .map_err(|cause| plane_error(GlobalExecutionErrorCodeV1::DaRejected, cause))?;
    let da = da_certified.head();
    let agent = sources
        .agent_market
        .fresh_readback()
        .map_err(|cause| plane_error(GlobalExecutionErrorCodeV1::AgentMarketRejected, cause))?;
    let verify = sources
        .verify_challenge
        .fresh_readback()
        .map_err(|cause| plane_error(GlobalExecutionErrorCodeV1::VerifyChallengeRejected, cause))?;
    let mvcc = sources
        .mvcc_fee
        .fresh_readback()
        .map_err(|cause| plane_error(GlobalExecutionErrorCodeV1::MvccFeeRejected, cause))?;
    let settlement = sources
        .consumption_settlement
        .fresh_readback()
        .map_err(|cause| {
            plane_error(
                GlobalExecutionErrorCodeV1::ConsumptionSettlementRejected,
                cause,
            )
        })?;
    require_da_context(da.context(), expected_context)?;
    require_agent_context(agent.context(), expected_context)?;
    require_agent_context(verify.context(), expected_context)?;
    require_mvcc_context(mvcc.context(), expected_context)?;
    require_agent_context(settlement.context(), expected_context)?;

    let terminals = &finalized.body.plane_terminals;
    let da_terminal = &terminals[0];
    let agent_terminal = &terminals[1];
    let verify_terminal = &terminals[2];
    let mvcc_terminal = &terminals[3];
    let settlement_terminal = &terminals[4];
    let da_batch = da_certified.batch();
    let exact = da_terminal.store_id.0 == *da.store_id().as_bytes()
        && da_terminal.terminal_sequence_or_height == da.sequence()
        && da_terminal.terminal_state_or_metadata_root.0 == *da.durable_metadata_root().as_bytes()
        && da_terminal.terminal_journal_root.0 == *da.attestation_journal_tail_root().as_bytes()
        && da_batch.certificate_id() == prepared.body.da_certificate_id
        && da_batch.obligation_id() == prepared.body.da_obligation_id
        && da_batch.obligation_version() == prepared.body.da_obligation_version
        && da_batch.obligation_status() == 0
        && agent_terminal.store_id.0 == agent.store_id().0
        && agent_terminal.terminal_sequence_or_height == agent.sequence()
        && agent_terminal.terminal_order_height == agent.order_height()
        && agent_terminal.terminal_order_block_id.0 == agent.order_block_id().0
        && agent_terminal.terminal_state_or_metadata_root.0 == agent.durable_state_root().0
        && agent_terminal.terminal_journal_root.0 == agent.durable_journal_root().0
        && verify_terminal.store_id.0 == verify.store_id().0
        && verify_terminal.terminal_sequence_or_height == verify.sequence()
        && verify_terminal.terminal_order_height == verify.order_height()
        && verify_terminal.terminal_order_block_id.0 == verify.order_block_id().0
        && verify_terminal.terminal_state_or_metadata_root.0 == verify.durable_state_root().0
        && verify_terminal.terminal_journal_root.0 == verify.durable_journal_root().0
        && mvcc_terminal.store_id.0 == mvcc.store_id().0
        && mvcc_terminal.terminal_sequence_or_height == mvcc.height()
        && mvcc_terminal.terminal_order_height == prepared.candidate_height()
        && mvcc_terminal.terminal_order_block_id == prepared.candidate_block_id()
        && mvcc.height() == prepared.candidate_height()
        && mvcc.block_id().0 == mvcc_execution_block_id.0
        && mvcc_terminal.terminal_state_or_metadata_root.0 == mvcc.durable_state_root().0
        && mvcc_terminal.terminal_journal_root.0 == mvcc.durable_journal_root().0
        && settlement_terminal.store_id.0 == settlement.store_id().0
        && settlement_terminal.terminal_sequence_or_height == settlement.sequence()
        && settlement_terminal.terminal_order_height == settlement.order_height()
        && settlement_terminal.terminal_order_block_id.0 == settlement.order_block_id().0
        && settlement_terminal.terminal_state_or_metadata_root.0
            == settlement.durable_state_root().0
        && settlement_terminal.terminal_journal_root.0 == settlement.durable_journal_root().0;
    if !exact {
        return Err(error(
            GlobalExecutionErrorCodeV1::RecoveryMismatch,
            "fresh five-plane terminal readback differs from finalized checkpoint owner",
        ));
    }
    Ok(())
}

fn expected_terminal_roots_v1(
    prepared: &CandidateCompositeCommitmentV1,
    plane_tag: u8,
) -> GlobalExecutionResultV1<(Hash32V1, Hash32V1)> {
    let body = &prepared.body;
    match plane_tag {
        0 => Ok((
            Hash32V1([0; 32]),
            digest_value(
                "trnm.poco-ai.global-execution-da-terminal-receipt.candidate.v1",
                &(
                    body.da_batch_id,
                    body.da_certificate_id,
                    body.da_obligation_id,
                    body.da_obligation_version,
                    body.retrieved_batch_digest,
                ),
            )?,
        )),
        1 => Ok((
            body.agent_market_candidate_root,
            body.agent_market_receipts_root,
        )),
        2 => Ok((
            body.verify_challenge_candidate_root,
            body.verify_challenge_receipts_root,
        )),
        3 => Ok((body.mvcc_fee_candidate_root, body.mvcc_receipts_root)),
        4 => Ok((
            body.consumption_settlement_candidate_root,
            body.consumption_settlement_receipts_root,
        )),
        _ => Err(error(
            GlobalExecutionErrorCodeV1::FinalizationOwnerMismatch,
            "terminal plane tag is unsupported",
        )),
    }
}

fn terminal_source_v1(source_cut: &SourceCutV1, tag: u8) -> GlobalExecutionResultV1<&PlaneHeadV1> {
    let source = source_cut
        .plane_heads
        .get(usize::from(tag))
        .ok_or_else(|| {
            error(
                GlobalExecutionErrorCodeV1::SourceCutMismatch,
                "prepared source cut is missing a terminal plane",
            )
        })?;
    if source.plane_tag != tag {
        return Err(error(
            GlobalExecutionErrorCodeV1::SourceCutMismatch,
            "prepared source cut plane order differs",
        ));
    }
    Ok(source)
}

fn validate_order_source_parent_v1(
    order: &VerifiedOrderFinalityV1,
    source_cut: &SourceCutV1,
    prepared: &CandidateCompositeCommitmentV1,
    batch: &GlobalExecutionBatchV1,
) -> GlobalExecutionResultV1<()> {
    let agent = terminal_source_v1(source_cut, 1)?;
    let verify = terminal_source_v1(source_cut, 2)?;
    let mvcc = terminal_source_v1(source_cut, 3)?;
    let settlement = terminal_source_v1(source_cut, 4)?;
    let expected_parent_height = prepared.candidate_height().checked_sub(1).ok_or_else(|| {
        error(
            GlobalExecutionErrorCodeV1::FinalizationOwnerMismatch,
            "candidate Order height has no strict predecessor",
        )
    })?;
    if agent.order_height != expected_parent_height
        || verify.order_height != expected_parent_height
        || settlement.order_height != expected_parent_height
        || verify.order_block_id != agent.order_block_id
        || settlement.order_block_id != agent.order_block_id
        || !order.proves_strict_ancestor_v1(expected_parent_height, agent.order_block_id.0)
        || mvcc.sequence_or_height != expected_parent_height
        || mvcc.order_height != expected_parent_height
        || batch.mvcc_fee_block.expected_parent_height != expected_parent_height
        || batch.mvcc_fee_block.expected_parent_block_id.0 != mvcc.order_block_id.0
        || batch.mvcc_fee_block.height != prepared.candidate_height()
    {
        return Err(error(
            GlobalExecutionErrorCodeV1::FinalizationOwnerMismatch,
            "source cut is not the exact verified Order parent plus exact MVCC execution parent",
        ));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn validate_ordered_plane_progress_v1(
    source: &PlaneHeadV1,
    store_id: [u8; 32],
    sequence: u64,
    order_height: u64,
    order_block_id: [u8; 32],
    candidate_height: u64,
    candidate_block_id: Hash32V1,
    command_count: usize,
) -> GlobalExecutionResultV1<()> {
    let command_count = u64::try_from(command_count).map_err(|_| {
        error(
            GlobalExecutionErrorCodeV1::ArithmeticOverflow,
            "ordered-plane command count exceeds u64",
        )
    })?;
    let terminal_sequence = source
        .sequence_or_height
        .checked_add(command_count)
        .ok_or_else(|| {
            error(
                GlobalExecutionErrorCodeV1::ArithmeticOverflow,
                "ordered-plane terminal sequence overflows",
            )
        })?;
    let at_source = sequence == source.sequence_or_height
        && order_height == source.order_height
        && order_block_id == source.order_block_id.0;
    let resuming_target = sequence >= source.sequence_or_height
        && sequence <= terminal_sequence
        && order_height == candidate_height
        && order_block_id == candidate_block_id.0;
    if store_id != source.store_id.0 || (!at_source && !resuming_target) {
        return Err(error(
            GlobalExecutionErrorCodeV1::SourceCutMismatch,
            "ordered source plane is neither the prepared parent nor a bounded target prefix",
        ));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn validate_ordered_plane_target_v1(
    source: &PlaneHeadV1,
    store_id: [u8; 32],
    sequence: u64,
    order_height: u64,
    order_block_id: [u8; 32],
    state_root: [u8; 32],
    journal_root: [u8; 32],
    candidate_height: u64,
    candidate_block_id: Hash32V1,
    command_count: usize,
    expected_state_root: Hash32V1,
    receipts_root: Hash32V1,
    expected_receipts_root: Hash32V1,
) -> GlobalExecutionResultV1<()> {
    let command_count = u64::try_from(command_count).map_err(|_| {
        error(
            GlobalExecutionErrorCodeV1::ArithmeticOverflow,
            "ordered-plane command count exceeds u64",
        )
    })?;
    let expected_sequence = source
        .sequence_or_height
        .checked_add(command_count)
        .ok_or_else(|| {
            error(
                GlobalExecutionErrorCodeV1::ArithmeticOverflow,
                "ordered-plane terminal sequence overflows",
            )
        })?;
    if store_id != source.store_id.0
        || sequence != expected_sequence
        || order_height != candidate_height
        || order_block_id != candidate_block_id.0
        || state_root != expected_state_root.0
        || journal_root == [0; 32]
        || receipts_root != expected_receipts_root
    {
        return Err(error(
            GlobalExecutionErrorCodeV1::FinalizationOwnerMismatch,
            "ordered source-plane target differs from prepared execution",
        ));
    }
    Ok(())
}

fn validate_mvcc_progress_v1(
    source: &PlaneHeadV1,
    observed: &trnm_poco_mvcc_fee_v1::MvccFeeFreshReadbackV1,
    candidate_height: u64,
    mvcc_execution_block_id: Hash32V1,
) -> GlobalExecutionResultV1<()> {
    let at_source = observed.height() == source.sequence_or_height
        && observed.block_id().0 == source.order_block_id.0
        && observed.durable_state_root().0 == source.state_or_metadata_root.0
        && observed.durable_journal_root().0 == source.journal_root.0;
    let at_target =
        observed.height() == candidate_height && observed.block_id().0 == mvcc_execution_block_id.0;
    if observed.store_id().0 != source.store_id.0 || (!at_source && !at_target) {
        return Err(error(
            GlobalExecutionErrorCodeV1::SourceCutMismatch,
            "MVCC/Fee source is neither the prepared parent nor exact target",
        ));
    }
    Ok(())
}

fn ordered_terminal_v1(
    source: &PlaneHeadV1,
    terminal_sequence_or_height: u64,
    terminal_state_root: [u8; 32],
    terminal_receipts_root: Hash32V1,
    terminal_journal_root: [u8; 32],
    candidate_height: u64,
    candidate_block_id: Hash32V1,
) -> PlaneTerminalFactsV1 {
    PlaneTerminalFactsV1 {
        plane_tag: source.plane_tag,
        store_id: source.store_id,
        source_sequence_or_height: source.sequence_or_height,
        source_state_or_metadata_root: source.state_or_metadata_root,
        source_journal_root: source.journal_root,
        terminal_sequence_or_height,
        terminal_order_height: candidate_height,
        terminal_order_block_id: candidate_block_id,
        terminal_state_or_metadata_root: Hash32V1(terminal_state_root),
        terminal_receipts_root,
        terminal_journal_root: Hash32V1(terminal_journal_root),
    }
}

#[cfg(test)]
fn test_plane_terminals_v1(
    source_cut: &SourceCutV1,
    prepared: &CandidateCompositeCommitmentV1,
) -> GlobalExecutionResultV1<Vec<PlaneTerminalFactsV1>> {
    source_cut
        .plane_heads
        .iter()
        .map(|source| {
            let (mut terminal_state, terminal_receipts) =
                expected_terminal_roots_v1(prepared, source.plane_tag)?;
            let (terminal_sequence_or_height, terminal_order_height, terminal_order_block_id) =
                if source.plane_tag == 0 {
                    terminal_state = source.state_or_metadata_root;
                    (source.sequence_or_height, 0, Hash32V1([0; 32]))
                } else {
                    (
                        source.sequence_or_height.checked_add(1).ok_or_else(|| {
                            error(
                                GlobalExecutionErrorCodeV1::ArithmeticOverflow,
                                "test terminal position overflows",
                            )
                        })?,
                        prepared.candidate_height(),
                        prepared.candidate_block_id(),
                    )
                };
            let terminal_journal_root = if source.plane_tag == 0 {
                source.journal_root
            } else {
                digest_value(
                    "trnm.poco-ai.global-execution-plane-terminal-journal.candidate.v1",
                    &(
                        source.plane_tag,
                        source.journal_root,
                        prepared.candidate_block_id(),
                        terminal_state,
                        terminal_receipts,
                    ),
                )?
            };
            Ok(PlaneTerminalFactsV1 {
                plane_tag: source.plane_tag,
                store_id: source.store_id,
                source_sequence_or_height: source.sequence_or_height,
                source_state_or_metadata_root: source.state_or_metadata_root,
                source_journal_root: source.journal_root,
                terminal_sequence_or_height,
                terminal_order_height,
                terminal_order_block_id,
                terminal_state_or_metadata_root: terminal_state,
                terminal_receipts_root: terminal_receipts,
                terminal_journal_root,
            })
        })
        .collect()
}

fn audit_checkpoint_history(
    connection: &Connection,
    current: &CheckpointRecordV1,
) -> GlobalExecutionResultV1<()> {
    let mut statement = connection.prepare(
        "SELECT generation,checkpoint_checksum,record_kind,record FROM global_execution_checkpoints_v1 ORDER BY generation",
    )?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, Vec<u8>>(3)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    let expected_length = current
        .body
        .generation
        .checked_add(1)
        .and_then(|value| usize::try_from(value).ok())
        .ok_or_else(|| {
            error(
                GlobalExecutionErrorCodeV1::ArithmeticOverflow,
                "checkpoint history length exceeds usize",
            )
        })?;
    if rows.len() != expected_length {
        return Err(error(
            GlobalExecutionErrorCodeV1::CheckpointTamper,
            "checkpoint history is partial or contains a future row",
        ));
    }

    let mut previous: Option<CheckpointRecordV1> = None;
    let mut prepared_count = 0usize;
    let mut finalized_count = 0usize;
    for (index, (generation, checksum, record_kind, raw)) in rows.into_iter().enumerate() {
        let expected_generation = u64::try_from(index).map_err(|_| {
            error(
                GlobalExecutionErrorCodeV1::ArithmeticOverflow,
                "checkpoint history index exceeds u64",
            )
        })?;
        let record: CheckpointRecordV1 = strict_decode(&raw)?;
        audit_checkpoint(&record)?;
        if generation != expected_generation.to_be_bytes()
            || checksum != record.checksum.0
            || record.body.generation != expected_generation
            || record.body.scope != current.body.scope
            || record.body.source_cut != current.body.source_cut
        {
            return Err(error(
                GlobalExecutionErrorCodeV1::CheckpointTamper,
                "checkpoint history row differs from its canonical record",
            ));
        }
        if let Some(parent) = &previous {
            if record.body.predecessor_checksum != parent.checksum {
                return Err(error(
                    GlobalExecutionErrorCodeV1::CheckpointTamper,
                    "checkpoint history predecessor chain is broken",
                ));
            }
        }
        let expected_kind = if record.body.generation == 0 {
            0
        } else if record.body.finalized.is_some() {
            2
        } else {
            1
        };
        if record_kind != expected_kind {
            return Err(error(
                GlobalExecutionErrorCodeV1::CheckpointTamper,
                "checkpoint history kind differs",
            ));
        }
        match expected_kind {
            0 => {}
            1 => {
                prepared_count = prepared_count.checked_add(1).ok_or_else(|| {
                    error(
                        GlobalExecutionErrorCodeV1::ArithmeticOverflow,
                        "prepared history count overflows",
                    )
                })?;
                audit_prepared_history_row_v1(connection, &record)?;
            }
            2 => {
                finalized_count = finalized_count.checked_add(1).ok_or_else(|| {
                    error(
                        GlobalExecutionErrorCodeV1::ArithmeticOverflow,
                        "finalized history count overflows",
                    )
                })?;
                if finalized_count != 1 || index + 1 != expected_length {
                    return Err(error(
                        GlobalExecutionErrorCodeV1::FinalizationTamper,
                        "terminal checkpoint must be the unique history tail",
                    ));
                }
                let parent = previous.as_ref().ok_or_else(|| {
                    error(
                        GlobalExecutionErrorCodeV1::FinalizationTamper,
                        "terminal checkpoint has no prepared predecessor",
                    )
                })?;
                if parent.body.finalized.is_some() || parent.body.prepared != record.body.prepared {
                    return Err(error(
                        GlobalExecutionErrorCodeV1::FinalizationTamper,
                        "terminal checkpoint does not retain the exact prepared predecessor",
                    ));
                }
                audit_finalized_history_row_v1(connection, &record)?;
            }
            _ => unreachable!("record kind is locally derived"),
        }
        previous = Some(record);
    }
    if previous.as_ref() != Some(current) {
        return Err(error(
            GlobalExecutionErrorCodeV1::CheckpointTamper,
            "checkpoint metadata is not the exact history tail",
        ));
    }
    let stored_prepared: i64 = connection.query_row(
        "SELECT COUNT(*) FROM global_execution_prepared_v1",
        [],
        |row| row.get(0),
    )?;
    let stored_finalized: i64 = connection.query_row(
        "SELECT COUNT(*) FROM global_execution_finalized_v1",
        [],
        |row| row.get(0),
    )?;
    if usize::try_from(stored_prepared).ok() != Some(prepared_count)
        || usize::try_from(stored_finalized).ok() != Some(finalized_count)
    {
        return Err(error(
            GlobalExecutionErrorCodeV1::CheckpointTamper,
            "checkpoint evidence table counts differ from history",
        ));
    }
    Ok(())
}

fn audit_prepared_history_row_v1(
    connection: &Connection,
    record: &CheckpointRecordV1,
) -> GlobalExecutionResultV1<()> {
    let expected = record.body.prepared.as_ref().ok_or_else(|| {
        error(
            GlobalExecutionErrorCodeV1::CheckpointTamper,
            "prepared history row has no commitment",
        )
    })?;
    let row: Option<PreparedEvidenceRowV1> = connection
        .query_row(
            "SELECT generation,candidate_composite_root,checkpoint_checksum,commitment FROM global_execution_prepared_v1 WHERE candidate_block_id=?1",
            params![&expected.body.candidate_block_id.0[..]],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .optional()?;
    let Some((generation, root, checkpoint_checksum, raw)) = row else {
        return Err(error(
            GlobalExecutionErrorCodeV1::CheckpointTamper,
            "prepared history evidence row is absent",
        ));
    };
    let commitment: CandidateCompositeCommitmentV1 = strict_decode(&raw)?;
    validate_commitment(&commitment)?;
    if commitment != *expected
        || generation != record.body.generation.to_be_bytes()
        || root != expected.candidate_composite_root.0
        || checkpoint_checksum != record.checksum.0
    {
        return Err(error(
            GlobalExecutionErrorCodeV1::CheckpointTamper,
            "prepared history evidence row differs",
        ));
    }
    Ok(())
}

fn audit_finalized_history_row_v1(
    connection: &Connection,
    record: &CheckpointRecordV1,
) -> GlobalExecutionResultV1<()> {
    let expected = record.body.finalized.as_ref().ok_or_else(|| {
        error(
            GlobalExecutionErrorCodeV1::FinalizationTamper,
            "terminal history row has no commitment",
        )
    })?;
    let row: Option<FinalizedEvidenceRowV1> = connection
            .query_row(
                "SELECT generation,prepared_generation,prepared_checkpoint_checksum,candidate_composite_root,final_execution_root,checkpoint_checksum,commitment FROM global_execution_finalized_v1 WHERE candidate_block_id=?1",
                params![&expected.body.candidate_block_id.0[..]],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                        row.get(6)?,
                    ))
                },
            )
            .optional()?;
    let Some((
        generation,
        prepared_generation,
        prepared_checksum,
        composite_root,
        final_root,
        checkpoint_checksum,
        raw,
    )) = row
    else {
        return Err(error(
            GlobalExecutionErrorCodeV1::FinalizationTamper,
            "terminal history evidence row is absent",
        ));
    };
    let commitment: WholeNodeFinalExecutionCommitmentV1 = strict_decode(&raw)?;
    validate_final_execution_commitment(&commitment)?;
    if commitment != *expected
        || generation != record.body.generation.to_be_bytes()
        || prepared_generation != expected.body.prepared_checkpoint_generation.to_be_bytes()
        || prepared_checksum != expected.body.prepared_checkpoint_checksum.0
        || composite_root != expected.body.candidate_composite_root.0
        || final_root != expected.final_execution_root.0
        || checkpoint_checksum != record.checksum.0
    {
        return Err(error(
            GlobalExecutionErrorCodeV1::FinalizationTamper,
            "terminal history evidence row differs",
        ));
    }
    Ok(())
}

fn load_metadata_from(
    connection: &Connection,
) -> GlobalExecutionResultV1<(CheckpointRecordV1, bool)> {
    let (generation, checksum, fenced, raw): (Vec<u8>, Vec<u8>, i64, Vec<u8>) = connection
        .query_row(
            "SELECT generation,checkpoint_checksum,fenced,record FROM global_execution_metadata_v1 WHERE singleton=1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )?;
    let record: CheckpointRecordV1 = strict_decode(&raw)?;
    if generation != record.body.generation.to_be_bytes()
        || checksum != record.checksum.0
        || !matches!(fenced, 0 | 1)
    {
        return Err(error(
            GlobalExecutionErrorCodeV1::CheckpointTamper,
            "checkpoint metadata differs from canonical record",
        ));
    }
    Ok((record, fenced == 1))
}

fn verify_schema(connection: &Connection) -> GlobalExecutionResultV1<()> {
    if connection.query_row("PRAGMA application_id", [], |row| row.get::<_, i64>(0))?
        != SQLITE_APPLICATION_ID_V1
        || connection.query_row("PRAGMA user_version", [], |row| row.get::<_, i64>(0))?
            != SQLITE_USER_VERSION_V1
    {
        return Err(error(
            GlobalExecutionErrorCodeV1::CheckpointTamper,
            "checkpoint SQLite identity/schema version differs",
        ));
    }
    let mut statement = connection.prepare(
        "SELECT name,sql FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name",
    )?;
    let actual = statement
        .query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    let expected = vec![
        (
            "global_execution_checkpoints_v1".to_owned(),
            CHECKPOINTS_SQL.to_owned(),
        ),
        (
            "global_execution_finalized_v1".to_owned(),
            FINALIZED_SQL.to_owned(),
        ),
        (
            "global_execution_metadata_v1".to_owned(),
            META_SQL.to_owned(),
        ),
        (
            "global_execution_prepared_v1".to_owned(),
            PREPARED_SQL.to_owned(),
        ),
    ];
    if actual != expected {
        return Err(error(
            GlobalExecutionErrorCodeV1::CheckpointTamper,
            "checkpoint SQLite schema differs",
        ));
    }
    Ok(())
}

fn validate_path(path: &Path, must_exist: bool) -> GlobalExecutionResultV1<PathBuf> {
    if !path.is_absolute() {
        return Err(error(
            GlobalExecutionErrorCodeV1::CheckpointUnavailable,
            "checkpoint path must be absolute",
        ));
    }
    let parent = path
        .parent()
        .ok_or_else(|| unavailable("checkpoint path has no parent"))?;
    let parent = fs::canonicalize(parent).map_err(|cause| unavailable(cause.to_string()))?;
    let name = path
        .file_name()
        .ok_or_else(|| unavailable("checkpoint path has no file name"))?;
    let resolved = parent.join(name);
    if resolved.exists() != must_exist {
        return Err(error(
            GlobalExecutionErrorCodeV1::CheckpointUnavailable,
            "checkpoint path existence differs",
        ));
    }
    Ok(resolved)
}

fn open_rw_raw(path: &Path) -> GlobalExecutionResultV1<Connection> {
    let connection = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    connection.busy_timeout(Duration::from_secs(2))?;
    Ok(connection)
}

fn configure_rw(connection: &Connection) -> GlobalExecutionResultV1<()> {
    connection.pragma_update(None, "journal_mode", "DELETE")?;
    connection.pragma_update(None, "synchronous", "FULL")?;
    connection.pragma_update(None, "foreign_keys", true)?;
    Ok(())
}

fn open_ro(path: &Path) -> GlobalExecutionResultV1<Connection> {
    let bytes = path.as_os_str().as_encoded_bytes();
    let mut uri = String::from("file:");
    for byte in bytes {
        if byte.is_ascii_alphanumeric() || matches!(*byte, b'/' | b'.' | b'_' | b'-') {
            uri.push(char::from(*byte));
        } else {
            uri.push_str(&format!("%{byte:02X}"));
        }
    }
    uri.push_str("?mode=ro&immutable=1");
    let connection = Connection::open_with_flags(
        uri,
        OpenFlags::SQLITE_OPEN_READ_ONLY
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_URI,
    )?;
    connection.busy_timeout(Duration::from_secs(2))?;
    Ok(connection)
}

fn reject_sidecars(path: &Path) -> GlobalExecutionResultV1<()> {
    for suffix in ["-wal", "-shm", "-journal"] {
        let mut sidecar: OsString = path.as_os_str().to_os_string();
        sidecar.push(suffix);
        if Path::new(&sidecar).exists() {
            return Err(error(
                GlobalExecutionErrorCodeV1::CheckpointUnavailable,
                "checkpoint SQLite sidecar is present",
            ));
        }
    }
    Ok(())
}

fn plane_error(
    code: GlobalExecutionErrorCodeV1,
    cause: impl std::fmt::Display,
) -> crate::GlobalExecutionErrorV1 {
    error(code, cause.to_string())
}

fn unavailable(detail: impl Into<String>) -> crate::GlobalExecutionErrorV1 {
    error(GlobalExecutionErrorCodeV1::CheckpointUnavailable, detail)
}
