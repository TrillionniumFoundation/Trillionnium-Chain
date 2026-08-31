//! Application-authenticated same-version next-epoch commitment authority.
//!
//! This bridge consumes raw cutoff finality and namespace proofs together with
//! the private H3b2b2 candidate capability. It fresh-verifies H1 and H2 with
//! the hard-coded strict Ed25519 boundary, joins their exact cutoff tuple to
//! the checkpoint/candidate authority, and derives the inert consensus
//! commitment without caller-supplied commitment fields or configuration.
//!
//! The resulting crate-private capability does not authorize a checkpoint
//! header, two-seal proof, handoff, epoch anchor, activation, or Core epoch
//! transition. Those remain later composition boundaries.

use anyhow::{ensure, Context, Result};
use trnm_consensus_crypto::StrictEd25519Verifier;
use trnm_consensus_types::{
    decode_block_header_v0_exact, decode_finality_proof_v0_exact,
    verify_finalized_cutoff_header_v0, BlockHeader, BlockKind, CertifiedHeaderV0,
    ConsensusParametersV0, EpochFallbackReasonV0, EpochGeometryV0, Height, NextEpochCommitmentV0,
    NextEpochCommitmentV0Fields, ProtocolVersion, ValidatorSet, SCHEMA_VERSION_V0,
};
use trnm_finality_types::hash_domain;

use crate::{
    poco_application::{
        AuthenticatedPocoCandidateSelectionV0, AuthenticatedPocoCutoffCandidateSelectionV0,
    },
    poco_snapshot::{
        bind_poco_snapshot_namespace_to_cutoff_v0, verify_poco_snapshot_namespace_v0,
        AuthenticatedPocoSnapshotNamespaceV0, PocoSnapshotNamespaceProofV0,
    },
};

const AUTHORIZATION_DOMAIN_V0: &str = "trnm.poco-bft.authorized-next-epoch-commitment.v0";
const PREHEADER_AUTHORIZATION_DOMAIN_V0: &str =
    "trnm.poco-bft.authorized-preheader-next-epoch-commitment.v0";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PocoCutoffTupleV0 {
    epoch: u64,
    height: u64,
    state_root: [u8; 32],
    entries_root: [u8; 32],
    entry_count: u32,
}

trait PocoCommitmentCandidateAuthorityV0 {
    fn old_validator_set(&self) -> &ValidatorSet;
    fn old_parameters(&self) -> &ConsensusParametersV0;
    fn effective_validator_set(&self) -> &ValidatorSet;
    fn effective_parameters(&self) -> &ConsensusParametersV0;
    fn fallback_used(&self) -> bool;
    fn fallback_reason(&self) -> EpochFallbackReasonV0;
    fn candidate_parameters_hash(&self) -> trnm_consensus_types::ConsensusParametersHash;
    fn authorization_id(&self) -> [u8; 32];
    fn cutoff_tuple(&self) -> PocoCutoffTupleV0;
    fn ensure_old_context(
        &self,
        old_validator_set: &ValidatorSet,
        old_parameters: &ConsensusParametersV0,
    ) -> Result<()>;
}

impl PocoCommitmentCandidateAuthorityV0 for AuthenticatedPocoCandidateSelectionV0 {
    fn old_validator_set(&self) -> &ValidatorSet {
        self.old_validator_set()
    }

    fn old_parameters(&self) -> &ConsensusParametersV0 {
        self.old_parameters()
    }

    fn effective_validator_set(&self) -> &ValidatorSet {
        self.effective_validator_set()
    }

    fn effective_parameters(&self) -> &ConsensusParametersV0 {
        self.effective_parameters()
    }

    fn fallback_used(&self) -> bool {
        self.fallback_used()
    }

    fn fallback_reason(&self) -> EpochFallbackReasonV0 {
        self.fallback_reason()
    }

    fn candidate_parameters_hash(&self) -> trnm_consensus_types::ConsensusParametersHash {
        self.candidate_parameters_hash()
    }

    fn authorization_id(&self) -> [u8; 32] {
        self.authorization_id()
    }

    fn cutoff_tuple(&self) -> PocoCutoffTupleV0 {
        let checkpoint = self.checkpoint_execution();
        PocoCutoffTupleV0 {
            epoch: checkpoint.epoch().get(),
            height: checkpoint.cutoff_height().get(),
            state_root: *checkpoint.cutoff_state_root().as_bytes(),
            entries_root: checkpoint.cutoff_entries_root(),
            entry_count: checkpoint.cutoff_entry_count(),
        }
    }

    fn ensure_old_context(
        &self,
        old_validator_set: &ValidatorSet,
        old_parameters: &ConsensusParametersV0,
    ) -> Result<()> {
        let checkpoint = self.checkpoint_execution();
        ensure!(
            checkpoint.genesis_hash() == old_validator_set.genesis_hash()
                && checkpoint.chain_id() == old_validator_set.chain_id()
                && checkpoint.protocol_version() == ProtocolVersion::V0
                && checkpoint.epoch() == old_validator_set.epoch()
                && checkpoint.validator_set_id() == old_validator_set.id()
                && checkpoint.consensus_parameters_hash() == old_parameters.hash(),
            "checkpoint context differs from authenticated old configuration"
        );
        Ok(())
    }
}

impl PocoCommitmentCandidateAuthorityV0 for AuthenticatedPocoCutoffCandidateSelectionV0 {
    fn old_validator_set(&self) -> &ValidatorSet {
        self.old_validator_set()
    }

    fn old_parameters(&self) -> &ConsensusParametersV0 {
        self.old_parameters()
    }

    fn effective_validator_set(&self) -> &ValidatorSet {
        self.effective_validator_set()
    }

    fn effective_parameters(&self) -> &ConsensusParametersV0 {
        self.effective_parameters()
    }

    fn fallback_used(&self) -> bool {
        self.fallback_used()
    }

    fn fallback_reason(&self) -> EpochFallbackReasonV0 {
        self.fallback_reason()
    }

    fn candidate_parameters_hash(&self) -> trnm_consensus_types::ConsensusParametersHash {
        self.candidate_parameters_hash()
    }

    fn authorization_id(&self) -> [u8; 32] {
        self.authorization_id()
    }

    fn cutoff_tuple(&self) -> PocoCutoffTupleV0 {
        let cutoff = self.scheduled_cutoff();
        PocoCutoffTupleV0 {
            epoch: cutoff.epoch().get(),
            height: cutoff.cutoff_height().get(),
            state_root: *cutoff.cutoff_state_root().as_bytes(),
            entries_root: cutoff.cutoff_entries_root(),
            entry_count: cutoff.cutoff_entry_count(),
        }
    }

    fn ensure_old_context(
        &self,
        old_validator_set: &ValidatorSet,
        old_parameters: &ConsensusParametersV0,
    ) -> Result<()> {
        let cutoff = self.scheduled_cutoff();
        ensure!(
            cutoff.genesis_hash() == old_validator_set.genesis_hash()
                && cutoff.chain_id() == old_validator_set.chain_id()
                && cutoff.protocol_version() == ProtocolVersion::V0
                && cutoff.epoch() == old_validator_set.epoch()
                && cutoff.old_validator_set().id() == old_validator_set.id()
                && cutoff.old_parameters().hash() == old_parameters.hash(),
            "scheduled-cutoff context differs from authenticated old configuration"
        );
        Ok(())
    }
}

struct PocoNextEpochCommitmentFactsV0 {
    cutoff_parent_header: BlockHeader,
    checkpoint_parent: CertifiedHeaderV0,
    finalized_cutoff: AuthenticatedPocoSnapshotNamespaceV0,
    old_validator_set: ValidatorSet,
    old_parameters: ConsensusParametersV0,
    new_validator_set: ValidatorSet,
    new_parameters: ConsensusParametersV0,
    commitment: NextEpochCommitmentV0,
}

fn ensure_same_poco_cutoff_tuple_v0(
    finalized: PocoCutoffTupleV0,
    checkpoint: PocoCutoffTupleV0,
) -> Result<()> {
    let epoch_matches = finalized.epoch == checkpoint.epoch;
    let height_matches = finalized.height == checkpoint.height;
    let state_root_matches = finalized.state_root == checkpoint.state_root;
    let entries_root_matches = finalized.entries_root == checkpoint.entries_root;
    let entry_count_matches = finalized.entry_count == checkpoint.entry_count;
    ensure!(
        epoch_matches
            && height_matches
            && state_root_matches
            && entries_root_matches
            && entry_count_matches,
        "H1/H2 cutoff differs from candidate checkpoint authority: epoch={epoch_matches}, height={height_matches}, state_root={state_root_matches}, entries_root={entries_root_matches}, entry_count={entry_count_matches}"
    );
    Ok(())
}

/// Private composition authority for one application-authenticated,
/// same-version next-epoch commitment.
///
/// Every field is retained as an exact preimage or a fresh H1/H2 result. There
/// is no constructor from an inert commitment, candidate kernel, event, or
/// status value.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct AuthorizedPocoNextEpochCommitmentV0 {
    candidate: AuthenticatedPocoCandidateSelectionV0,
    cutoff_parent_header: BlockHeader,
    checkpoint_parent: CertifiedHeaderV0,
    finalized_cutoff: AuthenticatedPocoSnapshotNamespaceV0,
    old_validator_set: ValidatorSet,
    old_parameters: ConsensusParametersV0,
    new_validator_set: ValidatorSet,
    new_parameters: ConsensusParametersV0,
    commitment: NextEpochCommitmentV0,
    authorization_id: [u8; 32],
}

/// Pre-header counterpart of [`AuthorizedPocoNextEpochCommitmentV0`].
///
/// Its candidate authority is cutoff-only, so this capability can exist
/// before the checkpoint block hash, timestamp, body, receipts, or
/// post-execution state exist. It still fresh-verifies raw H1 and H2 and is the
/// only input from which the checkpoint-header preparation layer may obtain a
/// next-epoch commitment.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct AuthorizedPocoPreheaderNextEpochCommitmentV0 {
    candidate: AuthenticatedPocoCutoffCandidateSelectionV0,
    cutoff_parent_header: BlockHeader,
    checkpoint_parent: CertifiedHeaderV0,
    finalized_cutoff: AuthenticatedPocoSnapshotNamespaceV0,
    old_validator_set: ValidatorSet,
    old_parameters: ConsensusParametersV0,
    new_validator_set: ValidatorSet,
    new_parameters: ConsensusParametersV0,
    commitment: NextEpochCommitmentV0,
    authorization_id: [u8; 32],
}

impl AuthorizedPocoNextEpochCommitmentV0 {
    pub(crate) const fn candidate(&self) -> &AuthenticatedPocoCandidateSelectionV0 {
        &self.candidate
    }

    pub(crate) const fn cutoff_parent_header(&self) -> &BlockHeader {
        &self.cutoff_parent_header
    }

    /// Exact height-(checkpoint - 1) proposal witness and ordinary
    /// certifying QC retained from the freshly strict-verified H1 proof.
    pub(crate) const fn checkpoint_parent(&self) -> &CertifiedHeaderV0 {
        &self.checkpoint_parent
    }

    pub(crate) const fn finalized_cutoff(&self) -> AuthenticatedPocoSnapshotNamespaceV0 {
        self.finalized_cutoff
    }

    pub(crate) const fn old_validator_set(&self) -> &ValidatorSet {
        &self.old_validator_set
    }

    pub(crate) const fn old_parameters(&self) -> &ConsensusParametersV0 {
        &self.old_parameters
    }

    pub(crate) const fn new_validator_set(&self) -> &ValidatorSet {
        &self.new_validator_set
    }

    pub(crate) const fn new_parameters(&self) -> &ConsensusParametersV0 {
        &self.new_parameters
    }

    pub(crate) const fn commitment(&self) -> NextEpochCommitmentV0 {
        self.commitment
    }

    pub(crate) const fn authorization_id(&self) -> [u8; 32] {
        self.authorization_id
    }
}

impl AuthorizedPocoPreheaderNextEpochCommitmentV0 {
    pub(crate) const fn candidate(&self) -> &AuthenticatedPocoCutoffCandidateSelectionV0 {
        &self.candidate
    }

    pub(crate) const fn scheduled_cutoff(
        &self,
    ) -> &crate::poco_checkpoint::AuthorizedPocoScheduledCutoffV0 {
        self.candidate.scheduled_cutoff()
    }

    pub(crate) const fn cutoff_parent_header(&self) -> &BlockHeader {
        &self.cutoff_parent_header
    }

    /// Exact height-(checkpoint - 1) proposal witness and ordinary
    /// certifying QC retained from the freshly strict-verified H1 proof.
    pub(crate) const fn checkpoint_parent(&self) -> &CertifiedHeaderV0 {
        &self.checkpoint_parent
    }

    pub(crate) const fn finalized_cutoff(&self) -> AuthenticatedPocoSnapshotNamespaceV0 {
        self.finalized_cutoff
    }

    pub(crate) const fn old_validator_set(&self) -> &ValidatorSet {
        &self.old_validator_set
    }

    pub(crate) const fn old_parameters(&self) -> &ConsensusParametersV0 {
        &self.old_parameters
    }

    pub(crate) const fn new_validator_set(&self) -> &ValidatorSet {
        &self.new_validator_set
    }

    pub(crate) const fn new_parameters(&self) -> &ConsensusParametersV0 {
        &self.new_parameters
    }

    pub(crate) const fn commitment(&self) -> NextEpochCommitmentV0 {
        self.commitment
    }

    pub(crate) const fn authorization_id(&self) -> [u8; 32] {
        self.authorization_id
    }
}

/// Fresh-verifies one raw H1 finality proof and raw H2 namespace bundle, joins
/// both to the private H3b2b2 candidate/checkpoint cutoff, and derives the
/// unique same-version commitment.
///
/// The signature verifier, old/new configuration, fallback fields,
/// activation height, protocol version, and commitment fields are deliberately
/// not caller inputs.
fn verify_poco_next_epoch_commitment_v0(
    candidate: &impl PocoCommitmentCandidateAuthorityV0,
    raw_finalized_cutoff_proof_cev0: &[u8],
    raw_cutoff_parent_header_cev0: &[u8],
    raw_snapshot_namespace_proof: &PocoSnapshotNamespaceProofV0,
) -> Result<PocoNextEpochCommitmentFactsV0> {
    let old_validator_set = candidate.old_validator_set().clone();
    let old_parameters = *candidate.old_parameters();
    old_validator_set
        .validate_against_parameters(&old_parameters)
        .map_err(|error| anyhow::anyhow!("invalid authenticated old configuration: {error:?}"))?;
    ensure!(
        old_parameters.snapshot_lead_blocks()
            >= u64::from(old_parameters.finality_certified_chain_length()),
        "snapshot lead is shorter than the finality proof chain; commitment cannot be derived before checkpoint proposal"
    );

    let cutoff_parent_header = decode_block_header_v0_exact(raw_cutoff_parent_header_cev0)
        .map_err(|error| anyhow::anyhow!("decode exact cutoff parent header: {error:?}"))?;
    let finalized_cutoff_proof = decode_finality_proof_v0_exact(
        raw_finalized_cutoff_proof_cev0,
        &old_validator_set,
        &old_parameters,
        cutoff_parent_header.timestamp_ms(),
    )
    .map_err(|error| anyhow::anyhow!("decode exact finalized-cutoff proof: {error:?}"))?;
    let finalized_block_header = finalized_cutoff_proof.finalized_block().header();
    let justify_qc = finalized_cutoff_proof
        .finalized_block()
        .justify_qc()
        .as_ordinary()
        .context("finalized cutoff justify must be an ordinary QC")?;
    ensure!(
        cutoff_parent_header.genesis_hash() == old_validator_set.genesis_hash()
            && cutoff_parent_header.chain_id() == old_validator_set.chain_id()
            && cutoff_parent_header.protocol_version() == old_validator_set.protocol_version()
            && cutoff_parent_header.epoch() == old_validator_set.epoch()
            && cutoff_parent_header.validator_set_id() == old_validator_set.id()
            && cutoff_parent_header.consensus_parameters_hash() == old_parameters.hash(),
        "cutoff parent header differs from authenticated old context"
    );
    ensure!(
        cutoff_parent_header
            .height()
            .get()
            .checked_add(1)
            .is_some_and(|height| height == finalized_block_header.height().get()),
        "cutoff parent height is not immediately before finalized cutoff"
    );
    ensure!(
        cutoff_parent_header.id() == finalized_block_header.parent_id()
            && cutoff_parent_header.id() == justify_qc.block_id()
            && cutoff_parent_header.height() == justify_qc.height()
            && cutoff_parent_header.view() == justify_qc.view(),
        "cutoff parent header differs from finalized ordinary justify QC"
    );
    let geometry = EpochGeometryV0::new(old_validator_set.epoch(), &old_parameters)
        .map_err(|error| anyhow::anyhow!("invalid commitment epoch geometry: {error:?}"))?;
    let expected_parent_kind = geometry
        .expected_block_kind(cutoff_parent_header.height())
        .map_err(|error| anyhow::anyhow!("cutoff parent schedule: {error:?}"))?;
    ensure!(
        expected_parent_kind == BlockKind::Regular
            && cutoff_parent_header.block_kind() == expected_parent_kind,
        "cutoff parent is not the expected regular scheduled block"
    );

    // H1 is intentionally re-run from the raw proof. An earlier generic-
    // verifier token is neither accepted nor rebound here.
    let finalized_header = verify_finalized_cutoff_header_v0(
        &finalized_cutoff_proof,
        &old_validator_set,
        &old_parameters,
        cutoff_parent_header.timestamp_ms(),
        &StrictEd25519Verifier,
    )
    .map_err(|error| anyhow::anyhow!("strict finalized-cutoff verification failed: {error:?}"))?;

    // The same strict H1 proof also authenticates its exact certified
    // grandchild.  Under the lead-3 geometry that object is the regular block
    // immediately preceding the checkpoint.  Retain the complete proposal
    // witness and certifying QC instead of accepting a second, caller-supplied
    // parent header at the pre-header seam.
    let checkpoint_parent = finalized_cutoff_proof.grandchild().clone();
    let checkpoint_parent_header = checkpoint_parent.header();
    let expected_checkpoint_parent_kind = geometry
        .expected_block_kind(checkpoint_parent_header.height())
        .map_err(|error| anyhow::anyhow!("checkpoint parent schedule: {error:?}"))?;
    ensure!(
        checkpoint_parent_header
            .height()
            .get()
            .checked_add(1)
            .is_some_and(|height| height == geometry.checkpoint_height().get())
            && expected_checkpoint_parent_kind == BlockKind::Regular
            && checkpoint_parent_header.block_kind() == BlockKind::Regular
            && checkpoint_parent_header
                .next_epoch_commitment_hash()
                .is_none(),
        "strict H1 grandchild is not the expected commitment-free checkpoint parent"
    );

    // H2 is likewise re-run from the complete raw ICS23 bundle at the exact
    // H1 version/root before the two results are sealed together.
    let verified_namespace = verify_poco_snapshot_namespace_v0(
        finalized_header.cutoff_height().get(),
        *finalized_header.cutoff_state_root().as_bytes(),
        raw_snapshot_namespace_proof,
    )?;
    let finalized_cutoff =
        bind_poco_snapshot_namespace_to_cutoff_v0(verified_namespace, &finalized_header)?;
    ensure!(
        finalized_cutoff.absence_count() == 0,
        "H3b2b3a does not authorize non-empty absence evidence without query/proof identity sealing"
    );

    candidate.ensure_old_context(&old_validator_set, &old_parameters)?;
    ensure_same_poco_cutoff_tuple_v0(
        PocoCutoffTupleV0 {
            epoch: finalized_cutoff.epoch().get(),
            height: finalized_cutoff.cutoff_height().get(),
            state_root: *finalized_cutoff.cutoff_state_root().as_bytes(),
            entries_root: finalized_cutoff.entries_root(),
            entry_count: finalized_cutoff.entry_count(),
        },
        candidate.cutoff_tuple(),
    )?;

    let new_validator_set = candidate.effective_validator_set().clone();
    let new_parameters = *candidate.effective_parameters();
    let activation_height = geometry
        .epoch_end()
        .get()
        .checked_add(1)
        .map(Height::new)
        .context("next-epoch activation height overflow")?;

    let commitment = NextEpochCommitmentV0::new(NextEpochCommitmentV0Fields {
        schema_version: SCHEMA_VERSION_V0,
        genesis_hash: old_validator_set.genesis_hash(),
        chain_id: old_validator_set.chain_id(),
        old_epoch: old_validator_set.epoch(),
        new_epoch: new_validator_set.epoch(),
        snapshot_cutoff_height: finalized_cutoff.cutoff_height(),
        snapshot_state_root: finalized_cutoff.cutoff_state_root(),
        new_protocol_version: ProtocolVersion::V0,
        new_validator_set_hash: new_validator_set.id(),
        new_consensus_parameters_hash: new_parameters.hash(),
        rollout_phase: new_parameters.rollout_phase(),
        upgrade_plan_hash: None,
        fallback_used: candidate.fallback_used(),
        fallback_reason: candidate.fallback_reason(),
        activation_height,
    })
    .map_err(|error| anyhow::anyhow!("derive same-version commitment: {error:?}"))?;
    commitment
        .validate_same_version_context(
            &old_validator_set,
            &old_parameters,
            &new_validator_set,
            &new_parameters,
        )
        .map_err(|error| anyhow::anyhow!("authorize same-version commitment: {error:?}"))?;

    // H1's narrow cutoff token exposes only the finalized header, but the
    // strict proof verification above authenticates the full carrier chain.
    // We retain the certified grandchild solely as the exact pre-checkpoint
    // parent; it is not checkpoint execution authority. In particular, this
    // layer cannot equate the H3b2a CometBFT block hash with a native PoCO
    // BlockId or interpret checkpoint body roots; that join remains H3b2b3b.

    Ok(PocoNextEpochCommitmentFactsV0 {
        cutoff_parent_header,
        checkpoint_parent,
        finalized_cutoff,
        old_validator_set,
        old_parameters,
        new_validator_set,
        new_parameters,
        commitment,
    })
}

fn poco_next_epoch_commitment_authorization_id_v0(
    domain: &str,
    candidate: &impl PocoCommitmentCandidateAuthorityV0,
    raw_cutoff_parent_header_cev0: &[u8],
    facts: &PocoNextEpochCommitmentFactsV0,
) -> Result<[u8; 32]> {
    let old_set_bytes = facts
        .old_validator_set
        .try_cev0_bytes()
        .map_err(|error| anyhow::anyhow!("encode old validator set: {error:?}"))?;
    let new_set_bytes = facts
        .new_validator_set
        .try_cev0_bytes()
        .map_err(|error| anyhow::anyhow!("encode new validator set: {error:?}"))?;
    let old_parameter_bytes = facts.old_parameters.canonical_bytes();
    let new_parameter_bytes = facts.new_parameters.canonical_bytes();
    let commitment_bytes = facts
        .commitment
        .try_cev0_bytes()
        .map_err(|error| anyhow::anyhow!("encode next-epoch commitment: {error:?}"))?;
    let entry_count = facts.finalized_cutoff.entry_count().to_be_bytes();
    let absence_count = facts.finalized_cutoff.absence_count().to_be_bytes();
    let candidate_parameters_hash = candidate.candidate_parameters_hash();
    let candidate_authorization_id = candidate.authorization_id();
    let entries_root = facts.finalized_cutoff.entries_root();
    Ok(hash_domain(
        domain,
        &[
            &candidate_authorization_id,
            candidate_parameters_hash.as_bytes(),
            raw_cutoff_parent_header_cev0,
            facts.finalized_cutoff.proof_id().as_bytes(),
            facts.finalized_cutoff.cutoff_block_id().as_bytes(),
            facts.finalized_cutoff.cutoff_state_root().as_bytes(),
            &entries_root,
            &entry_count,
            &absence_count,
            &old_set_bytes,
            &old_parameter_bytes,
            &new_set_bytes,
            &new_parameter_bytes,
            &commitment_bytes,
        ],
    ))
}

/// Fresh-verifies H1/H2 and joins them to the existing post-execution
/// candidate authority. This preserves the H3b2b3a authorization preimage and
/// remains useful as an independent post-execution consistency witness.
pub(crate) fn authorize_poco_next_epoch_commitment_v0(
    candidate: AuthenticatedPocoCandidateSelectionV0,
    raw_finalized_cutoff_proof_cev0: &[u8],
    raw_cutoff_parent_header_cev0: &[u8],
    raw_snapshot_namespace_proof: &PocoSnapshotNamespaceProofV0,
) -> Result<AuthorizedPocoNextEpochCommitmentV0> {
    let facts = verify_poco_next_epoch_commitment_v0(
        &candidate,
        raw_finalized_cutoff_proof_cev0,
        raw_cutoff_parent_header_cev0,
        raw_snapshot_namespace_proof,
    )?;
    let authorization_id = poco_next_epoch_commitment_authorization_id_v0(
        AUTHORIZATION_DOMAIN_V0,
        &candidate,
        raw_cutoff_parent_header_cev0,
        &facts,
    )?;
    Ok(AuthorizedPocoNextEpochCommitmentV0 {
        candidate,
        cutoff_parent_header: facts.cutoff_parent_header,
        checkpoint_parent: facts.checkpoint_parent,
        finalized_cutoff: facts.finalized_cutoff,
        old_validator_set: facts.old_validator_set,
        old_parameters: facts.old_parameters,
        new_validator_set: facts.new_validator_set,
        new_parameters: facts.new_parameters,
        commitment: facts.commitment,
        authorization_id,
    })
}

/// Fresh-verifies the same raw H1/H2 evidence against the cutoff-only
/// candidate authority, deriving the unique commitment before the checkpoint
/// header or block ID exists.
pub(crate) fn authorize_poco_preheader_next_epoch_commitment_v0(
    candidate: AuthenticatedPocoCutoffCandidateSelectionV0,
    raw_finalized_cutoff_proof_cev0: &[u8],
    raw_cutoff_parent_header_cev0: &[u8],
    raw_snapshot_namespace_proof: &PocoSnapshotNamespaceProofV0,
) -> Result<AuthorizedPocoPreheaderNextEpochCommitmentV0> {
    let facts = verify_poco_next_epoch_commitment_v0(
        &candidate,
        raw_finalized_cutoff_proof_cev0,
        raw_cutoff_parent_header_cev0,
        raw_snapshot_namespace_proof,
    )?;
    let authorization_id = poco_next_epoch_commitment_authorization_id_v0(
        PREHEADER_AUTHORIZATION_DOMAIN_V0,
        &candidate,
        raw_cutoff_parent_header_cev0,
        &facts,
    )?;
    Ok(AuthorizedPocoPreheaderNextEpochCommitmentV0 {
        candidate,
        cutoff_parent_header: facts.cutoff_parent_header,
        checkpoint_parent: facts.checkpoint_parent,
        finalized_cutoff: facts.finalized_cutoff,
        old_validator_set: facts.old_validator_set,
        old_parameters: facts.old_parameters,
        new_validator_set: facts.new_validator_set,
        new_parameters: facts.new_parameters,
        commitment: facts.commitment,
        authorization_id,
    })
}

#[cfg(test)]
mod tests {
    use super::{ensure_same_poco_cutoff_tuple_v0, PocoCutoffTupleV0};

    #[test]
    fn raw_h1_h2_cutoff_tuple_manifest_branches_fail_closed() {
        let expected = PocoCutoffTupleV0 {
            epoch: 1,
            height: 20,
            state_root: [0x11; 32],
            entries_root: [0x22; 32],
            entry_count: 47,
        };

        let entries_root_error = ensure_same_poco_cutoff_tuple_v0(
            PocoCutoffTupleV0 {
                entries_root: [0x23; 32],
                ..expected
            },
            expected,
        )
        .expect_err("manifest entries-root substitution must fail closed")
        .to_string();
        assert!(
            entries_root_error.contains("entries_root=false")
                && entries_root_error.contains("entry_count=true"),
            "entries-root branch did not identify the exact drift: {entries_root_error}"
        );

        let entry_count_error = ensure_same_poco_cutoff_tuple_v0(
            PocoCutoffTupleV0 {
                entry_count: 48,
                ..expected
            },
            expected,
        )
        .expect_err("manifest entry-count substitution must fail closed")
        .to_string();
        assert!(
            entry_count_error.contains("entries_root=true")
                && entry_count_error.contains("entry_count=false"),
            "entry-count branch did not identify the exact drift: {entry_count_error}"
        );
    }
}
