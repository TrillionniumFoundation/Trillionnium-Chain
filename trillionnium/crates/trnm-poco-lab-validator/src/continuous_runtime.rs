//! Bounded continuous authority owner for the PoCO-BFT G3 laboratory lane.
//!
//! The normal-build entry joins manifest-bound [`LoadedValidatorConfig`] to a
//! Node-owned authenticated native h1->h2->h3 takeover runtime. Every accepted
//! ordinary proposal therefore has an exact headerful application parent and
//! traverses real Core obligation, native execution/P, Safety C, K,
//! independent whole-node checkpoint, signer journal, `SignatureReady`, QC,
//! and finalization/application-apply paths. No simulator or accept-all
//! signature verifier is used. A test-only plain-genesis constructor remains
//! for bounded ingress/proposal projection checks; its headerless legacy
//! parent is deliberately not application-seal authority.
//!
//! The deterministic multi-authority driver at the bottom of the module is a
//! single-process integration harness.  It does **not** exchange messages over
//! TCP, drive the pacemaker, inject faults, or establish G3 LAN/WAN evidence.
//! Those claims remain false until the persistent authenticated peer mesh is
//! bound to these phase transitions in real validator processes.

use std::collections::BTreeMap;

#[cfg(test)]
use std::{
    fs,
    os::unix::fs::{DirBuilderExt, PermissionsExt},
    path::{Path, PathBuf},
};

use anyhow::{anyhow, bail, ensure, Context, Result};
use ed25519_dalek::{Signer, SigningKey};
use sha2::{Digest, Sha256};
use trnm_consensus_core::leader_for;
#[cfg(test)]
use trnm_consensus_core::{CoreConfig, SafetyStateRecordLimitsV0};
use trnm_consensus_crypto::StrictEd25519Verifier;
use trnm_consensus_signer_journal::{
    ExternalMonotonicWatermarkV0, ProposalSignatureProducerV0, ProposalSignatureRequestV0,
    SignatureProducerV0,
};
#[cfg(test)]
use trnm_consensus_types::GenesisQcV0;
use trnm_consensus_types::{
    ApplicationPayloadV0, Block, BlockHeader, BlockId, BlockKind, CertificateId,
    ConsensusParametersV0, EvidenceRoot, Height, PayloadDigest, ProposalWitnessV0, QcRef,
    QcReferenceV0, QuorumCertificate, ReceiptsRoot, SignatureBytes, SignatureVerifier,
    SignedProposalV0, StateRoot, TimeoutCertificateV0, TimeoutVote, ValidatorId, ValidatorSet,
    View, Vote,
};
#[cfg(test)]
use trnm_native_execution_v0::{DurableNativeApplicationV0, NativeApplicationConfigV0};
use trnm_poco_node::{
    PocoNodeLabAuthorityPhaseV0, PocoNodeLabCertificateAdvanceV0,
    PocoNodeLabOrdinaryProposalRuntimeV0, PocoNodeLabPhaseFactsV0, PocoNodeLabSignedTimeoutOwnerV0,
    PocoNodeLabSignedVoteOwnerV0, PocoNodeLabTerminalCutV0, PocoNodeLabTerminalOwnerV0,
};
#[cfg(test)]
use trnm_poco_node::{
    PocoNodeLabFreshOrdinaryGenesisConfigV0, PocoNodeLabProposalJournalConfigV0,
    SqliteExternalNodeCheckpointStoreV0,
};

use crate::{
    collector::{
        decode_authenticated_consensus_frame_v0, required_pending_coordinate_capacity_v0,
        AdmittedConsensusMessageV0, CollectorAdmissionV0, ConsensusCertificateCollectorV0,
        ConsensusIngressErrorV0,
    },
    config::LoadedValidatorConfig,
    crypto::{
        LabEd25519ProposalSignatureProducerV0, LabEd25519SignatureProducer, LabFileWatermark,
    },
    fleet_barrier::FleetStartCertificateV1,
    frame::AuthenticatedFrame,
    loop_driver::{
        BoundedConsensusIngressLoopV0, ConsensusRelayIngressErrorV0, RoutedConsensusActionV0,
        RoutedConsensusRelayV0,
    },
    relay::{
        required_relay_message_capacity_v0, ConsensusRelayAdmissionWindowV0,
        ConsensusRelayEnvelopeV0, RelayAdmissionV0,
    },
    restart_cut::{
        LocalRestartParkV1, RestartCutParkStatementV1, RestartParkRoleV1, SignedLocalRestartParkV1,
        SignedRestartCutV1,
    },
    wire::UnboundProposalV0,
    workload_corpus::WorkloadBlockV1,
};

#[cfg(test)]
const MAXIMUM_SAFETY_RECORD_BYTES_V0: usize = 64 * 1024 * 1024;
#[cfg(test)]
const MAXIMUM_SAFETY_BLOB_BYTES_V0: usize = 16 * 1024 * 1024;
#[cfg(test)]
const MAXIMUM_SAFETY_DATABASE_BYTES_V0: usize = 256 * 1024 * 1024;
const MAXIMUM_SIGNER_INTENTS_V0: u64 = 4_096;
#[cfg(test)]
const MAXIMUM_SIGNER_INTENT_BYTES_V0: usize = 4_096;
#[cfg(test)]
const MAXIMUM_SIGNER_DATABASE_BYTES_V0: usize = 64 * 1024 * 1024;
const MAXIMUM_COLLECTOR_COORDINATES_V0: usize = 64;

/// Number of consecutive views retained by the process-local consensus
/// collector and relay replay window. The current view and its five immediate
/// predecessors fit in this tail; older authenticated statements are stale.
pub const CONTINUOUS_RUNTIME_RETAINED_VIEW_TAIL_V0: usize = 6;

/// Explicit owner-thread stack budget for native takeover commissioning and
/// the continuous authority loop. The owner must be constructed inside this
/// bounded thread; moving an already-constructed owner from a smaller caller
/// stack does not satisfy the runtime contract.
pub const CONTINUOUS_RUNTIME_OWNER_STACK_BYTES_V0: usize = 32 * 1024 * 1024;

type LabRuntimeV0 = PocoNodeLabOrdinaryProposalRuntimeV0<LabFileWatermark>;
type LabSignedVoteOwnerV0 = PocoNodeLabSignedVoteOwnerV0<LabFileWatermark>;
type LabSignedTimeoutOwnerV0 = PocoNodeLabSignedTimeoutOwnerV0<LabFileWatermark>;

/// Object-safe carrier used by the non-generic continuous authority. The
/// signer-journal trait intentionally has no blanket `Box<T>` implementation,
/// so this private wrapper keeps the public authority surface small while
/// preserving an injected producer's exact error semantics.
struct ContinuousSignatureProducerV0(Box<dyn SignatureProducerV0 + Send>);

impl SignatureProducerV0 for ContinuousSignatureProducerV0 {
    fn sign(
        &mut self,
        request: trnm_consensus_signer_journal::SignatureRequestV0<'_>,
    ) -> std::result::Result<SignatureBytes, trnm_consensus_signer_journal::SignatureProducerErrorV0>
    {
        self.0.sign(request)
    }
}

/// Crate-local inert copy of the Node's freshly owner-authenticated signer
/// inventory. Its fields are private and its only normal constructor consumes
/// the Node getter; no fleet/control caller can supply accounting scalars.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ContinuousAuthenticatedSignerInventoryV1 {
    exact_watermark: trnm_consensus_signer_journal::SignerWatermarkV0,
    durable_vote_intent_count: u64,
    durable_timeout_intent_count: u64,
    signed_vote_intent_count: u64,
    signed_timeout_intent_count: u64,
    inventory_digest: [u8; 32],
    checkpoint_canonical_sha256: [u8; 32],
}

impl ContinuousAuthenticatedSignerInventoryV1 {
    pub(crate) const fn exact_watermark_v1(
        self,
    ) -> trnm_consensus_signer_journal::SignerWatermarkV0 {
        self.exact_watermark
    }

    pub(crate) const fn durable_vote_intent_count_v1(self) -> u64 {
        self.durable_vote_intent_count
    }

    pub(crate) const fn durable_timeout_intent_count_v1(self) -> u64 {
        self.durable_timeout_intent_count
    }

    pub(crate) const fn signed_vote_intent_count_v1(self) -> u64 {
        self.signed_vote_intent_count
    }

    pub(crate) const fn signed_timeout_intent_count_v1(self) -> u64 {
        self.signed_timeout_intent_count
    }

    pub(crate) const fn inventory_digest_v1(self) -> [u8; 32] {
        self.inventory_digest
    }

    pub(crate) const fn checkpoint_canonical_sha256_v1(self) -> [u8; 32] {
        self.checkpoint_canonical_sha256
    }
}

fn fresh_node_ready_signer_inventory_v1(
    runtime: &mut LabRuntimeV0,
) -> Result<ContinuousAuthenticatedSignerInventoryV1> {
    let inventory = runtime
        .fresh_clean_signer_inventory_v1()
        .map_err(|error| anyhow!("audit Node Ready signer inventory: {error}"))?;
    Ok(ContinuousAuthenticatedSignerInventoryV1 {
        exact_watermark: inventory.exact_watermark_v1(),
        durable_vote_intent_count: inventory.durable_vote_intent_count_v1(),
        durable_timeout_intent_count: inventory.durable_timeout_intent_count_v1(),
        signed_vote_intent_count: inventory.signed_vote_intent_count_v1(),
        signed_timeout_intent_count: inventory.signed_timeout_intent_count_v1(),
        inventory_digest: inventory.inventory_digest_v1(),
        checkpoint_canonical_sha256: inventory.checkpoint_canonical_sha256_v1(),
    })
}

/// The signer-journal capacity of this bounded first continuous slice.
///
/// It is deliberately below the complete 100k-block campaign requirement and
/// therefore cannot be used as evidence that the long-run G3 profile closes.
pub const CONTINUOUS_RUNTIME_MAXIMUM_SIGNER_INTENTS_V0: u64 = MAXIMUM_SIGNER_INTENTS_V0;

/// Explicit lifetime bounds for one commissioned signer journal.
///
/// `requested_max_blocks` alone is not a signer bound: a validator may vote in
/// more than one view at one height, and timeout-only views also consume one
/// durable intent each. The campaign therefore installs and enforces one hard
/// maximum view-advance budget. This budget, rather than any claim about
/// physical fleet launch skew, bounds both extra Votes and TimeoutVotes.
/// Commissioning fails before opening any authority store unless the resulting
/// `B + 2 * theta` ceiling fits the immutable journal profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ContinuousSignerLifetimeBoundsV0 {
    requested_max_blocks: u64,
    maximum_timeout_view_advances: u64,
    maximum_local_vote_intents: u64,
    maximum_local_timeout_intents: u64,
    maximum_total_intents: u64,
}

impl ContinuousSignerLifetimeBoundsV0 {
    pub(crate) fn from_campaign_v0(
        requested_max_blocks: u64,
        requested_duration_seconds: u64,
        terminal_drain_seconds: u64,
        timeout_view_budget_allowance_seconds: u64,
        pacemaker_base_timeout_seconds: u64,
    ) -> Result<Self> {
        ensure!(
            requested_max_blocks > 0,
            "continuous runtime max_blocks must be positive"
        );
        ensure!(
            requested_duration_seconds > 0 && pacemaker_base_timeout_seconds > 0,
            "continuous runtime duration and pacemaker base timeout must be positive"
        );
        let timeout_view_budget_horizon = requested_duration_seconds
            .checked_add(terminal_drain_seconds)
            .and_then(|value| value.checked_add(timeout_view_budget_allowance_seconds))
            .context("continuous timeout-view budget horizon overflows")?;
        let maximum_timeout_view_advances =
            ceil_div_u64_v0(timeout_view_budget_horizon, pacemaker_base_timeout_seconds)?;
        let maximum_local_timeout_intents = maximum_timeout_view_advances;
        let maximum_local_vote_intents = requested_max_blocks
            .checked_add(maximum_timeout_view_advances)
            .context("continuous Vote-intent lifetime bound overflows")?;
        let maximum_total_intents = maximum_local_vote_intents
            .checked_add(maximum_local_timeout_intents)
            .context("continuous signer lifetime intent bound overflows")?;
        ensure!(
            maximum_total_intents <= MAXIMUM_SIGNER_INTENTS_V0,
            "continuous signer lifetime requires {maximum_total_intents} intents \
             ({maximum_local_vote_intents} Vote + {maximum_local_timeout_intents} TimeoutVote), \
             exceeding the configured append-only journal capacity {MAXIMUM_SIGNER_INTENTS_V0}"
        );
        Ok(Self {
            requested_max_blocks,
            maximum_timeout_view_advances,
            maximum_local_vote_intents,
            maximum_local_timeout_intents,
            maximum_total_intents,
        })
    }

    #[cfg(test)]
    pub(crate) fn from_exact_test_bounds_v0(
        requested_max_blocks: u64,
        maximum_timeout_view_advances: u64,
        maximum_local_vote_intents: u64,
        maximum_local_timeout_intents: u64,
    ) -> Result<Self> {
        ensure!(
            requested_max_blocks > 0,
            "continuous runtime max_blocks must be positive"
        );
        ensure!(
            maximum_local_vote_intents
                == requested_max_blocks
                    .checked_add(maximum_timeout_view_advances)
                    .context("continuous test Vote-intent bound overflows")?,
            "continuous test Vote-intent ceiling does not equal blocks plus timeout views"
        );
        ensure!(
            maximum_local_timeout_intents == maximum_timeout_view_advances,
            "continuous test TimeoutVote ceiling does not equal the hard timeout-view budget"
        );
        let maximum_total_intents = maximum_local_vote_intents
            .checked_add(maximum_local_timeout_intents)
            .context("continuous signer lifetime intent bound overflows")?;
        ensure!(
            maximum_total_intents <= MAXIMUM_SIGNER_INTENTS_V0,
            "continuous signer lifetime requires {maximum_total_intents} intents, exceeding the configured append-only journal capacity {MAXIMUM_SIGNER_INTENTS_V0}"
        );
        Ok(Self {
            requested_max_blocks,
            maximum_timeout_view_advances,
            maximum_local_vote_intents,
            maximum_local_timeout_intents,
            maximum_total_intents,
        })
    }

    pub const fn requested_max_blocks_v0(self) -> u64 {
        self.requested_max_blocks
    }

    pub const fn maximum_timeout_view_advances_v0(self) -> u64 {
        self.maximum_timeout_view_advances
    }

    pub const fn maximum_local_vote_intents_v0(self) -> u64 {
        self.maximum_local_vote_intents
    }

    pub const fn maximum_local_timeout_intents_v0(self) -> u64 {
        self.maximum_local_timeout_intents
    }

    pub const fn maximum_total_intents_v0(self) -> u64 {
        self.maximum_total_intents
    }
}

fn ceil_div_u64_v0(numerator: u64, denominator: u64) -> Result<u64> {
    ensure!(denominator > 0, "continuous ceiling divisor is zero");
    numerator
        .checked_add(denominator - 1)
        .map(|value| value / denominator)
        .context("continuous ceiling division overflows")
}

/// Secret-free capacity result which can be copied into runtime preflight and
/// evidence. It derives the same bounded sliding-window sizes used by the real
/// ingress and relay constructors and carries the explicit signer lifetime.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ContinuousRuntimeCapacityPreflightV0 {
    validator_count: usize,
    retained_views: usize,
    ingress_coordinate_capacity: usize,
    relay_message_capacity: usize,
    signer_lifetime: ContinuousSignerLifetimeBoundsV0,
    signer_journal_capacity: u64,
    owner_thread_stack_bytes: usize,
}

impl ContinuousRuntimeCapacityPreflightV0 {
    pub fn new(
        validator_count: usize,
        signer_lifetime: ContinuousSignerLifetimeBoundsV0,
    ) -> Result<Self> {
        let ingress_coordinate_capacity = required_pending_coordinate_capacity_v0(
            validator_count,
            CONTINUOUS_RUNTIME_RETAINED_VIEW_TAIL_V0,
        )
        .map_err(|error| anyhow!("derive retained-view ingress capacity: {error}"))?;
        let relay_message_capacity = required_relay_message_capacity_v0(
            validator_count,
            CONTINUOUS_RUNTIME_RETAINED_VIEW_TAIL_V0,
        )
        .map_err(|error| anyhow!("derive retained-view relay capacity: {error}"))?;
        Ok(Self {
            validator_count,
            retained_views: CONTINUOUS_RUNTIME_RETAINED_VIEW_TAIL_V0,
            ingress_coordinate_capacity,
            relay_message_capacity,
            signer_lifetime,
            signer_journal_capacity: MAXIMUM_SIGNER_INTENTS_V0,
            owner_thread_stack_bytes: CONTINUOUS_RUNTIME_OWNER_STACK_BYTES_V0,
        })
    }

    pub const fn validator_count_v0(self) -> usize {
        self.validator_count
    }

    pub const fn retained_views_v0(self) -> usize {
        self.retained_views
    }

    pub const fn ingress_coordinate_capacity_v0(self) -> usize {
        self.ingress_coordinate_capacity
    }

    pub const fn relay_message_capacity_v0(self) -> usize {
        self.relay_message_capacity
    }

    pub const fn signer_lifetime_v0(self) -> ContinuousSignerLifetimeBoundsV0 {
        self.signer_lifetime
    }

    pub const fn signer_journal_capacity_v0(self) -> u64 {
        self.signer_journal_capacity
    }

    pub const fn owner_thread_stack_bytes_v0(self) -> usize {
        self.owner_thread_stack_bytes
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ContinuousSignerLifetimeStateV0 {
    bounds: ContinuousSignerLifetimeBoundsV0,
    signed_vote_intents: u64,
    signed_timeout_intents: u64,
    authenticated_exact_watermark: trnm_consensus_signer_journal::SignerWatermarkV0,
    authenticated_inventory_digest: [u8; 32],
}

/// Typed, owner-lifetime history of strictly authenticated consensus
/// violations observed by this continuous authority. Exact replays and stale
/// messages are not violations; only conflicting signed statements or QC
/// carriers increment these counters.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ContinuousProtocolViolationCountersV0 {
    double_vote_count: u64,
    double_timeout_count: u64,
    conflicting_certificate_count: u64,
}

impl ContinuousProtocolViolationCountersV0 {
    pub const fn double_vote_count_v0(self) -> u64 {
        self.double_vote_count
    }

    pub const fn double_timeout_count_v0(self) -> u64 {
        self.double_timeout_count
    }

    pub const fn conflicting_certificate_count_v0(self) -> u64 {
        self.conflicting_certificate_count
    }

    fn record_ingress_error_v0(&mut self, error: &ConsensusIngressErrorV0) -> Result<()> {
        let counter = match error {
            ConsensusIngressErrorV0::VoteEquivocation => &mut self.double_vote_count,
            ConsensusIngressErrorV0::TimeoutEquivocation => &mut self.double_timeout_count,
            ConsensusIngressErrorV0::ConflictingQcReference(_) => {
                &mut self.conflicting_certificate_count
            }
            _ => return Ok(()),
        };
        *counter = counter
            .checked_add(1)
            .context("continuous protocol-violation accounting overflows")?;
        Ok(())
    }

    fn record_anyhow_v0(&mut self, error: &anyhow::Error) -> Result<()> {
        if let Some(ingress) = error
            .chain()
            .find_map(|cause| cause.downcast_ref::<ConsensusIngressErrorV0>())
        {
            return self.record_ingress_error_v0(ingress);
        }
        if let Some(ConsensusRelayIngressErrorV0::Consensus(ingress)) = error
            .chain()
            .find_map(|cause| cause.downcast_ref::<ConsensusRelayIngressErrorV0>())
        {
            return self.record_ingress_error_v0(ingress);
        }
        Ok(())
    }
}

impl ContinuousSignerLifetimeStateV0 {
    fn from_authenticated_inventory_v1(
        bounds: ContinuousSignerLifetimeBoundsV0,
        inventory: ContinuousAuthenticatedSignerInventoryV1,
    ) -> Result<Self> {
        let state = Self {
            bounds,
            signed_vote_intents: inventory.signed_vote_intent_count_v1(),
            signed_timeout_intents: inventory.signed_timeout_intent_count_v1(),
            authenticated_exact_watermark: inventory.exact_watermark_v1(),
            authenticated_inventory_digest: inventory.inventory_digest_v1(),
        };
        state.require_vote_accounting_v0()?;
        state.require_timeout_accounting_v0()?;
        state.require_authenticated_inventory_v1(inventory)?;
        Ok(state)
    }

    fn refresh_authenticated_inventory_v1(
        &mut self,
        inventory: ContinuousAuthenticatedSignerInventoryV1,
    ) -> Result<()> {
        self.require_authenticated_inventory_v1(inventory)?;
        let watermark = inventory.exact_watermark_v1();
        ensure!(
            watermark.scope() == self.authenticated_exact_watermark.scope()
                && watermark.journal_id() == self.authenticated_exact_watermark.journal_id(),
            "fresh signer inventory changed its authenticated watermark identity"
        );
        self.authenticated_exact_watermark = watermark;
        self.authenticated_inventory_digest = inventory.inventory_digest_v1();
        Ok(())
    }

    fn require_authenticated_inventory_v1(
        self,
        inventory: ContinuousAuthenticatedSignerInventoryV1,
    ) -> Result<()> {
        let durable_vote = inventory.durable_vote_intent_count_v1();
        let durable_timeout = inventory.durable_timeout_intent_count_v1();
        let signed_vote = inventory.signed_vote_intent_count_v1();
        let signed_timeout = inventory.signed_timeout_intent_count_v1();
        let signed_total = signed_vote
            .checked_add(signed_timeout)
            .context("authenticated signer intent accounting overflows")?;
        let expected_sequence = signed_total
            .checked_mul(2)
            .context("authenticated signer event accounting overflows")?;
        let watermark = inventory.exact_watermark_v1();
        ensure!(
            durable_vote == signed_vote
                && durable_timeout == signed_timeout
                && signed_vote == self.signed_vote_intents
                && signed_timeout == self.signed_timeout_intents
                && watermark.scope() != [0; 32]
                && watermark.journal_id() != [0; 32]
                && watermark.chain_checksum() != [0; 32]
                && watermark.sequence() == expected_sequence
                && inventory.inventory_digest_v1() != [0; 32]
                && inventory.checkpoint_canonical_sha256_v1() != [0; 32],
            "continuous signer counters, watermark, inventory digest, or checkpoint content address differ from the fresh owner-authenticated inventory"
        );
        Ok(())
    }

    fn require_vote_available_v0(self) -> Result<()> {
        ensure!(
            self.signed_vote_intents < self.bounds.maximum_local_vote_intents,
            "continuous signer reached its declared Vote-intent lifetime ceiling"
        );
        Ok(())
    }

    fn require_timeout_available_v0(self) -> Result<()> {
        ensure!(
            self.signed_timeout_intents < self.bounds.maximum_local_timeout_intents,
            "continuous signer reached its declared TimeoutVote-intent lifetime ceiling"
        );
        Ok(())
    }

    fn record_vote_v0(&mut self) -> Result<()> {
        self.signed_vote_intents = self
            .signed_vote_intents
            .checked_add(1)
            .context("continuous signed-Vote accounting overflows")?;
        self.require_vote_accounting_v0()
    }

    fn record_timeout_v0(&mut self) -> Result<()> {
        self.signed_timeout_intents = self
            .signed_timeout_intents
            .checked_add(1)
            .context("continuous signed-TimeoutVote accounting overflows")?;
        self.require_timeout_accounting_v0()
    }

    fn require_vote_accounting_v0(self) -> Result<()> {
        ensure!(
            self.signed_vote_intents <= self.bounds.maximum_local_vote_intents,
            "continuous signed-Vote accounting crossed its commissioned ceiling"
        );
        self.require_total_accounting_v0()
    }

    fn require_timeout_accounting_v0(self) -> Result<()> {
        ensure!(
            self.signed_timeout_intents <= self.bounds.maximum_local_timeout_intents,
            "continuous signed-TimeoutVote accounting crossed its commissioned ceiling"
        );
        self.require_total_accounting_v0()
    }

    fn require_total_accounting_v0(self) -> Result<()> {
        let total = self
            .signed_vote_intents
            .checked_add(self.signed_timeout_intents)
            .context("continuous signed-intent accounting overflows")?;
        ensure!(
            total <= self.bounds.maximum_total_intents && total <= MAXIMUM_SIGNER_INTENTS_V0,
            "continuous signed-intent accounting crossed its commissioned journal lifetime"
        );
        Ok(())
    }
}

/// Process-local consensus admission state. It owns no socket or transport
/// session; authenticated frames are handed in by the future mesh owner.
struct ContinuousConsensusWindowsV0 {
    validator_set: ValidatorSet,
    consensus_parameters: ConsensusParametersV0,
    ingress: BoundedConsensusIngressLoopV0,
    relay: ConsensusRelayAdmissionWindowV0,
    direct_proposals: BTreeMap<DirectProposalIdentityV0, ()>,
    preflight: ContinuousRuntimeCapacityPreflightV0,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct DirectProposalIdentityV0 {
    view: View,
    block_id: BlockId,
    canonical_payload_sha256: [u8; 32],
}

impl ContinuousConsensusWindowsV0 {
    fn new(
        validator_set: ValidatorSet,
        consensus_parameters: ConsensusParametersV0,
        preflight: ContinuousRuntimeCapacityPreflightV0,
        authoritative_high_qc: QcReferenceV0,
    ) -> Result<Self> {
        ensure!(
            validator_set.validators().len() == preflight.validator_count,
            "capacity preflight validator count differs from the authority set"
        );
        let mut ingress = BoundedConsensusIngressLoopV0::new_for_retained_views(
            validator_set.clone(),
            consensus_parameters,
            preflight.retained_views,
        )
        .map_err(|error| anyhow!("construct retained-view consensus ingress: {error}"))?;
        ensure!(
            ingress
                .seed_verified_qc_reference_v0(authoritative_high_qc)
                .map_err(|error| anyhow!("seed authoritative high-QC carrier: {error}"))?
                == CollectorAdmissionV0::Inserted,
            "fresh consensus ingress unexpectedly replayed its authoritative high QC"
        );
        let relay = ConsensusRelayAdmissionWindowV0::new(preflight.relay_message_capacity)
            .map_err(|error| anyhow!("construct retained-view relay admission: {error}"))?;
        Ok(Self {
            validator_set,
            consensus_parameters,
            ingress,
            relay,
            direct_proposals: BTreeMap::new(),
            preflight,
        })
    }

    fn minimum_retained_view_v0(&self) -> Result<View> {
        let ingress = self.ingress.collector().minimum_retained_view();
        let relay = self.relay.minimum_retained_view();
        ensure!(
            ingress == relay,
            "consensus ingress and relay retained-view watermarks diverged"
        );
        Ok(ingress)
    }

    fn admit_authenticated_frame_v0(
        &mut self,
        frame: &AuthenticatedFrame,
    ) -> Result<Option<RoutedConsensusActionV0>> {
        let decoded = decode_authenticated_consensus_frame_v0(
            frame,
            &self.validator_set,
            &self.consensus_parameters,
        )
        .context("preflight authenticated consensus frame")?;
        ensure!(
            admitted_consensus_message_view_v0(&decoded) >= self.minimum_retained_view_v0()?,
            "direct consensus statement view was pruned"
        );
        let action = self
            .ingress
            .admit_authenticated_frame(frame)
            .context("admit authenticated consensus frame")?;
        let RoutedConsensusActionV0::Proposal(proposal) = &action else {
            return Ok(Some(action));
        };
        let view = proposal.block().header().view();
        ensure!(
            view >= self.minimum_retained_view_v0()?,
            "direct Proposal view was pruned"
        );
        let identity = DirectProposalIdentityV0 {
            view,
            block_id: proposal.block().id(),
            canonical_payload_sha256: Sha256::digest(&frame.payload).into(),
        };
        if self.direct_proposals.contains_key(&identity) {
            return Ok(None);
        }
        ensure!(
            self.direct_proposals.len() < self.preflight.relay_message_capacity,
            "bounded direct-Proposal identity capacity exhausted"
        );
        self.direct_proposals.insert(identity, ());
        Ok(Some(action))
    }

    fn admit_consensus_relay_frame_v0(
        &mut self,
        frame: &AuthenticatedFrame,
    ) -> Result<RoutedConsensusRelayV0> {
        self.ingress
            .admit_consensus_relay_frame(frame, &mut self.relay)
            .context("admit authenticated consensus relay")
    }

    /// Reserves the stable relay identity of one locally originated statement
    /// without routing that statement through the collector a second time.
    ///
    /// Local Vote/TimeoutVote statements enter the collector through their
    /// typed signer-journal paths, while local proposals and certificates have
    /// already changed the Node authority before publication. Re-decoding the
    /// signed envelope and its embedded consensus bytes here preserves the
    /// same origin/signature/view checks as remote relay ingress. Reserving the
    /// identity before the first socket effect makes every returning copy an
    /// inert exact replay.
    fn reserve_originated_consensus_relay_v0(
        &mut self,
        envelope: &ConsensusRelayEnvelopeV0,
    ) -> Result<[u8; 32]> {
        let verified = ConsensusRelayEnvelopeV0::decode(&envelope.encode(), &self.validator_set)
            .map_err(|error| anyhow!("verify originated relay envelope: {error}"))?;
        ensure!(
            verified == *envelope,
            "originated relay envelope changed during canonical verification"
        );
        let embedded = verified.embedded_statement_frame();
        let decoded = decode_authenticated_consensus_frame_v0(
            &embedded,
            &self.validator_set,
            &self.consensus_parameters,
        )
        .context("verify originated relay consensus statement")?;
        let statement_view = admitted_consensus_message_view_v0(&decoded);
        ensure!(
            statement_view >= self.minimum_retained_view_v0()?,
            "originated relay statement view was pruned"
        );
        ensure!(
            self.relay
                .admit_verified_at_view(&verified, statement_view)
                .map_err(|error| anyhow!("reserve originated relay identity: {error}"))?
                == RelayAdmissionV0::New,
            "originated relay identity was already admitted"
        );
        Ok(verified.message_id())
    }

    fn admit_local_vote_v0(&mut self, vote: Vote) -> Result<Option<QuorumCertificate>> {
        let expected = vote.clone();
        let action = self
            .ingress
            .admit_local_vote_v0(vote)
            .context("admit locally signed Vote")?;
        let RoutedConsensusActionV0::Vote {
            vote: routed,
            formed_qc,
        } = action
        else {
            bail!("local Vote reached a non-Vote collector action")
        };
        ensure!(
            *routed == expected,
            "local Vote collector changed the signed statement"
        );
        Ok(formed_qc.map(|certificate| *certificate))
    }

    fn admit_local_timeout_vote_v0(
        &mut self,
        vote: TimeoutVote,
    ) -> Result<Option<TimeoutCertificateV0>> {
        let expected = vote.clone();
        let action = self
            .ingress
            .admit_local_timeout_vote_v0(vote)
            .context("admit locally signed TimeoutVote")?;
        let RoutedConsensusActionV0::TimeoutVote {
            vote: routed,
            formed_tc,
        } = action
        else {
            bail!("local TimeoutVote reached a non-TimeoutVote collector action")
        };
        ensure!(
            *routed == expected,
            "local TimeoutVote collector changed the signed statement"
        );
        Ok(formed_tc.map(|certificate| *certificate))
    }

    fn synchronize_authoritative_progress_v0(
        &mut self,
        current_view: View,
        high_qc: &QcReferenceV0,
        pending_timeout_certificate: Option<&TimeoutCertificateV0>,
    ) -> Result<View> {
        let retained_predecessors = u64::try_from(
            self.preflight
                .retained_views
                .checked_sub(1)
                .expect("positive retained-view preflight"),
        )
        .context("retained-view tail does not fit u64")?;
        let minimum_retained_view =
            View::new(current_view.get().saturating_sub(retained_predecessors));
        let existing = self.minimum_retained_view_v0()?;
        ensure!(
            minimum_retained_view >= existing,
            "authoritative Core progress regressed the retained-view watermark"
        );

        // The Node supplies the complete verified carrier, never a bare
        // QcRef/ID. Seeding it through the collector's strict reference path
        // lets the first timeout quorum after takeover form a TC without a
        // fabricated self-authenticated QC frame.
        self.ingress
            .seed_verified_qc_reference_v0(high_qc.clone())
            .map_err(|error| anyhow!("seed authoritative high-QC progress: {error}"))?;

        let mut retain_qc_references = vec![high_qc.id()];
        if let Some(certificate) = pending_timeout_certificate {
            ensure!(
                certificate.timed_out_view() < current_view
                    && certificate
                        .referenced_qcs()
                        .iter()
                        .any(|reference| reference.id() == high_qc.id()),
                "pending timeout certificate does not retain the authoritative high QC"
            );
            retain_qc_references.extend(certificate.referenced_qcs().iter().map(QcReferenceV0::id));
        }

        // Both calls have the same monotonic precondition. If either future
        // implementation adds another failure after mutation, the enclosing
        // authority remains consumed and therefore fails closed.
        self.ingress
            .prune_before_view(minimum_retained_view, retain_qc_references)
            .map_err(|error| anyhow!("prune authoritative consensus ingress: {error}"))?;
        self.relay
            .prune_before_view(minimum_retained_view)
            .map_err(|error| anyhow!("prune authoritative relay admission: {error}"))?;
        self.direct_proposals
            .retain(|identity, _| identity.view >= minimum_retained_view);
        ensure!(
            self.minimum_retained_view_v0()? == minimum_retained_view,
            "consensus sliding windows did not install one authoritative watermark"
        );
        Ok(minimum_retained_view)
    }
}

fn admitted_consensus_message_view_v0(message: &AdmittedConsensusMessageV0) -> View {
    match message {
        AdmittedConsensusMessageV0::Proposal(proposal) => proposal.block().header().view(),
        AdmittedConsensusMessageV0::Vote(vote) => vote.view(),
        AdmittedConsensusMessageV0::TimeoutVote(vote) => vote.view(),
        AdmittedConsensusMessageV0::QuorumCertificate(certificate) => certificate.view(),
        AdmittedConsensusMessageV0::TimeoutCertificate(certificate) => certificate.timed_out_view(),
    }
}

#[derive(Debug)]
enum ContinuousAuthorityPhaseV0 {
    Ready(Box<LabRuntimeV0>),
    VoteSigned(Box<LabSignedVoteOwnerV0>),
    TimeoutSigned(Box<LabSignedTimeoutOwnerV0>),
}

/// One non-cloneable validator authority with every safety-sensitive owner
/// retained behind the Node's linear phase carriers.
pub struct ContinuousValidatorAuthorityV0 {
    local_validator: ValidatorId,
    validator_set: ValidatorSet,
    consensus_parameters: ConsensusParametersV0,
    justify: QcReferenceV0,
    proposal_timeout_certificate: Option<TimeoutCertificateV0>,
    capacity_preflight: ContinuousRuntimeCapacityPreflightV0,
    signer_lifetime: ContinuousSignerLifetimeStateV0,
    protocol_violations: ContinuousProtocolViolationCountersV0,
    consensus_windows: ContinuousConsensusWindowsV0,
    /// Injected consensus signature boundary for Vote/TimeoutVote owners.
    ///
    /// The normal laboratory constructors install the fixture-only
    /// `LabEd25519SignatureProducer`; an operator-facing composition entry can
    /// instead supply a bounded remote/HSM producer.  This authority never
    /// calls a producer for arbitrary bytes: the Node signer journal has
    /// already durably issued the exact intent before this field is reached.
    producer: ContinuousSignatureProducerV0,
    phase: Option<ContinuousAuthorityPhaseV0>,
}

impl std::fmt::Debug for ContinuousValidatorAuthorityV0 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let phase = match self.phase.as_ref() {
            Some(ContinuousAuthorityPhaseV0::Ready(_)) => "ready",
            Some(ContinuousAuthorityPhaseV0::VoteSigned(_)) => "vote-signed",
            Some(ContinuousAuthorityPhaseV0::TimeoutSigned(_)) => "timeout-signed",
            None => "failed-closed",
        };
        formatter
            .debug_struct("ContinuousValidatorAuthorityV0")
            .field("local_validator", &self.local_validator)
            .field("justify", &self.justify.qc_ref())
            .field(
                "proposal_timeout_certificate",
                &self
                    .proposal_timeout_certificate
                    .as_ref()
                    .map(TimeoutCertificateV0::id),
            )
            .field("capacity_preflight", &self.capacity_preflight)
            .field("signer_lifetime", &self.signer_lifetime)
            .field(
                "minimum_retained_view",
                &self.consensus_windows.minimum_retained_view_v0(),
            )
            .field("phase", &phase)
            .finish_non_exhaustive()
    }
}

/// Non-cloneable process-local authority after restart quiescence has
/// consumed the ordinary Ready owner.
///
/// The complete continuous authority remains private so this carrier cannot
/// propose, vote, time out, advance a certificate, or rearm a pacemaker.  Its
/// only public surface is the freshly authenticated comparison projection
/// captured at the consuming transition.
#[must_use = "the restart-parked authority retains the quiesced validator authority"]
pub(crate) struct ContinuousRestartParkedAuthorityV1 {
    _authority: ContinuousValidatorAuthorityV0,
    facts: ContinuousRuntimeFactsV0,
}

impl ContinuousRestartParkedAuthorityV1 {
    pub(crate) const fn facts_v1(&self) -> ContinuousRuntimeFactsV0 {
        self.facts
    }

    /// Consumes the parked authority into its sole target dual declaration.
    /// The existing target Prepare is reused byte-for-byte as the Cut half;
    /// only the exact validated local-park digest is signed here.
    pub(crate) fn into_target_restart_cut_park_v1(
        self,
        config: &LoadedValidatorConfig,
        target_prepare: SignedRestartCutV1,
        local_park: LocalRestartParkV1,
        fleet_start_certificate: &FleetStartCertificateV1,
    ) -> Result<ContinuousRestartDeclaredParkAuthorityV1> {
        self.require_restart_park_parts_v1(
            config,
            &target_prepare,
            &local_park,
            RestartParkRoleV1::Target,
            fleet_start_certificate,
        )?;
        let park = sign_local_restart_park_v1(
            config,
            target_prepare.body(),
            local_park,
            fleet_start_certificate,
        )?;
        let statement = RestartCutParkStatementV1::new(
            target_prepare,
            park,
            fleet_start_certificate,
            config.validator_set(),
        )
        .map_err(|error| anyhow!("form target dual Cut/Park declaration: {error}"))?;
        Ok(ContinuousRestartDeclaredParkAuthorityV1 {
            _parked: self,
            statement,
        })
    }

    /// Consumes the parked authority into its sole peer dual declaration.
    /// The raw key is reachable only inside this closed typed method and is
    /// never returned as a signing oracle.
    pub(crate) fn into_peer_restart_cut_park_v1(
        self,
        config: &LoadedValidatorConfig,
        target_prepare: &SignedRestartCutV1,
        local_park: LocalRestartParkV1,
        fleet_start_certificate: &FleetStartCertificateV1,
    ) -> Result<ContinuousRestartDeclaredParkAuthorityV1> {
        self.require_restart_park_parts_v1(
            config,
            target_prepare,
            &local_park,
            RestartParkRoleV1::Peer,
            fleet_start_certificate,
        )?;
        let cut = SignedRestartCutV1::new(
            config.local_validator(),
            target_prepare.body().clone(),
            config.validator_set(),
            config.consensus_signing_key(),
        )
        .map_err(|error| anyhow!("sign peer RestartCut declaration: {error}"))?;
        let park = sign_local_restart_park_v1(
            config,
            target_prepare.body(),
            local_park,
            fleet_start_certificate,
        )?;
        let statement = RestartCutParkStatementV1::new(
            cut,
            park,
            fleet_start_certificate,
            config.validator_set(),
        )
        .map_err(|error| anyhow!("form peer dual Cut/Park declaration: {error}"))?;
        Ok(ContinuousRestartDeclaredParkAuthorityV1 {
            _parked: self,
            statement,
        })
    }

    fn require_restart_park_parts_v1(
        &self,
        config: &LoadedValidatorConfig,
        target_prepare: &SignedRestartCutV1,
        local_park: &LocalRestartParkV1,
        expected_role: RestartParkRoleV1,
        fleet_start_certificate: &FleetStartCertificateV1,
    ) -> Result<()> {
        let facts = self.facts;
        let state = local_park.local_state();
        ensure!(
            config.validator_set() == &self._authority.validator_set
                && config.local_validator() == self._authority.local_validator
                && target_prepare.body().process_instance() == 1
                && target_prepare.body().target_validator() == target_prepare.origin()
                && local_park.role() == expected_role
                && local_park.local_validator() == config.local_validator()
                && local_park.local_config_sha256() == config.config_sha256()
                && facts.phase_v0() == PocoNodeLabAuthorityPhaseV0::Ready
                && facts.pending_timeout_certificate_id_v0().is_none()
                && state.current_view == facts.current_view_v0()
                && state.direct_high_qc == facts.high_qc_v0()
                && state.proposal_parent_height.get() == facts.proposal_parent_height_v0()
                && state.proposal_parent_block_id == facts.proposal_parent_block_id_v0()
                && state.finalized_height.get() == facts.finalized_height_v0()
                && state.finalized_block_id == facts.finalized_block_id_v0()
                && state.finalized_chain_root == facts.finalized_chain_root_v0()
                && state.application_height.get() == facts.application_applied_height_v0()
                && state.application_block_id == facts.application_applied_block_id_v0()
                && state.application_state_root == facts.application_state_root_v0()
                && state.safety_revision == facts.safety_revision_v0()
                && state.safety_state_record_checksum == facts.safety_record_checksum_v0()
                && state.safety_record_chain_checksum == facts.safety_chain_checksum_v0()
                && state.signer_watermark == facts.signer_exact_watermark_v1()
                && state.signer_signed_vote_intent_count == facts.signed_vote_intents_v0()
                && state.signer_signed_timeout_intent_count == facts.signed_timeout_intents_v0()
                && state.signer_inventory_digest
                    == facts.authenticated_signer_inventory_digest_v1()
                && state.pending_sign.is_none()
                && state.external_checkpoint_generation == facts.checkpoint_generation_v0()
                && state.external_checkpoint_checksum == facts.checkpoint_canonical_sha256_v1(),
            "restart local-park facts differ from the consumed continuous authority"
        );
        target_prepare
            .clone()
            .verify_target_prepare_owned(fleet_start_certificate, config.validator_set())
            .map(|_| ())
            .map_err(|error| anyhow!("verify target Prepare at parked boundary: {error}"))?;
        local_park
            .validate_for_restart_body(
                target_prepare.body(),
                fleet_start_certificate,
                config.validator_set(),
            )
            .map_err(|error| anyhow!("verify local park at parked boundary: {error}"))
    }
}

/// Consumed parked authority after its one dual declaration has been issued.
/// It can be retained by a local barrier owner but has no second declaration,
/// ordinary consensus, timer, or inner-authority escape method.
#[must_use = "declared restart-park authority must remain in the local barrier owner"]
pub(crate) struct ContinuousRestartDeclaredParkAuthorityV1 {
    _parked: ContinuousRestartParkedAuthorityV1,
    statement: RestartCutParkStatementV1,
}

impl ContinuousRestartDeclaredParkAuthorityV1 {
    pub(crate) const fn facts_v1(&self) -> ContinuousRuntimeFactsV0 {
        self._parked.facts_v1()
    }

    /// Borrows the sole dual statement issued by this consumed authority.
    /// The statement cannot be separated from its authority owner by this
    /// API; the phase-bound ingress owner consumes the whole carrier.
    pub(crate) const fn statement_v1(&self) -> &RestartCutParkStatementV1 {
        &self.statement
    }
}

impl std::fmt::Debug for ContinuousRestartDeclaredParkAuthorityV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ContinuousRestartDeclaredParkAuthorityV1")
            .field("facts", &self.facts_v1())
            .field("statement_sha256", &self.statement.statement_sha256())
            .finish_non_exhaustive()
    }
}

fn sign_local_restart_park_v1(
    config: &LoadedValidatorConfig,
    restart_cut_body: &crate::restart_cut::RestartCutBodyV1,
    local_park: LocalRestartParkV1,
    fleet_start_certificate: &FleetStartCertificateV1,
) -> Result<SignedLocalRestartParkV1> {
    let digest = SignedLocalRestartParkV1::signing_digest_for_parts(
        config.local_validator(),
        restart_cut_body,
        &local_park,
        fleet_start_certificate,
        config.validator_set(),
    )
    .map_err(|error| anyhow!("construct exact local-park signing digest: {error}"))?;
    let signature = config.consensus_signing_key().sign(&digest).to_bytes();
    SignedLocalRestartParkV1::from_parts(
        config.local_validator(),
        restart_cut_body,
        local_park,
        signature,
        fleet_start_certificate,
        config.validator_set(),
    )
    .map_err(|error| anyhow!("verify exact local-park signature bytes: {error}"))
}

impl std::fmt::Debug for ContinuousRestartParkedAuthorityV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ContinuousRestartParkedAuthorityV1")
            .field("facts", &self.facts)
            .finish_non_exhaustive()
    }
}

/// Authority-free continuous-layer projection joined to the Node terminal cut.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ContinuousValidatorTerminalCutV0 {
    node: PocoNodeLabTerminalCutV0,
    local_validator: ValidatorId,
    validator_count: usize,
    retained_views: usize,
    signer_lifetime: ContinuousSignerLifetimeBoundsV0,
    signed_vote_intents: u64,
    signed_timeout_intents: u64,
    protocol_violations: ContinuousProtocolViolationCountersV0,
}

impl ContinuousValidatorTerminalCutV0 {
    pub const fn node_v0(self) -> PocoNodeLabTerminalCutV0 {
        self.node
    }

    pub const fn submitted_height_v0(self) -> u64 {
        self.node.submitted_height_v0()
    }

    pub const fn finalized_chain_root_v0(self) -> [u8; 32] {
        self.node.finalized_chain_root_v0()
    }

    pub const fn local_validator_v0(self) -> ValidatorId {
        self.local_validator
    }

    pub const fn validator_count_v0(self) -> usize {
        self.validator_count
    }

    pub const fn retained_views_v0(self) -> usize {
        self.retained_views
    }

    pub const fn signer_lifetime_v0(self) -> ContinuousSignerLifetimeBoundsV0 {
        self.signer_lifetime
    }

    pub const fn signed_vote_intents_v0(self) -> u64 {
        self.signed_vote_intents
    }

    pub const fn signed_timeout_intents_v0(self) -> u64 {
        self.signed_timeout_intents
    }

    pub const fn protocol_violations_v0(self) -> ContinuousProtocolViolationCountersV0 {
        self.protocol_violations
    }

    pub const fn double_vote_count_v0(self) -> u64 {
        self.protocol_violations.double_vote_count_v0()
    }

    pub const fn double_timeout_count_v0(self) -> u64 {
        self.protocol_violations.double_timeout_count_v0()
    }

    pub const fn conflicting_certificate_count_v0(self) -> u64 {
        self.protocol_violations.conflicting_certificate_count_v0()
    }
}

/// Non-cloneable clean-stop owner for one continuous validator.
///
/// The Node terminal owner pins every mutable authority namespace. This wrapper
/// adds only the bounded continuous-layer capacity and signer-lifetime facts;
/// it exposes no path back to a live phase or network admission window.
#[must_use = "the continuous terminal owner pins the clean validator cut"]
pub struct ContinuousValidatorTerminalOwnerV0 {
    _node: PocoNodeLabTerminalOwnerV0<LabFileWatermark>,
    facts: ContinuousValidatorTerminalCutV0,
}

impl ContinuousValidatorTerminalOwnerV0 {
    pub const fn facts_v0(&self) -> &ContinuousValidatorTerminalCutV0 {
        &self.facts
    }
}

impl std::fmt::Debug for ContinuousValidatorTerminalOwnerV0 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ContinuousValidatorTerminalOwnerV0")
            .field("facts", &self.facts)
            .finish_non_exhaustive()
    }
}

impl ContinuousValidatorAuthorityV0 {
    #[cfg(test)]
    fn initialize_from_parts_v0(
        core_config: CoreConfig,
        application_config: NativeApplicationConfigV0,
        signing_key: SigningKey,
        authority_root: &Path,
        signer_lifetime: ContinuousSignerLifetimeBoundsV0,
    ) -> Result<Self> {
        let local_validator = core_config.local_validator();
        let validator_set = core_config.validator_set().clone();
        let consensus_parameters = *core_config.consensus_parameters();
        let genesis_qc = GenesisQcV0::new(
            validator_set.genesis_hash(),
            validator_set.chain_id(),
            &validator_set,
        )
        .map_err(|error| anyhow!("construct trusted genesis QC: {error}"))?;
        let capacity_preflight = ContinuousRuntimeCapacityPreflightV0::new(
            validator_set.validators().len(),
            signer_lifetime,
        )?;
        let consensus_windows = ContinuousConsensusWindowsV0::new(
            validator_set.clone(),
            consensus_parameters,
            capacity_preflight,
            QcReferenceV0::genesis_anchor(genesis_qc.clone()),
        )?;
        let local = validator_set
            .validator(local_validator)
            .ok_or_else(|| anyhow!("local validator is absent from Core config"))?;
        ensure!(
            signing_key.verifying_key().to_bytes() == local.consensus_key().into_bytes(),
            "continuous authority signing key differs from Core local validator"
        );
        ensure!(
            application_config.initial_block_id_v0() == *core_config.genesis_block_id().as_bytes(),
            "native application height-zero block differs from Core genesis"
        );

        let paths = create_fresh_authority_tree_v0(authority_root)?;
        let expected_chain_descriptor_hash = application_config.chain_descriptor_hash_v0();
        let expected_signer_policy_commitment = application_config.signer_policy_commitment_v0();
        let expected_initial_commit_id = application_config.initial_commit_id_v0();
        let application =
            DurableNativeApplicationV0::open(&paths.application_store, application_config)
                .map_err(|error| anyhow!("open fresh native application: {error}"))?;
        let checkpoint_store =
            SqliteExternalNodeCheckpointStoreV0::initialize_new(&paths.checkpoint_store)
                .map_err(|error| anyhow!("initialize whole-node checkpoint: {error}"))?;
        let watermark = LabFileWatermark::open(&paths.external_watermark)
            .map_err(|error| anyhow!("open external signer watermark: {error:?}"))?;
        let proposal_journal = PocoNodeLabProposalJournalConfigV0::new(
            paths.proposal_store,
            authority_hash_v0(
                b"trnm.poco-g3.continuous.proposal-scope.v0",
                local_validator,
                validator_set.id().as_bytes(),
            ),
            authority_hash_v0(
                b"trnm.poco-g3.continuous.proposal-owner.v0",
                local_validator,
                expected_chain_descriptor_hash.as_slice(),
            ),
            0,
        )
        .map_err(|error| anyhow!("construct proposal-journal authority: {error}"))?;
        let record_limits = SafetyStateRecordLimitsV0::new(
            MAXIMUM_SAFETY_RECORD_BYTES_V0,
            MAXIMUM_SAFETY_BLOB_BYTES_V0,
        )
        .map_err(|error| anyhow!("construct Safety record limits: {error}"))?;
        let fresh = PocoNodeLabFreshOrdinaryGenesisConfigV0::new(
            core_config,
            genesis_qc.clone(),
            paths.safety_store,
            record_limits,
            MAXIMUM_SAFETY_DATABASE_BYTES_V0,
            application,
            expected_chain_descriptor_hash,
            expected_signer_policy_commitment,
            expected_initial_commit_id,
            paths.signer_store,
            MAXIMUM_SIGNER_INTENTS_V0,
            MAXIMUM_SIGNER_INTENT_BYTES_V0,
            MAXIMUM_SIGNER_DATABASE_BYTES_V0,
            watermark,
            checkpoint_store,
            proposal_journal,
        )
        .map_err(|error| anyhow!("construct fresh continuous authority: {error}"))?;
        let mut runtime = LabRuntimeV0::initialize_fresh_ordinary_genesis_v0(fresh)
            .map_err(|error| anyhow!("commission fresh continuous authority: {error}"))?;
        let facts = runtime.facts_v0();
        ensure!(
            facts.finalized_height_v0() == 0
                && facts.application_applied_height_v0() == 0
                && facts.proposal_parent_height_v0() == 0,
            "fresh continuous authority did not return the exact genesis cut"
        );
        let authenticated_inventory = fresh_node_ready_signer_inventory_v1(&mut runtime)
            .context("audit fresh process-one signer inventory")?;
        ensure!(
            authenticated_inventory.durable_vote_intent_count_v1() == 0
                && authenticated_inventory.durable_timeout_intent_count_v1() == 0
                && authenticated_inventory.signed_vote_intent_count_v1() == 0
                && authenticated_inventory.signed_timeout_intent_count_v1() == 0
                && authenticated_inventory.exact_watermark_v1().sequence() == 0,
            "fresh process-one authority did not have an authenticated empty signer inventory"
        );
        let signer_lifetime = ContinuousSignerLifetimeStateV0::from_authenticated_inventory_v1(
            signer_lifetime,
            authenticated_inventory,
        )?;
        Ok(Self {
            local_validator,
            validator_set,
            consensus_parameters,
            justify: QcReferenceV0::genesis_anchor(genesis_qc),
            proposal_timeout_certificate: None,
            capacity_preflight,
            signer_lifetime,
            protocol_violations: ContinuousProtocolViolationCountersV0::default(),
            consensus_windows,
            producer: ContinuousSignatureProducerV0(Box::new(LabEd25519SignatureProducer::new(
                signing_key,
            ))),
            phase: Some(ContinuousAuthorityPhaseV0::Ready(Box::new(runtime))),
        })
    }

    /// Normal-build entry from the one-way authenticated native h1 takeover.
    /// The supplied runtime already owns the exact Core/Safety/App/signer/
    /// checkpoint and retained h2->h3 execution path; this layer only compares
    /// the manifest-bound network identity, commissions bounded admission
    /// windows from the Node's complete high-QC carrier, and moves that same
    /// linear runtime behind the continuous phase owner.
    pub fn from_takeover_runtime_v0(
        config: &LoadedValidatorConfig,
        runtime: PocoNodeLabOrdinaryProposalRuntimeV0<LabFileWatermark>,
        signer_lifetime: ContinuousSignerLifetimeBoundsV0,
    ) -> Result<Self> {
        Self::from_takeover_parts_v0(
            config.local_validator(),
            config.validator_set().clone(),
            *config.consensus_parameters(),
            config.consensus_signing_key().clone(),
            config.ordinary_start_height(),
            runtime,
            signer_lifetime,
        )
    }

    /// Binds an already commissioned native takeover runtime to an injected
    /// Vote/TimeoutVote signature producer.
    ///
    /// This is a composition seam, not a production activation path.  The
    /// takeover runtime still contains the laboratory `LabFileWatermark`;
    /// this entry does not copy a consensus `SigningKey` into the continuous
    /// authority. The Node signer journal and the exact Vote/TimeoutVote
    /// verification performed by the inert owners remain the identity and
    /// signature gates. Callers that need a remote/HSM signer can therefore
    /// exercise the real timeout/vote owner without making this owner know
    /// about a private key. External watermark, host attestation, and full
    /// Core/SafetyRules signer authority remain separate gates.
    pub fn from_takeover_runtime_with_producer_v0(
        config: &LoadedValidatorConfig,
        runtime: PocoNodeLabOrdinaryProposalRuntimeV0<LabFileWatermark>,
        signer_lifetime: ContinuousSignerLifetimeBoundsV0,
        producer: Box<dyn SignatureProducerV0 + Send>,
    ) -> Result<Self> {
        Self::from_takeover_parts_with_producer_v0(
            config.local_validator(),
            config.validator_set().clone(),
            *config.consensus_parameters(),
            None,
            config.ordinary_start_height(),
            runtime,
            signer_lifetime,
            ContinuousSignatureProducerV0(producer),
        )
    }

    /// Installs an independently administered monotonic watermark behind the
    /// already commissioned Ready signer journal.
    ///
    /// This method is intentionally Ready-only and does not alter the normal
    /// local-fixture constructor or `run_bounded_consensus`.  The Node journal
    /// claims its exact existing head through the injected CAS object before
    /// refreshing the authority's authenticated inventory.  A failed claim,
    /// fork, or replay therefore leaves the authority unusable rather than
    /// silently falling back to the local file watermark.
    pub fn install_external_monotonic_watermark_v0(
        &mut self,
        external: Box<dyn ExternalMonotonicWatermarkV0 + Send>,
    ) -> Result<()> {
        let runtime = match self.phase.as_mut() {
            Some(ContinuousAuthorityPhaseV0::Ready(runtime)) => runtime,
            Some(ContinuousAuthorityPhaseV0::VoteSigned(_)) => {
                bail!("external watermark installation requires a Ready authority")
            }
            Some(ContinuousAuthorityPhaseV0::TimeoutSigned(_)) => {
                bail!("external watermark installation requires a Ready authority")
            }
            None => bail!("external watermark installation requires a live authority"),
        };
        runtime
            .install_external_monotonic_watermark_v0(external)
            .map_err(|error| anyhow!("install external monotonic watermark: {error}"))?;
        let inventory = fresh_node_ready_signer_inventory_v1(runtime)
            .context("audit signer inventory after external watermark installation")?;
        self.signer_lifetime
            .refresh_authenticated_inventory_v1(inventory)?;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn from_takeover_parts_v0(
        local_validator: ValidatorId,
        validator_set: ValidatorSet,
        consensus_parameters: ConsensusParametersV0,
        signing_key: SigningKey,
        ordinary_start_height: u64,
        runtime: PocoNodeLabOrdinaryProposalRuntimeV0<LabFileWatermark>,
        signer_lifetime: ContinuousSignerLifetimeBoundsV0,
    ) -> Result<Self> {
        Self::from_takeover_parts_with_producer_v0(
            local_validator,
            validator_set,
            consensus_parameters,
            Some(signing_key.clone()),
            ordinary_start_height,
            runtime,
            signer_lifetime,
            ContinuousSignatureProducerV0(Box::new(LabEd25519SignatureProducer::new(signing_key))),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn from_takeover_parts_with_producer_v0(
        local_validator: ValidatorId,
        validator_set: ValidatorSet,
        consensus_parameters: ConsensusParametersV0,
        signing_key: Option<SigningKey>,
        ordinary_start_height: u64,
        mut runtime: PocoNodeLabOrdinaryProposalRuntimeV0<LabFileWatermark>,
        signer_lifetime: ContinuousSignerLifetimeBoundsV0,
        producer: ContinuousSignatureProducerV0,
    ) -> Result<Self> {
        ensure!(
            runtime.matches_consensus_context_v0(
                local_validator,
                &validator_set,
                &consensus_parameters,
            ),
            "takeover runtime consensus context differs from loaded validator config"
        );
        let local = validator_set
            .validator(local_validator)
            .ok_or_else(|| anyhow!("local validator is absent from takeover validator set"))?;
        if let Some(signing_key) = signing_key {
            ensure!(
                signing_key.verifying_key().to_bytes() == local.consensus_key().into_bytes(),
                "loaded signing key differs from takeover local validator"
            );
        }

        let facts = runtime.phase_facts_v0();
        let binding = runtime
            .proposal_binding_v0()
            .map_err(|error| anyhow!("read takeover proposal binding: {error}"))?;
        ensure!(
            facts.phase_v0() == PocoNodeLabAuthorityPhaseV0::Ready
                && facts.pending_timeout_certificate_id_v0().is_none()
                && facts.current_view_v0() == binding.current_view_v0()
                && facts.high_qc_v0() == binding.high_qc_v0().qc_ref()
                && binding.current_view_v0().get().checked_sub(1)
                    == Some(binding.high_qc_v0().qc_ref().view().get())
                && facts.proposal_parent_height_v0().checked_add(1) == Some(ordinary_start_height),
            "takeover runtime is not the exact direct-highQC ordinary-start cut"
        );

        let capacity_preflight = ContinuousRuntimeCapacityPreflightV0::new(
            validator_set.validators().len(),
            signer_lifetime,
        )?;
        let mut consensus_windows = ContinuousConsensusWindowsV0::new(
            validator_set.clone(),
            consensus_parameters,
            capacity_preflight,
            binding.high_qc_v0().clone(),
        )?;
        consensus_windows.synchronize_authoritative_progress_v0(
            binding.current_view_v0(),
            binding.high_qc_v0(),
            None,
        )?;
        let authenticated_inventory = fresh_node_ready_signer_inventory_v1(&mut runtime)
            .context("audit takeover signer inventory")?;
        let signer_lifetime = ContinuousSignerLifetimeStateV0::from_authenticated_inventory_v1(
            signer_lifetime,
            authenticated_inventory,
        )?;
        Ok(Self {
            local_validator,
            validator_set,
            consensus_parameters,
            justify: binding.high_qc_v0().clone(),
            proposal_timeout_certificate: None,
            capacity_preflight,
            signer_lifetime,
            protocol_violations: ContinuousProtocolViolationCountersV0::default(),
            consensus_windows,
            producer,
            phase: Some(ContinuousAuthorityPhaseV0::Ready(Box::new(runtime))),
        })
    }

    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_takeover_parts_for_test_v0(
        local_validator: ValidatorId,
        validator_set: ValidatorSet,
        consensus_parameters: ConsensusParametersV0,
        signing_key: SigningKey,
        ordinary_start_height: u64,
        runtime: PocoNodeLabOrdinaryProposalRuntimeV0<LabFileWatermark>,
        signer_lifetime: ContinuousSignerLifetimeBoundsV0,
    ) -> Result<Self> {
        Self::from_takeover_parts_v0(
            local_validator,
            validator_set,
            consensus_parameters,
            signing_key,
            ordinary_start_height,
            runtime,
            signer_lifetime,
        )
    }

    pub const fn local_validator_v0(&self) -> ValidatorId {
        self.local_validator
    }

    pub const fn validator_set_v0(&self) -> &ValidatorSet {
        &self.validator_set
    }

    pub const fn consensus_parameters_v0(&self) -> &ConsensusParametersV0 {
        &self.consensus_parameters
    }

    pub fn justify_v0(&self) -> &QcReferenceV0 {
        &self.justify
    }

    pub const fn capacity_preflight_v0(&self) -> ContinuousRuntimeCapacityPreflightV0 {
        self.capacity_preflight
    }

    /// Consumes the exact obligation-free Ready authority into a restart-park
    /// carrier.  The signer journal is freshly owner-audited at this boundary;
    /// caller-supplied counters or a cached runtime projection are never used
    /// as parking authority.
    pub(crate) fn into_restart_parked_authority_v1(
        mut self,
    ) -> Result<ContinuousRestartParkedAuthorityV1> {
        ensure!(
            self.proposal_timeout_certificate.is_none(),
            "continuous restart park retains a pending proposal timeout certificate"
        );
        self.signer_lifetime.require_vote_accounting_v0()?;
        self.signer_lifetime.require_timeout_accounting_v0()?;
        let fresh_inventory = self.fresh_ready_signer_inventory_v1()?;
        let facts = self
            .facts_v0()
            .context("project freshly audited restart-park facts")?;
        ensure!(
            facts.phase_v0() == PocoNodeLabAuthorityPhaseV0::Ready
                && facts.pending_timeout_certificate_id_v0().is_none()
                && fresh_inventory.durable_vote_intent_count_v1()
                    == fresh_inventory.signed_vote_intent_count_v1()
                && fresh_inventory.durable_timeout_intent_count_v1()
                    == fresh_inventory.signed_timeout_intent_count_v1()
                && facts.signed_vote_intents_v0()
                    == fresh_inventory.signed_vote_intent_count_v1()
                && facts.signed_timeout_intents_v0()
                    == fresh_inventory.signed_timeout_intent_count_v1()
                && facts.signer_exact_watermark_v1() == fresh_inventory.exact_watermark_v1()
                && facts.authenticated_signer_inventory_digest_v1()
                    == fresh_inventory.inventory_digest_v1()
                && facts.checkpoint_canonical_sha256_v1()
                    == fresh_inventory.checkpoint_canonical_sha256_v1()
                && facts.high_qc_v0() == self.justify.qc_ref(),
            "continuous restart-park facts differ from the fresh Ready signer inventory or authoritative high QC"
        );
        Ok(ContinuousRestartParkedAuthorityV1 {
            _authority: self,
            facts,
        })
    }

    /// Consumes an exact Ready phase into the Node's clean terminal owner.
    /// Pending TC proposal context and signed/intermediate phase carriers are
    /// rejected; signer-lifetime counters are then joined to the freshly
    /// authenticated signer journal before the inert wrapper is returned.
    pub fn into_terminal_owner_v0(mut self) -> Result<ContinuousValidatorTerminalOwnerV0> {
        ensure!(
            self.proposal_timeout_certificate.is_none(),
            "continuous terminal cut retains a pending proposal timeout certificate"
        );
        self.signer_lifetime.require_vote_accounting_v0()?;
        self.signer_lifetime.require_timeout_accounting_v0()?;
        let fresh_inventory = self.fresh_ready_signer_inventory_v1()?;
        let phase = self
            .phase
            .take()
            .ok_or_else(|| anyhow!("continuous terminal cut has no live authority phase"))?;
        let ContinuousAuthorityPhaseV0::Ready(runtime) = phase else {
            bail!("continuous terminal cut requires the exact Ready phase");
        };
        let node = runtime
            .into_terminal_owner_v0()
            .map_err(|error| anyhow!("consume Node terminal owner: {error}"))?;
        let node_facts = *node.facts_v0();
        ensure!(
            node_facts.signer_durable_vote_intent_count_v1()
                == fresh_inventory.durable_vote_intent_count_v1()
                && node_facts.signer_durable_timeout_intent_count_v1()
                    == fresh_inventory.durable_timeout_intent_count_v1()
                && node_facts.signer_signed_vote_intent_count_v1()
                    == fresh_inventory.signed_vote_intent_count_v1()
                && node_facts.signer_signed_timeout_intent_count_v1()
                    == fresh_inventory.signed_timeout_intent_count_v1()
                && node_facts.signer_inventory_digest_v1()
                    == fresh_inventory.inventory_digest_v1()
                && node_facts.signer_exact_watermark_v0()
                    == fresh_inventory.exact_watermark_v1()
                && node_facts.checkpoint_canonical_sha256_v0()
                    == fresh_inventory.checkpoint_canonical_sha256_v1()
                && node_facts.signer_signed_vote_intent_count_v1()
                    == self.signer_lifetime.signed_vote_intents
                && node_facts.signer_signed_timeout_intent_count_v1()
                    == self.signer_lifetime.signed_timeout_intents
                && node_facts.high_qc_v0() == self.justify.qc_ref(),
            "continuous terminal per-kind signer inventory, digest, watermark, or high QC differs from the Node terminal cut"
        );
        let facts = ContinuousValidatorTerminalCutV0 {
            node: node_facts,
            local_validator: self.local_validator,
            validator_count: self.capacity_preflight.validator_count,
            retained_views: self.capacity_preflight.retained_views,
            signer_lifetime: self.signer_lifetime.bounds,
            signed_vote_intents: self.signer_lifetime.signed_vote_intents,
            signed_timeout_intents: self.signer_lifetime.signed_timeout_intents,
            protocol_violations: self.protocol_violations,
        };
        Ok(ContinuousValidatorTerminalOwnerV0 { _node: node, facts })
    }

    /// Current process-local sliding-window watermark. This is not a network
    /// or G3 evidence claim; it reports only this authority's bounded admission
    /// state.
    pub fn minimum_retained_view_v0(&self) -> Result<View> {
        self.consensus_windows.minimum_retained_view_v0()
    }

    /// Routes one already transport-authenticated direct consensus frame into
    /// this authority's bounded process-local collector. `None` is an inert
    /// exact Proposal replay, including a replay arriving in a fresh transport
    /// session; all non-Proposal collector actions remain explicit.
    pub fn admit_authenticated_consensus_frame_v0(
        &mut self,
        frame: &AuthenticatedFrame,
    ) -> Result<Option<RoutedConsensusActionV0>> {
        let result = self.consensus_windows.admit_authenticated_frame_v0(frame);
        if let Err(error) = &result {
            self.protocol_violations.record_anyhow_v0(error)?;
        }
        result
    }

    /// Routes one already hop-authenticated relay frame through origin
    /// verification, view-aware replay admission, and strict consensus decode.
    /// The caller remains responsible for recording/retrying mesh
    /// backpressure; this method owns no peer queue or socket.
    pub fn admit_authenticated_consensus_relay_frame_v0(
        &mut self,
        frame: &AuthenticatedFrame,
    ) -> Result<RoutedConsensusRelayV0> {
        let result = self.consensus_windows.admit_consensus_relay_frame_v0(frame);
        if let Err(error) = &result {
            self.protocol_violations.record_anyhow_v0(error)?;
        }
        result
    }

    /// Verifies and reserves one locally signed relay envelope before the
    /// caller exposes it to any peer. This does not replace the local typed
    /// Vote/TimeoutVote collector path and never fabricates a self-session.
    pub fn reserve_originated_consensus_relay_v0(
        &mut self,
        envelope: &ConsensusRelayEnvelopeV0,
    ) -> Result<[u8; 32]> {
        ensure!(
            envelope.origin() == self.local_validator,
            "originated relay author differs from this continuous authority"
        );
        self.consensus_windows
            .reserve_originated_consensus_relay_v0(envelope)
    }

    /// Inserts the exact Vote most recently released by this authority into
    /// its process-local collector. Local messages never traverse a synthetic
    /// self mesh/session; the typed Vote is strictly reverified and shares the
    /// remote path's replay, equivocation, capacity, and QC aggregation state.
    /// The returned QC is the deterministic aggregate when this Vote reaches
    /// quorum, including when remote Votes arrived first.
    pub fn admit_local_vote_v0(&mut self, vote: Vote) -> Result<Option<QuorumCertificate>> {
        ensure!(
            vote.author() == self.local_validator,
            "local Vote author differs from this continuous authority"
        );
        let Some(ContinuousAuthorityPhaseV0::VoteSigned(signed)) = self.phase.as_ref() else {
            bail!("continuous authority has no locally signed Vote to admit")
        };
        ensure!(
            signed.outbound_v0().vote_v0() == &vote,
            "local Vote differs from the exact signer-journal output"
        );
        let result = self.consensus_windows.admit_local_vote_v0(vote);
        if let Err(error) = &result {
            self.protocol_violations.record_anyhow_v0(error)?;
        }
        result
    }

    /// Inserts the exact TimeoutVote most recently released by this authority
    /// into the same process-local collector used for remote TimeoutVotes.
    /// The returned TC is the deterministic aggregate when this local vote
    /// completes quorum; no authenticated self frame or transport session is
    /// created.
    pub fn admit_local_timeout_vote_v0(
        &mut self,
        vote: TimeoutVote,
    ) -> Result<Option<TimeoutCertificateV0>> {
        ensure!(
            vote.author() == self.local_validator,
            "local TimeoutVote author differs from this continuous authority"
        );
        let Some(ContinuousAuthorityPhaseV0::TimeoutSigned(signed)) = self.phase.as_ref() else {
            bail!("continuous authority has no locally signed TimeoutVote to admit")
        };
        ensure!(
            signed.outbound_v0().timeout_vote_v0() == &vote,
            "local TimeoutVote differs from the exact signer-journal output"
        );
        let result = self.consensus_windows.admit_local_timeout_vote_v0(vote);
        if let Err(error) = &result {
            self.protocol_violations.record_anyhow_v0(error)?;
        }
        result
    }

    /// Builds the next exact non-empty proposal preimage from this validator's
    /// pinned public workload corpus. Only the scheduled leader may call this
    /// successfully. Proposal witness signing is separate from Vote/Timeout
    /// signing because PoCO v0's canonical signer-intent set contains only
    /// Vote and TimeoutVote; all votes still pass through the journal below.
    pub fn proposal_preimage_from_loaded_config_v0(
        &self,
        config: &mut LoadedValidatorConfig,
    ) -> Result<ContinuousProposalPreimageV0> {
        ensure!(
            config.local_validator() == self.local_validator
                && config.validator_set() == &self.validator_set
                && config.consensus_parameters() == &self.consensus_parameters,
            "loaded workload context differs from continuous authority"
        );
        let height = self
            .ready_runtime_v0()?
            .facts_v0()
            .proposal_parent_height_v0()
            .checked_add(1)
            .context("next workload height overflows")?;
        let workload = config.workload_corpus_mut().block_at_height(height)?;
        self.proposal_preimage_v0(workload)
    }

    /// Convenience leader path which signs only the proposal witness with the
    /// manifest-bound Ed25519 key. It cannot create a Vote or TimeoutVote;
    /// those roots remain inaccessible until Core and Safety authorize the
    /// signer journal.
    pub fn signed_workload_proposal_from_loaded_config_v0(
        &self,
        config: &mut LoadedValidatorConfig,
    ) -> Result<SignedProposalV0> {
        let preimage = self.proposal_preimage_from_loaded_config_v0(config)?;
        preimage.seal_with_key_v0(config.consensus_signing_key())
    }

    pub fn proposal_preimage_v0(
        &self,
        workload: WorkloadBlockV1,
    ) -> Result<ContinuousProposalPreimageV0> {
        self.proposal_preimage_from_transactions_v0(
            workload.height,
            workload.timestamp_ms,
            workload.transactions.into_iter().collect(),
        )
    }

    #[cfg(test)]
    pub(crate) fn proposal_preimage_for_test_v0(
        &self,
        height: u64,
        timestamp_ms: u64,
        transactions: Vec<Vec<u8>>,
    ) -> Result<ContinuousProposalPreimageV0> {
        self.proposal_preimage_from_transactions_v0(height, timestamp_ms, transactions)
    }

    fn proposal_preimage_from_transactions_v0(
        &self,
        height: u64,
        timestamp_ms: u64,
        transactions: Vec<Vec<u8>>,
    ) -> Result<ContinuousProposalPreimageV0> {
        let runtime = self.ready_runtime_v0()?;
        let binding = runtime
            .proposal_binding_v0()
            .map_err(|error| anyhow!("read typed proposal binding: {error}"))?;
        ensure!(
            binding.high_qc_v0() == &self.justify,
            "cached proposal justify differs from Node authoritative high QC"
        );
        let parent = runtime
            .proposal_parent_v0()
            .map_err(|error| anyhow!("read exact proposal parent: {error}"))?;
        let justify_ref = self.justify.qc_ref();
        ensure!(
            parent.application_head_v0().height().get() == justify_ref.height().get()
                && parent.application_head_v0().block_id().as_bytes()
                    == justify_ref.block_id().as_bytes(),
            "runtime speculative parent differs from the exact justify QC"
        );
        let expected_height = parent
            .application_head_v0()
            .height()
            .get()
            .checked_add(1)
            .context("proposal height overflows")?;
        ensure!(
            height == expected_height,
            "workload height differs from the runtime successor"
        );
        let view = runtime.facts_v0().current_view_v0();
        ensure!(
            view > justify_ref.view(),
            "Core current view does not advance beyond the proposal justify"
        );
        let proposer = leader_for(&self.validator_set, view);
        ensure!(
            proposer == self.local_validator,
            "only the scheduled local leader may author a proposal preimage"
        );
        let payload = ApplicationPayloadV0::new(transactions.clone())
            .map_err(|error| anyhow!("construct non-empty application payload: {error}"))?;
        ensure!(
            payload.transaction_count() > 0,
            "continuous proposal payload is empty"
        );
        let (preview_parent, preview) = runtime
            .preview_next_nonempty_v0(transactions, timestamp_ms)
            .map_err(|error| anyhow!("preview exact workload transition: {error}"))?;
        ensure!(
            preview_parent == parent,
            "native preview changed the authenticated proposal parent"
        );
        let payload_root = PayloadDigest::new(*preview.payload_root().as_bytes());
        ensure!(
            payload
                .payload_root()
                .map_err(|error| anyhow!("compute payload root: {error}"))?
                == payload_root,
            "native preview payload root differs from consensus payload"
        );
        let header = BlockHeader::new(
            self.validator_set.genesis_hash(),
            self.validator_set.chain_id(),
            self.validator_set.protocol_version(),
            self.validator_set.epoch(),
            view,
            Height::new(expected_height),
            BlockKind::Regular,
            BlockId::new(*parent.application_head_v0().block_id().as_bytes()),
            proposer,
            self.validator_set.id(),
            self.validator_set.consensus_parameters_hash(),
            payload_root,
            StateRoot::new(*preview.post_state_root().as_bytes()),
            ReceiptsRoot::new(*preview.receipts_root().as_bytes()),
            EvidenceRoot::new(*preview.evidence_root().as_bytes()),
            timestamp_ms,
            None,
        )
        .map_err(|error| anyhow!("construct exact proposal header: {error}"))?;
        let block = Block::new(
            header,
            payload
                .try_cev0_bytes()
                .map_err(|error| anyhow!("encode exact application payload: {error}"))?,
            Vec::new(),
        )
        .map_err(|error| anyhow!("construct exact proposal block: {error}"))?;
        let timeout_certificate = self.proposal_timeout_certificate.clone();
        let signing_root = ProposalWitnessV0::signing_root_for(
            block.header(),
            &self.justify,
            timeout_certificate.as_ref(),
            None,
        )
        .map_err(|error| anyhow!("derive proposal signing root: {error}"))?;
        Ok(ContinuousProposalPreimageV0 {
            block,
            justify: self.justify.clone(),
            timeout_certificate,
            validator_set: self.validator_set.clone(),
            consensus_parameters: self.consensus_parameters,
            authenticated_parent_timestamp_ms: parent.authenticated_parent_timestamp_ms_v0(),
            signing_root,
            expected_post_state_root: StateRoot::new(*preview.post_state_root().as_bytes()),
        })
    }

    /// Atomically applies the certificates embedded by one untrusted network
    /// proposal, aligns them with the Node-selected view/highQC/native parent,
    /// binds the locally authenticated parent timestamp, and only then enters
    /// the Vote authority chain.
    pub fn vote_unbound_proposal_v0(&mut self, proposal: UnboundProposalV0) -> Result<Vote> {
        if let Some(certificate) = proposal.timeout_certificate().cloned() {
            self.advance_timeout_certificate_v0(certificate)?;
        } else if let Some(certificate) = proposal.justify_qc().as_ordinary().cloned() {
            self.advance_quorum_certificate_v0(certificate)?;
        }
        let binding = self
            .ready_runtime_v0()?
            .proposal_binding_v0()
            .map_err(|error| anyhow!("read authoritative proposal binding: {error}"))?;
        let header = proposal.block().header();
        ensure!(
            header.view() == binding.current_view_v0(),
            "proposal view differs from authoritative current_view"
        );
        ensure!(
            proposal.justify_qc() == binding.high_qc_v0(),
            "proposal justify differs from authoritative high QC"
        );
        ensure!(
            header.parent_id().as_bytes()
                == binding
                    .parent_v0()
                    .application_head_v0()
                    .block_id()
                    .as_bytes()
                && header.height().get()
                    == binding
                        .parent_v0()
                        .application_head_v0()
                        .height()
                        .get()
                        .checked_add(1)
                        .context("authoritative proposal-parent height overflows")?,
            "proposal parent differs from authoritative native parent"
        );
        let proposal = proposal
            .bind_authenticated_parent(
                &self.validator_set,
                &self.consensus_parameters,
                binding.parent_v0().authenticated_parent_timestamp_ms_v0(),
            )
            .map_err(|error| anyhow!("bind authenticated proposal parent: {error}"))?;
        self.vote_bound_proposal_v0(proposal)
    }

    /// Drives one verified proposal through real native execution, Safety,
    /// checkpointing, and signer-journal Vote production.
    pub fn vote_proposal_v0(&mut self, proposal: SignedProposalV0) -> Result<Vote> {
        let unbound = UnboundProposalV0::from_signed(&proposal)
            .map_err(|error| anyhow!("project proposal into unbound ingress: {error}"))?;
        self.vote_unbound_proposal_v0(unbound)
    }

    fn vote_bound_proposal_v0(&mut self, proposal: SignedProposalV0) -> Result<Vote> {
        if !matches!(self.phase, Some(ContinuousAuthorityPhaseV0::Ready(_))) {
            bail!("continuous authority is not ready for a proposal");
        }
        self.signer_lifetime.require_vote_available_v0()?;
        let Some(ContinuousAuthorityPhaseV0::Ready(runtime)) = self.phase.take() else {
            unreachable!("phase checked above")
        };
        let inert = (*runtime)
            .drive_one_to_inert_request_v0(proposal)
            .map_err(|error| anyhow!("drive proposal authority chain: {error}"))?;
        let signed = inert
            .sign_exact_vote_v0(&mut self.producer)
            .map_err(|error| anyhow!("journal and release exact Vote: {error}"))?;
        let vote = signed.outbound_v0().vote_v0().clone();
        self.signer_lifetime.record_vote_v0()?;
        self.phase = Some(ContinuousAuthorityPhaseV0::VoteSigned(Box::new(signed)));
        Ok(vote)
    }

    /// Starts and journals the local timeout for the authoritative current
    /// view from either Ready or VoteSigned.
    pub fn begin_local_timeout_v0(&mut self) -> Result<TimeoutVote> {
        if matches!(
            self.phase,
            Some(ContinuousAuthorityPhaseV0::TimeoutSigned(_)) | None
        ) {
            bail!("continuous authority cannot start another local timeout");
        }
        self.signer_lifetime.require_timeout_available_v0()?;
        let phase = self
            .phase
            .take()
            .expect("eligible phase checked before consuming owner");
        let inert = match phase {
            ContinuousAuthorityPhaseV0::Ready(runtime) => (*runtime)
                .begin_local_timeout_v0()
                .map_err(|error| anyhow!("begin Ready local timeout: {error}"))?,
            ContinuousAuthorityPhaseV0::VoteSigned(signed) => (*signed)
                .begin_local_timeout_v0()
                .map_err(|error| anyhow!("begin VoteSigned local timeout: {error}"))?,
            ContinuousAuthorityPhaseV0::TimeoutSigned(_) => unreachable!("phase checked above"),
        };
        let signed = inert
            .sign_exact_timeout_v0(&mut self.producer)
            .map_err(|error| anyhow!("journal and release exact TimeoutVote: {error}"))?;
        let vote = signed.outbound_v0().timeout_vote_v0().clone();
        self.signer_lifetime.record_timeout_v0()?;
        self.phase = Some(ContinuousAuthorityPhaseV0::TimeoutSigned(Box::new(signed)));
        Ok(vote)
    }

    /// Applies a strict-Ed25519 QC from Ready, VoteSigned, or TimeoutSigned.
    /// No local Vote membership or coordinate precondition is imposed outside
    /// Core's certificate and safety rules.
    pub fn advance_quorum_certificate_v0(
        &mut self,
        certificate: QuorumCertificate,
    ) -> Result<ContinuousRuntimeFactsV0> {
        certificate
            .verify(&self.validator_set, &StrictEd25519Verifier)
            .map_err(|error| anyhow!("verify continuous QC: {error}"))?;
        if self
            .justify
            .as_ordinary()
            .is_some_and(|authoritative| authoritative.id() == certificate.id())
        {
            let phase = self
                .phase
                .as_mut()
                .ok_or_else(|| anyhow!("continuous authority is fail-closed"))?;
            let before = match phase {
                ContinuousAuthorityPhaseV0::Ready(runtime) => runtime.phase_facts_v0(),
                ContinuousAuthorityPhaseV0::VoteSigned(signed) => signed.phase_facts_v0(),
                ContinuousAuthorityPhaseV0::TimeoutSigned(signed) => signed.phase_facts_v0(),
            };
            let after = match phase {
                ContinuousAuthorityPhaseV0::Ready(runtime) => runtime
                    .reconfirm_phase_neutral_exact_high_qc_v0(&certificate)
                    .map_err(|error| anyhow!("reconfirm Ready exact high-QC replay: {error}"))?,
                ContinuousAuthorityPhaseV0::VoteSigned(signed) => signed
                    .reconfirm_phase_neutral_exact_high_qc_v0(&certificate)
                    .map_err(|error| {
                        anyhow!("reconfirm VoteSigned exact high-QC replay: {error}")
                    })?,
                ContinuousAuthorityPhaseV0::TimeoutSigned(signed) => signed
                    .reconfirm_phase_neutral_exact_high_qc_v0(&certificate)
                    .map_err(|error| {
                        anyhow!("reconfirm TimeoutSigned exact high-QC replay: {error}")
                    })?,
            };
            ensure!(
                after == before,
                "exact high-QC replay changed the live authority phase or durable facts"
            );
            return self.facts_v0();
        }
        let phase = self
            .phase
            .take()
            .ok_or_else(|| anyhow!("continuous authority is fail-closed"))?;
        let advance = match phase {
            ContinuousAuthorityPhaseV0::Ready(runtime) => (*runtime)
                .advance_quorum_certificate_v0(certificate)
                .map_err(|error| anyhow!("advance Ready QC: {error}"))?,
            ContinuousAuthorityPhaseV0::VoteSigned(signed) => (*signed)
                .advance_quorum_certificate_v0(certificate)
                .map_err(|error| anyhow!("advance VoteSigned QC: {error}"))?,
            ContinuousAuthorityPhaseV0::TimeoutSigned(signed) => (*signed)
                .advance_quorum_certificate_v0(certificate)
                .map_err(|error| anyhow!("advance TimeoutSigned QC: {error}"))?,
        };
        self.install_ready_after_advance_v0(advance, None)
    }

    /// Applies a strict TC from Ready, VoteSigned, or TimeoutSigned.
    pub fn advance_timeout_certificate_v0(
        &mut self,
        certificate: TimeoutCertificateV0,
    ) -> Result<ContinuousRuntimeFactsV0> {
        certificate
            .verify(&self.validator_set, None, &StrictEd25519Verifier)
            .map_err(|error| anyhow!("verify continuous TC: {error}"))?;
        let accepted_certificate = certificate.clone();
        let phase = self
            .phase
            .take()
            .ok_or_else(|| anyhow!("continuous authority is fail-closed"))?;
        let advance = match phase {
            ContinuousAuthorityPhaseV0::Ready(runtime) => (*runtime)
                .advance_timeout_certificate_v0(certificate)
                .map_err(|error| anyhow!("advance Ready TC: {error}"))?,
            ContinuousAuthorityPhaseV0::VoteSigned(signed) => (*signed)
                .advance_timeout_certificate_v0(certificate)
                .map_err(|error| anyhow!("advance VoteSigned TC: {error}"))?,
            ContinuousAuthorityPhaseV0::TimeoutSigned(signed) => (*signed)
                .advance_timeout_certificate_v0(certificate)
                .map_err(|error| anyhow!("advance TimeoutSigned TC: {error}"))?,
        };
        self.install_ready_after_advance_v0(advance, Some(accepted_certificate))
    }

    fn install_ready_after_advance_v0(
        &mut self,
        advance: PocoNodeLabCertificateAdvanceV0<LabFileWatermark>,
        accepted_timeout_certificate: Option<TimeoutCertificateV0>,
    ) -> Result<ContinuousRuntimeFactsV0> {
        let mut runtime = drain_finalizations_v0(advance)?;
        let binding = runtime
            .proposal_binding_v0()
            .map_err(|error| anyhow!("read post-certificate proposal binding: {error}"))?;
        self.justify = binding.high_qc_v0().clone();
        let next_view_is_direct = binding.current_view_v0().get().checked_sub(1)
            == Some(binding.high_qc_v0().qc_ref().view().get());
        if next_view_is_direct {
            self.proposal_timeout_certificate = None;
        } else {
            let candidate = accepted_timeout_certificate
                .or_else(|| self.proposal_timeout_certificate.take())
                .ok_or_else(|| {
                    anyhow!("authoritative skipped view lacks its exact timeout certificate")
                })?;
            ensure!(
                candidate.timed_out_view().get().checked_add(1)
                    == Some(binding.current_view_v0().get())
                    && candidate.selected_high_qc_digest() == binding.high_qc_v0().id()
                    && candidate
                        .referenced_qcs()
                        .iter()
                        .any(|reference| reference == binding.high_qc_v0()),
                "timeout certificate differs from the authoritative proposal binding"
            );
            self.proposal_timeout_certificate = Some(candidate);
        }
        let minimum_retained_view = self
            .consensus_windows
            .synchronize_authoritative_progress_v0(
                binding.current_view_v0(),
                &self.justify,
                self.proposal_timeout_certificate.as_ref(),
            )?;
        let authenticated_inventory = fresh_node_ready_signer_inventory_v1(&mut runtime)
            .context("audit post-certificate Ready signer inventory")?;
        self.signer_lifetime
            .refresh_authenticated_inventory_v1(authenticated_inventory)?;
        let mut facts = ContinuousRuntimeFactsV0::from_phase_facts_v0(
            self.local_validator,
            runtime.phase_facts_v0(),
            self.capacity_preflight,
            self.signer_lifetime,
            minimum_retained_view,
        );
        if let Some(certificate) = self.proposal_timeout_certificate.as_ref() {
            facts.pending_timeout_certificate_id = Some(certificate.id());
        }
        self.phase = Some(ContinuousAuthorityPhaseV0::Ready(runtime));
        Ok(facts)
    }

    /// Freshly audits the exact operational signer inventory while the Node
    /// authority is Ready and joins it to the process-local lifetime counters.
    /// No scalar accounting is accepted from the caller.
    pub(crate) fn fresh_ready_signer_inventory_v1(
        &mut self,
    ) -> Result<ContinuousAuthenticatedSignerInventoryV1> {
        let inventory = match self.phase.as_mut() {
            Some(ContinuousAuthorityPhaseV0::Ready(runtime)) => {
                fresh_node_ready_signer_inventory_v1(runtime)
                    .context("audit Ready signer inventory")?
            }
            Some(ContinuousAuthorityPhaseV0::VoteSigned(_)) => {
                bail!("fresh signer inventory requires a Ready authority, not VoteSigned")
            }
            Some(ContinuousAuthorityPhaseV0::TimeoutSigned(_)) => {
                bail!("fresh signer inventory requires a Ready authority, not TimeoutSigned")
            }
            None => bail!("continuous authority failed closed before signer inventory audit"),
        };
        self.signer_lifetime
            .refresh_authenticated_inventory_v1(inventory)?;
        Ok(inventory)
    }

    pub fn facts_v0(&self) -> Result<ContinuousRuntimeFactsV0> {
        let phase = self.phase.as_ref().ok_or_else(|| {
            anyhow!("continuous authority failed closed after a consumed-owner error")
        })?;
        let facts = match phase {
            ContinuousAuthorityPhaseV0::Ready(runtime) => runtime.phase_facts_v0(),
            ContinuousAuthorityPhaseV0::VoteSigned(signed) => signed.phase_facts_v0(),
            ContinuousAuthorityPhaseV0::TimeoutSigned(signed) => signed.phase_facts_v0(),
        };
        let mut projected = ContinuousRuntimeFactsV0::from_phase_facts_v0(
            self.local_validator,
            facts,
            self.capacity_preflight,
            self.signer_lifetime,
            self.consensus_windows.minimum_retained_view_v0()?,
        );
        if let Some(certificate) = self.proposal_timeout_certificate.as_ref() {
            projected.pending_timeout_certificate_id = Some(certificate.id());
        }
        Ok(projected)
    }

    fn ready_runtime_v0(&self) -> Result<&LabRuntimeV0> {
        match self.phase.as_ref() {
            Some(ContinuousAuthorityPhaseV0::Ready(runtime)) => Ok(runtime),
            Some(ContinuousAuthorityPhaseV0::VoteSigned(_)) => {
                bail!("continuous authority is VoteSigned")
            }
            Some(ContinuousAuthorityPhaseV0::TimeoutSigned(_)) => {
                bail!("continuous authority is TimeoutSigned")
            }
            None => bail!("continuous authority failed closed after a consumed-owner error"),
        }
    }
}

/// Proposal witness preimage produced by a real native execution preview.
/// It owns no Core, Safety, application, checkpoint, or Vote authority.
pub struct ContinuousProposalPreimageV0 {
    block: Block,
    justify: QcReferenceV0,
    timeout_certificate: Option<TimeoutCertificateV0>,
    validator_set: ValidatorSet,
    consensus_parameters: ConsensusParametersV0,
    authenticated_parent_timestamp_ms: u64,
    signing_root: trnm_consensus_types::SigningRoot,
    expected_post_state_root: StateRoot,
}

impl std::fmt::Debug for ContinuousProposalPreimageV0 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ContinuousProposalPreimageV0")
            .field("block_id", &self.block.id())
            .field("height", &self.block.header().height())
            .field("view", &self.block.header().view())
            .field("proposer", &self.block.header().proposer_id())
            .finish_non_exhaustive()
    }
}

impl ContinuousProposalPreimageV0 {
    pub const fn block_v0(&self) -> &Block {
        &self.block
    }

    pub const fn signing_root_v0(&self) -> trnm_consensus_types::SigningRoot {
        self.signing_root
    }

    pub const fn expected_post_state_root_v0(&self) -> StateRoot {
        self.expected_post_state_root
    }

    /// Derives the exact request identity presented to an injected proposal
    /// signer.  The request binds the canonical block ID, parent, epoch/view/
    /// height, scheduled proposer key, and already-derived proposal root.
    /// Constructing it does not authorize a proposal or advance signer state.
    pub fn proposal_signature_request_v0(
        &self,
        signer_profile_ref: [u8; 32],
    ) -> Result<ProposalSignatureRequestV0> {
        let proposer = self.block.header().proposer_id();
        let validator = self
            .validator_set
            .validator(proposer)
            .ok_or_else(|| anyhow!("proposal leader is absent from validator set"))?;
        ProposalSignatureRequestV0::new(
            self.block.id(),
            self.block.header().parent_id(),
            self.block.header().validator_set_id(),
            proposer,
            self.block.header().epoch(),
            self.block.header().view(),
            self.block.header().height(),
            self.signing_root,
            validator.consensus_key().into_bytes(),
            signer_profile_ref,
        )
        .ok_or_else(|| anyhow!("proposal signature request has invalid identity fields"))
    }

    /// Signs and strictly verifies one exact proposal witness through an
    /// injected producer.  This is a composition seam only: the producer is
    /// not journaled here, and Core/SafetyRules/whole-node fencing remain
    /// separate authorities.
    pub fn seal_with_producer_v0(
        self,
        producer: &mut dyn ProposalSignatureProducerV0,
        signer_profile_ref: [u8; 32],
    ) -> Result<SignedProposalV0> {
        let request = self.proposal_signature_request_v0(signer_profile_ref)?;
        let signature = producer
            .sign_proposal(request)
            .map_err(|error| anyhow!("proposal signer rejected exact request: {error:?}"))?;
        self.finish_with_signature_v0(signature)
    }

    /// Fixture-only compatibility helper.  Normal runtime code must use an
    /// injected producer; this method remains for deterministic test material
    /// and is intentionally not a production activation path.
    pub fn seal_with_key_v0(self, key: &SigningKey) -> Result<SignedProposalV0> {
        let mut producer = LabEd25519ProposalSignatureProducerV0::new(key.clone());
        self.seal_with_producer_v0(&mut producer, [0x51; 32])
    }

    fn finish_with_signature_v0(self, signature: SignatureBytes) -> Result<SignedProposalV0> {
        let proposer = self.block.header().proposer_id();
        let validator = self
            .validator_set
            .validator(proposer)
            .ok_or_else(|| anyhow!("proposal leader is absent from validator set"))?;
        ensure!(
            StrictEd25519Verifier.verify(validator, &self.signing_root, &signature),
            "proposal signer returned a signature for a different root or key"
        );
        let witness = ProposalWitnessV0::new(
            self.block.header(),
            self.justify,
            self.timeout_certificate,
            None,
            signature,
            &self.validator_set,
            None,
            &self.consensus_parameters,
            self.authenticated_parent_timestamp_ms,
        )
        .map_err(|error| anyhow!("construct strict proposal witness: {error}"))?;
        let proposal = SignedProposalV0::new(
            self.block,
            witness,
            &self.validator_set,
            None,
            &self.consensus_parameters,
            self.authenticated_parent_timestamp_ms,
        )
        .map_err(|error| anyhow!("construct signed proposal: {error}"))?;
        proposal
            .verify(
                &self.validator_set,
                None,
                &self.consensus_parameters,
                self.authenticated_parent_timestamp_ms,
                &StrictEd25519Verifier,
            )
            .map_err(|error| anyhow!("verify strict proposal signature: {error}"))?;
        Ok(proposal)
    }
}

/// Secret-free, phase-neutral convergence projection from one continuous
/// authority. Every storage scalar comes from the Node's exact checkpointed
/// Safety/App/Signer readback rather than network claims.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ContinuousRuntimeFactsV0 {
    local_validator: ValidatorId,
    phase: PocoNodeLabAuthorityPhaseV0,
    capacity_preflight: ContinuousRuntimeCapacityPreflightV0,
    signed_vote_intents: u64,
    signed_timeout_intents: u64,
    minimum_retained_view: View,
    current_view: View,
    high_qc: QcRef,
    pending_timeout_certificate_id: Option<CertificateId>,
    finalized_block_id: BlockId,
    finalized_height: u64,
    finalized_chain_root: [u8; 32],
    application_applied_block_id: BlockId,
    application_applied_height: u64,
    proposal_parent_block_id: BlockId,
    proposal_parent_height: u64,
    application_state_root: StateRoot,
    safety_revision: u64,
    safety_record_checksum: [u8; 32],
    safety_chain_checksum: [u8; 32],
    signer_exact_watermark: trnm_consensus_signer_journal::SignerWatermarkV0,
    signer_watermark_sequence: u64,
    authenticated_signer_inventory_digest: [u8; 32],
    checkpoint_generation: u64,
    checkpoint_canonical_sha256: [u8; 32],
}

impl ContinuousRuntimeFactsV0 {
    fn from_phase_facts_v0(
        local_validator: ValidatorId,
        facts: PocoNodeLabPhaseFactsV0,
        capacity_preflight: ContinuousRuntimeCapacityPreflightV0,
        signer_lifetime: ContinuousSignerLifetimeStateV0,
        minimum_retained_view: View,
    ) -> Self {
        let checkpoint = facts.checkpoint_v0();
        Self {
            local_validator,
            phase: facts.phase_v0(),
            capacity_preflight,
            signed_vote_intents: signer_lifetime.signed_vote_intents,
            signed_timeout_intents: signer_lifetime.signed_timeout_intents,
            minimum_retained_view,
            current_view: facts.current_view_v0(),
            high_qc: facts.high_qc_v0(),
            pending_timeout_certificate_id: facts.pending_timeout_certificate_id_v0(),
            finalized_block_id: facts.finalized_block_id_v0(),
            finalized_height: facts.finalized_height_v0(),
            finalized_chain_root: facts.finalized_chain_root_v0(),
            application_applied_block_id: facts.application_applied_block_id_v0(),
            application_applied_height: facts.application_applied_height_v0(),
            proposal_parent_block_id: facts.proposal_parent_block_id_v0(),
            proposal_parent_height: facts.proposal_parent_height_v0(),
            application_state_root: checkpoint.fields().application_state_root,
            safety_revision: facts.safety_revision_v0(),
            safety_record_checksum: facts.safety_record_checksum_v0(),
            safety_chain_checksum: facts.safety_chain_checksum_v0(),
            signer_exact_watermark: facts.signer_exact_watermark_v0(),
            signer_watermark_sequence: facts.signer_exact_watermark_v0().sequence(),
            authenticated_signer_inventory_digest: signer_lifetime.authenticated_inventory_digest,
            checkpoint_generation: checkpoint.generation(),
            checkpoint_canonical_sha256: Sha256::digest(checkpoint.encode_canonical()).into(),
        }
    }

    pub const fn local_validator_v0(self) -> ValidatorId {
        self.local_validator
    }

    pub const fn phase_v0(self) -> PocoNodeLabAuthorityPhaseV0 {
        self.phase
    }

    pub const fn capacity_preflight_v0(self) -> ContinuousRuntimeCapacityPreflightV0 {
        self.capacity_preflight
    }

    pub const fn signed_vote_intents_v0(self) -> u64 {
        self.signed_vote_intents
    }

    pub const fn signed_timeout_intents_v0(self) -> u64 {
        self.signed_timeout_intents
    }

    pub const fn minimum_retained_view_v0(self) -> View {
        self.minimum_retained_view
    }

    pub const fn current_view_v0(self) -> View {
        self.current_view
    }

    pub const fn high_qc_v0(self) -> QcRef {
        self.high_qc
    }

    pub const fn pending_timeout_certificate_id_v0(self) -> Option<CertificateId> {
        self.pending_timeout_certificate_id
    }

    pub const fn finalized_block_id_v0(self) -> BlockId {
        self.finalized_block_id
    }

    pub const fn finalized_height_v0(self) -> u64 {
        self.finalized_height
    }

    pub const fn finalized_chain_root_v0(self) -> [u8; 32] {
        self.finalized_chain_root
    }

    pub const fn application_applied_block_id_v0(self) -> BlockId {
        self.application_applied_block_id
    }

    pub const fn application_applied_height_v0(self) -> u64 {
        self.application_applied_height
    }

    pub const fn proposal_parent_block_id_v0(self) -> BlockId {
        self.proposal_parent_block_id
    }

    pub const fn proposal_parent_height_v0(self) -> u64 {
        self.proposal_parent_height
    }

    pub const fn application_state_root_v0(self) -> StateRoot {
        self.application_state_root
    }

    pub const fn safety_revision_v0(self) -> u64 {
        self.safety_revision
    }

    pub const fn safety_record_checksum_v0(self) -> [u8; 32] {
        self.safety_record_checksum
    }

    pub const fn safety_chain_checksum_v0(self) -> [u8; 32] {
        self.safety_chain_checksum
    }

    pub const fn signer_watermark_sequence_v0(self) -> u64 {
        self.signer_watermark_sequence
    }

    pub const fn signer_exact_watermark_v1(
        self,
    ) -> trnm_consensus_signer_journal::SignerWatermarkV0 {
        self.signer_exact_watermark
    }

    /// Last owner-authenticated inventory digest observed while the Node
    /// authority was Ready. Restart quiescence refreshes it immediately before
    /// use; signed intermediate phases may retain the preceding Ready digest.
    pub const fn authenticated_signer_inventory_digest_v1(self) -> [u8; 32] {
        self.authenticated_signer_inventory_digest
    }

    pub const fn checkpoint_generation_v0(self) -> u64 {
        self.checkpoint_generation
    }

    pub const fn checkpoint_canonical_sha256_v1(self) -> [u8; 32] {
        self.checkpoint_canonical_sha256
    }

    fn same_chain_cut_v0(self, other: Self) -> bool {
        // `local_validator`, Safety record checksum, and Safety chain checksum
        // are validator-local durable identities. They must be nonzero and
        // freshly verified on every owner, but honest validators at the same
        // consensus/application cut are neither expected nor permitted to
        // share those byte identities.
        self.phase == other.phase
            && self.capacity_preflight == other.capacity_preflight
            && self.signed_vote_intents == other.signed_vote_intents
            && self.signed_timeout_intents == other.signed_timeout_intents
            && self.minimum_retained_view == other.minimum_retained_view
            && self.current_view == other.current_view
            && self.high_qc == other.high_qc
            && self.pending_timeout_certificate_id == other.pending_timeout_certificate_id
            && self.finalized_block_id == other.finalized_block_id
            && self.finalized_height == other.finalized_height
            && self.finalized_chain_root == other.finalized_chain_root
            && self.application_applied_block_id == other.application_applied_block_id
            && self.application_applied_height == other.application_applied_height
            && self.proposal_parent_block_id == other.proposal_parent_block_id
            && self.proposal_parent_height == other.proposal_parent_height
            && self.application_state_root == other.application_state_root
            && self.safety_revision == other.safety_revision
            && self.signer_watermark_sequence == other.signer_watermark_sequence
            && self.checkpoint_generation == other.checkpoint_generation
    }
}

/// Result of one deterministic all-validator proposal/Vote/QC round.
#[derive(Debug, Clone)]
pub struct ContinuousDeterministicRoundV0 {
    quorum_certificate: QuorumCertificate,
    common_cut: ContinuousRuntimeFactsV0,
}

impl ContinuousDeterministicRoundV0 {
    pub const fn quorum_certificate_v0(&self) -> &QuorumCertificate {
        &self.quorum_certificate
    }

    pub const fn common_cut_v0(&self) -> ContinuousRuntimeFactsV0 {
        self.common_cut
    }
}

/// Deterministically drives one proposal through all supplied real authority
/// owners, builds a strict QC with the existing bounded collector, and checks
/// that every ready owner reaches one common finality/application cut.
///
/// This is intentionally process-local and performs no socket I/O.
pub fn drive_deterministic_authority_round_v0(
    authorities: &mut [ContinuousValidatorAuthorityV0],
    proposal: SignedProposalV0,
) -> Result<ContinuousDeterministicRoundV0> {
    let first = authorities
        .first()
        .ok_or_else(|| anyhow!("deterministic authority harness is empty"))?;
    let validator_set = first.validator_set.clone();
    ensure!(
        authorities.len() == validator_set.validators().len(),
        "deterministic harness does not own the complete validator set"
    );
    for (authority, validator) in authorities.iter().zip(validator_set.validators()) {
        ensure!(
            authority.local_validator == validator.id()
                && authority.validator_set == validator_set
                && authority.consensus_parameters == *first.consensus_parameters_v0(),
            "deterministic authority owners are not in canonical validator-set order"
        );
    }
    let coordinate = proposal.block().header();
    let mut collector = ConsensusCertificateCollectorV0::new(
        validator_set.clone(),
        MAXIMUM_COLLECTOR_COORDINATES_V0,
    )
    .map_err(|error| anyhow!("construct continuous QC collector: {error}"))?;
    let mut votes = Vec::with_capacity(authorities.len());
    for authority in authorities.iter_mut() {
        votes.push(authority.vote_proposal_v0(proposal.clone())?);
    }
    let mut certificate = None;
    for vote in votes {
        collector
            .admit_vote(vote)
            .map_err(|error| anyhow!("admit continuous Vote: {error}"))?;
        certificate = collector
            .try_quorum_certificate(coordinate.view(), coordinate.height(), coordinate.id())
            .map_err(|error| anyhow!("form continuous QC: {error}"))?;
        if certificate.is_some() {
            break;
        }
    }
    let certificate =
        certificate.ok_or_else(|| anyhow!("complete validator set did not form a QC"))?;
    let mut common: Option<ContinuousRuntimeFactsV0> = None;
    for authority in authorities.iter_mut() {
        let facts = authority.advance_quorum_certificate_v0(certificate.clone())?;
        if let Some(expected) = common {
            ensure!(
                expected.same_chain_cut_v0(facts),
                "continuous authorities diverged after the same QC"
            );
        } else {
            common = Some(facts);
        }
    }
    Ok(ContinuousDeterministicRoundV0 {
        quorum_certificate: certificate,
        common_cut: common.expect("non-empty authority set checked"),
    })
}

fn drain_finalizations_v0(
    mut advance: PocoNodeLabCertificateAdvanceV0<LabFileWatermark>,
) -> Result<Box<LabRuntimeV0>> {
    loop {
        match advance {
            PocoNodeLabCertificateAdvanceV0::Ready(runtime) => return Ok(runtime),
            PocoNodeLabCertificateAdvanceV0::PendingFinalization(owner) => {
                advance = owner
                    .apply_and_ack_finalization_v0()
                    .map_err(|error| anyhow!("apply exact continuous finalization: {error}"))?;
            }
        }
    }
}

#[cfg(test)]
struct FreshAuthorityPathsV0 {
    safety_store: PathBuf,
    application_store: PathBuf,
    signer_store: PathBuf,
    checkpoint_store: PathBuf,
    proposal_store: PathBuf,
    external_watermark: PathBuf,
}

#[cfg(test)]
fn create_fresh_authority_tree_v0(authority_root: &Path) -> Result<FreshAuthorityPathsV0> {
    ensure!(
        authority_root.is_absolute() && authority_root.file_name().is_some(),
        "continuous authority root must be an absolute child path"
    );
    match fs::symlink_metadata(authority_root) {
        Ok(_) => bail!("continuous authority root already exists"),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error).context("inspect continuous authority root"),
    }
    let supplied_parent = authority_root
        .parent()
        .ok_or_else(|| anyhow!("continuous authority root lacks a parent"))?;
    let parent =
        fs::canonicalize(supplied_parent).context("canonicalize continuous authority parent")?;
    let parent_metadata =
        fs::symlink_metadata(&parent).context("inspect continuous authority parent")?;
    ensure!(
        parent_metadata.is_dir()
            && !parent_metadata.file_type().is_symlink()
            && parent_metadata.permissions().mode() & 0o077 == 0,
        "continuous authority parent is not one private canonical directory"
    );
    let root = parent.join(
        authority_root
            .file_name()
            .expect("absolute child path checked"),
    );
    ensure!(
        root == authority_root,
        "continuous authority root is not canonical"
    );
    create_private_directory_v0(&root)?;
    let root = fs::canonicalize(&root).context("canonicalize new continuous authority root")?;
    let mut stores = Vec::with_capacity(6);
    for name in [
        "safety",
        "application",
        "signer",
        "checkpoint",
        "proposal",
        "watermark",
    ] {
        let path = root.join(name);
        create_private_directory_v0(&path)?;
        stores.push(path);
    }
    Ok(FreshAuthorityPathsV0 {
        safety_store: stores[0].join("safety.sqlite3"),
        application_store: stores[1].join("application.sqlite3"),
        signer_store: stores[2].join("signer.sqlite3"),
        checkpoint_store: stores[3].join("checkpoint.sqlite3"),
        proposal_store: stores[4].join("proposal.sqlite3"),
        external_watermark: stores[5].join("signer-watermark.v1"),
    })
}

#[cfg(test)]
fn create_private_directory_v0(path: &Path) -> Result<()> {
    let mut builder = fs::DirBuilder::new();
    builder.mode(0o700);
    builder
        .create(path)
        .with_context(|| format!("create private authority directory {}", path.display()))?;
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("inspect private authority directory {}", path.display()))?;
    ensure!(
        metadata.is_dir()
            && !metadata.file_type().is_symlink()
            && metadata.permissions().mode() & 0o777 == 0o700,
        "new continuous authority directory is not exactly 0700"
    );
    Ok(())
}

#[cfg(test)]
fn authority_hash_v0(domain: &[u8], local_validator: ValidatorId, binding: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update((domain.len() as u64).to_be_bytes());
    hasher.update(domain);
    hasher.update(local_validator.as_bytes());
    hasher.update((binding.len() as u64).to_be_bytes());
    hasher.update(binding);
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use std::{
        collections::BTreeMap,
        fs,
        net::TcpListener,
        os::unix::{
            fs::{FileTypeExt, PermissionsExt},
            net::UnixListener,
        },
        sync::{
            atomic::{AtomicUsize, Ordering},
            mpsc, Arc, Mutex,
        },
        thread,
        time::{Duration, Instant},
    };

    use tempfile::TempDir;
    use trnm_consensus_external_watermark::{
        serve_connection, ExternalWatermarkAuthority, UnixWatermarkClient,
    };
    use trnm_consensus_remote_signer_protocol::{
        ProcessGenerationV1, RemoteSignerCheckpointWitnessV1, RemoteSignerClientProfileRefV1,
        RemoteSignerLeaseIdV1, RemoteSignerRequestBindingV1, RemoteSignerRoleProfileRefV1,
        RemoteSignerServiceProfileRefV1,
    };
    use trnm_consensus_remote_signer_service::{
        PurposePolicyV1, RemoteSignerService, RemoteSignerServiceConfig,
    };
    use trnm_consensus_types::{
        ChainId, ConsensusPublicKey, Epoch, GenesisHash, ProtocolVersion, SigningRoot, Validator,
        VotingPower,
    };
    use trnm_consensus_unix_remote_signer::{
        UnixRemoteSignerError, UnixRemoteSignerProducer, UnixRemoteSignerProducerConfig,
    };
    use trnm_native_execution_v0::{
        AuthorizedSignerV0, CanonicalLabNativeApplicationConfigInputsV0, NativeApplicationConfigV0,
    };
    use trnm_poco_node::commission_native_h1_ordinary_lab_test_bundle_v0;

    use super::*;
    use crate::{
        consensus_mesh::{
            MeshFixtureConfigV1, MeshIngressEventV0, PersistentAuthenticatedPeerMeshV0,
        },
        frame::FrameKind,
        key_roles::{ValidatorKeyRoleBindingV1, ValidatorKeyRoleRegistryV1},
        p2p_admission::{PeerAdmissionContextV1, TestExternalPeerLeaseAuthorityV1},
        relay::{ConsensusRelayEnvelopeV0, ConsensusRelayErrorV0},
        transport::RunTransportContext,
        wire::{encode_timeout_vote, encode_vote},
        workload_corpus::{build_public_workload_corpus_v1, VerifiedWorkloadCorpusV1},
    };

    const PROPOSED_BLOCKS: u64 = 6;
    const REQUIRED_FINALIZED_BLOCKS: u64 = 4;

    struct CountingSignatureProducerV0 {
        inner: LabEd25519SignatureProducer,
        calls: Arc<AtomicUsize>,
    }

    impl SignatureProducerV0 for CountingSignatureProducerV0 {
        fn sign(
            &mut self,
            request: trnm_consensus_signer_journal::SignatureRequestV0<'_>,
        ) -> std::result::Result<
            SignatureBytes,
            trnm_consensus_signer_journal::SignatureProducerErrorV0,
        > {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.inner.sign(request)
        }
    }

    /// Test-only wrapper that proves the continuous authority hands the exact
    /// Core-produced intent to the Unix transport producer.  Capturing the
    /// immutable intent also lets the test issue an exact duplicate after the
    /// remote service has been restarted, without reconstructing a request
    /// from guessed SafetyState revisions.
    struct CapturingUnixRemoteSignerProducerV0 {
        inner: UnixRemoteSignerProducer,
        requests: Arc<Mutex<Vec<trnm_consensus_types::CanonicalSignIntentV0>>>,
    }

    impl SignatureProducerV0 for CapturingUnixRemoteSignerProducerV0 {
        fn sign(
            &mut self,
            request: trnm_consensus_signer_journal::SignatureRequestV0<'_>,
        ) -> std::result::Result<
            SignatureBytes,
            trnm_consensus_signer_journal::SignatureProducerErrorV0,
        > {
            self.requests
                .lock()
                .expect("remote signer capture mutex")
                .push(request.intent().clone());
            self.inner.sign(request)
        }
    }

    struct CapturingProposalProducerV0 {
        key: SigningKey,
        request: Option<ProposalSignatureRequestV0>,
    }

    impl ProposalSignatureProducerV0 for CapturingProposalProducerV0 {
        fn sign_proposal(
            &mut self,
            request: ProposalSignatureRequestV0,
        ) -> std::result::Result<
            SignatureBytes,
            trnm_consensus_signer_journal::SignatureProducerErrorV0,
        > {
            if self.key.verifying_key().to_bytes() != request.expected_consensus_public_key() {
                return Err(trnm_consensus_signer_journal::SignatureProducerErrorV0::Rejected);
            }
            self.request = Some(request);
            Ok(SignatureBytes::from_array(
                self.key.sign(request.signing_root().as_bytes()).to_bytes(),
            ))
        }
    }

    struct WrongRootProposalProducerV0 {
        key: SigningKey,
    }

    impl ProposalSignatureProducerV0 for WrongRootProposalProducerV0 {
        fn sign_proposal(
            &mut self,
            _request: ProposalSignatureRequestV0,
        ) -> std::result::Result<
            SignatureBytes,
            trnm_consensus_signer_journal::SignatureProducerErrorV0,
        > {
            Ok(SignatureBytes::from_array(
                self.key
                    .sign(SigningRoot::new([0xa5; 32]).as_bytes())
                    .to_bytes(),
            ))
        }
    }

    #[derive(Clone, Default)]
    struct CountingExternalWatermarkV0 {
        state: Arc<Mutex<Option<trnm_consensus_signer_journal::SignerWatermarkV0>>>,
    }

    impl CountingExternalWatermarkV0 {
        fn current(&self) -> Option<trnm_consensus_signer_journal::SignerWatermarkV0> {
            *self.state.lock().expect("external watermark mutex")
        }
    }

    impl ExternalMonotonicWatermarkV0 for CountingExternalWatermarkV0 {
        fn load(
            &mut self,
            scope: [u8; 32],
        ) -> std::result::Result<
            Option<trnm_consensus_signer_journal::SignerWatermarkV0>,
            trnm_consensus_signer_journal::ExternalWatermarkErrorV0,
        > {
            let value = *self.state.lock().expect("external watermark mutex");
            if value.is_some_and(|watermark| watermark.scope() != scope) {
                return Err(trnm_consensus_signer_journal::ExternalWatermarkErrorV0::CompareFailed);
            }
            Ok(value)
        }

        fn compare_and_advance(
            &mut self,
            expected: Option<trnm_consensus_signer_journal::SignerWatermarkV0>,
            target: trnm_consensus_signer_journal::SignerWatermarkV0,
        ) -> std::result::Result<(), trnm_consensus_signer_journal::ExternalWatermarkErrorV0>
        {
            let mut value = self.state.lock().expect("external watermark mutex");
            if *value != expected {
                return Err(trnm_consensus_signer_journal::ExternalWatermarkErrorV0::CompareFailed);
            }
            if let Some(previous) = expected {
                if previous.scope() != target.scope()
                    || previous.journal_id() != target.journal_id()
                    || previous.sequence().checked_add(1) != Some(target.sequence())
                {
                    return Err(
                        trnm_consensus_signer_journal::ExternalWatermarkErrorV0::CompareFailed,
                    );
                }
            } else if target.sequence() != 0 {
                return Err(trnm_consensus_signer_journal::ExternalWatermarkErrorV0::CompareFailed);
            }
            *value = Some(target);
            Ok(())
        }
    }

    #[test]
    fn injected_signature_producer_owns_vote_and_timeout_boundaries() {
        on_bounded_takeover_owner_stack_v0(|| {
            let mut harness = takeover_phase_harness_v0(4);
            let external = CountingExternalWatermarkV0::default();
            let external_observer = external.clone();
            harness.authorities[0]
                .install_external_monotonic_watermark_v0(Box::new(external))
                .expect("install external watermark behind the Ready journal");
            let calls = Arc::new(AtomicUsize::new(0));
            let key = harness.keys[0].clone();
            harness.authorities[0].producer =
                ContinuousSignatureProducerV0(Box::new(CountingSignatureProducerV0 {
                    inner: LabEd25519SignatureProducer::new(key),
                    calls: Arc::clone(&calls),
                }));
            let proposal = proposal_for_takeover_v0(&harness);
            harness.authorities[0]
                .vote_proposal_v0(proposal)
                .expect("injected producer signs the exact Vote intent");
            harness.authorities[0]
                .begin_local_timeout_v0()
                .expect("injected producer signs the exact TimeoutVote intent");
            assert_eq!(calls.load(Ordering::SeqCst), 2);
            assert_eq!(
                external_observer
                    .current()
                    .expect("external head after Vote and TimeoutVote")
                    .sequence(),
                4,
                "external CAS advanced for intent and signature events"
            );
        });
    }

    #[test]
    fn unix_external_watermark_fences_vote_timeout_restart_and_tamper() {
        on_bounded_takeover_owner_stack_v0(|| {
            let mut harness = takeover_phase_harness_v0(4);
            let authority_dir = harness._temp.path().join("unix-external-authority");
            create_private_directory_v0(&authority_dir)
                .expect("create private Unix external authority directory");
            let log_path = authority_dir.join("watermark.log");
            let socket_path = authority_dir.join("watermark.sock");
            let (stop, daemon) =
                spawn_unix_watermark_daemon_v0(log_path.clone(), socket_path.clone());

            let client = UnixWatermarkClient::new(&socket_path)
                .expect("construct Unix external watermark client");
            harness.authorities[0]
                .install_external_monotonic_watermark_v0(Box::new(client.clone()))
                .expect("Ready authority claims the external watermark head");
            let proposal = proposal_for_takeover_v0(&harness);
            harness.authorities[0]
                .vote_proposal_v0(proposal)
                .expect("Unix external producer boundary signs the exact Vote intent");
            harness.authorities[0]
                .begin_local_timeout_v0()
                .expect("Unix external producer boundary signs the exact TimeoutVote intent");

            let scope = harness.authorities[0]
                .facts_v0()
                .expect("read authority facts after Vote and TimeoutVote")
                .signer_exact_watermark_v1()
                .scope();
            let observed = client
                .load_checked(scope)
                .expect("read external watermark after Vote and TimeoutVote")
                .expect("external watermark has a durable head");
            assert_eq!(observed.sequence(), 4);

            stop.send(()).expect("stop first external watermark daemon");
            daemon
                .join()
                .expect("join first external watermark daemon")
                .expect("first external watermark daemon exits cleanly");
            assert!(!socket_path.exists(), "daemon cleanup removes its socket");

            // A fresh daemon process/thread must authenticate and serve the
            // exact append-only head; this is the restart boundary outside
            // the validator's local SQLite namespace.
            let (restart_stop, restart_daemon) =
                spawn_unix_watermark_daemon_v0(log_path.clone(), socket_path.clone());
            let restarted_client = UnixWatermarkClient::new(&socket_path)
                .expect("construct restarted Unix watermark client");
            let restarted = restarted_client
                .load_checked(scope)
                .expect("restarted authority serves the authenticated head")
                .expect("restarted authority retains the exact head");
            assert_eq!(restarted, observed);
            restart_stop
                .send(())
                .expect("stop restarted external watermark daemon");
            restart_daemon
                .join()
                .expect("join restarted external watermark daemon")
                .expect("restarted external watermark daemon exits cleanly");

            // Mutating a durable record must prevent a new authority from
            // serving any client.  This is deliberately a fail-stop check,
            // not a best-effort repair or a local-watermark fallback.
            let mut bytes = fs::read(&log_path).expect("read external watermark log for tamper");
            assert!(!bytes.is_empty(), "Vote/TimeoutVote produced a log record");
            bytes[0] ^= 0x01;
            fs::write(&log_path, bytes).expect("tamper external watermark log");
            let rejected = match ExternalWatermarkAuthority::open(&log_path) {
                Ok(_) => panic!("tampered external watermark log must fail closed"),
                Err(error) => error,
            };
            assert!(
                rejected.to_string().contains("rejected")
                    || rejected.to_string().contains("invalid"),
                "tampered authority failure must identify invalid persisted state: {rejected}"
            );
            assert!(
                UnixWatermarkClient::new(&socket_path)
                    .expect("construct offline client")
                    .load_checked(scope)
                    .is_err(),
                "no daemon may serve a tampered authority namespace"
            );
        });
    }

    #[test]
    fn unix_remote_signer_producer_drives_continuous_vote_timeout_restart_and_tamper() {
        on_bounded_takeover_owner_stack_v0(|| {
            let mut harness = takeover_phase_harness_v0(4);
            let remote_dir = harness._temp.path().join("unix-remote-signer-authority");
            create_private_directory_v0(&remote_dir)
                .expect("create private Unix remote signer directory");
            let watermark_path = remote_dir.join("signer.sqlite3");
            let socket_path = remote_dir.join("signer.sock");
            let author = harness.validator_set.validators()[0].id();
            let binding = RemoteSignerRequestBindingV1::new(
                &harness.validator_set,
                author,
                RemoteSignerRoleProfileRefV1::from_public_descriptor(b"lab-consensus-role")
                    .expect("remote signer role profile"),
                RemoteSignerServiceProfileRefV1::from_public_descriptor(b"lab-signer-service")
                    .expect("remote signer service profile"),
                RemoteSignerClientProfileRefV1::from_public_descriptor(b"lab-node-client")
                    .expect("remote signer client profile"),
                ProcessGenerationV1::new(1).expect("remote signer process generation"),
                RemoteSignerLeaseIdV1::from_public_grant_descriptor(b"lab-signer-lease")
                    .expect("remote signer lease"),
                RemoteSignerCheckpointWitnessV1::new(1, [0x53; 32])
                    .expect("remote signer checkpoint witness"),
            )
            .expect("construct remote signer request binding");
            let producer_config = UnixRemoteSignerProducerConfig {
                socket_path: socket_path.clone(),
                validator_set: harness.validator_set.clone(),
                author,
                signer_profile_ref: trnm_poco_node::SIGNER_JOURNAL_PROFILE_REF_V0,
                role_profile_ref: binding.role_profile_ref(),
                service_profile_ref: binding.service_profile_ref(),
                client_profile_ref: binding.client_profile_ref(),
                process_generation: binding.process_generation(),
                lease_id: binding.lease_id(),
                checkpoint_witness: binding.checkpoint_witness(),
                timeout: Duration::from_secs(2),
            };
            let producer = UnixRemoteSignerProducer::new(producer_config.clone())
                .expect("construct Unix remote signer producer");
            let mut duplicate_producer = producer.clone();
            let requests = Arc::new(Mutex::new(Vec::new()));
            harness.authorities[0].producer =
                ContinuousSignatureProducerV0(Box::new(CapturingUnixRemoteSignerProducerV0 {
                    inner: producer,
                    requests: Arc::clone(&requests),
                }));

            // A fresh service instance handles each request.  This makes the
            // durable SQLite reservation and Unix protocol boundary cross a
            // restart between Vote and Timeout rather than being hidden in a
            // long-lived in-process fixture.
            let service_handle = spawn_remote_signer_service_once_v0(
                remote_signer_service_config_v0(
                    &harness.validator_set,
                    binding,
                    &harness.keys[0],
                    &watermark_path,
                ),
                socket_path.clone(),
            );
            let proposal = proposal_for_takeover_v0(&harness);
            harness.authorities[0]
                .vote_proposal_v0(proposal)
                .expect("continuous authority Vote uses the Unix remote signer producer");
            service_handle
                .join()
                .expect("join Vote remote signer service")
                .expect("Vote remote signer service exits cleanly");

            let captured_vote = requests
                .lock()
                .expect("read captured Vote intent")
                .first()
                .cloned()
                .expect("continuous authority passed a Vote intent to Unix producer");

            // Replaying the exact immutable intent after a service restart is
            // rejected by the service's durable request fingerprint CAS.
            let duplicate_service = spawn_remote_signer_service_once_v0(
                remote_signer_service_config_v0(
                    &harness.validator_set,
                    binding,
                    &harness.keys[0],
                    &watermark_path,
                ),
                socket_path.clone(),
            );
            let duplicate_error = duplicate_producer
                .sign_intent_exact(&captured_vote)
                .expect_err("exact Vote replay must be rejected after service restart");
            assert!(matches!(
                duplicate_error,
                UnixRemoteSignerError::ServiceRejected(_)
            ));
            duplicate_service
                .join()
                .expect("join duplicate remote signer service")
                .expect("duplicate remote signer service exits cleanly");

            let timeout_service = spawn_remote_signer_service_once_v0(
                remote_signer_service_config_v0(
                    &harness.validator_set,
                    binding,
                    &harness.keys[0],
                    &watermark_path,
                ),
                socket_path.clone(),
            );
            harness.authorities[0]
                .begin_local_timeout_v0()
                .expect("continuous authority TimeoutVote uses the Unix remote signer producer");
            timeout_service
                .join()
                .expect("join TimeoutVote remote signer service")
                .expect("TimeoutVote remote signer service exits cleanly");

            let captured = requests.lock().expect("read captured signer intents");
            assert_eq!(
                captured.len(),
                2,
                "Vote and TimeoutVote each cross Unix producer"
            );
            assert!(matches!(
                captured[0].preimage(),
                trnm_consensus_types::CanonicalSignPreimageV0::Vote(_)
            ));
            assert!(matches!(
                captured[1].preimage(),
                trnm_consensus_types::CanonicalSignPreimageV0::TimeoutVote(_)
            ));
            drop(captured);

            let snapshot = RemoteSignerService::open(remote_signer_service_config_v0(
                &harness.validator_set,
                binding,
                &harness.keys[0],
                &watermark_path,
            ))
            .expect("reopen remote signer watermark after Vote and TimeoutVote")
            .watermark_snapshot()
            .expect("read remote signer watermark after restart");
            assert_eq!(snapshot.sequence, 2);

            // Corrupt the durable signer namespace.  A new service must fail
            // closed instead of silently creating a fresh watermark or using
            // a local fallback key.
            let mut bytes = fs::read(&watermark_path).expect("read remote signer database");
            assert!(!bytes.is_empty(), "remote signer database is non-empty");
            bytes[0] ^= 0x01;
            fs::write(&watermark_path, bytes).expect("tamper remote signer database");
            assert!(
                RemoteSignerService::open(remote_signer_service_config_v0(
                    &harness.validator_set,
                    binding,
                    &harness.keys[0],
                    &watermark_path,
                ))
                .is_err(),
                "tampered remote signer database must fail closed"
            );
        });
    }

    #[test]
    fn injected_proposal_producer_is_bound_to_exact_witness_identity() {
        on_bounded_takeover_owner_stack_v0(|| {
            let harness = takeover_phase_harness_v0(4);
            let view = harness
                .authorities
                .iter()
                .filter_map(|authority| authority.facts_v0().ok())
                .find(|facts| facts.phase_v0() == PocoNodeLabAuthorityPhaseV0::Ready)
                .expect("at least one ready takeover authority")
                .current_view_v0();
            let leader = leader_for(&harness.validator_set, view);
            let leader_index = harness
                .validator_set
                .validators()
                .iter()
                .position(|validator| validator.id() == leader)
                .expect("scheduled leader belongs to validator set");
            let preimage = harness.authorities[leader_index]
                .proposal_preimage_for_test_v0(
                    harness.ordinary_start_height,
                    harness.timestamp_ms,
                    harness.transactions.clone(),
                )
                .expect("leader builds exact proposal preimage");
            let profile = [0x91; 32];
            let expected_request = preimage
                .proposal_signature_request_v0(profile)
                .expect("proposal request has complete identity");
            let expected_root = expected_request.signing_root();
            let expected_block = expected_request.proposal_id();
            let expected_key = expected_request.expected_consensus_public_key();
            let mut producer = CapturingProposalProducerV0 {
                key: harness.keys[leader_index].clone(),
                request: None,
            };
            let proposal = preimage
                .seal_with_producer_v0(&mut producer, profile)
                .expect("injected producer signs and strict verifier accepts witness");
            let observed = producer.request.expect("producer observed one request");
            assert_eq!(observed.signing_root(), expected_root);
            assert_eq!(observed.proposal_id(), expected_block);
            assert_eq!(observed.author(), leader);
            assert_eq!(observed.expected_consensus_public_key(), expected_key);
            assert_eq!(observed.signer_profile_ref(), profile);
            assert_eq!(proposal.block().id(), expected_block);
        });
    }

    #[test]
    fn injected_proposal_producer_wrong_root_fails_closed() {
        on_bounded_takeover_owner_stack_v0(|| {
            let harness = takeover_phase_harness_v0(4);
            let view = harness
                .authorities
                .iter()
                .filter_map(|authority| authority.facts_v0().ok())
                .find(|facts| facts.phase_v0() == PocoNodeLabAuthorityPhaseV0::Ready)
                .expect("at least one ready takeover authority")
                .current_view_v0();
            let leader = leader_for(&harness.validator_set, view);
            let leader_index = harness
                .validator_set
                .validators()
                .iter()
                .position(|validator| validator.id() == leader)
                .expect("scheduled leader belongs to validator set");
            let preimage = harness.authorities[leader_index]
                .proposal_preimage_for_test_v0(
                    harness.ordinary_start_height,
                    harness.timestamp_ms,
                    harness.transactions.clone(),
                )
                .expect("leader builds exact proposal preimage");
            let mut producer = WrongRootProposalProducerV0 {
                key: harness.keys[leader_index].clone(),
            };
            let error = preimage
                .seal_with_producer_v0(&mut producer, [0x92; 32])
                .expect_err("wrong proposal root must fail strict verification");
            assert!(error.to_string().contains("different root or key"));
        });
    }

    #[test]
    fn protocol_violation_counters_classify_only_typed_conflicts() {
        let mut counters = ContinuousProtocolViolationCountersV0::default();
        let double_vote = anyhow::Error::new(ConsensusIngressErrorV0::VoteEquivocation)
            .context("direct Vote admission");
        counters.record_anyhow_v0(&double_vote).unwrap();
        let double_timeout = anyhow::Error::new(ConsensusIngressErrorV0::TimeoutEquivocation)
            .context("direct TimeoutVote admission");
        counters.record_anyhow_v0(&double_timeout).unwrap();
        let conflicting_certificate = anyhow::Error::new(ConsensusRelayIngressErrorV0::Consensus(
            ConsensusIngressErrorV0::ConflictingQcReference(CertificateId::new([0x41; 32])),
        ))
        .context("relay certificate admission");
        counters.record_anyhow_v0(&conflicting_certificate).unwrap();
        let exact_replay = anyhow::Error::new(ConsensusIngressErrorV0::StaleView)
            .context("non-violation admission rejection");
        counters.record_anyhow_v0(&exact_replay).unwrap();

        assert_eq!(counters.double_vote_count_v0(), 1);
        assert_eq!(counters.double_timeout_count_v0(), 1);
        assert_eq!(counters.conflicting_certificate_count_v0(), 1);
    }

    #[test]
    fn process_one_continuous_state_starts_from_fresh_authenticated_empty_inventory() {
        let mut harness = fresh_test_harness_v0(4, 1);
        for authority in &mut harness.authorities {
            let inventory = authority
                .fresh_ready_signer_inventory_v1()
                .expect("fresh process-one inventory is owner-authenticated");
            assert_eq!(inventory.durable_vote_intent_count_v1(), 0);
            assert_eq!(inventory.durable_timeout_intent_count_v1(), 0);
            assert_eq!(inventory.signed_vote_intent_count_v1(), 0);
            assert_eq!(inventory.signed_timeout_intent_count_v1(), 0);
            assert_eq!(inventory.exact_watermark_v1().sequence(), 0);
            assert_ne!(inventory.inventory_digest_v1(), [0; 32]);
            assert_ne!(inventory.checkpoint_canonical_sha256_v1(), [0; 32]);
            assert_eq!(
                authority
                    .facts_v0()
                    .expect("fresh process-one facts")
                    .authenticated_signer_inventory_digest_v1(),
                inventory.inventory_digest_v1()
            );
        }
    }

    #[test]
    fn fresh_ready_inventory_rejects_stale_process_local_signer_counter() {
        let mut harness = fresh_test_harness_v0(4, 1);
        harness.authorities[0].signer_lifetime.signed_vote_intents = 1;
        let rejection = harness.authorities[0]
            .fresh_ready_signer_inventory_v1()
            .expect_err("fresh empty signer inventory must reject a stale in-memory Vote count");
        assert!(rejection.to_string().contains("counters"));
    }

    #[test]
    fn restart_parked_authority_consumes_ready_owner_with_fresh_comparison_facts() {
        let mut harness = fresh_test_harness_v0(4, 1);
        let authority = harness.authorities.remove(0);
        let expected = authority
            .facts_v0()
            .expect("project pre-park Ready comparison facts");
        let parked = authority
            .into_restart_parked_authority_v1()
            .expect("consume exact Ready authority into restart park");

        assert_eq!(parked.facts_v1(), expected);
        assert_eq!(
            parked.facts_v1().phase_v0(),
            PocoNodeLabAuthorityPhaseV0::Ready
        );
        assert!(parked
            .facts_v1()
            .pending_timeout_certificate_id_v0()
            .is_none());
        assert_ne!(
            parked.facts_v1().authenticated_signer_inventory_digest_v1(),
            [0; 32]
        );
    }

    #[test]
    fn restart_parked_authority_rejects_signed_intermediate_phase() {
        let mut harness = fresh_test_harness_v0(4, 1);
        let mut authority = harness.authorities.remove(0);
        authority
            .begin_local_timeout_v0()
            .expect("enter a signed TimeoutVote intermediate phase");

        let rejection = authority
            .into_restart_parked_authority_v1()
            .expect_err("restart park must consume only the exact Ready phase");
        assert!(rejection.to_string().contains("Ready authority"));
    }

    #[test]
    fn restart_parked_authority_rejects_stale_signer_accounting() {
        let mut harness = fresh_test_harness_v0(4, 1);
        let mut authority = harness.authorities.remove(0);
        authority.signer_lifetime.signed_vote_intents = 1;

        let rejection = authority
            .into_restart_parked_authority_v1()
            .expect_err("restart park must freshly join exact signer accounting");
        assert!(rejection.to_string().contains("counters"));
    }

    fn private_temp_v0() -> TempDir {
        let temp = tempfile::tempdir().expect("create continuous-runtime test root");
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700))
            .expect("make continuous-runtime test root private");
        temp
    }

    /// Starts a bounded Unix daemon thread around the real external
    /// watermark authority.  The production `serve_unix` loop intentionally
    /// has process lifetime semantics and no shutdown API; this test harness
    /// keeps the same socket/framing/authority implementation while adding a
    /// private stop channel so it can prove a clean restart against one log.
    fn spawn_unix_watermark_daemon_v0(
        log_path: PathBuf,
        socket_path: PathBuf,
    ) -> (
        mpsc::Sender<()>,
        thread::JoinHandle<std::result::Result<(), String>>,
    ) {
        let (stop_sender, stop_receiver) = mpsc::channel::<()>();
        let (ready_sender, ready_receiver) =
            mpsc::sync_channel::<std::result::Result<(), String>>(1);
        let daemon = thread::Builder::new()
            .name("trnm-external-watermark-daemon-test".to_owned())
            .spawn(move || {
                let mut authority = match ExternalWatermarkAuthority::open(&log_path) {
                    Ok(authority) => authority,
                    Err(error) => {
                        let message = error.to_string();
                        let _ = ready_sender.send(Err(message.clone()));
                        return Err(message);
                    }
                };
                let _ = fs::remove_file(&socket_path);
                let listener = match UnixListener::bind(&socket_path) {
                    Ok(listener) => listener,
                    Err(error) => {
                        let message = format!("bind test authority socket: {error}");
                        let _ = ready_sender.send(Err(message.clone()));
                        return Err(message);
                    }
                };
                if let Err(error) =
                    fs::set_permissions(&socket_path, fs::Permissions::from_mode(0o600))
                {
                    let message = format!("protect test authority socket: {error}");
                    let _ = ready_sender.send(Err(message.clone()));
                    return Err(message);
                }
                listener
                    .set_nonblocking(true)
                    .map_err(|error| format!("set test authority nonblocking: {error}"))?;
                ready_sender
                    .send(Ok(()))
                    .map_err(|_| "test authority readiness receiver dropped".to_owned())?;
                loop {
                    match stop_receiver.try_recv() {
                        Ok(()) | Err(mpsc::TryRecvError::Disconnected) => break,
                        Err(mpsc::TryRecvError::Empty) => {}
                    }
                    match listener.accept() {
                        Ok((stream, _)) => serve_connection(&mut authority, stream)
                            .map_err(|error| format!("serve test authority request: {error}"))?,
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            thread::sleep(Duration::from_millis(2));
                        }
                        Err(error) => {
                            return Err(format!("accept test authority connection: {error}"));
                        }
                    }
                }
                drop(listener);
                let _ = fs::remove_file(&socket_path);
                Ok(())
            })
            .expect("spawn external watermark daemon thread");
        match ready_receiver
            .recv_timeout(Duration::from_secs(5))
            .expect("external watermark daemon readiness")
        {
            Ok(()) => (stop_sender, daemon),
            Err(error) => {
                let _ = daemon.join();
                panic!("external watermark daemon failed to start: {error}");
            }
        }
    }

    fn remote_signer_service_config_v0(
        validator_set: &ValidatorSet,
        binding: RemoteSignerRequestBindingV1,
        signing_key: &SigningKey,
        watermark_path: &Path,
    ) -> RemoteSignerServiceConfig {
        RemoteSignerServiceConfig {
            validator_set: validator_set.clone(),
            binding,
            signing_key: signing_key.clone(),
            watermark_path: watermark_path.to_path_buf(),
            purpose_policy: PurposePolicyV1::both(),
        }
    }

    fn wait_for_remote_signer_socket_v0(path: &Path) {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if let Ok(metadata) = fs::symlink_metadata(path) {
                if metadata.file_type().is_socket() && metadata.permissions().mode() & 0o077 == 0 {
                    return;
                }
            }
            assert!(
                Instant::now() < deadline,
                "remote signer Unix socket did not become ready: {}",
                path.display()
            );
            thread::sleep(Duration::from_millis(2));
        }
    }

    fn spawn_remote_signer_service_once_v0(
        config: RemoteSignerServiceConfig,
        socket_path: PathBuf,
    ) -> thread::JoinHandle<std::result::Result<(), String>> {
        let mut service =
            RemoteSignerService::open(config).expect("open remote signer service fixture");
        let socket_for_thread = socket_path.clone();
        let handle = thread::Builder::new()
            .name("trnm-remote-signer-service-test".to_owned())
            .spawn(move || {
                service
                    .serve_unix_once(&socket_for_thread)
                    .map_err(|error| error.to_string())
            })
            .expect("spawn remote signer service fixture");
        wait_for_remote_signer_socket_v0(&socket_path);
        handle
    }

    fn on_bounded_takeover_owner_stack_v0<T: Send + 'static>(
        body: impl FnOnce() -> T + Send + 'static,
    ) -> T {
        let owner = std::thread::Builder::new()
            .name("poco-takeover-owner-test".to_owned())
            .stack_size(CONTINUOUS_RUNTIME_OWNER_STACK_BYTES_V0)
            .spawn(body)
            .expect("spawn bounded native takeover owner test thread");
        match owner.join() {
            Ok(value) => value,
            Err(panic) => std::panic::resume_unwind(panic),
        }
    }

    fn decode_hash32_v0(value: &str) -> [u8; 32] {
        let bytes = hex::decode(value).expect("decode test hash");
        bytes.try_into().expect("test hash is exactly 32 bytes")
    }

    fn fixture_validator_set_v0(
        validator_count: usize,
    ) -> (ValidatorSet, ConsensusParametersV0, Vec<SigningKey>) {
        let parameters = ConsensusParametersV0::reference_shadow_v0();
        let keys = (0..validator_count)
            .map(|index| {
                let marker = u8::try_from(index + 31).expect("bounded validator marker");
                SigningKey::from_bytes(&[marker; 32])
            })
            .collect::<Vec<_>>();
        let validators = keys
            .iter()
            .enumerate()
            .map(|(index, key)| {
                let id_marker = u8::try_from(index + 1).expect("bounded validator ID marker");
                Validator::new(
                    ValidatorId::new([id_marker; 32]),
                    ConsensusPublicKey::new(key.verifying_key().to_bytes()),
                    VotingPower::new(1).expect("positive equal voting power"),
                )
                .expect("valid deterministic validator")
            })
            .collect::<Vec<_>>();
        let chain_name = format!("trnm-g3-continuous-{validator_count}");
        let chain = ChainId::new(&chain_name).expect("valid deterministic chain ID");
        let genesis_marker =
            u8::try_from(0x70 + validator_count).expect("bounded deterministic genesis marker");
        let validator_set = ValidatorSet::new(
            GenesisHash::new([genesis_marker; 32]),
            chain,
            ProtocolVersion::V0,
            Epoch::new(0),
            parameters.hash(),
            validators,
        )
        .expect("valid deterministic validator set");
        (validator_set, parameters, keys)
    }

    struct TestHarnessV0 {
        validator_set: ValidatorSet,
        parameters: ConsensusParametersV0,
        keys: Vec<SigningKey>,
        corpus: VerifiedWorkloadCorpusV1,
        authorities: Vec<ContinuousValidatorAuthorityV0>,
        _temp: TempDir,
    }

    struct TakeoverPhaseHarnessV0 {
        validator_set: ValidatorSet,
        keys: Vec<SigningKey>,
        ordinary_start_height: u64,
        timestamp_ms: u64,
        transactions: Vec<Vec<u8>>,
        workloads: Vec<(u64, u64, Vec<Vec<u8>>)>,
        authorities: Vec<ContinuousValidatorAuthorityV0>,
        _temp: TempDir,
    }

    struct CommissionedTakeoverHarnessAuthorityV0 {
        validator_set: ValidatorSet,
        parameters: ConsensusParametersV0,
        ordinary_start_height: u64,
        workloads: Vec<(u64, u64, Vec<Vec<u8>>)>,
        signing_key: SigningKey,
        authority: ContinuousValidatorAuthorityV0,
    }

    fn commission_takeover_harness_authority_v0(
        authority_root: PathBuf,
        watermark_root: PathBuf,
        validator_count: usize,
        validator_index: usize,
        signer_lifetime: ContinuousSignerLifetimeBoundsV0,
        proposed_blocks: u64,
    ) -> CommissionedTakeoverHarnessAuthorityV0 {
        create_private_directory_v0(&authority_root)
            .expect("create empty private takeover authority root");
        create_private_directory_v0(&watermark_root)
            .expect("create private takeover watermark root");
        let watermark = LabFileWatermark::open(watermark_root.join("signer-watermark.v1"))
            .expect("open takeover signer watermark");
        let bundle = commission_native_h1_ordinary_lab_test_bundle_v0(
            &authority_root,
            watermark,
            validator_count,
            validator_index,
        )
        .expect("commission exact native h1-h3 takeover fixture");
        let ordinary_start_height = bundle.ordinary_start_height_v0();
        let workloads = (0..proposed_blocks)
            .map(|offset| {
                let height = ordinary_start_height
                    .checked_add(offset)
                    .expect("bounded takeover workload height");
                let timestamp_ms = 400_u64
                    .checked_add(
                        offset
                            .checked_mul(100)
                            .expect("bounded takeover timestamp delta"),
                    )
                    .expect("bounded takeover workload timestamp");
                let transactions = bundle
                    .ordinary_transactions_v0(height, timestamp_ms)
                    .expect("author policy-compatible ordinary transaction");
                (height, timestamp_ms, transactions)
            })
            .collect::<Vec<_>>();
        let validator_set = bundle.validator_set_v0().clone();
        let parameters = *bundle.consensus_parameters_v0();
        let (local, set, consensus_parameters, signing_key, start, runtime) =
            bundle.into_continuous_runtime_parts_v0();
        let authority = ContinuousValidatorAuthorityV0::from_takeover_parts_v0(
            local,
            set,
            consensus_parameters,
            signing_key.clone(),
            start,
            runtime,
            signer_lifetime,
        )
        .expect("join takeover runtime to continuous authority");
        CommissionedTakeoverHarnessAuthorityV0 {
            validator_set,
            parameters,
            ordinary_start_height,
            workloads,
            signing_key,
            authority,
        }
    }

    fn takeover_phase_harness_v0(validator_count: usize) -> TakeoverPhaseHarnessV0 {
        let signer_lifetime =
            ContinuousSignerLifetimeBoundsV0::from_exact_test_bounds_v0(1, 1, 2, 1)
                .expect("bound focused takeover signer lifetime");
        takeover_phase_harness_with_profile_v0(validator_count, signer_lifetime, 1)
    }

    fn takeover_phase_harness_with_signer_lifetime_v0(
        validator_count: usize,
        signer_lifetime: ContinuousSignerLifetimeBoundsV0,
    ) -> TakeoverPhaseHarnessV0 {
        takeover_phase_harness_with_profile_v0(validator_count, signer_lifetime, 1)
    }

    fn takeover_phase_harness_with_profile_v0(
        validator_count: usize,
        signer_lifetime: ContinuousSignerLifetimeBoundsV0,
        proposed_blocks: u64,
    ) -> TakeoverPhaseHarnessV0 {
        let temp = private_temp_v0();
        let mut validator_set = None;
        let mut parameters = None;
        let mut ordinary_start_height = None;
        let mut workloads = None;
        let mut keys = Vec::with_capacity(validator_count);
        let mut authorities = Vec::with_capacity(validator_count);
        let handles = (0..validator_count)
            .map(|index| {
                let authority_root = temp.path().join(format!("takeover-authority-{index:03}"));
                let watermark_root = temp.path().join(format!("takeover-watermark-{index:03}"));
                thread::Builder::new()
                    .name(format!("poco-takeover-commission-{index:03}"))
                    .stack_size(CONTINUOUS_RUNTIME_OWNER_STACK_BYTES_V0)
                    .spawn(move || {
                        commission_takeover_harness_authority_v0(
                            authority_root,
                            watermark_root,
                            validator_count,
                            index,
                            signer_lifetime,
                            proposed_blocks,
                        )
                    })
                    .expect("spawn bounded takeover commissioning thread")
            })
            .collect::<Vec<_>>();

        for handle in handles {
            let commissioned = handle
                .join()
                .unwrap_or_else(|panic| std::panic::resume_unwind(panic));
            if let Some(expected) = validator_set.as_ref() {
                assert_eq!(&commissioned.validator_set, expected);
                assert_eq!(commissioned.parameters, parameters.unwrap());
                assert_eq!(
                    Some(commissioned.ordinary_start_height),
                    ordinary_start_height
                );
                assert_eq!(Some(&commissioned.workloads), workloads.as_ref());
            } else {
                validator_set = Some(commissioned.validator_set.clone());
                parameters = Some(commissioned.parameters);
                ordinary_start_height = Some(commissioned.ordinary_start_height);
                workloads = Some(commissioned.workloads.clone());
            }
            keys.push(commissioned.signing_key);
            authorities.push(commissioned.authority);
        }

        let workloads = workloads.expect("takeover ordinary workloads");
        let (_, timestamp_ms, transactions) = workloads
            .first()
            .expect("takeover profile has one ordinary workload")
            .clone();
        TakeoverPhaseHarnessV0 {
            validator_set: validator_set.expect("takeover validator set"),
            keys,
            ordinary_start_height: ordinary_start_height.expect("takeover ordinary start"),
            timestamp_ms,
            transactions,
            workloads,
            authorities,
            _temp: temp,
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn commission_test_authority_v0(
        validator_set: &ValidatorSet,
        parameters: ConsensusParametersV0,
        keys: &[SigningKey],
        application_signers: &[AuthorizedSignerV0],
        governance_signer_id: &str,
        run_id: &str,
        validator_index: usize,
        authority_root: &Path,
        signer_lifetime: ContinuousSignerLifetimeBoundsV0,
    ) -> ContinuousValidatorAuthorityV0 {
        let validator = &validator_set.validators()[validator_index];
        let core_config = CoreConfig::new(
            validator.id(),
            validator_set.clone(),
            parameters,
            0,
            64,
            1_024,
        )
        .expect("construct real Core config");
        let application_config = NativeApplicationConfigV0::from_canonical_lab_inputs_v0(
            CanonicalLabNativeApplicationConfigInputsV0::new(
                run_id.to_owned(),
                [0x81; 32],
                [0x82; 32],
                [0x83; 32],
                [0x84; 32],
                validator.id(),
                validator_set.clone(),
                parameters,
                application_signers.to_vec(),
                governance_signer_id.to_owned(),
            )
            .expect("construct canonical native application inputs"),
        )
        .expect("derive canonical native application config");
        ContinuousValidatorAuthorityV0::initialize_from_parts_v0(
            core_config,
            application_config,
            keys[validator_index].clone(),
            authority_root,
            signer_lifetime,
        )
        .expect("commission fresh real authority")
    }

    fn fresh_test_harness_v0(validator_count: usize, proposed_blocks: u64) -> TestHarnessV0 {
        let temp = private_temp_v0();
        let (validator_set, parameters, keys) = fixture_validator_set_v0(validator_count);
        let corpus_path = temp.path().join("workload.corpus");
        let policy_path = temp.path().join("workload-policy.json");
        let summary = build_public_workload_corpus_v1(
            validator_set.chain_id().as_str(),
            proposed_blocks,
            &corpus_path,
            &policy_path,
        )
        .expect("build real pre-signed workload corpus");
        let consensus_keys = validator_set
            .validators()
            .iter()
            .map(|validator| validator.consensus_key().into_bytes())
            .collect::<Vec<_>>();
        let corpus = VerifiedWorkloadCorpusV1::load(
            &corpus_path,
            &policy_path,
            decode_hash32_v0(&summary.corpus_sha256),
            decode_hash32_v0(&summary.policy_sha256),
            validator_set.chain_id().as_str(),
            &consensus_keys,
        )
        .expect("load verified workload corpus");
        let application_signers = corpus
            .authorized_signers_v0()
            .expect("derive application signer policy");
        let governance_signer_id = corpus.header().governance_signer_id.clone();
        let run_id = format!("g3-continuous-{validator_count}-authority-test");
        let maximum_local_vote_intents = proposed_blocks
            .checked_mul(2)
            .expect("bounded deterministic Vote-intent ceiling");
        let signer_lifetime = ContinuousSignerLifetimeBoundsV0::from_exact_test_bounds_v0(
            proposed_blocks,
            proposed_blocks,
            maximum_local_vote_intents,
            proposed_blocks,
        )
        .expect("bound deterministic test signer lifetime");
        let mut authorities = Vec::with_capacity(validator_count);
        for index in 0..validator_count {
            authorities.push(commission_test_authority_v0(
                &validator_set,
                parameters,
                &keys,
                &application_signers,
                &governance_signer_id,
                &run_id,
                index,
                &temp.path().join(format!("authority-{index:03}")),
                signer_lifetime,
            ));
        }
        TestHarnessV0 {
            validator_set,
            parameters,
            keys,
            corpus,
            authorities,
            _temp: temp,
        }
    }

    fn proposal_for_workload_v0(
        harness: &TestHarnessV0,
        workload: WorkloadBlockV1,
    ) -> SignedProposalV0 {
        let view = harness
            .authorities
            .iter()
            .filter_map(|authority| authority.facts_v0().ok())
            .find(|facts| facts.phase_v0() == PocoNodeLabAuthorityPhaseV0::Ready)
            .expect("at least one ready authority")
            .current_view_v0();
        let leader = leader_for(&harness.validator_set, view);
        let leader_index = harness
            .validator_set
            .validators()
            .iter()
            .position(|validator| validator.id() == leader)
            .expect("scheduled leader belongs to validator set");
        harness.authorities[leader_index]
            .proposal_preimage_v0(workload)
            .expect("scheduled leader builds exact proposal preimage")
            .seal_with_key_v0(&harness.keys[leader_index])
            .expect("scheduled leader signs strict proposal witness")
    }

    fn proposal_for_takeover_v0(harness: &TakeoverPhaseHarnessV0) -> SignedProposalV0 {
        let view = harness
            .authorities
            .iter()
            .filter_map(|authority| authority.facts_v0().ok())
            .find(|facts| facts.phase_v0() == PocoNodeLabAuthorityPhaseV0::Ready)
            .expect("at least one ready takeover authority")
            .current_view_v0();
        let leader = leader_for(&harness.validator_set, view);
        let leader_index = harness
            .validator_set
            .validators()
            .iter()
            .position(|validator| validator.id() == leader)
            .expect("takeover leader belongs to validator set");
        harness.authorities[leader_index]
            .proposal_preimage_for_test_v0(
                harness.ordinary_start_height,
                harness.timestamp_ms,
                harness.transactions.clone(),
            )
            .expect("takeover leader builds exact proposal preimage")
            .seal_with_key_v0(&harness.keys[leader_index])
            .expect("takeover leader signs strict proposal witness")
    }

    fn quorum_certificate_from_votes_v0(
        validator_set: &ValidatorSet,
        proposal: &SignedProposalV0,
        votes: impl IntoIterator<Item = Vote>,
    ) -> QuorumCertificate {
        let coordinate = proposal.block().header();
        let mut collector = ConsensusCertificateCollectorV0::new(
            validator_set.clone(),
            MAXIMUM_COLLECTOR_COORDINATES_V0,
        )
        .expect("construct focused QC collector");
        let mut certificate = None;
        for vote in votes {
            collector.admit_vote(vote).expect("admit focused Vote");
            certificate = collector
                .try_quorum_certificate(coordinate.view(), coordinate.height(), coordinate.id())
                .expect("form focused QC");
            if certificate.is_some() {
                break;
            }
        }
        certificate.expect("focused votes reach quorum")
    }

    fn signed_vote_v0(
        validator_set: &ValidatorSet,
        key: &SigningKey,
        validator_index: usize,
        view: u64,
    ) -> Vote {
        let block_id = BlockId::new([0xd7; 32]);
        let signing_root =
            Vote::signing_root_for_set(validator_set, View::new(view), Height::new(1), block_id)
                .expect("derive focused Vote root");
        Vote::new(
            validator_set.chain_id(),
            validator_set.protocol_version(),
            validator_set.epoch(),
            View::new(view),
            Height::new(1),
            block_id,
            validator_set.id(),
            validator_set.validators()[validator_index].id(),
            SignatureBytes::from_array(key.sign(signing_root.as_bytes()).to_bytes()),
            validator_set,
        )
        .expect("construct focused Vote")
    }

    fn drive_parallel_deployed_authority_round_v0(
        authorities: &mut [ContinuousValidatorAuthorityV0],
        proposal: SignedProposalV0,
    ) -> Result<ContinuousDeterministicRoundV0> {
        let first = authorities
            .first()
            .ok_or_else(|| anyhow!("parallel deployed authority harness is empty"))?;
        let validator_set = first.validator_set.clone();
        ensure!(
            authorities.len() == validator_set.validators().len(),
            "parallel deployed harness does not own the complete validator set"
        );
        let coordinate = proposal.block().header();
        let votes = thread::scope(|scope| -> Result<Vec<Vote>> {
            let mut handles = Vec::with_capacity(authorities.len());
            for authority in authorities.iter_mut() {
                let proposal = proposal.clone();
                handles.push(
                    thread::Builder::new()
                        .name("poco-parallel-deployed-vote".to_owned())
                        .stack_size(CONTINUOUS_RUNTIME_OWNER_STACK_BYTES_V0)
                        .spawn_scoped(scope, move || authority.vote_proposal_v0(proposal))
                        .context("spawn parallel deployed Vote owner")?,
                );
            }
            let mut votes = Vec::with_capacity(handles.len());
            for handle in handles {
                votes.push(
                    handle
                        .join()
                        .map_err(|_| anyhow!("parallel deployed Vote owner panicked"))??,
                );
            }
            Ok(votes)
        })?;
        let mut collector =
            ConsensusCertificateCollectorV0::new(validator_set, MAXIMUM_COLLECTOR_COORDINATES_V0)
                .map_err(|error| anyhow!("construct parallel deployed QC collector: {error}"))?;
        let mut certificate = None;
        for vote in votes {
            collector
                .admit_vote(vote)
                .map_err(|error| anyhow!("admit parallel deployed Vote: {error}"))?;
            certificate = collector
                .try_quorum_certificate(coordinate.view(), coordinate.height(), coordinate.id())
                .map_err(|error| anyhow!("form parallel deployed QC: {error}"))?;
            if certificate.is_some() {
                break;
            }
        }
        let certificate = certificate
            .ok_or_else(|| anyhow!("complete deployed validator set did not form a QC"))?;
        let facts = thread::scope(|scope| -> Result<Vec<ContinuousRuntimeFactsV0>> {
            let mut handles = Vec::with_capacity(authorities.len());
            for authority in authorities.iter_mut() {
                let certificate = certificate.clone();
                handles.push(
                    thread::Builder::new()
                        .name("poco-parallel-deployed-qc".to_owned())
                        .stack_size(CONTINUOUS_RUNTIME_OWNER_STACK_BYTES_V0)
                        .spawn_scoped(scope, move || {
                            authority.advance_quorum_certificate_v0(certificate)
                        })
                        .context("spawn parallel deployed QC owner")?,
                );
            }
            let mut facts = Vec::with_capacity(handles.len());
            for handle in handles {
                facts.push(
                    handle
                        .join()
                        .map_err(|_| anyhow!("parallel deployed QC owner panicked"))??,
                );
            }
            Ok(facts)
        })?;
        let common = *facts
            .first()
            .expect("non-empty deployed authority set checked");
        ensure!(
            facts.iter().all(|facts| {
                facts.safety_record_checksum_v0() != [0; 32]
                    && facts.safety_chain_checksum_v0() != [0; 32]
            }),
            "deployed authority returned a zero local Safety checksum"
        );
        ensure!(
            facts
                .iter()
                .copied()
                .all(|facts| common.same_chain_cut_v0(facts)),
            "deployed authorities diverged after the same parallel QC"
        );
        Ok(ContinuousDeterministicRoundV0 {
            quorum_certificate: certificate,
            common_cut: common,
        })
    }

    fn run_deployed_convergent_harness_v0(validator_count: usize) {
        on_bounded_takeover_owner_stack_v0(move || {
            let signer_lifetime = ContinuousSignerLifetimeBoundsV0::from_exact_test_bounds_v0(
                PROPOSED_BLOCKS,
                0,
                PROPOSED_BLOCKS,
                0,
            )
            .expect("bound deployed deterministic signer lifetime");
            let mut harness = takeover_phase_harness_with_profile_v0(
                validator_count,
                signer_lifetime,
                PROPOSED_BLOCKS,
            );

            let mut block_ids = Vec::new();
            let mut post_state_roots = Vec::new();
            let mut last_round = None;
            for (height, timestamp_ms, transactions) in harness.workloads.clone() {
                let view = harness.authorities[0]
                    .facts_v0()
                    .expect("deployed authority remains ready")
                    .current_view_v0();
                let leader = leader_for(&harness.validator_set, view);
                let leader_index = harness
                    .validator_set
                    .validators()
                    .iter()
                    .position(|validator| validator.id() == leader)
                    .expect("scheduled leader belongs to deployed validator set");
                let preimage = harness.authorities[leader_index]
                    .proposal_preimage_for_test_v0(height, timestamp_ms, transactions)
                    .expect("scheduled leader builds exact deployed proposal preimage");
                assert!(preimage.block_v0().application_payload().len() > 4);
                post_state_roots.push(preimage.expected_post_state_root_v0());
                let proposal = preimage
                    .seal_with_key_v0(&harness.keys[leader_index])
                    .expect("scheduled leader signs strict deployed proposal witness");
                block_ids.push(proposal.block().id());
                let round =
                    drive_parallel_deployed_authority_round_v0(&mut harness.authorities, proposal)
                        .expect("all deployed authority owners converge on one QC");
                assert!(round.quorum_certificate_v0().votes().len() < validator_count);
                last_round = Some(round);
            }

            let common = last_round
                .expect("at least one deployed deterministic round")
                .common_cut_v0();
            let expected_finalized_height = harness
                .ordinary_start_height
                .checked_add(REQUIRED_FINALIZED_BLOCKS - 1)
                .expect("bounded deployed finalized height");
            let expected_index = usize::try_from(REQUIRED_FINALIZED_BLOCKS - 1)
                .expect("bounded deployed finalized index");
            assert_eq!(common.finalized_height_v0(), expected_finalized_height);
            assert_eq!(
                common.application_applied_height_v0(),
                expected_finalized_height
            );
            assert_eq!(common.finalized_block_id_v0(), block_ids[expected_index]);
            assert_ne!(common.finalized_chain_root_v0(), [0; 32]);
            assert_eq!(
                common.application_applied_block_id_v0(),
                common.finalized_block_id_v0()
            );
            assert_eq!(
                common.application_state_root_v0(),
                post_state_roots[expected_index]
            );
            assert_ne!(common.application_state_root_v0(), StateRoot::new([0; 32]));
            assert_eq!(common.signer_watermark_sequence_v0(), PROPOSED_BLOCKS * 2);
            assert!(common.safety_revision_v0() > 5);
            assert!(common.checkpoint_generation_v0() > 5);
        });
    }

    #[test]
    fn phase_complete_lab_authority_v0_capacity_and_sliding_replay_preflight() {
        let lifetime =
            ContinuousSignerLifetimeBoundsV0::from_exact_test_bounds_v0(100, 20, 120, 20)
                .expect("bounded signer lifetime");
        for (validators, ingress, relay) in [
            (7usize, 48usize, 108usize),
            (31, 192, 396),
            (100, 606, 1_224),
        ] {
            let preflight = ContinuousRuntimeCapacityPreflightV0::new(validators, lifetime)
                .expect("derive campaign capacity");
            assert_eq!(preflight.validator_count_v0(), validators);
            assert_eq!(
                preflight.retained_views_v0(),
                CONTINUOUS_RUNTIME_RETAINED_VIEW_TAIL_V0
            );
            assert_eq!(preflight.ingress_coordinate_capacity_v0(), ingress);
            assert_eq!(preflight.relay_message_capacity_v0(), relay);
            assert_eq!(
                preflight.signer_journal_capacity_v0(),
                CONTINUOUS_RUNTIME_MAXIMUM_SIGNER_INTENTS_V0
            );
            assert_eq!(preflight.signer_lifetime_v0(), lifetime);
        }
        assert!(
            ContinuousSignerLifetimeBoundsV0::from_exact_test_bounds_v0(100, 0, 99, 0).is_err()
        );
        let exhausted =
            ContinuousSignerLifetimeBoundsV0::from_exact_test_bounds_v0(4_097, 0, 4_097, 0)
                .expect_err("max_blocks beyond the journal must fail before commissioning");
        assert!(exhausted.to_string().contains("4097 intents"));

        let (validator_set, parameters, keys) = fixture_validator_set_v0(7);
        let preflight = ContinuousRuntimeCapacityPreflightV0::new(7, lifetime)
            .expect("derive seven-validator capacity");
        let high_qc = QcReferenceV0::genesis_anchor(
            GenesisQcV0::new(
                validator_set.genesis_hash(),
                validator_set.chain_id(),
                &validator_set,
            )
            .expect("construct focused genesis QC"),
        );
        let mut windows = ContinuousConsensusWindowsV0::new(
            validator_set.clone(),
            parameters,
            preflight,
            high_qc.clone(),
        )
        .expect("construct process-local windows");
        assert_eq!(
            windows
                .synchronize_authoritative_progress_v0(View::new(10), &high_qc, None)
                .expect("advance both process-local windows"),
            View::new(5)
        );
        assert_eq!(
            windows
                .minimum_retained_view_v0()
                .expect("common watermark"),
            View::new(5)
        );

        let live_vote = signed_vote_v0(&validator_set, &keys[0], 0, 6);
        let live_relay = ConsensusRelayEnvelopeV0::new(
            live_vote.author(),
            FrameKind::Vote,
            2,
            encode_vote(&live_vote),
            &validator_set,
            &keys[0],
        )
        .expect("construct live originated relay envelope");
        let live_id = windows
            .reserve_originated_consensus_relay_v0(&live_relay)
            .expect("reserve local relay identity before any socket effect");
        assert_eq!(live_id, live_relay.message_id());
        let returning = AuthenticatedFrame {
            sender: validator_set.validators()[1].id(),
            session: [0x40; 32],
            sequence: 1,
            kind: FrameKind::ConsensusRelay,
            payload: live_relay
                .forwarded()
                .expect("two-hop envelope has one forwarded copy")
                .encode(),
        };
        let replay = windows
            .admit_consensus_relay_frame_v0(&returning)
            .expect("returning locally originated relay is an exact replay");
        assert_eq!(replay.admission, RelayAdmissionV0::ExactReplay);
        assert_eq!(replay.message_id, live_id);
        assert!(replay.action.is_none() && replay.forward.is_none());
        assert!(windows
            .reserve_originated_consensus_relay_v0(&live_relay)
            .expect_err("one local relay identity may be originated only once")
            .to_string()
            .contains("already admitted"));

        let old_vote = signed_vote_v0(&validator_set, &keys[0], 0, 4);
        let payload = encode_vote(&old_vote);
        let direct = AuthenticatedFrame {
            sender: old_vote.author(),
            session: [0x41; 32],
            sequence: 1,
            kind: FrameKind::Vote,
            payload: payload.clone(),
        };
        let stale_direct = windows
            .admit_authenticated_frame_v0(&direct)
            .expect_err("old direct Vote replay must remain stale after pruning");
        assert!(stale_direct.to_string().contains("view was pruned"));

        let relay_envelope = ConsensusRelayEnvelopeV0::new(
            old_vote.author(),
            FrameKind::Vote,
            1,
            payload,
            &validator_set,
            &keys[0],
        )
        .expect("construct focused relay envelope");
        assert!(matches!(
            windows
                .relay
                .preflight_at_view(&relay_envelope, View::new(4)),
            Err(ConsensusRelayErrorV0::StaleView)
        ));
    }

    #[test]
    fn phase_complete_lab_authority_v0_single_takeover_leader_embedded_qc_rebase() {
        on_bounded_takeover_owner_stack_v0(|| {
            let temp = private_temp_v0();
            let authority_root = temp.path().join("single-takeover-leader");
            let watermark_root = temp.path().join("single-takeover-watermark");
            create_private_directory_v0(&authority_root)
                .expect("create empty private single-owner takeover root");
            create_private_directory_v0(&watermark_root)
                .expect("create private single-owner watermark root");
            let watermark = LabFileWatermark::open(watermark_root.join("signer-watermark.v1"))
                .expect("open single-owner takeover watermark");
            // The exact fixture starts at view 4 and leader selection is
            // canonical round-robin, so validator index 3 is the sole h4
            // proposer. The validator set remains the real four-member set.
            let bundle =
                commission_native_h1_ordinary_lab_test_bundle_v0(&authority_root, watermark, 4, 3)
                    .expect("commission one local owner in the four-validator takeover set");
            let start_height = bundle.ordinary_start_height_v0();
            let timestamp_ms = 400;
            let transactions = bundle
                .ordinary_transactions_v0(start_height, timestamp_ms)
                .expect("author single-owner policy-compatible transaction");
            let (local, set, parameters, signing_key, start, runtime) =
                bundle.into_continuous_runtime_parts_v0();
            let lifetime = ContinuousSignerLifetimeBoundsV0::from_exact_test_bounds_v0(1, 1, 2, 1)
                .expect("bound single-owner Vote/Timeout lifetime");
            let mut authority = ContinuousValidatorAuthorityV0::from_takeover_parts_v0(
                local,
                set.clone(),
                parameters,
                signing_key.clone(),
                start,
                runtime,
                lifetime,
            )
            .expect("join single takeover owner to continuous runtime");
            let facts = authority.facts_v0().expect("single takeover facts");
            assert_eq!(facts.application_applied_height_v0(), 1);
            assert_eq!(facts.proposal_parent_height_v0(), 3);
            assert_eq!(facts.high_qc_v0().height().get(), 3);
            assert_eq!(leader_for(&set, facts.current_view_v0()), local);
            let proposal = authority
                .proposal_preimage_for_test_v0(start_height, timestamp_ms, transactions)
                .expect("single takeover leader builds h4 proposal")
                .seal_with_key_v0(&signing_key)
                .expect("single takeover leader signs h4 proposal");
            let vote = authority
                .vote_proposal_v0(proposal)
                .expect("embedded h3 QC rebase and h4 authority chain succeed");
            assert_eq!(vote.author(), local);
            assert_eq!(vote.height().get(), start_height);
            let exact_high_qc = authority
                .justify_v0()
                .as_ordinary()
                .expect("takeover high QC is ordinary")
                .clone();
            let vote_signed = authority
                .advance_quorum_certificate_v0(exact_high_qc.clone())
                .expect("VoteSigned exact high-QC replay is phase-neutral");
            assert_eq!(
                vote_signed.phase_v0(),
                PocoNodeLabAuthorityPhaseV0::VoteSigned
            );
            let timeout = authority
                .begin_local_timeout_v0()
                .expect("VoteSigned owner remains live after exact replay");
            assert_eq!(timeout.author(), local);
            let timeout_signed = authority
                .advance_quorum_certificate_v0(exact_high_qc)
                .expect("TimeoutSigned exact high-QC replay is phase-neutral");
            assert_eq!(
                timeout_signed.phase_v0(),
                PocoNodeLabAuthorityPhaseV0::TimeoutSigned
            );
        });
    }

    #[test]
    fn phase_complete_lab_authority_v0_local_votes_share_remote_qc_tc_collector() {
        on_bounded_takeover_owner_stack_v0(|| {
            let mut harness = takeover_phase_harness_v0(4);
            let proposal = proposal_for_takeover_v0(&harness);
            let votes = harness
                .authorities
                .iter_mut()
                .map(|authority| {
                    authority
                        .vote_proposal_v0(proposal.clone())
                        .expect("release exact local Vote")
                })
                .collect::<Vec<_>>();

            assert!(harness.authorities[0]
                .admit_local_vote_v0(votes[1].clone())
                .expect_err("foreign authored Vote is not a local statement")
                .to_string()
                .contains("author differs"));
            for (sequence, vote) in votes[1..3].iter().enumerate() {
                let frame = AuthenticatedFrame {
                    sender: vote.author(),
                    session: [0x61; 32],
                    sequence: u64::try_from(sequence).expect("bounded remote Vote sequence"),
                    kind: FrameKind::Vote,
                    payload: encode_vote(vote),
                };
                let Some(RoutedConsensusActionV0::Vote { formed_qc, .. }) = harness.authorities[0]
                    .admit_authenticated_consensus_frame_v0(&frame)
                    .expect("admit remote Vote before the local Vote")
                else {
                    panic!("remote Vote reached the wrong action");
                };
                assert!(formed_qc.is_none());
            }
            let certificate = harness.authorities[0]
                .admit_local_vote_v0(votes[0].clone())
                .expect("admit exact signer-journal Vote without a self frame")
                .expect("local Vote completes the weighted QC");
            assert_eq!(certificate.votes().len(), 3);
            assert!(certificate
                .votes()
                .iter()
                .any(|vote| vote.author() == harness.authorities[0].local_validator_v0()));
            assert_eq!(
                harness.authorities[0]
                    .admit_local_vote_v0(votes[0].clone())
                    .expect("exact local Vote replay is idempotent"),
                Some(certificate.clone())
            );

            for authority in &mut harness.authorities {
                authority
                    .advance_quorum_certificate_v0(certificate.clone())
                    .expect("advance all authorities to the same ordinary QC");
            }
            let timeout_votes = harness
                .authorities
                .iter_mut()
                .map(|authority| {
                    authority
                        .begin_local_timeout_v0()
                        .expect("release exact local TimeoutVote")
                })
                .collect::<Vec<_>>();
            assert!(harness.authorities[0]
                .admit_local_timeout_vote_v0(timeout_votes[1].clone())
                .expect_err("foreign authored TimeoutVote is not a local statement")
                .to_string()
                .contains("author differs"));
            for (sequence, vote) in timeout_votes[1..3].iter().enumerate() {
                let frame = AuthenticatedFrame {
                    sender: vote.author(),
                    session: [0x62; 32],
                    sequence: u64::try_from(sequence).expect("bounded remote TimeoutVote sequence"),
                    kind: FrameKind::TimeoutVote,
                    payload: encode_timeout_vote(vote),
                };
                let Some(RoutedConsensusActionV0::TimeoutVote { formed_tc, .. }) = harness
                    .authorities[0]
                    .admit_authenticated_consensus_frame_v0(&frame)
                    .expect("admit remote TimeoutVote before the local TimeoutVote")
                else {
                    panic!("remote TimeoutVote reached the wrong action");
                };
                assert!(formed_tc.is_none());
            }
            let timeout_certificate = harness.authorities[0]
                .admit_local_timeout_vote_v0(timeout_votes[0].clone())
                .expect("admit exact signer-journal TimeoutVote without a self frame")
                .expect("local TimeoutVote completes the weighted TC");
            assert_eq!(timeout_certificate.entries().len(), 3);
            assert_eq!(
                timeout_certificate.selected_high_qc_digest(),
                certificate.id()
            );
            assert_eq!(
                harness.authorities[0]
                    .admit_local_timeout_vote_v0(timeout_votes[0].clone())
                    .expect("exact local TimeoutVote replay is idempotent"),
                Some(timeout_certificate.clone())
            );
            for authority in &mut harness.authorities {
                authority
                    .advance_timeout_certificate_v0(timeout_certificate.clone())
                    .expect("TC restores every Vote+Timeout authority to Ready");
            }
            let inventory = harness.authorities[0]
                .fresh_ready_signer_inventory_v1()
                .expect("audit exact one-Vote/one-Timeout baseline");
            assert_eq!(inventory.durable_vote_intent_count_v1(), 1);
            assert_eq!(inventory.durable_timeout_intent_count_v1(), 1);
            assert_eq!(inventory.signed_vote_intent_count_v1(), 1);
            assert_eq!(inventory.signed_timeout_intent_count_v1(), 1);
            assert_eq!(inventory.exact_watermark_v1().sequence(), 4);
            assert_ne!(inventory.inventory_digest_v1(), [0; 32]);
            assert_ne!(inventory.checkpoint_canonical_sha256_v1(), [0; 32]);
            let baseline_bounds = harness.authorities[0]
                .capacity_preflight_v0()
                .signer_lifetime_v0();
            let baseline = ContinuousSignerLifetimeStateV0::from_authenticated_inventory_v1(
                baseline_bounds,
                inventory,
            )
            .expect("authenticated nonzero process-two baseline is constructor-safe");
            assert_eq!(baseline.signed_vote_intents, 1);
            assert_eq!(baseline.signed_timeout_intents, 1);
            let mut same_total_swapped = baseline;
            same_total_swapped.signed_vote_intents = 2;
            same_total_swapped.signed_timeout_intents = 0;
            assert!(same_total_swapped
                .require_authenticated_inventory_v1(inventory)
                .is_err());
        });
    }

    #[test]
    fn authenticated_mesh_ingress_routes_directly_into_live_authority_admission() {
        // This is a bounded unit/loopback composition proof only.  It does
        // not commission a production validator, start Core, or contribute
        // any Stage-0/7-node observation.
        on_bounded_takeover_owner_stack_v0(|| {
            let mut harness = fresh_test_harness_v0(4, 1);
            let validator_set = harness.validator_set.clone();
            let local = validator_set.validators()[0].id();
            let remote = validator_set.validators()[1].id();
            let p2p_keys = (0..validator_set.validators().len())
                .map(|index| {
                    let marker = u8::try_from(0xa1 + index).expect("bounded p2p key marker");
                    SigningKey::from_bytes(&[marker; 32])
                })
                .collect::<Vec<_>>();
            let operator_keys = (0..validator_set.validators().len())
                .map(|index| {
                    let marker = u8::try_from(0xb1 + index).expect("bounded operator key marker");
                    SigningKey::from_bytes(&[marker; 32])
                })
                .collect::<Vec<_>>();
            let role_bindings = validator_set
                .validators()
                .iter()
                .enumerate()
                .map(|(index, validator)| {
                    ValidatorKeyRoleBindingV1::new(
                        validator.id(),
                        validator.consensus_key().into_bytes(),
                        p2p_keys[index].verifying_key().to_bytes(),
                        operator_keys[index].verifying_key().to_bytes(),
                    )
                    .expect("construct fixture key-role binding")
                })
                .collect::<Vec<_>>();
            let roles = ValidatorKeyRoleRegistryV1::new(&validator_set, role_bindings)
                .expect("construct complete fixture key-role registry");
            let local_addr = TcpListener::bind("127.0.0.1:0")
                .expect("allocate local mesh listener address")
                .local_addr()
                .expect("read local mesh listener address");
            let remote_addr = TcpListener::bind("127.0.0.1:0")
                .expect("allocate remote mesh listener address")
                .local_addr()
                .expect("read remote mesh listener address");
            let context = RunTransportContext::new([0xc1; 32], [0xc2; 32], [0xc3; 32], [0xc4; 32])
                .with_validator_set_binding(
                    validator_set.epoch().get(),
                    validator_set.id().into_bytes(),
                );
            let mut local_outgoing = BTreeMap::new();
            local_outgoing.insert(remote, remote_addr);
            let mut local_incoming = BTreeMap::new();
            local_incoming.insert(remote, remote_addr);
            let mut remote_outgoing = BTreeMap::new();
            remote_outgoing.insert(local, local_addr);
            let mut remote_incoming = BTreeMap::new();
            remote_incoming.insert(local, local_addr);
            let local_config = MeshFixtureConfigV1::new(
                "poco-g3-authority-admission-route",
                local,
                p2p_keys[0].clone(),
                validator_set.clone(),
                roles.clone(),
                context,
                local_addr,
                local_outgoing,
                local_incoming,
            )
            .expect("construct local authenticated mesh fixture");
            let remote_config = MeshFixtureConfigV1::new(
                "poco-g3-authority-admission-route",
                remote,
                p2p_keys[1].clone(),
                validator_set.clone(),
                roles,
                context,
                remote_addr,
                remote_outgoing,
                remote_incoming,
            )
            .expect("construct remote authenticated mesh fixture");
            let lease_authority = Arc::new(TestExternalPeerLeaseAuthorityV1::new(
                PeerAdmissionContextV1::from_validator_set(&validator_set),
            ));
            let local_lease = Arc::clone(&lease_authority);
            let remote_lease = Arc::clone(&lease_authority);
            let local_thread = thread::spawn(move || {
                PersistentAuthenticatedPeerMeshV0::establish_fixture_with_fence_ttl_v1(
                    &local_config,
                    Duration::from_secs(5),
                    Duration::from_millis(500),
                    8,
                    Duration::from_secs(2),
                    local_lease,
                )
                .expect("establish local authenticated mesh worker")
            });
            let remote_thread = thread::spawn(move || {
                PersistentAuthenticatedPeerMeshV0::establish_fixture_with_fence_ttl_v1(
                    &remote_config,
                    Duration::from_secs(5),
                    Duration::from_millis(500),
                    8,
                    Duration::from_secs(2),
                    remote_lease,
                )
                .expect("establish remote authenticated mesh worker")
            });
            let local_mesh = local_thread.join().expect("local mesh setup thread");
            let remote_mesh = remote_thread.join().expect("remote mesh setup thread");

            let remote_vote = signed_vote_v0(&harness.validator_set, &harness.keys[1], 1, 1);
            remote_mesh
                .send_to(local, FrameKind::Vote, encode_vote(&remote_vote))
                .expect("queue signed Vote on authenticated mesh");

            let deadline = Instant::now() + Duration::from_secs(2);
            let mut admitted = None;
            while Instant::now() < deadline {
                let Some(event) = local_mesh
                    .receive_timeout(Duration::from_millis(100))
                    .expect("receive authenticated mesh event")
                else {
                    continue;
                };
                let MeshIngressEventV0::Frame(frame) = event else {
                    continue;
                };
                assert_eq!(frame.remote(), remote);
                let authenticated = frame.into_frame();
                let action = harness.authorities[0]
                    .admit_authenticated_consensus_frame_v0(&authenticated)
                    .expect("authority admission accepts mesh-authenticated Vote");
                admitted = Some(action);
                break;
            }
            let Some(Some(RoutedConsensusActionV0::Vote { vote, formed_qc })) = admitted else {
                panic!("mesh ingress did not route a Vote into authority admission");
            };
            assert_eq!(*vote, remote_vote);
            assert!(formed_qc.is_none(), "one remote Vote cannot form a QC");
            local_mesh
                .close()
                .expect("close local authenticated mesh worker");
            remote_mesh
                .close()
                .expect("close remote authenticated mesh worker");
        });
    }

    #[test]
    fn phase_complete_lab_authority_v0_fresh_genesis_vote_is_expected_reject() {
        let mut harness = fresh_test_harness_v0(4, 1);
        let workload = harness
            .corpus
            .block_at_height(1)
            .expect("load focused height-one workload");
        let proposal = proposal_for_workload_v0(&harness, workload);
        let rejection = harness.authorities[0]
            .vote_proposal_v0(proposal)
            .expect_err("headerless fresh-genesis parent must not authorize a Vote");
        assert!(
            rejection
                .to_string()
                .contains("durable P parent lacks authenticated application-state authority"),
            "fresh-genesis rejection must identify the missing application parent: {rejection:#}"
        );
        assert!(
            harness.authorities[0].facts_v0().is_err(),
            "consumed fresh-genesis failure must remain fail-closed"
        );
    }

    #[test]
    fn phase_complete_lab_authority_v0_direct_proposal_replay_is_process_inert() {
        let mut harness = fresh_test_harness_v0(4, 1);
        let workload = harness
            .corpus
            .block_at_height(1)
            .expect("load focused proposal workload");
        let proposal = proposal_for_workload_v0(&harness, workload);
        let unbound =
            UnboundProposalV0::from_signed(&proposal).expect("project focused direct Proposal");
        let payload = unbound.encode().expect("encode canonical direct Proposal");
        let proposer = proposal.block().header().proposer_id();
        let first = AuthenticatedFrame {
            sender: proposer,
            session: [0x51; 32],
            sequence: 1,
            kind: FrameKind::Proposal,
            payload: payload.clone(),
        };
        assert!(matches!(
            harness.authorities[0]
                .admit_authenticated_consensus_frame_v0(&first)
                .expect("admit first canonical direct Proposal"),
            Some(RoutedConsensusActionV0::Proposal(_))
        ));

        let reconnect_replay = AuthenticatedFrame {
            session: [0x52; 32],
            sequence: 1,
            ..first
        };
        assert!(harness.authorities[0]
            .admit_authenticated_consensus_frame_v0(&reconnect_replay)
            .expect("exact reconnect replay is inert")
            .is_none());

        let original_header = proposal.block().header();
        let alternate_header = BlockHeader::new(
            original_header.genesis_hash(),
            original_header.chain_id(),
            original_header.protocol_version(),
            original_header.epoch(),
            original_header.view(),
            original_header.height(),
            original_header.block_kind(),
            original_header.parent_id(),
            original_header.proposer_id(),
            original_header.validator_set_id(),
            original_header.consensus_parameters_hash(),
            original_header.payload_root(),
            original_header.state_root(),
            original_header.receipts_root(),
            original_header.evidence_root(),
            original_header
                .timestamp_ms()
                .checked_add(1)
                .expect("alternate proposal timestamp"),
            original_header.next_epoch_commitment_hash(),
        )
        .expect("construct same-coordinate alternate header");
        let alternate_block = Block::new(
            alternate_header,
            proposal.block().application_payload().to_vec(),
            proposal.block().evidence_objects().to_vec(),
        )
        .expect("construct same-coordinate alternate block");
        assert_ne!(alternate_block.id(), proposal.block().id());
        let proposer_index = harness
            .validator_set
            .validators()
            .iter()
            .position(|validator| validator.id() == proposer)
            .expect("alternate proposer belongs to validator set");
        let alternate_root = ProposalWitnessV0::signing_root_for(
            alternate_block.header(),
            proposal.witness().justify_qc(),
            proposal.witness().timeout_certificate(),
            None,
        )
        .expect("derive alternate Proposal root");
        let alternate_signature = SignatureBytes::from_array(
            harness.keys[proposer_index]
                .sign(alternate_root.as_bytes())
                .to_bytes(),
        );
        let alternate_witness = ProposalWitnessV0::new(
            alternate_block.header(),
            proposal.witness().justify_qc().clone(),
            proposal.witness().timeout_certificate().cloned(),
            None,
            alternate_signature,
            &harness.validator_set,
            None,
            &harness.parameters,
            0,
        )
        .expect("construct alternate Proposal witness");
        let alternate = SignedProposalV0::new(
            alternate_block,
            alternate_witness,
            &harness.validator_set,
            None,
            &harness.parameters,
            0,
        )
        .expect("construct same-coordinate alternate Proposal");
        let alternate_payload = UnboundProposalV0::from_signed(&alternate)
            .expect("project alternate direct Proposal")
            .encode()
            .expect("encode alternate direct Proposal");
        let alternate_frame = AuthenticatedFrame {
            sender: proposer,
            session: [0x53; 32],
            sequence: 1,
            kind: FrameKind::Proposal,
            payload: alternate_payload,
        };
        assert!(matches!(
            harness.authorities[0]
                .admit_authenticated_consensus_frame_v0(&alternate_frame)
                .expect("same-view different block reaches authority routing"),
            Some(RoutedConsensusActionV0::Proposal(_))
        ));

        let high_qc = harness.authorities[0].justify_v0().clone();
        harness.authorities[0]
            .consensus_windows
            .synchronize_authoritative_progress_v0(View::new(7), &high_qc, None)
            .expect("prune direct-Proposal identity tail");
        let stale = harness.authorities[0]
            .admit_authenticated_consensus_frame_v0(&reconnect_replay)
            .expect_err("pruned Proposal replay must be stale, not fresh");
        assert!(stale
            .to_string()
            .contains("consensus statement view was pruned"));
    }

    #[test]
    fn phase_complete_lab_authority_v0_accepts_qc_from_every_live_phase_without_local_membership() {
        on_bounded_takeover_owner_stack_v0(|| {
            let mut harness = takeover_phase_harness_v0(4);
            let proposal = proposal_for_takeover_v0(&harness);
            let votes = harness
                .authorities
                .iter_mut()
                .map(|authority| {
                    authority
                        .vote_proposal_v0(proposal.clone())
                        .expect("release focused Vote")
                })
                .collect::<Vec<_>>();
            let certificate = quorum_certificate_from_votes_v0(
                &harness.validator_set,
                &proposal,
                votes.iter().take(3).cloned(),
            );
            let excluded = harness.authorities[3].local_validator_v0();
            assert!(
                certificate
                    .votes()
                    .iter()
                    .all(|vote| vote.author() != excluded),
                "focused QC must exclude the fourth authority's local Vote"
            );

            assert_eq!(
                harness.authorities[0]
                    .facts_v0()
                    .expect("VoteSigned facts")
                    .phase_v0(),
                PocoNodeLabAuthorityPhaseV0::VoteSigned
            );
            harness.authorities[0]
                .advance_quorum_certificate_v0(certificate.clone())
                .expect("VoteSigned accepts QC");
            harness.authorities[0]
                .advance_quorum_certificate_v0(certificate.clone())
                .expect("Ready accepts a late exact QC");

            harness.authorities[1]
                .begin_local_timeout_v0()
                .expect("VoteSigned starts the same-view timeout");
            assert_eq!(
                harness.authorities[1]
                    .facts_v0()
                    .expect("TimeoutSigned facts")
                    .phase_v0(),
                PocoNodeLabAuthorityPhaseV0::TimeoutSigned
            );
            harness.authorities[1]
                .advance_quorum_certificate_v0(certificate.clone())
                .expect("TimeoutSigned accepts the late QC");
            harness.authorities[2]
                .advance_quorum_certificate_v0(certificate.clone())
                .expect("second VoteSigned accepts QC");
            harness.authorities[3]
                .advance_quorum_certificate_v0(certificate.clone())
                .expect("QC without local Vote membership is accepted");

            for authority in &harness.authorities {
                let facts = authority.facts_v0().expect("phase-complete QC facts");
                assert_eq!(facts.phase_v0(), PocoNodeLabAuthorityPhaseV0::Ready);
                assert_eq!(facts.high_qc_v0(), QcRef::from(&certificate));
                assert!(facts.pending_timeout_certificate_id_v0().is_none());
            }
        });
    }

    #[test]
    fn phase_complete_lab_authority_v0_tc_rebases_and_ingress_fails_closed() {
        on_bounded_takeover_owner_stack_v0(|| {
            let signer_lifetime =
                ContinuousSignerLifetimeBoundsV0::from_exact_test_bounds_v0(1, 1, 2, 1)
                    .expect("bound TC-rebase signer lifetime");
            let mut harness = takeover_phase_harness_with_signer_lifetime_v0(4, signer_lifetime);
            let initial_reference = harness.authorities[0].justify_v0().clone();
            let initial_facts = harness.authorities[0]
                .facts_v0()
                .expect("initial takeover facts");
            let initial_parent_block_id = initial_facts.proposal_parent_block_id_v0();
            let initial_parent_height = initial_facts.proposal_parent_height_v0();
            assert_eq!(
                initial_parent_height.checked_add(1),
                Some(harness.ordinary_start_height)
            );
            let original = proposal_for_takeover_v0(&harness);
            let original_view = original.block().header().view();
            let next_view = View::new(
                original_view
                    .get()
                    .checked_add(1)
                    .expect("focused TC successor view"),
            );
            let original_votes = harness.authorities[..3]
                .iter_mut()
                .map(|authority| {
                    authority
                        .vote_proposal_v0(original.clone())
                        .expect("release original branch Vote")
                })
                .collect::<Vec<_>>();
            let original_qc = quorum_certificate_from_votes_v0(
                &harness.validator_set,
                &original,
                original_votes.iter().cloned(),
            );

            let timeout_votes = harness.authorities[..3]
                .iter_mut()
                .map(|authority| {
                    authority
                        .begin_local_timeout_v0()
                        .expect("VoteSigned starts focused timeout")
                })
                .collect::<Vec<_>>();
            let mut timeout_collector = ConsensusCertificateCollectorV0::new(
                harness.validator_set.clone(),
                MAXIMUM_COLLECTOR_COORDINATES_V0,
            )
            .expect("construct focused TC collector");
            timeout_collector
                .register_qc_reference(initial_reference.clone())
                .expect("register exact takeover high-QC reference");
            for vote in timeout_votes {
                timeout_collector
                    .admit_timeout_vote(vote)
                    .expect("admit focused TimeoutVote");
            }
            let certificate = timeout_collector
                .try_timeout_certificate(original_view)
                .expect("form focused TC")
                .expect("focused timeouts reach quorum");
            assert_eq!(
                certificate.selected_high_qc_digest(),
                initial_reference.id()
            );

            harness.authorities[3]
                .advance_timeout_certificate_v0(certificate.clone())
                .expect("Ready accepts TC");
            for authority in &mut harness.authorities[..3] {
                authority
                    .advance_timeout_certificate_v0(certificate.clone())
                    .expect("TimeoutSigned accepts TC");
            }

            for authority in &harness.authorities {
                let facts = authority.facts_v0().expect("post-TC ready facts");
                assert_eq!(facts.phase_v0(), PocoNodeLabAuthorityPhaseV0::Ready);
                assert_eq!(facts.current_view_v0(), next_view);
                assert_eq!(facts.high_qc_v0(), initial_reference.qc_ref());
                assert_eq!(facts.proposal_parent_block_id_v0(), initial_parent_block_id);
                assert_eq!(facts.proposal_parent_height_v0(), initial_parent_height);
                assert_eq!(
                    facts.pending_timeout_certificate_id_v0(),
                    Some(certificate.id())
                );
            }

            let next_leader = leader_for(&harness.validator_set, next_view);
            let next_leader_index = harness
                .validator_set
                .validators()
                .iter()
                .position(|validator| validator.id() == next_leader)
                .expect("post-TC leader belongs to validator set");
            let sacrifice = (0..harness.authorities.len())
                .find(|index| *index != next_leader_index)
                .expect("one non-leader authority is available");
            let missing = harness.authorities[sacrifice]
                .advance_quorum_certificate_v0(original_qc)
                .expect_err("pruned detached execution must fail closed");
            assert!(
                missing.to_string().contains("retained execution"),
                "missing retained execution must be classified explicitly: {missing:#}"
            );
            assert!(
                harness.authorities[sacrifice].facts_v0().is_err(),
                "consumed owner failure must remain fail-closed"
            );

            let rebound = proposal_for_takeover_v0(&harness);
            assert_ne!(rebound.block().id(), original.block().id());
            assert_eq!(
                rebound
                    .witness()
                    .timeout_certificate()
                    .map(TimeoutCertificateV0::id),
                Some(certificate.id())
            );
            let remaining = (0..harness.authorities.len())
                .filter(|index| *index != sacrifice)
                .collect::<Vec<_>>();
            let rebound_votes = remaining
                .iter()
                .map(|index| {
                    harness.authorities[*index]
                        .vote_proposal_v0(rebound.clone())
                        .expect("rebound branch votes from exact TC parent")
                })
                .collect::<Vec<_>>();
            let rebound_qc =
                quorum_certificate_from_votes_v0(&harness.validator_set, &rebound, rebound_votes);
            for index in &remaining {
                harness.authorities[*index]
                    .advance_quorum_certificate_v0(rebound_qc.clone())
                    .expect("rebound QC returns one exact ready parent");
            }

            let stale_index = remaining[0];
            let stale = UnboundProposalV0::from_signed(&rebound)
                .expect("project stale rebound proposal into ingress");
            let authoritative = harness.authorities[stale_index]
                .facts_v0()
                .expect("post-rebound authoritative facts");
            assert_ne!(stale.justify_qc().qc_ref(), authoritative.high_qc_v0());
            assert_ne!(
                stale.block().header().parent_id(),
                authoritative.proposal_parent_block_id_v0()
            );
            let rejection = harness.authorities[stale_index]
                .vote_unbound_proposal_v0(stale)
                .expect_err("wrong parent/justify carrier must fail closed");
            assert!(
                rejection.to_string().contains("proposal")
                    || rejection.to_string().contains("certificate"),
                "typed ingress rejection must remain attributable: {rejection:#}"
            );
        });
    }

    #[test]
    fn four_validator_real_authorities_finalize_four_nonempty_blocks_v0() {
        run_deployed_convergent_harness_v0(4);
    }

    #[test]
    fn seven_validator_real_authorities_finalize_four_nonempty_blocks_v0() {
        run_deployed_convergent_harness_v0(7);
    }
}
