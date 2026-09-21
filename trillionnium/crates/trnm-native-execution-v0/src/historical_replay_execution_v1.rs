//! Read-only deterministic replay over an audited local source and M01 history.
//! These private computation facts are never ordinary P or epoch-owner permits.

use anyhow::{ensure, Context, Result};
use trnm_consensus_crypto::{
    StrictHistoricalHeaderPathV1, StrictSameVersionEpochActivationAuthorityV0,
};
use trnm_consensus_types::{
    decode_application_payload_v0_exact, validate_root_bound_epoch_body_v1,
    validate_root_bound_regular_body_v0, Block, BlockHeader, BlockKind, ConsensusParametersV0,
    EpochGeometryV0, ValidatorSet,
};
use trnm_finality_types::hash_domain;
use trnm_native_application::{
    encode_native_executed_block_artifact_v0, encode_native_executed_epoch_block_artifact_v1,
    ApplicationCommitIdV0, ApplicationHeadV0, BlockIdV0, ChainIdV0, GenesisHashV0, Hash32V0,
    HeightV0, NativeBlockExecutionRequestV0, NativeEpochBlockExecutionRequestV1,
    NativeEpochBlockPreviewRequestV1, NativeExecutedEpochBlockV1, NativeExpectedBlockCommitmentsV0,
    ReceiptsRootV0, StateRootV0, ValidatorSetIdV0,
};

use crate::{
    complete::{
        compute_complete_epoch_native_block_with_context_v1, execute_complete_native_block_v0,
        load_validator_lifecycle_from_live_v0, preview_complete_native_block_v0,
        CompleteBlockExecutionInputV0, NativeBlockPreviewRequestV0, NativeBlockPreviewV0,
    },
    epoch_edge::{sealed, EpochApplicationCoordinatesV1, EpochExecutionContextV1},
    poco_checkpoint::{active_consensus_configuration, validate_application_validator_projection},
    poco_transition::take_and_validate_production_poco_projection_v0,
    store::{InMemoryNativeExecutionStoreV0, NativeExecutionStoreV0},
    NativeHistoricalRecordV1, NativeHistoricalReplayV1,
};

use std::{borrow::Cow, collections::BTreeSet};

pub(super) struct ComputedHistoricalReplayV1 {
    pub(super) target_head: ApplicationHeadV0,
    pub(super) target_header: BlockHeader,
    pub(super) target_set: ValidatorSet,
    pub(super) target_parameters: ConsensusParametersV0,
    pub(super) snapshot: Vec<u8>,
    pub(super) commands: Vec<u8>,
    pub(super) nonces: Vec<u8>,
    pub(super) lifecycle: Vec<u8>,
    pub(super) application_count: usize,
}

/// Independently replayed computation state retained only inside the owner.
/// Neither the store nor its coordinates grant persistence or signing authority.
pub(super) struct ReplayedHistoricalStateV1 {
    pub(super) computed: ComputedHistoricalReplayV1,
    pub(super) store: InMemoryNativeExecutionStoreV0,
    pub(super) coordinates: Vec<EpochApplicationCoordinatesV1>,
}

/// Selected parent bytes already authenticated by the owner pipeline. These
/// fields are inert comparison data and cannot authorize persistence.
pub(super) struct ReplayExecutionParentV1<'a> {
    pub(super) head: &'a ApplicationHeadV0,
    pub(super) header: &'a BlockHeader,
    pub(super) snapshot: &'a [u8],
    pub(super) commands: &'a [u8],
    pub(super) nonces: &'a [u8],
    pub(super) store: Option<&'a InMemoryNativeExecutionStoreV0>,
}

pub(super) struct ReplayExecutionContextV1<'a> {
    pub(super) config: &'a crate::durable::NativeApplicationConfigV0,
    pub(super) active_set: &'a ValidatorSet,
    pub(super) active_parameters: &'a ConsensusParametersV0,
    pub(super) coordinates: &'a [EpochApplicationCoordinatesV1],
}

pub(super) struct ComputedReplayExecutionV1 {
    pub(super) artifact: Vec<u8>,
    pub(super) snapshot: Vec<u8>,
    pub(super) commands: Vec<u8>,
    pub(super) nonces: Vec<u8>,
    pub(super) lifecycle: Vec<u8>,
}

fn restore_replay_parent<'a>(
    context: &ReplayExecutionContextV1<'_>,
    parent: &ReplayExecutionParentV1<'a>,
) -> Result<Cow<'a, InMemoryNativeExecutionStoreV0>> {
    ensure!(
        !parent.snapshot.is_empty()
            && parent.snapshot.len() <= 256 * 1024 * 1024
            && (4..=16 * 1024 * 1024).contains(&parent.commands.len())
            && (4..=16 * 1024 * 1024).contains(&parent.nonces.len())
            && !context.coordinates.is_empty()
            && context.coordinates.len() <= 64,
        "replay execution parent resource bound"
    );
    ensure_head_header(parent.head, parent.header)?;
    protocol(parent.header.validate_shape())?;
    protocol(
        context
            .active_set
            .validate_against_parameters(context.active_parameters),
    )?;
    let set = context.active_set;
    ensure!(
        set.chain_id().as_str() == context.config.chain_id
            && set.genesis_hash().as_bytes() == &context.config.genesis_hash
            && parent.header.chain_id() == set.chain_id()
            && parent.header.genesis_hash() == set.genesis_hash()
            && parent.header.protocol_version() == set.protocol_version()
            && parent.header.epoch() == set.epoch()
            && parent.header.validator_set_id() == set.id()
            && parent.header.consensus_parameters_hash() == context.active_parameters.hash(),
        "replay execution parent active context"
    );
    let store = match parent.store {
        Some(store) => Cow::Borrowed(store),
        None => {
            let commands: BTreeSet<String> = borsh::from_slice(parent.commands)
                .context("replay execution parent command identities")?;
            let nonces: BTreeSet<(String, u64)> = borsh::from_slice(parent.nonces)
                .context("replay execution parent signer nonces")?;
            Cow::Owned(
                InMemoryNativeExecutionStoreV0::decode_epoch_snapshot_for_coordinates_v1(
                    context.config.chain_id.clone(),
                    context.config.signers.clone(),
                    *context.active_parameters,
                    commands,
                    nonces,
                    parent.snapshot,
                    context.coordinates,
                )?,
            )
        }
    };
    let (version, root) = crate::store::verify_parent_root_v0(store.as_ref())?;
    ensure!(
        version == parent.head.height().get()
            && root.0 == *parent.head.state_root().as_bytes()
            && store.chain_id_v0()? == context.config.chain_id
            && store.consensus_parameters_v0()? == *context.active_parameters
            && store.signer_policy_commitment_v0()? == context.config.signer_policy_commitment,
        "replay execution parent store binding"
    );
    let (commands, nonces) = store.replay_sets_v0();
    ensure!(
        borsh::to_vec(commands)? == parent.commands
            && borsh::to_vec(nonces)? == parent.nonces
            && store.encode_epoch_snapshot_for_coordinates_v1(context.coordinates)?
                == parent.snapshot,
        "replay execution parent canonical snapshot/replay binding"
    );
    Ok(store)
}

fn validate_replay_request<R: CompleteBlockExecutionInputV0>(
    context: &ReplayExecutionContextV1<'_>,
    parent: &ReplayExecutionParentV1<'_>,
    request: &R,
) -> Result<()> {
    let maximum_timestamp = parent
        .header
        .timestamp_ms()
        .checked_add(context.active_parameters.max_block_time_step_ms())
        .context("replay execution parent timestamp overflow")?;
    ensure!(
        request.parent_v0() == parent.head
            && parent.head.height().get().checked_add(1) == Some(request.height_v0().get())
            && request.chain_id_v0().as_str() == context.config.chain_id
            && request.genesis_hash_v0().as_bytes() == &context.config.genesis_hash
            && request.active_validator_set_id_v0().as_bytes()
                == context.active_set.id().as_bytes()
            && request.timestamp_ms_v0() > parent.header.timestamp_ms()
            && request.timestamp_ms_v0() <= maximum_timestamp,
        "replay execution exact request parent/context"
    );
    let geometry = protocol(EpochGeometryV0::new(
        context.active_set.epoch(),
        context.active_parameters,
    ))?;
    ensure!(
        protocol(geometry.expected_block_kind(parent.header.height()))?
            == parent.header.block_kind()
            && protocol(
                geometry.expected_block_kind(trnm_consensus_types::Height::new(
                    request.height_v0().get(),
                ))
            )? == BlockKind::Regular,
        "replay execution requires ordinary epoch geometry"
    );
    Ok(())
}

/// A read-only preview has no proposal view/leader or finality authority. Final
/// execution below binds those additional fields to the exact supplied header.
pub(super) fn preview_replay_execution_v1(
    context: &ReplayExecutionContextV1<'_>,
    parent: &ReplayExecutionParentV1<'_>,
    request: &NativeBlockPreviewRequestV0,
) -> Result<NativeBlockPreviewV0> {
    validate_replay_request(context, parent, request)?;
    let store = restore_replay_parent(context, parent)?;
    preview_complete_native_block_v0(
        store.as_ref(),
        context.active_set,
        context.active_set.genesis_hash(),
        request,
    )
}

/// Compute one ordinary successor using the unchanged complete engine. The
/// resulting artifact and state bytes are inert until the owner persists them.
#[inline(never)]
pub(super) fn compute_replay_execution_v1(
    context: &ReplayExecutionContextV1<'_>,
    parent: &ReplayExecutionParentV1<'_>,
    request: &NativeBlockExecutionRequestV0,
    header: &BlockHeader,
) -> Result<ComputedReplayExecutionV1> {
    validate_replay_request(context, parent, request)?;
    ensure!(
        header.block_kind() == BlockKind::Regular && header.next_epoch_commitment_hash().is_none(),
        "replay execution requires Regular header without epoch commitment"
    );
    protocol(trnm_consensus_types::validate_historical_header_link_v1(
        header,
        parent.header,
        context.active_set,
        context.active_parameters,
    ))?;
    crate::durable::ensure_finalized_header_binding_v0(header, request)?;
    let payload = protocol(trnm_consensus_types::ApplicationPayloadV0::new(
        request.transactions().to_vec(),
    ))?;
    let block = protocol(Block::new(
        header.clone(),
        protocol(payload.try_cev0_bytes())?,
        Vec::new(),
    ))?;
    protocol(validate_root_bound_regular_body_v0(
        &block,
        context.active_set,
        context.active_parameters,
    ))?;
    let mut store = restore_replay_parent(context, parent)?.into_owned();
    let (executed, plan, identities, lifecycle) = execute_complete_native_block_v0(
        &store,
        context.active_set,
        context.active_set.genesis_hash(),
        request,
    )?
    .into_parts();
    crate::durable::validate_native_finalized_execution_receipts_v0(&executed)?;
    let artifact = encode_native_executed_block_artifact_v0(&executed)?;
    store.apply_complete_state_plan_v0(plan)?;
    for identity in identities {
        store.mark_committed_command_v0(
            identity.command_id(),
            identity.signer_id(),
            identity.nonce(),
        )?;
    }
    let snapshot = store.encode_epoch_snapshot_for_coordinates_v1(context.coordinates)?;
    let (commands, nonces) = store.replay_sets_v0();
    let commands = borsh::to_vec(commands)?;
    let nonces = borsh::to_vec(nonces)?;
    let lifecycle = serde_json::to_vec(&lifecycle)?;
    ensure!(
        artifact.len() <= 16 * 1024 * 1024
            && snapshot.len() <= 256 * 1024 * 1024
            && commands.len() <= 16 * 1024 * 1024
            && nonces.len() <= 16 * 1024 * 1024
            && lifecycle.len() <= 1024 * 1024,
        "replay execution computed resource bound"
    );
    Ok(ComputedReplayExecutionV1 {
        artifact,
        snapshot,
        commands,
        nonces,
        lifecycle,
    })
}

/// A replay-local checkpoint joined to sealed M01 activation facts. It borrows
/// cryptographic authority but issues no durable edge, sequence or acknowledgement.
struct ReplayEpochContextV1<'a> {
    parent: ApplicationHeadV0,
    activation: &'a StrictSameVersionEpochActivationAuthorityV0,
    coordinates: EpochApplicationCoordinatesV1,
}

impl<'a> ReplayEpochContextV1<'a> {
    fn new(
        parent: ApplicationHeadV0,
        activation: &'a StrictSameVersionEpochActivationAuthorityV0,
    ) -> Result<Self> {
        let checkpoint = activation
            .old_checkpoint_finality()
            .finalized_block()
            .header();
        ensure_head_header(&parent, checkpoint)?;
        let coordinates = EpochApplicationCoordinatesV1 {
            checkpoint_version: checkpoint.height().get(),
            checkpoint_root: *checkpoint.state_root().as_bytes(),
            terminal_version: activation.terminal_old_header().height().get(),
            first_version: activation
                .handoff_certificate()
                .descriptor()
                .fields()
                .activation_height
                .get(),
            authorization_id: *activation.binding_ref().as_bytes(),
        };
        coordinates.validate()?;
        Ok(Self {
            parent,
            activation,
            coordinates,
        })
    }
}

impl sealed::Sealed for ReplayEpochContextV1<'_> {}
impl EpochExecutionContextV1 for ReplayEpochContextV1<'_> {
    fn application_parent_v1(&self) -> &ApplicationHeadV0 {
        &self.parent
    }
    fn consensus_parent_v1(&self) -> &BlockHeader {
        self.activation.terminal_old_header()
    }
    fn first_application_height_v1(&self) -> u64 {
        self.coordinates.first_version
    }
    fn old_validator_set_v1(&self) -> &ValidatorSet {
        self.activation.old_validator_set()
    }
    fn old_parameters_v1(&self) -> &ConsensusParametersV0 {
        self.activation.old_consensus_parameters()
    }
    fn new_validator_set_v1(&self) -> &ValidatorSet {
        self.activation.new_validator_set()
    }
    fn new_parameters_v1(&self) -> &ConsensusParametersV0 {
        self.activation.new_consensus_parameters()
    }
    fn authorization_id_v1(&self) -> [u8; 32] {
        self.coordinates.authorization_id
    }
    fn coordinates_v1(&self) -> EpochApplicationCoordinatesV1 {
        self.coordinates
    }
}

fn protocol<T, E: core::fmt::Debug>(value: core::result::Result<T, E>) -> Result<T> {
    value.map_err(|error| anyhow::anyhow!("historical replay protocol: {error:?}"))
}

fn ensure_head_header(head: &ApplicationHeadV0, header: &BlockHeader) -> Result<()> {
    ensure!(
        head.height().get() == header.height().get()
            && head.block_id().as_bytes() == header.id().as_bytes()
            && head.state_root().as_bytes() == header.state_root().as_bytes(),
        "historical replay application head/header mismatch"
    );
    Ok(())
}

fn expected_roots(header: &BlockHeader) -> Result<NativeExpectedBlockCommitmentsV0> {
    Ok(NativeExpectedBlockCommitmentsV0::new(
        Hash32V0::new(*header.payload_root().as_bytes()),
        StateRootV0::new(*header.state_root().as_bytes())?,
        ReceiptsRootV0::new(*header.receipts_root().as_bytes())?,
        Hash32V0::new(*header.evidence_root().as_bytes()),
    )?)
}

/// Bind an authenticated historical header to the actual retained JMT version
/// and canonical cutoff namespace, using the active old epoch configuration.
fn validate_cutoff(
    store: &InMemoryNativeExecutionStoreV0,
    activation: &StrictSameVersionEpochActivationAuthorityV0,
    source_height: u64,
    source_cutoff_headers: &[BlockHeader],
    verified: &StrictHistoricalHeaderPathV1,
) -> Result<()> {
    let set = activation.old_validator_set();
    let parameters = activation.old_consensus_parameters();
    let geometry = protocol(EpochGeometryV0::new(set.epoch(), parameters))?;
    let cutoff = geometry
        .checkpoint_height()
        .get()
        .checked_sub(parameters.snapshot_lead_blocks())
        .context("historical replay cutoff underflow")?;
    let fields = activation.next_epoch_commitment().fields();
    ensure!(
        fields.snapshot_cutoff_height.get() == cutoff,
        "historical replay cutoff geometry"
    );
    let candidates = if cutoff <= source_height {
        source_cutoff_headers
    } else {
        verified.headers()
    };
    let mut matching = candidates
        .iter()
        .filter(|header| header.height().get() == cutoff);
    let header = matching
        .next()
        .context("historical replay missing authenticated cutoff header")?;
    ensure!(
        matching.next().is_none(),
        "historical replay ambiguous cutoff header"
    );
    ensure!(
        header.block_kind() == BlockKind::Regular
            && header.genesis_hash() == set.genesis_hash()
            && header.chain_id() == set.chain_id()
            && header.protocol_version() == set.protocol_version()
            && header.epoch() == set.epoch()
            && header.validator_set_id() == set.id()
            && header.consensus_parameters_hash() == parameters.hash()
            && header.state_root() == fields.snapshot_state_root,
        "historical replay cutoff header/context mismatch"
    );
    ensure!(
        jmt::Sha256Jmt::new(store).get_root_hash(cutoff)?.0 == *header.state_root().as_bytes(),
        "historical replay cutoff JMT root mismatch"
    );
    let mut live = store.verified_live_values_v0(cutoff)?;
    let lifecycle = load_validator_lifecycle_from_live_v0(&live, cutoff)?;
    let projection = take_and_validate_production_poco_projection_v0(cutoff, &mut live)?
        .context("historical replay cutoff lacks PoCO namespace")?;
    ensure!(
        projection.manifest().cutoff_height().get() == cutoff,
        "historical replay cutoff manifest height"
    );
    let (actual_set, actual_parameters) = active_consensus_configuration(&projection)?;
    ensure!(
        &actual_set == set && &actual_parameters == parameters,
        "historical replay cutoff active configuration"
    );
    validate_application_validator_projection(set, &lifecycle.active_validators)?;
    let computed = crate::poco_application::derive_poco_next_epoch_from_cutoff_v1(
        &projection,
        header.state_root(),
        set,
        parameters,
    )?;
    ensure!(
        computed.new_validator_set == *activation.new_validator_set()
            && computed.new_parameters == *activation.new_consensus_parameters()
            && computed.commitment == *activation.next_epoch_commitment(),
        "historical replay activation differs from deterministic cutoff selection"
    );
    Ok(())
}

fn step_head(
    run_digest: [u8; 32],
    ordinal: usize,
    parent: &ApplicationHeadV0,
    header: &BlockHeader,
    artifact: &[u8],
) -> Result<ApplicationHeadV0> {
    use sha2::{Digest, Sha256};
    let artifact_digest: [u8; 32] = Sha256::digest(artifact).into();
    let mut parent_bytes = Vec::with_capacity(104);
    parent_bytes.extend_from_slice(&parent.height().get().to_be_bytes());
    parent_bytes.extend_from_slice(parent.block_id().as_bytes());
    parent_bytes.extend_from_slice(parent.state_root().as_bytes());
    parent_bytes.extend_from_slice(parent.commit_id().as_bytes());
    let commit = hash_domain(
        "trnm.native.historical-replay-step.v1",
        &[
            &run_digest,
            &(ordinal as u64).to_be_bytes(),
            &parent_bytes,
            header.id().as_bytes(),
            &artifact_digest,
        ],
    );
    Ok(ApplicationHeadV0::new(
        HeightV0::new(header.height().get()),
        BlockIdV0::new(*header.id().as_bytes())?,
        StateRootV0::new(*header.state_root().as_bytes())?,
        ApplicationCommitIdV0::new(commit)?,
    ))
}

/// The same deterministic replay, retaining its store and exact mixed source /
/// historical coordinates for the owner's independently audited continuation.
#[allow(clippy::too_many_arguments)]
#[inline(never)]
pub(super) fn replay_verified_history_state_v1(
    mut store: InMemoryNativeExecutionStoreV0,
    source_head: ApplicationHeadV0,
    source_header: &BlockHeader,
    source_set: &ValidatorSet,
    source_contexts: &[&dyn EpochExecutionContextV1],
    source_cutoff_headers: &[BlockHeader],
    history: &NativeHistoricalReplayV1,
    verified: &StrictHistoricalHeaderPathV1,
    run_digest: [u8; 32],
) -> Result<ReplayedHistoricalStateV1> {
    ensure!(
        run_digest != [0; 32],
        "historical replay missing run identity"
    );
    ensure!(
        source_cutoff_headers.len() <= 32 && source_contexts.len() <= 32,
        "historical replay source cutoff bound"
    );
    ensure!(
        !history.records.is_empty()
            && history.records.len() <= 256
            && verified.headers().len() == history.records.len()
            && verified.activations().len() == history.activations.len()
            && verified.activations().len() <= 32,
        "historical replay input/path counts"
    );
    ensure_head_header(&source_head, source_header)?;
    ensure!(
        history.anchor_header_cev0 == protocol(source_header.try_cev0_bytes())?,
        "historical replay source anchor bytes"
    );
    ensure!(
        history.terminal_finality_cev0 == protocol(verified.terminal_proof().try_cev0_bytes())?,
        "historical replay terminal proof bytes"
    );
    let (version, root) = crate::store::verify_parent_root_v0(&store)?;
    ensure!(
        version == source_head.height().get() && root.0 == *source_head.state_root().as_bytes(),
        "historical replay source store head"
    );
    let mut active_set = source_set;
    let mut active_parameters = store.consensus_parameters_v0()?;
    protocol(active_set.validate_against_parameters(&active_parameters))?;
    ensure!(
        source_header.validator_set_id() == active_set.id()
            && source_header.consensus_parameters_hash() == active_parameters.hash(),
        "historical replay source configuration"
    );
    let mut head = source_head.clone();
    let mut previous = source_header;
    let mut contexts = Vec::new();
    let mut next_activation = 0usize;
    let mut application_count = 0usize;
    let mut final_lifecycle = None;
    for (ordinal, (record, header)) in history.records.iter().zip(verified.headers()).enumerate() {
        ensure!(
            record.header_cev0() == protocol(header.try_cev0_bytes())?,
            "historical replay header bytes differ from strict path"
        );
        ensure!(
            header.parent_id() == previous.id()
                && previous.height().get().checked_add(1) == Some(header.height().get()),
            "historical replay disconnected source/history"
        );
        previous = header;
        let payload = match record {
            NativeHistoricalRecordV1::Seal { .. } => {
                ensure!(
                    matches!(
                        header.block_kind(),
                        BlockKind::EpochSeal1 | BlockKind::EpochSeal2
                    ),
                    "historical replay seal tag mismatch"
                );
                continue;
            }
            NativeHistoricalRecordV1::Application {
                application_payload_cev0,
                ..
            } => {
                ensure!(
                    !matches!(
                        header.block_kind(),
                        BlockKind::EpochSeal1 | BlockKind::EpochSeal2
                    ),
                    "historical replay application tag mismatch"
                );
                application_payload_cev0
            }
        };
        if header.block_kind() == BlockKind::EpochHandoff {
            let activation = verified
                .activations()
                .get(next_activation)
                .context("historical replay missing activation")?
                .as_ref();
            ensure!(
                activation.old_validator_set() == active_set
                    && activation.old_consensus_parameters() == &active_parameters,
                "historical replay activation old trust"
            );
            validate_cutoff(
                &store,
                activation,
                source_head.height().get(),
                source_cutoff_headers,
                verified,
            )?;
            let context = ReplayEpochContextV1::new(head.clone(), activation)?;
            ensure!(
                header.parent_id() == context.consensus_parent_v1().id()
                    && header.height().get() == context.first_application_height_v1(),
                "historical replay handoff geometry"
            );
            active_set = activation.new_validator_set();
            active_parameters = *activation.new_consensus_parameters();
            contexts.push(context);
            next_activation += 1;
        }
        let block = protocol(Block::new(header.clone(), payload.clone(), Vec::new()))?;
        if header.block_kind() == BlockKind::Regular {
            protocol(validate_root_bound_regular_body_v0(
                &block,
                active_set,
                &active_parameters,
            ))?;
        } else {
            protocol(validate_root_bound_epoch_body_v1(
                &block,
                active_set,
                &active_parameters,
            ))?;
        }
        if header.block_kind() == BlockKind::EpochCheckpoint {
            let successor = verified
                .activations()
                .get(next_activation)
                .context("historical replay checkpoint lacks complete activation evidence")?;
            ensure!(
                successor
                    .old_checkpoint_finality()
                    .finalized_block()
                    .header()
                    == header
                    && successor
                        .authenticated_checkpoint_parent_header()
                        .id()
                        .as_bytes()
                        == head.block_id().as_bytes(),
                "historical replay checkpoint exact authority"
            );
            validate_cutoff(
                &store,
                successor,
                source_head.height().get(),
                source_cutoff_headers,
                verified,
            )?;
        }
        let transactions = protocol(decode_application_payload_v0_exact(
            payload,
            &active_parameters,
        ))?
        .transactions()
        .to_vec();
        let expected = expected_roots(header)?;
        let (artifact, plan, replay, lifecycle) = if header.block_kind() == BlockKind::EpochHandoff
        {
            let context = contexts
                .last()
                .context("historical replay epoch computation context")?;
            let preview = NativeEpochBlockPreviewRequestV1::new(
                ChainIdV0::new(header.chain_id().as_str())?,
                GenesisHashV0::new(*header.genesis_hash().as_bytes())?,
                head.clone(),
                BlockIdV0::new(*context.consensus_parent_v1().id().as_bytes())?,
                HeightV0::new(context.consensus_parent_v1().height().get()),
                Hash32V0::new(context.authorization_id_v1()),
                HeightV0::new(header.height().get()),
                header.timestamp_ms(),
                ValidatorSetIdV0::new(*active_set.id().as_bytes())?,
                transactions,
            )?;
            let computed =
                compute_complete_epoch_native_block_with_context_v1(&store, context, &preview)?;
            let computed_roots = NativeExpectedBlockCommitmentsV0::new(
                Hash32V0::new(computed.payload_root),
                StateRootV0::new(computed.post_state_root)?,
                ReceiptsRootV0::new(computed.receipts_root)?,
                Hash32V0::new(computed.evidence_root),
            )?;
            let request = NativeEpochBlockExecutionRequestV1::new(
                preview,
                BlockIdV0::new(*header.id().as_bytes())?,
                expected,
            )?;
            let executed =
                NativeExecutedEpochBlockV1::new(request, computed_roots, computed.native_receipts)?;
            (
                encode_native_executed_epoch_block_artifact_v1(&executed)?,
                computed.plan,
                computed.replay_identities,
                computed.final_lifecycle,
            )
        } else {
            ensure!(
                header.parent_id().as_bytes() == head.block_id().as_bytes(),
                "historical replay ordinary application parent"
            );
            let request = NativeBlockExecutionRequestV0::new(
                ChainIdV0::new(header.chain_id().as_str())?,
                GenesisHashV0::new(*header.genesis_hash().as_bytes())?,
                head.clone(),
                BlockIdV0::new(*header.id().as_bytes())?,
                HeightV0::new(header.height().get()),
                header.timestamp_ms(),
                ValidatorSetIdV0::new(*active_set.id().as_bytes())?,
                transactions,
                expected,
            )?;
            let (executed, plan, replay, lifecycle) = execute_complete_native_block_v0(
                &store,
                active_set,
                active_set.genesis_hash(),
                &request,
            )?
            .into_parts();
            (
                encode_native_executed_block_artifact_v0(&executed)?,
                plan,
                replay,
                lifecycle,
            )
        };
        ensure!(
            artifact.len() <= 16 * 1024 * 1024,
            "historical replay artifact bound"
        );
        store.apply_complete_state_plan_v0(plan)?;
        for identity in replay {
            store.mark_committed_command_v0(
                identity.command_id(),
                identity.signer_id(),
                identity.nonce(),
            )?;
        }
        head = step_head(run_digest, ordinal, &head, header, &artifact)?;
        application_count += 1;
        final_lifecycle = Some(lifecycle);
    }
    ensure!(
        next_activation == verified.activations().len() && application_count > 0,
        "historical replay unused activation/application count"
    );
    ensure_head_header(&head, verified.terminal_header())?;
    ensure!(
        active_set == verified.terminal_validator_set()
            && active_parameters == *verified.terminal_parameters(),
        "historical replay terminal configuration"
    );
    let mut all_contexts = source_contexts.to_vec();
    all_contexts.extend(
        contexts
            .iter()
            .map(|context| context as &dyn EpochExecutionContextV1),
    );
    let snapshot = store.encode_epoch_authenticated_snapshot_for_context_v1(&all_contexts)?;
    let coordinates = all_contexts
        .iter()
        .map(|context| context.coordinates_v1())
        .collect();
    ensure!(
        snapshot.len() <= 256 * 1024 * 1024,
        "historical replay snapshot bound"
    );
    let (commands, nonces) = store.replay_sets_v0();
    let commands = borsh::to_vec(commands)?;
    let nonces = borsh::to_vec(nonces)?;
    ensure!(
        commands.len() <= 16 * 1024 * 1024 && nonces.len() <= 16 * 1024 * 1024,
        "historical replay identity bound"
    );
    let lifecycle =
        serde_json::to_vec(&final_lifecycle.context("historical replay missing lifecycle")?)?;
    ensure!(
        lifecycle.len() <= 1024 * 1024,
        "historical replay lifecycle bound"
    );
    let computed = ComputedHistoricalReplayV1 {
        target_head: head,
        target_header: verified.terminal_header().clone(),
        target_set: active_set.clone(),
        target_parameters: active_parameters,
        snapshot,
        commands,
        nonces,
        lifecycle,
        application_count,
    };
    Ok(ReplayedHistoricalStateV1 {
        computed,
        store,
        coordinates,
    })
}
