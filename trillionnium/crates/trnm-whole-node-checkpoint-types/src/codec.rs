use alloc::vec::Vec;

use sha2::{Digest, Sha256};
use trnm_consensus_types::{
    BlockId, ChainId, ConsensusParametersHash, Epoch, EvidenceRoot, GenesisHash, Height,
    PayloadDigest, ProtocolVersion, ReceiptsRoot, SigningRoot, StateRoot, ValidatorId,
    ValidatorSetId, View, MAX_CONSENSUS_STRING_BYTES, MAX_VALIDATOR_ID_BYTES,
};

use crate::{
    model::WholeNodeCheckpointPartsV1, AppAttestorCutRefV1, ApplicationCutRefV1,
    ApplicationValidationCutRefV1, ApplicationValidationGenerationV1,
    ApplicationValidationLineageCutRefV1, ChainCutRefV1, CoreSafetyCutRefV1, ProcessFenceRefV1,
    ProcessFencesCutRefV1, ProcessGenerationV1, RemoteSafetyCutRefV1, RoleBindingsCutRefV1,
    SignOperationCutRefV1, SignOperationKindV1, SignerCutRefV1, SignerJournalStateV1,
    WholeNodeCheckpointChecksumV1, WholeNodeCheckpointErrorV1, WholeNodeCheckpointGenerationV1,
    WholeNodeCheckpointPhaseV1, WholeNodeCheckpointResultV1, WholeNodeCheckpointScopeV1,
    WholeNodeCheckpointV1, WholeNodeCutDigestV1, WHOLE_NODE_CHECKPOINT_SCHEMA_V1,
};

const RECORD_MAGIC_V1: &[u8; 8] = b"TRNMWC01";
const CHECKSUM_DOMAIN_V1: &[u8] = b"trnm.whole-node-checkpoint.value.v1\0";

/// Hard bound checked before allocation-heavy exact decoding.
pub const MAX_WHOLE_NODE_CHECKPOINT_BYTES_V1: usize = 4096;

impl WholeNodeCheckpointV1 {
    /// Returns the complete canonical record including its checksum.
    pub fn try_exact_bytes(&self) -> WholeNodeCheckpointResultV1<Vec<u8>> {
        self.validate_local_shape()?;
        let mut encoded = encode_checkpoint_prefix_v1(self)?;
        encoded.extend_from_slice(self.checkpoint_checksum().as_bytes());
        if encoded.len() > MAX_WHOLE_NODE_CHECKPOINT_BYTES_V1 {
            return Err(WholeNodeCheckpointErrorV1::LengthLimitExceeded);
        }
        Ok(encoded)
    }
}

pub(crate) fn recompute_checkpoint_checksum_v1(
    checkpoint: &WholeNodeCheckpointV1,
) -> WholeNodeCheckpointResultV1<WholeNodeCheckpointChecksumV1> {
    let prefix = encode_checkpoint_prefix_v1(checkpoint)?;
    let mut hash = Sha256::new();
    hash.update(CHECKSUM_DOMAIN_V1);
    hash.update(
        u32::try_from(prefix.len())
            .map_err(|_| WholeNodeCheckpointErrorV1::LengthLimitExceeded)?
            .to_be_bytes(),
    );
    hash.update(&prefix);
    WholeNodeCheckpointChecksumV1::from_exact_bytes(hash.finalize().into()).map_err(Into::into)
}

pub(crate) fn encode_checkpoint_prefix_v1(
    checkpoint: &WholeNodeCheckpointV1,
) -> WholeNodeCheckpointResultV1<Vec<u8>> {
    if !checkpoint.phase().is_signing_cycle_record_phase() {
        return Err(WholeNodeCheckpointErrorV1::InvalidPhaseShape(
            "epoch-transition reference-only phase",
        ));
    }
    let mut encoded = Vec::with_capacity(MAX_WHOLE_NODE_CHECKPOINT_BYTES_V1);
    encoded.extend_from_slice(RECORD_MAGIC_V1);
    encoded.extend_from_slice(&WHOLE_NODE_CHECKPOINT_SCHEMA_V1.to_be_bytes());
    encoded.push(checkpoint.phase().tag());
    encoded.extend_from_slice(&checkpoint.generation().get().to_be_bytes());
    encode_option_checksum_v1(&mut encoded, checkpoint.predecessor_checksum());
    encoded.extend_from_slice(checkpoint.scope().as_bytes());
    encode_chain_v1(&mut encoded, checkpoint.chain())?;
    encode_fences_v1(&mut encoded, checkpoint.fences());
    encode_roles_v1(&mut encoded, checkpoint.roles());
    encode_core_safety_v1(&mut encoded, checkpoint.core_safety());
    encode_application_v1(&mut encoded, checkpoint.application());
    encode_application_attestor_v1(&mut encoded, checkpoint.application_attestor());
    encode_remote_safety_v1(&mut encoded, checkpoint.remote_safety());
    encode_signer_v1(&mut encoded, checkpoint.signer());
    encode_option_operation_v1(&mut encoded, checkpoint.operation());
    if encoded
        .len()
        .checked_add(32)
        .ok_or(WholeNodeCheckpointErrorV1::LengthLimitExceeded)?
        > MAX_WHOLE_NODE_CHECKPOINT_BYTES_V1
    {
        return Err(WholeNodeCheckpointErrorV1::LengthLimitExceeded);
    }
    Ok(encoded)
}

fn encode_chain_v1(encoded: &mut Vec<u8>, chain: ChainCutRefV1) -> WholeNodeCheckpointResultV1<()> {
    encoded.extend_from_slice(chain.genesis_hash().as_bytes());
    encode_bounded_bytes_u16_v1(encoded, chain.chain_id().as_bytes())?;
    encoded.extend_from_slice(&chain.protocol_version().get().to_be_bytes());
    encoded.extend_from_slice(&chain.epoch().get().to_be_bytes());
    encoded.extend_from_slice(chain.validator_set_id().as_bytes());
    encoded.extend_from_slice(chain.consensus_parameters_hash().as_bytes());
    encode_bounded_bytes_u16_v1(encoded, chain.author().as_bytes())
}

fn encode_fences_v1(encoded: &mut Vec<u8>, fences: ProcessFencesCutRefV1) {
    encode_process_fence_v1(encoded, fences.node());
    encode_process_fence_v1(encoded, fences.application_attestor());
    encode_process_fence_v1(encoded, fences.remote_signer());
}

fn encode_process_fence_v1(encoded: &mut Vec<u8>, fence: ProcessFenceRefV1) {
    encoded.extend_from_slice(&fence.process_generation().get().to_be_bytes());
    encode_digest_v1(encoded, fence.lease_id());
    encode_digest_v1(encoded, fence.lease_grant_checksum());
    encode_digest_v1(encoded, fence.external_fence_head_checksum());
}

fn encode_roles_v1(encoded: &mut Vec<u8>, roles: RoleBindingsCutRefV1) {
    for digest in [
        roles.node_role_bindings_checksum(),
        roles.node_adapter_checksum(),
        roles.consensus_purpose_profile_digest(),
        roles.remote_role_profile_ref(),
        roles.remote_service_profile_ref(),
        roles.remote_client_profile_ref(),
        roles.application_attestor_role_profile_ref(),
        roles.application_validation_purpose_profile_digest(),
        roles.application_attestor_public_key_ref(),
    ] {
        encode_digest_v1(encoded, digest);
    }
}

fn encode_core_safety_v1(encoded: &mut Vec<u8>, core: CoreSafetyCutRefV1) {
    encode_digest_v1(encoded, core.journal_id());
    encode_digest_v1(encoded, core.verifier_profile_ref());
    encode_digest_v1(encoded, core.config_ref());
    encoded.extend_from_slice(&core.revision().to_be_bytes());
    encode_digest_v1(encoded, core.state_record_checksum());
    encode_digest_v1(encoded, core.record_chain_checksum());
    encode_digest_v1(encoded, core.active_head_checksum());
    encode_option_digest_v1(encoded, core.checkpoint_predecessor_head_checksum());
    encode_option_digest_v1(encoded, core.pending_intent_checksum());
}

fn encode_application_v1(encoded: &mut Vec<u8>, application: ApplicationCutRefV1) {
    for digest in [
        application.host_config_ref(),
        application.projection_profile_ref(),
        application.safety_binding_manifest_checksum(),
        application.store_scope(),
    ] {
        encode_digest_v1(encoded, digest);
    }
    encoded.extend_from_slice(&application.committed_sequence().to_be_bytes());
    encode_digest_v1(encoded, application.committed_head_row_checksum());
    encode_digest_v1(encoded, application.recovery_closure_checksum());
    encode_digest_v1(encoded, application.active_head_checksum());
    encode_option_digest_v1(encoded, application.checkpoint_predecessor_head_checksum());
    encoded.extend_from_slice(application.block_id().as_bytes());
    encoded.extend_from_slice(&application.height().get().to_be_bytes());
    encoded.extend_from_slice(application.state_root().as_bytes());
    encoded.extend_from_slice(&application.view().get().to_be_bytes());
    encoded.extend_from_slice(&application.timestamp_ms().to_be_bytes());
    encode_option_application_validation_lineage_v1(encoded, application.validation_lineage());
    encode_option_application_validation_v1(encoded, application.validation());
}

fn encode_option_application_validation_lineage_v1(
    encoded: &mut Vec<u8>,
    lineage: Option<ApplicationValidationLineageCutRefV1>,
) {
    match lineage {
        None => encoded.push(0),
        Some(lineage) => {
            encoded.push(1);
            encode_digest_v1(encoded, lineage.validation_store_scope());
            encoded.extend_from_slice(&lineage.last_generation().get().to_be_bytes());
            encode_digest_v1(encoded, lineage.last_validation_id());
            encode_digest_v1(encoded, lineage.record_chain_checksum());
            encode_digest_v1(encoded, lineage.active_head_checksum());
        }
    }
}

fn encode_option_application_validation_v1(
    encoded: &mut Vec<u8>,
    validation: Option<ApplicationValidationCutRefV1>,
) {
    let Some(validation) = validation else {
        encoded.push(0);
        return;
    };
    encoded.push(1);
    encoded.extend_from_slice(&validation.generation().get().to_be_bytes());
    encode_digest_v1(encoded, validation.validation_store_scope());
    encode_digest_v1(encoded, validation.validation_id());
    encode_digest_v1(encoded, validation.validation_record_chain_checksum());
    encode_digest_v1(encoded, validation.validation_active_head_checksum());
    encode_option_digest_v1(
        encoded,
        validation.validation_predecessor_record_chain_checksum(),
    );
    encode_option_digest_v1(
        encoded,
        validation.validation_predecessor_active_head_checksum(),
    );
    encoded.extend_from_slice(validation.block_id().as_bytes());
    encoded.extend_from_slice(validation.parent_block_id().as_bytes());
    encoded.extend_from_slice(&validation.height().get().to_be_bytes());
    encoded.extend_from_slice(&validation.view().get().to_be_bytes());
    encoded.extend_from_slice(validation.payload_digest().as_bytes());
    encoded.extend_from_slice(validation.result_state_root().as_bytes());
    encoded.extend_from_slice(validation.receipts_root().as_bytes());
    encoded.extend_from_slice(validation.evidence_root().as_bytes());
    encode_digest_v1(encoded, validation.overlay_checksum());
    encode_digest_v1(encoded, validation.source_artifact_checksum());
    encode_digest_v1(encoded, validation.validation_artifact_checksum());
    encode_digest_v1(encoded, validation.application_head_checksum());
    encode_digest_v1(encoded, validation.core_safety_record_checksum());
    encoded.extend_from_slice(validation.whole_node_predecessor_checksum().as_bytes());
    encode_digest_v1(encoded, validation.statement_digest());
}

fn encode_application_attestor_v1(encoded: &mut Vec<u8>, attestor: AppAttestorCutRefV1) {
    encode_digest_v1(encoded, attestor.journal_id());
    encode_digest_v1(encoded, attestor.profile_checksum());
    encode_digest_v1(encoded, attestor.store_scope());
    encoded.extend_from_slice(&attestor.sequence().to_be_bytes());
    encode_digest_v1(encoded, attestor.record_checksum());
    encode_digest_v1(encoded, attestor.record_chain_checksum());
    encode_digest_v1(encoded, attestor.active_head_checksum());
    encode_option_digest_v1(encoded, attestor.checkpoint_predecessor_head_checksum());
    encode_option_digest_v1(encoded, attestor.attestation_digest());
}

fn encode_remote_safety_v1(encoded: &mut Vec<u8>, remote: RemoteSafetyCutRefV1) {
    encode_digest_v1(encoded, remote.store_scope());
    encode_digest_v1(encoded, remote.journal_id());
    encode_digest_v1(encoded, remote.profile_checksum());
    encoded.extend_from_slice(&remote.revision().to_be_bytes());
    encode_digest_v1(encoded, remote.state_digest());
    encode_digest_v1(encoded, remote.record_checksum());
    encode_digest_v1(encoded, remote.record_chain_checksum());
    encode_digest_v1(encoded, remote.active_head_checksum());
    encode_option_digest_v1(encoded, remote.checkpoint_predecessor_head_checksum());
    encode_option_digest_v1(encoded, remote.prepared_transition_digest());
}

fn encode_signer_v1(encoded: &mut Vec<u8>, signer: SignerCutRefV1) {
    encode_digest_v1(encoded, signer.journal_id());
    encode_digest_v1(encoded, signer.profile_checksum());
    encode_digest_v1(encoded, signer.store_scope());
    encoded.extend_from_slice(&signer.sequence().to_be_bytes());
    encode_digest_v1(encoded, signer.event_checksum());
    encode_digest_v1(encoded, signer.record_chain_checksum());
    encode_digest_v1(encoded, signer.active_head_checksum());
    encode_option_digest_v1(encoded, signer.checkpoint_predecessor_head_checksum());
    encoded.push(signer.state().tag());
    encode_option_digest_v1(encoded, signer.request_fingerprint());
    encode_option_digest_v1(encoded, signer.signature_digest());
}

fn encode_option_operation_v1(encoded: &mut Vec<u8>, operation: Option<SignOperationCutRefV1>) {
    let Some(operation) = operation else {
        encoded.push(0);
        return;
    };
    encoded.push(1);
    encoded.push(operation.kind().tag());
    encode_digest_v1(encoded, operation.operation_id());
    encode_digest_v1(encoded, operation.request_nonce());
    encode_digest_v1(encoded, operation.request_fingerprint());
    encode_digest_v1(encoded, operation.canonical_intent_checksum());
    encoded.extend_from_slice(operation.signing_root().as_bytes());
    encode_digest_v1(encoded, operation.safety_transition_digest());
    encoded.extend_from_slice(operation.cycle_predecessor_checkpoint_checksum().as_bytes());
    encode_option_digest_v1(encoded, operation.application_validation_statement_digest());
}

fn encode_option_checksum_v1(
    encoded: &mut Vec<u8>,
    checksum: Option<WholeNodeCheckpointChecksumV1>,
) {
    match checksum {
        None => encoded.push(0),
        Some(checksum) => {
            encoded.push(1);
            encoded.extend_from_slice(checksum.as_bytes());
        }
    }
}

fn encode_option_digest_v1(encoded: &mut Vec<u8>, digest: Option<WholeNodeCutDigestV1>) {
    match digest {
        None => encoded.push(0),
        Some(digest) => {
            encoded.push(1);
            encode_digest_v1(encoded, digest);
        }
    }
}

fn encode_digest_v1(encoded: &mut Vec<u8>, digest: WholeNodeCutDigestV1) {
    encoded.extend_from_slice(digest.as_bytes());
}

fn encode_bounded_bytes_u16_v1(
    encoded: &mut Vec<u8>,
    bytes: &[u8],
) -> WholeNodeCheckpointResultV1<()> {
    encoded.extend_from_slice(
        &u16::try_from(bytes.len())
            .map_err(|_| WholeNodeCheckpointErrorV1::LengthLimitExceeded)?
            .to_be_bytes(),
    );
    encoded.extend_from_slice(bytes);
    Ok(())
}

/// Strictly decodes one complete, bounded, canonical data record.
///
/// Success authenticates neither the referenced cuts nor their persistence.
pub fn decode_whole_node_checkpoint_v1_exact(
    encoded: &[u8],
) -> WholeNodeCheckpointResultV1<WholeNodeCheckpointV1> {
    if encoded.len() > MAX_WHOLE_NODE_CHECKPOINT_BYTES_V1 {
        return Err(WholeNodeCheckpointErrorV1::LengthLimitExceeded);
    }
    let mut cursor = CursorV1::new(encoded);
    if cursor.take_array::<8>()? != *RECORD_MAGIC_V1 {
        return Err(WholeNodeCheckpointErrorV1::WrongMagic);
    }
    if cursor.read_u16()? != WHOLE_NODE_CHECKPOINT_SCHEMA_V1 {
        return Err(WholeNodeCheckpointErrorV1::UnsupportedSchema);
    }
    let phase = WholeNodeCheckpointPhaseV1::from_tag(cursor.read_u8()?)?;
    if !phase.is_signing_cycle_record_phase() {
        return Err(WholeNodeCheckpointErrorV1::InvalidPhaseShape(
            "epoch-transition reference-only phase",
        ));
    }
    let generation = WholeNodeCheckpointGenerationV1::new(cursor.read_u64()?);
    let predecessor_checksum = decode_option_checksum_v1(&mut cursor, "predecessor checksum")?;
    let scope = WholeNodeCheckpointScopeV1::from_exact_bytes(cursor.take_array::<32>()?)?;
    let chain = decode_chain_v1(&mut cursor)?;
    let fences = decode_fences_v1(&mut cursor)?;
    let roles = decode_roles_v1(&mut cursor)?;
    let core_safety = decode_core_safety_v1(&mut cursor)?;
    let application = decode_application_v1(&mut cursor)?;
    let application_attestor = decode_application_attestor_v1(&mut cursor)?;
    let remote_safety = decode_remote_safety_v1(&mut cursor)?;
    let signer = decode_signer_v1(&mut cursor)?;
    let operation = decode_option_operation_v1(&mut cursor)?;
    let checkpoint_checksum =
        WholeNodeCheckpointChecksumV1::from_exact_bytes(cursor.take_array::<32>()?)?;
    if !cursor.is_finished() {
        return Err(WholeNodeCheckpointErrorV1::TrailingBytes);
    }

    let value = WholeNodeCheckpointV1::from_decoded_parts(
        WholeNodeCheckpointPartsV1 {
            scope,
            generation,
            phase,
            predecessor_checksum,
            chain,
            fences,
            roles,
            core_safety,
            application,
            application_attestor,
            remote_safety,
            signer,
            operation,
        },
        checkpoint_checksum,
    )?;
    if recompute_checkpoint_checksum_v1(&value)? != checkpoint_checksum {
        return Err(WholeNodeCheckpointErrorV1::ChecksumMismatch);
    }
    if value.try_exact_bytes()?.as_slice() != encoded {
        return Err(WholeNodeCheckpointErrorV1::NonCanonicalEncoding);
    }
    Ok(value)
}

fn decode_chain_v1(cursor: &mut CursorV1<'_>) -> WholeNodeCheckpointResultV1<ChainCutRefV1> {
    let genesis_hash = GenesisHash::new(cursor.take_array::<32>()?);
    let chain_length = cursor.read_u16()? as usize;
    if chain_length == 0 || chain_length > MAX_CONSENSUS_STRING_BYTES {
        return Err(WholeNodeCheckpointErrorV1::InvalidField("chain id length"));
    }
    let chain_id = ChainId::from_bytes(cursor.take(chain_length)?)
        .map_err(|_| WholeNodeCheckpointErrorV1::InvalidField("chain id"))?;
    let protocol_version = ProtocolVersion::new(cursor.read_u32()?)
        .map_err(|_| WholeNodeCheckpointErrorV1::InvalidField("protocol version"))?;
    let epoch = Epoch::new(cursor.read_u64()?);
    let validator_set_id = ValidatorSetId::new(cursor.take_array::<32>()?);
    let consensus_parameters_hash = ConsensusParametersHash::new(cursor.take_array::<32>()?);
    let author_length = cursor.read_u16()? as usize;
    if author_length == 0 || author_length > MAX_VALIDATOR_ID_BYTES {
        return Err(WholeNodeCheckpointErrorV1::InvalidField("author length"));
    }
    let author = ValidatorId::from_bytes(cursor.take(author_length)?)
        .map_err(|_| WholeNodeCheckpointErrorV1::InvalidField("author"))?;
    ChainCutRefV1::new(
        genesis_hash,
        chain_id,
        protocol_version,
        epoch,
        validator_set_id,
        consensus_parameters_hash,
        author,
    )
}

fn decode_fences_v1(
    cursor: &mut CursorV1<'_>,
) -> WholeNodeCheckpointResultV1<ProcessFencesCutRefV1> {
    Ok(ProcessFencesCutRefV1::new(
        decode_process_fence_v1(cursor)?,
        decode_process_fence_v1(cursor)?,
        decode_process_fence_v1(cursor)?,
    ))
}

fn decode_process_fence_v1(
    cursor: &mut CursorV1<'_>,
) -> WholeNodeCheckpointResultV1<ProcessFenceRefV1> {
    Ok(ProcessFenceRefV1::new(
        ProcessGenerationV1::new(cursor.read_u64()?)?,
        decode_digest_v1(cursor)?,
        decode_digest_v1(cursor)?,
        decode_digest_v1(cursor)?,
    ))
}

fn decode_roles_v1(cursor: &mut CursorV1<'_>) -> WholeNodeCheckpointResultV1<RoleBindingsCutRefV1> {
    Ok(RoleBindingsCutRefV1::new(
        decode_digest_v1(cursor)?,
        decode_digest_v1(cursor)?,
        decode_digest_v1(cursor)?,
        decode_digest_v1(cursor)?,
        decode_digest_v1(cursor)?,
        decode_digest_v1(cursor)?,
        decode_digest_v1(cursor)?,
        decode_digest_v1(cursor)?,
        decode_digest_v1(cursor)?,
    ))
}

fn decode_core_safety_v1(
    cursor: &mut CursorV1<'_>,
) -> WholeNodeCheckpointResultV1<CoreSafetyCutRefV1> {
    Ok(CoreSafetyCutRefV1::new(
        decode_digest_v1(cursor)?,
        decode_digest_v1(cursor)?,
        decode_digest_v1(cursor)?,
        cursor.read_u64()?,
        decode_digest_v1(cursor)?,
        decode_digest_v1(cursor)?,
        decode_digest_v1(cursor)?,
        decode_option_digest_v1(cursor, "Core checkpoint predecessor")?,
        decode_option_digest_v1(cursor, "Core pending intent")?,
    ))
}

fn decode_application_v1(
    cursor: &mut CursorV1<'_>,
) -> WholeNodeCheckpointResultV1<ApplicationCutRefV1> {
    ApplicationCutRefV1::new(
        decode_digest_v1(cursor)?,
        decode_digest_v1(cursor)?,
        decode_digest_v1(cursor)?,
        decode_digest_v1(cursor)?,
        cursor.read_u64()?,
        decode_digest_v1(cursor)?,
        decode_digest_v1(cursor)?,
        decode_digest_v1(cursor)?,
        decode_option_digest_v1(cursor, "Application checkpoint predecessor")?,
        BlockId::new(cursor.take_array::<32>()?),
        Height::new(cursor.read_u64()?),
        StateRoot::new(cursor.take_array::<32>()?),
        View::new(cursor.read_u64()?),
        cursor.read_u64()?,
        decode_option_application_validation_lineage_v1(cursor)?,
        decode_option_application_validation_v1(cursor)?,
    )
}

fn decode_option_application_validation_lineage_v1(
    cursor: &mut CursorV1<'_>,
) -> WholeNodeCheckpointResultV1<Option<ApplicationValidationLineageCutRefV1>> {
    match cursor.read_u8()? {
        0 => Ok(None),
        1 => Ok(Some(ApplicationValidationLineageCutRefV1::new(
            decode_digest_v1(cursor)?,
            ApplicationValidationGenerationV1::new(cursor.read_u64()?)?,
            decode_digest_v1(cursor)?,
            decode_digest_v1(cursor)?,
            decode_digest_v1(cursor)?,
        ))),
        _ => Err(WholeNodeCheckpointErrorV1::ReservedTag(
            "Application validation lineage",
        )),
    }
}

fn decode_option_application_validation_v1(
    cursor: &mut CursorV1<'_>,
) -> WholeNodeCheckpointResultV1<Option<ApplicationValidationCutRefV1>> {
    match cursor.read_u8()? {
        0 => Ok(None),
        1 => {
            let generation = ApplicationValidationGenerationV1::new(cursor.read_u64()?)?;
            let validation_store_scope = decode_digest_v1(cursor)?;
            let validation_id = decode_digest_v1(cursor)?;
            let validation_record_chain_checksum = decode_digest_v1(cursor)?;
            let validation_active_head_checksum = decode_digest_v1(cursor)?;
            let validation_predecessor_record_chain_checksum =
                decode_option_digest_v1(cursor, "validation predecessor record chain")?;
            let validation_predecessor_active_head_checksum =
                decode_option_digest_v1(cursor, "validation predecessor active head")?;
            let block_id = BlockId::new(cursor.take_array::<32>()?);
            let parent_block_id = BlockId::new(cursor.take_array::<32>()?);
            let height = Height::new(cursor.read_u64()?);
            let view = View::new(cursor.read_u64()?);
            let payload_digest = PayloadDigest::new(cursor.take_array::<32>()?);
            let result_state_root = StateRoot::new(cursor.take_array::<32>()?);
            let receipts_root = ReceiptsRoot::new(cursor.take_array::<32>()?);
            let evidence_root = EvidenceRoot::new(cursor.take_array::<32>()?);
            let overlay_checksum = decode_digest_v1(cursor)?;
            let source_artifact_checksum = decode_digest_v1(cursor)?;
            let validation_artifact_checksum = decode_digest_v1(cursor)?;
            let application_head_checksum = decode_digest_v1(cursor)?;
            let core_safety_record_checksum = decode_digest_v1(cursor)?;
            let whole_node_predecessor_checksum =
                WholeNodeCheckpointChecksumV1::from_exact_bytes(cursor.take_array::<32>()?)?;
            let supplied_statement_digest = decode_digest_v1(cursor)?;
            let value = ApplicationValidationCutRefV1::new(
                generation,
                validation_store_scope,
                validation_id,
                validation_record_chain_checksum,
                validation_active_head_checksum,
                validation_predecessor_record_chain_checksum,
                validation_predecessor_active_head_checksum,
                block_id,
                parent_block_id,
                height,
                view,
                payload_digest,
                result_state_root,
                receipts_root,
                evidence_root,
                overlay_checksum,
                source_artifact_checksum,
                validation_artifact_checksum,
                application_head_checksum,
                core_safety_record_checksum,
                whole_node_predecessor_checksum,
            )?;
            if value.statement_digest() != supplied_statement_digest {
                return Err(WholeNodeCheckpointErrorV1::InvalidField(
                    "application validation statement digest",
                ));
            }
            Ok(Some(value))
        }
        _ => Err(WholeNodeCheckpointErrorV1::ReservedTag(
            "application validation option",
        )),
    }
}

fn decode_application_attestor_v1(
    cursor: &mut CursorV1<'_>,
) -> WholeNodeCheckpointResultV1<AppAttestorCutRefV1> {
    Ok(AppAttestorCutRefV1::new(
        decode_digest_v1(cursor)?,
        decode_digest_v1(cursor)?,
        decode_digest_v1(cursor)?,
        cursor.read_u64()?,
        decode_digest_v1(cursor)?,
        decode_digest_v1(cursor)?,
        decode_digest_v1(cursor)?,
        decode_option_digest_v1(cursor, "application-attestor checkpoint predecessor")?,
        decode_option_digest_v1(cursor, "application attestation")?,
    ))
}

fn decode_remote_safety_v1(
    cursor: &mut CursorV1<'_>,
) -> WholeNodeCheckpointResultV1<RemoteSafetyCutRefV1> {
    Ok(RemoteSafetyCutRefV1::new(
        decode_digest_v1(cursor)?,
        decode_digest_v1(cursor)?,
        decode_digest_v1(cursor)?,
        cursor.read_u64()?,
        decode_digest_v1(cursor)?,
        decode_digest_v1(cursor)?,
        decode_digest_v1(cursor)?,
        decode_digest_v1(cursor)?,
        decode_option_digest_v1(cursor, "remote SafetyRules checkpoint predecessor")?,
        decode_option_digest_v1(cursor, "remote SafetyRules prepared transition")?,
    ))
}

fn decode_signer_v1(cursor: &mut CursorV1<'_>) -> WholeNodeCheckpointResultV1<SignerCutRefV1> {
    Ok(SignerCutRefV1::new(
        decode_digest_v1(cursor)?,
        decode_digest_v1(cursor)?,
        decode_digest_v1(cursor)?,
        cursor.read_u64()?,
        decode_digest_v1(cursor)?,
        decode_digest_v1(cursor)?,
        decode_digest_v1(cursor)?,
        decode_option_digest_v1(cursor, "signer checkpoint predecessor")?,
        SignerJournalStateV1::from_tag(cursor.read_u8()?)?,
        decode_option_digest_v1(cursor, "signer request fingerprint")?,
        decode_option_digest_v1(cursor, "signer signature digest")?,
    ))
}

fn decode_option_operation_v1(
    cursor: &mut CursorV1<'_>,
) -> WholeNodeCheckpointResultV1<Option<SignOperationCutRefV1>> {
    match cursor.read_u8()? {
        0 => Ok(None),
        1 => Ok(Some(SignOperationCutRefV1::new(
            SignOperationKindV1::from_tag(cursor.read_u8()?)?,
            decode_digest_v1(cursor)?,
            decode_digest_v1(cursor)?,
            decode_digest_v1(cursor)?,
            decode_digest_v1(cursor)?,
            SigningRoot::new(cursor.take_array::<32>()?),
            decode_digest_v1(cursor)?,
            WholeNodeCheckpointChecksumV1::from_exact_bytes(cursor.take_array::<32>()?)?,
            decode_option_digest_v1(cursor, "operation application validation statement")?,
        )?)),
        _ => Err(WholeNodeCheckpointErrorV1::ReservedTag("operation option")),
    }
}

fn decode_option_checksum_v1(
    cursor: &mut CursorV1<'_>,
    label: &'static str,
) -> WholeNodeCheckpointResultV1<Option<WholeNodeCheckpointChecksumV1>> {
    match cursor.read_u8()? {
        0 => Ok(None),
        1 => Ok(Some(WholeNodeCheckpointChecksumV1::from_exact_bytes(
            cursor.take_array::<32>()?,
        )?)),
        _ => Err(WholeNodeCheckpointErrorV1::ReservedTag(label)),
    }
}

fn decode_option_digest_v1(
    cursor: &mut CursorV1<'_>,
    label: &'static str,
) -> WholeNodeCheckpointResultV1<Option<WholeNodeCutDigestV1>> {
    match cursor.read_u8()? {
        0 => Ok(None),
        1 => Ok(Some(decode_digest_v1(cursor)?)),
        _ => Err(WholeNodeCheckpointErrorV1::ReservedTag(label)),
    }
}

fn decode_digest_v1(
    cursor: &mut CursorV1<'_>,
) -> WholeNodeCheckpointResultV1<WholeNodeCutDigestV1> {
    WholeNodeCutDigestV1::from_exact_bytes(cursor.take_array::<32>()?).map_err(Into::into)
}

struct CursorV1<'a> {
    encoded: &'a [u8],
    position: usize,
}

impl<'a> CursorV1<'a> {
    const fn new(encoded: &'a [u8]) -> Self {
        Self {
            encoded,
            position: 0,
        }
    }

    fn take(&mut self, length: usize) -> WholeNodeCheckpointResultV1<&'a [u8]> {
        let end = self
            .position
            .checked_add(length)
            .ok_or(WholeNodeCheckpointErrorV1::LengthLimitExceeded)?;
        let bytes = self
            .encoded
            .get(self.position..end)
            .ok_or(WholeNodeCheckpointErrorV1::UnexpectedEnd)?;
        self.position = end;
        Ok(bytes)
    }

    fn take_array<const LENGTH: usize>(&mut self) -> WholeNodeCheckpointResultV1<[u8; LENGTH]> {
        self.take(LENGTH)?
            .try_into()
            .map_err(|_| WholeNodeCheckpointErrorV1::UnexpectedEnd)
    }

    fn read_u8(&mut self) -> WholeNodeCheckpointResultV1<u8> {
        Ok(self.take_array::<1>()?[0])
    }

    fn read_u16(&mut self) -> WholeNodeCheckpointResultV1<u16> {
        Ok(u16::from_be_bytes(self.take_array::<2>()?))
    }

    fn read_u32(&mut self) -> WholeNodeCheckpointResultV1<u32> {
        Ok(u32::from_be_bytes(self.take_array::<4>()?))
    }

    fn read_u64(&mut self) -> WholeNodeCheckpointResultV1<u64> {
        Ok(u64::from_be_bytes(self.take_array::<8>()?))
    }

    fn is_finished(&self) -> bool {
        self.position == self.encoded.len()
    }
}
