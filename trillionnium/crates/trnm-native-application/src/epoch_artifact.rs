//! Separate local artifact codec; ordinary v0 bytes stay unchanged.
use super::*;
use crate::{
    NativeEpochBlockExecutionRequestV1, NativeEpochBlockPreviewRequestV1,
    NativeExecutedEpochBlockV1,
};

pub const NATIVE_EXECUTED_EPOCH_BLOCK_ARTIFACT_DOMAIN_V1: &[u8] =
    b"TRNM_NATIVE_EXECUTED_EPOCH_BLOCK_ARTIFACT_V1";
pub const NATIVE_EXECUTED_EPOCH_BLOCK_ARTIFACT_VERSION_V1: u64 = 1;

pub fn encode_native_executed_epoch_block_artifact_v1(
    executed: &NativeExecutedEpochBlockV1,
) -> NativeBoundaryResultV0<Vec<u8>> {
    let mut encoder = ArtifactEncoderV0::new();
    encoder.bytes(
        NATIVE_EXECUTED_EPOCH_BLOCK_ARTIFACT_DOMAIN_V1,
        "epoch_artifact.domain",
    )?;
    encoder.u64(NATIVE_EXECUTED_EPOCH_BLOCK_ARTIFACT_VERSION_V1)?;
    let execution = executed.request();
    let request = execution.preview();
    encoder.length_prefixed(
        request.chain_id().as_str().as_bytes(),
        "epoch_artifact.chain",
    )?;
    encoder.bytes(request.genesis_hash().as_bytes(), "epoch_artifact.genesis")?;
    encoder.u64(request.application_parent().height().get())?;
    encoder.bytes(
        request.application_parent().block_id().as_bytes(),
        "epoch_artifact.application_parent",
    )?;
    encoder.bytes(
        request.application_parent().state_root().as_bytes(),
        "epoch_artifact.application_root",
    )?;
    encoder.bytes(
        request.application_parent().commit_id().as_bytes(),
        "epoch_artifact.application_commit",
    )?;
    encoder.u64(request.consensus_parent_height().get())?;
    encoder.bytes(
        request.consensus_parent_id().as_bytes(),
        "epoch_artifact.consensus_parent",
    )?;
    encoder.bytes(request.edge_binding().as_bytes(), "epoch_artifact.edge")?;
    encoder.bytes(execution.block_id().as_bytes(), "epoch_artifact.block")?;
    encoder.u64(request.height().get())?;
    encoder.u64(request.timestamp_ms())?;
    encoder.bytes(
        request.active_validator_set_id().as_bytes(),
        "epoch_artifact.active_set",
    )?;
    encoder.count(request.transactions().len(), "epoch_artifact.transactions")?;
    for tx in request.transactions() {
        encoder.length_prefixed(tx, "epoch_artifact.transaction")?;
    }
    let expected = execution.expected();
    encoder.bytes(expected.payload_root().as_bytes(), "epoch_artifact.payload")?;
    encoder.bytes(
        expected.post_state_root().as_bytes(),
        "epoch_artifact.state",
    )?;
    encoder.bytes(
        expected.receipts_root().as_bytes(),
        "epoch_artifact.receipts",
    )?;
    encoder.bytes(
        expected.evidence_root().as_bytes(),
        "epoch_artifact.evidence",
    )?;
    encoder.count(executed.receipts().len(), "executed_artifact.receipts")?;
    for receipt in executed.receipts() {
        encoder.u32(receipt.transaction_index())?;
        encoder.bytes(
            receipt.transaction_digest().as_bytes(),
            "executed_artifact.transaction_digest",
        )?;
        encoder.u64(receipt.gas_used())?;
        encoder.u128(receipt.fee_charged())?;
        encoder.count(receipt.events().len(), "executed_artifact.events")?;
        for event in receipt.events() {
            encoder.length_prefixed(event.kind().as_bytes(), "executed_artifact.event_kind")?;
            encoder.count(
                event.attributes().len(),
                "executed_artifact.event_attributes",
            )?;
            for attribute in event.attributes() {
                encoder.length_prefixed(
                    attribute.key().as_bytes(),
                    "executed_artifact.attribute_key",
                )?;
                encoder.length_prefixed(
                    attribute.value().as_bytes(),
                    "executed_artifact.attribute_value",
                )?;
            }
        }
        encoder.bytes(
            receipt.commitment().as_bytes(),
            "executed_artifact.receipt_commitment",
        )?;
    }
    Ok(encoder.finish())
}

pub fn decode_native_executed_epoch_block_artifact_v1(
    bytes: &[u8],
) -> NativeBoundaryResultV0<NativeExecutedEpochBlockV1> {
    if bytes.len() > MAX_NATIVE_EXECUTED_BLOCK_ARTIFACT_BYTES_V0 {
        return Err(error(
            NativeBoundaryErrorCodeV0::TooLong,
            "epoch_artifact.bytes",
        ));
    }
    let mut decoder = ArtifactDecoderV0::new(bytes);
    if decoder.exact(NATIVE_EXECUTED_EPOCH_BLOCK_ARTIFACT_DOMAIN_V1.len())?
        != NATIVE_EXECUTED_EPOCH_BLOCK_ARTIFACT_DOMAIN_V1
        || decoder.u64()? != NATIVE_EXECUTED_EPOCH_BLOCK_ARTIFACT_VERSION_V1
    {
        return Err(error(
            NativeBoundaryErrorCodeV0::NotCanonical,
            "epoch_artifact.domain_version",
        ));
    }
    let chain = ChainIdV0::new(decoder.text("epoch_artifact.chain")?)?;
    let genesis = GenesisHashV0::new(decoder.array32()?)?;
    let parent = ApplicationHeadV0::new(
        HeightV0::new(decoder.u64()?),
        BlockIdV0::new(decoder.array32()?)?,
        StateRootV0::new(decoder.array32()?)?,
        ApplicationCommitIdV0::new(decoder.array32()?)?,
    );
    let consensus_height = HeightV0::new(decoder.u64()?);
    let consensus_id = BlockIdV0::new(decoder.array32()?)?;
    let edge = Hash32V0::new(decoder.array32()?);
    let block = BlockIdV0::new(decoder.array32()?)?;
    let height = HeightV0::new(decoder.u64()?);
    let timestamp = decoder.u64()?;
    let active = ValidatorSetIdV0::new(decoder.array32()?)?;
    let count = decoder.count("epoch_artifact.transactions")?;
    let mut transactions = Vec::with_capacity(count.min(4096));
    let mut transaction_bytes = 4usize;
    for _ in 0..count {
        let tx = decoder.length_prefixed("epoch_artifact.transaction")?;
        transaction_bytes = transaction_bytes
            .checked_add(4)
            .and_then(|n| n.checked_add(tx.len()))
            .ok_or_else(|| error(NativeBoundaryErrorCodeV0::Overflow, "epoch_artifact.body"))?;
        if transaction_bytes > crate::MAX_BLOCK_BYTES_V0 {
            return Err(error(
                NativeBoundaryErrorCodeV0::TooLong,
                "epoch_artifact.body",
            ));
        }
        transactions.push(tx.to_vec());
    }
    let expected = NativeExpectedBlockCommitmentsV0::new(
        Hash32V0::new(decoder.array32()?),
        StateRootV0::new(decoder.array32()?)?,
        ReceiptsRootV0::new(decoder.array32()?)?,
        Hash32V0::new(decoder.array32()?),
    )?;
    let preview = NativeEpochBlockPreviewRequestV1::new(
        chain,
        genesis,
        parent,
        consensus_id,
        consensus_height,
        edge,
        height,
        timestamp,
        active,
        transactions,
    )?;
    let request = NativeEpochBlockExecutionRequestV1::new(preview, block, expected)?;
    let receipt_count = decoder.count("executed_artifact.receipts")?;
    if receipt_count != request.preview().transactions().len() {
        return Err(error(
            NativeBoundaryErrorCodeV0::BindingMismatch,
            "executed_artifact.receipt_count",
        ));
    }
    let mut receipts = Vec::with_capacity(receipt_count.min(4096));
    for _ in 0..receipt_count {
        let transaction_index = decoder.u32()?;
        let transaction_digest = Hash32V0::new(decoder.array32()?);
        let gas_used = decoder.u64()?;
        let fee_charged = decoder.u128()?;
        let event_count = decoder.count("executed_artifact.events")?;
        let mut events = Vec::with_capacity(event_count.min(4096));
        for _ in 0..event_count {
            let kind = decoder.text("executed_artifact.event_kind")?;
            let attribute_count = decoder.count("executed_artifact.event_attributes")?;
            let mut attributes = Vec::with_capacity(attribute_count.min(4096));
            for _ in 0..attribute_count {
                attributes.push(NativeEventAttributeV0::new(
                    decoder.text("executed_artifact.attribute_key")?,
                    decoder.text("executed_artifact.attribute_value")?,
                )?);
            }
            events.push(NativeEventV0::new(kind, attributes)?);
        }
        let commitment = Hash32V0::new(decoder.array32()?);
        receipts.push(NativeExecutionReceiptV0::new(
            transaction_index,
            transaction_digest,
            gas_used,
            fee_charged,
            events,
            commitment,
        )?);
    }
    decoder.finish()?;
    let result = NativeExecutedEpochBlockV1::new(request, expected, receipts)?;
    if encode_native_executed_epoch_block_artifact_v1(&result)? != bytes {
        return Err(error(
            NativeBoundaryErrorCodeV0::NotCanonical,
            "epoch_artifact.reencoding",
        ));
    }
    Ok(result)
}
