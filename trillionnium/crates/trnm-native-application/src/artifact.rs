use crate::{
    application::{
        NativeBlockExecutionRequestV0, NativeExecutedBlockV0, NativeExpectedBlockCommitmentsV0,
    },
    error::{error, NativeBoundaryErrorCodeV0, NativeBoundaryResultV0},
    execution::{NativeEventAttributeV0, NativeEventV0, NativeExecutionReceiptV0},
    primitives::{
        ApplicationCommitIdV0, ApplicationHeadV0, BlockIdV0, ChainIdV0, GenesisHashV0, Hash32V0,
        HeightV0, ReceiptsRootV0, StateRootV0, ValidatorSetIdV0,
    },
};

/// Fixed domain prefix for the complete frozen-v0 execution artifact.
pub const NATIVE_EXECUTED_BLOCK_ARTIFACT_DOMAIN_V0: &[u8; 38] =
    b"TRNM_NATIVE_EXECUTED_BLOCK_ARTIFACT_V0";

/// Exact codec version carried after the fixed domain prefix.
pub const NATIVE_EXECUTED_BLOCK_ARTIFACT_VERSION_V0: u64 = 0;

/// Hard storage/decoder bound for one complete artifact.
///
/// The frozen block body is at most 4 MiB. The additional budget is bounded
/// receipt/event evidence; an application producing more must reject the
/// block before it can create a durable artifact.
pub const MAX_NATIVE_EXECUTED_BLOCK_ARTIFACT_BYTES_V0: usize = 16 * 1024 * 1024;

/// Encode one complete `NativeExecutedBlockV0` canonically.
///
/// Every scalar and every variable-length field length is fixed-width,
/// unsigned, and big-endian. No host serialization format participates.
pub fn encode_native_executed_block_artifact_v0(
    executed: &NativeExecutedBlockV0,
) -> NativeBoundaryResultV0<Vec<u8>> {
    let mut encoder = ArtifactEncoderV0::new();
    encoder.bytes(
        NATIVE_EXECUTED_BLOCK_ARTIFACT_DOMAIN_V0,
        "executed_artifact.domain",
    )?;
    encoder.u64(NATIVE_EXECUTED_BLOCK_ARTIFACT_VERSION_V0)?;

    let request = executed.request();
    encoder.length_prefixed(
        request.chain_id().as_str().as_bytes(),
        "executed_artifact.chain_id",
    )?;
    encoder.bytes(
        request.genesis_hash().as_bytes(),
        "executed_artifact.genesis_hash",
    )?;
    encoder.u64(request.parent().height().get())?;
    encoder.bytes(
        request.parent().block_id().as_bytes(),
        "executed_artifact.parent_block",
    )?;
    encoder.bytes(
        request.parent().state_root().as_bytes(),
        "executed_artifact.parent_state",
    )?;
    encoder.bytes(
        request.parent().commit_id().as_bytes(),
        "executed_artifact.parent_commit",
    )?;
    encoder.bytes(request.block_id().as_bytes(), "executed_artifact.block_id")?;
    encoder.u64(request.height().get())?;
    encoder.u64(request.timestamp_ms())?;
    encoder.bytes(
        request.active_validator_set_id().as_bytes(),
        "executed_artifact.validator_set",
    )?;
    encoder.count(
        request.transactions().len(),
        "executed_artifact.transactions",
    )?;
    for transaction in request.transactions() {
        encoder.length_prefixed(transaction, "executed_artifact.transaction")?;
    }
    let expected = request.expected();
    encoder.bytes(
        expected.payload_root().as_bytes(),
        "executed_artifact.payload_root",
    )?;
    encoder.bytes(
        expected.post_state_root().as_bytes(),
        "executed_artifact.post_state_root",
    )?;
    encoder.bytes(
        expected.receipts_root().as_bytes(),
        "executed_artifact.receipts_root",
    )?;
    encoder.bytes(
        expected.evidence_root().as_bytes(),
        "executed_artifact.evidence_root",
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

/// Decode exactly one complete canonical artifact and reconstruct the native
/// execution capability through all normal boundary constructors.
pub fn decode_native_executed_block_artifact_v0(
    bytes: &[u8],
) -> NativeBoundaryResultV0<NativeExecutedBlockV0> {
    if bytes.len() > MAX_NATIVE_EXECUTED_BLOCK_ARTIFACT_BYTES_V0 {
        return Err(error(
            NativeBoundaryErrorCodeV0::TooLong,
            "executed_artifact.bytes",
        ));
    }
    let mut decoder = ArtifactDecoderV0::new(bytes);
    if decoder.exact(NATIVE_EXECUTED_BLOCK_ARTIFACT_DOMAIN_V0.len())?
        != NATIVE_EXECUTED_BLOCK_ARTIFACT_DOMAIN_V0
    {
        return Err(error(
            NativeBoundaryErrorCodeV0::NotCanonical,
            "executed_artifact.domain",
        ));
    }
    if decoder.u64()? != NATIVE_EXECUTED_BLOCK_ARTIFACT_VERSION_V0 {
        return Err(error(
            NativeBoundaryErrorCodeV0::NotCanonical,
            "executed_artifact.version",
        ));
    }

    let chain_id = ChainIdV0::new(decoder.text("executed_artifact.chain_id")?)?;
    let genesis_hash = GenesisHashV0::new(decoder.array32()?)?;
    let parent = ApplicationHeadV0::new(
        HeightV0::new(decoder.u64()?),
        BlockIdV0::new(decoder.array32()?)?,
        StateRootV0::new(decoder.array32()?)?,
        ApplicationCommitIdV0::new(decoder.array32()?)?,
    );
    let block_id = BlockIdV0::new(decoder.array32()?)?;
    let height = HeightV0::new(decoder.u64()?);
    let timestamp_ms = decoder.u64()?;
    let validator_set = ValidatorSetIdV0::new(decoder.array32()?)?;
    let transaction_count = decoder.count("executed_artifact.transactions")?;
    let mut transactions = Vec::with_capacity(transaction_count.min(4096));
    for _ in 0..transaction_count {
        transactions.push(
            decoder
                .length_prefixed("executed_artifact.transaction")?
                .to_vec(),
        );
    }
    let expected = NativeExpectedBlockCommitmentsV0::new(
        Hash32V0::new(decoder.array32()?),
        StateRootV0::new(decoder.array32()?)?,
        ReceiptsRootV0::new(decoder.array32()?)?,
        Hash32V0::new(decoder.array32()?),
    )?;
    let request = NativeBlockExecutionRequestV0::new(
        chain_id,
        genesis_hash,
        parent,
        block_id,
        height,
        timestamp_ms,
        validator_set,
        transactions,
        expected,
    )?;

    let receipt_count = decoder.count("executed_artifact.receipts")?;
    if receipt_count != request.transactions().len() {
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
    NativeExecutedBlockV0::new(
        request,
        expected.payload_root(),
        expected.post_state_root(),
        expected.receipts_root(),
        expected.evidence_root(),
        receipts,
    )
}

struct ArtifactEncoderV0 {
    bytes: Vec<u8>,
}

impl ArtifactEncoderV0 {
    fn new() -> Self {
        Self {
            bytes: Vec::with_capacity(1024),
        }
    }

    fn bytes(&mut self, value: &[u8], field: &'static str) -> NativeBoundaryResultV0<()> {
        let target = self
            .bytes
            .len()
            .checked_add(value.len())
            .ok_or_else(|| error(NativeBoundaryErrorCodeV0::Overflow, field))?;
        if target > MAX_NATIVE_EXECUTED_BLOCK_ARTIFACT_BYTES_V0 {
            return Err(error(NativeBoundaryErrorCodeV0::TooLong, field));
        }
        self.bytes.extend_from_slice(value);
        Ok(())
    }

    fn u32(&mut self, value: u32) -> NativeBoundaryResultV0<()> {
        self.bytes(&value.to_be_bytes(), "executed_artifact.u32")
    }

    fn u64(&mut self, value: u64) -> NativeBoundaryResultV0<()> {
        self.bytes(&value.to_be_bytes(), "executed_artifact.u64")
    }

    fn u128(&mut self, value: u128) -> NativeBoundaryResultV0<()> {
        self.bytes(&value.to_be_bytes(), "executed_artifact.u128")
    }

    fn count(&mut self, value: usize, field: &'static str) -> NativeBoundaryResultV0<()> {
        let value =
            u32::try_from(value).map_err(|_| error(NativeBoundaryErrorCodeV0::TooMany, field))?;
        self.u32(value)
    }

    fn length_prefixed(&mut self, value: &[u8], field: &'static str) -> NativeBoundaryResultV0<()> {
        self.count(value.len(), field)?;
        self.bytes(value, field)
    }

    fn finish(self) -> Vec<u8> {
        self.bytes
    }
}

struct ArtifactDecoderV0<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> ArtifactDecoderV0<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn exact(&mut self, length: usize) -> NativeBoundaryResultV0<&'a [u8]> {
        let end = self.offset.checked_add(length).ok_or_else(|| {
            error(
                NativeBoundaryErrorCodeV0::Overflow,
                "executed_artifact.offset",
            )
        })?;
        let value = self.bytes.get(self.offset..end).ok_or_else(|| {
            error(
                NativeBoundaryErrorCodeV0::NotCanonical,
                "executed_artifact.truncated",
            )
        })?;
        self.offset = end;
        Ok(value)
    }

    fn array32(&mut self) -> NativeBoundaryResultV0<[u8; 32]> {
        self.exact(32)?.try_into().map_err(|_| {
            error(
                NativeBoundaryErrorCodeV0::NotCanonical,
                "executed_artifact.array32",
            )
        })
    }

    fn u32(&mut self) -> NativeBoundaryResultV0<u32> {
        let bytes = self.exact(4)?.try_into().map_err(|_| {
            error(
                NativeBoundaryErrorCodeV0::NotCanonical,
                "executed_artifact.u32",
            )
        })?;
        Ok(u32::from_be_bytes(bytes))
    }

    fn u64(&mut self) -> NativeBoundaryResultV0<u64> {
        let bytes = self.exact(8)?.try_into().map_err(|_| {
            error(
                NativeBoundaryErrorCodeV0::NotCanonical,
                "executed_artifact.u64",
            )
        })?;
        Ok(u64::from_be_bytes(bytes))
    }

    fn u128(&mut self) -> NativeBoundaryResultV0<u128> {
        let bytes = self.exact(16)?.try_into().map_err(|_| {
            error(
                NativeBoundaryErrorCodeV0::NotCanonical,
                "executed_artifact.u128",
            )
        })?;
        Ok(u128::from_be_bytes(bytes))
    }

    fn count(&mut self, field: &'static str) -> NativeBoundaryResultV0<usize> {
        usize::try_from(self.u32()?).map_err(|_| error(NativeBoundaryErrorCodeV0::TooMany, field))
    }

    fn length_prefixed(&mut self, field: &'static str) -> NativeBoundaryResultV0<&'a [u8]> {
        let length = self.count(field)?;
        self.exact(length)
    }

    fn text(&mut self, field: &'static str) -> NativeBoundaryResultV0<String> {
        String::from_utf8(self.length_prefixed(field)?.to_vec())
            .map_err(|_| error(NativeBoundaryErrorCodeV0::NotCanonical, field))
    }

    fn finish(self) -> NativeBoundaryResultV0<()> {
        if self.offset != self.bytes.len() {
            return Err(error(
                NativeBoundaryErrorCodeV0::NotCanonical,
                "executed_artifact.trailing_bytes",
            ));
        }
        Ok(())
    }
}
