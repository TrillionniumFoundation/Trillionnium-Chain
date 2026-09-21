/// Exact structural QC decoding under complete retained epoch evidence. This
/// performs no cryptographic verification and cannot activate a runtime.
pub fn decode_epoch_runtime_qc_reference_v1_exact_with_budget(
    bytes: &[u8],
    context: &crate::EpochRuntimeContextDataV1,
    budget: &mut Cev0AdmissionBudgetV0,
) -> DecodeResult<QcReferenceV0> {
    budget.admit_root_bytes(bytes.len())?;
    let mut cursor = Cursor::new(bytes);
    let raw = parse_raw_qc(&mut cursor, MAX_CEV0_CERTIFICATE_ITEMS)?;
    cursor.finish()?;
    let reference = admit_raw_qc_reference(
        raw,
        context.new_validator_set(),
        QcReferenceAdmissionV0::EpochContext(context.authorization(), context.old_validator_set()),
    )?;
    require_exact_canonical_reencoding(
        bytes,
        try_canonical_bytes(|e| reference.encode_cev0(e)),
        0,
    )?;
    budget.charge_qc_reference(&reference)?;
    Ok(reference)
}

/// Exact structural TC decoding. The parser enforces the authenticated nested
/// share ceiling before allocating; every synthetic reference must be the exact
/// anchor reconstructed from the complete epoch context.
pub fn decode_epoch_runtime_timeout_certificate_v1_exact_with_budget(
    bytes: &[u8],
    context: &crate::EpochRuntimeContextDataV1,
    budget: &mut Cev0AdmissionBudgetV0,
) -> DecodeResult<TimeoutCertificateV0> {
    budget.admit_root_bytes(bytes.len())?;
    let mut cursor = Cursor::new(bytes);
    let raw = parse_raw_timeout_certificate_with_aggregate_limit(
        &mut cursor,
        budget.maximum_tc_aggregate_signature_shares(),
    )?;
    cursor.finish()?;
    let certificate = admit_raw_timeout_certificate_with_reference_admission(
        raw,
        context.new_validator_set(),
        QcReferenceAdmissionV0::EpochContext(context.authorization(), context.old_validator_set()),
    )?;
    require_exact_canonical_reencoding(bytes, certificate.try_cev0_bytes(), 0)?;
    budget.charge_timeout_certificate(&certificate)?;
    Ok(certificate)
}

/// Exact structural three-chain decoding throughout one authenticated epoch.
/// Unlike the first-block-only entrypoint, later regular/checkpoint targets are
/// allowed. Parent timestamp is supplied by the consumer's authenticated edge;
/// it must never be inferred from the candidate proof.
pub fn decode_epoch_runtime_finality_proof_v1_exact_with_budget(
    bytes: &[u8],
    context: &crate::EpochRuntimeContextDataV1,
    authenticated_parent_timestamp_ms: u64,
    budget: &mut Cev0AdmissionBudgetV0,
) -> DecodeResult<FinalityProofV0> {
    budget.admit_root_bytes(bytes.len())?;
    let mut cursor = Cursor::new(bytes);
    let raw = parse_raw_finality_proof_with_epoch_context(
        &mut cursor,
        budget.maximum_tc_aggregate_signature_shares(),
        Some(context.authorization()),
    )?;
    cursor.finish()?;
    let proof = admit_raw_finality_proof_with_reference_admission(
        raw,
        context.new_validator_set(),
        context.new_parameters(),
        authenticated_parent_timestamp_ms,
        QcReferenceAdmissionV0::EpochContext(context.authorization(), context.old_validator_set()),
    )?;
    require_exact_canonical_reencoding(bytes, proof.try_cev0_bytes(), 0)?;
    budget.charge_finality_proof(&proof)?;
    Ok(proof)
}

/// Exact inert CertifiedHeader decoding under the complete retained epoch
/// context. The caller separately authenticates the parent and all signatures.
pub fn decode_epoch_runtime_certified_header_v1_exact_with_budget(
    bytes: &[u8],
    context: &crate::EpochRuntimeContextDataV1,
    authenticated_parent_timestamp_ms: u64,
    budget: &mut Cev0AdmissionBudgetV0,
) -> DecodeResult<CertifiedHeaderV0> {
    budget.admit_root_bytes(bytes.len())?;
    let mut cursor = Cursor::new(bytes);
    let raw = parse_raw_certified_header_with_epoch_context(
        &mut cursor,
        budget.maximum_tc_aggregate_signature_shares(),
        Some(context.authorization()),
    )?;
    cursor.finish()?;
    let header = admit_raw_certified_header_with_reference_admission(
        raw,
        context.new_validator_set(),
        context.new_parameters(),
        authenticated_parent_timestamp_ms,
        QcReferenceAdmissionV0::EpochContext(context.authorization(), context.old_validator_set()),
    )?;
    require_exact_canonical_reencoding(bytes, header.try_cev0_bytes(), 0)?;
    budget.charge_certified_header(&header)?;
    Ok(header)
}
