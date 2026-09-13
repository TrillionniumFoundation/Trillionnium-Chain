use alloc::vec::Vec;

use crate::{
    canonical::{
        canonical_hash, signing_root, try_canonical_bytes, CanonicalSignable, Encoder,
        DOMAIN_CONSUMPTION_CERTIFICATE, DOMAIN_CONSUMPTION_CERTIFICATE_ID,
    },
    CertificateId, ChainId, ConsensusParametersV0, ConsensusPublicKey, GenesisHash, Height, Result,
    Signature64, SignatureVerifier, SigningRoot, ValidationError, Validator, ValidatorId,
    VotingPower, MAX_CONSENSUS_STRING_BYTES, MAX_VALIDATOR_ID_BYTES, SCHEMA_VERSION_V0,
};

/// v0 uses the active opaque-ID bound for every Consumption Certificate Bytes field.
pub const MAX_CONSUMPTION_CERTIFICATE_ID_BYTES: usize = MAX_VALIDATOR_ID_BYTES;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsumptionCertificateBodyV0 {
    genesis_hash: GenesisHash,
    chain_id: ChainId,
    provider_id: ValidatorId,
    consumer_id: ValidatorId,
    consumer_key_id: ValidatorId,
    task_id: Vec<u8>,
    output_commitment: [u8; 32],
    meter_id: Vec<u8>,
    meter_version: u32,
    consumed_units: u128,
    billing_start_height: Height,
    billing_end_height: Height,
    consumer_nonce: u64,
    settlement_commitment: [u8; 32],
    measurement_evidence_root: Option<[u8; 32]>,
}

impl ConsumptionCertificateBodyV0 {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        genesis_hash: GenesisHash,
        chain_id: ChainId,
        provider_id: ValidatorId,
        consumer_id: ValidatorId,
        consumer_key_id: ValidatorId,
        task_id: Vec<u8>,
        output_commitment: [u8; 32],
        meter_id: Vec<u8>,
        meter_version: u32,
        consumed_units: u128,
        billing_start_height: Height,
        billing_end_height: Height,
        consumer_nonce: u64,
        settlement_commitment: [u8; 32],
        measurement_evidence_root: Option<[u8; 32]>,
    ) -> Result<Self> {
        let value = Self {
            genesis_hash,
            chain_id,
            provider_id,
            consumer_id,
            consumer_key_id,
            task_id,
            output_commitment,
            meter_id,
            meter_version,
            consumed_units,
            billing_start_height,
            billing_end_height,
            consumer_nonce,
            settlement_commitment,
            measurement_evidence_root,
        };
        value.validate_shape()?;
        Ok(value)
    }

    pub fn validate_shape(&self) -> Result<()> {
        if self.genesis_hash.is_zero() {
            return Err(ValidationError::ZeroGenesisHash);
        }
        validate_opaque_id("task_id", &self.task_id)?;
        validate_opaque_id("meter_id", &self.meter_id)?;
        if self.provider_id == self.consumer_id {
            return Err(ValidationError::InvalidCertificate(
                "provider and consumer must differ",
            ));
        }
        if self.consumed_units == 0 {
            return Err(ValidationError::InvalidCertificate(
                "consumed units must be positive",
            ));
        }
        if self.billing_start_height > self.billing_end_height {
            return Err(ValidationError::InvalidCertificate(
                "billing start exceeds billing end",
            ));
        }
        Ok(())
    }

    pub fn validate_acceptance_height(&self, acceptance_height: Height) -> Result<()> {
        self.validate_shape()?;
        if self.billing_end_height >= acceptance_height {
            return Err(ValidationError::InvalidCertificate(
                "billing end must precede acceptance height",
            ));
        }
        Ok(())
    }

    pub fn validate_against_parameters(&self, parameters: &ConsensusParametersV0) -> Result<()> {
        self.validate_shape()?;
        parameters.validate_safety_invariants()?;
        let id_maximum = usize::from(parameters.max_validator_id_bytes());
        for (field, actual) in [
            ("provider_id", self.provider_id.as_bytes().len()),
            ("consumer_id", self.consumer_id.as_bytes().len()),
            ("consumer_key_id", self.consumer_key_id.as_bytes().len()),
            ("task_id", self.task_id.len()),
            ("meter_id", self.meter_id.len()),
        ] {
            if actual > id_maximum {
                return Err(ValidationError::LengthOverflow {
                    field,
                    actual,
                    maximum: id_maximum,
                });
            }
        }
        if self.chain_id.as_bytes().len() > usize::from(parameters.max_chain_id_bytes()) {
            return Err(ValidationError::InvalidConsensusString);
        }
        Ok(())
    }

    pub fn digest(&self) -> SigningRoot {
        signing_root(DOMAIN_CONSUMPTION_CERTIFICATE, |encoder| {
            self.encode_cev0(encoder);
        })
    }

    pub fn certificate_id(&self) -> CertificateId {
        let body_digest = self.digest();
        CertificateId::new(canonical_hash(
            DOMAIN_CONSUMPTION_CERTIFICATE_ID,
            |encoder| encoder.fixed(body_digest.as_bytes()),
        ))
    }

    pub fn try_cev0_bytes(&self) -> Result<Vec<u8>> {
        try_canonical_bytes(|encoder| self.encode_cev0(encoder))
    }

    pub const fn genesis_hash(&self) -> GenesisHash {
        self.genesis_hash
    }
    pub const fn chain_id(&self) -> ChainId {
        self.chain_id
    }
    pub const fn provider_id(&self) -> ValidatorId {
        self.provider_id
    }
    pub const fn consumer_id(&self) -> ValidatorId {
        self.consumer_id
    }
    pub const fn consumer_key_id(&self) -> ValidatorId {
        self.consumer_key_id
    }
    pub fn task_id(&self) -> &[u8] {
        &self.task_id
    }
    pub const fn output_commitment(&self) -> &[u8; 32] {
        &self.output_commitment
    }
    pub fn meter_id(&self) -> &[u8] {
        &self.meter_id
    }
    pub const fn meter_version(&self) -> u32 {
        self.meter_version
    }
    pub const fn consumed_units(&self) -> u128 {
        self.consumed_units
    }
    pub const fn billing_start_height(&self) -> Height {
        self.billing_start_height
    }
    pub const fn billing_end_height(&self) -> Height {
        self.billing_end_height
    }
    pub const fn consumer_nonce(&self) -> u64 {
        self.consumer_nonce
    }
    pub const fn settlement_commitment(&self) -> &[u8; 32] {
        &self.settlement_commitment
    }
    pub const fn measurement_evidence_root(&self) -> Option<&[u8; 32]> {
        self.measurement_evidence_root.as_ref()
    }

    fn encode_cev0(&self, encoder: &mut Encoder) {
        encoder.u16(SCHEMA_VERSION_V0);
        encoder.fixed(self.genesis_hash.as_bytes());
        encoder.consensus_string(self.chain_id.as_bytes());
        encoder.bytes(self.provider_id.as_bytes());
        encoder.bytes(self.consumer_id.as_bytes());
        encoder.bytes(self.consumer_key_id.as_bytes());
        encoder.bytes(&self.task_id);
        encoder.fixed(&self.output_commitment);
        encoder.bytes(&self.meter_id);
        encoder.u32(self.meter_version);
        encoder.u128(self.consumed_units);
        encoder.u64(self.billing_start_height.get());
        encoder.u64(self.billing_end_height.get());
        encoder.u64(self.consumer_nonce);
        encoder.fixed(&self.settlement_commitment);
        encoder.optional_fixed(self.measurement_evidence_root.as_ref());
    }
}

impl CanonicalSignable for ConsumptionCertificateBodyV0 {
    fn signing_root(&self) -> SigningRoot {
        self.digest()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsumptionCertificateV0 {
    body: ConsumptionCertificateBodyV0,
    consumer_signature: Signature64,
    certificate_id: CertificateId,
}

impl ConsumptionCertificateV0 {
    pub fn new(
        body: ConsumptionCertificateBodyV0,
        consumer_signature: Signature64,
    ) -> Result<Self> {
        body.validate_shape()?;
        let certificate_id = body.certificate_id();
        Ok(Self {
            body,
            consumer_signature,
            certificate_id,
        })
    }

    pub fn from_parts(
        body: ConsumptionCertificateBodyV0,
        consumer_signature: Signature64,
        certificate_id: CertificateId,
    ) -> Result<Self> {
        body.validate_shape()?;
        if certificate_id != body.certificate_id() {
            return Err(ValidationError::CertificateMismatch);
        }
        Ok(Self {
            body,
            consumer_signature,
            certificate_id,
        })
    }

    pub const fn body(&self) -> &ConsumptionCertificateBodyV0 {
        &self.body
    }
    pub const fn consumer_signature(&self) -> &Signature64 {
        &self.consumer_signature
    }
    pub const fn certificate_id(&self) -> CertificateId {
        self.certificate_id
    }

    pub fn verify<V: SignatureVerifier>(
        &self,
        expected_genesis_hash: GenesisHash,
        expected_chain_id: ChainId,
        consensus_parameters: &ConsensusParametersV0,
        acceptance_height: Height,
        resolved_consumer_public_key: ConsensusPublicKey,
        verifier: &V,
    ) -> Result<()> {
        self.body
            .validate_against_parameters(consensus_parameters)?;
        self.body.validate_acceptance_height(acceptance_height)?;
        if self.body.genesis_hash != expected_genesis_hash {
            return Err(ValidationError::GenesisHashMismatch);
        }
        if self.body.chain_id != expected_chain_id {
            return Err(ValidationError::ChainIdMismatch);
        }
        if self.certificate_id != self.body.certificate_id() {
            return Err(ValidationError::CertificateMismatch);
        }
        let consumer = Validator::new(
            self.body.consumer_key_id,
            resolved_consumer_public_key,
            VotingPower::new(1)?,
        )?;
        if !verifier.verify(&consumer, &self.body.digest(), &self.consumer_signature) {
            return Err(ValidationError::InvalidSignature(alloc::boxed::Box::new(
                self.body.consumer_key_id,
            )));
        }
        Ok(())
    }

    /// Exact logical wrapper: body fields, signature, then independently-derived ID.
    pub fn try_cev0_bytes(&self) -> Result<Vec<u8>> {
        try_canonical_bytes(|encoder| {
            self.body.encode_cev0(encoder);
            encoder.fixed(self.consumer_signature.as_bytes());
            encoder.fixed(self.certificate_id.as_bytes());
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ConsumptionCertificateDecodeErrorCode {
    UnexpectedEnd,
    TrailingBytes,
    InvalidSchemaVersion,
    ZeroGenesisHash,
    InvalidChainId,
    EmptyId,
    IdTooLong,
    InvalidOptionalTag,
    ZeroConsumedUnits,
    InvalidBillingWindow,
    SameProviderConsumer,
    CertificateIdMismatch,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ConsumptionCertificateDecodeError {
    code: ConsumptionCertificateDecodeErrorCode,
    byte_offset: usize,
}

impl ConsumptionCertificateDecodeError {
    pub const fn code(self) -> ConsumptionCertificateDecodeErrorCode {
        self.code
    }
    pub const fn byte_offset(self) -> usize {
        self.byte_offset
    }
}

pub fn decode_consumption_certificate_v0_exact(
    bytes: &[u8],
) -> core::result::Result<ConsumptionCertificateV0, ConsumptionCertificateDecodeError> {
    let mut cursor = Cursor::new(bytes);
    let schema_offset = cursor.offset;
    if cursor.u16()? != SCHEMA_VERSION_V0 {
        return Err(decode_error(
            ConsumptionCertificateDecodeErrorCode::InvalidSchemaVersion,
            schema_offset,
        ));
    }
    let genesis_offset = cursor.offset;
    let genesis_hash = GenesisHash::new(cursor.fixed()?);
    if genesis_hash.is_zero() {
        return Err(decode_error(
            ConsumptionCertificateDecodeErrorCode::ZeroGenesisHash,
            genesis_offset,
        ));
    }
    let chain_offset = cursor.offset;
    let chain_len = usize::from(cursor.u16()?);
    if chain_len == 0 || chain_len > MAX_CONSENSUS_STRING_BYTES {
        return Err(decode_error(
            ConsumptionCertificateDecodeErrorCode::InvalidChainId,
            chain_offset,
        ));
    }
    let chain_id = ChainId::from_bytes(cursor.take(chain_len)?).map_err(|_| {
        decode_error(
            ConsumptionCertificateDecodeErrorCode::InvalidChainId,
            chain_offset,
        )
    })?;
    let provider = cursor.opaque_id()?;
    let consumer = cursor.opaque_id()?;
    let consumer_key = cursor.opaque_id()?;
    let task = cursor.bytes()?;
    let output: [u8; 32] = cursor.fixed()?;
    let meter = cursor.bytes()?;
    let meter_version = cursor.u32()?;
    let consumed_units = cursor.u128()?;
    let start = Height::new(cursor.u64()?);
    let end = Height::new(cursor.u64()?);
    let nonce = cursor.u64()?;
    let settlement: [u8; 32] = cursor.fixed()?;
    let optional_offset = cursor.offset;
    let evidence = match cursor.u8()? {
        0 => None,
        1 => Some(cursor.fixed()?),
        _ => {
            return Err(decode_error(
                ConsumptionCertificateDecodeErrorCode::InvalidOptionalTag,
                optional_offset,
            ))
        }
    };
    let signature = Signature64::from_array(cursor.fixed()?);
    let id_offset = cursor.offset;
    let id = CertificateId::new(cursor.fixed()?);
    if cursor.offset != bytes.len() {
        return Err(decode_error(
            ConsumptionCertificateDecodeErrorCode::TrailingBytes,
            cursor.offset,
        ));
    }
    let body = ConsumptionCertificateBodyV0::new(
        genesis_hash,
        chain_id,
        provider,
        consumer,
        consumer_key,
        task,
        output,
        meter,
        meter_version,
        consumed_units,
        start,
        end,
        nonce,
        settlement,
        evidence,
    )
    .map_err(|error| map_validation_error(error, id_offset))?;
    ConsumptionCertificateV0::from_parts(body, signature, id).map_err(|_| {
        decode_error(
            ConsumptionCertificateDecodeErrorCode::CertificateIdMismatch,
            id_offset,
        )
    })
}

fn validate_opaque_id(field: &'static str, value: &[u8]) -> Result<()> {
    if value.is_empty() {
        return Err(ValidationError::InvalidCertificate(
            "opaque ID must not be empty",
        ));
    }
    if value.len() > MAX_CONSUMPTION_CERTIFICATE_ID_BYTES {
        return Err(ValidationError::LengthOverflow {
            field,
            actual: value.len(),
            maximum: MAX_CONSUMPTION_CERTIFICATE_ID_BYTES,
        });
    }
    Ok(())
}

fn decode_error(
    code: ConsumptionCertificateDecodeErrorCode,
    byte_offset: usize,
) -> ConsumptionCertificateDecodeError {
    ConsumptionCertificateDecodeError { code, byte_offset }
}

fn map_validation_error(
    error: ValidationError,
    offset: usize,
) -> ConsumptionCertificateDecodeError {
    let code = match error {
        ValidationError::ZeroGenesisHash => ConsumptionCertificateDecodeErrorCode::ZeroGenesisHash,
        ValidationError::LengthOverflow { .. } | ValidationError::ValidatorIdTooLong { .. } => {
            ConsumptionCertificateDecodeErrorCode::IdTooLong
        }
        ValidationError::EmptyValidatorId => ConsumptionCertificateDecodeErrorCode::EmptyId,
        ValidationError::InvalidCertificate(message) if message.contains("positive") => {
            ConsumptionCertificateDecodeErrorCode::ZeroConsumedUnits
        }
        ValidationError::InvalidCertificate(message) if message.contains("billing") => {
            ConsumptionCertificateDecodeErrorCode::InvalidBillingWindow
        }
        ValidationError::InvalidCertificate(message) if message.contains("differ") => {
            ConsumptionCertificateDecodeErrorCode::SameProviderConsumer
        }
        ValidationError::InvalidCertificate(_) => {
            ConsumptionCertificateDecodeErrorCode::CertificateIdMismatch
        }
        _ => ConsumptionCertificateDecodeErrorCode::CertificateIdMismatch,
    };
    decode_error(code, offset)
}

struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}
impl<'a> Cursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }
    fn take(
        &mut self,
        len: usize,
    ) -> core::result::Result<&'a [u8], ConsumptionCertificateDecodeError> {
        let end = self.offset.checked_add(len).ok_or_else(|| {
            decode_error(
                ConsumptionCertificateDecodeErrorCode::UnexpectedEnd,
                self.offset,
            )
        })?;
        let value = self.bytes.get(self.offset..end).ok_or_else(|| {
            decode_error(
                ConsumptionCertificateDecodeErrorCode::UnexpectedEnd,
                self.offset,
            )
        })?;
        self.offset = end;
        Ok(value)
    }
    fn fixed<const N: usize>(
        &mut self,
    ) -> core::result::Result<[u8; N], ConsumptionCertificateDecodeError> {
        self.take(N)?.try_into().map_err(|_| {
            decode_error(
                ConsumptionCertificateDecodeErrorCode::UnexpectedEnd,
                self.offset,
            )
        })
    }
    fn u8(&mut self) -> core::result::Result<u8, ConsumptionCertificateDecodeError> {
        Ok(self.fixed::<1>()?[0])
    }
    fn u16(&mut self) -> core::result::Result<u16, ConsumptionCertificateDecodeError> {
        Ok(u16::from_be_bytes(self.fixed()?))
    }
    fn u32(&mut self) -> core::result::Result<u32, ConsumptionCertificateDecodeError> {
        Ok(u32::from_be_bytes(self.fixed()?))
    }
    fn u64(&mut self) -> core::result::Result<u64, ConsumptionCertificateDecodeError> {
        Ok(u64::from_be_bytes(self.fixed()?))
    }
    fn u128(&mut self) -> core::result::Result<u128, ConsumptionCertificateDecodeError> {
        Ok(u128::from_be_bytes(self.fixed()?))
    }
    fn bytes(&mut self) -> core::result::Result<Vec<u8>, ConsumptionCertificateDecodeError> {
        let length_offset = self.offset;
        let len = usize::try_from(self.u32()?).map_err(|_| {
            decode_error(
                ConsumptionCertificateDecodeErrorCode::IdTooLong,
                length_offset,
            )
        })?;
        if len == 0 {
            return Err(decode_error(
                ConsumptionCertificateDecodeErrorCode::EmptyId,
                length_offset,
            ));
        }
        if len > MAX_CONSUMPTION_CERTIFICATE_ID_BYTES {
            return Err(decode_error(
                ConsumptionCertificateDecodeErrorCode::IdTooLong,
                length_offset,
            ));
        }
        Ok(self.take(len)?.to_vec())
    }
    fn opaque_id(
        &mut self,
    ) -> core::result::Result<ValidatorId, ConsumptionCertificateDecodeError> {
        let offset = self.offset;
        let bytes = self.bytes()?;
        ValidatorId::from_bytes(&bytes)
            .map_err(|_| decode_error(ConsumptionCertificateDecodeErrorCode::IdTooLong, offset))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct RootVerifier(SigningRoot);
    impl SignatureVerifier for RootVerifier {
        fn verify(&self, _: &Validator, root: &SigningRoot, _: &Signature64) -> bool {
            *root == self.0
        }
    }

    fn body() -> ConsumptionCertificateBodyV0 {
        ConsumptionCertificateBodyV0::new(
            GenesisHash::new([1; 32]),
            ChainId::from_static("trnm-test"),
            ValidatorId::from_bytes(b"provider").unwrap(),
            ValidatorId::from_bytes(b"consumer").unwrap(),
            ValidatorId::from_bytes(b"consumer-key").unwrap(),
            b"task".to_vec(),
            [2; 32],
            b"meter".to_vec(),
            7,
            u128::MAX,
            Height::new(10),
            Height::new(20),
            9,
            [3; 32],
            Some([4; 32]),
        )
        .unwrap()
    }

    #[test]
    fn exact_round_trip_and_authority_checks() {
        let body = body();
        let root = body.digest();
        let cert = ConsumptionCertificateV0::new(body, Signature64::from_array([5; 64])).unwrap();
        let bytes = cert.try_cev0_bytes().unwrap();
        let decoded = decode_consumption_certificate_v0_exact(&bytes).unwrap();
        assert_eq!(decoded, cert);
        decoded
            .verify(
                GenesisHash::new([1; 32]),
                ChainId::from_static("trnm-test"),
                &ConsensusParametersV0::reference_shadow_v0(),
                Height::new(21),
                ConsensusPublicKey::new([6; 32]),
                &RootVerifier(root),
            )
            .unwrap();
        assert!(decoded
            .verify(
                GenesisHash::new([1; 32]),
                ChainId::from_static("trnm-test"),
                &ConsensusParametersV0::reference_shadow_v0(),
                Height::new(20),
                ConsensusPublicKey::new([6; 32]),
                &RootVerifier(root),
            )
            .is_err());
    }

    #[test]
    fn rejects_prefixes_trailing_bad_id_and_relations() {
        let cert = ConsumptionCertificateV0::new(body(), Signature64::from_array([5; 64])).unwrap();
        let bytes = cert.try_cev0_bytes().unwrap();
        for length in 0..bytes.len() {
            assert!(decode_consumption_certificate_v0_exact(&bytes[..length]).is_err());
        }
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert_eq!(
            decode_consumption_certificate_v0_exact(&trailing)
                .unwrap_err()
                .code(),
            ConsumptionCertificateDecodeErrorCode::TrailingBytes
        );
        let mut bad_id = bytes;
        *bad_id.last_mut().unwrap() ^= 1;
        assert_eq!(
            decode_consumption_certificate_v0_exact(&bad_id)
                .unwrap_err()
                .code(),
            ConsumptionCertificateDecodeErrorCode::CertificateIdMismatch
        );
        let same = ValidatorId::from_bytes(b"same").unwrap();
        assert!(ConsumptionCertificateBodyV0::new(
            GenesisHash::new([1; 32]),
            ChainId::from_static("trnm-test"),
            same,
            same,
            same,
            b"t".to_vec(),
            [2; 32],
            b"m".to_vec(),
            1,
            1,
            Height::new(1),
            Height::new(1),
            1,
            [3; 32],
            None,
        )
        .is_err());
    }

    #[test]
    fn active_parameter_bounds_are_checked_at_admission() {
        let body = body();
        let mut fields = ConsensusParametersV0::reference_shadow_v0().fields();
        fields.max_validator_id_bytes = 8;
        let parameters = ConsensusParametersV0::new(fields).unwrap();
        assert!(body.validate_against_parameters(&parameters).is_err());
    }
}
