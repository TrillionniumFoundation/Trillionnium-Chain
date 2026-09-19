//! Closed, comparison-only retirement wire values. Authority comes from the
//! consumed journal owner and independently durable terminal CAS, not this codec.
use crate::{
    hash::hash_domain, ExternalMonotonicWatermarkV0, ExternalWatermarkErrorV0, SignerWatermarkV0,
};

pub const SIGNER_RETIREMENT_RECORD_BYTES_V1: usize = 354;
const MAGIC: &[u8; 8] = b"TRNMSR01";
const RECORD_DOMAIN: &str = "trnm.consensus-signer-journal.retirement-record.v1";
const TERMINAL_DOMAIN: &str = "trnm.consensus-signer-journal.retirement-terminal.v1";

/// Host supplied comparison bindings. This value confers no native, Safety,
/// handoff or new ordinary signing authority. Retirement only removes authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SignerRetirementHostCutV1 {
    pub owner_generation: u64,
    pub native_committed_cut: [u8; 32],
    pub safety_revision: u64,
    pub safety_record_checksum: [u8; 32],
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SignerRetirementRecordV1 {
    source: SignerWatermarkV0,
    host: SignerRetirementHostCutV1,
    pre_handoff_binding: [u8; 32],
    descriptor: [u8; 32],
    old_handoff_intent: [u8; 32],
    source_profile: [u8; 32],
}
impl SignerRetirementRecordV1 {
    pub(crate) fn new(
        source: SignerWatermarkV0,
        host: SignerRetirementHostCutV1,
        pre_handoff_binding: [u8; 32],
        descriptor: [u8; 32],
        old_handoff_intent: [u8; 32],
        source_profile: [u8; 32],
    ) -> Result<Self, ExternalWatermarkErrorV0> {
        let r = Self {
            source,
            host,
            pre_handoff_binding,
            descriptor,
            old_handoff_intent,
            source_profile,
        };
        r.validate()?;
        Ok(r)
    }
    fn validate(&self) -> Result<(), ExternalWatermarkErrorV0> {
        if self.host.owner_generation == 0
            || self.host.safety_revision == 0
            || !self.source.sequence().is_multiple_of(2)
            || self.source.sequence().checked_add(1).is_none()
            || [
                self.pre_handoff_binding,
                self.descriptor,
                self.old_handoff_intent,
                self.source_profile,
                self.host.native_committed_cut,
                self.host.safety_record_checksum,
            ]
            .contains(&[0; 32])
        {
            return Err(ExternalWatermarkErrorV0::InvalidPersistedState);
        }
        Ok(())
    }
    pub const fn source_v1(&self) -> SignerWatermarkV0 {
        self.source
    }
    pub const fn host_cut_v1(&self) -> SignerRetirementHostCutV1 {
        self.host
    }
    pub const fn pre_handoff_binding_v1(&self) -> [u8; 32] {
        self.pre_handoff_binding
    }
    pub const fn descriptor_digest_v1(&self) -> [u8; 32] {
        self.descriptor
    }
    pub const fn old_handoff_intent_fingerprint_v1(&self) -> [u8; 32] {
        self.old_handoff_intent
    }
    pub const fn source_profile_checksum_v1(&self) -> [u8; 32] {
        self.source_profile
    }
    pub fn encode_v1(&self) -> [u8; SIGNER_RETIREMENT_RECORD_BYTES_V1] {
        let mut b = [0; SIGNER_RETIREMENT_RECORD_BYTES_V1];
        let mut o = 0;
        for p in [
            MAGIC.as_slice(),
            &1u16.to_be_bytes(),
            &self.source.scope(),
            &self.source.journal_id(),
            &self.source.sequence().to_be_bytes(),
            &self.source.chain_checksum(),
            &self.host.owner_generation.to_be_bytes(),
            &self.pre_handoff_binding,
            &self.descriptor,
            &self.old_handoff_intent,
            &self.source_profile,
            &self.host.native_committed_cut,
            &self.host.safety_revision.to_be_bytes(),
            &self.host.safety_record_checksum,
        ] {
            b[o..o + p.len()].copy_from_slice(p);
            o += p.len();
        }
        let h = hash_domain(RECORD_DOMAIN, &[&b[..o]]);
        b[o..].copy_from_slice(&h);
        b
    }
    pub fn decode_v1_exact(bytes: &[u8]) -> Result<Self, ExternalWatermarkErrorV0> {
        if bytes.len() != SIGNER_RETIREMENT_RECORD_BYTES_V1
            || &bytes[..8] != MAGIC
            || bytes[8..10] != 1u16.to_be_bytes()
        {
            return Err(ExternalWatermarkErrorV0::InvalidPersistedState);
        }
        let mut offset = 10;
        fn take<const N: usize>(b: &[u8], o: &mut usize) -> [u8; N] {
            let result = b[*o..*o + N]
                .try_into()
                .expect("fixed-size retirement preflight");
            *o += N;
            result
        }
        let source = SignerWatermarkV0::from_persisted_parts(
            take(bytes, &mut offset),
            take(bytes, &mut offset),
            u64::from_be_bytes(take(bytes, &mut offset)),
            take(bytes, &mut offset),
        )?;
        let generation = u64::from_be_bytes(take(bytes, &mut offset));
        let pre_handoff_binding = take(bytes, &mut offset);
        let descriptor = take(bytes, &mut offset);
        let old_handoff_intent = take(bytes, &mut offset);
        let source_profile = take(bytes, &mut offset);
        let native_committed_cut = take(bytes, &mut offset);
        let safety_revision = u64::from_be_bytes(take(bytes, &mut offset));
        let safety_record_checksum = take(bytes, &mut offset);
        let host = SignerRetirementHostCutV1 {
            owner_generation: generation,
            native_committed_cut,
            safety_revision,
            safety_record_checksum,
        };
        let value = Self::new(
            source,
            host,
            pre_handoff_binding,
            descriptor,
            old_handoff_intent,
            source_profile,
        )?;
        if value.encode_v1().as_slice() != bytes {
            return Err(ExternalWatermarkErrorV0::InvalidPersistedState);
        }
        Ok(value)
    }
    pub fn checksum_v1(&self) -> [u8; 32] {
        self.encode_v1()[SIGNER_RETIREMENT_RECORD_BYTES_V1 - 32..]
            .try_into()
            .expect("fixed checksum")
    }
    pub fn terminal_watermark_v1(&self) -> SignerWatermarkV0 {
        SignerWatermarkV0::from_persisted_parts(
            self.source.scope(),
            self.source.journal_id(),
            self.source.sequence() + 1,
            hash_domain(TERMINAL_DOMAIN, &[&self.encode_v1()]),
        )
        .expect("validated retirement source")
    }
}

/// Independently administered terminal policy for the SAME old signer scope.
/// Implementations must durably forbid every ordinary legacy load/CAS for a
/// retired scope. A separate unconsulted sidecar or scope does not implement
/// this contract. CAS is idempotent only for the exact encoded retirement.
/// Local database restore cannot remove this external terminal policy.
///
/// This is an injected authority boundary, like ExternalMonotonicWatermarkV0;
/// an in-memory test implementation is not production anti-rollback evidence.
pub trait ExternalSignerRetirementV1: ExternalMonotonicWatermarkV0 {
    fn load_signer_retirement_v1(
        &mut self,
        scope: [u8; 32],
    ) -> Result<Option<SignerRetirementRecordV1>, ExternalWatermarkErrorV0>;
    fn retire_signer_exact_v1(
        &mut self,
        record: &SignerRetirementRecordV1,
    ) -> Result<SignerWatermarkV0, ExternalWatermarkErrorV0>;
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exact_codec_binds_all_retirement_fields_and_terminal_sequence() {
        let r = SignerRetirementRecordV1::new(
            SignerWatermarkV0::from_persisted_parts([1; 32], [2; 32], 4, [3; 32]).unwrap(),
            SignerRetirementHostCutV1 {
                owner_generation: 1,
                native_committed_cut: [4; 32],
                safety_revision: 9,
                safety_record_checksum: [5; 32],
            },
            [6; 32],
            [7; 32],
            [8; 32],
            [9; 32],
        )
        .unwrap();
        let b = r.encode_v1();
        assert_eq!(SignerRetirementRecordV1::decode_v1_exact(&b).unwrap(), r);
        assert_eq!(r.terminal_watermark_v1().sequence(), 5);
        for n in 0..b.len() {
            assert!(SignerRetirementRecordV1::decode_v1_exact(&b[..n]).is_err());
            let mut bad = b;
            bad[n] ^= 1;
            assert!(SignerRetirementRecordV1::decode_v1_exact(&bad).is_err());
        }
        let mut trailing = b.to_vec();
        trailing.push(0);
        assert!(SignerRetirementRecordV1::decode_v1_exact(&trailing).is_err());
        assert!(SignerRetirementRecordV1::new(
            SignerWatermarkV0::from_persisted_parts([1; 32], [2; 32], 5, [3; 32]).unwrap(),
            r.host,
            r.pre_handoff_binding,
            r.descriptor,
            r.old_handoff_intent,
            r.source_profile
        )
        .is_err());
    }
}
