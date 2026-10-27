//! Explicit NPQ1 native transfer bytes. Parsing and signing data grant no authority.
//! Legacy PNX1 and the existing standalone QTX1 preview remain separate profiles.
use crate::pq_frame::{
    ml_dsa_65_key_id_from_spki, payload_commitment, ML_DSA_65_SPKI_BYTES, TPQ1_SIGNED_BYTES,
    TPQ1_UNSIGNED_BYTES,
};
use crate::pq_transfer::{self, UnverifiedPqTransfer, QTX1_HEADER_BYTES, QTX1_MAX_BYTES};
use sha2::{Digest, Sha256, Sha384};

pub const PROFILE: &str = "pon-native-pq-transfer-v1";
pub const PREFIX_BYTES: usize = 12;
pub const MIN_BYTES: usize =
    PREFIX_BYTES + QTX1_HEADER_BYTES + TPQ1_SIGNED_BYTES + ML_DSA_65_SPKI_BYTES;
pub const MAX_BYTES: usize = PREFIX_BYTES + QTX1_MAX_BYTES + ML_DSA_65_SPKI_BYTES;
pub const MAX_TRANSACTION_BYTES: usize = 524_288;
pub const MAX_TRANSACTIONS: usize = 256;
pub const MAX_FULL_SIZE_TRANSACTIONS: usize = MAX_TRANSACTION_BYTES / MAX_BYTES;
pub const PACKET_PREFIX: &[u8; 8] = b"PQP1\x01\0\0\0";
const _: () = assert!(MIN_BYTES == 5_617 && MAX_BYTES == 6_129 && MAX_FULL_SIZE_TRANSACTIONS == 85);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChainContext {
    pub network: [u8; 32],
    pub parameters: [u8; 32],
    pub genesis: [u8; 32],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Encoding,
    Key,
    Context,
    Length,
}

/// Every field remains unverified. M01 authentication and current M06 State follow.
#[derive(Debug)]
pub struct UnverifiedEnvelope<'a> {
    raw: &'a [u8],
    transfer: UnverifiedPqTransfer<'a>,
    spki: &'a [u8],
    key_id: [u8; 32],
}
impl<'a> UnverifiedEnvelope<'a> {
    pub fn decode(raw: &'a [u8]) -> Result<Self, Error> {
        if !(MIN_BYTES..=MAX_BYTES).contains(&raw.len()) {
            return Err(Error::Length);
        }
        if &raw[..6] != b"NPQ1\x01\x65" || raw[10..12] != [0, 0] {
            return Err(Error::Encoding);
        }
        let qtx_bytes = u16::from_be_bytes([raw[6], raw[7]]) as usize;
        let key_bytes = u16::from_be_bytes([raw[8], raw[9]]) as usize;
        if key_bytes != ML_DSA_65_SPKI_BYTES || raw.len() != PREFIX_BYTES + qtx_bytes + key_bytes {
            return Err(Error::Length);
        }
        let transfer = pq_transfer::decode_unverified(&raw[PREFIX_BYTES..PREFIX_BYTES + qtx_bytes])
            .map_err(|_| Error::Encoding)?;
        let spki = &raw[PREFIX_BYTES + qtx_bytes..];
        let key_id = ml_dsa_65_key_id_from_spki(spki).map_err(|_| Error::Key)?;
        Ok(Self {
            raw,
            transfer,
            spki,
            key_id,
        })
    }
    pub fn raw(&self) -> &'a [u8] {
        self.raw
    }
    pub fn transfer(&self) -> &UnverifiedPqTransfer<'a> {
        &self.transfer
    }
    pub fn spki(&self) -> &'a [u8] {
        self.spki
    }
    pub fn key_id(&self) -> [u8; 32] {
        self.key_id
    }
    pub fn wire_id(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(b"TRNM/PoN/NativePQWire/v1\0");
        h.update((self.raw.len() as u32).to_be_bytes());
        h.update(self.raw);
        h.finalize().into()
    }
    pub fn statement_id(&self, context: ChainContext) -> Result<[u8; 48], Error> {
        check_context(context)?;
        if self.transfer.network != context.network {
            return Err(Error::Context);
        }
        let mut h = Sha384::new();
        h.update(b"TRNM/PoN/NativePQStatement/v1\0");
        h.update(context.network);
        h.update(context.parameters);
        h.update(context.genesis);
        h.update(pq_transfer::statement_identity(
            &self.transfer,
            &self.key_id,
        ));
        Ok(h.finalize().into())
    }
}

fn check_context(context: ChainContext) -> Result<(), Error> {
    if [context.network, context.parameters, context.genesis].contains(&[0; 32]) {
        Err(Error::Context)
    } else {
        Ok(())
    }
}

pub fn owner_context(context: ChainContext, account: [u8; 32]) -> Result<[u8; 32], Error> {
    check_context(context)?;
    let mut h = Sha256::new();
    h.update(b"TRNM/PoN/NativePQTransferOwner/v1\0");
    h.update(context.network);
    h.update(context.parameters);
    h.update(context.genesis);
    h.update(account);
    h.update(PROFILE.as_bytes());
    Ok(h.finalize().into())
}

/// Exact framing only. A zero or invalid signature remains unauthenticated.
pub fn encode(qtx1: &[u8], spki: &[u8]) -> Result<Vec<u8>, Error> {
    pq_transfer::decode_unverified(qtx1).map_err(|_| Error::Encoding)?;
    ml_dsa_65_key_id_from_spki(spki).map_err(|_| Error::Key)?;
    let mut raw = Vec::with_capacity(PREFIX_BYTES + qtx1.len() + spki.len());
    raw.extend(b"NPQ1\x01\x65");
    raw.extend((qtx1.len() as u16).to_be_bytes());
    raw.extend((spki.len() as u16).to_be_bytes());
    raw.extend([0, 0]);
    raw.extend(qtx1);
    raw.extend(spki);
    UnverifiedEnvelope::decode(&raw)?;
    Ok(raw)
}

/// Canonical unsigned TPQ1 data for an already encoded QTX1 body. This does not
/// sign, authenticate an account, reserve a nonce, or execute a transfer.
pub fn signing_statement(
    qtx1_with_signature: &[u8],
    spki: &[u8],
    context: ChainContext,
) -> Result<[u8; TPQ1_UNSIGNED_BYTES], Error> {
    let transfer =
        pq_transfer::decode_unverified(qtx1_with_signature).map_err(|_| Error::Encoding)?;
    let key = ml_dsa_65_key_id_from_spki(spki).map_err(|_| Error::Key)?;
    if transfer.network != context.network {
        return Err(Error::Context);
    }
    let mut raw = [0; TPQ1_UNSIGNED_BYTES];
    raw[..8].copy_from_slice(b"TPQ1\x01\x65\x01\0");
    raw[8..40].copy_from_slice(&context.network);
    raw[40..72].copy_from_slice(&owner_context(context, transfer.sender)?);
    raw[72..104].copy_from_slice(&key);
    raw[104..112].copy_from_slice(&transfer.generation.to_be_bytes());
    raw[112..120].copy_from_slice(&transfer.nonce.to_be_bytes());
    raw[120..128].copy_from_slice(&transfer.expires_at.to_be_bytes());
    raw[128..].copy_from_slice(&payload_commitment(transfer.body()).map_err(|_| Error::Length)?);
    Ok(raw)
}

#[cfg(test)]
mod tests {
    use super::*;
    const QTX: &[u8] = include_bytes!("../tests/fixtures/pq_transfer/transfer.bin");
    const SPKI: &[u8] = include_bytes!("../tests/fixtures/pq_transfer/public.der");
    #[test]
    fn exact_outer_bounds_and_old_codec_refusal() {
        let raw = encode(QTX, SPKI).unwrap();
        let decoded = UnverifiedEnvelope::decode(&raw).unwrap();
        assert_eq!(decoded.spki(), SPKI);
        assert!(crate::pon_wire::Envelope::decode(&raw).is_err());
        assert!(pq_transfer::decode_unverified(&raw).is_err());
        for at in [0, 4, 5, 6, 8, 10, 11] {
            let mut changed = raw.clone();
            changed[at] ^= 1;
            assert!(UnverifiedEnvelope::decode(&changed).is_err(), "field {at}");
        }
        for len in [0, MIN_BYTES - 1, MAX_BYTES + 1] {
            let mut changed = raw.clone();
            changed.resize(len, 0);
            assert!(UnverifiedEnvelope::decode(&changed).is_err());
        }
    }
    #[test]
    fn genesis_and_parameters_bind_semantics_signature_randomness_only_changes_wire_id() {
        let raw = encode(QTX, SPKI).unwrap();
        let a = UnverifiedEnvelope::decode(&raw).unwrap();
        let context = ChainContext {
            network: a.transfer.network,
            parameters: [1; 32],
            genesis: [2; 32],
        };
        let mut changed = raw.clone();
        changed[PREFIX_BYTES + QTX.len() - 1] ^= 1;
        let b = UnverifiedEnvelope::decode(&changed).unwrap();
        assert_ne!(a.wire_id(), b.wire_id());
        assert_eq!(a.statement_id(context), b.statement_id(context));
        assert_ne!(
            a.statement_id(context),
            a.statement_id(ChainContext {
                genesis: [3; 32],
                ..context
            })
        );
        assert_ne!(
            a.statement_id(context),
            a.statement_id(ChainContext {
                parameters: [3; 32],
                ..context
            })
        );
        assert_ne!(
            owner_context(context, a.transfer.sender),
            owner_context(
                ChainContext {
                    genesis: [3; 32],
                    ..context
                },
                a.transfer.sender
            )
        );
    }
}
