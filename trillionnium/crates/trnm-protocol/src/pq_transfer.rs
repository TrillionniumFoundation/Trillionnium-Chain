//! Bounded QTX1 transfer research bytes. Parsing never authenticates a signer.
//! The installed PNX1 dispatch and limits do not accept this distinct format.
use crate::pq_frame::TPQ1_SIGNED_BYTES;
use sha2::{Digest, Sha256, Sha384};

pub const QTX1_HEADER_BYTES: usize = 144;
pub const QTX1_MAX_MEMO_BYTES: usize = 512;
pub const QTX1_MAX_BYTES: usize = QTX1_HEADER_BYTES + QTX1_MAX_MEMO_BYTES + TPQ1_SIGNED_BYTES;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PqTransferError {
    Length,
    Version,
    Identity,
    Range,
}

/// All fields are untrusted until actual ML-DSA verification and current M06
/// account/nonce/fee checks. `expires_at` is UTC seconds, not a block height.
#[derive(Debug)]
pub struct UnverifiedPqTransfer<'a> {
    pub network: [u8; 32],
    pub sender: [u8; 32],
    pub recipient: [u8; 32],
    pub generation: u64,
    pub nonce: u64,
    pub expires_at: u64,
    pub amount: u64,
    pub max_fee: u64,
    body: &'a [u8],
    frame: &'a [u8],
}

impl<'a> UnverifiedPqTransfer<'a> {
    pub fn body(&self) -> &'a [u8] {
        self.body
    }

    pub fn frame(&self) -> &'a [u8] {
        self.frame
    }
}

fn number(raw: &[u8], at: usize) -> u64 {
    let mut bytes = [0; 8];
    bytes.copy_from_slice(&raw[at..at + 8]);
    u64::from_be_bytes(bytes)
}

fn hash32(raw: &[u8], at: usize) -> [u8; 32] {
    let mut bytes = [0; 32];
    bytes.copy_from_slice(&raw[at..at + 32]);
    bytes
}

pub fn decode_unverified(raw: &[u8]) -> Result<UnverifiedPqTransfer<'_>, PqTransferError> {
    if !(QTX1_HEADER_BYTES + TPQ1_SIGNED_BYTES..=QTX1_MAX_BYTES).contains(&raw.len()) {
        return Err(PqTransferError::Length);
    }
    if &raw[..6] != b"QTX1\x01\x01" {
        return Err(PqTransferError::Version);
    }
    let memo_bytes = u16::from_be_bytes([raw[142], raw[143]]) as usize;
    let body_bytes = QTX1_HEADER_BYTES + memo_bytes;
    if memo_bytes > QTX1_MAX_MEMO_BYTES || raw.len() != body_bytes + TPQ1_SIGNED_BYTES {
        return Err(PqTransferError::Length);
    }
    let transfer = UnverifiedPqTransfer {
        network: hash32(raw, 6),
        sender: hash32(raw, 38),
        recipient: hash32(raw, 70),
        generation: number(raw, 102),
        nonce: number(raw, 110),
        expires_at: number(raw, 118),
        amount: number(raw, 126),
        max_fee: number(raw, 134),
        body: &raw[..body_bytes],
        frame: &raw[body_bytes..],
    };
    if transfer.sender == [0; 32]
        || transfer.recipient == [0; 32]
        || transfer.sender == transfer.recipient
    {
        return Err(PqTransferError::Identity);
    }
    if transfer.generation == 0
        || transfer.nonce == 0
        || transfer.expires_at == 0
        || transfer.amount == 0
    {
        return Err(PqTransferError::Range);
    }
    Ok(transfer)
}

pub fn owner_context(network: &[u8; 32], sender: &[u8; 32]) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"TRNM/PoN/QTX1Context/v1\0");
    digest.update(network);
    digest.update(sender);
    digest.finalize().into()
}

/// Identity of the semantic statement, independent of ML-DSA signing randomness.
pub fn statement_identity(transfer: &UnverifiedPqTransfer<'_>, key_id: &[u8; 32]) -> [u8; 48] {
    let mut digest = Sha384::new();
    digest.update(b"TRNM/PoN/QTX1Identity/v1\0");
    digest.update((transfer.body.len() as u32).to_be_bytes());
    digest.update(transfer.body);
    digest.update(key_id);
    digest.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> Vec<u8> {
        include_bytes!("../tests/fixtures/pq_transfer/transfer.bin").to_vec()
    }

    #[test]
    fn exact_bounds_and_canonical_body_reject_before_signature_work() {
        let original = fixture();
        let transfer = decode_unverified(&original).unwrap();
        assert_eq!(transfer.frame().len(), TPQ1_SIGNED_BYTES);
        for length in [
            0,
            143,
            144,
            QTX1_HEADER_BYTES + TPQ1_SIGNED_BYTES - 1,
            QTX1_MAX_BYTES + 1,
        ] {
            let mut bad = original.clone();
            bad.resize(length, 0);
            assert!(decode_unverified(&bad).is_err());
        }
        for index in [0, 4, 5] {
            let mut bad = original.clone();
            bad[index] ^= 1;
            assert!(decode_unverified(&bad).is_err());
        }
        let mut bad = original.clone();
        bad[142..144].copy_from_slice(&513_u16.to_be_bytes());
        assert!(decode_unverified(&bad).is_err());
        for range in [38..70, 70..102, 102..110, 110..118, 118..126, 126..134] {
            let mut bad = original.clone();
            bad[range].fill(0);
            assert!(decode_unverified(&bad).is_err());
        }
    }

    #[test]
    fn alleged_signature_is_not_parser_authority_or_transaction_identity() {
        let original = fixture();
        let a = decode_unverified(&original).unwrap();
        let mut zero_signature = original.clone();
        let signature_start = zero_signature.len() - 3309;
        zero_signature[signature_start..].fill(0);
        let b = decode_unverified(&zero_signature).unwrap();
        assert_eq!(
            statement_identity(&a, &a.sender),
            statement_identity(&b, &b.sender)
        );
        assert_ne!(a.frame(), b.frame());
        // Both objects are UNVERIFIED and require M01 then the actual state owner.
    }
}
