//! Exact QTX1 v1 transfer bytes, shared with the existing Python/C oracle.
//! Parsing and unsigned statements confer no account or signature authority.
use crate::pq_frame::{
    payload_commitment, PqFrameExpectation, TPQ1_SIGNED_BYTES, TPQ1_UNSIGNED_BYTES,
};
use sha2::{Digest, Sha256, Sha384};

pub const HEADER_BYTES: usize = 144;
pub const MAX_MEMO_BYTES: usize = 512;
pub const MAX_TRANSACTION_BYTES: usize = 8192;
pub const MIN_SIGNED_BYTES: usize = HEADER_BYTES + TPQ1_SIGNED_BYTES;
const CONTEXT_DOMAIN: &[u8] = b"TRNM/PoN/QTX1Context/v1\0";
const IDENTITY_DOMAIN: &[u8] = b"TRNM/PoN/QTX1Identity/v1\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QtxError {
    Length,
    Version,
    Identity,
    Integer,
    Framing,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transfer {
    pub network: [u8; 32],
    pub sender: [u8; 32],
    pub recipient: [u8; 32],
    pub generation: u64,
    pub nonce: u64,
    pub expires_at: u64,
    pub amount: u64,
    pub max_fee: u64,
    pub memo: Vec<u8>,
}
impl Transfer {
    pub fn encode(&self) -> Result<Vec<u8>, QtxError> {
        if self.sender == [0; 32] || self.recipient == [0; 32] || self.sender == self.recipient {
            return Err(QtxError::Identity);
        }
        if self.generation == 0 || self.nonce == 0 || self.expires_at == 0 || self.amount == 0 {
            return Err(QtxError::Integer);
        }
        if self.memo.len() > MAX_MEMO_BYTES {
            return Err(QtxError::Length);
        }
        let mut out = Vec::with_capacity(HEADER_BYTES + self.memo.len());
        out.extend_from_slice(b"QTX1\x01\x01");
        for value in [self.network, self.sender, self.recipient] {
            out.extend_from_slice(&value);
        }
        for value in [
            self.generation,
            self.nonce,
            self.expires_at,
            self.amount,
            self.max_fee,
        ] {
            out.extend_from_slice(&value.to_be_bytes());
        }
        out.extend_from_slice(&(self.memo.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.memo);
        Ok(out)
    }
    pub fn context(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(CONTEXT_DOMAIN);
        h.update(self.network);
        h.update(self.sender);
        h.finalize().into()
    }
    /// All owner fields must still be compared to the actual selected account.
    pub fn expectation<'a>(
        &self,
        signer_key_id: [u8; 32],
        now: u64,
        body: &'a [u8],
    ) -> PqFrameExpectation<'a> {
        PqFrameExpectation {
            purpose: 1,
            network: self.network,
            owner_context: self.context(),
            signer_key_id,
            owner_generation: self.generation,
            operation_sequence: self.nonce,
            expires_at: self.expires_at,
            now,
            payload: body,
        }
    }
    pub fn unsigned_statement(
        &self,
        signer_key_id: [u8; 32],
    ) -> Result<[u8; TPQ1_UNSIGNED_BYTES], QtxError> {
        let body = self.encode()?;
        let e = self.expectation(signer_key_id, 0, &body);
        let mut out = [0; TPQ1_UNSIGNED_BYTES];
        out[..8].copy_from_slice(b"TPQ1\x01\x65\x01\0");
        out[8..40].copy_from_slice(&e.network);
        out[40..72].copy_from_slice(&e.owner_context);
        out[72..104].copy_from_slice(&e.signer_key_id);
        out[104..112].copy_from_slice(&e.owner_generation.to_be_bytes());
        out[112..120].copy_from_slice(&e.operation_sequence.to_be_bytes());
        out[120..128].copy_from_slice(&e.expires_at.to_be_bytes());
        out[128..].copy_from_slice(&payload_commitment(&body).map_err(|_| QtxError::Length)?);
        Ok(out)
    }
    /// Same 48-byte logical identity as the existing QTX1 oracle. Signature
    /// randomness cannot create a distinct operation or bypass its account nonce.
    pub fn logical_id(&self, signer_key_id: [u8; 32]) -> Result<[u8; 48], QtxError> {
        let body = self.encode()?;
        let mut h = Sha384::new();
        h.update(IDENTITY_DOMAIN);
        h.update((body.len() as u32).to_be_bytes());
        h.update(body);
        h.update(signer_key_id);
        Ok(h.finalize().into())
    }
}

pub fn decode_body(body: &[u8]) -> Result<Transfer, QtxError> {
    if !(HEADER_BYTES..=HEADER_BYTES + MAX_MEMO_BYTES).contains(&body.len()) {
        return Err(QtxError::Length);
    }
    if &body[..6] != b"QTX1\x01\x01" {
        return Err(QtxError::Version);
    }
    let memo =
        u16::from_be_bytes(body[142..144].try_into().map_err(|_| QtxError::Framing)?) as usize;
    if memo > MAX_MEMO_BYTES || body.len() != HEADER_BYTES + memo {
        return Err(QtxError::Framing);
    }
    let hash = |offset| -> Result<[u8; 32], QtxError> {
        body[offset..offset + 32]
            .try_into()
            .map_err(|_| QtxError::Length)
    };
    let number = |offset| -> Result<u64, QtxError> {
        Ok(u64::from_be_bytes(
            body[offset..offset + 8]
                .try_into()
                .map_err(|_| QtxError::Length)?,
        ))
    };
    let transfer = Transfer {
        network: hash(6)?,
        sender: hash(38)?,
        recipient: hash(70)?,
        generation: number(102)?,
        nonce: number(110)?,
        expires_at: number(118)?,
        amount: number(126)?,
        max_fee: number(134)?,
        memo: body[144..].to_vec(),
    };
    if transfer.encode()? != body {
        return Err(QtxError::Framing);
    }
    Ok(transfer)
}

/// Exact framing only. The native owner must authenticate TPQ1 and all bindings.
pub fn decode_signed(raw: &[u8]) -> Result<(Transfer, &[u8], &[u8]), QtxError> {
    if !(MIN_SIGNED_BYTES..=MAX_TRANSACTION_BYTES).contains(&raw.len()) {
        return Err(QtxError::Length);
    }
    let memo =
        u16::from_be_bytes(raw[142..144].try_into().map_err(|_| QtxError::Framing)?) as usize;
    if memo > MAX_MEMO_BYTES || raw.len() != HEADER_BYTES + memo + TPQ1_SIGNED_BYTES {
        return Err(QtxError::Framing);
    }
    let (body, frame) = raw.split_at(HEADER_BYTES + memo);
    Ok((decode_body(body)?, body, frame))
}
