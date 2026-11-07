use crate::account_archive_prototype::multiproof::Multiproof;
use crate::{ensure, Error, Result};
use trnm_crypto_primitives::pon_work;
use trnm_mvcc_fee::pon_executor::growth as limits;
use trnm_protocol::pon_growth::{GrowthHeader, GROWTH_HEADER_BYTES};
use trnm_protocol::pon_wire::{hash, Envelope, Hash};

/// Only the explicitly selected native growth profile accepts PNP2. The complete
/// working partition is locally replicated; original-parent account proofs travel
/// with each block and are bound into its work challenge and block identity.
#[derive(Clone, Debug)]
pub struct GrowthPacket {
    pub header: GrowthHeader,
    pub transactions: Vec<Vec<u8>>,
    pub accounts: Multiproof,
    pub proof: Vec<u8>,
}
impl GrowthPacket {
    pub fn witness_digest(accounts: &Multiproof) -> Result<Hash> {
        ensure(
            accounts.accounts.len() <= limits::MAX_WITNESS_ACCOUNTS
                && accounts.encoded_len().map_err(super::archive_error)?
                    <= limits::MAX_WITNESS_BYTES,
            "GROWTH_WITNESS_LIMIT",
        )?;
        Ok(hash(
            b"native-growth-account-witness-v2",
            &[&accounts.encode().map_err(super::archive_error)?],
        ))
    }
    pub fn encode(&self) -> Result<Vec<u8>> {
        ensure(
            self.transactions.len() <= 256 && self.proof.len() == pon_work::PROOF_BYTES,
            "PACKET_LIMIT",
        )?;
        ensure(
            self.header.witness == Self::witness_digest(&self.accounts)?,
            "GROWTH_WITNESS_ROOT",
        )?;
        let witness = self.accounts.encode().map_err(super::archive_error)?;
        let mut length = 4 + GROWTH_HEADER_BYTES + 2 + 4 + witness.len() + self.proof.len();
        for tx in &self.transactions {
            ensure((159..=2048).contains(&tx.len()), "TRANSACTION_LIMIT")?;
            Envelope::decode(tx).map_err(|_| Error::from("TRANSACTION_CODEC"))?;
            length += 2 + tx.len();
        }
        ensure(length <= limits::MAX_PACKET_BYTES, "PACKET_LIMIT")?;
        let mut out = Vec::with_capacity(length);
        out.extend(b"PNP2");
        out.extend(self.header.encode());
        out.extend((self.transactions.len() as u16).to_le_bytes());
        for tx in &self.transactions {
            out.extend((tx.len() as u16).to_le_bytes());
            out.extend(tx);
        }
        out.extend((witness.len() as u32).to_le_bytes());
        out.extend(witness);
        out.extend(&self.proof);
        Ok(out)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let minimum = 4 + GROWTH_HEADER_BYTES + 2 + 4 + 44 + pon_work::PROOF_BYTES;
        ensure(
            (minimum..=limits::MAX_PACKET_BYTES).contains(&bytes.len()),
            "PACKET_LIMIT",
        )?;
        ensure(bytes[..4] == *b"PNP2", "GROWTH_PACKET_VERSION")?;
        let header = GrowthHeader::decode(&bytes[4..4 + GROWTH_HEADER_BYTES])
            .map_err(|_| Error::from("HEADER_CODEC"))?;
        let mut pos = 4 + GROWTH_HEADER_BYTES;
        let count = u16::from_le_bytes(
            bytes[pos..pos + 2]
                .try_into()
                .map_err(|_| "PACKET_LENGTH")?,
        ) as usize;
        pos += 2;
        ensure(count <= 256, "TRANSACTION_LIMIT")?;
        let mut transactions = Vec::with_capacity(count);
        for _ in 0..count {
            let length = u16::from_le_bytes(
                bytes
                    .get(pos..pos + 2)
                    .ok_or("PACKET_LENGTH")?
                    .try_into()
                    .map_err(|_| "PACKET_LENGTH")?,
            ) as usize;
            pos += 2;
            ensure((159..=2048).contains(&length), "TRANSACTION_LIMIT")?;
            let tx = bytes.get(pos..pos + length).ok_or("PACKET_LENGTH")?;
            Envelope::decode(tx).map_err(|_| Error::from("TRANSACTION_CODEC"))?;
            transactions.push(tx.to_vec());
            pos += length;
        }
        let length = u32::from_le_bytes(
            bytes
                .get(pos..pos + 4)
                .ok_or("PACKET_LENGTH")?
                .try_into()
                .map_err(|_| "PACKET_LENGTH")?,
        ) as usize;
        pos += 4;
        ensure(
            (44..=limits::MAX_WITNESS_BYTES).contains(&length),
            "GROWTH_WITNESS_LIMIT",
        )?;
        let witness = bytes.get(pos..pos + length).ok_or("PACKET_LENGTH")?;
        pos += length;
        ensure(bytes.len() - pos == pon_work::PROOF_BYTES, "PACKET_LENGTH")?;
        let accounts =
            u32::from_le_bytes(witness[36..40].try_into().map_err(|_| "PACKET_LENGTH")?) as usize;
        ensure(
            accounts <= limits::MAX_WITNESS_ACCOUNTS,
            "GROWTH_WITNESS_LIMIT",
        )?;
        let accounts = Multiproof::decode(witness).map_err(super::archive_error)?;
        ensure(
            header.witness == Self::witness_digest(&accounts)?,
            "GROWTH_WITNESS_ROOT",
        )?;
        Ok(Self {
            header,
            transactions,
            accounts,
            proof: bytes[pos..].to_vec(),
        })
    }
    pub fn id(&self) -> Result<Hash> {
        ensure(self.proof.len() == pon_work::PROOF_BYTES, "WORK_LENGTH")?;
        let trace = self.proof[self.proof.len() - 32..]
            .try_into()
            .map_err(|_| "WORK_LENGTH")?;
        Ok(self.header.block_id(trace))
    }
}
