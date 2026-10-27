//! Explicit native PQ transfer composition. No legacy transport or migration.
use crate::{ensure, Packet, Result, Settings};
use trnm_crypto_primitives::pon_work;
use trnm_mvcc_fee::pon_executor::pq_native_v1;
use trnm_protocol::pon_wire::{Hash, Header, HEADER_BYTES};
use trnm_protocol::pq_native_transfer_v1::{self as wire, UnverifiedEnvelope};

pub use crate::store::pq_native_v1::PqNodeV1;
pub use pq_native_v1::GenesisAccount;
pub use trnm_protocol::pq_native_transfer_v1::ChainContext;

impl Settings {
    pub fn native_pq_transfers_v1(accounts: &[GenesisAccount], timestamp: u64) -> Result<Self> {
        let (app, initial, genesis) = pq_native_v1::genesis(accounts, timestamp)?;
        Ok(Self {
            app,
            initial,
            genesis,
            operator_bootstrap: None,
            operator_material: None,
            checkpoint_tile_paths: None,
        })
    }
    pub fn native_pq_context(&self) -> Result<ChainContext> {
        Ok(pq_native_v1::context(&self.app)?)
    }
    pub(crate) fn is_native_pq_v1(&self) -> bool {
        pq_native_v1::enabled(&self.app)
    }
    pub(crate) fn encode_packet(&self, packet: &Packet) -> Result<Vec<u8>> {
        packet.encode_for_native_profile(self.is_native_pq_v1())
    }
    pub(crate) fn decode_packet(&self, raw: &[u8]) -> Result<Packet> {
        if self.is_native_pq_v1() {
            Ok(PqPacketV1::decode(raw)?.inner)
        } else {
            Packet::decode(raw)
        }
    }
}

/// Syntactically bounded PQP1 packet. It carries no verified work or admission.
#[derive(Clone, Debug)]
pub struct PqPacketV1 {
    pub(crate) inner: Packet,
}
impl PqPacketV1 {
    pub fn from_parts(header: Header, transactions: Vec<Vec<u8>>, proof: Vec<u8>) -> Result<Self> {
        let value = Self {
            inner: Packet {
                header,
                transactions,
                proof,
            },
        };
        checked_length(&value.inner)?;
        Ok(value)
    }
    pub(crate) fn from_packet(inner: Packet) -> Result<Self> {
        checked_length(&inner)?;
        Ok(Self { inner })
    }
    pub fn header(&self) -> &Header {
        &self.inner.header
    }
    pub fn transactions(&self) -> &[Vec<u8>] {
        &self.inner.transactions
    }
    pub fn proof(&self) -> &[u8] {
        &self.inner.proof
    }
    pub fn id(&self) -> Result<Hash> {
        self.inner.id()
    }
    pub fn encode(&self) -> Result<Vec<u8>> {
        encode(&self.inner)
    }
    pub fn decode(raw: &[u8]) -> Result<Self> {
        let minimum = 8 + HEADER_BYTES + 2 + pon_work::PROOF_BYTES;
        ensure(
            (minimum..=1_048_576).contains(&raw.len()),
            "PQ_PACKET_LIMIT",
        )?;
        ensure(raw.starts_with(wire::PACKET_PREFIX), "PQ_PACKET_PROFILE")?;
        let header = Header::decode(&raw[8..8 + HEADER_BYTES]).map_err(|_| "HEADER_CODEC")?;
        let mut pos = 8 + HEADER_BYTES;
        let count = u16::from_le_bytes([raw[pos], raw[pos + 1]]) as usize;
        pos += 2;
        ensure(count <= wire::MAX_TRANSACTIONS, "PQ_TRANSACTION_LIMIT")?;
        let mut transactions = Vec::with_capacity(count);
        let mut total = 0_usize;
        for _ in 0..count {
            let n = raw.get(pos..pos + 2).ok_or("PQ_PACKET_LENGTH")?;
            pos += 2;
            let len = u16::from_le_bytes([n[0], n[1]]) as usize;
            ensure(
                (wire::MIN_BYTES..=wire::MAX_BYTES).contains(&len),
                "PQ_TRANSACTION_LIMIT",
            )?;
            total = total.checked_add(len).ok_or("PQ_TRANSACTION_LIMIT")?;
            ensure(total <= wire::MAX_TRANSACTION_BYTES, "PQ_TRANSACTION_LIMIT")?;
            let tx = raw.get(pos..pos + len).ok_or("PQ_PACKET_LENGTH")?;
            UnverifiedEnvelope::decode(tx).map_err(|_| "PQ_TRANSACTION_CODEC")?;
            transactions.push(tx.to_vec());
            pos += len;
        }
        ensure(
            raw.len().checked_sub(pos) == Some(pon_work::PROOF_BYTES),
            "PQ_PACKET_LENGTH",
        )?;
        Self::from_parts(header, transactions, raw[pos..].to_vec())
    }
}
fn checked_length(packet: &Packet) -> Result<usize> {
    ensure(
        packet.transactions.len() <= wire::MAX_TRANSACTIONS
            && packet.proof.len() == pon_work::PROOF_BYTES,
        "PQ_PACKET_LIMIT",
    )?;
    let mut total = 0_usize;
    for raw in &packet.transactions {
        UnverifiedEnvelope::decode(raw).map_err(|_| "PQ_TRANSACTION_CODEC")?;
        total = total.checked_add(raw.len()).ok_or("PQ_TRANSACTION_LIMIT")?;
        ensure(total <= wire::MAX_TRANSACTION_BYTES, "PQ_TRANSACTION_LIMIT")?;
    }
    let length = 8 + HEADER_BYTES + 2 + packet.transactions.len() * 2 + total + packet.proof.len();
    ensure(length <= 1_048_576, "PQ_PACKET_LIMIT")?;
    Ok(length)
}
fn encode(packet: &Packet) -> Result<Vec<u8>> {
    let length = checked_length(packet)?;
    let mut raw = Vec::with_capacity(length);
    raw.extend(wire::PACKET_PREFIX);
    raw.extend(packet.header.encode());
    raw.extend((packet.transactions.len() as u16).to_le_bytes());
    for tx in &packet.transactions {
        raw.extend((tx.len() as u16).to_le_bytes());
        raw.extend(tx);
    }
    raw.extend(&packet.proof);
    ensure(raw.len() == length, "PQ_PACKET_LENGTH")?;
    Ok(raw)
}
impl Packet {
    pub(crate) fn encode_for_native_profile(&self, pq: bool) -> Result<Vec<u8>> {
        if pq {
            encode(self)
        } else {
            self.encode()
        }
    }
}

pub(crate) fn header_prefix_bytes(pq: bool) -> usize {
    HEADER_BYTES + if pq { 8 } else { 0 }
}
pub(crate) fn decode_header_projection(bytes: &[u8], pq: bool) -> Result<Header> {
    if pq {
        ensure(
            bytes.len() == HEADER_BYTES + 8 && bytes.starts_with(wire::PACKET_PREFIX),
            "PQ_HEADER_PROFILE",
        )?;
        Header::decode(&bytes[8..]).map_err(|_| "HEADER_CODEC".into())
    } else {
        Header::decode(bytes).map_err(|_| "HEADER_CODEC".into())
    }
}
