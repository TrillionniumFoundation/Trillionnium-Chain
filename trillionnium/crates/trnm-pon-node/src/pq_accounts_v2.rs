//! New native account/rotation/anchored-claim profile over original PoN owners.
//! Inner legacy signed tags and transport remain unsupported, not migrated.
pub use crate::store::pq_accounts_v2::PqNodeV2;
use crate::{ensure, Packet, Result, Settings};
pub use pq::{
    CheckpointMaterial, GenesisAccount, PrecommittedAccount, TrustedMigrationAnchor,
    TrustedPqPrecommitments,
};
use trnm_crypto_primitives::pon_work;
use trnm_mvcc_fee::pon_executor::pq_accounts_v2 as pq;
use trnm_protocol::pon_wire::{Hash, Header, HEADER_BYTES};
use trnm_protocol::pq_native_accounts_v2::{self as wire, UnverifiedEnvelope};
pub use wire::ChainContext;
impl Settings {
    pub fn native_pq_accounts_v2(accounts: &[GenesisAccount], timestamp: u64) -> Result<Self> {
        let (app, initial, genesis) = pq::genesis(accounts, timestamp)?;
        Ok(Self {
            app,
            initial,
            genesis,
            operator_bootstrap: None,
            operator_material: None,
            checkpoint_tile_paths: None,
        })
    }
    /// Protected new-network choice. No wire/old-store upgrade can mint an anchor.
    pub fn native_pq_accounts_v2_with_migration(
        accounts: &[GenesisAccount],
        timestamp: u64,
        anchor: TrustedMigrationAnchor,
    ) -> Result<Self> {
        let (app, initial, genesis) =
            pq::genesis_with_trusted_migration(accounts, timestamp, anchor)?;
        Ok(Self {
            app,
            initial,
            genesis,
            operator_bootstrap: None,
            operator_material: None,
            checkpoint_tile_paths: None,
        })
    }
    pub fn native_pq_accounts_context(&self) -> Result<ChainContext> {
        Ok(pq::context(&self.app)?)
    }
    pub(crate) fn is_native_pq_v2(&self) -> bool {
        pq::enabled(&self.app)
            && !pq::quota_v3_enabled(&self.app)
            && !pq::tasks_v4_enabled(&self.app)
            && !pq::tasks_v5_enabled(&self.app)
    }
}
/// Syntactically bounded PQP2 packet. It carries no verified work or admission.
#[derive(Clone, Debug)]
pub struct PqPacketV2 {
    pub(crate) inner: Packet,
}
impl PqPacketV2 {
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
        encode_packet(&self.inner)
    }
    pub fn decode(raw: &[u8]) -> Result<Self> {
        Ok(Self {
            inner: decode_packet_for_profile(raw, wire::AccountProfile::AccountsV2)?,
        })
    }
}
fn checked_length(packet: &Packet) -> Result<usize> {
    checked_length_for_profile(packet, wire::AccountProfile::AccountsV2)
}
pub(crate) fn checked_length_for_profile(
    packet: &Packet,
    profile: wire::AccountProfile,
) -> Result<usize> {
    ensure(
        packet.transactions.len() <= wire::MAX_TRANSACTIONS
            && packet.proof.len() == pon_work::PROOF_BYTES,
        "PQ2_PACKET_LIMIT",
    )?;
    let mut total = 0_usize;
    for raw in &packet.transactions {
        UnverifiedEnvelope::decode_for_profile(raw, profile)
            .map_err(|_| "PQ2_TRANSACTION_CODEC")?;
        total = total
            .checked_add(raw.len())
            .ok_or("PQ2_TRANSACTION_LIMIT")?;
        ensure(
            total <= wire::MAX_TRANSACTION_BYTES,
            "PQ2_TRANSACTION_LIMIT",
        )?;
    }
    let length = 8 + HEADER_BYTES + 2 + packet.transactions.len() * 2 + total + packet.proof.len();
    ensure(length <= 1_048_576, "PQ2_PACKET_LIMIT")?;
    Ok(length)
}
pub(crate) fn encode_packet(packet: &Packet) -> Result<Vec<u8>> {
    encode_packet_for_profile(packet, wire::AccountProfile::AccountsV2)
}
pub(crate) fn encode_packet_for_profile(
    packet: &Packet,
    profile: wire::AccountProfile,
) -> Result<Vec<u8>> {
    let length = checked_length_for_profile(packet, profile)?;
    let mut raw = Vec::with_capacity(length);
    raw.extend(profile.packet_prefix());
    raw.extend(packet.header.encode());
    raw.extend((packet.transactions.len() as u16).to_le_bytes());
    for tx in &packet.transactions {
        raw.extend((tx.len() as u16).to_le_bytes());
        raw.extend(tx);
    }
    raw.extend(&packet.proof);
    ensure(raw.len() == length, "PQ2_PACKET_LENGTH")?;
    Ok(raw)
}

pub(crate) fn decode_packet_for_profile(
    raw: &[u8],
    profile: wire::AccountProfile,
) -> Result<Packet> {
    let minimum = 8 + HEADER_BYTES + 2 + pon_work::PROOF_BYTES;
    ensure(
        (minimum..=1_048_576).contains(&raw.len()),
        "PQ2_PACKET_LIMIT",
    )?;
    ensure(
        raw.starts_with(profile.packet_prefix()),
        "PQ2_PACKET_PROFILE",
    )?;
    let header = Header::decode(&raw[8..8 + HEADER_BYTES]).map_err(|_| "HEADER_CODEC")?;
    let mut pos = 8 + HEADER_BYTES;
    let count = u16::from_le_bytes([raw[pos], raw[pos + 1]]) as usize;
    pos += 2;
    ensure(count <= wire::MAX_TRANSACTIONS, "PQ2_TRANSACTION_LIMIT")?;
    let mut transactions = Vec::with_capacity(count);
    let mut total = 0_usize;
    for _ in 0..count {
        let n = raw.get(pos..pos + 2).ok_or("PQ2_PACKET_LENGTH")?;
        pos += 2;
        let len = u16::from_le_bytes([n[0], n[1]]) as usize;
        ensure(
            (wire::MIN_BYTES..=wire::MAX_BYTES).contains(&len),
            "PQ2_TRANSACTION_LIMIT",
        )?;
        total = total.checked_add(len).ok_or("PQ2_TRANSACTION_LIMIT")?;
        ensure(
            total <= wire::MAX_TRANSACTION_BYTES,
            "PQ2_TRANSACTION_LIMIT",
        )?;
        let tx = raw.get(pos..pos + len).ok_or("PQ2_PACKET_LENGTH")?;
        UnverifiedEnvelope::decode_for_profile(tx, profile).map_err(|_| "PQ2_TRANSACTION_CODEC")?;
        transactions.push(tx.to_vec());
        pos += len;
    }
    ensure(
        raw.len().checked_sub(pos) == Some(pon_work::PROOF_BYTES),
        "PQ2_PACKET_LENGTH",
    )?;
    let packet = Packet {
        header,
        transactions,
        proof: raw[pos..].to_vec(),
    };
    checked_length_for_profile(&packet, profile)?;
    Ok(packet)
}
