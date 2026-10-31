//! Explicit NPQ4 task permissions. No listener, renewal, governance or activation.
pub use crate::pq_accounts_v2::GenesisAccount;
pub use crate::store::pq_tasks_v4::PqNodeV4;
use crate::{Packet, Result, Settings};
use trnm_mvcc_fee::pon_executor::pq_accounts_v2 as pq;
use trnm_protocol::pon_wire::{Hash, Header};
use trnm_protocol::pq_native_accounts_v2::AccountProfile;
impl Settings {
    pub fn native_pq_tasks_v4(accounts: &[GenesisAccount], timestamp: u64) -> Result<Self> {
        let (app, initial, genesis) = pq::genesis_tasks_v4(accounts, timestamp)?;
        Ok(Self {
            app,
            initial,
            genesis,
            operator_bootstrap: None,
            operator_material: None,
            checkpoint_tile_paths: None,
        })
    }
    pub(crate) fn is_native_pq_v4(&self) -> bool {
        pq::tasks_v4_enabled(&self.app)
    }
}
/// Unverified packet with an exact PQP4 prefix; neither old packet decoder opts in.
#[derive(Clone, Debug)]
pub struct PqPacketV4 {
    pub(crate) inner: Packet,
}
impl PqPacketV4 {
    pub fn from_parts(header: Header, transactions: Vec<Vec<u8>>, proof: Vec<u8>) -> Result<Self> {
        Self::from_packet(Packet {
            header,
            transactions,
            proof,
        })
    }
    pub(crate) fn from_packet(inner: Packet) -> Result<Self> {
        crate::pq_accounts_v2::checked_length_for_profile(&inner, AccountProfile::TasksV4)?;
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
        crate::pq_accounts_v2::encode_packet_for_profile(&self.inner, AccountProfile::TasksV4)
    }
    pub fn decode(raw: &[u8]) -> Result<Self> {
        Self::from_packet(crate::pq_accounts_v2::decode_packet_for_profile(
            raw,
            AccountProfile::TasksV4,
        )?)
    }
}
