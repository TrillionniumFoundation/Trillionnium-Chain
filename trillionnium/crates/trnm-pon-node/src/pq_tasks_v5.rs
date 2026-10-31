//! Explicit NPQ5 task permissions and a separate protected anchored-import constructor.
//! No listener, governance, old-store upgrade or production activation.
pub use crate::pq_accounts_v2::GenesisAccount;
pub use crate::store::pq_tasks_v5::PqNodeV5;
use crate::{Packet, Result, Settings};
use trnm_mvcc_fee::pon_executor::pq_accounts_v2 as pq;
use trnm_protocol::pon_wire::{Hash, Header};
use trnm_protocol::pq_native_accounts_v2::AccountProfile;
impl Settings {
    pub fn native_pq_tasks_v5(accounts: &[GenesisAccount], timestamp: u64) -> Result<Self> {
        let (app, initial, genesis) = pq::genesis_tasks_v5(accounts, timestamp)?;
        Ok(Self {
            app,
            initial,
            genesis,
            operator_bootstrap: None,
            operator_material: None,
            checkpoint_tile_paths: None,
        })
    }
    /// A new namespace with original locked import/CLAIM semantics. This does
    /// not establish prior registry timing or retire/finalize the source chain.
    pub fn native_pq_tasks_v5_with_anchored_migration_v1(
        accounts: &[GenesisAccount],
        timestamp: u64,
        anchor: pq::TrustedMigrationAnchor,
    ) -> Result<Self> {
        let (app, initial, genesis) =
            pq::task_migration_v1::genesis_with_trusted_migration(accounts, timestamp, anchor)?;
        Ok(Self {
            app,
            initial,
            genesis,
            operator_bootstrap: None,
            operator_material: None,
            checkpoint_tile_paths: None,
        })
    }
    pub(crate) fn is_native_pq_v5(&self) -> bool {
        pq::tasks_v5_enabled(&self.app)
    }
}
/// Unverified packet with an exact PQP5 prefix; neither old packet decoder opts in.
#[derive(Clone, Debug)]
pub struct PqPacketV5 {
    pub(crate) inner: Packet,
}
impl PqPacketV5 {
    pub fn from_parts(header: Header, transactions: Vec<Vec<u8>>, proof: Vec<u8>) -> Result<Self> {
        Self::from_packet(Packet {
            header,
            transactions,
            proof,
        })
    }
    pub(crate) fn from_packet(inner: Packet) -> Result<Self> {
        crate::pq_accounts_v2::checked_length_for_profile(&inner, AccountProfile::TasksV5)?;
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
        crate::pq_accounts_v2::encode_packet_for_profile(&self.inner, AccountProfile::TasksV5)
    }
    pub fn decode(raw: &[u8]) -> Result<Self> {
        Self::from_packet(crate::pq_accounts_v2::decode_packet_for_profile(
            raw,
            AccountProfile::TasksV5,
        )?)
    }
}
