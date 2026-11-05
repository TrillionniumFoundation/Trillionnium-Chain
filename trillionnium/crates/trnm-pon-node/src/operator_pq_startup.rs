//! Explicit NPQ6 startup for the original continuous owner. Genesis contains
//! public account configuration only. Its final digest is fixed BEFORE the two
//! ordinary OPEN/REGISTER transactions are signed and mined. This is neither a
//! state import nor a work/fee exemption, and grants no production readiness.
use crate::{ensure, ingress::pq_network::PqNetworkPolicy, Hash, Node, Packet, Result, Settings};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use trnm_mvcc_fee::pon_executor::pq_accounts_v2 as pq;
use trnm_protocol::{
    pq_native_accounts_v2::{AccountProfile, ChainContext, UnverifiedEnvelope},
    qualified_work_task::pq_lifecycle_v5::{DemandLeaseV5, TaskRegistrationV5},
};

pub const SPEC_SCHEMA: &str = "restricted-continuous-pq-startup-spec-v1";
pub const BUNDLE_SCHEMA: &str = "restricted-continuous-pq-startup-bundle-v1";
pub const SPEC_BYTES: usize = 512 << 10;
pub const BUNDLE_BYTES: usize = 512 << 10;
pub const CATALOG_DOMAIN: &[u8] = b"TRNM/PoN/ContinuousStartupCatalog/PQ/v1\0";

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct StartupAccount {
    pub spki: String,
    pub balance: u64,
}

/// Public-only protected configuration. No transaction, lease, signature or
/// caller-selected genesis digest is accepted as genesis State.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct StartupSpec {
    pub schema: String,
    pub genesis_timestamp: u64,
    pub accounts: Vec<StartupAccount>,
    pub evaluators: Vec<String>,
    pub evaluation_profile: String,
    pub model_profile: String,
    pub server_spki: String,
    pub network_generation: u64,
    pub peer_spkis: Vec<String>,
}

fn canonical_hex(raw: &str, limit: usize) -> Result<Vec<u8>> {
    ensure(raw.len() <= limit * 2, "PQ_STARTUP_HEX_SIZE")?;
    let bytes = hex::decode(raw).map_err(|_| "PQ_STARTUP_HEX")?;
    ensure(hex::encode(&bytes) == raw, "PQ_STARTUP_HEX")?;
    Ok(bytes)
}

fn decode<T: for<'a> Deserialize<'a> + Serialize>(raw: &[u8], limit: usize) -> Result<T> {
    ensure(!raw.is_empty() && raw.len() <= limit, "PQ_STARTUP_SIZE")?;
    let value: T = serde_json::from_slice(raw)?;
    ensure(serde_json::to_vec(&value)? == raw, "PQ_STARTUP_CANONICAL")?;
    Ok(value)
}

impl StartupSpec {
    pub fn decode(raw: &[u8]) -> Result<Self> {
        let value: Self = decode(raw, SPEC_BYTES)?;
        ensure(value.schema == SPEC_SCHEMA, "PQ_STARTUP_SPEC_SCHEMA")?;
        Ok(value)
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        let raw = serde_json::to_vec(self)?;
        Self::decode(&raw)?;
        Ok(raw)
    }

    /// The producer calls this before obtaining the actual requester/source
    /// signatures. Every consumer derives exactly the same NPQ6 genesis.
    pub fn settings(&self) -> Result<Settings> {
        ensure(self.schema == SPEC_SCHEMA, "PQ_STARTUP_SPEC_SCHEMA")?;
        ensure(
            (2..=pq::MAX_GENESIS_ACCOUNTS).contains(&self.accounts.len())
                && (2..=16).contains(&self.evaluators.len())
                && self.evaluators.windows(2).all(|pair| pair[0] < pair[1]),
            "PQ_STARTUP_ACCOUNT_LIMIT",
        )?;
        let accounts: Vec<_> = self
            .accounts
            .iter()
            .map(|account| {
                Ok(pq::GenesisAccount {
                    spki: canonical_hex(
                        &account.spki,
                        trnm_protocol::pq_frame::ML_DSA_65_SPKI_BYTES,
                    )?,
                    balance: account.balance,
                })
            })
            .collect::<Result<_>>()?;
        let evaluators = self
            .evaluators
            .iter()
            .map(|id| crate::digest(id))
            .collect::<Result<BTreeSet<_>>>()?;
        Settings::native_pq_application_v6(
            &accounts,
            self.genesis_timestamp,
            &pq::application_v6::ApplicationPolicy {
                evaluators,
                evaluation_profile: self.evaluation_profile.clone(),
                model_profile: self.model_profile.clone(),
            },
        )
    }

    pub fn network_policy(&self, settings: &Settings) -> Result<PqNetworkPolicy> {
        ensure(
            settings.is_native_pq_application_v6(),
            "PQ_STARTUP_APPLICATION_PROFILE",
        )?;
        ensure(
            (1..=64).contains(&self.peer_spkis.len()),
            "PQ_STARTUP_PEER_LIMIT",
        )?;
        let server = canonical_hex(
            &self.server_spki,
            trnm_protocol::pq_frame::ML_DSA_65_SPKI_BYTES,
        )?;
        let peers = self
            .peer_spkis
            .iter()
            .map(|raw| canonical_hex(raw, trnm_protocol::pq_frame::ML_DSA_65_SPKI_BYTES))
            .collect::<Result<Vec<_>>>()?;
        PqNetworkPolicy::new(settings, &server, self.network_generation, peers)
    }
}

/// Exactly two real, consecutive genesis-maintenance packets. They carry only
/// the ordinary NPQ6 OPEN and dual-authority REGISTER command, respectively.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct StartupBundle {
    pub schema: String,
    pub genesis: String,
    pub packets: Vec<String>,
}

impl StartupBundle {
    pub fn decode(raw: &[u8]) -> Result<Self> {
        let value: Self = decode(raw, BUNDLE_BYTES)?;
        ensure(
            value.schema == BUNDLE_SCHEMA && value.packets.len() == 2,
            "PQ_STARTUP_BUNDLE_SCHEMA",
        )?;
        Ok(value)
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        let raw = serde_json::to_vec(self)?;
        Self::decode(&raw)?;
        Ok(raw)
    }

    /// Uses the actual Node producer, verifier, M06 execution and activation.
    /// The caller supplies signatures made AFTER deriving spec.settings(); no
    /// signer is fabricated and no startup funds or chainwork are assigned.
    pub fn produce(
        node: &mut Node,
        commands: [Vec<u8>; 2],
        miner: Hash,
        observed_now: u64,
        max_attempts: u64,
    ) -> Result<Self> {
        let settings = node.settings().clone();
        ensure(
            settings.is_native_pq_application_v6(),
            "PQ_STARTUP_APPLICATION_PROFILE",
        )?;
        ensure(
            node.active()? == (settings.genesis(), 0),
            "PQ_STARTUP_PRODUCER_FRESH",
        )?;
        checked_commands(&settings, &commands)?;
        let mut parent = settings.genesis();
        let mut packets = Vec::with_capacity(2);
        for (index, command) in commands.into_iter().enumerate() {
            let timestamp = settings
                .genesis_time()
                .checked_add(index as u64 + 1)
                .ok_or("PQ_STARTUP_TIME")?;
            let packet = node.make_consensus_maintenance(
                parent,
                vec![command],
                miner,
                timestamp,
                max_attempts,
            )?;
            parent = node.admit(&packet, observed_now)?;
            ensure(
                node.activate_observed(parent, observed_now)? == parent,
                "PQ_STARTUP_ACTIVATION",
            )?;
            packets.push(hex::encode(packet.encode_for_settings(&settings)?));
        }
        let bundle = Self {
            schema: BUNDLE_SCHEMA.into(),
            genesis: hex::encode(settings.genesis()),
            packets,
        };
        bundle.encode()?;
        Ok(bundle)
    }
}

fn checked_commands(
    settings: &Settings,
    commands: &[Vec<u8>],
) -> Result<(DemandLeaseV5, TaskRegistrationV5)> {
    ensure(commands.len() == 2, "PQ_STARTUP_COMMAND_COUNT")?;
    let context = ChainContext {
        network: settings.network(),
        parameters: settings.parameters(),
        genesis: settings.genesis(),
    };
    let open = UnverifiedEnvelope::decode_for_profile(&commands[0], AccountProfile::ApplicationV6)
        .map_err(|_| "PQ_STARTUP_COMMAND_PROFILE")?;
    let register =
        UnverifiedEnvelope::decode_for_profile(&commands[1], AccountProfile::ApplicationV6)
            .map_err(|_| "PQ_STARTUP_COMMAND_PROFILE")?;
    ensure(
        open.kind == 18
            && register.kind == 21
            && open.common.context == context
            && register.common.context == context,
        "PQ_STARTUP_COMMAND_CONTEXT",
    )?;
    let lease = DemandLeaseV5::decode(open.payload).map_err(|_| "PQ_STARTUP_LEASE")?;
    let registration =
        TaskRegistrationV5::decode(register.payload).map_err(|_| "PQ_STARTUP_TASK")?;
    ensure(
        open.common.account == lease.requester
            && register.common.account == lease.requester
            && registration.lease_id == lease.id().map_err(|_| "PQ_STARTUP_LEASE")?,
        "PQ_STARTUP_COMMAND_BINDING",
    )?;
    Ok((lease, registration))
}

/// Cannot be manufactured by an input flag. Only the explicit PQ catalog branch
/// constructs this bounded binding; Work and signatures still belong to Node.
pub(crate) struct PreparedStartup {
    pub packets: Vec<Packet>,
    pub encoded: Vec<Vec<u8>>,
    pub ids: Vec<Hash>,
    pub lease: DemandLeaseV5,
    pub task: Hash,
}

impl PreparedStartup {
    pub(crate) fn decode(raw: &[u8], settings: &Settings) -> Result<Self> {
        let bundle = StartupBundle::decode(raw)?;
        ensure(
            bundle.genesis == hex::encode(settings.genesis()),
            "PQ_STARTUP_GENESIS",
        )?;
        let encoded = bundle
            .packets
            .iter()
            .map(|raw| canonical_hex(raw, BUNDLE_BYTES / 2))
            .collect::<Result<Vec<_>>>()?;
        let mut parent = settings.genesis();
        let mut ids = Vec::with_capacity(2);
        let mut packets = Vec::with_capacity(2);
        let mut commands = Vec::with_capacity(2);
        let maintenance = trnm_mvcc_fee::continuity_v1::maintenance_task()?;
        for (index, raw) in encoded.iter().enumerate() {
            let packet = Packet::decode_for_settings(raw, settings)?;
            ensure(
                packet.header.network == settings.network()
                    && packet.header.parameters == settings.parameters()
                    && packet.header.parent == parent
                    && packet.header.height == index as u64 + 1
                    && packet.header.work_task == maintenance
                    && packet.transactions.len() == 1,
                "PQ_STARTUP_PACKET_CONTEXT",
            )?;
            parent = packet.id()?;
            ids.push(parent);
            commands.push(packet.transactions[0].clone());
            packets.push(packet);
        }
        let (lease, registration) = checked_commands(settings, &commands)?;
        Ok(Self {
            packets,
            encoded,
            ids,
            lease,
            task: registration.manifest.matrix_task,
        })
    }

    pub(crate) fn head(&self) -> Hash {
        self.ids[1]
    }

    pub(crate) fn matches_packet(&self, raw: &[u8]) -> bool {
        self.encoded.iter().any(|expected| expected == raw)
    }

    pub(crate) fn matches_execution(
        &self,
        parent: Hash,
        miner: Hash,
        height: u64,
        transactions: &[Vec<u8>],
    ) -> bool {
        self.packets.iter().any(|packet| {
            packet.header.parent == parent
                && packet.header.miner == miner
                && packet.header.height == height
                && packet.transactions == transactions
        })
    }
}

#[cfg(all(test, target_os = "linux"))]
#[path = "operator_pq_startup_tests.rs"]
mod tests;
