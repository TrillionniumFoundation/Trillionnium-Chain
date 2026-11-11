//! Settings-selected PQ packet namespace over the original Node and M06 owners.
//! A parser supplies no account, work, activation or deployment qualification.
use crate::{ensure, Packet, Result, Settings};
pub use pq::application_v6::ApplicationPolicy;
pub use pq::{GenesisAccount, TrustedMigrationAnchor};
use trnm_crypto_primitives::pon_work;
use trnm_mvcc_fee::pon_executor::{pq_accounts_v2 as pq, Config};
use trnm_protocol::pon_wire::{Header, HEADER_BYTES};
use trnm_protocol::pq_native_accounts_v2::{self as wire, UnverifiedEnvelope};

/// An immutable copy of the original packet configuration, without genesis
/// State or operator task material. History only needs this configuration while
/// its Node owner is unlocked. Profile validation still runs at every original
/// codec/identity call; construction neither validates nor caches a verdict.
pub(crate) struct PacketCodecContext {
    app: Config,
}

impl PacketCodecContext {
    pub(crate) fn network(&self) -> crate::Hash {
        self.app.network
    }
    pub(crate) fn parameters(&self) -> crate::Hash {
        self.app.parameters
    }
    pub(crate) fn is_pq(&self) -> bool {
        pq::enabled(&self.app)
    }
    pub(crate) fn encode(&self, packet: &Packet) -> Result<Vec<u8>> {
        encode_packet_for_config(packet, &self.app)
    }
    pub(crate) fn decode(&self, raw: &[u8]) -> Result<Packet> {
        decode_packet_for_config(raw, &self.app)
    }
}

impl Settings {
    pub(crate) fn packet_codec_context(&self) -> PacketCodecContext {
        PacketCodecContext {
            app: self.app.clone(),
        }
    }
    pub fn native_pq_application_v6(
        accounts: &[GenesisAccount],
        timestamp: u64,
        policy: &ApplicationPolicy,
    ) -> Result<Self> {
        let (app, initial, genesis) = pq::application_v6::genesis(accounts, timestamp, policy)?;
        Ok(Self {
            app,
            initial,
            genesis,
            operator_bootstrap: None,
            operator_material: None,
            checkpoint_tile_paths: None,
        })
    }
    pub fn native_pq_application_v6_with_migration(
        accounts: &[GenesisAccount],
        timestamp: u64,
        anchor: TrustedMigrationAnchor,
        policy: &ApplicationPolicy,
    ) -> Result<Self> {
        let (app, initial, genesis) = pq::application_v6::genesis_with_trusted_migration(
            accounts, timestamp, anchor, policy,
        )?;
        Ok(Self {
            app,
            initial,
            genesis,
            operator_bootstrap: None,
            operator_material: None,
            checkpoint_tile_paths: None,
        })
    }
    pub fn is_native_pq_application_v6(&self) -> bool {
        pq::application_v6::enabled(&self.app)
    }
    pub(crate) fn packet_header_length(&self) -> usize {
        HEADER_BYTES + if pq::enabled(&self.app) { 8 } else { 0 }
    }
    pub(crate) fn decode_packet_header(&self, raw: &[u8]) -> Result<Header> {
        if pq::enabled(&self.app) {
            let profile = pq::account_profile(&self.app)?;
            ensure(
                raw.len() == HEADER_BYTES + 8 && raw.starts_with(profile.packet_prefix()),
                "PQ_PACKET_PROFILE",
            )?;
            Ok(Header::decode(&raw[8..]).map_err(|_| "HEADER_CODEC")?)
        } else {
            Ok(Header::decode(raw).map_err(|_| "HEADER_CODEC")?)
        }
    }
}
impl Packet {
    pub fn checked_wire_length_for_settings(&self, settings: &Settings) -> Result<usize> {
        if pq::enabled(&settings.app) {
            checked_length_for_profile(self, pq::account_profile(&settings.app)?)
        } else {
            self.checked_wire_length()
        }
    }
    pub fn encode_for_settings(&self, settings: &Settings) -> Result<Vec<u8>> {
        encode_packet_for_config(self, &settings.app)
    }
    pub fn decode_for_settings(raw: &[u8], settings: &Settings) -> Result<Self> {
        decode_packet_for_config(raw, &settings.app)
    }
}
fn encode_packet_for_config(packet: &Packet, app: &Config) -> Result<Vec<u8>> {
    if pq::enabled(app) {
        encode_packet_for_profile(packet, pq::account_profile(app)?)
    } else {
        packet.encode()
    }
}
fn decode_packet_for_config(raw: &[u8], app: &Config) -> Result<Packet> {
    if pq::enabled(app) {
        decode_packet_for_profile(raw, pq::account_profile(app)?)
    } else {
        Packet::decode(raw)
    }
}
pub(crate) fn checked_length_for_profile(
    packet: &Packet,
    profile: wire::AccountProfile,
) -> Result<usize> {
    ensure(
        packet.transactions.len() <= profile.maximum_transactions()
            && packet.proof.len() == pon_work::PROOF_BYTES,
        "PQ2_PACKET_LIMIT",
    )?;
    let mut total = 0_usize;
    let mut verifications = 0_usize;
    for raw in &packet.transactions {
        let decoded = UnverifiedEnvelope::decode_for_profile(raw, profile)
            .map_err(|_| "PQ2_TRANSACTION_CODEC")?;
        verifications = verifications
            .checked_add(decoded.verification_count())
            .ok_or("PQ_VERIFY_BUDGET")?;
        ensure(
            verifications <= profile.maximum_verifications(),
            "PQ_VERIFY_BUDGET",
        )?;
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
    ensure(
        count <= profile.maximum_transactions(),
        "PQ2_TRANSACTION_LIMIT",
    )?;
    let mut transactions = Vec::with_capacity(count);
    let mut total = 0_usize;
    let mut verifications = 0_usize;
    for _ in 0..count {
        let n = raw.get(pos..pos + 2).ok_or("PQ2_PACKET_LENGTH")?;
        pos += 2;
        let len = u16::from_le_bytes([n[0], n[1]]) as usize;
        ensure(
            (wire::MIN_BYTES..=profile.maximum_bytes()).contains(&len),
            "PQ2_TRANSACTION_LIMIT",
        )?;
        total = total.checked_add(len).ok_or("PQ2_TRANSACTION_LIMIT")?;
        ensure(
            total <= wire::MAX_TRANSACTION_BYTES,
            "PQ2_TRANSACTION_LIMIT",
        )?;
        let tx = raw.get(pos..pos + len).ok_or("PQ2_PACKET_LENGTH")?;
        let decoded = UnverifiedEnvelope::decode_for_profile(tx, profile)
            .map_err(|_| "PQ2_TRANSACTION_CODEC")?;
        // Retain each exact witness/evidence budget while its fully checked
        // envelope is available. Do not preflight the same frame a second time.
        verifications = verifications
            .checked_add(decoded.verification_count())
            .ok_or("PQ_VERIFY_BUDGET")?;
        transactions.push(tx.to_vec());
        pos += len;
    }
    // Check the entire framed input and original proof suffix BEFORE the
    // verification quota, retaining the original decode error precedence.
    ensure(
        raw.len().checked_sub(pos) == Some(pon_work::PROOF_BYTES),
        "PQ2_PACKET_LENGTH",
    )?;
    ensure(
        verifications <= profile.maximum_verifications(),
        "PQ_VERIFY_BUDGET",
    )?;
    // Count, per-command lengths, total bytes and framing were already checked
    // while decoding. Their exact sum equals raw.len(); do not re-run the full
    // envelope parser through checked_length_for_profile (encoding retains it).
    Ok(Packet {
        header,
        transactions,
        proof: raw[pos..].to_vec(),
    })
}

#[cfg(test)]
mod decode_budget_tests {
    use super::*;

    fn empty_packet() -> Packet {
        Packet {
            header: Header {
                network: [1; 32],
                parameters: [2; 32],
                parent: [3; 32],
                height: 1,
                timestamp: 2,
                target: [4; 32],
                miner: [5; 32],
                transactions: [6; 32],
                state: [7; 32],
                receipts: [8; 32],
                work_task: [9; 32],
                nonce: 3,
            },
            transactions: Vec::new(),
            proof: vec![0; pon_work::PROOF_BYTES],
        }
    }

    #[test]
    fn all_pq_profiles_keep_exact_framing_and_error_identities() {
        let packet = empty_packet();
        for profile in [
            wire::AccountProfile::AccountsV2,
            wire::AccountProfile::QuotaV3,
            wire::AccountProfile::TasksV4,
            wire::AccountProfile::TasksV5,
            wire::AccountProfile::ApplicationV6,
        ] {
            let raw = encode_packet_for_profile(&packet, profile).unwrap();
            let decoded = decode_packet_for_profile(&raw, profile).unwrap();
            assert_eq!(decoded.header, packet.header);
            assert!(decoded.transactions.is_empty());
            assert_eq!(decoded.proof, packet.proof);
            assert_eq!(encode_packet_for_profile(&decoded, profile).unwrap(), raw);

            let mut wrong_profile = raw.clone();
            wrong_profile[0] ^= 1;
            assert_eq!(
                decode_packet_for_profile(&wrong_profile, profile)
                    .unwrap_err()
                    .to_string(),
                "PQ2_PACKET_PROFILE"
            );

            let mut over_count = raw.clone();
            let offset = 8 + HEADER_BYTES;
            over_count[offset..offset + 2]
                .copy_from_slice(&((profile.maximum_transactions() + 1) as u16).to_le_bytes());
            assert_eq!(
                decode_packet_for_profile(&over_count, profile)
                    .unwrap_err()
                    .to_string(),
                "PQ2_TRANSACTION_LIMIT"
            );

            let mut empty_transaction = raw.clone();
            empty_transaction[offset..offset + 2].copy_from_slice(&1u16.to_le_bytes());
            empty_transaction.splice(offset + 2..offset + 2, [0u8, 0u8]);
            assert_eq!(
                decode_packet_for_profile(&empty_transaction, profile)
                    .unwrap_err()
                    .to_string(),
                "PQ2_TRANSACTION_LIMIT"
            );

            let mut trailing = raw.clone();
            trailing.push(0);
            assert_eq!(
                decode_packet_for_profile(&trailing, profile)
                    .unwrap_err()
                    .to_string(),
                "PQ2_PACKET_LENGTH"
            );
        }
    }
}
