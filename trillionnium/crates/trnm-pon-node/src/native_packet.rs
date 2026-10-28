//! Internal exact selected packet grammar; no automatic profile negotiation.
use crate::{ensure, Packet, Result, Settings};
use trnm_protocol::pon_wire::{Header, HEADER_BYTES};
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Profile {
    Legacy,
    Pq1,
    Pq2,
    Pq3,
}
impl Settings {
    pub(crate) fn packet_profile(&self) -> Profile {
        if self.is_native_pq_v3() {
            Profile::Pq3
        } else if self.is_native_pq_v2() {
            Profile::Pq2
        } else if self.is_native_pq_v1() {
            Profile::Pq1
        } else {
            Profile::Legacy
        }
    }
    pub(crate) fn is_native_pq(&self) -> bool {
        self.packet_profile() != Profile::Legacy
    }
}
pub(crate) fn header_prefix_bytes(profile: Profile) -> usize {
    match profile {
        Profile::Legacy => crate::pq_native_v1::header_prefix_bytes(false),
        Profile::Pq1 => crate::pq_native_v1::header_prefix_bytes(true),
        Profile::Pq2 | Profile::Pq3 => HEADER_BYTES + 8,
    }
}
pub(crate) fn decode_header_projection(bytes: &[u8], profile: Profile) -> Result<Header> {
    match profile {
        Profile::Legacy => crate::pq_native_v1::decode_header_projection(bytes, false),
        Profile::Pq1 => crate::pq_native_v1::decode_header_projection(bytes, true),
        Profile::Pq2 | Profile::Pq3 => {
            ensure(
                bytes.len() == HEADER_BYTES + 8
                    && bytes.starts_with(match profile {
                        Profile::Pq2 => {
                            trnm_protocol::pq_native_accounts_v2::AccountProfile::AccountsV2
                                .packet_prefix()
                        }
                        Profile::Pq3 => {
                            trnm_protocol::pq_native_accounts_v2::AccountProfile::QuotaV3
                                .packet_prefix()
                        }
                        _ => unreachable!(),
                    }),
                "PQ2_HEADER_PROFILE",
            )?;
            Header::decode(&bytes[8..]).map_err(|_| "HEADER_CODEC".into())
        }
    }
}
pub(crate) fn encode(packet: &Packet, profile: Profile) -> Result<Vec<u8>> {
    match profile {
        Profile::Legacy => packet.encode_for_native_profile(false),
        Profile::Pq1 => packet.encode_for_native_profile(true),
        Profile::Pq2 => crate::pq_accounts_v2::encode_packet(packet),
        Profile::Pq3 => crate::pq_accounts_v2::encode_packet_for_profile(
            packet,
            trnm_protocol::pq_native_accounts_v2::AccountProfile::QuotaV3,
        ),
    }
}
pub(crate) fn decode(raw: &[u8], profile: Profile) -> Result<Packet> {
    match profile {
        Profile::Legacy => Packet::decode(raw),
        Profile::Pq1 => Ok(crate::pq_native_v1::PqPacketV1::decode(raw)?.inner),
        Profile::Pq2 => Ok(crate::pq_accounts_v2::PqPacketV2::decode(raw)?.inner),
        Profile::Pq3 => Ok(crate::pq_quota_v3::PqPacketV3::decode(raw)?.inner),
    }
}
