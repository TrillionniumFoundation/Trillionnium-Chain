//! Format an already-read public History page without holding the Node mutex.
//! The actual ancestry/body read stays under its original owner. Only owned
//! packet material and bounded immutable encoding context leave that scope.
use super::{digest, ensure, lock_owner, Node, Result, Settings, MAX_HISTORY_STEPS, MAX_PACKET};
use crate::Packet;
use serde_json::Value;
use std::sync::Mutex;
use trnm_mvcc_fee::pon_executor::pq_accounts_v2;
use trnm_protocol::{pon_wire::Hash, pq_native_accounts_v2::AccountProfile};

// Preserve the independent importer's original total hex allowance and its
// 1024-byte Page framing reserve. The V3 signed response keeps its own original
// MAX_RESPONSE fence after formatting/signing. Neither ceiling grows per packet.
const MAX_PAGE_HEX_BYTES: usize = crate::ingress::MAX_FRAME - 1024;

struct EncodingContext {
    schema: &'static str,
    network: Hash,
    parameters: Hash,
    genesis: Hash,
    packet_profile: Option<AccountProfile>,
}
impl EncodingContext {
    fn capture(settings: &Settings, has_packet: bool) -> Result<Self> {
        Ok(Self {
            schema: if settings.is_native_pq_application_v6() {
                "pon-native-pq-history-v6"
            } else {
                "pon-native-history-v1"
            },
            network: settings.network(),
            parameters: settings.parameters(),
            genesis: settings.genesis(),
            packet_profile: if has_packet && pq_accounts_v2::enabled(&settings.app) {
                Some(pq_accounts_v2::account_profile(&settings.app)?)
            } else {
                None
            },
        })
    }
    fn encode(&self, packet: &Packet) -> Result<Vec<u8>> {
        match self.packet_profile {
            Some(profile) => crate::pq_application_v6::encode_packet_for_profile(packet, profile),
            None => packet.encode(),
        }
    }
}

pub(super) fn read(
    node: &Mutex<Node>,
    tip: String,
    after: String,
    progress: &mut dyn FnMut(u64) -> Result<()>,
) -> Result<Value> {
    let mut used = 0;
    let (packets, next, context, tip_id) = {
        let mut checked_progress = |steps| {
            used = steps;
            progress(steps)
        };
        let owner = lock_owner(node, &mut checked_progress)?;
        let tip_id = digest(&tip)?;
        let after_id = digest(&after)?;
        // Preserve the existing two-phase research control and all its final
        // source/epoch/read-fact/body fences. It remains test-only.
        #[cfg(test)]
        if owner.public_history_test_snapshot && tip_id != after_id {
            let snapshot = owner.prepare_public_history_snapshot(
                tip_id,
                after_id,
                MAX_HISTORY_STEPS,
                &mut checked_progress,
            )?;
            drop(owner);
            let read = snapshot.read(&mut checked_progress)?;
            let owner = lock_owner(node, &mut checked_progress)?;
            return owner.finish_public_history_snapshot(read, &mut checked_progress);
        }
        let packets = owner.public_history_page(
            tip_id,
            after_id,
            MAX_HISTORY_STEPS,
            MAX_PAGE_HEX_BYTES / 2,
            &mut checked_progress,
        )?;
        let next = packets
            .last()
            .map(|packet| packet.id().map(hex::encode))
            .transpose()?
            .unwrap_or_else(|| after.clone());
        let context = EncodingContext::capture(owner.settings(), !packets.is_empty())?;
        (packets, next, context, tip_id)
    };
    // The guard and its callback borrow have ended. No Settings/initial State
    // clone or SQLite handle escapes; the captured values grant no work, State
    // or activation authority.
    // Keep the same original deadline/stop/CPU callback and cumulative SQL count.
    progress(used)?;
    let mut encoded = Vec::with_capacity(packets.len());
    let mut hex_bytes = 0_usize;
    for packet in packets {
        let raw = context.encode(&packet)?;
        let length = raw.len().checked_mul(2).ok_or("PUBLIC_HISTORY_BYTES")?;
        hex_bytes = hex_bytes
            .checked_add(length)
            .ok_or("PUBLIC_HISTORY_BYTES")?;
        ensure(
            length <= 2 * MAX_PACKET && hex_bytes <= MAX_PAGE_HEX_BYTES,
            "PUBLIC_HISTORY_BYTES",
        )?;
        encoded.push(hex::encode(raw));
        progress(used)?;
    }
    let page = serde_json::to_value(crate::ingress::Page {
        schema: context.schema.into(),
        network: hex::encode(context.network),
        parameters: hex::encode(context.parameters),
        genesis: hex::encode(context.genesis),
        tip,
        after,
        complete: next == hex::encode(tip_id),
        next,
        packets: encoded,
    })?;
    progress(used)?;
    Ok(page)
}

#[cfg(test)]
#[path = "history_response_tests.rs"]
mod tests;
