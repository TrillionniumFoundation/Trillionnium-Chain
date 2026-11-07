//! Bounded public History reads under the original Node owner.
//! V2 retains its one-packet contract. V3 batches the same current ancestry and
//! packet checks, sharing one SQL and byte allowance across the whole page.
use super::*;
use crate::ancestry_index::PublicHistoryPageBudget;

const MAX_PACKET_BYTES: usize = 1_048_576;
const MAX_PAGE_PACKETS: usize = 16;

impl Node {
    /// One public history packet, with exact ancestry and pre-allocation bounds.
    /// This remains the original V2 and local single-packet read contract.
    pub(crate) fn public_history_packet(
        &self,
        tip: Hash,
        after: Hash,
        maximum_steps: u64,
        progress: &mut dyn FnMut(u64) -> Result<()>,
    ) -> Result<Vec<Packet>> {
        progress(0)?;
        self.ready()?;
        #[cfg(test)]
        let maximum_steps = self
            .public_history_test_sql_limit
            .map_or(maximum_steps, |limit| maximum_steps.min(limit));
        let lookup = crate::ancestry_index::next_public_request(
            &self.db,
            self.ancestry_context()?,
            tip,
            after,
            maximum_steps,
            progress,
        )?;
        let Some(id) = lookup.next else {
            return Ok(Vec::new());
        };
        let mut used = lookup.sql_lookups;
        let (packet, _) = self.read_public_history_packet(id, after, lookup.height, &mut || {
            used += 1;
            progress(used)
        })?;
        Ok(vec![packet])
    }

    /// At most sixteen consecutive packets, with one cumulative SQL allowance
    /// and a caller-owned raw-byte ceiling no larger than the original packet
    /// ceiling. Every returned body still requires independent native replay.
    pub(crate) fn public_history_page(
        &self,
        tip: Hash,
        after: Hash,
        maximum_steps: u64,
        maximum_bytes: usize,
        progress: &mut dyn FnMut(u64) -> Result<()>,
    ) -> Result<Vec<Packet>> {
        progress(0)?;
        self.ready()?;
        ensure(
            (1..=MAX_PACKET_BYTES).contains(&maximum_bytes),
            "PUBLIC_HISTORY_BYTES",
        )?;
        #[cfg(test)]
        let maximum_steps = self
            .public_history_test_sql_limit
            .map_or(maximum_steps, |limit| maximum_steps.min(limit));
        let context = self.ancestry_context()?;
        let mut budget = PublicHistoryPageBudget::new(maximum_steps, progress)?;
        let minimum_packet = self.settings.packet_header_length() + 2 + pon_work::PROOF_BYTES;
        let mut packets = Vec::with_capacity(MAX_PAGE_PACKETS);
        let mut cursor = after;
        let mut bytes = 0_usize;
        loop {
            let lookup = budget.next(&self.db, context, tip, cursor)?;
            let Some(id) = lookup.next else {
                break;
            };
            let (packet, length) =
                self.read_public_history_packet(id, cursor, lookup.height, &mut || {
                    budget.charge_packet_read()
                })?;
            let next_bytes = bytes.checked_add(length).ok_or("PUBLIC_HISTORY_BYTES")?;
            if next_bytes > maximum_bytes {
                // The candidate was bounded and fully decoded BEFORE choosing
                // a page boundary. A bad body is never hidden by byte pressure.
                // Leave this valid candidate at the next page's cursor; do not
                // publish an empty nonterminal page or advance past its bytes.
                ensure(!packets.is_empty(), "PUBLIC_HISTORY_BYTES")?;
                break;
            }
            packets.push(packet);
            bytes = next_bytes;
            cursor = id;
            if cursor == tip
                || packets.len() == MAX_PAGE_PACKETS
                || maximum_bytes - bytes < minimum_packet
                || !budget.can_read_next(lookup.tip_height - lookup.height)
            {
                break;
            }
        }
        Ok(packets)
    }

    fn read_public_history_packet(
        &self,
        id: Hash,
        after: Hash,
        height: u64,
        charge: &mut dyn FnMut() -> Result<()>,
    ) -> Result<(Packet, usize)> {
        charge()?;
        // Query the scalar length before materializing a possibly damaged BLOB.
        let length: Option<usize> = self.db.query_row(
            "SELECT length(packet) FROM blocks WHERE id=?",
            [id.as_slice()],
            |row| row.get(0),
        )?;
        ensure(
            length.is_some_and(|n| n > 0 && n <= MAX_PACKET_BYTES),
            "PUBLIC_HISTORY_BYTES",
        )
        .map_err(Error::local_integrity)?;
        charge()?;
        let raw: Vec<u8> = self.db.query_row(
            "SELECT packet FROM blocks WHERE id=? AND length(packet)<=?",
            params![id.as_slice(), MAX_PACKET_BYTES],
            |row| row.get(0),
        )?;
        let packet =
            Packet::decode_for_settings(&raw, &self.settings).map_err(Error::local_integrity)?;
        ensure(
            packet.id()? == id && packet.header.parent == after && packet.header.height == height,
            "STORAGE_PACKET",
        )?;
        Ok((packet, raw.len()))
    }
}
