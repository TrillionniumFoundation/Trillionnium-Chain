//! Bounded pure decoding of an actual, freshly selected account-node blob.
//! No SQL row, graph membership or state-validity verdict is retained here.
use super::super::{Node, Result, MAX_NODE_BYTES};
use std::cell::{Cell, RefCell};
use trnm_protocol::pon_wire::Hash;

const SLOTS: usize = 8192;
const MAX_PROBES: usize = 8;
const MAX_SOFTWARE_CHARGE: usize = 4 * 1024 * 1024;

#[derive(Clone)]
struct Entry {
    bytes: [u8; MAX_NODE_BYTES],
    length: u8,
    node: Node,
}

#[derive(Clone, Copy, Default, serde::Serialize)]
struct Counters {
    calls: u64,
    exact_hits: u64,
    original_decodes: u64,
    retained: u64,
    bounded_probe_refusals: u64,
    borrow_conflicts: u64,
}

#[derive(Default)]
pub(super) struct NodeDecodeArithmetic {
    // Allocated only after a successful original decode. Every slot is fixed
    // size: no per-entry Vec, map node or unbounded collision chain is retained.
    entries: RefCell<Option<Box<[Option<Entry>]>>>,
    counters: Cell<Counters>,
}

const MAX_ALLOCATED_SLOT_BYTES: usize = SLOTS * std::mem::size_of::<Option<Entry>>();
const MAX_RETAINED_SOFTWARE_CHARGE: usize =
    MAX_ALLOCATED_SLOT_BYTES + std::mem::size_of::<NodeDecodeArithmetic>();
const _: () = assert!(MAX_RETAINED_SOFTWARE_CHARGE <= MAX_SOFTWARE_CHARGE);

impl NodeDecodeArithmetic {
    fn count(&self, update: impl FnOnce(&mut Counters)) {
        let mut value = self.counters.get();
        update(&mut value);
        self.counters.set(value);
    }

    fn first_slot(id: Hash) -> usize {
        usize::from(u16::from_le_bytes([id[0], id[1]])) % SLOTS
    }

    pub(super) fn decode(&self, id: Hash, bytes: &[u8]) -> Result<Node> {
        self.count(|c| c.calls = c.calls.saturating_add(1));
        let first = Self::first_slot(id);
        match self.entries.try_borrow() {
            Ok(entries) => {
                if let Some(entries) = entries.as_ref() {
                    for distance in 0..MAX_PROBES {
                        match &entries[(first + distance) % SLOTS] {
                            Some(entry) if entry.node.id == id => {
                                if usize::from(entry.length) == bytes.len()
                                    && &entry.bytes[..bytes.len()] == bytes
                                {
                                    self.count(|c| c.exact_hits = c.exact_hits.saturating_add(1));
                                    return Ok(entry.node.clone());
                                }
                                // A changed current blob cannot use a previous
                                // decode merely because its lookup ID matches.
                                break;
                            }
                            Some(_) => (),
                            None => break,
                        }
                    }
                }
            }
            Err(_) => self.count(|c| c.borrow_conflicts = c.borrow_conflicts.saturating_add(1)),
        }
        self.count(|c| c.original_decodes = c.original_decodes.saturating_add(1));
        let node = Node::decode(id, bytes)?;
        // The original decoder established the fixed bound, canonical grammar
        // and content identity. Errors never occupy a slot or replace material.
        let mut encoded = [0; MAX_NODE_BYTES];
        encoded[..bytes.len()].copy_from_slice(bytes);
        let entry = Entry {
            bytes: encoded,
            length: bytes.len() as u8,
            node: node.clone(),
        };
        match self.entries.try_borrow_mut() {
            Ok(mut entries) => {
                let entries = entries.get_or_insert_with(|| vec![None; SLOTS].into_boxed_slice());
                for distance in 0..MAX_PROBES {
                    let slot = &mut entries[(first + distance) % SLOTS];
                    if slot.as_ref().is_none_or(|old| old.node.id == id) {
                        *slot = Some(entry);
                        self.count(|c| c.retained = c.retained.saturating_add(1));
                        return Ok(node);
                    }
                }
                self.count(|c| {
                    c.bounded_probe_refusals = c.bounded_probe_refusals.saturating_add(1)
                });
            }
            Err(_) => self.count(|c| c.borrow_conflicts = c.borrow_conflicts.saturating_add(1)),
        }
        Ok(node)
    }

    pub(super) fn observation(&self) -> serde_json::Value {
        let retained = self.entries.try_borrow().ok().map(|entries| {
            let (slots, occupied, payload) = entries.as_ref().map_or((0, 0, 0), |slots| {
                let occupied = slots.iter().flatten().count();
                let payload: usize = slots.iter().flatten().map(|e| usize::from(e.length)).sum();
                (slots.len(), occupied, payload)
            });
            serde_json::json!({
                "allocated_slots": slots,
                "occupied_slots": occupied,
                "retained_record_bytes": payload,
                "allocated_slot_bytes": slots * std::mem::size_of::<Option<Entry>>(),
                "retained_software_charge_bytes": slots * std::mem::size_of::<Option<Entry>>()
                    + std::mem::size_of::<Self>(),
            })
        });
        serde_json::json!({
            "schema": "pon-native-account-node-decode-arithmetic-v1",
            "scope": "exact current SQL blob and expected ID only; every row and full graph relation is checked again",
            "slot_limit": SLOTS,
            "probe_limit": MAX_PROBES,
            "record_byte_limit": MAX_NODE_BYTES,
            "slot_size_bytes": std::mem::size_of::<Option<Entry>>(),
            "retained_software_charge_limit_bytes": MAX_RETAINED_SOFTWARE_CHARGE,
            "hard_software_charge_ceiling_bytes": MAX_SOFTWARE_CHARGE,
            "retained": retained,
            "counters": self.counters.get(),
            "charge_is_process_rss_bound": false,
            "excluded": "allocator metadata, SQLite, temporary row buffers, stacks and other caches",
            "has_consensus_authority": false,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::super::super::{hash, Account};
    use super::*;

    fn fields(node: Node) -> (Hash, Hash, usize, Hash, Vec<u8>) {
        (node.id, node.path, node.depth, node.digest, node.encode())
    }

    #[test]
    fn native_decode_fixed_slots_collisions_and_charge_are_bounded() {
        let cache = NodeDecodeArithmetic::default();
        assert_eq!(cache.observation()["retained"]["allocated_slots"], 0);
        // These are nine genuine content hashes with the same initial slot.
        // No forged node or hash bypass is used to manufacture a full probe.
        let nodes: Vec<_> = [
            5939u64, 6117, 22112, 28640, 45305, 45989, 50798, 53278, 56075,
        ]
        .into_iter()
        .map(|index| {
            let mut owner = [0; 32];
            owner[..8].copy_from_slice(&index.to_le_bytes());
            let node = Node::account(
                owner,
                Account {
                    balance: 7,
                    nonce: 3,
                },
            );
            assert_eq!(NodeDecodeArithmetic::first_slot(node.id), 0);
            node
        })
        .collect();
        for node in &nodes {
            assert_eq!(
                fields(cache.decode(node.id, &node.encode()).unwrap()),
                fields(node.clone())
            );
        }
        assert_eq!(cache.counters.get().original_decodes, 9);
        assert_eq!(cache.counters.get().bounded_probe_refusals, 1);
        for node in &nodes {
            assert_eq!(
                fields(cache.decode(node.id, &node.encode()).unwrap()),
                fields(node.clone())
            );
        }
        assert_eq!(cache.counters.get().original_decodes, 10);
        assert_eq!(cache.counters.get().exact_hits, 8);
        assert_eq!(cache.counters.get().bounded_probe_refusals, 2);
        let observation = cache.observation();
        assert_eq!(observation["retained"]["occupied_slots"], MAX_PROBES);
        assert_eq!(observation["retained"]["allocated_slots"], SLOTS);
        assert_eq!(
            observation["retained"]["retained_software_charge_bytes"],
            MAX_RETAINED_SOFTWARE_CHARGE
        );
        assert!(
            observation["retained"]["retained_software_charge_bytes"]
                .as_u64()
                .unwrap()
                <= MAX_SOFTWARE_CHARGE as u64
        );
        assert_eq!(observation["charge_is_process_rss_bound"], false);
        eprintln!("pon_native_decode_retained_charge {}", observation);
    }

    #[test]
    fn native_decode_exact_bytes_and_borrow_conflicts_use_original_errors() {
        let cache = NodeDecodeArithmetic::default();
        let node = Node::account(
            [17; 32],
            Account {
                balance: 7,
                nonce: 3,
            },
        );
        let bytes = node.encode();
        assert_eq!(
            fields(cache.decode(node.id, &bytes).unwrap()),
            fields(node.clone())
        );
        let mut changed = bytes.clone();
        changed[40] ^= 0x80;
        for raw in [changed, bytes[..48].to_vec(), vec![0; 164], vec![0; 1024]] {
            for id in [node.id, hash(b"account-archive-node-record-v1", &[&raw])] {
                let expected = Node::decode(id, &raw).map(fields);
                let before = cache.counters.get().retained;
                let is_error = expected.is_err();
                assert_eq!(cache.decode(id, &raw).map(fields), expected);
                if is_error {
                    assert_eq!(cache.counters.get().retained, before);
                }
            }
        }
        assert_eq!(
            fields(cache.decode(node.id, &bytes).unwrap()),
            fields(node.clone())
        );
        // A nested diagnostic borrow cannot turn an optimization into a panic
        // or a new verification result; its sole fallback is original math.
        let held = cache.entries.borrow_mut();
        assert_eq!(fields(cache.decode(node.id, &bytes).unwrap()), fields(node));
        assert!(cache.counters.get().borrow_conflicts >= 2);
        drop(held);
        assert_eq!(cache.observation()["retained"]["occupied_slots"], 2);
    }
}
