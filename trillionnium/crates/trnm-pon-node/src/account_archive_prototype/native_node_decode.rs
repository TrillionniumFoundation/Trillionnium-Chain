//! Bounded pure decoding of an actual, freshly selected account-node blob.
//! No SQL row, graph membership or state-validity verdict is retained here.
use super::super::{Node, Result, MAX_NODE_BYTES};
use std::cell::{Cell, RefCell};
use trnm_protocol::pon_wire::Hash;

const SLOTS: usize = 8192;
const PAGE_SLOTS: usize = 8;
const PAGE_COUNT: usize = SLOTS / PAGE_SLOTS;
const _: () = assert!(SLOTS.is_multiple_of(PAGE_SLOTS));
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

type Page = [Option<Entry>; PAGE_SLOTS];
type PageDirectory = Box<[Option<Box<Page>>]>;

#[derive(Default)]
pub(super) struct NodeDecodeArithmetic {
    // The directory and each fixed-size page are allocated only after a
    // successful original decode needs a vacant slot. A missing page is exactly
    // an empty logical slot, not permission to skip any of the original probes.
    pages: RefCell<Option<PageDirectory>>,
    counters: Cell<Counters>,
}

const MAX_ALLOCATED_SLOT_BYTES: usize = PAGE_COUNT * std::mem::size_of::<Page>();
const MAX_DIRECTORY_BYTES: usize = PAGE_COUNT * std::mem::size_of::<Option<Box<Page>>>();
// Compared with the eager table, the maximum also charges every directory
// entry. The independent hard ceiling stays 4 MiB; this is not an RSS bound.
const MAX_RETAINED_SOFTWARE_CHARGE: usize =
    MAX_ALLOCATED_SLOT_BYTES + MAX_DIRECTORY_BYTES + std::mem::size_of::<NodeDecodeArithmetic>();
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
        match self.pages.try_borrow() {
            Ok(pages) => {
                if let Some(pages) = pages.as_ref() {
                    for distance in 0..MAX_PROBES {
                        let index = (first + distance) % SLOTS;
                        match pages[index / PAGE_SLOTS]
                            .as_ref()
                            .and_then(|page| page[index % PAGE_SLOTS].as_ref())
                        {
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
        match self.pages.try_borrow_mut() {
            Ok(mut pages) => {
                let pages = pages.get_or_insert_with(|| vec![None; PAGE_COUNT].into_boxed_slice());
                for distance in 0..MAX_PROBES {
                    let index = (first + distance) % SLOTS;
                    let page = &mut pages[index / PAGE_SLOTS];
                    let offset = index % PAGE_SLOTS;
                    if page
                        .as_ref()
                        .and_then(|page| page[offset].as_ref())
                        .is_none_or(|old| old.node.id == id)
                    {
                        let page =
                            page.get_or_insert_with(|| Box::new(std::array::from_fn(|_| None)));
                        page[offset] = Some(entry);
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
        let retained = self.pages.try_borrow().ok().map(|pages| {
            let (directory_entries, allocated_pages, occupied, payload) =
                pages.as_ref().map_or((0, 0, 0, 0), |pages| {
                    let allocated_pages = pages.iter().flatten().count();
                    let entries = pages
                        .iter()
                        .flatten()
                        .flat_map(|page| page.iter())
                        .flatten();
                    let occupied = entries.clone().count();
                    let payload: usize = entries.map(|entry| usize::from(entry.length)).sum();
                    (pages.len(), allocated_pages, occupied, payload)
                });
            let directory_bytes = directory_entries * std::mem::size_of::<Option<Box<Page>>>();
            let slot_bytes = allocated_pages * std::mem::size_of::<Page>();
            serde_json::json!({
                "allocated_directory_entries": directory_entries,
                "allocated_directory_bytes": directory_bytes,
                "allocated_pages": allocated_pages,
                "allocated_slots": allocated_pages * PAGE_SLOTS,
                "occupied_slots": occupied,
                "retained_record_bytes": payload,
                "allocated_slot_bytes": slot_bytes,
                "retained_software_charge_bytes": directory_bytes + slot_bytes
                    + std::mem::size_of::<Self>(),
            })
        });
        serde_json::json!({
            "schema": "pon-native-account-node-decode-arithmetic-v2",
            "storage": "lazy-fixed-pages",
            "scope": "exact current SQL blob and expected ID only; every row and full graph relation is checked again",
            "slot_limit": SLOTS,
            "page_slot_limit": PAGE_SLOTS,
            "page_limit": PAGE_COUNT,
            "page_size_bytes": std::mem::size_of::<Page>(),
            "directory_entry_size_bytes": std::mem::size_of::<Option<Box<Page>>>(),
            "owner_size_bytes": std::mem::size_of::<Self>(),
            "maximum_directory_bytes": MAX_DIRECTORY_BYTES,
            "maximum_allocated_slot_bytes": MAX_ALLOCATED_SLOT_BYTES,
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

    // Frozen eager storage algorithm from the parent source. Keep its logical
    // addressing, early exits and two independent borrow attempts separate from
    // the paged implementation so the differential is not a shared-helper test.
    #[derive(Default)]
    struct EagerOracle {
        entries: RefCell<Option<Box<[Option<Entry>]>>>,
        counters: Cell<Counters>,
    }

    impl EagerOracle {
        fn count(&self, update: impl FnOnce(&mut Counters)) {
            let mut value = self.counters.get();
            update(&mut value);
            self.counters.set(value);
        }

        fn first_slot(id: Hash) -> usize {
            usize::from(u16::from_le_bytes([id[0], id[1]])) % SLOTS
        }

        fn decode(&self, id: Hash, bytes: &[u8]) -> Result<Node> {
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
                                        self.count(|c| {
                                            c.exact_hits = c.exact_hits.saturating_add(1)
                                        });
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
                    let entries =
                        entries.get_or_insert_with(|| vec![None; SLOTS].into_boxed_slice());
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
    }

    fn account_node(index: u64) -> Node {
        let mut owner = [0; 32];
        owner[..8].copy_from_slice(&index.to_le_bytes());
        Node::account(
            owner,
            Account {
                balance: 7,
                nonce: 3,
            },
        )
    }

    fn assert_same_decode(
        cache: &NodeDecodeArithmetic,
        eager: &EagerOracle,
        id: Hash,
        bytes: &[u8],
    ) {
        assert_eq!(
            cache.decode(id, bytes).map(fields),
            eager.decode(id, bytes).map(fields)
        );
        assert_eq!(
            serde_json::to_value(cache.counters.get()).unwrap(),
            serde_json::to_value(eager.counters.get()).unwrap()
        );
    }

    fn assert_same_logical_slots(cache: &NodeDecodeArithmetic, eager: &EagerOracle) {
        let pages = cache.pages.borrow();
        let entries = eager.entries.borrow();
        for index in 0..SLOTS {
            let actual = pages.as_ref().and_then(|pages| {
                pages[index / PAGE_SLOTS]
                    .as_ref()
                    .and_then(|page| page[index % PAGE_SLOTS].as_ref())
            });
            let expected = entries.as_ref().and_then(|entries| entries[index].as_ref());
            assert_eq!(
                actual.map(|entry| (entry.bytes, entry.length, fields(entry.node.clone()))),
                expected.map(|entry| (entry.bytes, entry.length, fields(entry.node.clone()))),
                "logical slot {index}"
            );
        }
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
        assert_eq!(observation["retained"]["allocated_pages"], 1);
        assert_eq!(observation["retained"]["allocated_slots"], PAGE_SLOTS);
        assert_eq!(
            observation["retained"]["retained_software_charge_bytes"],
            MAX_DIRECTORY_BYTES
                + std::mem::size_of::<Page>()
                + std::mem::size_of::<NodeDecodeArithmetic>()
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
        let held = cache.pages.borrow_mut();
        assert_eq!(fields(cache.decode(node.id, &bytes).unwrap()), fields(node));
        assert!(cache.counters.get().borrow_conflicts >= 2);
        drop(held);
        assert_eq!(cache.observation()["retained"]["occupied_slots"], 2);
    }

    #[test]
    fn native_decode_paged_storage_matches_eager_reference() {
        let cache = NodeDecodeArithmetic::default();
        let eager = EagerOracle::default();
        let mut nodes: Vec<_> = (0..256).map(account_node).collect();
        let empty = super::super::super::empty_hashes();
        for pair in nodes[..16].chunks_exact(2) {
            let (left, right) = if pair[0].path < pair[1].path {
                (&pair[0], &pair[1])
            } else {
                (&pair[1], &pair[0])
            };
            let depth = super::super::super::common(&left.path, &right.path);
            let fork = Node::fork(depth, left, right, &empty).unwrap();
            assert_same_decode(&cache, &eager, fork.id, &fork.encode());
        }
        for node in &nodes {
            assert_same_decode(&cache, &eager, node.id, &node.encode());
        }
        nodes.reverse();
        for node in &nodes {
            assert_same_decode(&cache, &eager, node.id, &node.encode());
            let mut changed = node.encode();
            changed[40] ^= 0x80;
            assert_same_decode(&cache, &eager, node.id, &changed);
            let changed_id = hash(b"account-archive-node-record-v1", &[&changed]);
            assert_same_decode(&cache, &eager, changed_id, &changed);
            assert_same_decode(&cache, &eager, node.id, &node.encode());
        }
        assert_same_logical_slots(&cache, &eager);
    }

    #[test]
    fn native_decode_paged_cross_page_and_wrap_probes_match_eager() {
        // Genuine canonical leaves chosen by content hash, never by forging IDs.
        for (first, indices) in [
            (
                7,
                [958, 3720, 6438, 10204, 16506, 18996, 43368, 47297, 50534],
            ),
            (
                8190,
                [4817, 7699, 17484, 21993, 22642, 23429, 33390, 38624, 39924],
            ),
            (
                8191,
                [2417, 8662, 13089, 18241, 25830, 31771, 32928, 46061, 48121],
            ),
        ] {
            let cache = NodeDecodeArithmetic::default();
            let eager = EagerOracle::default();
            let nodes = indices.map(account_node);
            for (distance, node) in nodes.iter().enumerate() {
                assert_eq!(NodeDecodeArithmetic::first_slot(node.id), first);
                assert_same_decode(&cache, &eager, node.id, &node.encode());
                assert_same_logical_slots(&cache, &eager);
                let expected_pages =
                    if first % PAGE_SLOTS + distance.min(MAX_PROBES - 1) < PAGE_SLOTS {
                        1
                    } else {
                        2
                    };
                assert_eq!(
                    cache.observation()["retained"]["allocated_pages"],
                    expected_pages
                );
            }
            assert_eq!(cache.counters.get().retained, MAX_PROBES as u64);
            assert_eq!(cache.counters.get().bounded_probe_refusals, 1);
            for node in nodes.iter().rev() {
                assert_same_decode(&cache, &eager, node.id, &node.encode());
            }
            assert_eq!(cache.counters.get().bounded_probe_refusals, 2);
            assert_eq!(cache.counters.get().exact_hits, MAX_PROBES as u64);
            assert_eq!(cache.observation()["retained"]["allocated_pages"], 2);
            assert_same_logical_slots(&cache, &eager);
        }
    }

    #[test]
    fn native_decode_invalid_records_never_allocate_a_directory_or_page() {
        let cache = NodeDecodeArithmetic::default();
        let eager = EagerOracle::default();
        let node = account_node(5939);
        let bytes = node.encode();
        let mut trailing = bytes.clone();
        trailing.push(0);
        let mut invalid_tag = bytes.clone();
        invalid_tag[0] = 2;
        let mut invalid_depth = vec![0; MAX_NODE_BYTES];
        invalid_depth[..3].copy_from_slice(&[1, 0, 1]);
        let invalid = [
            Vec::new(),
            bytes[..48].to_vec(),
            trailing,
            invalid_tag,
            invalid_depth,
            vec![0; MAX_NODE_BYTES + 1],
            vec![0; 1024],
        ];
        for warm in [false, true] {
            if warm {
                assert_same_decode(&cache, &eager, node.id, &bytes);
            }
            let retained = cache.observation()["retained"].clone();
            for raw in &invalid {
                for id in [node.id, hash(b"account-archive-node-record-v1", &[raw])] {
                    assert!(Node::decode(id, raw).is_err());
                    assert_same_decode(&cache, &eager, id, raw);
                    assert_eq!(cache.observation()["retained"], retained);
                }
            }
            let wrong_id = account_node(4817).id;
            assert!(Node::decode(wrong_id, &bytes).is_err());
            assert_same_decode(&cache, &eager, wrong_id, &bytes);
            assert_eq!(cache.observation()["retained"], retained);
            assert_eq!(
                cache.observation()["retained"]["allocated_pages"],
                usize::from(warm)
            );
            assert_same_logical_slots(&cache, &eager);
        }
    }

    #[test]
    fn native_decode_paged_borrow_conflicts_preserve_eager_counters() {
        let cache = NodeDecodeArithmetic::default();
        let eager = EagerOracle::default();
        let node = account_node(5939);
        let absent = account_node(4817);
        // A mutable borrow before the first valid decode prevents both lookup
        // and insertion, so even the directory must remain unallocated.
        {
            let _pages = cache.pages.borrow_mut();
            let _entries = eager.entries.borrow_mut();
            assert_same_decode(&cache, &eager, node.id, &node.encode());
            assert_eq!(cache.counters.get().borrow_conflicts, 2);
            assert!(cache.observation()["retained"].is_null());
            assert_same_decode(&cache, &eager, node.id, &[]);
            assert_eq!(cache.counters.get().borrow_conflicts, 3);
        }
        assert_eq!(cache.observation()["retained"]["allocated_pages"], 0);
        assert_same_decode(&cache, &eager, node.id, &node.encode());
        let retained = cache.observation()["retained"].clone();
        {
            let _pages = cache.pages.borrow();
            let _entries = eager.entries.borrow();
            assert_same_decode(&cache, &eager, node.id, &node.encode());
            assert_eq!(cache.counters.get().borrow_conflicts, 3);
            assert_same_decode(&cache, &eager, absent.id, &absent.encode());
            assert_eq!(cache.counters.get().borrow_conflicts, 4);
            assert_same_decode(&cache, &eager, absent.id, &[]);
            assert_eq!(cache.counters.get().borrow_conflicts, 4);
        }
        {
            let _pages = cache.pages.borrow_mut();
            let _entries = eager.entries.borrow_mut();
            assert_same_decode(&cache, &eager, node.id, &node.encode());
            assert_eq!(cache.counters.get().borrow_conflicts, 6);
        }
        assert_eq!(cache.observation()["retained"], retained);
        assert_eq!(cache.counters.get().retained, 1);
        assert_same_decode(&cache, &eager, absent.id, &absent.encode());
        assert_same_logical_slots(&cache, &eager);
    }

    #[test]
    fn native_decode_sparse_charge_counts_actual_directory_and_pages() {
        let cache = NodeDecodeArithmetic::default();
        let owner = std::mem::size_of::<NodeDecodeArithmetic>();
        assert_eq!(
            cache.observation()["retained"]["retained_software_charge_bytes"],
            owner
        );
        assert_eq!(
            cache.observation()["retained"]["allocated_directory_bytes"],
            0
        );
        // First slots 0, 7 and 8190 touch exactly two pages. A repeated hit
        // neither allocates another page nor increments the retained writes.
        for (index, expected_pages, expected_retained) in
            [(5939, 1, 1), (958, 1, 2), (4817, 2, 3), (5939, 2, 3)]
        {
            let node = account_node(index);
            assert_eq!(
                cache.decode(node.id, &node.encode()).map(fields),
                Ok(fields(node))
            );
            let observation = cache.observation();
            let pages = cache.pages.borrow();
            let pages = pages.as_ref().unwrap();
            let measured_directory_bytes = std::mem::size_of_val(pages.as_ref());
            let measured_page_bytes: usize = pages
                .iter()
                .flatten()
                .map(|page| std::mem::size_of_val(page.as_ref()))
                .sum();
            assert_eq!(pages.iter().flatten().count(), expected_pages);
            assert_eq!(
                observation["retained"]["allocated_directory_entries"],
                pages.len()
            );
            assert_eq!(
                observation["retained"]["allocated_directory_bytes"],
                measured_directory_bytes
            );
            assert_eq!(observation["retained"]["allocated_pages"], expected_pages);
            assert_eq!(
                observation["retained"]["allocated_slots"],
                expected_pages * PAGE_SLOTS
            );
            assert_eq!(
                observation["retained"]["allocated_slot_bytes"],
                measured_page_bytes
            );
            assert_eq!(
                observation["retained"]["retained_software_charge_bytes"],
                measured_directory_bytes + measured_page_bytes + owner
            );
            assert_eq!(cache.counters.get().retained, expected_retained);
            assert!(
                measured_directory_bytes + measured_page_bytes + owner < MAX_ALLOCATED_SLOT_BYTES
            );
        }
        let observation = cache.observation();
        assert_eq!(
            observation["schema"],
            "pon-native-account-node-decode-arithmetic-v2"
        );
        assert_eq!(observation["slot_limit"], SLOTS);
        assert_eq!(observation["page_slot_limit"], PAGE_SLOTS);
        assert_eq!(observation["page_limit"], PAGE_COUNT);
        assert_eq!(observation["retained"]["occupied_slots"], 3);
        assert_eq!(observation["retained"]["retained_record_bytes"], 3 * 49);
        eprintln!("pon_native_decode_sparse_charge {}", observation);
    }

    #[test]
    fn native_decode_full_page_charge_and_refusal_match_eager() {
        let cache = NodeDecodeArithmetic::default();
        let eager = EagerOracle::default();
        let node = account_node(5939);
        let bytes = node.encode();
        let decoded = Node::decode(node.id, &bytes).unwrap();
        let mut encoded = [0; MAX_NODE_BYTES];
        encoded[..bytes.len()].copy_from_slice(&bytes);
        let entry = Entry {
            bytes: encoded,
            length: bytes.len() as u8,
            node: decoded,
        };
        // Saturate private storage to measure every real allocation without
        // searching for 8192 chosen content hashes. Repeated placement is only
        // an accounting/refusal fixture, not a claim about reachable placement.
        *cache.pages.borrow_mut() = Some(
            (0..PAGE_COUNT)
                .map(|_| Some(Box::new(std::array::from_fn(|_| Some(entry.clone())))))
                .collect::<Vec<_>>()
                .into_boxed_slice(),
        );
        *eager.entries.borrow_mut() = Some(vec![Some(entry); SLOTS].into_boxed_slice());
        let observation = cache.observation();
        let measured_directory_bytes;
        let measured_page_bytes;
        {
            let pages = cache.pages.borrow();
            let pages = pages.as_ref().unwrap();
            measured_directory_bytes = std::mem::size_of_val(pages.as_ref());
            measured_page_bytes = pages
                .iter()
                .flatten()
                .map(|page| std::mem::size_of_val(page.as_ref()))
                .sum::<usize>();
        }
        assert_eq!(measured_directory_bytes, MAX_DIRECTORY_BYTES);
        assert_eq!(measured_page_bytes, MAX_ALLOCATED_SLOT_BYTES);
        assert_eq!(
            measured_page_bytes,
            SLOTS * std::mem::size_of::<Option<Entry>>()
        );
        assert_eq!(observation["retained"]["allocated_pages"], PAGE_COUNT);
        assert_eq!(observation["retained"]["allocated_slots"], SLOTS);
        assert_eq!(observation["retained"]["occupied_slots"], SLOTS);
        assert_eq!(
            observation["retained"]["retained_record_bytes"],
            SLOTS * bytes.len()
        );
        assert_eq!(
            observation["retained"]["retained_software_charge_bytes"],
            measured_directory_bytes
                + measured_page_bytes
                + std::mem::size_of::<NodeDecodeArithmetic>()
        );
        assert_eq!(
            observation["retained"]["retained_software_charge_bytes"],
            MAX_RETAINED_SOFTWARE_CHARGE
        );
        assert_eq!(
            observation["retained_software_charge_limit_bytes"],
            MAX_RETAINED_SOFTWARE_CHARGE
        );
        assert_eq!(
            observation["hard_software_charge_ceiling_bytes"],
            4 * 1024 * 1024
        );
        assert!(
            measured_directory_bytes
                + measured_page_bytes
                + std::mem::size_of::<NodeDecodeArithmetic>()
                <= MAX_SOFTWARE_CHARGE
        );
        let absent = account_node(4817);
        for _ in 0..2 {
            assert_same_decode(&cache, &eager, absent.id, &absent.encode());
        }
        assert_eq!(cache.counters.get().bounded_probe_refusals, 2);
        assert_eq!(cache.counters.get().retained, 0);
        assert_eq!(cache.observation()["retained"], observation["retained"]);
        assert_same_logical_slots(&cache, &eager);
        eprintln!("pon_native_decode_full_charge {}", observation);
    }

    #[test]
    fn native_decode_missing_and_empty_pages_keep_first_empty_stop() {
        for (index, first) in [(958, 7), (2417, SLOTS - 1)] {
            for allocate_empty_page in [false, true] {
                let cache = NodeDecodeArithmetic::default();
                let eager = EagerOracle::default();
                let node = account_node(index);
                let bytes = node.encode();
                assert_eq!(NodeDecodeArithmetic::first_slot(node.id), first);
                assert_same_decode(&cache, &eager, node.id, &bytes);
                // Move the validated entry past a hole to directly distinguish
                // stopping at the first empty slot from skipping a missing page.
                // This deliberately tests private storage outside its normal
                // insertion invariant; it does not alter the production API.
                let next = (first + 1) % SLOTS;
                {
                    let mut pages = cache.pages.borrow_mut();
                    let pages = pages.as_mut().unwrap();
                    let entry =
                        pages[first / PAGE_SLOTS].as_mut().unwrap()[first % PAGE_SLOTS].take();
                    if !allocate_empty_page {
                        pages[first / PAGE_SLOTS] = None;
                    }
                    let page = pages[next / PAGE_SLOTS]
                        .get_or_insert_with(|| Box::new(std::array::from_fn(|_| None)));
                    page[next % PAGE_SLOTS] = entry;
                    let mut entries = eager.entries.borrow_mut();
                    let entries = entries.as_mut().unwrap();
                    entries[next] = entries[first].take();
                }
                assert_same_decode(&cache, &eager, node.id, &bytes);
                assert_eq!(cache.counters.get().exact_hits, 0);
                assert_eq!(cache.counters.get().original_decodes, 2);
                assert_eq!(cache.counters.get().retained, 2);
                assert_eq!(cache.observation()["retained"]["allocated_pages"], 2);
                assert_same_logical_slots(&cache, &eager);
            }
        }
    }

    #[test]
    fn native_decode_paged_replacement_counts_writes_without_reallocating() {
        let cache = NodeDecodeArithmetic::default();
        let eager = EagerOracle::default();
        let node = account_node(5939);
        let bytes = node.encode();
        assert_same_decode(&cache, &eager, node.id, &bytes);
        let retained = cache.observation()["retained"].clone();
        // A private stale-byte fixture proves that equality includes bytes,
        // that decode errors cannot replace it, and that successful replacement
        // increments retained writes without increasing occupancy or allocation.
        cache.pages.borrow_mut().as_mut().unwrap()[0]
            .as_mut()
            .unwrap()[0]
            .as_mut()
            .unwrap()
            .bytes[0] = 2;
        eager.entries.borrow_mut().as_mut().unwrap()[0]
            .as_mut()
            .unwrap()
            .bytes[0] = 2;
        assert_same_decode(&cache, &eager, node.id, &[]);
        assert_eq!(cache.counters.get().retained, 1);
        assert_same_logical_slots(&cache, &eager);
        assert_same_decode(&cache, &eager, node.id, &bytes);
        assert_eq!(cache.counters.get().exact_hits, 0);
        assert_eq!(cache.counters.get().retained, 2);
        assert_eq!(cache.observation()["retained"], retained);
        assert_same_logical_slots(&cache, &eager);
        assert_same_decode(&cache, &eager, node.id, &bytes);
        assert_eq!(cache.counters.get().exact_hits, 1);
        assert_eq!(cache.counters.get().retained, 2);
    }
}
