//! Ordinary native history pages: complete actual ancestry checks with a bounded
//! operation-local page window. This does not use the derived ancestry index,
//! cache a validity result, read active State, or change any durable boundary.
use super::{bytes32, bytes64, Node, Record};
use crate::{consensus::Work, ensure, Error, Packet, Result};
use rusqlite::params;
use std::collections::VecDeque;
use trnm_protocol::pon_wire::Hash;

const ANCESTOR_BATCH: u64 = 64;

/// Monotonic local observations, reset on Node open. These are not wire fields
/// or state/ancestry authority. Counts include work before failure/cancellation.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct HistoryPageReadCounters {
    /// Actual bounded ancestry SELECT attempts; excludes ready, cursor and bodies.
    pub ancestor_selects: u64,
    /// Actual complete child/parent record pairs whose checks finished.
    pub ancestor_links: u64,
    /// Largest simultaneously retained page-ID count, at most the page limit 16.
    /// This is logical Hash payload, not SQLite memory, allocator traffic or RSS.
    pub retained_ids_high_water: u64,
}

type RawRecord = (Option<Vec<u8>>, u64, Vec<u8>, Vec<u8>);

fn raw_record(row: &rusqlite::Row<'_>, first: usize) -> rusqlite::Result<RawRecord> {
    Ok((
        row.get(first)?,
        row.get(first + 1)?,
        row.get(first + 2)?,
        row.get(first + 3)?,
    ))
}

fn decode_record(raw: RawRecord) -> Result<Record> {
    // Match record(): SQL value conversions precede parent/work/root shapes.
    Ok(Record {
        parent: raw.0.map(bytes32).transpose()?,
        height: raw.1,
        work: Work::from_bytes(bytes64(raw.2)?),
        root: bytes32(raw.3)?,
    })
}

impl Node {
    pub fn history_page_read_counters(&self) -> HistoryPageReadCounters {
        self.history_page_read_counters.get()
    }

    /// Only actual record projections survive one SQL statement. The stop cursor
    /// is excluded from recursion, while its complete parent record is still read
    /// for the last required edge. Corrupt cycles cannot make this query unbounded.
    fn history_page_ancestors(
        &self,
        start: Hash,
        after: Hash,
        window: &mut VecDeque<Hash>,
        limit: usize,
    ) -> Result<(Hash, u64)> {
        let mut statement = self.db.prepare_cached(
            "WITH RECURSIVE ancestry(id,parent,ordinal) AS (
                 SELECT id,parent,0 FROM blocks
                 WHERE id=?1 AND id!=?2 AND id!=?3
                 UNION ALL
                 SELECT b.id,b.parent,a.ordinal+1
                 FROM ancestry a JOIN blocks b ON b.id=a.parent
                 WHERE b.id!=?2 AND b.id!=?3 LIMIT ?4
             )
             SELECT b.parent,b.height,b.chainwork,b.state_root,
                 p.parent,p.height,p.chainwork,p.state_root,b.id,a.ordinal,p.id
             FROM ancestry a JOIN blocks b ON b.id=a.id
             LEFT JOIN blocks p ON p.id=b.parent ORDER BY a.ordinal",
        )?;
        let mut counters = self.history_page_read_counters.get();
        counters.ancestor_selects = counters.ancestor_selects.saturating_add(1);
        self.history_page_read_counters.set(counters);
        let mut rows = statement.query(params![
            start.as_slice(),
            after.as_slice(),
            self.settings.genesis().as_slice(),
            ANCESTOR_BATCH,
        ])?;
        let mut current = start;
        let mut checked = 0_u64;
        while let Some(row) = rows.next()? {
            let id = bytes32(row.get(8)?)?;
            ensure(
                checked < ANCESTOR_BATCH && row.get::<_, u64>(9)? == checked && id == current,
                "ANCESTRY_HEIGHT",
            )
            .map_err(Error::local_integrity)?;
            // The old parent() reads the complete child first, then the complete
            // parent under local-integrity provenance. Keep that error order.
            let child = decode_record(raw_record(row, 0)?)?;
            let parent = child
                .parent
                .ok_or_else(|| Error::from("UNKNOWN_PARENT").local_integrity())?;
            let actual_parent = (|| {
                let present: Option<Vec<u8>> = row.get(10)?;
                ensure(present.is_some(), "UNKNOWN_PARENT")?;
                decode_record(raw_record(row, 4)?)
            })()
            .map_err(Error::local_integrity)?;
            ensure(
                actual_parent.height.checked_add(1) == Some(child.height),
                "ANCESTRY_HEIGHT",
            )
            .map_err(Error::local_integrity)?;
            if window.len() == limit {
                window.pop_front();
            }
            window.push_back(id);
            let mut counters = self.history_page_read_counters.get();
            counters.ancestor_links = counters.ancestor_links.saturating_add(1);
            counters.retained_ids_high_water =
                counters.retained_ids_high_water.max(window.len() as u64);
            self.history_page_read_counters.set(counters);
            current = parent;
            checked = checked.checked_add(1).ok_or("ANCESTRY_LIMIT")?;
        }
        // The first unknown locator retains the old non-local identity. A known
        // child with an absent internal parent failed above, with local identity.
        if checked == 0 {
            return Err("UNKNOWN_PARENT".into());
        }
        ensure(
            checked == ANCESTOR_BATCH || current == after || current == self.settings.genesis(),
            "UNKNOWN_PARENT",
        )
        .map_err(Error::local_integrity)?;
        Ok((current, checked))
    }

    pub fn history(&self, tip: Hash, after: Hash, limit: usize) -> Result<Vec<Packet>> {
        self.history_with_progress(tip, after, limit, &mut |_| Ok(()))
    }

    /// Checks every requested actual ancestor before decoding any returned body.
    /// Complete traversal remains O(H); at most `limit` Hashes survive each row.
    /// Progress retains its initial, every-256-links and final callback positions.
    pub fn history_with_progress(
        &self,
        tip: Hash,
        after: Hash,
        limit: usize,
        progress: &mut dyn FnMut(u64) -> Result<()>,
    ) -> Result<Vec<Packet>> {
        progress(0)?;
        self.ready()?;
        ensure((1..=16).contains(&limit), "PAGE_LIMIT")?;
        ensure(
            self.record(after)?.height <= self.record(tip)?.height,
            "CURSOR",
        )?;
        let mut window = VecDeque::with_capacity(limit);
        let mut current = tip;
        let mut count = 0_u64;
        while current != after {
            if count.is_multiple_of(256) {
                progress(count)?;
            }
            ensure(current != self.settings.genesis(), "CURSOR")?;
            let (parent, checked) =
                self.history_page_ancestors(current, after, &mut window, limit)?;
            count = count.checked_add(checked).ok_or("ANCESTRY_LIMIT")?;
            current = parent;
        }
        let mut packets = Vec::new();
        let mut bytes = 0_usize;
        for id in window.into_iter().rev() {
            let packet = self.packet(id)?;
            let n = packet.encode()?.len();
            if bytes + n > 800_000 && !packets.is_empty() {
                break;
            }
            bytes += n;
            packets.push(packet);
        }
        progress(count)?;
        Ok(packets)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{development_public, ErrorCode, Settings};
    use serde_json::{json, Value};
    use sha2::{Digest, Sha256};
    use std::{
        fs::{self, File},
        io::{Read, Seek, SeekFrom, Write},
        path::Path,
        time::Instant,
    };
    use trnm_crypto_primitives::{sign_hex, signing_key_from_hex};
    use trnm_protocol::pon_wire::{hash, Envelope};

    mod compiled_source {
        include!("../../examples/support/distributed_source_inventory.rs");
    }

    const CLOCK: u64 = 1_000_000;

    #[derive(Default)]
    struct ReferenceCounts {
        ancestor_selects: u64,
        ancestor_links: u64,
        spool_bytes_written: u64,
        spool_bytes_read: u64,
    }

    // Independent earlier whole-operation algorithm. No new window, CTE or
    // derived-index helper is used. Its temporary file is always dropped.
    fn spooled_reference(
        node: &Node,
        tip: Hash,
        after: Hash,
        limit: usize,
        progress: &mut dyn FnMut(u64) -> Result<()>,
    ) -> Result<(Vec<Packet>, ReferenceCounts)> {
        progress(0)?;
        node.ready()?;
        ensure((1..=16).contains(&limit), "PAGE_LIMIT")?;
        ensure(
            node.record(after)?.height <= node.record(tip)?.height,
            "CURSOR",
        )?;
        let mut counts = ReferenceCounts::default();
        let mut spool = tempfile::tempfile()?;
        let mut current = tip;
        let mut count = 0_u64;
        while current != after {
            if count.is_multiple_of(256) {
                progress(count)?;
            }
            ensure(current != node.settings.genesis(), "CURSOR")?;
            spool.write_all(&current)?;
            counts.spool_bytes_written += 32;
            count = count.checked_add(1).ok_or("ANCESTRY_LIMIT")?;
            // Spell out the original two record queries, preserving their
            // conversion/error order and each parent's local provenance.
            counts.ancestor_selects += 1;
            let child = node.record(current)?;
            let parent = child
                .parent
                .ok_or_else(|| Error::from("UNKNOWN_PARENT").local_integrity())?;
            counts.ancestor_selects += 1;
            let parent_record = node.record(parent).map_err(Error::local_integrity)?;
            ensure(
                parent_record.height.checked_add(1) == Some(child.height),
                "ANCESTRY_HEIGHT",
            )
            .map_err(Error::local_integrity)?;
            current = parent;
            counts.ancestor_links += 1;
        }
        let mut packets = Vec::new();
        let mut bytes = 0_usize;
        for i in (0..count).rev().take(limit) {
            spool.seek(SeekFrom::Start(i.checked_mul(32).ok_or("ANCESTRY_LIMIT")?))?;
            let mut id = [0; 32];
            spool.read_exact(&mut id)?;
            counts.spool_bytes_read += 32;
            let packet = node.packet(id)?;
            let n = packet.encode()?.len();
            if bytes + n > 800_000 && !packets.is_empty() {
                break;
            }
            bytes += n;
            packets.push(packet);
        }
        progress(count)?;
        Ok((packets, counts))
    }

    fn encoded(packets: &[Packet]) -> Vec<Vec<u8>> {
        packets.iter().map(|p| p.encode().unwrap()).collect()
    }

    fn transfer(settings: &Settings, nonce: u64) -> Vec<u8> {
        let key =
            signing_key_from_hex(&hex::encode(hash(b"DEV-ONLY-KEY", &[&0_u64.to_le_bytes()])))
                .unwrap();
        let mut payload = development_public(1).unwrap().to_vec();
        payload.extend(1_u64.to_le_bytes());
        let mut tx = Envelope {
            network: settings.network(),
            sender: development_public(0).unwrap(),
            nonce,
            expiry: 10_000,
            fee_limit: 1000,
            tag: 1,
            payload,
            signature: [0; 64],
        };
        tx.signature = hex::decode(sign_hex(&key, &tx.signing_digest().unwrap()))
            .unwrap()
            .try_into()
            .unwrap();
        tx.encode().unwrap()
    }

    fn extend(node: &mut Node, parent: Hash, wide: bool, miner: u64, active: bool) -> Hash {
        let height = node.record(parent).unwrap().height + 1;
        let transactions = if wide {
            (1..=16)
                .map(|n| transfer(node.settings(), (height - 1) * 16 + n))
                .collect()
        } else {
            Vec::new()
        };
        let packet = node
            .make(
                parent,
                transactions,
                development_public(miner).unwrap(),
                1 + height * 10,
                4096,
            )
            .unwrap();
        let id = node.admit(&packet, CLOCK).unwrap();
        if active {
            node.activate(id).unwrap();
        }
        id
    }

    fn chain(directory: &Path, blocks: u64) -> (Node, Vec<Hash>) {
        let settings = Settings::development(Some(1)).unwrap();
        let mut node = Node::open(directory, settings.clone(), 1).unwrap();
        let mut ids = vec![settings.genesis()];
        for height in 1..=blocks {
            ids.push(extend(
                &mut node,
                *ids.last().unwrap(),
                height <= 17,
                2,
                true,
            ));
        }
        (node, ids)
    }

    fn compare(node: &Node, tip: Hash, after: Hash, limit: usize, distance: u64) -> Vec<Vec<u8>> {
        let before = node.history_page_read_counters();
        let mut optimized_progress = Vec::new();
        let actual = node
            .history_with_progress(tip, after, limit, &mut |n| {
                optimized_progress.push(n);
                Ok(())
            })
            .unwrap();
        let counters = node.history_page_read_counters();
        let mut reference_progress = Vec::new();
        let (reference, counts) = spooled_reference(node, tip, after, limit, &mut |n| {
            reference_progress.push(n);
            Ok(())
        })
        .unwrap();
        assert_eq!(optimized_progress, reference_progress);
        assert_eq!(encoded(&actual), encoded(&reference));
        assert_eq!(
            counters.ancestor_selects - before.ancestor_selects,
            distance.div_ceil(64)
        );
        assert_eq!(counters.ancestor_links - before.ancestor_links, distance);
        assert!(counters.retained_ids_high_water <= 16);
        assert_eq!(counts.ancestor_selects, 2 * distance);
        assert_eq!(counts.ancestor_links, distance);
        assert_eq!(counts.spool_bytes_written, 32 * distance);
        assert!(counts.spool_bytes_read <= 32 * limit as u64);
        encoded(&actual)
    }

    fn matching_error(node: &Node, tip: Hash, after: Hash, expected: &str, local: bool) {
        let error = node.history(tip, after, 16).unwrap_err();
        let reference = match spooled_reference(node, tip, after, 16, &mut |_| Ok(())) {
            Ok(_) => panic!("reference accepted invalid history"),
            Err(error) => error,
        };
        assert_eq!(error.to_string(), expected);
        assert_eq!(reference.to_string(), expected);
        assert_eq!(error.kind(), reference.kind());
        assert_eq!(error.code(), reference.code());
        assert_eq!(error.requires_owner_stop(), local);
        assert_eq!(reference.requires_owner_stop(), local);
    }

    #[test]
    fn history_page_native_pages_keep_complete_bytes_cursor_cancellation_and_reopen() {
        let directory = tempfile::tempdir().unwrap();
        let (mut node, ids) = chain(directory.path(), 257);
        let original = node.read_active().unwrap();
        let slot = node.slot().unwrap();
        let writes = node.db.total_changes();
        for (tip, after, limit) in [
            (257, 0, 1),
            (257, 0, 16),
            (257, 64, 16),
            (257, 256, 16),
            (65, 0, 16),
            (64, 0, 16),
            (17, 0, 16),
            (16, 0, 16),
            (1, 0, 1),
            (257, 257, 16),
        ] {
            compare(&node, ids[tip], ids[after], limit, (tip - after) as u64);
        }
        let large_page = node.history(ids[257], ids[0], 16).unwrap();
        // Sixteen real wide transaction bodies cross the exact old byte cutoff.
        assert!(!large_page.is_empty() && large_page.len() < 16);
        let bytes: usize = encoded(&large_page).iter().map(Vec::len).sum();
        assert!(bytes <= 800_000);
        assert!(
            bytes
                + node
                    .packet(ids[large_page.len() + 1])
                    .unwrap()
                    .encode()
                    .unwrap()
                    .len()
                > 800_000
        );

        for stop in [0, 256, 257] {
            let before = node.history_page_read_counters();
            let error = node
                .history_with_progress(ids[257], ids[0], 16, &mut |n| {
                    if n == stop {
                        Err(Error::new(ErrorCode::PublicRequestCancelled))
                    } else {
                        Ok(())
                    }
                })
                .unwrap_err();
            let reference = match spooled_reference(&node, ids[257], ids[0], 16, &mut |n| {
                if n == stop {
                    Err(Error::new(ErrorCode::PublicRequestCancelled))
                } else {
                    Ok(())
                }
            }) {
                Ok(_) => panic!("reference ignored cancellation"),
                Err(error) => error,
            };
            assert!(error.is(ErrorCode::PublicRequestCancelled));
            assert_eq!(error.kind(), reference.kind());
            assert!(!error.requires_owner_stop());
            assert_eq!(
                node.history_page_read_counters().ancestor_links - before.ancestor_links,
                stop
            );
        }
        assert_eq!(node.db.total_changes(), writes);
        assert_eq!(node.slot().unwrap(), slot);
        assert_eq!(node.read_active().unwrap(), original);

        // Corruption beyond the stop cursor must not be read by the recursive CTE.
        node.db
            .execute(
                "UPDATE blocks SET height=height+1 WHERE id=?",
                [ids[63].as_slice()],
            )
            .unwrap();
        compare(&node, ids[257], ids[64], 16, 193);
        matching_error(&node, ids[257], ids[0], "ANCESTRY_HEIGHT", true);
        node.db
            .execute(
                "UPDATE blocks SET height=height-1 WHERE id=?",
                [ids[63].as_slice()],
            )
            .unwrap();

        // Boundary 256 cancellation precedes decoding the next corrupt child.
        node.db
            .execute(
                "UPDATE blocks SET chainwork=X'01' WHERE id=?",
                [ids[1].as_slice()],
            )
            .unwrap();
        let before = node.history_page_read_counters();
        let error = node
            .history_with_progress(ids[257], ids[0], 16, &mut |n| {
                if n == 256 {
                    Err(Error::new(ErrorCode::PublicRequestCancelled))
                } else {
                    Ok(())
                }
            })
            .unwrap_err();
        // The parent record of edge #256 is required before that callback, so its
        // damage must win. A mutation at the callback itself tests the boundary.
        assert_eq!(error.to_string(), "STORAGE_WORK");
        assert!(error.requires_owner_stop());
        assert_eq!(
            node.history_page_read_counters().ancestor_links - before.ancestor_links,
            255
        );
        let work = node
            .record(ids[2])
            .unwrap()
            .work
            .checked_sub(
                crate::consensus::required_work(node.packet(ids[2]).unwrap().header.target)
                    .unwrap(),
            )
            .unwrap();
        node.db
            .execute(
                "UPDATE blocks SET chainwork=? WHERE id=?",
                params![work.bytes().as_slice(), ids[1].as_slice()],
            )
            .unwrap();
        let error = node
            .history_with_progress(ids[257], ids[0], 16, &mut |n| {
                if n == 256 {
                    node.db.execute(
                        "UPDATE blocks SET chainwork=X'01' WHERE id=?",
                        [ids[1].as_slice()],
                    )?;
                    Err(Error::new(ErrorCode::PublicRequestCancelled))
                } else {
                    Ok(())
                }
            })
            .unwrap_err();
        assert!(error.is(ErrorCode::PublicRequestCancelled));
        node.db
            .execute(
                "UPDATE blocks SET chainwork=? WHERE id=?",
                params![work.bytes().as_slice(), ids[1].as_slice()],
            )
            .unwrap();
        compare(&node, ids[257], ids[0], 16, 257);

        // A real inactive fork is a supported fixed-tip history locator. Its
        // equal-height foreign cursor must fail even when the first page exists.
        let fork1 = extend(&mut node, ids[255], false, 3, false);
        let fork2 = extend(&mut node, fork1, false, 3, false);
        compare(&node, fork2, ids[255], 16, 2);
        matching_error(&node, fork2, ids[256], "CURSOR", false);
        matching_error(&node, ids[1], ids[2], "CURSOR", false);
        matching_error(&node, [255; 32], ids[0], "UNKNOWN_PARENT", false);
        for limit in [0, 17] {
            assert_eq!(
                node.history(ids[257], ids[0], limit)
                    .unwrap_err()
                    .to_string(),
                "PAGE_LIMIT"
            );
        }
        let fork3 = extend(&mut node, fork2, false, 3, false);
        node.activate(fork3).unwrap();
        let state = node.read_active().unwrap();
        let expected = compare(&node, ids[257], ids[0], 16, 257);
        // An explicit old tip remains meaningful after active generation changed.
        assert_eq!(
            encoded(&node.history(ids[257], ids[0], 16).unwrap()),
            expected
        );
        let settings = node.settings().clone();
        drop(node);
        let node = Node::open(directory.path(), settings, 1).unwrap();
        assert_eq!(node.read_active().unwrap(), state);
        assert_eq!(compare(&node, ids[257], ids[0], 16, 257), expected);
    }

    #[test]
    fn history_page_record_errors_keep_origin_and_validation_order() {
        let directory = tempfile::tempdir().unwrap();
        let (node, ids) = chain(directory.path(), 2);
        let parent = node.record(ids[1]).unwrap();
        let genesis = node.record(ids[0]).unwrap();
        // Complete parent shape, even beyond the returned page's first body.
        for (column, bad, expected) in [
            ("chainwork", vec![1_u8], "STORAGE_WORK"),
            ("state_root", vec![1], "STORAGE_HASH"),
            ("parent", vec![1], "STORAGE_HASH"),
        ] {
            node.db
                .execute(
                    &format!("UPDATE blocks SET {column}=? WHERE id=?"),
                    params![bad, ids[1].as_slice()],
                )
                .unwrap();
            matching_error(&node, ids[2], ids[0], expected, true);
            node.db
                .execute(
                    "UPDATE blocks SET parent=?,chainwork=?,state_root=? WHERE id=?",
                    params![
                        parent.parent.unwrap().as_slice(),
                        parent.work.bytes().as_slice(),
                        parent.root.as_slice(),
                        ids[1].as_slice()
                    ],
                )
                .unwrap();
        }
        node.db
            .execute(
                "UPDATE blocks SET parent=? WHERE id=?",
                params![[250_u8; 32].as_slice(), ids[1].as_slice()],
            )
            .unwrap();
        matching_error(&node, ids[2], ids[0], "UNKNOWN_PARENT", true);
        node.db
            .execute(
                "UPDATE blocks SET parent=? WHERE id=?",
                params![ids[2].as_slice(), ids[1].as_slice()],
            )
            .unwrap();
        matching_error(&node, ids[2], ids[0], "ANCESTRY_HEIGHT", true);
        node.db
            .execute(
                "UPDATE blocks SET parent=? WHERE id=?",
                params![ids[0].as_slice(), ids[1].as_slice()],
            )
            .unwrap();
        // The after locator is checked first, including when it equals tip.
        node.db
            .execute(
                "UPDATE blocks SET state_root=X'01' WHERE id=?",
                [ids[0].as_slice()],
            )
            .unwrap();
        matching_error(&node, [255; 32], ids[0], "STORAGE_HASH", true);
        matching_error(&node, ids[0], ids[0], "STORAGE_HASH", true);
        node.db
            .execute(
                "UPDATE blocks SET state_root=? WHERE id=?",
                params![genesis.root.as_slice(), ids[0].as_slice()],
            )
            .unwrap();
        compare(&node, ids[2], ids[0], 16, 2);
    }

    fn framed(packets: &[Vec<u8>]) -> Vec<u8> {
        let mut output = b"TRNMPAGE1".to_vec();
        output.extend((packets.len() as u32).to_le_bytes());
        for packet in packets {
            output.extend((packet.len() as u32).to_le_bytes());
            output.extend(packet);
        }
        output
    }

    fn emit(log: &mut File, row: Value) {
        let row = serde_json::to_string(&row).unwrap();
        writeln!(log, "{row}").unwrap();
        log.flush().unwrap();
        println!("{row}");
    }

    /// A finite actual-chain observation, explicitly selected outside routine CI.
    /// The old complete-call control exists only in this test binary. The paired
    /// clocks include call, returned Packet encoding and Packet release; framing,
    /// comparison, hashing, file writes and encoded-byte release are outside.
    #[test]
    #[ignore = "finite paired native history cost; requires a new output directory"]
    fn history_page_complete_call_cost() {
        let directory = std::env::var_os("TRNM_HISTORY_PAGE_COST_DIRECTORY")
            .expect("TRNM_HISTORY_PAGE_COST_DIRECTORY must name a new output directory");
        let directory = Path::new(&directory);
        fs::create_dir(directory).unwrap();
        fs::create_dir(directory.join("pages")).unwrap();
        let mut log = File::create(directory.join("history-page-cost.jsonl")).unwrap();
        let blocks: u64 = std::env::var("TRNM_HISTORY_PAGE_COST_BLOCKS")
            .unwrap_or_else(|_| "512".into())
            .parse()
            .unwrap();
        assert!((256..=512).contains(&blocks));
        let entries: Vec<_> = compiled_source::FILES
            .iter()
            .map(|(path, bytes)| json!({"path":path,"sha256":hex::encode(Sha256::digest(bytes))}))
            .collect();
        emit(
            &mut log,
            json!({
                "schema":"pon-native-history-page-cost-source-v1",
                "source_files":entries,
                "builder_commit_claim":option_env!("TRNM_DISTRIBUTED_SOURCE_COMMIT"),
                "builder_tree_claim":option_env!("TRNM_DISTRIBUTED_SOURCE_TREE"),
                "binary_sha256":hex::encode(Sha256::digest(fs::read(std::env::current_exe().unwrap()).unwrap())),
                "architecture":std::env::consts::ARCH,"os":std::env::consts::OS,
                "blocks":blocks,"pairs_per_case":8,"one_owner":true,
                "timed_scope":"complete history call, returned Packet encoding and Packet release; encoded bytes retained for out-of-clock comparison",
                "outside_clocks":["chain construction","control seeding","framing","full-byte comparisons","hashing","exports","encoded-byte release"],
                "reference":"earlier two-record-query and tempfile algorithm in this test binary, with logical counters; not an old binary",
                "page_cache_cleared":false,"process_rss_measured":false,
                "public_network_ready":false,"independent_accepted":false,"production_activation":false
            }),
        );
        let (node, ids) = chain(&directory.join("owner"), blocks);
        let (tip, generation, state) = node.read_active().unwrap();
        let root = trnm_mvcc_fee::pon_executor::root(&state).unwrap();
        assert_eq!(root, node.packet(tip).unwrap().header.state);
        fs::write(
            directory.join("active-state.json"),
            serde_json::to_vec(&state).unwrap(),
        )
        .unwrap();
        emit(
            &mut log,
            json!({
                "schema":"pon-native-history-page-cost-chain-v1",
                "blocks":blocks,"tip":hex::encode(tip),"genesis":hex::encode(ids[0]),
                "active_generation":generation,"physical_state_slot":node.slot().unwrap(),
                "actual_state_keys":state.len(),"full_reference_root":hex::encode(root),
                "first_wide_blocks":17,"signed_transactions_per_wide_block":16,
                "every_block_mined_admitted_activated":true
            }),
        );
        let writes = node.db.total_changes();
        let cases = [
            (64, 0, 16),
            (256, 0, 16),
            (blocks, 0, 16),
            (blocks, blocks - 17, 16),
            (blocks, blocks, 16),
        ];
        let mut samples = 0;
        for (case, (height, cursor, limit)) in cases.into_iter().enumerate() {
            let case_tip = ids[height as usize];
            let after = ids[cursor as usize];
            let distance = height - cursor;
            let expected = encoded(
                &spooled_reference(&node, case_tip, after, limit, &mut |_| Ok(()))
                    .unwrap()
                    .0,
            );
            let expected_frame = framed(&expected);
            let expected_digest = hex::encode(Sha256::digest(&expected_frame));
            for pair in 0..8 {
                for arm in if pair % 2 == 0 {
                    ["reference", "bounded"]
                } else {
                    ["bounded", "reference"]
                } {
                    let before = node.history_page_read_counters();
                    let started = Instant::now();
                    let (packets, reference_counts) = if arm == "reference" {
                        let (packets, counts) =
                            spooled_reference(&node, case_tip, after, limit, &mut |_| Ok(()))
                                .unwrap();
                        (packets, Some(counts))
                    } else {
                        (node.history(case_tip, after, limit).unwrap(), None)
                    };
                    let actual = encoded(&packets);
                    drop(packets);
                    let elapsed = started.elapsed().as_nanos();
                    let after_counts = node.history_page_read_counters();
                    assert_eq!(actual, expected);
                    let actual_frame = framed(&actual);
                    let digest = hex::encode(Sha256::digest(&actual_frame));
                    assert_eq!(digest, expected_digest);
                    let (queries, links, spool_write, spool_read) = match reference_counts {
                        Some(counts) => (
                            counts.ancestor_selects,
                            counts.ancestor_links,
                            counts.spool_bytes_written,
                            counts.spool_bytes_read,
                        ),
                        None => (
                            after_counts.ancestor_selects - before.ancestor_selects,
                            after_counts.ancestor_links - before.ancestor_links,
                            0,
                            0,
                        ),
                    };
                    assert_eq!(
                        queries,
                        if arm == "reference" {
                            2 * distance
                        } else {
                            distance.div_ceil(64)
                        }
                    );
                    assert_eq!(links, distance);
                    assert_eq!(
                        spool_write,
                        if arm == "reference" { 32 * distance } else { 0 }
                    );
                    assert!(after_counts.retained_ids_high_water <= 16);
                    let exported = if pair == 0 {
                        let name = format!("pages/case-{case}-{arm}.packets");
                        fs::write(directory.join(&name), &actual_frame).unwrap();
                        Some(name)
                    } else {
                        None
                    };
                    emit(
                        &mut log,
                        json!({
                            "schema":"pon-native-history-page-cost-sample-v1",
                            "case":case,"pair":pair,"arm":arm,
                            "first_arm":if pair % 2 == 0 { "reference" } else { "bounded" },
                            "tip_height":height,"after_height":cursor,"tip":hex::encode(case_tip),"after":hex::encode(after),
                            "limit":limit,"elapsed_ns":elapsed,"ancestor_links":links,"ancestor_selects":queries,
                            "ancestry_batch_limit":if arm == "bounded" { Some(64) } else { None },
                            "path_spool_bytes_written":spool_write,"path_spool_bytes_read":spool_read,
                            "spool_scope":"successful explicit path writes/reads only; no SQLite or physical filesystem traffic",
                            "node_retained_ids_lifetime_high_water":after_counts.retained_ids_high_water,
                            "returned_packets":actual.len(),"returned_packet_bytes":actual.iter().map(Vec::len).sum::<usize>(),
                            "framed_bytes":actual_frame.len(),"framed_sha256":digest,"full_bytes_equal":true,
                            "pair_zero_complete_export":exported,
                            "public_network_ready":false,"independent_accepted":false,"production_activation":false
                        }),
                    );
                    samples += 1;
                }
            }
        }
        assert_eq!(node.db.total_changes(), writes);
        assert_eq!(node.read_active().unwrap(), (tip, generation, state));
        let settings = node.settings().clone();
        drop(node);
        let reopened = Node::open(&directory.join("owner"), settings, 1).unwrap();
        assert_eq!(reopened.active().unwrap(), (tip, generation));
        assert_eq!(
            trnm_mvcc_fee::pon_executor::root(&reopened.read_active().unwrap().2).unwrap(),
            root
        );
        emit(
            &mut log,
            json!({
                "schema":"pon-native-history-page-cost-result-v1","complete":true,
                "blocks":blocks,"cases":5,"pairs":40,"samples":samples,
                "no_read_operation_sql_writes":true,"reopened_actual_root_equal":true,
                "public_network_ready":false,"independent_accepted":false,"production_activation":false
            }),
        );
    }
}
