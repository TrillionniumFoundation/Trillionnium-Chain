// Qualification fixture only. Does not supply a SourceFinalityVerifier.
use std::convert::Infallible;
use std::io::{self, Write};
use std::path::Path;
use trnm_state_import::{
    Digest32V0, DurableDeltaSnapshotV0, ExportRowV0, SourceCheckpointContextV0,
    SqliteIncrementalStateStoreV0, TargetRootBuilderV0, TargetRowV0, derive_incremental_delta_v0,
};

fn d(value: u8) -> Digest32V0 {
    Digest32V0([value; 32])
}

// Deterministic test-only callback isolates durable staging from the separate
// root/finality owner. It does not authenticate a checkpoint.
struct FixtureRoot;
impl TargetRootBuilderV0 for FixtureRoot {
    type Error = Infallible;
    fn recompute_target_root<'a, I>(
        &self,
        schema: Digest32V0,
        rows: I,
    ) -> Result<Digest32V0, Self::Error>
    where
        I: IntoIterator<Item = &'a TargetRowV0>,
    {
        let mut parts = vec![schema.0];
        for row in rows {
            parts.push(ExportRowV0::canonical_digest(&row.namespace, &row.key, &row.value).0);
        }
        Ok(Digest32V0::hash(
            b"trnm.local-qualification.target-state",
            &parts.iter().map(|part| &part[..]).collect::<Vec<_>>(),
        ))
    }
}

fn private_frame(snapshot: DurableDeltaSnapshotV0) -> Vec<u8> {
    let mut out = Vec::new();
    for digest in [
        snapshot.plan_digest,
        snapshot.target_schema_digest,
        snapshot.source_context_digest,
        snapshot.target_context_digest,
        snapshot.rows_digest,
        snapshot.state_root,
    ] {
        out.extend(digest.0);
    }
    out.extend(snapshot.row_count.to_be_bytes());
    out.extend(snapshot.generation.to_be_bytes());
    out.extend(snapshot.last_delta_digest.0);
    out.extend(snapshot.snapshot_digest.0);
    for row in snapshot.rows {
        for field in [&row.namespace, &row.key, &row.value] {
            out.extend(u32::try_from(field.len()).expect("bounded fixture").to_le_bytes());
        }
        out.extend(ExportRowV0::canonical_digest(&row.namespace, &row.key, &row.value).0);
        out.extend(row.namespace);
        out.extend(row.key);
        out.extend(row.value);
    }
    out
}

fn context(rows: &[TargetRowV0], height: u64) -> SourceCheckpointContextV0 {
    SourceCheckpointContextV0 {
        chain_id: d(1),
        protocol_digest: d(2),
        checkpoint_digest: d(height as u8 + 20),
        block_id: d(height as u8 + 40),
        height,
        epoch: 1,
        state_root: FixtureRoot.recompute_target_root(d(11), rows.iter()).unwrap(),
        validator_set_digest: d(7),
        finality_proof_digest: d(height as u8 + 60),
    }
}

fn fixture(count: u16) -> Vec<TargetRowV0> {
    (0..count)
        .map(|n| TargetRowV0 {
            namespace: b"ordinary-snapshot".to_vec(),
            key: n.to_be_bytes().to_vec(),
            value: (0..(n % 137)).map(|i| (i ^ n) as u8).collect(),
        })
        .collect()
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = std::env::args().collect::<Vec<_>>();
    let path = Path::new(&args[2]);
    match (&*args[1], args.len()) {
        ("seed", 4) => {
            let rows = fixture(args[3].parse()?);
            SqliteIncrementalStateStoreV0::initialize(
                path, d(10), d(11), context(&rows, 5), &rows, &FixtureRoot,
            )?;
        }
        ("seed-stream", 3) => {
            let sizes = [0usize, 1, 65535, 65536, 65537, 16777216];
            let rows = sizes.iter().enumerate().map(|(i, n)| TargetRowV0 {
                namespace: b"ordinary-stream".to_vec(),
                key: vec![i as u8, 0, 255],
                value: (0..*n).map(|position| {
                    ((position * 37 + position / 65536 * 23 + i) & 255) as u8
                }).collect(),
            }).collect::<Vec<_>>();
            SqliteIncrementalStateStoreV0::initialize(
                path, d(10), d(11), context(&rows, 5), &rows, &FixtureRoot,
            )?;
        }
        ("read-digest", 3) => {
            let store = SqliteIncrementalStateStoreV0::open_existing(path, d(10), d(11))?;
            let read = store.readback_v0()?;
            let mut out = io::stdout().lock();
            for field in [read.plan_digest, read.target_schema_digest, read.source_context_digest,
                          read.target_context_digest, read.rows_digest, read.state_root] {
                out.write_all(&field.0)?;
            }
            out.write_all(&read.row_count.to_be_bytes())?;
            out.write_all(&read.generation.to_be_bytes())?;
            out.write_all(&read.last_delta_digest.0)?;
        }
        ("seed-rich", 3) => {
            let mut rows = vec![
                (vec![0], vec![0], Vec::new()),
                (vec![0], vec![0, 0], vec![0, 128, 255]),
                (vec![0], vec![255], vec![1]),
                (vec![0, 255], vec![0], vec![58]),
                (b"Signer_journal".to_vec(), vec![128], vec![0]),
                (b"signer_journa".to_vec(), vec![1], vec![42]),
                (b"xsigner_journal".to_vec(), vec![255], vec![10]),
                (vec![255; 128], vec![255; 65536], vec![255, 0]),
            ].into_iter().map(|(namespace, key, value)| TargetRowV0 { namespace, key, value })
                .collect::<Vec<_>>();
            rows.sort();
            SqliteIncrementalStateStoreV0::initialize(
                path, d(10), d(11), context(&rows, 5), &rows, &FixtureRoot,
            )?;
        }
        ("advance", 3) => {
            let store = SqliteIncrementalStateStoreV0::open_existing(path, d(10), d(11))?;
            let before = store.read_rows_v0()?;
            let mut after = before.clone();
            after[0].value = b"committed successor row".to_vec();
            after.pop().expect("nonempty local fixture");
            let delta = derive_incremental_delta_v0(
                d(10), d(11), context(&before, 5), context(&after, 6),
                &before, &after, &FixtureRoot,
            )?;
            store.apply_delta_v0(&delta, &FixtureRoot)?;
        }
        ("vector-advance", 3) => {
            let store = SqliteIncrementalStateStoreV0::open_existing(path, d(10), d(11))?;
            let before = store.read_rows_v0()?;
            let mut after = before.clone();
            let insert = |key: Vec<u8>, value: Vec<u8>| TargetRowV0 {
                namespace: b"ordinary-snapshot".to_vec(), key, value,
            };
            let wanted = match before.len() {
                0 => {
                    after.push(insert(vec![0, 4, 255], Vec::new()));
                    b"I".to_vec()
                }
                11 => {
                    for index in [6, 4, 2, 0] {
                        after.remove(index);
                    }
                    b"DDDD".to_vec()
                }
                17 => {
                    after[0].value = vec![255, 0, 128, 13, 10];
                    after[3].value = Vec::new();
                    after[5].value = (0..128).map(|i| (255 - i * 3 % 256) as u8).collect();
                    after.remove(2);
                    after.remove(1);
                    after.push(insert(vec![0, 1, 255], vec![58, 13, 0]));
                    after.push(insert(vec![0, 3, 255], Vec::new()));
                    after.push(insert(vec![0, 4, 255], vec![255, 0, 85]));
                    b"UDIDUIIU".to_vec()
                }
                rows if (22..=27).contains(&rows) => {
                    let kinds = b"IUDDIUU";
                    let requested = rows - 20;
                    for (index, kind) in kinds[..requested].iter().enumerate() {
                        match kind {
                            b'I' => after.push(insert(vec![0, index as u8, 255], vec![0, 255])),
                            b'U' => after.iter_mut().find(|row| row.key == before[index].key)
                                .unwrap().value = vec![255, index as u8, 0],
                            b'D' => after.retain(|row| row.key != before[index].key),
                            _ => unreachable!(),
                        }
                    }
                    kinds[..requested].to_vec()
                }
                _ => return Err("wrong bounded vector qualification fixture".into()),
            };
            after.sort();
            let delta = derive_incremental_delta_v0(
                d(10), d(11), context(&before, 5), context(&after, 6),
                &before, &after, &FixtureRoot,
            )?;
            let kinds: Vec<u8> = delta.entries.iter().map(|entry| {
                if entry.value.is_none() {
                    b'D'
                } else if before.iter().any(|row| row.namespace == entry.namespace && row.key == entry.key) {
                    b'U'
                } else {
                    b'I'
                }
            }).collect();
            if kinds != wanted {
                return Err("original must derive exact bounded vector kinds in byte-key order".into());
            }
            store.apply_delta_v0(&delta, &FixtureRoot)?;
        }
        ("mixed-advance", 3) => {
            let store = SqliteIncrementalStateStoreV0::open_existing(path, d(10), d(11))?;
            let before = store.read_rows_v0()?;
            if before.len() < 3 {
                return Err("mixed fixture requires three or more predecessor rows".into());
            }
            let mut after = before[1..].to_vec();
            let last = after.last_mut().unwrap();
            last.value = vec![255, 0, 13, 10, 128, 0, 58];
            let inserted = TargetRowV0 {
                namespace: b"ordinary-snapshot".to_vec(),
                key: vec![0, 0, 255],
                value: if before.len() == 3 { Vec::new() } else {
                    (0..128).map(|i| (255 - i * 3 % 256) as u8).collect()
                },
            };
            after.push(inserted.clone());
            after.sort();
            let update = after.last().unwrap();
            let delta = derive_incremental_delta_v0(
                d(10), d(11), context(&before, 5), context(&after, 6),
                &before, &after, &FixtureRoot,
            )?;
            if delta.entries.len() != 3
                || delta.entries[0].key != before[0].key
                || delta.entries[0].value.is_some()
                || delta.entries[1].key != inserted.key
                || delta.entries[1].value.as_ref() != Some(&inserted.value)
                || delta.entries[2].key != update.key
                || delta.entries[2].value.as_ref() != Some(&update.value)
            {
                return Err("reference should derive one sorted DELETE/INSERT/UPDATE".into());
            }
            store.apply_delta_v0(&delta, &FixtureRoot)?;
        }
        ("update-advance", 3) => {
            let store = SqliteIncrementalStateStoreV0::open_existing(path, d(10), d(11))?;
            let before = store.read_rows_v0()?;
            if before.is_empty() {
                return Err("update fixture starts with at least one row".into());
            }
            let mut after = before.clone();
            let idx = before.len() / 2;
            after[idx].value = if before[idx].value.is_empty() {
                (0..128).map(|i| (255 - i * 5 % 256) as u8).collect()
            } else {
                Vec::new()
            };
            let delta = derive_incremental_delta_v0(
                d(10), d(11), context(&before, 5), context(&after, 6),
                &before, &after, &FixtureRoot,
            )?;
            if delta.entries.len() != 1 || delta.entries[0].value.as_ref() != Some(&after[idx].value) {
                return Err("reference should contain exactly one value change".into());
            }
            store.apply_delta_v0(&delta, &FixtureRoot)?;
        }
        ("insert-advance", 3) => {
            let store = SqliteIncrementalStateStoreV0::open_existing(path, d(10), d(11))?;
            let before = store.read_rows_v0()?;
            let mut after = before.clone();
            after.push(TargetRowV0 {
                namespace: b"ordinary-snapshot".to_vec(),
                key: vec![0, 0, 255],
                value: if before.is_empty() { vec![] } else {
                    (0..128).map(|i| (255 - i * 3 % 256) as u8).collect()
                },
            });
            after.sort();
            let delta = derive_incremental_delta_v0(
                d(10), d(11), context(&before, 5), context(&after, 6),
                &before, &after, &FixtureRoot,
            )?;
            if delta.entries.len() != 1 || delta.entries[0].value.is_none() {
                return Err("reference should contain exactly one original insertion".into());
            }
            store.apply_delta_v0(&delta, &FixtureRoot)?;
        }
        ("delete-advance", 3) => {
            let store = SqliteIncrementalStateStoreV0::open_existing(path, d(10), d(11))?;
            let before = store.read_rows_v0()?;
            if before.is_empty() {
                return Err("delete fixture starts with at least one row".into());
            }
            let mut after = before.clone();
            after.remove(before.len() / 2);
            let delta = derive_incremental_delta_v0(
                d(10), d(11), context(&before, 5), context(&after, 6),
                &before, &after, &FixtureRoot,
            )?;
            if delta.entries.len() != 1 || delta.entries[0].value.is_some() {
                return Err("reference should contain exactly one DELETE".into());
            }
            store.apply_delta_v0(&delta, &FixtureRoot)?;
        }
        ("empty-advance" | "empty-receipt", 3) => {
            let store = SqliteIncrementalStateStoreV0::open_existing(path, d(10), d(11))?;
            let rows = store.read_rows_v0()?;
            let delta = derive_incremental_delta_v0(
                d(10), d(11), context(&rows, 5), context(&rows, 6),
                &rows, &rows, &FixtureRoot,
            )?;
            if !delta.entries.is_empty() {
                return Err("reference should contain no row mutations".into());
            }
            let receipt = store.apply_delta_v0(&delta, &FixtureRoot)?;
            if args[1] == "empty-receipt" {
                let mut out = io::stdout().lock();
                out.write_all(&receipt.generation.to_be_bytes())?;
                out.write_all(&receipt.delta_digest.0)?;
            }
        }
        ("export", 3) => {
            let store = SqliteIncrementalStateStoreV0::open_existing(path, d(10), d(11))?;
            let snapshot = store.export_snapshot_v0(&FixtureRoot)?;
            io::stdout().write_all(&private_frame(snapshot))?;
        }
        _ => return Err("scope is seed/seed-rich/seed-stream/read-digest/advance/vector-advance/mixed-advance/update-advance/insert-advance/delete-advance/empty-advance/empty-receipt/export on disposable staging only".into()),
    }
    Ok(())
}
