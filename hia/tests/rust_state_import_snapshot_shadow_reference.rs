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
        ("empty-advance", 3) => {
            let store = SqliteIncrementalStateStoreV0::open_existing(path, d(10), d(11))?;
            let rows = store.read_rows_v0()?;
            let delta = derive_incremental_delta_v0(
                d(10), d(11), context(&rows, 5), context(&rows, 6),
                &rows, &rows, &FixtureRoot,
            )?;
            if !delta.entries.is_empty() {
                return Err("reference should contain no row mutations".into());
            }
            store.apply_delta_v0(&delta, &FixtureRoot)?;
        }
        ("export", 3) => {
            let store = SqliteIncrementalStateStoreV0::open_existing(path, d(10), d(11))?;
            let snapshot = store.export_snapshot_v0(&FixtureRoot)?;
            io::stdout().write_all(&private_frame(snapshot))?;
        }
        _ => return Err("scope is seed/advance/insert-advance/delete-advance/empty-advance/export on disposable staging only".into()),
    }
    Ok(())
}
