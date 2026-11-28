use std::cell::{Cell, RefCell};
use std::io::{self, Read, Write};
use trnm_state_import::{
    Digest32V0, ExportRowV0, IncrementalDeltaErrorV0, MigrationErrorV0, SourceCheckpointContextV0,
    TargetDeltaRowV0, TargetRootBuilderV0, TargetRowV0, apply_incremental_delta_v0,
    derive_incremental_delta_v0, incremental_delta_root_v0,
};

fn synthetic_root<'a>(
    schema: Digest32V0,
    rows: impl IntoIterator<Item = &'a TargetRowV0>,
) -> Digest32V0 {
    let mut leaves = vec![schema];
    leaves.extend(
        rows.into_iter()
            .map(|r| ExportRowV0::canonical_digest(&r.namespace, &r.key, &r.value)),
    );
    let parts: Vec<_> = leaves.iter().map(|v| v.0.as_slice()).collect();
    Digest32V0::hash(b"trnm.test.incremental-projection-chain", &parts)
}

struct Observer<'a> {
    expected_base: Option<&'a [TargetRowV0]>,
    refuse_first: bool,
    calls: Cell<u32>,
    target: RefCell<Vec<TargetRowV0>>,
}

impl TargetRootBuilderV0 for Observer<'_> {
    type Error = io::Error;
    fn recompute_target_root<'a, I>(
        &self,
        schema: Digest32V0,
        rows: I,
    ) -> Result<Digest32V0, Self::Error>
    where
        I: IntoIterator<Item = &'a TargetRowV0>,
    {
        let ordered: Vec<_> = rows.into_iter().collect();
        let seen = self.calls.replace(self.calls.get() + 1);
        if let Some(base) = self.expected_base {
            if seen == 0 {
                assert!(ordered.iter().copied().eq(base.iter()));
                if self.refuse_first {
                    return Err(io::Error::other("synthetic first boundary refusal"));
                }
            } else {
                assert_eq!(seen, 1);
                *self.target.borrow_mut() = ordered.into_iter().cloned().collect();
                return Err(io::Error::other("synthetic second boundary refusal"));
            }
        }
        Ok(synthetic_root(schema, ordered))
    }
}

fn context(height: u64, state_root: Digest32V0) -> SourceCheckpointContextV0 {
    SourceCheckpointContextV0 {
        chain_id: Digest32V0([1; 32]),
        protocol_digest: Digest32V0([2; 32]),
        checkpoint_digest: Digest32V0([3; 32]),
        block_id: Digest32V0([4; 32]),
        height,
        epoch: 0,
        state_root,
        validator_set_digest: Digest32V0([5; 32]),
        finality_proof_digest: Digest32V0([6; 32]),
    }
}

fn pack_context(c: &SourceCheckpointContextV0, out: &mut Vec<u8>) {
    for d in [
        c.chain_id,
        c.protocol_digest,
        c.checkpoint_digest,
        c.block_id,
    ] {
        out.extend(d.0);
    }
    out.extend(c.height.to_be_bytes());
    out.extend(c.epoch.to_be_bytes());
    for d in [
        c.state_root,
        c.validator_set_digest,
        c.finality_proof_digest,
    ] {
        out.extend(d.0);
    }
}

fn take<'a>(source: &mut &'a [u8], n: usize) -> &'a [u8] {
    let (a, b) = source.split_at(n);
    *source = b;
    a
}
fn le32(input: &mut &[u8]) -> u32 {
    u32::from_le_bytes(take(input, 4).try_into().unwrap())
}
fn fields(input: &mut &[u8]) -> Option<(TargetRowV0, bool)> {
    if input.is_empty() {
        return None;
    }
    let ns = le32(input) as usize;
    let key = le32(input) as usize;
    let val = le32(input) as usize;
    let tag = le32(input);
    assert!(tag == 1 || (tag == 0 && val == 0));
    Some((
        TargetRowV0 {
            namespace: take(input, ns).to_vec(),
            key: take(input, key).to_vec(),
            value: take(input, val).to_vec(),
        },
        tag == 1,
    ))
}
fn base_rows(input: &mut &[u8], count: u8) -> Vec<TargetRowV0> {
    (0..count)
        .map(|_| {
            let (row, present) = fields(input).expect("typed fixture row");
            assert!(present);
            row
        })
        .collect()
}
fn pack_fields(
    out: &mut Vec<u8>,
    ns: &[u8],
    key: &[u8],
    val: Option<&[u8]>,
    op: Option<Digest32V0>,
) {
    let value = val.unwrap_or_default();
    for n in [ns.len(), key.len(), value.len(), usize::from(val.is_some())] {
        out.extend((n as u32).to_le_bytes());
    }
    if let Some(digest) = op {
        out.extend(digest.0);
    }
    out.extend(ns);
    out.extend(key);
    out.extend(value);
}

fn main() {
    let mut input = Vec::new();
    io::stdin()
        .read_to_end(&mut input)
        .expect("owned synthetic fixture");
    let mut packets = input.as_slice();
    let schema = Digest32V0([12; 32]);
    let mut out = io::stdout().lock();
    while !packets.is_empty() {
        let size = le32(&mut packets) as usize;
        let mut packet = take(&mut packets, size);
        let flags = le32(&mut packet);
        let counts = take(&mut packet, 4);
        let seed_base = base_rows(&mut packet, counts[0]);
        let mut base = base_rows(&mut packet, counts[1]);
        let golden = base_rows(&mut packet, counts[2]);
        let entries = (0..counts[3])
            .map(|i| {
                let (row, some) = fields(&mut packet).expect("typed fixture operation");
                let value = some.then_some(row.value);
                let mut op =
                    TargetDeltaRowV0::canonical_digest(&row.namespace, &row.key, value.as_deref());
                if i == 0 && flags & 1 != 0 {
                    op.0[3] ^= 1;
                }
                TargetDeltaRowV0 {
                    namespace: row.namespace,
                    key: row.key,
                    value,
                    operation_digest: op,
                }
            })
            .collect::<Vec<_>>();
        assert!(packet.is_empty());

        let source = context(1, synthetic_root(schema, &seed_base));
        let target = context(2, synthetic_root(schema, &golden));
        let derivation = Observer {
            expected_base: None,
            refuse_first: false,
            calls: Cell::new(0),
            target: RefCell::default(),
        };
        let mut delta = derive_incremental_delta_v0(
            Digest32V0([11; 32]),
            schema,
            source,
            target,
            &seed_base,
            &golden,
            &derivation,
        )
        .expect("exact unchanged Rust derives canonical context and commitments");
        assert_eq!(derivation.calls.get(), 2);
        delta.entries = entries;
        let leaves: Vec<_> = delta
            .entries
            .iter()
            .map(|row| row.operation_digest)
            .collect();
        delta.delta_root = incremental_delta_root_v0(&leaves);
        if flags & 2 != 0 {
            delta.delta_root.0[1] ^= 1;
        }
        let mut supplied_source = source;
        let mut supplied_target = target;
        if flags & 4 != 0 {
            supplied_source.height += 13;
        }
        if flags & 8 != 0 {
            supplied_target.protocol_digest.0[0] ^= 1;
        }
        if flags & 16 != 0 {
            delta.base_rows_digest.0[7] ^= 1;
        }
        if flags & 32 != 0 {
            delta.target_rows_digest.0[9] ^= 1;
        }
        if flags & 64 != 0 {
            delta.target_row_count += 1;
        }
        if flags & 128 != 0 {
            delta.base_row_count += 1;
        }
        if flags & 256 != 0 {
            base.first_mut().unwrap().namespace.clear();
        }
        if flags & 512 != 0 {
            delta.source_context.chain_id.0.fill(0);
        }
        if flags & 1024 != 0 {
            delta.plan_digest.0.fill(0);
        }
        delta.delta_digest = delta.canonical_digest();
        if flags & 2048 != 0 {
            delta.delta_digest.0[4] ^= 1;
        }

        let observed = |refuse_first| {
            let owner = Observer {
                expected_base: Some(&base),
                refuse_first,
                calls: Cell::new(0),
                target: RefCell::default(),
            };
            let result = apply_incremental_delta_v0(
                &delta,
                &supplied_source,
                &supplied_target,
                &base,
                &owner,
            );
            let observed = owner.calls.get();
            let status: u32 = match result {
                Err(IncrementalDeltaErrorV0::Protocol(MigrationErrorV0::InvalidDeltaRow)) => 101,
                Err(IncrementalDeltaErrorV0::Protocol(
                    MigrationErrorV0::RowsNotStrictlyOrdered,
                )) => 109,
                Err(IncrementalDeltaErrorV0::Protocol(MigrationErrorV0::DeltaRootMismatch)) => 112,
                Err(IncrementalDeltaErrorV0::Protocol(
                    MigrationErrorV0::InvalidSourceCheckpointContext,
                )) => 113,
                Err(IncrementalDeltaErrorV0::Protocol(
                    MigrationErrorV0::InvalidIncrementalDelta,
                )) => 114,
                Err(IncrementalDeltaErrorV0::Protocol(MigrationErrorV0::BaseStateMismatch)) => 115,
                Err(IncrementalDeltaErrorV0::Protocol(
                    MigrationErrorV0::SourceCheckpointContextMismatch,
                )) => 117,
                Err(IncrementalDeltaErrorV0::Protocol(MigrationErrorV0::InvalidTargetRow)) => 118,
                Err(IncrementalDeltaErrorV0::Protocol(MigrationErrorV0::TargetStateMismatch)) => {
                    119
                }
                Err(IncrementalDeltaErrorV0::RootBuilder(_)) if refuse_first => {
                    assert_eq!(observed, 1);
                    1
                }
                Err(IncrementalDeltaErrorV0::RootBuilder(_)) => {
                    assert_eq!(observed, 2);
                    0
                }
                other => {
                    panic!("unexpected authoritative result in refuse-only fixture: {other:?}")
                }
            };
            (status, observed, owner.target.into_inner())
        };
        let (status, count, rows) = observed(false);
        let (first_status, first_count, first_rows) = observed(true);
        assert!(first_rows.is_empty());
        if status == 0 {
            assert_eq!(rows, golden);
        }

        let mut wire = Vec::new();
        pack_context(&delta.source_context, &mut wire);
        pack_context(&delta.target_context, &mut wire);
        for d in [
            delta.plan_digest,
            delta.target_schema_digest,
            delta.base_rows_digest,
            delta.base_state_root,
            delta.target_rows_digest,
            delta.target_state_root,
        ] {
            wire.extend(d.0);
        }
        wire.extend(delta.base_row_count.to_be_bytes());
        wire.extend(delta.target_row_count.to_be_bytes());
        wire.extend(delta.delta_root.0);
        wire.extend(delta.delta_digest.0);
        wire.extend((delta.entries.len() as u64).to_be_bytes());
        assert_eq!(wire.len(), 760);
        for row in &delta.entries {
            pack_fields(
                &mut wire,
                &row.namespace,
                &row.key,
                row.value.as_deref(),
                Some(row.operation_digest),
            );
        }
        let cut = wire.len() as u64;
        pack_context(&supplied_source, &mut wire);
        pack_context(&supplied_target, &mut wire);
        wire.extend((base.len() as u64).to_be_bytes());
        for row in &base {
            pack_fields(&mut wire, &row.namespace, &row.key, Some(&row.value), None);
        }
        wire.extend(cut.to_be_bytes());
        for item in [
            status,
            count,
            first_status,
            first_count,
            rows.len() as u32,
            wire.len() as u32,
        ] {
            out.write_all(&item.to_le_bytes())
                .expect("exact bounded fixture observation");
        }
        out.write_all(&wire).expect("exact shared immutable frame");
        for row in rows {
            let mut frame = Vec::new();
            pack_fields(&mut frame, &row.namespace, &row.key, Some(&row.value), None);
            out.write_all(&frame).expect("original observed rows ");
        }
    }
}
