use std::cell::{Cell, RefCell};
use std::io::{self, Read, Write};
use trnm_state_import::{
    Digest32V0, ExportRowV0, IncrementalDeltaErrorV0, MigrationErrorV0,
    SourceCheckpointContextV0, TargetDeltaRowV0, TargetRootBuilderV0, TargetRowV0,
    apply_incremental_delta_v0, derive_incremental_delta_v0, incremental_delta_root_v0,
};

fn synthetic_root<'a>(schema: Digest32V0, rows: impl IntoIterator<Item = &'a TargetRowV0>) -> Digest32V0 {
    let mut leaves = vec![schema];
    leaves.extend(rows.into_iter().map(|r| ExportRowV0::canonical_digest(&r.namespace, &r.key, &r.value)));
    let parts: Vec<_> = leaves.iter().map(|v| v.0.as_slice()).collect();
    Digest32V0::hash(b"trnm.test.incremental-target-projection", &parts)
}

struct Observer<'a> {
    expected_base: Option<&'a [TargetRowV0]>,
    calls: Cell<u32>,
    observed_target: RefCell<Option<Vec<TargetRowV0>>>,
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
        let seen = self.calls.get();
        self.calls.set(seen + 1);
        if let Some(expected_base) = self.expected_base {
            if seen == 0 {
                assert!(ordered.iter().copied().eq(expected_base.iter()));
            } else {
                assert_eq!(seen, 1);
                *self.observed_target.borrow_mut() = Some(ordered.into_iter().cloned().collect());
                return Err(io::Error::other("stop at genuine second root callback"));
            }
        }
        Ok(synthetic_root(schema, ordered))
    }
}

fn take<'a>(source: &mut &'a [u8], n: usize) -> &'a [u8] {
    let (a, b) = source.split_at(n);
    *source = b;
    a
}

fn le32(source: &mut &[u8]) -> u32 {
    u32::from_le_bytes(take(source, 4).try_into().expect("fixture word"))
}

fn be64(source: &mut &[u8]) -> u64 {
    u64::from_be_bytes(take(source, 8).try_into().expect("fixture count"))
}

fn fields(input: &mut &[u8]) -> (TargetRowV0, bool) {
    let ns = le32(input) as usize;
    let key = le32(input) as usize;
    let val = le32(input) as usize;
    let tag = le32(input);
    assert!(tag <= 1 && (tag == 1 || val == 0));
    (
        TargetRowV0 {
            namespace: take(input, ns).to_vec(),
            key: take(input, key).to_vec(),
            value: take(input, val).to_vec(),
        },
        tag == 1,
    )
}

fn target_rows(input: &mut &[u8], len: u64) -> Vec<TargetRowV0> {
    (0..len)
        .map(|_| {
            let (row, present) = fields(input);
            assert!(present);
            row
        })
        .collect()
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

fn main() {
    let mut input = Vec::new();
    io::stdin().read_to_end(&mut input).expect("fixture input");
    let mut cases = input.as_slice();
    let mut output = io::stdout().lock();
    let schema = Digest32V0([12; 32]);
    while !cases.is_empty() {
        let width = le32(&mut cases) as usize;
        let mut recipe = take(&mut cases, width);
        let mode = take(&mut recipe, 1)[0];
        let base_count = be64(&mut recipe);
        let operation_count = be64(&mut recipe);
        let fixture_target_count = be64(&mut recipe);
        let alternate_claim = be64(&mut recipe);
        assert!(mode <= 3 && base_count <= 8 && operation_count <= 8 && fixture_target_count <= 16);
        let base = target_rows(&mut recipe, base_count);
        let entries: Vec<_> = (0..operation_count)
            .map(|_| {
                let (row, present) = fields(&mut recipe);
                let value = present.then_some(row.value);
                let operation_digest =
                    TargetDeltaRowV0::canonical_digest(&row.namespace, &row.key, value.as_deref());
                TargetDeltaRowV0 { namespace: row.namespace, key: row.key, value, operation_digest }
            })
            .collect();
        let fixture_target = target_rows(&mut recipe, fixture_target_count);
        assert!(recipe.is_empty());

        let source = context(1, synthetic_root(schema, &base));
        let target = context(2, synthetic_root(schema, &fixture_target));
        let derive_owner = Observer { expected_base: None, calls: Cell::new(0), observed_target: RefCell::new(None) };
        let mut delta = derive_incremental_delta_v0(
            Digest32V0([11; 32]), schema, source, target, &base, &fixture_target, &derive_owner,
        )
        .expect("genuine original synthetic header and target claim");
        assert_eq!(derive_owner.calls.get(), 2);
        delta.entries = entries;
        let leaves: Vec<_> = delta.entries.iter().map(|e| e.operation_digest).collect();
        delta.delta_root = incremental_delta_root_v0(&leaves);
        if mode & 1 != 0 {
            delta.target_row_count = alternate_claim;
        }
        if mode & 2 != 0 {
            delta.target_rows_digest.0[0] ^= 1;
        }
        delta.delta_digest = delta.canonical_digest();
        let owner = Observer { expected_base: Some(&base), calls: Cell::new(0), observed_target: RefCell::new(None) };
        let (status, callbacks): (u32, u32) = match apply_incremental_delta_v0(
            &delta, &source, &target, &base, &owner,
        ) {
            Err(IncrementalDeltaErrorV0::Protocol(MigrationErrorV0::TargetStateMismatch)) => (119, 1),
            Err(IncrementalDeltaErrorV0::RootBuilder(_)) => (0, 2),
            other => panic!("unexpected original bounded projection observation: {other:?}"),
        };
        assert_eq!(owner.calls.get(), callbacks);
        let rows = owner.observed_target.into_inner().unwrap_or_default();
        assert_eq!(rows.len(), if callbacks == 2 { fixture_target_count as usize } else { 0 });
        output.write_all(&status.to_le_bytes()).expect("status");
        output.write_all(&callbacks.to_le_bytes()).expect("callback count");
        output.write_all(&delta.target_row_count.to_be_bytes()).expect("declared count");
        output.write_all(&delta.target_rows_digest.0).expect("declared digest");
        output.write_all(&(rows.len() as u32).to_le_bytes()).expect("observed count");
        for row in rows {
            for field in [row.namespace, row.key, row.value] {
                output.write_all(&(field.len() as u32).to_le_bytes()).expect("field width");
                output.write_all(&field).expect("exact field");
            }
        }
    }
}
