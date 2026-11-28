use std::cell::Cell;
use std::io::{self, Read, Write};
use trnm_state_import::{
    Digest32V0, IncrementalDeltaErrorV0, IncrementalStateDeltaV0, MigrationErrorV0,
    SourceCheckpointContextV0, TargetDeltaRowV0, TargetRootBuilderV0, TargetRowV0,
    apply_incremental_delta_v0, derive_incremental_delta_v0, incremental_delta_root_v0,
};

struct RefusedOwner(Cell<u32>);
impl TargetRootBuilderV0 for RefusedOwner {
    type Error = io::Error;
    fn recompute_target_root<'a, I>(
        &self,
        _schema: Digest32V0,
        rows: I,
    ) -> Result<Digest32V0, Self::Error>
    where
        I: IntoIterator<Item = &'a TargetRowV0>,
    {
        assert!(rows.into_iter().next().is_none());
        self.0.set(self.0.get() + 1);
        Err(io::Error::other("intentional refusal after original validation"))
    }
}

struct SyntheticRoot;
impl TargetRootBuilderV0 for SyntheticRoot {
    type Error = io::Error;
    fn recompute_target_root<'a, I>(
        &self,
        _schema: Digest32V0,
        _rows: I,
    ) -> Result<Digest32V0, Self::Error>
    where
        I: IntoIterator<Item = &'a TargetRowV0>,
    {
        Ok(Digest32V0([42; 32]))
    }
}

fn original_empty_rows_digest() -> Digest32V0 {
    let d = Digest32V0([1; 32]);
    let source = SourceCheckpointContextV0 {
        chain_id: d,
        protocol_digest: d,
        checkpoint_digest: d,
        block_id: d,
        height: 1,
        epoch: 0,
        state_root: Digest32V0([42; 32]),
        validator_set_digest: d,
        finality_proof_digest: d,
    };
    let target = SourceCheckpointContextV0 { height: 2, ..source };
    derive_incremental_delta_v0(d, d, source, target, &[], &[], &SyntheticRoot)
        .expect("authentic synthetic canonical base")
        .base_rows_digest
}

fn digest(raw: &[u8], at: usize) -> Digest32V0 {
    Digest32V0(raw[at..at + 32].try_into().expect("fixture digest"))
}

fn number(raw: &[u8], at: usize) -> u64 {
    u64::from_be_bytes(raw[at..at + 8].try_into().expect("fixture number"))
}

fn context(raw: &[u8], base: usize) -> SourceCheckpointContextV0 {
    SourceCheckpointContextV0 {
        chain_id: digest(raw, base),
        protocol_digest: digest(raw, base + 32),
        checkpoint_digest: digest(raw, base + 64),
        block_id: digest(raw, base + 96),
        height: number(raw, base + 128),
        epoch: number(raw, base + 136),
        state_root: digest(raw, base + 144),
        validator_set_digest: digest(raw, base + 176),
        finality_proof_digest: digest(raw, base + 208),
    }
}

fn take<'a>(source: &mut &'a [u8], count: usize) -> &'a [u8] {
    let (value, rest) = source.split_at(count);
    *source = rest;
    value
}

fn u32_le(source: &mut &[u8]) -> u32 {
    u32::from_le_bytes(take(source, 4).try_into().expect("fixture word"))
}

fn main() {
    let mut bytes = Vec::new();
    io::stdin().read_to_end(&mut bytes).expect("fixture stream");
    let mut contents = bytes.as_slice();
    let base_rows = original_empty_rows_digest();
    let mut output = io::stdout().lock();
    while !contents.is_empty() {
        let size = u32_le(&mut contents) as usize;
        let mut case = take(&mut contents, size);
        let mode = take(&mut case, 1)[0];
        assert!(mode <= 3);
        let mut raw = take(&mut case, 760).to_vec();
        let source = context(&raw, 0);
        let target = context(&raw, 240);
        let count = number(&raw, 752);
        assert!(count <= 8);
        let mut entries = Vec::new();
        for _ in 0..count {
            let ns = u32_le(&mut case) as usize;
            let key = u32_le(&mut case) as usize;
            let val = u32_le(&mut case) as usize;
            let kind = u32_le(&mut case);
            let corrupt = take(&mut case, 1)[0];
            assert!(kind <= 1 && (kind == 1 || val == 0));
            let namespace = take(&mut case, ns).to_vec();
            let key = take(&mut case, key).to_vec();
            let field = take(&mut case, val);
            let value = (kind == 1).then(|| field.to_vec());
            let mut stored = TargetDeltaRowV0::canonical_digest(&namespace, &key, value.as_deref());
            if corrupt > 0 {
                stored.0[usize::from(corrupt - 1)] ^= 1;
            }
            entries.push(TargetDeltaRowV0 { namespace, key, value, operation_digest: stored });
        }
        assert!(case.is_empty());
        let leaves: Vec<_> = entries.iter().map(|entry| entry.operation_digest).collect();
        let mut root = incremental_delta_root_v0(&leaves);
        if mode & 2 != 0 {
            root.0[31] ^= 1;
        }
        let mut delta = IncrementalStateDeltaV0 {
            plan_digest: digest(&raw, 480),
            target_schema_digest: digest(&raw, 512),
            source_context: source,
            target_context: target,
            base_rows_digest: base_rows,
            base_state_root: digest(&raw, 576),
            target_rows_digest: digest(&raw, 608),
            target_state_root: digest(&raw, 640),
            base_row_count: number(&raw, 672),
            target_row_count: number(&raw, 680),
            delta_root: root,
            delta_digest: Digest32V0([0; 32]),
            entries,
        };
        delta.delta_digest = delta.canonical_digest();
        if mode & 1 != 0 {
            delta.delta_digest.0[13] ^= 1;
        }
        raw[544..576].copy_from_slice(&base_rows.0);
        raw[688..720].copy_from_slice(&root.0);
        raw[720..752].copy_from_slice(&delta.delta_digest.0);

        let owner = RefusedOwner(Cell::new(0));
        let (status, calls): (u32, u32) = match apply_incremental_delta_v0(&delta, &source, &target, &[], &owner) {
            Err(IncrementalDeltaErrorV0::Protocol(MigrationErrorV0::InvalidSourceCheckpointContext)) => (113, 0),
            Err(IncrementalDeltaErrorV0::Protocol(MigrationErrorV0::InvalidIncrementalDelta)) => (114, 0),
            Err(IncrementalDeltaErrorV0::Protocol(MigrationErrorV0::InvalidDeltaRow)) => (101, 0),
            Err(IncrementalDeltaErrorV0::Protocol(MigrationErrorV0::RowsNotStrictlyOrdered)) => (109, 0),
            Err(IncrementalDeltaErrorV0::Protocol(MigrationErrorV0::DeltaRootMismatch)) => (112, 0),
            Err(IncrementalDeltaErrorV0::RootBuilder(_)) => (0, 1),
            other => panic!("Unexpected result from original compound stage: {other:?}"),
        };
        assert_eq!(owner.0.get(), calls);
        output.write_all(&status.to_le_bytes()).expect("status");
        output.write_all(&calls.to_le_bytes()).expect("callback count");
        output.write_all(&raw).expect("header");
        for leaf in leaves {
            output.write_all(&leaf.0).expect("leaf");
        }
    }
}
