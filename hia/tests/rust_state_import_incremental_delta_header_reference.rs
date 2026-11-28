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

fn main() {
    let mut contents = Vec::new();
    io::stdin().read_to_end(&mut contents).expect("fixture stream");
    assert_eq!(contents.len() % 761, 0);
    let base_rows = original_empty_rows_digest();
    let mut output = io::stdout().lock();
    for record in contents.chunks_exact_mut(761) {
        let mode = record[0];
        let raw = &mut record[1..];
        let source = context(raw, 0);
        let target = context(raw, 240);
        let count = number(raw, 752);
        assert!(count <= 8 && mode < 16);
        let mut entries = (0..count)
            .map(|index| {
                let namespace = vec![b'a'];
                let key = vec![index.try_into().expect("fixture key")];
                let value = (index % 2 == 0).then(|| vec![b'x']);
                let operation_digest = TargetDeltaRowV0::canonical_digest(&namespace, &key, value.as_deref());
                TargetDeltaRowV0 { namespace, key, value, operation_digest }
            })
            .collect::<Vec<_>>();
        if mode & 4 != 0 {
            entries[0].operation_digest.0[0] ^= 1;
        }
        let requested_root = if mode & 2 == 0 {
            let leaves: Vec<_> = entries.iter().map(|entry| entry.operation_digest).collect();
            incremental_delta_root_v0(&leaves)
        } else {
            digest(raw, 688)
        };
        let mut delta = IncrementalStateDeltaV0 {
            plan_digest: digest(raw, 480),
            target_schema_digest: digest(raw, 512),
            source_context: source,
            target_context: target,
            base_rows_digest: if mode & 8 == 0 {
                base_rows
            } else {
                digest(raw, 544)
            },
            base_state_root: digest(raw, 576),
            target_rows_digest: digest(raw, 608),
            target_state_root: digest(raw, 640),
            base_row_count: number(raw, 672),
            target_row_count: number(raw, 680),
            delta_root: requested_root,
            delta_digest: Digest32V0([0; 32]),
            entries,
        };
        delta.delta_digest = delta.canonical_digest();
        if mode & 1 != 0 {
            delta.delta_digest.0[0] ^= 1;
        }
        raw[544..576].copy_from_slice(&delta.base_rows_digest.0);
        raw[688..720].copy_from_slice(&requested_root.0);
        raw[720..752].copy_from_slice(&delta.delta_digest.0);

        let owner = RefusedOwner(Cell::new(0));
        let (status, stage_after, calls): (u32, u32, u32) =
            match apply_incremental_delta_v0(&delta, &source, &target, &[], &owner) {
                Err(IncrementalDeltaErrorV0::Protocol(MigrationErrorV0::InvalidSourceCheckpointContext)) => (113, 0, 0),
                Err(IncrementalDeltaErrorV0::Protocol(MigrationErrorV0::InvalidIncrementalDelta)) => (114, 0, 0),
                Err(IncrementalDeltaErrorV0::Protocol(MigrationErrorV0::InvalidDeltaRow)) => (0, 101, 0),
                Err(IncrementalDeltaErrorV0::Protocol(MigrationErrorV0::DeltaRootMismatch)) => (0, 112, 0),
                Err(IncrementalDeltaErrorV0::Protocol(MigrationErrorV0::BaseStateMismatch)) => (0, 115, 0),
                Err(IncrementalDeltaErrorV0::RootBuilder(_)) => (0, 116, 1),
                other => panic!("Unexpected original header-stage observation: {other:?}"),
            };
        assert_eq!(owner.0.get(), calls);
        output.write_all(&status.to_le_bytes()).expect("status");
        output.write_all(&stage_after.to_le_bytes()).expect("downstream stage");
        output.write_all(&calls.to_le_bytes()).expect("owner call count");
        output.write_all(raw).expect("exact header");
    }
}
