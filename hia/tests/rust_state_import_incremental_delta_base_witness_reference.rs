use std::cell::Cell;
use std::io::{self, Read, Write};
use trnm_state_import::{
    Digest32V0, IncrementalDeltaErrorV0, MigrationErrorV0, SourceCheckpointContextV0,
    TargetRootBuilderV0, TargetRowV0, apply_incremental_delta_v0, derive_incremental_delta_v0,
};

const STATIC_ROOT: Digest32V0 = Digest32V0([42; 32]);

struct OwnerProbe<'a> {
    calls: Cell<u32>,
    will_refuse: bool,
    expect: &'a [TargetRowV0],
}

impl TargetRootBuilderV0 for OwnerProbe<'_> {
    type Error = io::Error;
    fn recompute_target_root<'a, I>(
        &self,
        _schema: Digest32V0,
        rows: I,
    ) -> Result<Digest32V0, Self::Error>
    where
        I: IntoIterator<Item = &'a TargetRowV0>,
    {
        assert!(rows.into_iter().eq(self.expect.iter()), "unexpected ordered base rows");
        self.calls.set(self.calls.get() + 1);
        if self.will_refuse {
            Err(io::Error::other("intentional first application root-owner refusal"))
        } else {
            Ok(STATIC_ROOT)
        }
    }
}

fn take<'a>(source: &mut &'a [u8], count: usize) -> &'a [u8] {
    let (value, rest) = source.split_at(count);
    *source = rest;
    value
}

fn u32_le(source: &mut &[u8]) -> u32 {
    u32::from_le_bytes(take(source, 4).try_into().expect("fixture frame word"))
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
    let mut input = Vec::new();
    io::stdin().read_to_end(&mut input).expect("fixture stream");
    let mut cases = input.as_slice();
    let mut output = io::stdout().lock();
    while !cases.is_empty() {
        let size = u32_le(&mut cases) as usize;
        let mut recipe = take(&mut cases, size);
        let mode = take(&mut recipe, 1)[0];
        let mut raw = take(&mut recipe, 1008).to_vec();
        assert!(mode <= 3);
        let source = context(&raw, 0);
        let target = context(&raw, 240);
        let supplied_source = context(&raw, 480);
        let supplied_target = context(&raw, 720);
        let observed_count = number(&raw, 1000);
        assert!(observed_count <= 8);
        let mut rows = Vec::new();
        for _ in 0..observed_count {
            let ns = u32_le(&mut recipe) as usize;
            let key = u32_le(&mut recipe) as usize;
            let value = u32_le(&mut recipe) as usize;
            assert_eq!(u32_le(&mut recipe), 0);
            rows.push(TargetRowV0 {
                namespace: take(&mut recipe, ns).to_vec(),
                key: take(&mut recipe, key).to_vec(),
                value: take(&mut recipe, value).to_vec(),
            });
        }
        assert!(recipe.is_empty());

        let derive = |selected: &[TargetRowV0]| {
            let derive_owner = OwnerProbe { calls: Cell::new(0), will_refuse: false, expect: selected };
            derive_incremental_delta_v0(
                Digest32V0([11; 32]), Digest32V0([12; 32]), source, target,
                selected, selected, &derive_owner,
            )
        };
        // For malformed candidate rows the genuine producer refuses; use the separately
        // genuine empty baseline so that the consumer reaches the intended row check.
        let mut delta = match derive(&rows) {
            Ok(valid) => valid,
            Err(IncrementalDeltaErrorV0::Protocol(MigrationErrorV0::InvalidTargetRow |
                                                   MigrationErrorV0::RowsNotStrictlyOrdered)) => {
                derive(&[]).expect("original unaffected empty baseline")
            }
            other => panic!("unexpected original baseline: {other:?}"),
        };
        if mode & 1 != 0 {
            delta.base_row_count = number(&raw, 960);
        }
        if mode & 2 != 0 {
            delta.base_rows_digest.0[3] ^= 1;
        }
        delta.delta_digest = delta.canonical_digest();
        raw[960..968].copy_from_slice(&delta.base_row_count.to_be_bytes());
        raw[968..1000].copy_from_slice(&delta.base_rows_digest.0);

        let owner = OwnerProbe { calls: Cell::new(0), will_refuse: true, expect: &rows };
        let (status, count): (u32, u32) = match apply_incremental_delta_v0(
            &delta, &supplied_source, &supplied_target, &rows, &owner,
        ) {
            Err(IncrementalDeltaErrorV0::Protocol(MigrationErrorV0::SourceCheckpointContextMismatch)) => (117, 0),
            Err(IncrementalDeltaErrorV0::Protocol(MigrationErrorV0::InvalidTargetRow)) => (118, 0),
            Err(IncrementalDeltaErrorV0::Protocol(MigrationErrorV0::RowsNotStrictlyOrdered)) => (109, 0),
            Err(IncrementalDeltaErrorV0::Protocol(MigrationErrorV0::BaseStateMismatch)) => (115, 0),
            Err(IncrementalDeltaErrorV0::RootBuilder(_)) => (0, 1),
            other => panic!("unexpected original base witness result: {other:?}"),
        };
        assert_eq!(owner.calls.get(), count);
        output.write_all(&status.to_le_bytes()).expect("status");
        output.write_all(&count.to_le_bytes()).expect("owner count");
        output.write_all(&raw).expect("exact base witness header");
    }
}
