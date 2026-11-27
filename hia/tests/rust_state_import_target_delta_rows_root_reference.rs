use std::cell::Cell;
use std::io::{self, Read, Write};
use trnm_state_import::{
    Digest32V0, IncrementalDeltaErrorV0, MigrationErrorV0, SourceCheckpointContextV0,
    TargetDeltaRowV0, TargetRootBuilderV0, TargetRowV0, apply_incremental_delta_v0,
    derive_incremental_delta_v0, incremental_delta_root_v0,
};

const FIXTURE_ROOT: Digest32V0 = Digest32V0([42; 32]);

struct RootProbe {
    calls: Cell<u32>,
    refuse: bool,
}

impl TargetRootBuilderV0 for RootProbe {
    type Error = io::Error;

    fn recompute_target_root<'a, I>(
        &self,
        _schema: Digest32V0,
        rows: I,
    ) -> Result<Digest32V0, Self::Error>
    where
        I: IntoIterator<Item = &'a TargetRowV0>,
    {
        assert!(rows.into_iter().next().is_none(), "source probe must stay empty");
        self.calls.set(self.calls.get() + 1);
        if self.refuse {
            Err(io::Error::other("intentional root-owner refusal after the checked stage"))
        } else {
            Ok(FIXTURE_ROOT)
        }
    }
}

fn context(height: u64) -> SourceCheckpointContextV0 {
    SourceCheckpointContextV0 {
        chain_id: Digest32V0([1; 32]),
        protocol_digest: Digest32V0([2; 32]),
        checkpoint_digest: Digest32V0([3; 32]),
        block_id: Digest32V0([4; 32]),
        height,
        epoch: 0,
        state_root: FIXTURE_ROOT,
        validator_set_digest: Digest32V0([5; 32]),
        finality_proof_digest: Digest32V0([6; 32]),
    }
}

fn take<'a>(input: &mut &'a [u8], n: usize) -> &'a [u8] {
    let (first, rest) = input.split_at(n);
    *input = rest;
    first
}

fn le_word(input: &mut &[u8]) -> u32 {
    u32::from_le_bytes(take(input, 4).try_into().expect("fixture word"))
}

fn main() {
    let mut buffer = Vec::new();
    io::stdin().read_to_end(&mut buffer).expect("fixture stream");
    let mut input = buffer.as_slice();
    let source = context(1);
    let target = context(2);
    let baseline = derive_incremental_delta_v0(
        Digest32V0([7; 32]),
        Digest32V0([8; 32]),
        source,
        target,
        &[],
        &[],
        &RootProbe { calls: Cell::new(0), refuse: false },
    )
    .expect("actual ordinary canonical derivation");
    let mut output = io::stdout().lock();
    while !input.is_empty() {
        let size = le_word(&mut input) as usize;
        let mut recipe = take(&mut input, size);
        let mut delta = baseline.clone();
        let count = le_word(&mut recipe);
        let wrong_root = take(&mut recipe, 1)[0];
        assert!(count <= 8 && wrong_root <= 1);
        for _ in 0..count {
            let ns_len = le_word(&mut recipe) as usize;
            let key_len = le_word(&mut recipe) as usize;
            let val_len = le_word(&mut recipe) as usize;
            let kind = le_word(&mut recipe);
            let changed = take(&mut recipe, 1)[0];
            let namespace = take(&mut recipe, ns_len).to_vec();
            let key = take(&mut recipe, key_len).to_vec();
            let value_bytes = take(&mut recipe, val_len);
            assert!(kind <= 1 && (kind == 1 || val_len == 0));
            let value = (kind == 1).then(|| value_bytes.to_vec());

            let mut stored = TargetDeltaRowV0::canonical_digest(&namespace, &key, value.as_deref());
            if changed != 0 {
                stored.0[usize::from(changed - 1)] ^= 0x80;
            }
            delta.entries.push(TargetDeltaRowV0 { namespace, key, value, operation_digest: stored });
        }
        assert!(recipe.is_empty());
        let digests: Vec<_> = delta.entries.iter().map(|row| row.operation_digest).collect();
        delta.delta_root = incremental_delta_root_v0(&digests);
        if wrong_root == 1 {
            delta.delta_root.0[0] ^= 1;
        }
        // All enclosing commitments are the original computed values; the
        // witness may single out this stage without forging a verified context.
        delta.delta_digest = delta.canonical_digest();
        let owner = RootProbe { calls: Cell::new(0), refuse: true };
        let (status, expected_calls) = match apply_incremental_delta_v0(&delta, &source, &target, &[], &owner) {
            Err(IncrementalDeltaErrorV0::RootBuilder(_)) => (0_u32, 1),
            Err(IncrementalDeltaErrorV0::Protocol(MigrationErrorV0::InvalidDeltaRow)) => (101, 0),
            Err(IncrementalDeltaErrorV0::Protocol(MigrationErrorV0::RowsNotStrictlyOrdered)) => (109, 0),
            Err(IncrementalDeltaErrorV0::Protocol(MigrationErrorV0::DeltaRootMismatch)) => (112, 0),
            other => panic!("Unexpected original stage observation: {other:?}"),
        };
        assert_eq!(owner.calls.get(), expected_calls);
        output.write_all(&status.to_le_bytes()).expect("status");
        output.write_all(&owner.calls.get().to_le_bytes()).expect("call count");
        output.write_all(&delta.delta_root.0).expect("declared root");
        for digest in digests {
            output.write_all(&digest.0).expect("stored leaf");
        }
    }
}
