//! Finite controls retained from the packed-branch candidate at 8805ce62ff28.
//! These exercise the current shared primitive without running the historical
//! source-rewrite script. Timing output is a local observation, not acceptance
//! or a performance claim. The original native-primitive roster stays separate.
use super::*;
use serde_json::json;
use std::time::Instant;

// Independent pon_wire transcript oracle for the packed fixed-size branch.
fn unpacked_branch(left: Hash, right: Hash) -> Hash {
    hash(b"account-archive-branch-v1", &[&left, &right])
}

#[test]
fn packed_branch_preserves_domain_lengths_order_and_every_input_bit() {
    for seed in 0..64u64 {
        let left = hash(b"packed-branch-left", &[&seed.to_le_bytes()]);
        let right = hash(b"packed-branch-right", &[&seed.to_le_bytes()]);
        assert_eq!(branch(left, right), unpacked_branch(left, right));
        for bit_index in 0..256 {
            let mut changed = left;
            changed[bit_index / 8] ^= 1 << (bit_index % 8);
            assert_eq!(branch(changed, right), unpacked_branch(changed, right));
            let mut changed = right;
            changed[bit_index / 8] ^= 1 << (bit_index % 8);
            assert_eq!(branch(left, changed), unpacked_branch(left, changed));
        }
        assert_ne!(branch(left, right), branch(right, left));
        assert_ne!(
            branch(left, right),
            hash(b"account-archive-branch-v1", &[&[left, right].concat()])
        );
        assert_ne!(
            branch(left, right),
            hash(b"account-archive-branch-v2", &[&left, &right])
        );
    }
    for left in [[0; 32], [255; 32]] {
        for right in [[0; 32], [255; 32]] {
            assert_eq!(branch(left, right), unpacked_branch(left, right));
        }
    }
}

#[test]
fn packed_branch_complete_sparse_roots_match_independent_depth_walk() {
    fn reference(rows: &[(Hash, Hash, Account)], depth: usize, empty: &[Hash; 257]) -> Hash {
        if rows.is_empty() {
            return empty[depth];
        }
        if depth == 256 {
            assert_eq!(rows.len(), 1);
            return hash(
                b"account-archive-leaf-v1",
                &[
                    &rows[0].1,
                    &rows[0].2.balance.to_le_bytes(),
                    &rows[0].2.nonce.to_le_bytes(),
                ],
            );
        }
        let split = rows.partition_point(|row| !bit(&row.0, depth));
        unpacked_branch(
            reference(&rows[..split], depth + 1, empty),
            reference(&rows[split..], depth + 1, empty),
        )
    }
    let mut empty = [[0; 32]; 257];
    empty[256] = hash(b"account-archive-empty-v1", &[]);
    for depth in (0..256).rev() {
        empty[depth] = unpacked_branch(empty[depth + 1], empty[depth + 1]);
    }
    assert_eq!(empty_hashes(), empty);
    for count in [0, 1, 2, 3, 17, 64, 513, 2048] {
        let accounts = (0..count)
            .map(|index: u64| {
                (
                    hash(b"packed-branch-root-owner", &[&index.to_le_bytes()]),
                    Account {
                        balance: index.wrapping_mul(17),
                        nonce: index.wrapping_mul(3),
                    },
                )
            })
            .collect::<BTreeMap<_, _>>();
        let rows = ordered_accounts(&accounts).unwrap();
        assert_eq!(
            account_root(&accounts).unwrap(),
            reference(&rows, 0, &empty)
        );
    }
}

#[test]
fn packed_branch_chained_computation_retains_both_arms() {
    use std::hint::black_box;
    let mut observations = Vec::new();
    let rounds = if cfg!(debug_assertions) {
        1000
    } else {
        100_000
    };
    for pair in 0..8 {
        let mut terminal = Vec::new();
        for arm in if pair % 2 == 0 { [0, 1] } else { [1, 0] } {
            let compute: fn(Hash, Hash) -> Hash = if arm == 0 { unpacked_branch } else { branch };
            let mut left = [0; 32];
            let right = [255; 32];
            let start = Instant::now();
            for _ in 0..rounds {
                left = black_box(compute(black_box(left), black_box(right)));
            }
            let elapsed_ns = start.elapsed().as_nanos();
            terminal.push(left);
            observations.push(json!({"pair":pair,"arm":if arm == 0 {"original"} else {"packed"},"rounds":rounds,"elapsed_ns":elapsed_ns,"terminal":hex::encode(left)}));
        }
        assert_eq!(terminal[0], terminal[1]);
    }
    eprintln!(
        "pon_packed_branch_cost_v1 {}",
        json!({"scope":"chained branch hash only; not Node TPS or a speed guarantee","debug_assertions":cfg!(debug_assertions),"observations":observations})
    );
}
