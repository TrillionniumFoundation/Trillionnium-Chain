#!/usr/bin/env python3
"""Isolated candidate construction; never a production fallback or acceptance receipt."""
import hashlib
from pathlib import Path

root = Path(__file__).resolve().parents[2]
source = root / 'trillionnium/crates/trnm-pon-node/src/account_archive_prototype.rs'
tests = root / 'trillionnium/crates/trnm-pon-node/src/account_archive_prototype/native_primitive_tests.rs'

def check(path, expected):
    data = path.read_bytes()
    actual = hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest()
    if actual != expected:
        raise SystemExit(f'candidate source changed: {path}: {actual}')
    return data.decode()

old = check(source, '4288f23e49db89b9b3d0f1a61011240431bb1bb7')
prior_tests = check(tests, '2376d7d90c54ade7c751dc76612f87c9d0bee935')
needle = 'fn branch(left: Hash, right: Hash) -> Hash {\n    hash(b"account-archive-branch-v1", &[&left, &right])\n}'
replacement = r'''fn branch(left: Hash, right: Hash) -> Hash {
    use sha2::{Digest, Sha256};
    // The exact pon_wire::hash transcript for this fixed tag and two Hash
    // parts. One stack buffer avoids seven small update calls per sparse edge;
    // no node, hash result or validation verdict is cached.
    let mut encoded = [0u8; 109];
    encoded[..41].copy_from_slice(b"TRNM-PON1\0\x19\0account-archive-branch-v1\x20\0\0\0");
    encoded[41..73].copy_from_slice(&left);
    encoded[73..77].copy_from_slice(&32u32.to_le_bytes());
    encoded[77..].copy_from_slice(&right);
    Sha256::digest(encoded).into()
}'''
if old.count(needle) != 1:
    raise SystemExit('unexpected branch function')
source.write_text(old.replace(needle, replacement))
tests.write_text(prior_tests + r'''

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
        assert_ne!(branch(left, right), hash(b"account-archive-branch-v1", &[&[left, right].concat()]));
        assert_ne!(branch(left, right), hash(b"account-archive-branch-v2", &[&left, &right]));
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
        if rows.is_empty() { return empty[depth]; }
        if depth == 256 {
            assert_eq!(rows.len(), 1);
            return hash(b"account-archive-leaf-v1", &[
                &rows[0].1,
                &rows[0].2.balance.to_le_bytes(),
                &rows[0].2.nonce.to_le_bytes(),
            ]);
        }
        let split = rows.partition_point(|row| !bit(&row.0, depth));
        unpacked_branch(reference(&rows[..split], depth + 1, empty), reference(&rows[split..], depth + 1, empty))
    }
    let mut empty = [[0; 32]; 257];
    empty[256] = hash(b"account-archive-empty-v1", &[]);
    for depth in (0..256).rev() { empty[depth] = unpacked_branch(empty[depth + 1], empty[depth + 1]); }
    assert_eq!(empty_hashes(), empty);
    for count in [0, 1, 2, 3, 17, 64, 513, 2048] {
        let accounts = (0..count).map(|index: u64| (
            hash(b"packed-branch-root-owner", &[&index.to_le_bytes()]),
            Account { balance: index.wrapping_mul(17), nonce: index.wrapping_mul(3) }
        )).collect::<BTreeMap<_, _>>();
        let rows = ordered_accounts(&accounts).unwrap();
        assert_eq!(account_root(&accounts).unwrap(), reference(&rows, 0, &empty));
    }
}

#[test]
fn packed_branch_chained_computation_retains_both_arms() {
    use std::hint::black_box;
    let mut observations = Vec::new();
    let rounds = if cfg!(debug_assertions) { 1000 } else { 100_000 };
    for pair in 0..8 {
        let mut terminal = Vec::new();
        for arm in if pair % 2 == 0 { [0, 1] } else { [1, 0] } {
            let compute: fn(Hash, Hash) -> Hash = if arm == 0 { unpacked_branch } else { branch };
            let mut left = [0; 32];
            let right = [255; 32];
            let start = Instant::now();
            for _ in 0..rounds { left = black_box(compute(black_box(left), black_box(right))); }
            let elapsed_ns = start.elapsed().as_nanos();
            terminal.push(left);
            observations.push(json!({"pair":pair,"arm":if arm == 0 {"original"} else {"packed"},"rounds":rounds,"elapsed_ns":elapsed_ns,"terminal":hex::encode(left)}));
        }
        assert_eq!(terminal[0], terminal[1]);
    }
    eprintln!("pon_packed_branch_cost_v1 {}", json!({"scope":"chained branch hash only; not Node TPS or a speed guarantee","debug_assertions":cfg!(debug_assertions),"observations":observations}));
}
''')
print('Candidate construction only; original tests preserved. No native acceptance yet.')
