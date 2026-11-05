use super::super::{account_root, account_root_with_lifts, build_with_lift, hash, path, Node};
use super::*;

// Retain the original record-building entry as a differential oracle. It
// really constructs every leaf/fork ID and never calls the digest builder.
fn record_root(values: &BTreeMap<Hash, Account>, lifts: &LiftCache) -> Result<Hash> {
    let lift = |node: &Node, depth| lifts.lift(node, depth);
    Ok(
        build_with_lift(None, &ordered_accounts(values)?, &mut || Ok(()), &lift)?
            .map_or_else(|| empty_hashes()[0], |node| lift(&node, 0)),
    )
}

fn accounts(count: usize) -> BTreeMap<Hash, Account> {
    (0..count as u64)
        .map(|index| {
            (
                hash(b"native-root-digest-fixture-v1", &[&index.to_le_bytes()]),
                Account {
                    balance: index * 7,
                    nonce: index,
                },
            )
        })
        .collect()
}

fn protocol_root(values: &BTreeMap<Hash, Account>) -> Hash {
    // This independently expands the complete 256-level sparse relation,
    // without the Patricia record or new digest-only build implementation.
    trnm_protocol::pon_wire::account_archive_root_from_accounts(
        values
            .iter()
            .map(|(&owner, value)| (owner, value.balance, value.nonce)),
    )
    .unwrap()
}

#[test]
fn native_root_digest_matches_record_and_sparse_references_after_exact_input_changes() {
    let old_cache = LiftCache::default();
    let new_cache = LiftCache::default();
    for count in [0, 1, 2, 3, 17, 65, 513] {
        let mut values = accounts(count);
        let expected = protocol_root(&values);
        assert_eq!(account_root(&values).unwrap(), expected);
        assert_eq!(record_root(&values, &old_cache).unwrap(), expected);
        assert_eq!(
            account_root_with_lifts(&values, &new_cache).unwrap(),
            expected
        );
        assert_eq!(
            account_root_with_lifts(&values, &new_cache).unwrap(),
            expected
        );
        // Every field can change while the same arithmetic owner remains warm.
        for (index, value) in values.values_mut().enumerate() {
            if index % 3 == 0 {
                value.balance = u64::MAX - index as u64;
            }
            if index % 5 == 0 {
                value.nonce = u64::MAX - index as u64;
            }
        }
        let expected = protocol_root(&values);
        assert_eq!(record_root(&values, &old_cache).unwrap(), expected);
        assert_eq!(
            account_root_with_lifts(&values, &new_cache).unwrap(),
            expected
        );
        if let Some((owner, value)) = values.pop_first() {
            assert_eq!(
                account_root_with_lifts(&values, &new_cache).unwrap(),
                protocol_root(&values)
            );
            values.insert(hash(b"native-root-digest-new-owner-v1", &[&owner]), value);
            assert_eq!(
                record_root(&values, &old_cache).unwrap(),
                protocol_root(&values)
            );
            assert_eq!(
                account_root_with_lifts(&values, &new_cache).unwrap(),
                protocol_root(&values)
            );
        }
    }
    // Zero balance does not erase account existence or its old nonce. Change
    // each field independently with the same warm arithmetic owners.
    let mut values = BTreeMap::new();
    let absent = protocol_root(&values);
    let owner = hash(b"native-root-digest-zero-owner-v1", &[]);
    for (balance, nonce) in [
        (0, 0),
        (0, u64::MAX),
        (u64::MAX, 0),
        (u64::MAX, u64::MAX),
        (1, 0),
        (0, 1),
    ] {
        values.insert(owner, Account { balance, nonce });
        let expected = protocol_root(&values);
        assert_ne!(expected, absent);
        assert_eq!(account_root(&values).unwrap(), expected);
        assert_eq!(record_root(&values, &old_cache).unwrap(), expected);
        assert_eq!(
            account_root_with_lifts(&values, &new_cache).unwrap(),
            expected
        );
    }
    values.remove(&owner);
    assert_eq!(
        account_root_with_lifts(&values, &new_cache).unwrap(),
        absent
    );
}

#[test]
fn native_root_digest_keeps_original_traversal_cancellation_and_collision_order() {
    let values = accounts(17);
    let valid = ordered_accounts(&values).unwrap();
    let mut repeated = valid.clone();
    repeated[16].0 = repeated[0].0;
    let mut reversed = valid.clone();
    reversed.reverse();
    let mut mismatched_single = vec![valid[0]];
    mismatched_single[0].0[0] ^= 0x80;
    let mut swapped_owners = vec![valid[0], valid[16]];
    let first_owner = swapped_owners[0].1;
    swapped_owners[0].1 = swapped_owners[1].1;
    swapped_owners[1].1 = first_owner;
    let actual_common_prefix = valid
        .windows(2)
        .find(|rows| common(&rows[0].0, &rows[1].0) > 0)
        .unwrap();
    let mut false_shape = actual_common_prefix.to_vec();
    false_shape[0].0 = [0; 32];
    false_shape[1].0 = [0x80; 32];
    // A caller supplies actual owners/accounts, never path/owner tuples. Even
    // when such tuples are forged here, rebuilding that public input derives
    // each path afresh before the private recursive builder can see any row.
    // Test this entry precondition rather than adding a second owner hash to
    // every production leaf for malformed tuples that cannot reach it.
    let public_cache = LiftCache::default();
    for (case, supplied) in [
        ("mismatched singleton path", mismatched_single),
        ("swapped owners", swapped_owners),
        ("false supplied fork shape", false_shape),
    ] {
        assert!(
            supplied
                .iter()
                .any(|(supplied_path, owner, _)| *supplied_path != path(*owner)),
            "{case} must violate the internal row precondition"
        );
        let actual: BTreeMap<_, _> = supplied
            .iter()
            .map(|(_, owner, value)| (*owner, *value))
            .collect();
        let rebuilt = ordered_accounts(&actual).unwrap();
        assert_eq!(rebuilt.len(), actual.len());
        assert!(rebuilt.windows(2).all(|rows| rows[0].0 < rows[1].0));
        for (derived_path, owner, value) in &rebuilt {
            assert_eq!(*derived_path, path(*owner), "{case}");
            let expected = actual.get(owner).unwrap();
            assert_eq!(
                (value.balance, value.nonce),
                (expected.balance, expected.nonce),
                "{case}"
            );
            assert_eq!(*derived_path, Node::account(*owner, *value).path, "{case}");
        }
        let expected = protocol_root(&actual);
        assert_eq!(account_root(&actual).unwrap(), expected, "{case}");
        assert_eq!(
            account_root_with_lifts(&actual, &public_cache).unwrap(),
            expected,
            "{case}"
        );
    }
    // The production builder only receives ordered_accounts output. These
    // retained malformed-row controls preserve the original collision and
    // partition errors and every original cancellation point.
    for (case, rows, expected_error) in [
        ("valid", valid, None),
        ("repeated path", repeated, Some(ArchiveError::KeyCollision)),
        ("reversed rows", reversed, Some(ArchiveError::CorruptRecord)),
    ] {
        for cancel_at in 1..=2 * rows.len() + 1 {
            let old_cache = LiftCache::default();
            let new_cache = LiftCache::default();
            let mut old_visits = 0;
            let mut new_visits = 0;
            let old = build_with_lift(
                None,
                &rows,
                &mut || {
                    old_visits += 1;
                    if old_visits == cancel_at {
                        Err(ArchiveError::Cancelled)
                    } else {
                        Ok(())
                    }
                },
                &|node, depth| old_cache.lift(node, depth),
            )
            .map(|node| node.map(|node| (node.path, node.depth, node.digest)));
            let new = build(
                &rows,
                &mut || {
                    new_visits += 1;
                    if new_visits == cancel_at {
                        Err(ArchiveError::Cancelled)
                    } else {
                        Ok(())
                    }
                },
                &new_cache,
            )
            .map(|node| node.map(|node| (node.path, node.depth, node.digest)));
            assert_eq!(new, old, "{case}, cancel at {cancel_at}");
            assert_eq!(new_visits, old_visits);
            if cancel_at > 2 * rows.len() {
                assert_eq!(new.as_ref().err(), expected_error.as_ref(), "{case}");
            }
        }
    }
    let mut visits = 0;
    assert!(build(
        &[],
        &mut || {
            visits += 1;
            Ok(())
        },
        &LiftCache::default()
    )
    .unwrap()
    .is_none());
    assert_eq!(visits, 0);
}

#[test]
fn native_root_digest_keeps_fork_shape_and_all_lift_input_relations() {
    let rows = ordered_accounts(&accounts(2)).unwrap();
    let seed_left = Node::account(rows[0].1, rows[0].2);
    let seed_right = Node::account(rows[1].1, rows[1].2);
    let cache = LiftCache::default();
    let empty = empty_hashes();
    for depth in 0usize..256 {
        // Synthetic mathematical subtrees cover every divergence bit without
        // assuming an ability to find chosen-prefix account-key hash preimages.
        // The reference retains its independent original Node::lift body.
        let mut left = seed_left.clone();
        let mut right = seed_right.clone();
        left.path = hash(b"native-root-fork-path-v1", &[&depth.to_le_bytes()]);
        let mask = 0x80u8 >> (depth % 8);
        left.path[depth / 8] &= !mask;
        right.path = left.path;
        right.path[depth / 8] |= mask;
        right.path[depth / 8 + 1..].fill(0xa5);
        assert_eq!(common(&left.path, &right.path), depth);
        for (left_depth, right_depth) in [
            (depth + 1, depth + 1),
            (depth + 1, 256),
            (256, depth + 1),
            (256, 256),
        ] {
            left.depth = left_depth;
            right.depth = right_depth;
            for variant in 0..7 {
                let mut left = left.clone();
                let mut right = right.clone();
                let selected_depth = match variant {
                    0 => depth,
                    1 => 256,
                    2 => {
                        left.depth = depth;
                        depth
                    }
                    3 => {
                        right.depth = depth;
                        depth
                    }
                    4 => {
                        std::mem::swap(&mut left, &mut right);
                        depth
                    }
                    5 => {
                        right.path = left.path;
                        depth
                    }
                    _ => depth + 1,
                };
                let old = Node::fork(selected_depth, &left, &right, &empty)
                    .map(|node| (node.path, node.depth, node.digest));
                let project = |node: &Node| RootDigest {
                    path: node.path,
                    depth: node.depth,
                    digest: node.digest,
                };
                let new =
                    RootDigest::fork(selected_depth, &project(&left), &project(&right), &cache)
                        .map(|node| (node.path, node.depth, node.digest));
                assert_eq!(
                    new, old,
                    "fork depth {depth}, children {left_depth}/{right_depth}, variant {variant}"
                );
                assert_eq!(new.is_ok(), variant == 0);
            }
        }
    }
    for source_depth in [0, 1, 7, 8, 63, 64, 128, 255, 256] {
        for salt in [0, 1, 255] {
            let mut node = seed_left.clone();
            node.path.fill(salt);
            node.digest = hash(b"native-root-lift-input-v1", &[&[salt]]);
            node.depth = source_depth;
            for target in [0, source_depth / 2, source_depth, source_depth + 1] {
                assert_eq!(
                    cache.lift_parts(node.path, node.digest, node.depth, target),
                    node.lift(target, &empty)
                );
                assert_eq!(cache.lift(&node, target), node.lift(target, &empty));
            }
        }
    }
}

#[test]
#[ignore = "explicit paired complete-account-root cost; excludes current SQL/Host/business confirmation"]
fn native_root_digest_paired_complete_root_cost_observation() {
    use sha2::{Digest, Sha256};
    use std::io::Write;
    use std::time::Instant;
    let path = std::env::var("TRNM_NATIVE_ROOT_DIGEST_COST_OUTPUT")
        .expect("fresh output filename required");
    let mut output = std::fs::File::create_new(path).unwrap();
    let write = |output: &mut std::fs::File, value: serde_json::Value| {
        serde_json::to_writer(&mut *output, &value).unwrap();
        writeln!(output).unwrap();
        output.flush().unwrap();
    };
    let cpu = || -> Option<u64> {
        let stamp = rustix::time::clock_gettime_dynamic(rustix::time::DynamicClockId::Known(
            rustix::time::ClockId::ThreadCPUTime,
        ))
        .ok()?;
        let nanos = u64::try_from(stamp.tv_nsec).ok()?;
        if nanos >= 1_000_000_000 {
            return None;
        }
        u64::try_from(stamp.tv_sec)
            .ok()?
            .checked_mul(1_000_000_000)?
            .checked_add(nanos)
    };
    write(
        &mut output,
        serde_json::json!({
            "schema":"pon-native-root-digest-cost-v1", "kind":"source",
            "prototype_sha256":hex::encode(Sha256::digest(include_bytes!("../account_archive_prototype.rs"))),
            "native_store_sha256":hex::encode(Sha256::digest(include_bytes!("native_store.rs"))),
            "digest_builder_sha256":hex::encode(Sha256::digest(include_bytes!("native_root_digest.rs"))),
            "test_source_sha256":hex::encode(Sha256::digest(include_bytes!("native_root_digest_tests.rs"))),
            "debug_assertions":cfg!(debug_assertions), "live_lift_caches":4,
            "scope":"same complete current-account math and exact hash/cache grammar; excludes account State parsing, SQL graph verification, Host, PQ, full State root, networking and business confirmation",
            "order":"alternating ABBA/BAAB, two independent caches per arm; two cold and 100 warm observations per arm and size",
            "source_authority":false, "business_acceptance_qualified":false
        }),
    );
    for count in [1024usize, 9216] {
        let values = accounts(count);
        let expected = protocol_root(&values);
        let caches =
            std::array::from_fn::<_, 2, _>(|_| [LiftCache::default(), LiftCache::default()]);
        let mut cold = [Vec::new(), Vec::new()];
        let mut warm = [Vec::new(), Vec::new()];
        for round in 0..=50 {
            let sequence = if round % 2 == 0 {
                [(0, 0), (1, 0), (1, 1), (0, 1)]
            } else {
                [(1, 0), (0, 0), (0, 1), (1, 1)]
            };
            for (arm, instance) in sequence {
                let start = Instant::now();
                let cpu_before = cpu();
                let root = if arm == 0 {
                    record_root(&values, &caches[arm][instance])
                } else {
                    account_root_with_lifts(&values, &caches[arm][instance])
                }
                .unwrap();
                let thread_cpu_ns = cpu_before
                    .zip(cpu())
                    .and_then(|(before, after)| after.checked_sub(before));
                let elapsed_ns = start.elapsed().as_nanos();
                assert_eq!(root, expected);
                if round == 0 {
                    cold[arm].push(elapsed_ns);
                } else {
                    warm[arm].push(elapsed_ns);
                }
                write(
                    &mut output,
                    serde_json::json!({
                        "kind":"root", "accounts":count, "arm":arm, "instance":instance,
                        "round":round, "temperature":if round == 0 { "cold" } else { "warm" },
                        "root":hex::encode(root), "elapsed_ns":elapsed_ns, "thread_cpu_ns":thread_cpu_ns,
                        "retained_account_rows":values.len()
                    }),
                );
            }
        }
        for arm in 0..2 {
            warm[arm].sort_unstable();
            assert_eq!(warm[arm].len(), 100);
            write(
                &mut output,
                serde_json::json!({
                    "kind":"summary", "accounts":count, "arm":arm,
                    "cold_elapsed_ns":cold[arm], "warm_samples":warm[arm].len(),
                    "warm_p50_ns":warm[arm][49], "warm_p99_ns":warm[arm][98], "warm_max_ns":warm[arm][99],
                    "quantile_scope":"descriptive nearest rank on this shared process; no independent-host interval"
                }),
            );
        }
    }
}
