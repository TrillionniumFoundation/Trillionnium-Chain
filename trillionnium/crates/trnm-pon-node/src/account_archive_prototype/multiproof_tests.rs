use super::*;
use crate::account_archive_prototype::{account_root, CheckedAccounts, Limits, MAX_WITNESS_BYTES};
use serde_json::json;
use std::sync::atomic::{AtomicUsize, Ordering};
use trnm_mvcc_fee::pon_executor::{self, State};

fn owner(number: u64) -> Hash {
    let mut owner = [0; 32];
    owner[..8].copy_from_slice(&number.to_le_bytes());
    owner
}
fn context() -> Context {
    Context {
        network: [1; 32],
        parameters: [2; 32],
        genesis: [3; 32],
    }
}
fn fixture(
    count: usize,
) -> (
    tempfile::TempDir,
    AccountArchive,
    Checkpoint,
    BTreeMap<Hash, Account>,
) {
    let dir = tempfile::tempdir().unwrap();
    let values: BTreeMap<_, _> = (0..count)
        .map(|i| {
            (
                owner(i as u64),
                Account {
                    balance: i as u64 * 17,
                    nonce: i as u64 + 1,
                },
            )
        })
        .collect();
    let state: State = values
        .iter()
        .map(|(owner, account)| (format!("account:{}", hex::encode(owner)), json!(account)))
        .collect();
    let mut archive = AccountArchive::open(
        &dir.path().join("account.sqlite"),
        context(),
        Limits::default(),
    )
    .unwrap();
    let checkpoint = archive
        .project_initial(&state, pon_executor::root(&state).unwrap())
        .unwrap();
    (dir, archive, checkpoint, values)
}

#[test]
fn compact_queries_match_scalar_witnesses_absence_and_preserve_aaw1() {
    let (_dir, archive, checkpoint, values) = fixture(96);
    let requested: Vec<_> = (0..160).filter(|i| i % 3 == 0).map(owner).collect();
    let scalar: Vec<_> = requested
        .iter()
        .map(|&owner| archive.witness(checkpoint.id(), owner).unwrap().0)
        .collect();
    let scalar_bytes: Vec<_> = scalar.iter().map(|proof| proof.encode().unwrap()).collect();
    let (proof, observation) = archive.multiproof(checkpoint.id(), &requested).unwrap();
    let encoded = proof.encode().unwrap();
    assert_eq!(Multiproof::decode(&encoded).unwrap(), proof);
    let checked = CheckedMultiproof::verify(context(), &checkpoint, &proof).unwrap();
    assert_eq!(checked.checkpoint(), checkpoint.id());
    assert_eq!(checked.len(), requested.len());
    assert_eq!(observation.proof.encoded_bytes, encoded.len());
    assert!(encoded.len() * 20 < scalar_bytes.iter().map(Vec::len).sum::<usize>());
    assert_eq!(observation.expanded_witnesses_allocated, 0);
    assert!(
        observation.proof.retained_tree_nodes < 2 * (proof.accounts.len() + proof.frontier.len())
    );
    for batch in scalar.chunks(32) {
        let owners: Vec<_> = batch.iter().map(|proof| proof.owner).collect();
        let old = CheckedAccounts::verify(context(), &checkpoint, &owners, batch).unwrap();
        for owner in owners {
            assert_eq!(old.account(owner).unwrap(), checked.account(owner).unwrap());
            assert_eq!(checked.account(owner).unwrap(), values.get(&owner).copied());
        }
    }
    let reversed: Vec<_> = requested.iter().copied().rev().collect();
    assert_eq!(
        archive
            .multiproof(checkpoint.id(), &reversed)
            .unwrap()
            .0
            .encode()
            .unwrap(),
        encoded
    );
    assert_eq!(
        scalar
            .iter()
            .map(|proof| proof.encode().unwrap())
            .collect::<Vec<_>>(),
        scalar_bytes
    );
    assert!(matches!(
        CheckedAccounts::verify(context(), &checkpoint, &requested, &scalar),
        Err(ArchiveError::Budget)
    ));
    assert_eq!(
        checked.account(owner(1000)),
        Err(ArchiveError::MissingWitness)
    );
}

#[test]
fn compact_updates_rehash_changed_edges_and_match_complete_state_reference() {
    let (_dir, archive, checkpoint, mut values) = fixture(64);
    let requested: Vec<_> = (0..80).map(owner).collect();
    let proof = archive.multiproof(checkpoint.id(), &requested).unwrap().0;
    let checked = CheckedMultiproof::verify(context(), &checkpoint, &proof).unwrap();
    let no_change = checked
        .root_for_updates(&[], &|_| Ok::<_, ArchiveError>(()))
        .unwrap();
    assert_eq!(no_change.0, checkpoint.account_root());
    assert_eq!(no_change.1.branch_hashes, 0);
    let mut updates: Vec<_> = [0, 7, 32, 70]
        .map(|i| ResearchUpdate {
            owner: owner(i),
            before: values.get(&owner(i)).copied(),
            after: Account {
                balance: 0,
                nonce: i + 2,
            },
        })
        .into_iter()
        .collect();
    updates.sort_unstable_by_key(|update| update.owner);
    for update in &updates {
        values.insert(update.owner, update.after);
    }
    let (root, observation) = checked
        .root_for_updates(&updates, &|_| Ok::<_, ArchiveError>(()))
        .unwrap();
    assert_eq!(root, account_root(&values).unwrap());
    assert_eq!(observation.changed_accounts, 4);
    assert!(observation.branch_hashes < checked.observation().verification_branch_hashes);
    // Original checked bytes remain usable for a second distinct parent-relative
    // update. Mandatory execution never replaces the base of final execution.
    let single = ResearchUpdate {
        owner: owner(1),
        before: checked.account(owner(1)).unwrap(),
        after: Account {
            balance: u64::MAX,
            nonce: 3,
        },
    };
    let (_, archive2, checkpoint2, mut old) = fixture(64);
    old.insert(single.owner, single.after);
    assert_eq!(
        checked
            .root_for_updates(&[single], &|_| Ok::<_, ArchiveError>(()))
            .unwrap()
            .0,
        account_root(&old).unwrap()
    );
    assert_eq!(
        archive2
            .checkpoint(checkpoint2.id())
            .unwrap()
            .account_root(),
        checkpoint.account_root()
    );
    let mut wrong = updates.clone();
    wrong[0].before = None;
    assert!(matches!(
        checked.root_for_updates(&wrong, &|_| Ok::<_, ArchiveError>(())),
        Err(ArchiveError::InvalidTransition)
    ));
    let mut duplicate = updates.clone();
    duplicate.insert(1, duplicate[0]);
    assert!(matches!(
        checked.root_for_updates(&duplicate, &|_| Ok::<_, ArchiveError>(())),
        Err(ArchiveError::InvalidTransition)
    ));
    let rewind = ResearchUpdate {
        owner: owner(7),
        before: checked.account(owner(7)).unwrap(),
        after: Account {
            balance: 0,
            nonce: 1,
        },
    };
    assert!(matches!(
        checked.root_for_updates(&[rewind], &|_| Ok::<_, ArchiveError>(())),
        Err(ArchiveError::InvalidTransition)
    ));
}

#[test]
fn compact_canonical_parser_rejects_redundant_missing_overlapping_and_forged_nodes() {
    let (_dir, archive, checkpoint, _) = fixture(64);
    let proof = archive
        .multiproof(checkpoint.id(), &[owner(0), owner(1), owner(100)])
        .unwrap()
        .0;
    assert!(proof.frontier.len() >= 2);
    let mut invalid = Vec::new();
    let mut item = proof.clone();
    item.checkpoint[0] ^= 1;
    invalid.push(item);
    let mut item = proof.clone();
    item.accounts.swap(0, 1);
    invalid.push(item);
    let mut item = proof.clone();
    item.accounts.insert(1, item.accounts[0].clone());
    invalid.push(item);
    let mut item = proof.clone();
    item.accounts[0].account = Some(Account {
        balance: 99,
        nonce: 2,
    });
    invalid.push(item);
    let mut item = proof.clone();
    item.frontier.swap(0, 1);
    invalid.push(item);
    let mut item = proof.clone();
    item.frontier.insert(1, item.frontier[0].clone());
    invalid.push(item);
    let mut item = proof.clone();
    item.frontier.remove(0);
    invalid.push(item);
    let mut item = proof.clone();
    item.frontier[0].digest[0] ^= 1;
    invalid.push(item);
    let mut item = proof.clone();
    item.frontier[0].depth = 0;
    invalid.push(item);
    let mut item = proof.clone();
    item.frontier[0].depth = 257;
    invalid.push(item);
    let mut item = proof.clone();
    item.frontier[0].prefix[31] |= 1;
    invalid.push(item);
    let mut item = proof.clone();
    item.frontier[0].digest = empty_hashes()[usize::from(item.frontier[0].depth)];
    invalid.push(item);
    let mut item = proof.clone();
    item.frontier[0].depth += 1;
    invalid.push(item);
    let mut item = proof.clone();
    item.frontier.push(FrontierNode {
        depth: 256,
        prefix: path(item.accounts[0].owner),
        digest: [99; 32],
    });
    item.frontier.sort_unstable_by_key(|node| node.prefix);
    invalid.push(item);
    let mut item = proof.clone();
    let mut nested = item.frontier[0].clone();
    nested.depth += 1;
    item.frontier.push(nested);
    item.frontier.sort_unstable_by_key(|node| node.prefix);
    invalid.push(item);
    for item in invalid {
        assert!(CheckedMultiproof::verify(context(), &checkpoint, &item).is_err());
    }
    let bytes = proof.encode().unwrap();
    for length in [0, 3, 35, 43, 44, bytes.len() - 1] {
        assert!(Multiproof::decode(&bytes[..length]).is_err());
    }
    let mut extra = bytes.clone();
    extra.push(0);
    assert!(Multiproof::decode(&extra).is_err());
    let mut flag = bytes.clone();
    flag[44 + 32] = 2;
    assert!(Multiproof::decode(&flag).is_err());
    let mut counts = bytes.clone();
    counts[36..40].copy_from_slice(&u32::MAX.to_le_bytes());
    assert_eq!(Multiproof::decode(&counts), Err(ArchiveError::Budget));
    let mut old_magic = bytes;
    old_magic[..4].copy_from_slice(b"AAW1");
    assert!(Multiproof::decode(&old_magic).is_err());
    let mut wrong_context = context();
    wrong_context.parameters[0] ^= 1;
    assert!(matches!(
        CheckedMultiproof::verify(wrong_context, &checkpoint, &proof),
        Err(ArchiveError::Context)
    ));
    assert!(archive
        .multiproof(checkpoint.id(), &[owner(1), owner(1)])
        .is_err());
}

#[test]
fn compact_empty_queries_and_empty_trees_keep_checkpoint_and_absence_distinct() {
    for count in [0, 1, 32] {
        let (_dir, archive, checkpoint, _) = fixture(count);
        let (proof, observation) = archive.multiproof(checkpoint.id(), &[]).unwrap();
        assert!(proof.frontier.is_empty());
        assert!(proof.accounts.is_empty());
        assert_eq!(observation.archive_point_reads, 0);
        assert_eq!(proof.encode().unwrap().len(), HEADER_BYTES);
        let checked = CheckedMultiproof::verify(context(), &checkpoint, &proof).unwrap();
        assert!(checked.is_empty());
        let attempted = ResearchUpdate {
            owner: owner(999),
            before: None,
            after: Account {
                balance: 0,
                nonce: 0,
            },
        };
        assert!(matches!(
            checked.root_for_updates(&[attempted], &|_| Ok::<_, ArchiveError>(())),
            Err(ArchiveError::Budget),
        ));
        let mut wrong_context = context();
        wrong_context.genesis[0] ^= 1;
        assert!(matches!(
            CheckedMultiproof::verify(wrong_context, &checkpoint, &proof),
            Err(ArchiveError::Context)
        ));
        let mut wrong_checkpoint = proof.clone();
        wrong_checkpoint.checkpoint[0] ^= 1;
        assert!(CheckedMultiproof::verify(context(), &checkpoint, &wrong_checkpoint).is_err());
        assert_eq!(
            checked
                .root_for_updates(&[], &|_| Ok::<_, ArchiveError>(()))
                .unwrap()
                .0,
            checkpoint.account_root()
        );
        let query = archive
            .multiproof(checkpoint.id(), &[owner(999)])
            .unwrap()
            .0;
        let checked = CheckedMultiproof::verify(context(), &checkpoint, &query).unwrap();
        assert_eq!(checked.account(owner(999)).unwrap(), None);
        let mut extra = proof.clone();
        extra.frontier.push(FrontierNode {
            depth: 1,
            prefix: [0; 32],
            digest: [7; 32],
        });
        assert!(CheckedMultiproof::verify(context(), &checkpoint, &extra).is_err());
    }
}

#[test]
fn compact_verification_update_and_direct_archive_read_are_cancellable() {
    let (_dir, archive, checkpoint, _) = fixture(32);
    let requested: Vec<_> = (0..40).map(owner).collect();
    let proof = archive.multiproof(checkpoint.id(), &requested).unwrap().0;
    let checked = CheckedMultiproof::verify(context(), &checkpoint, &proof).unwrap();
    for stop in [
        MultiproofProgress::BeforeVerification,
        MultiproofProgress::Account { index: 33 },
        MultiproofProgress::BeforeOutput,
    ] {
        assert!(matches!(
            CheckedMultiproof::verify_with_progress(context(), &checkpoint, &proof, &|point| {
                if point == stop {
                    Err(ArchiveError::Cancelled)
                } else {
                    Ok(())
                }
            }),
            Err(ArchiveError::Cancelled)
        ));
    }
    let reads = AtomicUsize::new(0);
    assert!(matches!(
        archive.multiproof_with_progress(checkpoint.id(), &requested, &|point| {
            if matches!(point, MultiproofProgress::ArchiveRead { .. })
                && reads.fetch_add(1, Ordering::SeqCst) == 3
            {
                Err(ArchiveError::Cancelled)
            } else {
                Ok(())
            }
        }),
        Err(ArchiveError::Cancelled)
    ));
    let update = ResearchUpdate {
        owner: owner(7),
        before: checked.account(owner(7)).unwrap(),
        after: Account {
            balance: 0,
            nonce: 9,
        },
    };
    for stop in [
        MultiproofProgress::Update { index: 0 },
        MultiproofProgress::BeforeOutput,
    ] {
        assert!(matches!(
            checked.root_for_updates(&[update], &|point| {
                if point == stop {
                    Err(ArchiveError::Cancelled)
                } else {
                    Ok(())
                }
            }),
            Err(ArchiveError::Cancelled)
        ));
    }
    assert!(matches!(
        checked.root_for_updates(&[update], &|point| {
            if matches!(point, MultiproofProgress::Hash { .. }) {
                Err(ArchiveError::Cancelled)
            } else {
                Ok(())
            }
        }),
        Err(ArchiveError::Cancelled)
    ));
    assert_eq!(
        archive.checkpoint(checkpoint.id()).unwrap().account_root(),
        checkpoint.account_root()
    );
}

#[test]
fn compact_wire_budget_is_finite_and_missing_archive_nodes_are_not_absence() {
    assert_eq!(MAX_ENCODED_BYTES, 7_561_821);
    const { assert!(MAX_ENCODED_BYTES * 70 < MAX_ACCOUNTS * MAX_WITNESS_BYTES) };
    let (dir, archive, checkpoint, _) = fixture(4);
    let db = Connection::open(dir.path().join("account.sqlite")).unwrap();
    db.execute("DELETE FROM archive_nodes", []).unwrap();
    assert!(matches!(
        archive.multiproof(checkpoint.id(), &[owner(0)]),
        Err(ArchiveError::DataUnavailable)
    ));
}
