//! Filesystem/transaction mechanics only. The substituted authority is cfg(test),
//! not a real signed external service or a production launch qualification.
use super::frontier::{Digest32, ExternalM15Authority, Frontier, Result, Validity};
use super::transaction::TransactionStore;
use super::transaction_faults;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

const NS: Digest32 = [9; 32];
const OLD: &[u8] = b"{\"schema_version\":1,\"value\":1}";
const NEXT: &[u8] = b"{\"schema_version\":1,\"value\":2}";
const WINDOW: Validity = Validity {
    not_before: 10,
    expires_at: 100,
};

#[derive(Default)]
struct FixtureAuthority {
    head: Option<Frontier>,
    calls: usize,
    loads: usize,
    on_load: Option<(usize, Box<dyn FnOnce()>)>,
    on_cas: Option<Box<dyn FnOnce()>>,
    on_clock: Option<Box<dyn FnOnce()>>,
    cas_error: Option<bool>,
}

impl ExternalM15Authority for FixtureAuthority {
    fn now_seconds(&mut self) -> Result<u64> {
        if let Some(action) = self.on_clock.take() {
            action();
        }
        Ok(20)
    }
    fn load(&mut self, _: Digest32) -> Result<Option<Frontier>> {
        self.loads += 1;
        if self
            .on_load
            .as_ref()
            .is_some_and(|(at, _)| *at == self.loads)
        {
            let (_, action) = self.on_load.take().unwrap();
            action();
        }
        Ok(self.head.clone())
    }
    fn compare_and_set(
        &mut self,
        expected: Option<&Frontier>,
        next: &Frontier,
        validity: Validity,
    ) -> Result<()> {
        self.calls += 1;
        validity.check(20)?;
        if self.head.as_ref() != expected {
            return Err(io::Error::other("fixture exact CAS conflict"));
        }
        if self.cas_error != Some(false) {
            self.head = Some(next.clone());
        }
        if let Some(action) = self.on_cas.take() {
            action();
        }
        if self.cas_error.take().is_some() {
            return Err(io::Error::other("fixture lost CAS reply"));
        }
        Ok(())
    }
}

fn seeded() -> (
    tempfile::TempDir,
    PathBuf,
    TransactionStore,
    FixtureAuthority,
) {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap().join("owner");
    let mut authority = FixtureAuthority::default();
    let mut store = TransactionStore::initialize(&root, NS, &mut authority).unwrap();
    store
        .commit(&mut authority, OLD, WINDOW, |_, _| Ok(()))
        .unwrap();
    (temp, root, store, authority)
}

fn overwrite(root: &Path, name: &str, raw: &[u8]) {
    let mut file = OpenOptions::new()
        .write(true)
        .truncate(true)
        .create(true)
        .mode(0o600)
        .open(root.join(name))
        .unwrap();
    file.write_all(raw).unwrap();
    file.sync_all().unwrap();
    fs::File::open(root).unwrap().sync_all().unwrap();
}

#[test]
fn first_verification_cannot_overwrite_a_new_pending_record_or_return_idempotent_success() {
    for next in [OLD, NEXT] {
        let (_temp, root, mut store, mut authority) = seeded();
        let calls = authority.calls;
        let mut count = 0;
        let result = store.commit(&mut authority, next, WINDOW, |_, _| {
            count += 1;
            if count == 1 {
                overwrite(&root, "pending.json", b"{\"foreign\":1}");
            }
            Ok(())
        });
        assert!(result.is_err());
        assert!(store.snapshot().is_err());
        assert_eq!(authority.calls, calls);
        assert_eq!(
            fs::read(root.join("pending.json")).unwrap(),
            b"{\"foreign\":1}"
        );
        assert_eq!(fs::read(root.join("index.json")).unwrap(), OLD);
    }
}

#[test]
fn second_verification_cannot_cas_after_lock_proposal_attempt_or_index_replacement() {
    for name in ["owner.lock", "pending.json", "attempt.json", "index.json"] {
        let (_temp, root, mut store, mut authority) = seeded();
        let head = authority.head.clone();
        let calls = authority.calls;
        let mut count = 0;
        assert!(store
            .commit(&mut authority, NEXT, WINDOW, |_, _| {
                count += 1;
                if count == 2 {
                    if name == "owner.lock" {
                        fs::rename(root.join(name), root.join("retained-old.lock"))?;
                    }
                    overwrite(&root, name, b"foreign");
                }
                Ok(())
            })
            .is_err());
        assert_eq!(count, 2);
        assert_eq!(authority.calls, calls);
        assert_eq!(authority.head, head);
        assert!(store.snapshot().is_err());
        assert_eq!(fs::read(root.join(name)).unwrap(), b"foreign");
    }
}

#[test]
fn final_external_load_cannot_move_the_lock_before_cas() {
    let (_temp, root, mut store, mut authority) = seeded();
    let calls = authority.calls;
    let target = root.clone();
    // commit's initial recheck, post-verifier recheck, then last pre-CAS load.
    authority.on_load = Some((
        authority.loads + 3,
        Box::new(move || {
            fs::rename(target.join("owner.lock"), target.join("retained-old.lock")).unwrap();
            overwrite(&target, "owner.lock", b"foreign");
        }),
    ));
    assert!(store
        .commit(&mut authority, NEXT, WINDOW, |_, _| Ok(()))
        .is_err());
    assert_eq!(authority.calls, calls);
    assert!(store.snapshot().is_err());
    assert_ne!(fs::read(root.join("pending.json")).unwrap(), b"null");
    assert_ne!(fs::read(root.join("attempt.json")).unwrap(), b"null");
}

#[test]
fn known_external_winner_cannot_tombstone_a_different_retained_local_record() {
    for name in ["pending.json", "attempt.json"] {
        let (_temp, root, mut store, mut authority) = seeded();
        let target = root.clone();
        let calls = authority.calls;
        authority.on_cas = Some(Box::new(move || overwrite(&target, name, b"foreign")));
        assert!(store
            .commit(&mut authority, NEXT, WINDOW, |_, _| Ok(()))
            .is_err());
        assert_eq!(authority.calls, calls + 1);
        assert!(store.snapshot().is_err());
        assert_eq!(fs::read(root.join(name)).unwrap(), b"foreign");
        assert_eq!(fs::read(root.join("index.json")).unwrap(), OLD);
        drop(store);
        assert!(TransactionStore::open_existing(&root, NS, &mut authority).is_err());
        assert_eq!(authority.calls, calls + 1);
    }
}

#[test]
fn actual_fsync_cuts_preserve_unknown_and_only_cleanup_an_exact_external_winner() {
    for (name, tombstone, committed) in [
        ("pending.json", false, false),
        ("attempt.json", false, false),
        ("index.json", false, true),
        ("attempt.json", true, true),
        ("pending.json", true, true),
    ] {
        let (_temp, root, mut store, mut authority) = seeded();
        let calls = authority.calls;
        transaction_faults::cut_once(name, tombstone);
        assert!(store
            .commit(&mut authority, NEXT, WINDOW, |_, _| Ok(()))
            .is_err());
        assert!(store.snapshot().is_err());
        drop(store);
        let cold = TransactionStore::open_existing(&root, NS, &mut authority);
        assert_eq!(cold.is_ok(), committed);
        assert_eq!(authority.calls, calls + usize::from(committed));
        if let Ok(cold) = cold {
            assert_eq!(cold.snapshot().unwrap().1, Some(NEXT));
            assert_eq!(fs::read(root.join("pending.json")).unwrap(), b"null");
            assert_eq!(fs::read(root.join("attempt.json")).unwrap(), b"null");
        }
    }
}

#[test]
fn cas_error_and_reply_loss_never_cause_an_automatic_cold_retry() {
    for committed in [false, true] {
        let (_temp, root, mut store, mut authority) = seeded();
        let calls = authority.calls;
        authority.cas_error = Some(committed);
        assert!(store
            .commit(&mut authority, NEXT, WINDOW, |_, _| Ok(()))
            .is_err());
        assert!(store.snapshot().is_err());
        drop(store);
        assert_eq!(
            TransactionStore::open_existing(&root, NS, &mut authority).is_ok(),
            committed
        );
        assert_eq!(authority.calls, calls + 1);
    }
}

#[test]
fn whole_local_slot_rollback_is_rejected_against_the_retained_external_frontier() {
    let (_temp, root, mut store, mut authority) = seeded();
    let names = ["index.json", "pending.json", "attempt.json"];
    let old = names.map(|name| fs::read(root.join(name)).unwrap());
    store
        .commit(&mut authority, NEXT, WINDOW, |_, _| Ok(()))
        .unwrap();
    let external = authority.head.clone();
    let calls = authority.calls;
    drop(store);
    for (name, bytes) in names.iter().zip(&old) {
        overwrite(&root, name, bytes);
    }
    assert!(TransactionStore::open_existing(&root, NS, &mut authority).is_err());
    assert_eq!(authority.head, external);
    assert_eq!(authority.calls, calls);
    for (name, bytes) in names.iter().zip(&old) {
        assert_eq!(&fs::read(root.join(name)).unwrap(), bytes);
    }
}

#[test]
fn rollback_after_index_fsync_keeps_the_attempt_for_completed_only_cold_recovery() {
    let (_temp, root, mut store, mut authority) = seeded();
    let calls = authority.calls;
    let target = root.clone();
    transaction_faults::after_write_once("index.json", move || {
        overwrite(&target, "index.json", OLD)
    });
    assert!(store
        .commit(&mut authority, NEXT, WINDOW, |_, _| Ok(()))
        .is_err());
    assert!(store.snapshot().is_err());
    assert_eq!(authority.calls, calls + 1);
    assert_eq!(fs::read(root.join("index.json")).unwrap(), OLD);
    let retained_pending = fs::read(root.join("pending.json")).unwrap();
    let retained_attempt = fs::read(root.join("attempt.json")).unwrap();
    assert_ne!(retained_pending, b"null");
    assert_ne!(retained_attempt, b"null");
    let actual: Option<Digest32> = serde_json::from_slice(&retained_attempt).unwrap();
    assert_eq!(
        actual,
        Some(super::frontier::hash(
            b"TRNM/M15/OwnerAttempt/v1\0",
            &retained_pending
        ))
    );
    drop(store);
    let cold = TransactionStore::open_existing(&root, NS, &mut authority).unwrap();
    assert_eq!(cold.snapshot().unwrap().1, Some(NEXT));
    assert_eq!(authority.calls, calls + 1);
    assert_eq!(fs::read(root.join("pending.json")).unwrap(), b"null");
    assert_eq!(fs::read(root.join("attempt.json")).unwrap(), b"null");
}

#[test]
fn final_clock_cannot_admit_an_action_after_local_lock_or_index_replacement() {
    // Calls the same final-clock helper used by Owner::reload/revalidate_current.
    // This is a real file fault with a test clock, not a signed-service/Node test.
    for name in ["owner.lock", "index.json"] {
        let (_temp, root, mut store, mut authority) = seeded();
        store.recheck(&mut authority).unwrap();
        let target = root.clone();
        let calls = authority.calls;
        authority.on_clock = Some(Box::new(move || {
            if name == "owner.lock" {
                fs::rename(target.join(name), target.join("retained-old.lock")).unwrap();
            }
            overwrite(&target, name, b"foreign-after-final-clock");
        }));
        let mut effects = 0;
        let result =
            super::owner::checked_time(&mut store, &mut authority, || Ok(())).map(|_| effects += 1);
        assert!(result.is_err());
        assert_eq!(effects, 0);
        assert!(store.snapshot().is_err());
        assert!(store.recheck(&mut authority).is_err());
        assert_eq!(authority.calls, calls);
        assert_eq!(
            fs::read(root.join(name)).unwrap(),
            b"foreign-after-final-clock"
        );
    }
}
