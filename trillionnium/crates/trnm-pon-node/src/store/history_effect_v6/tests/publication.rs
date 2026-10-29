//! The hook exists only in the Linux native test executable. It parks at an
//! actual original publication syscall boundary; an external guardian owns the
//! kill/wait4, and the disclosed outside fixture separately signs exact bytes.
use super::*;
use journal::publication::Authorization;
use std::cell::RefCell;

thread_local! {
    static HOOK: RefCell<Option<(String, PathBuf)>> = const { RefCell::new(None) };
}
pub(in crate::store::history_effect_v6) fn install_hook(mode: &str, control: &Path) {
    if mode.starts_with("publication-")
        || mode.starts_with("epoch-recovery-publish-")
        || mode.starts_with("startup-no-native-publish-")
        || mode.starts_with("reorg-publish-")
        || mode.starts_with("lifecycle-publish-")
        || mode.starts_with("reorg-repair-")
    {
        HOOK.with(|slot| *slot.borrow_mut() = Some((mode.into(), control.into())));
    }
}
pub(in crate::store::history_effect_v6) fn append_cut(
    journal: &journal::Journal,
    frame: &journal::Frame,
    raw: &[u8],
    stage: &str,
) {
    let hook = HOOK.with(|slot| slot.borrow().clone());
    let Some((mode, control)) = hook else {
        return;
    };
    if mode == format!("lifecycle-publish-{stage}") {
        if let journal::Event::LifecycleReconciledV1 { signed, .. } = &frame.event {
            write_value(
                &control.join("crash-ready.json"),
                &json!({
                    "schema":"actual-history-lifecycle-barrier-v1",
                    "pid":std::process::id(),"cutpoint":mode,"publication_stage":stage,
                    "anchor":Anchor{sequence:frame.sequence,digest:policy::digest(raw)},
                    "acknowledged_prefix_anchor":journal.anchor(),"frame_bytes":raw.len(),
                    "signed_lifecycle_sha256":policy::digest(signed),
                    "native_operation_started":false,"cpu_epoch_created":false,
                    "recovery_receipt_created":false,
                }),
            );
            loop {
                std::thread::park_timeout(Duration::from_secs(5));
            }
        }
        return;
    }
    if mode == format!("reorg-publish-{stage}") {
        if let journal::Event::ReorgContinuationPreparedV1 { signed, .. } = &frame.event {
            write_value(
                &control.join("crash-ready.json"),
                &json!({
                    "schema":"actual-history-reorg-continuation-barrier-v1",
                    "pid":std::process::id(),"cutpoint":mode,"publication_stage":stage,
                    "anchor":Anchor{sequence:frame.sequence,digest:policy::digest(raw)},
                    "acknowledged_prefix_anchor":journal.anchor(),"frame_bytes":raw.len(),
                    "signed_reorg_continuation_sha256":policy::digest(signed),
                    "native_operation_started":false,"cpu_epoch_created":false,
                    "recovery_receipt_created":false,
                }),
            );
            loop {
                std::thread::park_timeout(Duration::from_secs(5));
            }
        }
        return;
    }
    if mode == format!("startup-no-native-publish-{stage}") {
        if let journal::Event::StartupNoNativeClosedV1 { signed, .. } = &frame.event {
            write_value(
                &control.join("crash-ready.json"),
                &json!({
                    "schema":"actual-history-startup-no-native-publication-barrier-v1",
                    "pid":std::process::id(),"cutpoint":mode,"publication_stage":stage,
                    "anchor":Anchor{sequence:frame.sequence,digest:policy::digest(raw)},
                    "acknowledged_prefix_anchor":journal.anchor(),"frame_bytes":raw.len(),
                    "signed_startup_closure_sha256":policy::digest(signed),
                    "native_operation_started":false,"cpu_epoch_created":false,
                    "recovery_receipt_created":false,
                }),
            );
            loop {
                std::thread::park_timeout(Duration::from_secs(5));
            }
        }
        return;
    }
    if mode == format!("epoch-recovery-publish-{stage}") {
        if let journal::Event::SettledEpochReconciledV1 { signed, .. } = &frame.event {
            write_value(
                &control.join("crash-ready.json"),
                &json!({
                    "schema":"actual-history-settled-epoch-publication-barrier-v1",
                    "pid":std::process::id(),"cutpoint":mode,"publication_stage":stage,
                    "anchor":Anchor{sequence:frame.sequence,digest:policy::digest(raw)},
                    "acknowledged_prefix_anchor":journal.anchor(),"frame_bytes":raw.len(),
                    "signed_epoch_recovery_sha256":policy::digest(signed),
                    "native_operation_started":false,"cpu_epoch_created":false,
                    "recovery_receipt_created":false,
                }),
            );
            loop {
                std::thread::park_timeout(Duration::from_secs(5));
            }
        }
        return;
    }
    if mode != format!("publication-intent-{stage}") {
        return;
    }
    let journal::Event::Intent { signed } = &frame.event else {
        return;
    };
    let verified = policy::operation(signed, journal.identity(), frame.at_ns).unwrap();
    if verified.body.purpose != Purpose::Validation {
        return;
    }
    let candidate = Anchor {
        sequence: frame.sequence,
        digest: policy::digest(raw),
    };
    write_value(
        &control.join("crash-ready.json"),
        &json!({
            "schema":"actual-history-effect-crash-barrier-v6",
            "pid":std::process::id(),"cutpoint":mode,"publication_stage":stage,
            "anchor":candidate,"acknowledged_prefix_anchor":journal.anchor(),
            "frame_bytes":raw.len(),"pending_operation":verified.body.operation_id,
            "intent_sha256":verified.intent_sha256,"epoch":verified.body.epoch,
            "actual_worker_thread":false,"native_operation_started":false,
            "candidate_anchor_requires_outside_publication_authorization":true,
            "clean_close_created":false,
        }),
    );
    loop {
        std::thread::park_timeout(Duration::from_secs(5));
    }
}
pub(in crate::store::history_effect_v6) fn repair_cut(signed: &[u8], stage: &str) {
    let hook = HOOK.with(|slot| slot.borrow().clone());
    let Some((mode, control)) = hook else {
        return;
    };
    if mode == format!("reorg-repair-{stage}") {
        write_value(
            &control.join("crash-ready.json"),
            &json!({
                "schema":"actual-history-reorg-continuation-barrier-v1",
                "pid":std::process::id(),"cutpoint":mode,
                "signed_publication_sha256":policy::digest(signed),
                "native_operation_started":false,"cpu_epoch_created":false,
                "recovery_receipt_created":false,
            }),
        );
        loop {
            std::thread::park_timeout(Duration::from_secs(5));
        }
    }
    if mode != format!("publication-repair-{stage}") {
        return;
    }
    write_value(
        &control.join("crash-ready.json"),
        &json!({
            "schema":"actual-history-publication-repair-crash-barrier-v1",
            "pid":std::process::id(),"cutpoint":mode,
            "signed_publication_sha256":policy::digest(signed),
            "native_operation_started":false,"cpu_epoch_created":false,
            "recovery_receipt_created":false,
        }),
    );
    loop {
        std::thread::park_timeout(Duration::from_secs(5));
    }
}
pub(in crate::store::history_effect_v6) fn repair_child(
    mode: &str,
    control: &Path,
    path: &Path,
    digest: &str,
) {
    install_hook(mode, control);
    let result = repair(path, digest);
    panic!("repair child returned without its selected actual crash barrier: {result:?}");
}
pub(in crate::store::history_effect_v6) fn envelope(body: &Authorization) -> Vec<u8> {
    let registry = signing_key_from_hex(&"11".repeat(32)).unwrap();
    let task = signing_key_from_hex(&"22".repeat(32)).unwrap();
    policy::encoded(&policy::Envelope {
        body,
        registry_signature: sign_hex(&registry, &journal::publication::message(1, body).unwrap()),
        task_signature: sign_hex(&task, &journal::publication::message(2, body).unwrap()),
    })
    .unwrap()
}
pub(in crate::store::history_effect_v6) fn input(
    a: &TestAuthority,
    label: &str,
    body: &Authorization,
    signed: &[u8],
    outside: Anchor,
) -> (PathBuf, String) {
    let config = json!({"schema":"restricted-history-journal-publication-input-v1",
        "identity":a.identity,"journal_path":a.journal,
        "outside_latest_anchor":outside,"signed_publication":signed});
    assert_eq!(body.identity, a.identity);
    let path = a.f.dir.path().join(format!("publication-{label}.json"));
    let digest = write_value(&path, &config);
    (path, digest)
}
pub(in crate::store::history_effect_v6) fn repair(path: &Path, digest: &str) -> Result<Value> {
    repair_history_journal_publication_v1(ProtectedHistoryJournalPublicationV1Input::load(
        path,
        rustix::process::geteuid().as_raw(),
        digest,
    )?)
}
fn files(path: &Path) -> BTreeMap<String, (u64, String)> {
    fs::read_dir(path)
        .unwrap()
        .map(|entry| {
            let entry = entry.unwrap();
            (
                entry.file_name().into_string().unwrap(),
                (
                    entry.metadata().unwrap().nlink(),
                    policy::digest(&fs::read(entry.path()).unwrap()),
                ),
            )
        })
        .collect()
}
pub(in crate::store::history_effect_v6) fn after_crash(
    a: &TestAuthority,
    control: &Path,
    barrier: &Value,
    expected_prefix: &Anchor,
) -> (PathBuf, String) {
    let candidate: Anchor = serde_json::from_value(barrier["anchor"].clone()).unwrap();
    assert_eq!(
        &serde_json::from_value::<Anchor>(barrier["acknowledged_prefix_anchor"].clone()).unwrap(),
        expected_prefix
    );
    assert_eq!(candidate.sequence, expected_prefix.sequence + 1);
    let pending = a
        .journal
        .join(format!("pending-{:020}", candidate.sequence));
    let final_path = a.journal.join(format!(
        "{:020}-{}.json",
        candidate.sequence, candidate.digest
    ));
    let raw = fs::read(if pending.exists() {
        &pending
    } else {
        &final_path
    })
    .unwrap();
    assert_eq!(policy::digest(&raw), candidate.digest);
    let now = policy::now().unwrap();
    let body = Authorization {
        schema: "restricted-history-journal-publication-authorization-v1".into(),
        identity: a.identity.clone(),
        prefix_anchor: expected_prefix.clone(),
        published_anchor: candidate.clone(),
        frame_sha256: policy::digest(&raw),
        frame_bytes: raw.len() as u64,
        issued_ns: now,
        expires_ns: now + 3_000_000_000_000,
    };
    let snapshot = files(&a.journal);
    // A fresh caller cannot silently promote a durable suffix with the old pin.
    let original_open = journal::Journal::open(
        &a.journal,
        rustix::process::geteuid().as_raw(),
        &a.identity,
        expected_prefix,
    );
    let original_error = original_open
        .err()
        .expect("old anchor unexpectedly promoted a tail")
        .to_string();
    assert_eq!(files(&a.journal), snapshot);
    let mut refusals = BTreeMap::new();
    for (label, signed, outside) in [
        ("wrong-domain", signed(b'P', &body), candidate.clone()),
        (
            "old-outside-anchor",
            envelope(&body),
            expected_prefix.clone(),
        ),
    ] {
        let (path, digest) = input(a, label, &body, &signed, outside);
        let error = repair(&path, &digest).unwrap_err().to_string();
        assert_eq!(files(&a.journal), snapshot);
        refusals.insert(label, error);
    }
    for (label, changed) in [
        ("wrong-prefix", {
            let mut c = body.clone();
            c.prefix_anchor.digest = "ab".repeat(32);
            c
        }),
        ("wrong-size", {
            let mut c = body.clone();
            c.frame_bytes += 1;
            c
        }),
        ("expired", {
            let mut c = body.clone();
            c.issued_ns = 0;
            c.expires_ns = 1;
            c
        }),
    ] {
        let (path, digest) = input(
            a,
            label,
            &changed,
            &envelope(&changed),
            changed.published_anchor.clone(),
        );
        let error = repair(&path, &digest).unwrap_err().to_string();
        assert_eq!(files(&a.journal), snapshot);
        refusals.insert(label, error);
    }
    let (path, digest) = input(a, "authorized", &body, &envelope(&body), candidate.clone());
    // Exercise the newly implemented repair itself, not only the old append.
    // These two owned processes create no native scope or V6 CPU receipt.
    if barrier["publication_stage"] == "file-synced" {
        process::repair_crash(a, "linked", &path, &digest, None);
        assert!(pending.exists() && final_path.exists());
        assert_eq!(
            fs::metadata(&pending).unwrap().ino(),
            fs::metadata(&final_path).unwrap().ino()
        );
        process::repair_crash(a, "unlinked", &path, &digest, None);
        assert!(!pending.exists() && final_path.exists());
        assert_eq!(fs::read(&final_path).unwrap(), raw);
    }
    let result = repair(&path, &digest).unwrap();
    assert_eq!(result["journal"]["anchor"], json!(candidate));
    assert_eq!(result["journal"]["spent"]["cpu_ns"], 8_000_000_000u64);
    assert_eq!(result["journal"]["used_operations"], 2);
    assert_eq!(result["journal"]["known_settlements"], 1);
    assert_eq!(result["journal"]["pending"], a.id(2));
    assert_eq!(result["native_effect_repeated"], false);
    assert_eq!(result["cpu_receipt_created"], false);
    assert_eq!(fs::read(&final_path).unwrap(), raw);
    assert!(!pending.exists());
    let repaired = files(&a.journal);
    let repeated = repair(&path, &digest).unwrap();
    assert_eq!(repeated["already_published"], true);
    assert_eq!(repeated["journal"], result["journal"]);
    assert_eq!(files(&a.journal), repaired);
    let journal = journal::Journal::open(
        &a.journal,
        rustix::process::geteuid().as_raw(),
        &a.identity,
        &candidate,
    )
    .unwrap();
    assert_eq!(journal.pending().unwrap().operation.operation_id, a.id(2));
    assert!(journal.pending().unwrap().observed_receipt.is_none());
    drop(journal);
    write_value(
        &control.join("publication-repair-result.json"),
        &json!({
            "schema":"actual-history-publication-repair-fixture-v1",
            "original_old_anchor_refusal":original_error,"refusals":refusals,
            "result":result,"idempotent_retry":repeated,
            "frame_bytes_unchanged":true,"original_unknown_split_kept":true,
            "outside_authorities_are_disclosed_fixture_keys":true,
        }),
    );
    (path, digest)
}
pub(in crate::store::history_effect_v6) fn rejects_after_advance(
    a: &TestAuthority,
    path: &Path,
    digest: &str,
) {
    let before = files(&a.journal);
    assert!(repair(path, digest).is_err());
    assert_eq!(files(&a.journal), before);
}

#[test]
fn original_frame_and_physical_tail_refusals_preserve_every_byte() {
    let mut a = TestAuthority::new();
    let original = a.journal.clone();
    let parent_rows: Vec<_> = fs::read_dir(&original)
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    let now = policy::now().unwrap();
    let old: policy::Envelope<policy::Budget> = serde_json::from_slice(&a.budget).unwrap();
    let mut budget = old.body;
    budget.sequence = 2;
    budget.outside_anchor = a.installed.clone();
    let labels = [
        "partial",
        "tampered",
        "noncanonical",
        "original-signature",
        "original-ceiling",
        "chain-previous",
        "chain-identity",
        "unexpected-tail",
        "external-hardlink",
        "distinct-two-files",
        "final-symlink",
        "missing-prefix",
        "unsafe-mode",
        "held-lock",
    ];
    let mut observations = Vec::new();
    for label in labels {
        a.journal = a.f.dir.path().join(format!("refusal-{label}"));
        fs::create_dir(&a.journal).unwrap();
        fs::set_permissions(&a.journal, fs::Permissions::from_mode(0o700)).unwrap();
        for source in &parent_rows {
            fs::copy(source, a.journal.join(source.file_name().unwrap())).unwrap();
        }
        let mut proposed = budget.clone();
        if label == "original-ceiling" {
            proposed.lifetime_ceiling.cpu_ns = 1;
        }
        let mut signed_budget = signed(b'B', &proposed);
        if label == "original-signature" {
            let mut envelope: Value = serde_json::from_slice(&signed_budget).unwrap();
            envelope["registry_signature"] = json!("00".repeat(64));
            signed_budget = policy::encoded(&envelope).unwrap();
        }
        let mut frame = journal::Frame {
            schema: "restricted-history-effect-record-v6".into(),
            identity_sha256: a.identity.digest().unwrap(),
            sequence: 2,
            previous: a.installed.digest.clone(),
            at_ns: now,
            event: journal::Event::Budget {
                signed: signed_budget,
            },
        };
        if label == "chain-previous" {
            frame.previous = "aa".repeat(32);
        }
        if label == "chain-identity" {
            frame.identity_sha256 = "bb".repeat(32);
        }
        let mut raw = policy::encoded(&frame).unwrap();
        if label == "partial" {
            raw.truncate(raw.len() / 2);
        }
        if label == "noncanonical" {
            raw.push(b'\n');
        }
        let digest = policy::digest(&raw);
        let pending = a.journal.join("pending-00000000000000000002");
        let final_path = a
            .journal
            .join(format!("00000000000000000002-{digest}.json"));
        write(&pending, &raw);
        match label {
            "unexpected-tail" => {
                write(&a.journal.join("unrelated-tail"), b"retained");
            }
            "external-hardlink" => {
                fs::hard_link(&pending, a.f.dir.path().join("external-link")).unwrap()
            }
            "distinct-two-files" => {
                write(&final_path, &raw);
            }
            "final-symlink" => std::os::unix::fs::symlink(&pending, &final_path).unwrap(),
            "missing-prefix" => {
                for path in &parent_rows {
                    if path.file_name().unwrap() != "owner.lock" {
                        fs::remove_file(a.journal.join(path.file_name().unwrap())).unwrap();
                    }
                }
            }
            "unsafe-mode" => {
                fs::set_permissions(&pending, fs::Permissions::from_mode(0o644)).unwrap()
            }
            _ => {}
        }
        let lock = if label == "held-lock" {
            let lock = OpenOptions::new()
                .read(true)
                .write(true)
                .open(a.journal.join("owner.lock"))
                .unwrap();
            lock.try_lock_exclusive().unwrap();
            Some(lock)
        } else {
            None
        };
        let body = Authorization {
            schema: "restricted-history-journal-publication-authorization-v1".into(),
            identity: a.identity.clone(),
            prefix_anchor: a.installed.clone(),
            published_anchor: Anchor {
                sequence: 2,
                digest: digest.clone(),
            },
            frame_sha256: digest,
            frame_bytes: raw.len() as u64,
            issued_ns: now,
            expires_ns: now + 3_000_000_000_000,
        };
        let (path, sha) = input(
            &a,
            label,
            &body,
            &envelope(&body),
            body.published_anchor.clone(),
        );
        if label == "tampered" {
            let mut changed = raw.clone();
            changed[0] = b'[';
            fs::write(&pending, changed).unwrap();
        }
        let snapshot = files(&a.journal);
        let error = repair(&path, &sha).expect_err(label).to_string();
        assert_eq!(files(&a.journal), snapshot, "{label}");
        observations.push(json!({"label":label,"error":error,"files_unchanged":true,"frame_sha256":body.frame_sha256}));
        drop(lock);
    }
    eprintln!(
        "HISTORY_PUBLICATION_REFUSALS {}",
        serde_json::to_string(&observations).unwrap()
    );
}
