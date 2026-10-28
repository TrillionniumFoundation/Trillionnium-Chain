//! A real fully settled activation is killed before clean close. Independent
//! fixture authorities acknowledge that exit; no unexecuted/mocked process
//! observation is used as the successful recovery case.
use super::*;
use epoch_recovery_v1::Authorization;

pub(super) fn barrier(
    owner: &HistoryEffectV6,
    signed_operation: &[u8],
    result: &HistoryEffectV6Result,
    control: &Path,
) -> ! {
    let op = policy::operation(
        signed_operation,
        &owner.owner.identity,
        policy::now().unwrap(),
    )
    .unwrap();
    let journal = owner.owner.journal().unwrap();
    assert!(journal.pending().is_none());
    assert!(result.known_success());
    assert_eq!(result.operation_id, op.body.operation_id);
    write_value(
        &control.join("crash-ready.json"),
        &json!({
            "schema":"actual-history-settled-epoch-crash-barrier-v1",
            "pid":std::process::id(),"cutpoint":"settled-epoch","anchor":journal.anchor(),
            "pending_operation":null,"last_settled_operation":op.body.operation_id,
            "intent_sha256":op.intent_sha256,"epoch":op.body.epoch,
            "original_known_settlement_preserved":true,"original_settlement":result,
            "clean_close_created":false,
        }),
    );
    drop(journal);
    loop {
        std::thread::park_timeout(Duration::from_secs(5));
    }
}

fn envelope(body: &Authorization) -> Vec<u8> {
    let registry = signing_key_from_hex(&"11".repeat(32)).unwrap();
    let task = signing_key_from_hex(&"22".repeat(32)).unwrap();
    policy::encoded(&policy::Envelope {
        body,
        registry_signature: sign_hex(&registry, &epoch_recovery_v1::message(1, body).unwrap()),
        task_signature: sign_hex(&task, &epoch_recovery_v1::message(2, body).unwrap()),
    })
    .unwrap()
}

pub(super) fn refused_frontier_barrier(
    owner: &HistoryEffectV6,
    signed_operation: &[u8],
    result: &HistoryEffectV6Result,
    control: &Path,
) -> ! {
    let op = policy::operation(
        signed_operation,
        &owner.owner.identity,
        policy::now().unwrap(),
    )
    .unwrap();
    checked(result, 0);
    assert!(!result.known_success());
    assert_eq!(
        result.native_error.as_deref(),
        Some("HISTORY_V6_OWNER_FRONTIER")
    );
    assert!(result.marker.is_none() && result.operation_closed);
    assert_ne!(actual(owner), op.body.owner_frontier);
    let journal = owner.owner.journal().unwrap();
    assert!(journal.pending().is_none());
    assert_eq!(result.operation_id, op.body.operation_id);
    write_value(
        &control.join("crash-ready.json"),
        &json!({
            "schema":"actual-history-settled-epoch-crash-barrier-v1",
            "pid":std::process::id(),"cutpoint":"settled-epoch-wrong-frontier",
            "anchor":journal.anchor(),"pending_operation":null,
            "last_settled_operation":op.body.operation_id,"intent_sha256":op.intent_sha256,
            "epoch":op.body.epoch,"requested_frontier":op.body.owner_frontier,
            "actual_frontier":actual(owner),"original_settlement":result,
            "original_known_settlement_preserved":true,"clean_close_created":false,
        }),
    );
    drop(journal);
    loop {
        std::thread::park_timeout(Duration::from_secs(5));
    }
}
fn configuration(
    a: &TestAuthority,
    label: &str,
    body: &Authorization,
    signed: Vec<u8>,
    raw: &[u8],
) -> (PathBuf, String) {
    let config = json!({
        "schema":"restricted-history-settled-epoch-input-v1", "identity":a.identity,
        "expected_source_commit":a.identity.source_commit,
        "expected_executable_sha256":process::sha_file(&std::env::current_exe().unwrap()),
        "journal_path":a.journal,"outside_latest_anchor":body.outside_anchor,
        "signed":signed,"closed_process":raw,
    });
    let path = a.f.dir.path().join(format!("epoch-recovery-{label}.json"));
    let digest = write_value(&path, &config);
    (path, digest)
}
pub(super) fn input(
    a: &TestAuthority,
    label: &str,
    raw: &[u8],
    operation: &str,
) -> (PathBuf, String) {
    let closed: policy::ClosedProcess = serde_json::from_slice(raw).unwrap();
    let budget: policy::Envelope<policy::Budget> = serde_json::from_slice(&a.budget).unwrap();
    let now = policy::now().unwrap();
    let body = Authorization {
        schema: "restricted-history-settled-epoch-authorization-v1".into(),
        identity: a.identity.clone(),
        executable_sha256: closed.executable_sha256.clone(),
        budget_id: budget.body.budget_id,
        reconciliation_id: a.id(10),
        request_nonce: 10,
        epoch: closed.epoch.clone(),
        outside_anchor: closed.original_journal.clone(),
        last_operation_id: operation.into(),
        last_intent_sha256: closed.intent_sha256.clone(),
        closed_process_sha256: policy::digest(raw),
        actual_frontier: closed.actual_frontier.clone(),
        allowance: Usage {
            cpu_ns: 4_000_000_000,
            material_bytes: 0,
            received_bytes: 0,
            operations: 1,
        },
        issued_ns: now,
        expires_ns: now + 3_000_000_000_000,
    };
    configuration(a, label, &body, envelope(&body), raw)
}
pub(super) fn refusals(
    a: &TestAuthority,
    path: &Path,
    sha: &str,
    reject: &impl Fn(&TestAuthority, &Path, &str) -> String,
) {
    let config = read(path);
    let signed: Vec<u8> = serde_json::from_value(config["signed"].clone()).unwrap();
    let raw: Vec<u8> = serde_json::from_value(config["closed_process"].clone()).unwrap();
    let envelope_body: policy::Envelope<Authorization> = serde_json::from_slice(&signed).unwrap();
    let body = envelope_body.body;
    let mut results = BTreeMap::new();
    let (p, s) = configuration(a, "old-domain", &body, super::signed(b'E', &body), &raw);
    results.insert("old-v6-signature-domain", reject(a, &p, &s));
    let mut one: Value = serde_json::from_slice(&signed).unwrap();
    one["task_signature"] = json!("00".repeat(64));
    let (p, s) = configuration(
        a,
        "missing-task-signature",
        &body,
        policy::encoded(&one).unwrap(),
        &raw,
    );
    results.insert("missing-task-signature", reject(a, &p, &s));
    let mut wrong_binary: policy::ClosedProcess = serde_json::from_slice(&raw).unwrap();
    wrong_binary.executable_sha256 = "ab".repeat(32);
    let wrong_raw = policy::encoded(&wrong_binary).unwrap();
    let mut wrong_body = body.clone();
    wrong_body.executable_sha256 = wrong_binary.executable_sha256.clone();
    wrong_body.closed_process_sha256 = policy::digest(&wrong_raw);
    let (p, s) = configuration(
        a,
        "resigned-wrong-binary",
        &wrong_body,
        envelope(&wrong_body),
        &wrong_raw,
    );
    let error = reject(a, &p, &s);
    assert!(error.contains("SOURCE_PIN"));
    results.insert("resigned-wrong-executable-pin", error);
    let mut wrong_source = config.clone();
    wrong_source["expected_source_commit"] = json!("ab".repeat(20));
    let source_path = a.f.dir.path().join("epoch-wrong-independent-source.json");
    let source_sha = write_value(&source_path, &wrong_source);
    let error = ProtectedHistorySettledEpochV1Input::load(
        &source_path,
        rustix::process::geteuid().as_raw(),
        &source_sha,
    )
    .err()
    .expect("wrong source pin accepted")
    .to_string();
    assert!(error.contains("SOURCE_PIN"));
    results.insert("wrong-independent-source-pin", error);
    let original_lock = a.journal.join("owner.lock");
    let retained_lock = a.f.dir.path().join("retained-journal-owner.lock");
    fs::rename(&original_lock, &retained_lock).unwrap();
    let error = reject(a, path, sha);
    assert!(
        !original_lock.exists(),
        "missing journal lock was silently recreated"
    );
    fs::rename(&retained_lock, &original_lock).unwrap();
    results.insert("missing-journal-lock-no-recreation", error);
    for (label, changed) in [
        ("reused-nonce", {
            let mut c = body.clone();
            c.request_nonce = 3;
            c
        }),
        ("reused-operation-id", {
            let mut c = body.clone();
            c.reconciliation_id = a.id(2);
            c
        }),
        ("wrong-budget", {
            let mut c = body.clone();
            c.budget_id = "aa".repeat(32);
            c
        }),
        ("wrong-last-settlement", {
            let mut c = body.clone();
            c.last_operation_id = a.id(2);
            c
        }),
        ("insufficient-process-allowance", {
            let mut c = body.clone();
            c.allowance.cpu_ns = 1;
            c
        }),
        ("lifetime-overdraft", {
            let mut c = body.clone();
            c.allowance.cpu_ns = 128_000_000_000;
            c
        }),
        ("wrong-operation-count", {
            let mut c = body.clone();
            c.allowance.operations = 0;
            c
        }),
        ("expired", {
            let mut c = body.clone();
            c.issued_ns = 0;
            c.expires_ns = 1;
            c
        }),
    ] {
        let (p, s) = configuration(a, label, &changed, envelope(&changed), &raw);
        results.insert(label, reject(a, &p, &s));
    }
    // Recovered runtime content must also agree; changing just SQLite cannot
    // be blessed by a correct receipt/journal pair or new signature.
    let native_copy = a.f.dir.path().join("epoch-native-mismatch");
    fs::create_dir(&native_copy).unwrap();
    fs::set_permissions(&native_copy, fs::Permissions::from_mode(0o700)).unwrap();
    for entry in fs::read_dir(&a.store).unwrap() {
        let entry = entry.unwrap();
        if entry.file_type().unwrap().is_file() {
            fs::copy(entry.path(), native_copy.join(entry.file_name())).unwrap();
        }
    }
    let db = Connection::open(native_copy.join("native.sqlite")).unwrap();
    db.execute("UPDATE active SET generation=generation+1", [])
        .unwrap();
    drop(db);
    let before = fs::read_dir(&a.journal).unwrap().count();
    let result = prepare_history_settled_epoch_v1_recovery(
        &native_copy,
        ProtectedHistorySettledEpochV1Input::load(path, rustix::process::geteuid().as_raw(), sha)
            .unwrap(),
    );
    let error = result.unwrap_err().to_string();
    assert!(error.contains("NATIVE_FRONTIER"), "{error}");
    assert_eq!(fs::read_dir(&a.journal).unwrap().count(), before);
    results.insert("sqlite-frontier-mismatch", error);
    write_value(
        &a.f.dir.path().join("settled-epoch-refusals.json"),
        &json!({
            "schema":"actual-history-settled-epoch-refusals-v1","refusals":results,
            "journal_unchanged":true,"outside_fixture_authorities_disclosed":true,
        }),
    );
}

#[test]
fn settled_activation_epoch_sigkill_requires_fresh_charge_then_resumes() {
    process::run("settled-epoch");
}

pub(super) fn publish_interrupted(
    a: &TestAuthority,
    stage: &str,
    path: &Path,
    sha: &str,
    closed_raw: &[u8],
) -> Value {
    let closed: policy::ClosedProcess = serde_json::from_slice(closed_raw).unwrap();
    // A complete original event must remain publishable after that event's
    // authorization expires. Only the new publication authorization is current.
    let expiring = (stage == "file-synced").then(|| {
        let config = read(path);
        let signed: Vec<u8> = serde_json::from_value(config["signed"].clone()).unwrap();
        let mut body: policy::Envelope<Authorization> = serde_json::from_slice(&signed).unwrap();
        body.body.issued_ns = policy::now().unwrap();
        body.body.expires_ns = body.body.issued_ns + 10_000_000_000;
        let (p, s) = configuration(
            a,
            "publication-expiring",
            &body.body,
            envelope(&body.body),
            closed_raw,
        );
        (p, s, body.body.expires_ns)
    });
    let (path, sha) = expiring
        .as_ref()
        .map_or((path, sha), |(p, s, _)| (p.as_path(), s.as_str()));
    let prior = {
        let journal = journal::Journal::open_existing(
            &a.journal,
            rustix::process::geteuid().as_raw(),
            &a.identity,
            &closed.original_journal,
        )
        .unwrap();
        assert!(journal.pending().is_none());
        journal.observation()
    };
    let barrier = process::epoch_recovery_crash(a, stage, path, sha);
    assert_eq!(
        barrier["acknowledged_prefix_anchor"],
        json!(closed.original_journal)
    );
    let candidate: Anchor = serde_json::from_value(barrier["anchor"].clone()).unwrap();
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
    let frame: journal::Frame = serde_json::from_slice(&raw).unwrap();
    assert_eq!(frame.schema, epoch_recovery_v1::RECORD_SCHEMA);
    let journal::Event::SettledEpochReconciledV1 {
        signed,
        closed_process,
    } = frame.event
    else {
        panic!("wrong interrupted event")
    };
    assert_eq!(closed_process, closed_raw);
    let original_config = read(path);
    assert_eq!(
        signed,
        serde_json::from_value::<Vec<u8>>(original_config["signed"].clone()).unwrap()
    );
    if let Some((_, _, expires)) = &expiring {
        assert!(frame.at_ns < *expires);
        let deadline = Instant::now() + Duration::from_secs(15);
        while policy::now().unwrap() < *expires {
            assert!(Instant::now() < deadline, "original event did not expire");
            std::thread::sleep(Duration::from_millis(25));
        }
    }
    let now = policy::now().unwrap();
    let authorization = journal::publication::Authorization {
        schema: "restricted-history-journal-publication-authorization-v1".into(),
        identity: a.identity.clone(),
        prefix_anchor: closed.original_journal.clone(),
        published_anchor: candidate.clone(),
        frame_sha256: policy::digest(&raw),
        frame_bytes: raw.len() as u64,
        issued_ns: now,
        expires_ns: now + 3_000_000_000_000,
    };
    let (pub_path, pub_sha) = publication::input(
        a,
        "settled-epoch-record",
        &authorization,
        &publication::envelope(&authorization),
        candidate.clone(),
    );
    let mut temporal_refusals = BTreeMap::new();
    if let Some((_, _, event_expires)) = &expiring {
        let uid = rustix::process::geteuid().as_raw();
        let mut expired = authorization.clone();
        expired.issued_ns = 0;
        expired.expires_ns = 1;
        let (p, s) = publication::input(
            a,
            "expired-new-publication",
            &expired,
            &publication::envelope(&expired),
            candidate.clone(),
        );
        let error = repair_history_settled_epoch_v1_publication(
            &a.store,
            ProtectedHistorySettledEpochV1Input::load(path, uid, sha).unwrap(),
            ProtectedHistoryJournalPublicationV1Input::load(&p, uid, &s).unwrap(),
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("PUBLICATION_AUTHORIZATION"));
        temporal_refusals.insert("expired-current-publication", error);
        for label in [
            "wrong-independent-binary",
            "different-original-signed-bytes",
        ] {
            let mut changed = original_config.clone();
            if label == "wrong-independent-binary" {
                changed["expected_executable_sha256"] = json!("ab".repeat(32));
            } else {
                let mut body: policy::Envelope<Authorization> =
                    serde_json::from_slice(&signed).unwrap();
                body.body.expires_ns += 1;
                changed["signed"] = json!(envelope(&body.body));
            }
            let p = a.f.dir.path().join(format!("publication-{label}.json"));
            let s = write_value(&p, &changed);
            let error = repair_history_settled_epoch_v1_publication(
                &a.store,
                ProtectedHistorySettledEpochV1Input::load(&p, uid, &s).unwrap(),
                ProtectedHistoryJournalPublicationV1Input::load(&pub_path, uid, &pub_sha).unwrap(),
            )
            .unwrap_err()
            .to_string();
            assert!(error.contains(if label == "wrong-independent-binary" {
                "SOURCE_PIN"
            } else {
                "PUBLICATION_BINDING"
            }));
            temporal_refusals.insert(label, error);
        }
        assert_eq!(fs::read(&pending).unwrap(), raw);
        assert!(!final_path.exists());
        write_value(
            &a.f.dir.path().join("expired-event-publication.json"),
            &json!({
                "original_frame_at_ns": frame.at_ns, "original_event_expires_ns": event_expires,
                "publication_observed_at_ns": now, "fresh_publication_issued_ns": authorization.issued_ns,
                "refusals": temporal_refusals, "original_pending_bytes_unchanged": true,
            }),
        );
    }
    if stage == "file-synced" {
        process::repair_crash(a, "linked", &pub_path, &pub_sha, Some((path, sha)));
        assert!(pending.exists() && final_path.exists());
        process::repair_crash(a, "unlinked", &pub_path, &pub_sha, Some((path, sha)));
        assert!(!pending.exists() && final_path.exists());
    }
    let generic_error = publication::repair(&pub_path, &pub_sha)
        .unwrap_err()
        .to_string();
    assert!(generic_error.contains("EPOCH_PINS_REQUIRED"));
    let pinned_repair = || {
        let uid = rustix::process::geteuid().as_raw();
        repair_history_settled_epoch_v1_publication(
            &a.store,
            ProtectedHistorySettledEpochV1Input::load(path, uid, sha).unwrap(),
            ProtectedHistoryJournalPublicationV1Input::load(&pub_path, uid, &pub_sha).unwrap(),
        )
    };
    let repaired = pinned_repair().unwrap();
    let repeated = pinned_repair().unwrap();
    assert_eq!(repaired["journal"], repeated["journal"]);
    assert_eq!(repeated["already_published"], true);
    assert_eq!(repaired["journal"]["spent"]["cpu_ns"], 16_000_000_000u64);
    assert_eq!(repaired["journal"]["known_settlements"], 3);
    assert_eq!(repaired["journal"]["settled_epoch_reconciliations_v1"], 1);
    assert_eq!(repaired["journal"]["pending"], Value::Null);
    assert_eq!(repaired["journal"]["epoch"], Value::Null);
    assert_eq!(fs::read(&final_path).unwrap(), raw);
    assert!(!pending.exists());
    let result = json!({
        "schema":"actual-history-settled-epoch-publication-restored-v1",
        "prior_journal":prior,"journal":repaired["journal"],
        "closed_process":closed,"original_settlements_preserved":true,
        "clean_close_fabricated":false,"exact_residual_cpu_claimed":false,
        "native_effect_repeated":false,"new_cpu_epoch_created":false,
        "additional_conservative_debit":{"cpu_ns":4_000_000_000u64,"material_bytes":0,"received_bytes":0,"operations":1},
        "barrier":barrier,"publication_repair":repaired,"idempotent_publication_retry":repeated,
        "generic_publication_bypass_refused":generic_error,
        "original_death_witness_unchanged":true,"administrative_wait4_used_as_original_receipt":false,
    });
    write_value(
        &a.f.dir.path().join("epoch-publication-recovery.json"),
        &result,
    );
    result
}

pub(super) fn wait_expired(a: &TestAuthority) {
    let budget: policy::Envelope<policy::Budget> = serde_json::from_slice(&a.budget).unwrap();
    let end = Instant::now() + Duration::from_secs(35);
    while policy::now().unwrap() < budget.body.expires_ns {
        assert!(
            Instant::now() < end,
            "original finite budget did not actually expire"
        );
        std::thread::sleep(Duration::from_millis(25));
    }
    write_value(
        &a.f.dir.path().join("old-budget-expired.json"),
        &json!({
            "schema":"actual-history-old-budget-expired-v1","expires_ns":budget.body.expires_ns,
            "observed_at_ns":policy::now().unwrap(),"new_run_authority_created":false,
        }),
    );
}

pub(super) fn renew_budget(a: &mut TestAuthority, anchor: Anchor) -> Anchor {
    let old: policy::Envelope<policy::Budget> = serde_json::from_slice(&a.budget).unwrap();
    let now = policy::now().unwrap();
    assert!(now >= old.body.expires_ns);
    let current = {
        let db = Connection::open_with_flags(
            a.store.join("native.sqlite"),
            OpenFlags::SQLITE_OPEN_READ_ONLY,
        )
        .unwrap();
        storage::frontier(&db).unwrap()
    };
    let (old_launch, old_sha) = a.launch(
        "expired-old-budget-still-refused",
        11,
        2,
        current,
        anchor.clone(),
    );
    let before = fs::read_dir(&a.journal).unwrap().count();
    let error = HistoryEffectV6::open(
        &a.store,
        ProtectedHistoryV6Input::load(&old_launch, rustix::process::geteuid().as_raw(), &old_sha)
            .unwrap(),
        2,
        deadline(),
    )
    .err()
    .expect("closure revived expired run authority")
    .to_string();
    assert!(
        error.contains("BUDGET_EXPIRED") || error.contains("WINDOW"),
        "{error}"
    );
    assert_eq!(fs::read_dir(&a.journal).unwrap().count(), before);
    write_value(
        &a.f.dir
            .path()
            .join("expired-old-run-authority-refused.json"),
        &json!({
            "error":error,"journal_unchanged":true,"old_budget_revived":false,
        }),
    );
    let mut body = old.body;
    body.sequence += 1;
    body.outside_anchor = anchor.clone();
    body.issued_ns = now;
    body.expires_ns = now + 3_600_000_000_000;
    let signed = super::signed(b'B', &body);
    let config = json!({"schema":"restricted-history-effect-budget-input-v6","identity":a.identity,
        "journal_path":a.journal,"outside_latest_anchor":anchor,"signed_budget":signed});
    let path = a.f.dir.path().join("renew-after-closed-epoch.json");
    let digest = write_value(&path, &config);
    let result = prepare_history_effect_v6_budget(
        ProtectedHistoryV6BudgetInput::load(&path, rustix::process::geteuid().as_raw(), &digest)
            .unwrap(),
    )
    .unwrap();
    assert_eq!(result["spent"]["cpu_ns"], 16_000_000_000u64);
    a.budget = signed;
    write_value(
        &a.f.dir.path().join("budget-renewed-after-closure.json"),
        &result,
    );
    serde_json::from_value(result["anchor"].clone()).unwrap()
}

pub(super) fn rejects_legacy_record_relabel(a: &TestAuthority) {
    let mut records: Vec<_> = fs::read_dir(&a.journal)
        .unwrap()
        .map(|r| r.unwrap().path())
        .filter(|p| p.extension().is_some_and(|e| e == "json"))
        .collect();
    records.sort();
    let (source, mut frame) = records
        .iter()
        .find_map(|p| {
            let f: journal::Frame = serde_json::from_slice(&fs::read(p).unwrap()).unwrap();
            (f.schema == epoch_recovery_v1::RECORD_SCHEMA).then_some((p.clone(), f))
        })
        .expect("fresh epoch record absent");
    let clone = a.f.dir.path().join("new-event-wrong-legacy-record-schema");
    fs::create_dir(&clone).unwrap();
    fs::set_permissions(&clone, fs::Permissions::from_mode(0o700)).unwrap();
    fs::copy(a.journal.join("owner.lock"), clone.join("owner.lock")).unwrap();
    for path in records {
        let f: journal::Frame = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        if f.sequence < frame.sequence {
            fs::copy(&path, clone.join(path.file_name().unwrap())).unwrap();
        }
    }
    frame.schema = "restricted-history-effect-record-v6".into();
    let raw = policy::encoded(&frame).unwrap();
    let altered = Anchor {
        sequence: frame.sequence,
        digest: policy::digest(&raw),
    };
    let path = clone.join(format!("{:020}-{}.json", altered.sequence, altered.digest));
    write(&path, &raw);
    let error = journal::Journal::open_existing(
        &clone,
        rustix::process::geteuid().as_raw(),
        &a.identity,
        &altered,
    )
    .err()
    .expect("new transition relabeled as old V6 record accepted")
    .to_string();
    assert!(error.contains("JOURNAL_CHAIN"));
    assert_eq!(fs::read(path).unwrap(), raw);
    write_value(
        &a.f.dir
            .path()
            .join("new-epoch-record-namespace-refusal.json"),
        &json!({
            "error":error,"original_frame_sha256":process::sha_file(&source),
            "changed_record_prefix_self_consistent":true,"new_event_signatures_preserved":true,
            "legacy_record_schema_relabel_refused":true,
        }),
    );
}

#[test]
fn settled_epoch_recovery_record_survives_every_publication_cut_and_retry() {
    for stage in [
        "file-synced",
        "linked",
        "final-synced",
        "unlinked",
        "published",
    ] {
        process::run(&format!("settled-epoch-record-{stage}"));
    }
}

#[test]
fn expired_old_budget_needs_fresh_close_authorization_then_separate_renewal() {
    process::run("settled-epoch-expired-budget");
}

#[test]
fn known_wrong_frontier_refusal_keeps_actual_frontier_through_sigkill_and_recovery() {
    process::run("settled-epoch-wrong-frontier");
}
