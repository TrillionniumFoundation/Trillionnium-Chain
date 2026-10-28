//! Actual native fixtures and disclosed, independently role-signed local test
//! authority. They are not an external Registry2 or real-model qualification.
use super::*;
use crate::store::operator_continuous_owner::history_import::tests::fixture::{Fixture, CLOCK};
use policy::{Anchor, Identity, Operation, Usage};
use serde_json::json;
use trnm_crypto_primitives::{sign_hex, signing_key_from_hex};

mod process;
pub(super) mod publication;
mod settled_epoch;
mod startup;

fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(50)
}
fn signed<T: serde::Serialize>(tag: u8, body: &T) -> Vec<u8> {
    let registry = signing_key_from_hex(&"11".repeat(32)).unwrap();
    let task = signing_key_from_hex(&"22".repeat(32)).unwrap();
    policy::encoded(&policy::Envelope {
        body,
        registry_signature: sign_hex(&registry, &policy::message(tag, 1, body).unwrap()),
        task_signature: sign_hex(&task, &policy::message(tag, 2, body).unwrap()),
    })
    .unwrap()
}
fn write(path: &Path, raw: &[u8]) -> String {
    assert!(!path.exists());
    let pending = path.with_extension("pending");
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&pending)
        .unwrap();
    file.write_all(raw).unwrap();
    file.sync_all().unwrap();
    drop(file);
    fs::rename(&pending, path).unwrap();
    sync_dir(path.parent().unwrap()).unwrap();
    policy::digest(raw)
}
fn write_value(path: &Path, value: &Value) -> String {
    write(path, &policy::encoded(value).unwrap())
}
fn read(path: &Path) -> Value {
    serde_json::from_slice(&fs::read(path).unwrap()).unwrap()
}
fn anchor(owner: &HistoryEffectV6) -> Anchor {
    owner.owner.journal().unwrap().anchor()
}
fn actual(owner: &HistoryEffectV6) -> Frontier {
    storage::frontier(&owner.node.db).unwrap()
}
fn checked(result: &HistoryEffectV6Result, workers: u64) {
    assert!(
        result.accounting_record_persisted,
        "{}",
        serde_json::to_string(result).unwrap()
    );
    assert!(result.within_original_allowance);
    let cpu = &result.cpu;
    assert!(!cpu.accounting_unavailable && !cpu.live_refused);
    assert_eq!(cpu.spawned_workers, workers);
    assert_eq!(cpu.started_workers, workers);
    assert_eq!(cpu.finished_workers, workers);
    assert_eq!(cpu.known_workers, workers);
    assert_eq!(
        cpu.total_cpu_ns,
        cpu.owner_cpu_ns
            .zip(cpu.scoped_worker_cpu_ns)
            .map(|(a, b)| a + b)
    );
    assert!(cpu.total_cpu_ns.unwrap() > 0);
    if workers > 0 {
        assert!(cpu.scoped_worker_cpu_ns.unwrap() > 0);
    }
}
struct Grant<'a> {
    purpose: Purpose,
    nonce: u64,
    epoch: u64,
    frontier: Frontier,
    anchor: Anchor,
    packet: Option<&'a Packet>,
    pair: Option<(u64, u64)>,
}
struct TestAuthority {
    f: Fixture,
    identity: Identity,
    journal: PathBuf,
    store: PathBuf,
    budget: Vec<u8>,
    installed: Anchor,
    materials: Value,
}
impl TestAuthority {
    fn new() -> Self {
        Self::with_budget_lifetime(3_600_000_000_000)
    }
    fn with_budget_lifetime(lifetime_ns: u64) -> Self {
        let f = Fixture::new();
        let identity = Identity {
            schema: "restricted-history-effect-identity-v6".into(),
            owner: policy::digest(b"disclosed-local-v6-test-owner"),
            store: policy::digest(f.dir.path().as_os_str().as_encoded_bytes()),
            network: hex::encode(f.settings.network()),
            parameters: hex::encode(f.settings.parameters()),
            genesis: hex::encode(f.settings.genesis()),
            source_commit: "1116ae390e4ed408ab0899e13aec5d1f90f2192c".into(),
            registry_key: f.identity.registry_key.clone(),
            task_key: f.identity.task_key.clone(),
        };
        let journal = f.dir.path().join("v6-journal");
        let store = f.dir.path().join("v6-native");
        let now = policy::now().unwrap();
        let budget_body = policy::Budget {
            schema: "restricted-history-effect-budget-v6".into(),
            identity: identity.clone(),
            budget_id: policy::digest(b"v6-test-budget"),
            sequence: 1,
            outside_anchor: Anchor::empty(),
            lifetime_ceiling: Usage {
                cpu_ns: 128_000_000_000,
                material_bytes: 128 << 20,
                received_bytes: 128 << 20,
                operations: 32,
            },
            nonce_first: 1,
            nonce_last: 4096,
            work_nonce_first: 1,
            work_nonce_last: 4096,
            issued_ns: now,
            expires_ns: now + lifetime_ns,
        };
        let budget = signed(b'B', &budget_body);
        let input = json!({"schema":"restricted-history-effect-budget-input-v6", "identity":identity,
            "journal_path":journal, "outside_latest_anchor":Anchor::empty(),"signed_budget":budget});
        let path = f.dir.path().join("install-budget.json");
        let digest = write_value(&path, &input);
        let result = prepare_history_effect_v6_budget(
            ProtectedHistoryV6BudgetInput::load(
                &path,
                rustix::process::geteuid().as_raw(),
                &digest,
            )
            .unwrap(),
        )
        .unwrap();
        let installed = serde_json::from_value(result["anchor"].clone()).unwrap();
        let materials = Value::Array(f.material_inputs().into_iter().map(|row|
            json!({"role":row.role,"path":row.path,"bytes":row.bytes,"sha256":row.sha256})).collect());
        Self {
            f,
            identity,
            journal,
            store,
            budget,
            installed,
            materials,
        }
    }
    fn id(&self, nonce: u64) -> String {
        policy::digest(format!("{}:{nonce}", self.identity.store).as_bytes())
    }
    fn epoch(&self, nonce: u64) -> String {
        policy::digest(format!("epoch:{}:{nonce}", self.identity.store).as_bytes())
    }
    fn genesis(&self) -> Frontier {
        Frontier {
            block: self.identity.genesis.clone(),
            root: hex::encode(
                self.f
                    .settings
                    .state_root(&self.f.settings.initial)
                    .unwrap(),
            ),
            generation: 0,
        }
    }
    fn grant(&self, g: Grant<'_>) -> Vec<u8> {
        let now = policy::now().unwrap();
        let parent = g.packet.map(|p| policy::ExecutionParent {
            block: hex::encode(p.header.parent),
            root: if p.header.parent == self.f.settings.genesis() {
                self.genesis().root
            } else {
                assert_eq!(p.header.parent, self.f.packet.id().unwrap());
                hex::encode(self.f.packet.header.state)
            },
            height: p.header.height - 1,
        });
        let op = Operation {
            schema: "restricted-history-effect-operation-v6".into(),
            identity: self.identity.clone(),
            budget_id: policy::digest(b"v6-test-budget"),
            operation_id: self.id(g.nonce),
            request_nonce: g.nonce,
            epoch: self.epoch(g.epoch),
            purpose: g.purpose,
            owner_frontier: g.frontier.clone(),
            outside_spent_anchor: g.anchor,
            execution_parent: parent,
            packet_sha256: g.packet.map(|p| policy::digest(&p.encode().unwrap())),
            target: g
                .packet
                .map_or(g.frontier.block, |p| hex::encode(p.id().unwrap())),
            target_root: g
                .packet
                .map_or(g.frontier.root, |p| hex::encode(p.header.state)),
            validation_operation_id: g.pair.map(|(v, _)| self.id(v)),
            activation_operation_id: g.pair.map(|(_, a)| self.id(a)),
            binding: Some(self.f.binding.clone()),
            allowance: Usage {
                cpu_ns: 4_000_000_000,
                material_bytes: 2 << 20,
                received_bytes: 2 << 20,
                operations: 1,
            },
            issued_ns: now,
            expires_ns: now + 3_000_000_000_000,
        };
        signed(b'O', &op)
    }
    fn launch(
        &self,
        label: &str,
        nonce: u64,
        epoch: u64,
        frontier: Frontier,
        anchor: Anchor,
    ) -> (PathBuf, String) {
        let startup = self.grant(Grant {
            purpose: Purpose::Startup,
            nonce,
            epoch,
            frontier,
            anchor: anchor.clone(),
            packet: None,
            pair: None,
        });
        let path = self.f.dir.path().join(format!("launch-{label}.json"));
        let digest = write_value(
            &path,
            &json!({"schema":"restricted-history-effect-launch-v6","identity":self.identity,
            "journal_path":self.journal,"outside_latest_anchor":anchor,"signed_budget":self.budget,"signed_startup":startup,"materials":self.materials}),
        );
        (path, digest)
    }
    fn open(
        &self,
        label: &str,
        nonce: u64,
        epoch: u64,
        frontier: Frontier,
        anchor: Anchor,
    ) -> HistoryEffectV6 {
        let (path, sha) = self.launch(label, nonce, epoch, frontier, anchor);
        HistoryEffectV6::open(
            &self.store,
            ProtectedHistoryV6Input::load(&path, rustix::process::geteuid().as_raw(), &sha)
                .unwrap(),
            2,
            deadline(),
        )
        .unwrap()
    }
}

#[test]
fn v6_actual_two_worker_cancel_retry_close_and_cold_reopen_keep_predebits() {
    let a = TestAuthority::new();
    let mut owner = a.open("first", 1, 1, a.genesis(), a.installed.clone());
    assert_eq!(owner.initial_cpu.stored_credit_ns, 0);
    let original_owner = std::thread::current().id();
    let grant = a.grant(Grant {
        purpose: Purpose::Validation,
        nonce: 2,
        epoch: 1,
        frontier: actual(&owner),
        anchor: anchor(&owner),
        packet: Some(&a.f.packet),
        pair: Some((2, 3)),
    });
    let cancel = owner.cancellation_for(&a.id(2)).unwrap();
    assert!(!cancel.cancel().unwrap());
    let cancel_requested = AtomicBool::new(false);
    let cancelled = owner
        .receive_with_progress(&grant, &a.f.page, CLOCK, deadline(), &|point| {
            if point == Progress::Execution(ExecutionProgress::AfterPrepare { index: 0 }) {
                assert_ne!(std::thread::current().id(), original_owner);
                assert!(cancel.cancel()?);
                cancel_requested.store(true, Ordering::Release);
            }
            Ok(())
        })
        .unwrap();
    assert!(cancel_requested.load(Ordering::Acquire));
    assert!(!cancel.cancel().unwrap());
    checked(&cancelled, 2);
    assert!(cancelled
        .native_error
        .as_deref()
        .unwrap()
        .contains("HISTORY_V6_CANCELLED"));
    assert_eq!(actual(&owner), a.genesis());
    let before = owner.observation().unwrap();
    assert!(owner
        .receive_with_progress(&grant, &a.f.page, CLOCK, deadline(), &|_| Ok(()))
        .is_err());
    assert_eq!(owner.observation().unwrap()["journal"], before["journal"]);
    let validation = a.grant(Grant {
        purpose: Purpose::Validation,
        nonce: 4,
        epoch: 1,
        frontier: actual(&owner),
        anchor: anchor(&owner),
        packet: Some(&a.f.packet),
        pair: Some((4, 5)),
    });
    let got = owner
        .receive_with_progress(&validation, &a.f.page, CLOCK, deadline(), &|_| {
            // This old handle cannot cancel the fresh independently signed op.
            assert!(!cancel.cancel()?);
            Ok(())
        })
        .unwrap();
    checked(&got, 2);
    assert!(got.known_success());
    let activation = a.grant(Grant {
        purpose: Purpose::Activation,
        nonce: 5,
        epoch: 1,
        frontier: actual(&owner),
        anchor: anchor(&owner),
        packet: Some(&a.f.packet),
        pair: Some((4, 5)),
    });
    let activated = owner
        .activate_with_progress(&activation, CLOCK, deadline(), &|_| Ok(()))
        .unwrap();
    checked(&activated, 0);
    assert!(activated.known_success());
    assert_eq!(actual(&owner).generation, 1);
    let close = a.grant(Grant {
        purpose: Purpose::Close,
        nonce: 6,
        epoch: 1,
        frontier: actual(&owner),
        anchor: anchor(&owner),
        packet: None,
        pair: None,
    });
    let frontier = actual(&owner);
    let closed = owner.close(&close, deadline()).unwrap();
    let head = serde_json::from_value(closed["journal"]["anchor"].clone()).unwrap();
    drop(owner);
    let mut reopened = a.open("reopen", 7, 2, frontier.clone(), head);
    assert_eq!(reopened.initial_cpu.stored_credit_ns, 0);
    assert_eq!(actual(&reopened), frontier);
    let close = a.grant(Grant {
        purpose: Purpose::Close,
        nonce: 8,
        epoch: 2,
        frontier,
        anchor: anchor(&reopened),
        packet: None,
        pair: None,
    });
    let result = reopened.close(&close, deadline()).unwrap();
    assert_eq!(result["journal"]["used_operations"], 7);
    assert_eq!(result["journal"]["known_settlements"], 7);
    eprintln!(
        "HISTORY_V6_ACTUAL_CANCEL_REOPEN {}",
        serde_json::to_string(&result).unwrap()
    );
}

#[test]
fn v6_late_journal_lock_failure_keeps_actual_native_and_original_cpu() {
    let a = TestAuthority::new();
    let mut owner = a.open("late-lock", 1, 1, a.genesis(), a.installed.clone());
    let validation = a.grant(Grant {
        purpose: Purpose::Validation,
        nonce: 2,
        epoch: 1,
        frontier: actual(&owner),
        anchor: anchor(&owner),
        packet: Some(&a.f.packet),
        pair: Some((2, 3)),
    });
    let validated = owner
        .receive_with_progress(&validation, &a.f.page, CLOCK, deadline(), &|_| Ok(()))
        .unwrap();
    checked(&validated, 2);
    assert!(validated.known_success());
    let activation = a.grant(Grant {
        purpose: Purpose::Activation,
        nonce: 3,
        epoch: 1,
        frontier: actual(&owner),
        anchor: anchor(&owner),
        packet: Some(&a.f.packet),
        pair: Some((2, 3)),
    });
    let journal = owner.owner.journal.clone();
    let owner_thread = std::thread::current().id();
    let poisoned = AtomicBool::new(false);
    let result = owner
        .activate_with_progress(&activation, CLOCK, deadline(), &|point| {
            if point == Progress::BeforeSettlement {
                assert_eq!(std::thread::current().id(), owner_thread);
                // Controlled same-owner fault injection AFTER the real SQL
                // transaction, with no new unmetered worker or forged receipt.
                let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    let _guard = journal.lock().unwrap();
                    panic!("V6_CONTROLLED_LATE_JOURNAL_POISON");
                }));
                assert!(outcome.is_err());
                poisoned.store(true, Ordering::Release);
            }
            Ok(())
        })
        .unwrap();
    assert!(poisoned.load(Ordering::Acquire));
    assert_eq!(
        result.native_id,
        Some(hex::encode(a.f.packet.id().unwrap()))
    );
    assert!(result.native_error.is_none());
    assert!(journal::CpuReceipt::from(&result.cpu).known());
    assert!(result.cpu.total_cpu_ns.unwrap() > 0);
    assert!(!result.accounting_record_persisted && !result.operation_closed);
    assert!(!result.known_success());
    assert!(result
        .accounting_error
        .as_deref()
        .unwrap()
        .contains("JOURNAL_UNKNOWN"));
    assert!(owner.owner.unavailable.load(Ordering::Acquire));
    assert_eq!(actual(&owner).block, hex::encode(a.f.packet.id().unwrap()));
    let marker = storage::read_marker(&owner.node.db, &a.id(3))
        .unwrap()
        .unwrap();
    assert_eq!(marker.after, actual(&owner));
    let outside = {
        let original = match journal.lock() {
            Err(poisoned) => poisoned.into_inner(),
            Ok(_) => panic!("controlled mutex was not poisoned"),
        };
        assert_eq!(original.pending().unwrap().operation.operation_id, a.id(3));
        original.anchor()
    };
    eprintln!(
        "HISTORY_V6_ACTUAL_LATE_JOURNAL_FAILURE {}",
        serde_json::to_string(&result).unwrap()
    );
    drop(owner);
    drop(journal);
    let reopened = journal::Journal::open(
        &a.journal,
        rustix::process::geteuid().as_raw(),
        &a.identity,
        &outside,
    )
    .unwrap();
    assert_eq!(reopened.pending().unwrap().operation.operation_id, a.id(3));
    assert!(reopened.pending().unwrap().observed_receipt.is_none());
    assert_eq!(reopened.observation()["used_operations"], 3);
    assert_eq!(reopened.observation()["known_settlements"], 2);
    // No fabricated clean close or successful debt reconciliation follows this
    // induced mutex fault. Its actual unknown durable prefix is retained.
}

#[test]
fn v6_unmarked_existing_bad_product_is_not_validated_by_sql_syntax() {
    let a = TestAuthority::new();
    let mut owner = a.open("unmarked", 1, 1, a.genesis(), a.installed.clone());
    let mut bad = a.f.packet.clone();
    let offset = 4 + 2 * pon_work::CELLS * 4;
    let word = u32::from_le_bytes(bad.proof[offset..offset + 4].try_into().unwrap());
    let changed = ((u128::from(word) + 1) % pon_work::Q) as u32;
    bad.proof[offset..offset + 4].copy_from_slice(&changed.to_le_bytes());
    assert_ne!(bad.encode().unwrap(), a.f.packet.encode().unwrap());
    pon_work::precheck_proof_statement(
        bad.header.challenge(),
        bad.header.work_task,
        bad.header.target,
        &bad.proof,
    )
    .unwrap();
    assert!(matches!(
        pon_work::verify_reference(
            bad.header.challenge(),
            bad.header.work_task,
            bad.header.target,
            &bad.proof
        ),
        Err(pon_work::WorkError::Product)
    ));
    let page = process::page(&a, &bad);
    let grant = a.grant(Grant {
        purpose: Purpose::Validation,
        nonce: 2,
        epoch: 1,
        frontier: actual(&owner),
        anchor: anchor(&owner),
        packet: Some(&bad),
        pair: Some((2, 3)),
    });
    let uncached = owner
        .receive_with_progress(&grant, &page, CLOCK, deadline(), &|_| Ok(()))
        .unwrap();
    checked(&uncached, 0);
    assert!(uncached
        .native_error
        .as_deref()
        .unwrap()
        .contains("Product"));
    assert!(!uncached.known_success());
    // Explicit fixture corruption, not an authorized admission and not a claim
    // that an unauthenticated network peer can write this protected database.
    // It reproduces the exact Existing fast-path precondition with a bad C.
    let bad_id = bad.id().unwrap();
    let parent = owner.node.record(bad.header.parent).unwrap();
    let chainwork = parent
        .work
        .checked_add(consensus::required_work(bad.header.target).unwrap())
        .unwrap();
    owner
        .node
        .db
        .execute(
            "INSERT INTO blocks VALUES(?,?,?,?,?,?)",
            params![
                bad_id.as_slice(),
                bad.header.parent.as_slice(),
                bad.header.height,
                chainwork.bytes().as_slice(),
                bad.encode().unwrap(),
                bad.header.state.as_slice()
            ],
        )
        .unwrap();
    let grant = a.grant(Grant {
        purpose: Purpose::Validation,
        nonce: 4,
        epoch: 1,
        frontier: actual(&owner),
        anchor: anchor(&owner),
        packet: Some(&bad),
        pair: Some((4, 5)),
    });
    let called_work = AtomicBool::new(false);
    let cached = owner
        .receive_with_progress(&grant, &page, CLOCK, deadline(), &|point| {
            if matches!(point, Progress::Work(_) | Progress::Execution(_)) {
                called_work.store(true, Ordering::Release);
            }
            Ok(())
        })
        .unwrap();
    checked(&cached, 0);
    assert!(!called_work.load(Ordering::Acquire));
    assert!(cached
        .native_error
        .as_deref()
        .unwrap()
        .contains("REUSE_VALIDATION_FACT_REQUIRED"));
    assert!(!cached.known_success());
    assert!(storage::read_marker(&owner.node.db, &a.id(4))
        .unwrap()
        .is_none());
    assert!(
        storage::verify_known_markers(&owner.node.db, &owner.owner.journal().unwrap(), None)
            .unwrap_err()
            .to_string()
            .contains("BLOCK_VALIDATION_COVERAGE")
    );
    eprintln!(
        "HISTORY_V6_ACTUAL_UNMARKED_BAD_PRODUCT {}",
        json!({
            "cheap_statement_passed":true,"scalar_reference":"Product",
            "uncached":uncached,"cached":cached,"controlled_database_corruption":true,
            "new_validation_marker":false,"full_store_coverage_refused":true
        })
    );
}

#[test]
fn v6_unsigned_worker_host_and_delegated_nonce_refuse_without_new_authority() {
    let a = TestAuthority::new();
    let (path, sha) = a.launch("bad", 1, 1, a.genesis(), a.installed.clone());
    let invalid = HistoryEffectV6::open(
        &a.store,
        ProtectedHistoryV6Input::load(&path, rustix::process::geteuid().as_raw(), &sha).unwrap(),
        3,
        deadline(),
    );
    assert!(invalid.err().unwrap().to_string().contains("WORKERS"));
    let mut value = read(&path);
    let signed_raw: Vec<u8> = serde_json::from_value(value["signed_startup"].clone()).unwrap();
    let mut envelope: Value = serde_json::from_slice(&signed_raw).unwrap();
    envelope["task_signature"] = json!("00".repeat(64));
    value["signed_startup"] = json!(policy::encoded(&envelope).unwrap());
    let badpath = a.f.dir.path().join("bad-signature.json");
    let badsha = write_value(&badpath, &value);
    let bad = HistoryEffectV6::open(
        &a.store,
        ProtectedHistoryV6Input::load(&badpath, rustix::process::geteuid().as_raw(), &badsha)
            .unwrap(),
        2,
        deadline(),
    );
    assert!(bad.err().unwrap().to_string().contains("SIGNATURE"));
    let mut owner = HistoryEffectV6::open(
        &a.store,
        ProtectedHistoryV6Input::load(&path, rustix::process::geteuid().as_raw(), &sha).unwrap(),
        2,
        deadline(),
    )
    .unwrap();
    let validation = a.grant(Grant {
        purpose: Purpose::Validation,
        nonce: 2,
        epoch: 1,
        frontier: actual(&owner),
        anchor: anchor(&owner),
        packet: Some(&a.f.packet),
        pair: Some((2, 3)),
    });
    let before = anchor(&owner);
    assert!(owner
        .receive_from(
            "127.0.0.1:1".parse().unwrap(),
            &validation,
            &a.f.page,
            CLOCK,
            deadline()
        )
        .is_err());
    assert_eq!(anchor(&owner), before);
    // A fresh, actually signed budget restricts the W1/header nonce separately
    // from request nonces. A signed exact packet cannot override that fence.
    let mut budget: policy::Envelope<policy::Budget> = serde_json::from_slice(&a.budget).unwrap();
    budget.body.sequence = 2;
    budget.body.outside_anchor = before;
    budget.body.work_nonce_first = a.f.packet.header.nonce + 1;
    budget.body.work_nonce_last = a.f.packet.header.nonce + 1;
    owner
        .owner
        .journal()
        .unwrap()
        .install_budget(&signed(b'B', &budget.body))
        .unwrap();
    let validation = a.grant(Grant {
        purpose: Purpose::Validation,
        nonce: 2,
        epoch: 1,
        frontier: actual(&owner),
        anchor: anchor(&owner),
        packet: Some(&a.f.packet),
        pair: Some((2, 3)),
    });
    let called = AtomicBool::new(false);
    let refused = owner
        .receive_with_progress(&validation, &a.f.page, CLOCK, deadline(), &|p| {
            if matches!(p, Progress::Work(_) | Progress::Execution(_)) {
                called.store(true, Ordering::Release);
            }
            Ok(())
        })
        .unwrap();
    checked(&refused, 0);
    assert!(!called.load(Ordering::Acquire));
    assert!(refused
        .native_error
        .as_deref()
        .unwrap()
        .contains("WORK_NONCE"));
    let close = a.grant(Grant {
        purpose: Purpose::Close,
        nonce: 4,
        epoch: 1,
        frontier: actual(&owner),
        anchor: anchor(&owner),
        packet: None,
        pair: None,
    });
    owner.close(&close, deadline()).unwrap();
    eprintln!(
        "HISTORY_V6_ORIGINAL_NONCE_REFUSAL {}",
        serde_json::to_string(&refused).unwrap()
    );
}

#[test]
fn v6_actual_sigkill_during_registered_worker_recovers_with_fresh_claims() {
    process::run("validation-worker");
}
#[test]
fn v6_actual_sigkill_after_activation_commit_recovers_and_advances_again() {
    process::run("activation-committed");
}

#[test]
#[ignore = "mandatory process tests invoke this exact source-bound helper with pinned protected inputs"]
fn history_effect_v6_process_child_helper() {
    process::child();
}

#[test]
fn history_publication_pending_file_fsync_crash_repairs_and_resumes() {
    process::run("publication-intent-file-synced");
}
#[test]
fn history_publication_two_hardlinks_crash_repairs_and_resumes() {
    process::run("publication-intent-linked");
}
#[test]
fn history_publication_final_directory_fsync_crash_repairs_and_resumes() {
    process::run("publication-intent-final-synced");
}
#[test]
fn history_publication_pending_unlink_crash_repairs_and_resumes() {
    process::run("publication-intent-unlinked");
}
#[test]
fn history_publication_durable_unacknowledged_crash_repairs_and_resumes() {
    process::run("publication-intent-published");
}
