use super::*;
use crate::{
    ingress::{
        self,
        pq_network::{canonical_tests::key, PqClient, PqNetworkPolicy, PqServer, VerifiedRequest},
        Request,
    },
    pq_rollback_witness::{DurableWitness, WitnessTransport},
    Settings,
};
use std::{
    fs,
    net::TcpListener,
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, AtomicU8, Ordering},
        Arc, Mutex,
    },
    thread,
    time::Duration,
};

struct Fixture {
    directory: tempfile::TempDir,
    settings: Settings,
    policy: Arc<PqNetworkPolicy>,
    service: Arc<Mutex<Option<DurableWitness>>>,
    mode: Arc<AtomicU8>,
    captured: Arc<Mutex<Option<Vec<u8>>>>,
}
struct Transport {
    service: Arc<Mutex<Option<DurableWitness>>>,
    mode: Arc<AtomicU8>,
    captured: Arc<Mutex<Option<Vec<u8>>>>,
}
impl WitnessTransport for Transport {
    fn exchange(&mut self, request: &[u8], until: Instant) -> Result<Vec<u8>> {
        let mode = self.mode.load(Ordering::Acquire);
        if mode == 3 {
            return Err("WITNESS_OUTAGE".into());
        }
        if mode == 2 {
            return self
                .captured
                .lock()
                .unwrap()
                .clone()
                .ok_or_else(|| "NO_OLD_REPLY".into());
        }
        let reply = self
            .service
            .lock()
            .unwrap()
            .as_mut()
            .ok_or("WITNESS_MISSING")?
            .handle(request, until)?;
        *self.captured.lock().unwrap() = Some(reply.clone());
        if request[4] == 2 {
            if mode == 1 {
                return Err("LOST_CAS_REPLY".into());
            }
            if mode == 5 {
                self.mode.store(7, Ordering::Release);
            }
            if mode == 6 {
                thread::sleep(
                    until.saturating_duration_since(Instant::now()) + Duration::from_millis(2),
                );
            }
        } else if mode == 4 {
            self.mode.store(7, Ordering::Release);
        }
        Ok(reply)
    }
}
impl Fixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let settings = Settings::development(Some(7)).unwrap();
        let policy = Arc::new(
            PqNetworkPolicy::new(
                &settings,
                key(11).public_spki(),
                1,
                [key(12).public_spki().to_vec()],
            )
            .unwrap(),
        );
        let binding = Self::make_binding(&policy, 1);
        let initial = initial_checkpoint(&policy, &binding).unwrap();
        let owner = DurableWitness::register_new(
            &directory.path().join("witness.sqlite"),
            binding,
            initial,
            key(13),
        )
        .unwrap();
        Self {
            directory,
            settings,
            policy,
            service: Arc::new(Mutex::new(Some(owner))),
            mode: Arc::new(AtomicU8::new(0)),
            captured: Arc::new(Mutex::new(None)),
        }
    }
    fn make_binding(policy: &PqNetworkPolicy, generation: u64) -> WitnessBinding {
        WitnessBinding::new(
            policy,
            generation,
            key(13).public_spki(),
            key(14).public_spki(),
        )
        .unwrap()
    }
    fn node_path(&self) -> PathBuf {
        self.directory.path().join("node")
    }
    fn database(&self) -> PathBuf {
        self.node_path().join("native.sqlite")
    }
    fn witness_path(&self) -> PathBuf {
        self.directory.path().join("witness.sqlite")
    }
    fn client(&self) -> WitnessClient {
        WitnessClient::new(
            Self::make_binding(&self.policy, 1),
            key(14),
            Box::new(Transport {
                service: self.service.clone(),
                mode: self.mode.clone(),
                captured: self.captured.clone(),
            }),
        )
        .unwrap()
    }
    fn node(&self) -> Node {
        Node::create_with_pq_witness(
            &self.node_path(),
            self.settings.clone(),
            1,
            &self.policy,
            self.client(),
        )
        .unwrap()
    }
    fn reopen(&self) -> Result<Node> {
        Node::open_with_pq_witness(
            &self.node_path(),
            self.settings.clone(),
            1,
            &self.policy,
            self.client(),
        )
    }
    fn head(&self) -> Checkpoint {
        self.client().current().unwrap()
    }
    fn request(&self, sequence: u64) -> VerifiedRequest {
        self.request_at(sequence, ingress::now().unwrap() + 50)
    }
    fn request_at(&self, sequence: u64, expiry: u64) -> VerifiedRequest {
        let client = PqClient::new(self.policy.clone(), key(12)).unwrap();
        let prepared = client.prepare(sequence, expiry, Request::Head).unwrap();
        self.policy
            .verify_request(prepared.wire(), ingress::now().unwrap())
            .unwrap()
    }
    fn restart_service(&self) {
        *self.service.lock().unwrap() = None;
        let reopened = DurableWitness::open_existing(
            &self.witness_path(),
            Self::make_binding(&self.policy, 1),
            key(13),
        )
        .unwrap();
        *self.service.lock().unwrap() = Some(reopened);
    }
    fn live_check(&self) -> impl FnMut() -> Result<()> + '_ {
        || ensure(self.mode.load(Ordering::Acquire) != 7, "LIVE_CANCELLED")
    }
}
fn error<T>(result: Result<T>, expected: &str) {
    match result {
        Ok(_) => panic!("expected {expected}"),
        Err(error) => assert!(
            error.to_string().contains(expected),
            "expected {expected}, got {error}"
        ),
    }
}
fn records(node: &Node) -> u64 {
    node.db
        .query_row("SELECT COUNT(*) FROM pq_network_request_v2", [], |r| {
            r.get(0)
        })
        .unwrap()
}
fn input_bytes(node: &Node) -> u64 {
    node.db
        .query_row("SELECT input_bytes FROM pq_network_resource_v2", [], |r| {
            r.get(0)
        })
        .unwrap()
}

#[test]
fn guarded_charge_pending_revocation_survive_service_cold_restart() {
    let f = Fixture::new();
    let mut node = f.node();
    node.charge_pq_ingress(&f.policy, true, 17, true).unwrap();
    assert!(matches!(
        node.begin_pq_network_request(&f.policy, &f.request(1))
            .unwrap(),
        super::super::pq_network::PqReplay::Execute(_, _)
    ));
    node.revoke_pq_network_peer(&f.policy, key(12).public_key_id())
        .unwrap();
    let head = f.head();
    drop(node);
    f.restart_service();
    let mut reopened = f.reopen().unwrap();
    assert_eq!(input_bytes(&reopened), 17);
    assert_eq!(records(&reopened), 1);
    assert_eq!(checkpoint(&reopened.db).unwrap(), head);
    error(
        reopened.begin_pq_network_request(&f.policy, &f.request(1)),
        "PQ_NETWORK_REVOKED",
    );
}

#[test]
fn whole_node_old_sqlite_and_checkpoint_restore_is_rejected() {
    let f = Fixture::new();
    let node = f.node();
    let old = checkpoint(&node.db).unwrap();
    drop(node);
    let snapshot = f.directory.path().join("old-node.sqlite");
    fs::copy(f.database(), &snapshot).unwrap();
    let mut node = f.reopen().unwrap();
    node.charge_pq_ingress(&f.policy, true, 29, true).unwrap();
    let retained = f.head();
    assert!(retained.sequence > old.sequence);
    drop(node);
    fs::copy(snapshot, f.database()).unwrap();
    let restored = Connection::open(f.database()).unwrap();
    assert_eq!(checkpoint(&restored).unwrap(), old);
    drop(restored);
    error(f.reopen(), "PQ_WITNESS_ROLLBACK");
    assert_eq!(f.head(), retained);
}

#[test]
fn witness_outage_latches_owner_without_refunding_or_charging_quota() {
    let f = Fixture::new();
    let mut node = f.node();
    let before = f.head();
    f.mode.store(3, Ordering::Release);
    error(
        node.charge_pq_ingress(&f.policy, true, 31, true),
        "WITNESS_OUTAGE",
    );
    assert_eq!(input_bytes(&node), 0);
    f.mode.store(0, Ordering::Release);
    error(
        node.charge_pq_ingress(&f.policy, true, 31, true),
        "PQ_WITNESS_UNAVAILABLE",
    );
    drop(node);
    let mut reopened = f.reopen().unwrap();
    assert_eq!(f.head(), before);
    reopened
        .charge_pq_ingress(&f.policy, true, 31, true)
        .unwrap();
    assert_eq!(input_bytes(&reopened), 31);
}

#[test]
fn lost_successful_cas_reply_never_revives_old_local_authority() {
    let f = Fixture::new();
    let mut node = f.node();
    let before = checkpoint(&node.db).unwrap();
    f.mode.store(1, Ordering::Release);
    error(
        node.charge_pq_ingress(&f.policy, true, 37, true),
        "LOST_CAS_REPLY",
    );
    assert_eq!(checkpoint(&node.db).unwrap(), before);
    assert_eq!(input_bytes(&node), 0);
    f.mode.store(0, Ordering::Release);
    assert_eq!(f.head().sequence, before.sequence + 1);
    error(
        node.begin_pq_network_request(&f.policy, &f.request(1)),
        "PQ_WITNESS_UNAVAILABLE",
    );
    drop(node);
    error(f.reopen(), "PQ_WITNESS_ROLLBACK");
}

#[test]
fn local_commit_failure_after_external_cas_is_permanently_detectable() {
    let f = Fixture::new();
    let mut node = f.node();
    let before = f.head();
    node.db.commit_hook(Some(|| true)).unwrap();
    assert!(node.charge_pq_ingress(&f.policy, true, 41, true).is_err());
    node.db.commit_hook(None::<fn() -> bool>).unwrap();
    assert_eq!(checkpoint(&node.db).unwrap(), before);
    assert_eq!(input_bytes(&node), 0);
    assert_eq!(f.head().sequence, before.sequence + 1);
    error(
        node.charge_pq_ingress(&f.policy, true, 41, true),
        "PQ_WITNESS_UNAVAILABLE",
    );
    drop(node);
    error(f.reopen(), "PQ_WITNESS_ROLLBACK");
}

#[test]
fn captured_signed_reply_cannot_answer_a_new_random_challenge() {
    let f = Fixture::new();
    let mut client = f.client();
    client.current().unwrap();
    f.mode.store(2, Ordering::Release);
    error(client.current(), "PQ_WITNESS_REPLY_CONTEXT");
    f.mode.store(0, Ordering::Release);
    error(client.current(), "PQ_WITNESS_UNAVAILABLE");
    f.client().current().unwrap();
}

#[test]
fn guarded_namespace_requires_explicit_guarded_open_and_existing_node() {
    let f = Fixture::new();
    error(f.reopen(), "PQ_WITNESS_EXISTING_NODE_REQUIRED");
    assert!(!f.node_path().exists());
    drop(f.node());
    assert!(Node::open_with_pq_network(&f.node_path(), f.settings.clone(), 1, &f.policy).is_err());
    error(
        Node::create_with_pq_witness(&f.node_path(), f.settings.clone(), 1, &f.policy, f.client()),
        "PQ_WITNESS_NEW_NODE_REQUIRED",
    );
    f.reopen().unwrap();
}

#[test]
fn missing_external_state_is_not_enrolled_on_open_and_registration_is_exclusive() {
    let f = Fixture::new();
    let initial = f.head();
    assert!(DurableWitness::register_new(
        &f.witness_path(),
        Fixture::make_binding(&f.policy, 1),
        initial,
        key(13)
    )
    .is_err());
    drop(f.node());
    *f.service.lock().unwrap() = None;
    fs::remove_file(f.witness_path()).unwrap();
    assert!(DurableWitness::open_existing(
        &f.witness_path(),
        Fixture::make_binding(&f.policy, 1),
        key(13)
    )
    .is_err());
    assert!(!f.witness_path().exists());
    error(f.reopen(), "WITNESS_MISSING");
    assert!(!f.witness_path().exists());
}

#[test]
fn pending_permission_and_revocation_are_rechecked_under_fresh_predecessor() {
    for tamper_revocation in [false, true] {
        let f = Fixture::new();
        let mut node = f.node();
        let request = f.request(1);
        node.begin_pq_network_request(&f.policy, &request).unwrap();
        if tamper_revocation {
            node.revoke_pq_network_peer(&f.policy, key(12).public_key_id())
                .unwrap();
            node.db
                .execute("UPDATE pq_network_peer_v2 SET revoked=0", [])
                .unwrap();
        } else {
            node.db
                .execute(
                    "UPDATE pq_network_request_v2 SET operation=zeroblob(32)",
                    [],
                )
                .unwrap();
        }
        let retained = f.head();
        error(
            node.begin_pq_network_request(&f.policy, &request),
            "PQ_WITNESS_LOCAL_ROOT",
        );
        assert_eq!(f.head(), retained);
    }
}

#[test]
fn oversized_restored_fixed_blob_is_rejected_before_hashing_and_external_advance() {
    let f = Fixture::new();
    let mut node = f.node();
    let before = f.head();
    node.db.execute_batch("PRAGMA ignore_check_constraints=ON; UPDATE pq_network_peer_v2 SET peer=zeroblob(1048576); PRAGMA ignore_check_constraints=OFF;").unwrap();
    error(
        node.charge_pq_ingress(&f.policy, true, 43, true),
        "PQ_WITNESS_LOCAL_WIDTH",
    );
    assert_eq!(f.head(), before);
    assert_eq!(input_bytes(&node), 0);
}

#[test]
fn binding_generation_policy_and_distinct_identity_are_mandatory() {
    let f = Fixture::new();
    assert!(
        WitnessBinding::new(&f.policy, 1, key(13).public_spki(), key(13).public_spki()).is_err()
    );
    assert!(WitnessClient::new(
        Fixture::make_binding(&f.policy, 1),
        key(15),
        Box::new(Transport {
            service: f.service.clone(),
            mode: f.mode.clone(),
            captured: f.captured.clone()
        })
    )
    .is_err());
    *f.service.lock().unwrap() = None;
    error(
        DurableWitness::open_existing(
            &f.witness_path(),
            Fixture::make_binding(&f.policy, 2),
            key(13),
        ),
        "PQ_WITNESS_BINDING",
    );
    let changed = PqNetworkPolicy::new(
        &f.settings,
        key(11).public_spki(),
        2,
        [key(12).public_spki().to_vec()],
    )
    .unwrap();
    error(
        DurableWitness::open_existing(
            &f.witness_path(),
            Fixture::make_binding(&changed, 1),
            key(13),
        ),
        "PQ_WITNESS_BINDING",
    );
    f.restart_service();
}

#[test]
fn exact_cas_retry_is_idempotent_but_fork_skip_and_wrap_refuse() {
    let f = Fixture::new();
    let mut client = f.client();
    let initial = client.current().unwrap();
    let next = Checkpoint::new(2, [2; 64]).unwrap();
    client.advance(initial, next).unwrap();
    client.advance(initial, next).unwrap();
    assert_eq!(client.current().unwrap(), next);
    assert!(client
        .advance(next, Checkpoint::new(4, [4; 64]).unwrap())
        .is_err());
    client.current().unwrap();
    assert!(Checkpoint::new(u64::MAX, [4; 64]).is_err());
    error(
        client.advance(initial, Checkpoint::new(2, [3; 64]).unwrap()),
        "PQ_WITNESS_CAS",
    );
    assert_eq!(f.head(), next);
}

#[test]
fn replacing_external_database_path_is_rejected_while_old_descriptor_is_locked() {
    let f = Fixture::new();
    let mut client = f.client();
    let initial = client.current().unwrap();
    let old = f.directory.path().join("retained.sqlite");
    fs::rename(f.witness_path(), &old).unwrap();
    fs::copy(&old, f.witness_path()).unwrap();
    error(client.current(), "PQ_WITNESS_STORAGE_IDENTITY");
    *f.service.lock().unwrap() = None;
    // Restoration is an explicit operator action, never done by open.
    fs::remove_file(f.witness_path()).unwrap();
    fs::rename(old, f.witness_path()).unwrap();
    f.restart_service();
    assert_eq!(f.head(), initial);
}

#[test]
fn live_cancellation_after_current_prevents_pending_insert_and_owner_can_resume() {
    let f = Fixture::new();
    let mut node = f.node();
    let initial = f.head();
    let request = f.request(1);
    f.mode.store(4, Ordering::Release);
    error(
        node.begin_pq_network_request_with_check(
            &f.policy,
            &request,
            Instant::now() + Duration::from_secs(1),
            &mut f.live_check(),
        ),
        "LIVE_CANCELLED",
    );
    assert_eq!(records(&node), 0);
    f.mode.store(0, Ordering::Release);
    assert_eq!(f.head(), initial);
    node.begin_pq_network_request(&f.policy, &request).unwrap();
    assert_eq!(records(&node), 1);
}

#[test]
fn expired_before_current_transport_does_not_poison_guarded_owner() {
    let f = Fixture::new();
    let mut node = f.node();
    let before = f.head();
    let epoch = node.pq_network_epoch.load(Ordering::Acquire);
    error(
        node.charge_pq_ingress_with_check(
            &f.policy,
            true,
            47,
            true,
            Instant::now() - Duration::from_millis(1),
            &mut || Ok(()),
        ),
        "PQ_WITNESS_DEADLINE",
    );
    assert_eq!(input_bytes(&node), 0);
    assert_eq!(f.head(), before);
    assert_eq!(node.pq_network_epoch.load(Ordering::Acquire), epoch);
    node.charge_pq_ingress(&f.policy, true, 47, true).unwrap();
    assert_eq!(input_bytes(&node), 47);
    assert_eq!(checkpoint(&node.db).unwrap(), f.head());
}

#[test]
fn uncertain_revocation_invalidates_epoch_of_already_admitted_work() {
    let f = Fixture::new();
    let mut node = f.node();
    let request = f.request(1);
    let super::super::pq_network::PqReplay::Execute(epoch, expected) =
        node.begin_pq_network_request(&f.policy, &request).unwrap()
    else {
        panic!("fresh signed request must obtain Execute");
    };
    let before = f.head();
    assert_eq!(epoch.load(Ordering::Acquire), expected);

    // The witness commits the revocation but its successful reply is lost.
    // Local rollback cannot leave the old dispatch progress check authorized.
    f.mode.store(1, Ordering::Release);
    error(
        node.revoke_pq_network_peer(&f.policy, key(12).public_key_id()),
        "LOST_CAS_REPLY",
    );
    f.mode.store(0, Ordering::Release);
    assert_ne!(epoch.load(Ordering::Acquire), expected);
    let revoked: bool = node
        .db
        .query_row("SELECT revoked FROM pq_network_peer_v2", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert!(!revoked);
    assert_eq!(checkpoint(&node.db).unwrap(), before);
    assert_eq!(f.head().sequence, before.sequence + 1);
    assert_ne!(f.head().root, before.root);
    error(
        node.begin_pq_network_request(&f.policy, &request),
        "PQ_WITNESS_UNAVAILABLE",
    );
}

#[test]
fn authenticated_successful_cas_commits_before_late_live_cancellation() {
    let f = Fixture::new();
    let mut node = f.node();
    f.mode.store(5, Ordering::Release);
    error(
        node.charge_pq_ingress_with_check(
            &f.policy,
            true,
            53,
            true,
            Instant::now() + Duration::from_secs(1),
            &mut f.live_check(),
        ),
        "LIVE_CANCELLED",
    );
    f.mode.store(0, Ordering::Release);
    assert_eq!(input_bytes(&node), 53);
    assert_eq!(checkpoint(&node.db).unwrap(), f.head());
    node.charge_pq_ingress(&f.policy, false, 1, false).unwrap();
    drop(node);
    assert_eq!(input_bytes(&f.reopen().unwrap()), 54);
}

#[test]
fn oversized_local_binding_and_checkpoint_are_rejected_before_blob_copy() {
    for column in ["binding", "root"] {
        let f = Fixture::new();
        let mut node = f.node();
        let initial = f.head();
        node.db
            .execute_batch("PRAGMA ignore_check_constraints=ON;")
            .unwrap();
        if column == "binding" {
            node.db
                .execute(
                    "UPDATE metadata SET value=zeroblob(1048576) WHERE key=?",
                    [KEY],
                )
                .unwrap();
        } else {
            node.db
                .execute(
                    "UPDATE pq_witness_checkpoint_v1 SET root=zeroblob(1048576)",
                    [],
                )
                .unwrap();
        }
        error(
            node.charge_pq_ingress(&f.policy, true, 59, true),
            "PQ_WITNESS_LOCAL_WIDTH",
        );
        assert_eq!(f.head(), initial);
    }
}

#[test]
fn non_system_trigger_with_sqlitex_prefix_cannot_hide_from_schema_check() {
    let f = Fixture::new();
    let attacker = Connection::open(f.witness_path()).unwrap();
    attacker
        .execute_batch("CREATE TRIGGER sqlitexevil AFTER UPDATE ON witness_v1 BEGIN SELECT 1; END;")
        .unwrap();
    drop(attacker);
    error(f.client().current(), "PQ_WITNESS_SCHEMA");
}

#[test]
fn oversized_external_binding_and_roots_are_rejected_before_blob_copy() {
    for column in ["binding", "root", "previous_root"] {
        let f = Fixture::new();
        let initial = f.head();
        let attacker = Connection::open(f.witness_path()).unwrap();
        attacker
            .execute_batch("PRAGMA ignore_check_constraints=ON;")
            .unwrap();
        attacker
            .execute(
                &format!("UPDATE witness_v1 SET {column}=zeroblob(1048576)"),
                [],
            )
            .unwrap();
        error(f.client().current(), "PQ_WITNESS_STATE_WIDTH");
        let sequence: u64 = attacker
            .query_row("SELECT sequence FROM witness_v1", [], |r| r.get(0))
            .unwrap();
        assert_eq!(sequence, initial.sequence);
    }
}

#[test]
fn authenticated_cas_receipt_after_original_deadline_still_aligns_local_commit() {
    let f = Fixture::new();
    let mut node = f.node();
    f.mode.store(6, Ordering::Release);
    let until = Instant::now() + Duration::from_millis(200);
    error(
        node.charge_pq_ingress_with_check(&f.policy, true, 61, true, until, &mut || {
            ensure(Instant::now() < until, "LIVE_DEADLINE")
        }),
        "LIVE_DEADLINE",
    );
    f.mode.store(0, Ordering::Release);
    assert_eq!(input_bytes(&node), 61);
    assert_eq!(checkpoint(&node.db).unwrap(), f.head());
    node.charge_pq_ingress(&f.policy, false, 1, false).unwrap();
    drop(node);
    assert_eq!(input_bytes(&f.reopen().unwrap()), 62);
}

#[test]
fn committed_expiry_retirement_publishes_epoch_even_when_live_callback_refuses() {
    let f = Fixture::new();
    let mut node = f.node();
    let expiry = ingress::now().unwrap() + 1;
    let old = f.request_at(1, expiry);
    node.begin_pq_network_request(&f.policy, &old).unwrap();
    let before = node.pq_network_epoch.load(Ordering::Acquire);
    while ingress::now().unwrap() <= expiry {
        thread::sleep(Duration::from_millis(10));
    }
    f.mode.store(5, Ordering::Release);
    let next = f.request(2);
    error(
        node.begin_pq_network_request_with_check(
            &f.policy,
            &next,
            Instant::now() + Duration::from_secs(1),
            &mut f.live_check(),
        ),
        "LIVE_CANCELLED",
    );
    assert!(node.pq_network_epoch.load(Ordering::Acquire) > before);
    let (status, highest): (u64, u64) = node.db.query_row("SELECT r.status,p.highest_sequence FROM pq_network_request_v2 r JOIN pq_network_peer_v2 p ON r.peer=p.peer WHERE r.sequence=1", [], |r| Ok((r.get(0)?, r.get(1)?))).unwrap();
    assert_eq!((status, highest), (2, 1));
    f.mode.store(0, Ordering::Release);
    assert_eq!(checkpoint(&node.db).unwrap(), f.head());
    node.begin_pq_network_request(&f.policy, &next).unwrap();
    assert_eq!(records(&node), 2);
}

#[test]
fn lost_retirement_cas_reply_preserves_terminal_zero_epoch() {
    let f = Fixture::new();
    let mut node = f.node();
    let expiry = ingress::now().unwrap() + 1;
    let old = f.request_at(1, expiry);
    let super::super::pq_network::PqReplay::Execute(epoch, expected) =
        node.begin_pq_network_request(&f.policy, &old).unwrap()
    else {
        panic!("fresh signed request must obtain Execute");
    };
    let before = f.head();
    while ingress::now().unwrap() <= expiry {
        thread::sleep(Duration::from_millis(10));
    }
    let next = f.request(2);
    f.mode.store(1, Ordering::Release);
    error(
        node.begin_pq_network_request(&f.policy, &next),
        "LOST_CAS_REPLY",
    );
    f.mode.store(0, Ordering::Release);
    assert_ne!(expected, 0);
    assert_eq!(epoch.load(Ordering::Acquire), 0);
    let (status, highest): (u64, u64) = node
        .db
        .query_row(
            "SELECT r.status,p.highest_sequence FROM pq_network_request_v2 r JOIN pq_network_peer_v2 p ON r.peer=p.peer WHERE r.sequence=1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!((status, highest), (0, 0));
    assert_eq!(records(&node), 1);
    assert_eq!(checkpoint(&node.db).unwrap(), before);
    assert_eq!(f.head().sequence, before.sequence + 1);
    error(
        node.begin_pq_network_request(&f.policy, &next),
        "PQ_WITNESS_UNAVAILABLE",
    );
    assert_eq!(epoch.load(Ordering::Acquire), 0);
}

#[test]
fn cached_permission_is_rechecked_after_actual_native_tcp_success() {
    let f = Fixture::new();
    let node = f.node();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let stopped = stop.clone();
    let policy = f.policy.clone();
    let server = thread::spawn(move || {
        ingress::pq_network::serve_pq_authenticated(
            listener,
            node,
            Duration::from_secs(10),
            stopped,
            PqServer::new(policy, key(11)).unwrap(),
        )
        .unwrap()
    });
    let client = PqClient::new(f.policy.clone(), key(12)).unwrap();
    let prepared = client
        .prepare(1, ingress::now().unwrap() + 50, Request::Head)
        .unwrap();
    assert!(
        client
            .send(address, &prepared, Duration::from_secs(3))
            .unwrap()
            .ok
    );
    stop.store(true, Ordering::Release);
    assert_eq!(server.join().unwrap().accepted, 1);
    let mut reopened = f.reopen().unwrap();
    let request = f
        .policy
        .verify_request(prepared.wire(), ingress::now().unwrap())
        .unwrap();
    assert!(matches!(
        reopened
            .begin_pq_network_request(&f.policy, &request)
            .unwrap(),
        super::super::pq_network::PqReplay::Cached(_)
    ));
    reopened
        .db
        .execute("UPDATE pq_network_peer_v2 SET revoked=1", [])
        .unwrap();
    error(
        reopened.begin_pq_network_request(&f.policy, &request),
        "PQ_WITNESS_LOCAL_ROOT",
    );
}

#[test]
fn cold_reopen_rejects_oversized_metadata_and_accepts_exact_operator_repair() {
    for (key, expected) in [
        ("pq_network_owner_v2", "PQ_NETWORK_POLICY_REQUIRED"),
        (KEY, "PQ_WITNESS_BINDING_REQUIRED"),
        ("schema", "STORAGE_CONTEXT"),
        ("parameters", "STORAGE_CONTEXT"),
        ("genesis", "STORAGE_CONTEXT"),
    ] {
        let f = Fixture::new();
        let node = f.node();
        let original: Vec<u8> = node
            .db
            .query_row("SELECT value FROM metadata WHERE key=?", [key], |row| {
                row.get(0)
            })
            .unwrap();
        let retained = f.head();
        drop(node);
        let offline = Connection::open(f.database()).unwrap();
        assert_eq!(
            offline
                .execute(
                    "UPDATE metadata SET value=zeroblob(1048576) WHERE key=?",
                    [key],
                )
                .unwrap(),
            1
        );
        drop(offline);
        error(f.reopen(), expected);
        assert_eq!(f.head(), retained);
        // Explicit exact-value operator repair is not automatic enrollment or
        // a rollback to an older external checkpoint.
        let offline = Connection::open(f.database()).unwrap();
        assert_eq!(
            offline
                .execute(
                    "UPDATE metadata SET value=? WHERE key=?",
                    params![original, key],
                )
                .unwrap(),
            1
        );
        drop(offline);
        let reopened = f.reopen().unwrap();
        assert_eq!(checkpoint(&reopened.db).unwrap(), retained);
        assert_eq!(f.head(), retained);
    }
}

struct CountedTransport {
    inner: Transport,
    operations: Arc<Mutex<Vec<u8>>>,
}
impl WitnessTransport for CountedTransport {
    fn exchange(&mut self, request: &[u8], until: Instant) -> Result<Vec<u8>> {
        self.operations.lock().unwrap().push(request[4]);
        self.inner.exchange(request, until)
    }
}
fn counted_node(f: &Fixture) -> (Node, Arc<Mutex<Vec<u8>>>) {
    let operations = Arc::new(Mutex::new(Vec::new()));
    let witness = WitnessClient::new(
        Fixture::make_binding(&f.policy, 1),
        key(14),
        Box::new(CountedTransport {
            inner: Transport {
                service: f.service.clone(),
                mode: f.mode.clone(),
                captured: f.captured.clone(),
            },
            operations: operations.clone(),
        }),
    )
    .unwrap();
    let node =
        Node::create_with_pq_witness(&f.node_path(), f.settings.clone(), 1, &f.policy, witness)
            .unwrap();
    operations.lock().unwrap().clear();
    (node, operations)
}

#[test]
fn ordinary_admission_reuses_fresh_witness_guard_without_rechecking_unchanged_state() {
    let f = Fixture::new();
    let request = f.request(1);
    let (mut node, operations) = counted_node(&f);
    let before = checkpoint(&node.db).unwrap();
    let super::super::pq_network::PqReplay::Execute(epoch, expected) =
        node.begin_pq_network_request(&f.policy, &request).unwrap()
    else {
        panic!("fresh signed request must obtain Execute");
    };
    assert_eq!(*operations.lock().unwrap(), [1, 2]);
    assert_eq!(records(&node), 1);
    let pending = checkpoint(&node.db).unwrap();
    assert_eq!(pending.sequence, before.sequence + 1);
    assert_eq!(pending, f.head());

    operations.lock().unwrap().clear();
    let super::super::pq_network::PqReplay::Execute(replayed_epoch, replayed_expected) =
        node.begin_pq_network_request(&f.policy, &request).unwrap()
    else {
        panic!("retained pending request must preserve ordinary recovery");
    };
    assert_eq!(*operations.lock().unwrap(), [1]);
    assert_eq!(records(&node), 1);
    assert_eq!(checkpoint(&node.db).unwrap(), pending);
    assert_eq!(replayed_expected, expected);
    assert!(Arc::ptr_eq(&replayed_epoch, &epoch));
    drop(node);
    let reopened = f.reopen().unwrap();
    assert_eq!(records(&reopened), 1);
    assert_eq!(checkpoint(&reopened.db).unwrap(), pending);
}

#[test]
fn expired_admission_commits_retirement_then_obtains_a_new_witness_guard() {
    let f = Fixture::new();
    let expiry = ingress::now().unwrap() + 1;
    let request = f.request_at(1, expiry);
    let (mut node, operations) = counted_node(&f);
    let super::super::pq_network::PqReplay::Execute(epoch, expected) =
        node.begin_pq_network_request(&f.policy, &request).unwrap()
    else {
        panic!("fresh signed request must obtain Execute");
    };
    let before = checkpoint(&node.db).unwrap();
    while ingress::now().unwrap() <= expiry {
        thread::sleep(Duration::from_millis(10));
    }
    operations.lock().unwrap().clear();
    let next = f.request(2);
    assert!(matches!(
        node.begin_pq_network_request(&f.policy, &next).unwrap(),
        super::super::pq_network::PqReplay::Execute(_, _)
    ));
    assert_eq!(*operations.lock().unwrap(), [1, 2, 1, 2]);
    assert!(epoch.load(Ordering::Acquire) > expected);
    let (status, highest): (u64, u64) = node
        .db
        .query_row(
            "SELECT r.status,p.highest_sequence FROM pq_network_request_v2 r JOIN pq_network_peer_v2 p ON r.peer=p.peer WHERE r.sequence=1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!((status, highest), (2, 1));
    assert_eq!(records(&node), 2);
    let after = checkpoint(&node.db).unwrap();
    assert_eq!(after.sequence, before.sequence + 2);
    assert_eq!(after, f.head());
    drop(node);
    let reopened = f.reopen().unwrap();
    assert_eq!(records(&reopened), 2);
    assert_eq!(checkpoint(&reopened.db).unwrap(), after);
}
