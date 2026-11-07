use super::super::files::Point;
use super::super::{
    PqClient, PqNetworkPolicy, PqPublicIdentity, PqRecoveryTransport, PublicPolicy,
};
use super::*;
use crate::ingress::pq_network::{serve_pq_authenticated, PqServer};
use crate::{Node, Settings};
use openssl::pkey::{KeyType, PKey};
use std::fs::{File, Permissions};
use std::io::Write;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::os::unix::fs::{symlink, DirBuilderExt, PermissionsExt};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::thread;
use trnm_crypto_primitives::pq_auth::PqNativeSigningKey;
use trnm_protocol::pq_frame::ml_dsa_65_key_id_from_spki;
use zeroize::Zeroizing;

fn signing(seed: u8) -> PqNativeSigningKey {
    let key = PKey::private_key_from_seed(None, KeyType::ML_DSA_65, None, &[seed; 32]).unwrap();
    let id = ml_dsa_65_key_id_from_spki(&key.public_key_to_der().unwrap()).unwrap();
    PqNativeSigningKey::from_owned_key(key, id).unwrap()
}
struct Fixture {
    directory: tempfile::TempDir,
    node: Node,
    native: PqClient,
    history: PqPublicIdentity,
    policy: Arc<PqNetworkPolicy>,
}
impl Fixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let settings = Settings::development(Some(crate::ingress::now().unwrap() - 100)).unwrap();
        let policy = Arc::new(
            PqNetworkPolicy::new(
                &settings,
                signing(71).public_spki(),
                1,
                [
                    signing(72).public_spki().to_vec(),
                    signing(73).public_spki().to_vec(),
                ],
            )
            .unwrap(),
        );
        let node = Node::open_with_pq_network(&directory.path().join("node"), settings, 1, &policy)
            .unwrap();
        let history = PqPublicIdentity::from_owned_seed(
            Zeroizing::new([72; 32]),
            signing(72).public_key_id(),
        )
        .unwrap();
        Self {
            directory,
            node,
            native: PqClient::new(policy.clone(), signing(72)).unwrap(),
            history,
            policy,
        }
    }
    fn client(&self, address: SocketAddr) -> PinnedPqRecoveryClient<'_> {
        PinnedPqRecoveryClient::new(
            &self.node,
            PqRecoveryTransport::AuthenticatedLoopback(&self.native),
            address,
            address,
            &self.history,
            PublicPolicy::development(),
        )
        .unwrap()
    }
    fn path(&self) -> std::path::PathBuf {
        self.directory.path().join("outbox")
    }
    fn plan(&self) -> SubmitRecoveryPlan {
        let mut plan = SubmitRecoveryPlan::new(Duration::from_secs(60)).unwrap();
        plan.max_calls = 64;
        plan.max_parent_packets = 16;
        plan
    }
}
fn address() -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], 12001))
}
fn expiry() -> u64 {
    crate::ingress::now().unwrap() + 30
}
fn blob_path(path: &Path, blob: &Blob) -> std::path::PathBuf {
    path.join(format!("blob-{}", hex::encode(blob.digest)))
}
fn encoded_record(path: &Path, name: &str) -> Record {
    parse(&fs::read(path.join(name)).unwrap()).unwrap()
}
fn fault_write(path: &Path, raw: &[u8]) {
    let mut file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .mode(0o600)
        .open(path)
        .unwrap();
    file.write_all(raw).unwrap();
    file.sync_all().unwrap();
}
fn fault_blob(path: &Path, raw: &[u8]) -> Blob {
    let value = Blob {
        digest: hash(b"pq-parent-blob-v1", &[raw]),
        bytes: raw.len() as u32,
    };
    fault_write(&blob_path(path, &value), raw);
    value
}

#[test]
fn journal_cold_open_preserves_exact_wire_sequence_epoch_and_history_budget() {
    let f = Fixture::new();
    let client = f.client(address());
    let path = f.path();
    let plan = f.plan();
    let mut journal = Journal::initialize(&path, &client, [41; 32], 7, &plan).unwrap();
    journal.reserve_read().unwrap();
    journal.reserve_parent([42; 32]).unwrap();
    let prepared = journal
        .prepare_or_restore(&client, &Request::Head, expiry())
        .unwrap();
    let wire = prepared.wire().to_vec();
    journal.record_attempt().unwrap();
    let before_deadline = journal.record.epoch.deadline;
    drop(journal);
    let mut cold = Journal::open(&path, &client, [41; 32], 7).unwrap();
    assert_eq!(cold.record.epoch.deadline, before_deadline);
    assert!(cold.recovery_plan().unwrap().deadline <= plan.deadline);
    assert_eq!(cold.status().unwrap().used_calls, 2);
    assert_eq!(cold.status().unwrap().planned_parent_count, 1);
    assert_eq!(cold.cursor().unwrap(), 7);
    let pending = cold.pending_request().unwrap().unwrap();
    assert_eq!(pending.attempts, 1);
    assert_eq!(pending.sequence, 7);
    assert_eq!(pending.operation, prepared.operation_id());
    assert_eq!(pending.packet_id, None);
    assert_eq!(
        pending.canonical_request_json,
        serde_json::to_string(&Request::Head).unwrap()
    );
    assert_eq!(
        cold.prepare_or_restore(&client, &Request::Head, expiry() + 10)
            .unwrap()
            .wire(),
        wire
    );
}

#[test]
fn journal_blob_prewrite_cut_leaves_inert_orphan_without_sequence_or_budget_credit() {
    let f = Fixture::new();
    let client = f.client(address());
    let path = f.path();
    let mut journal = Journal::initialize(&path, &client, [41; 32], 1, &f.plan()).unwrap();
    let before = fs::read(path.join("journal")).unwrap();
    journal.files.fail_at = Some(Point::BlobReady);
    assert!(journal
        .prepare_or_restore(&client, &Request::Head, expiry())
        .is_err());
    assert!(journal.status().is_err());
    assert_eq!(fs::read(path.join("journal")).unwrap(), before);
    assert!(fs::read_dir(&path).unwrap().count() > 2);
    drop(journal);
    let mut cold = Journal::open(&path, &client, [41; 32], 1).unwrap();
    assert!(cold.pending_request().unwrap().is_none());
    assert_eq!(cold.status().unwrap().used_calls, 0);
    assert_eq!(cold.cursor().unwrap(), 1);
    cold.prepare_or_restore(&client, &Request::Head, expiry())
        .unwrap();
}

#[test]
fn journal_prepared_request_and_attempt_fsync_cuts_finish_exact_local_transition_on_cold_open() {
    let f = Fixture::new();
    let client = f.client(address());
    let path = f.path();
    let mut journal = Journal::initialize(&path, &client, [41; 32], 1, &f.plan()).unwrap();
    journal.files.fail_at = Some(Point::Prepared);
    assert!(journal
        .prepare_or_restore(&client, &Request::Head, expiry())
        .is_err());
    let proposed = encoded_record(&path, "prepared");
    let wire = fs::read(blob_path(&path, &proposed.operations[0].wire)).unwrap();
    drop(journal);
    let mut cold = Journal::open(&path, &client, [41; 32], 1).unwrap();
    assert_eq!(
        cold.prepare_or_restore(&client, &Request::Head, expiry())
            .unwrap()
            .wire(),
        wire
    );
    cold.files.fail_at = Some(Point::Prepared);
    assert!(cold.record_attempt().is_err());
    drop(cold);
    let mut reopened = Journal::open(&path, &client, [41; 32], 1).unwrap();
    assert_eq!(reopened.status().unwrap().used_calls, 1);
    assert_eq!(reopened.pending_request().unwrap().unwrap().attempts, 1);
    assert_eq!(
        reopened
            .prepare_or_restore(&client, &Request::Head, expiry())
            .unwrap()
            .wire(),
        wire
    );
    assert_eq!(reopened.cursor().unwrap(), 1);
}

#[test]
fn journal_unknown_publication_is_sticky_and_cold_replay_does_not_refund_attempt() {
    let f = Fixture::new();
    let client = f.client(address());
    let path = f.path();
    let mut journal = Journal::initialize(&path, &client, [41; 32], 1, &f.plan()).unwrap();
    journal
        .prepare_or_restore(&client, &Request::Head, expiry())
        .unwrap();
    journal.files.fail_at = Some(Point::Published);
    assert!(journal.record_attempt().is_err());
    assert!(journal.reserve_read().is_err());
    assert!(journal.cursor().is_err());
    drop(journal);
    let mut cold = Journal::open(&path, &client, [41; 32], 1).unwrap();
    assert_eq!(cold.status().unwrap().used_calls, 1);
    assert_eq!(cold.pending_request().unwrap().unwrap().attempts, 1);
    assert!(!path.join("prepared").exists());
}

#[test]
fn journal_lost_actual_tcp_ack_replays_original_wire_and_durably_consumes_only_signed_reply() {
    let f = Fixture::new();
    let path = f.path();
    let directory = tempfile::tempdir().unwrap();
    let settings = f.node.settings().clone();
    let node =
        Node::open_with_pq_network(directory.path(), settings.clone(), 1, &f.policy).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let client = f.client(address);
    let stop = Arc::new(AtomicBool::new(false));
    let flag = stop.clone();
    let server = PqServer::new(f.policy.clone(), signing(71)).unwrap();
    let server_thread = thread::spawn(move || {
        serve_pq_authenticated(listener, node, Duration::from_secs(20), flag, server)
    });
    let operation = (|| -> Result<()> {
        let mut journal = Journal::initialize(&path, &client, [41; 32], 1, &f.plan())?;
        let prepared = journal.prepare_or_restore(&client, &Request::Head, expiry())?;
        let original = prepared.wire().to_vec();
        journal.record_attempt()?;
        let mut socket = TcpStream::connect_timeout(&address, Duration::from_secs(2))?;
        socket.set_write_timeout(Some(Duration::from_secs(2)))?;
        socket.write_all(&(original.len() as u32).to_be_bytes())?;
        socket.write_all(&original)?;
        drop(socket);
        drop(journal); // The actual server response cannot reach this socket.
        let mut cold = Journal::open(&path, &client, [41; 32], 1)?;
        let replay = cold.prepare_or_restore(&client, &Request::Head, expiry() + 10)?;
        assert_eq!(replay.wire(), original);
        assert_eq!(cold.cursor()?, 1);
        cold.reserve_read()?; // A history observation reservation cannot consume the native sequence.
        assert_eq!(cold.cursor()?, 1);
        cold.record_attempt()?;
        let evidence = client.send(&replay, Duration::from_secs(5))?;
        assert!(evidence.response().ok);
        cold.files.fail_at = Some(Point::Prepared);
        assert!(cold.complete(&client, &evidence).is_err());
        drop(cold);
        let mut final_owner = Journal::open(&path, &client, [41; 32], 1)?;
        assert_eq!(final_owner.cursor()?, 2);
        assert_eq!(final_owner.status()?.used_calls, 3);
        assert!(final_owner.pending_request()?.is_none());
        assert_eq!(
            fs::read(blob_path(
                &path,
                final_owner.record.operations[0].reply.as_ref().unwrap()
            ))?,
            evidence.wire()
        );
        Ok(())
    })();
    stop.store(true, Ordering::Release);
    let terminal = server_thread.join().unwrap();
    operation.unwrap();
    terminal.unwrap();
    let reopened = Node::open_with_pq_network(directory.path(), settings, 1, &f.policy).unwrap();
    assert_eq!(reopened.pq_network_status(&f.policy).unwrap()["records"], 1);
    // Metadata checksums alone must never substitute for the retained server signature.
    let mut record = encoded_record(&path, "journal");
    let mut bad = fs::read(blob_path(
        &path,
        record.operations[0].reply.as_ref().unwrap(),
    ))
    .unwrap();
    bad[8 + 178] ^= 1;
    record.operations[0].reply = Some(fault_blob(&path, &bad));
    fault_write(&path.join("journal"), &serde_json::to_vec(&record).unwrap());
    assert!(Journal::open(&path, &client, [41; 32], 1).is_err());
}

#[test]
fn journal_cold_replay_rejects_context_initial_sequence_bad_signature_and_wrong_signed_sequence() {
    for fault in 0..4 {
        let f = Fixture::new();
        let client = f.client(address());
        let path = f.path();
        let mut journal = Journal::initialize(&path, &client, [41; 32], 1, &f.plan()).unwrap();
        journal
            .prepare_or_restore(&client, &Request::Head, expiry())
            .unwrap();
        drop(journal);
        if fault == 0 {
            assert!(Journal::open(
                &path,
                &f.client(SocketAddr::from(([127, 0, 0, 1], 12002))),
                [41; 32],
                1
            )
            .is_err());
        } else if fault == 1 {
            assert!(Journal::open(&path, &client, [41; 32], 2).is_err());
        } else {
            let mut record = encoded_record(&path, "journal");
            let wire = if fault == 2 {
                let mut wire = fs::read(blob_path(&path, &record.operations[0].wire)).unwrap();
                wire[8 + 178] ^= 1;
                wire
            } else {
                client
                    .prepare(9, expiry(), Request::Head)
                    .unwrap()
                    .wire()
                    .to_vec()
            };
            record.operations[0].wire = fault_blob(&path, &wire);
            fault_write(&path.join("journal"), &serde_json::to_vec(&record).unwrap());
            assert!(Journal::open(&path, &client, [41; 32], 1).is_err());
        }
    }
}

#[test]
fn journal_expired_unknown_request_is_never_resigned_or_replaced_by_new_expiry() {
    let f = Fixture::new();
    let client = f.client(address());
    let path = f.path();
    let mut journal = Journal::initialize(&path, &client, [41; 32], 1, &f.plan()).unwrap();
    let signed_expiry = crate::ingress::now().unwrap() + 2;
    let original = journal
        .prepare_or_restore(&client, &Request::Head, signed_expiry)
        .unwrap()
        .wire()
        .to_vec();
    journal.record_attempt().unwrap();
    drop(journal);
    thread::sleep(Duration::from_secs(3));
    let mut cold = Journal::open(&path, &client, [41; 32], 1).unwrap();
    let before = encoded_record(&path, "journal");
    assert!(cold
        .prepare_or_restore(&client, &Request::Head, expiry())
        .is_err());
    assert!(cold.record_attempt().is_err());
    assert!(cold.pending_request().is_err());
    assert!(cold.status().is_err());
    assert!(cold.cursor().is_err());
    assert!(cold.recovery_plan().is_err());
    assert!(cold.reserve_read().is_err());
    assert!(cold.reserve_parent([42; 32]).is_err());
    let after = encoded_record(&path, "journal");
    assert_eq!(after.pending_fence, Some(PendingFence::ExpiredUnconfirmed));
    assert_eq!(after.operations, before.operations);
    assert_eq!(after.epoch, before.epoch);
    assert_eq!(after.reads, before.reads);
    assert_eq!(after.parents, before.parents);
    assert_eq!(after.operations[0].expiry, signed_expiry);
    assert_eq!(after.operations[0].attempts, 1);
    assert_eq!(after.operations[0].sequence, 1);
    assert_eq!(after.revision, before.revision + 1);
    assert_eq!(
        fs::read(blob_path(&path, &after.operations[0].wire)).unwrap(),
        original
    );
    drop(cold);
    // open audits retained requests historically and never samples wall time.
    // Its exact fence error therefore does not depend on wall time staying expired.
    let error = match Journal::open(&path, &client, [41; 32], 1) {
        Ok(_) => panic!("a persisted expiry conclusion reopened"),
        Err(error) => error,
    };
    assert!(error.to_string().contains("PQ_RECOVERY_FENCED"));
}

#[test]
fn journal_original_rpc_submit_and_parent_caps_survive_real_cold_open() {
    let f = Fixture::new();
    let client = f.client(address());
    let path = f.path();
    let packet = f
        .node
        .make(
            f.node.settings().genesis(),
            vec![],
            crate::development_public(0).unwrap(),
            f.node.settings().genesis_time() + 10,
            4096,
        )
        .unwrap();
    let id = packet.id().unwrap();
    let body = Request::Submit {
        packet: hex::encode(packet.encode_for_settings(f.node.settings()).unwrap()),
    };
    let mut journal = Journal::initialize(&path, &client, id, 1, &f.plan()).unwrap();
    journal
        .prepare_or_restore(&client, &body, expiry())
        .unwrap();
    for _ in 0..3 {
        journal.record_attempt().unwrap();
    }
    for value in 1..=16 {
        journal.reserve_parent([value; 32]).unwrap();
    }
    drop(journal);
    let mut cold = Journal::open(&path, &client, id, 1).unwrap();
    assert!(cold.record_attempt().is_err());
    assert!(cold.reserve_parent([99; 32]).is_err());
    cold.reserve_parent([1; 32]).unwrap(); // Existing planned parent is not refunded or charged twice.
    assert_eq!(
        cold.status().unwrap().per_packet_submit_counts.get(&id),
        Some(&3)
    );
    assert_eq!(cold.status().unwrap().planned_parent_count, 16);
    for _ in 3..64 {
        cold.reserve_read().unwrap();
    }
    assert_eq!(cold.status().unwrap().used_calls, 64);
    let before = fs::read(path.join("journal")).unwrap();
    assert!(cold.reserve_read().is_err());
    assert_eq!(fs::read(path.join("journal")).unwrap(), before);
    drop(cold);
    let again = Journal::open(&path, &client, id, 1).unwrap();
    assert_eq!(again.status().unwrap().used_calls, 64);
}

#[test]
fn journal_cold_open_cannot_renew_expired_epoch_or_change_boot_namespace_identity() {
    let f = Fixture::new();
    let client = f.client(address());
    let path = f.path();
    let plan = SubmitRecoveryPlan::new(Duration::from_secs(5)).unwrap();
    let journal = Journal::initialize(&path, &client, [41; 32], 1, &plan).unwrap();
    drop(journal);
    thread::sleep(Duration::from_secs(6));
    let mut cold = Journal::open(&path, &client, [41; 32], 1).unwrap();
    assert!(cold.recovery_plan().is_err());
    assert!(cold.reserve_read().is_err());
    drop(cold);
    let mut record = encoded_record(&path, "journal");
    record.epoch.boot.inode ^= 1;
    fault_write(&path.join("journal"), &serde_json::to_vec(&record).unwrap());
    assert!(Journal::open(&path, &client, [41; 32], 1).is_err());
}

#[test]
fn journal_lock_inode_and_named_directory_replacement_fence_before_snapshot_publication() {
    for replace_directory in [false, true] {
        let f = Fixture::new();
        let client = f.client(address());
        let path = f.path();
        let mut journal = Journal::initialize(&path, &client, [41; 32], 1, &f.plan()).unwrap();
        journal
            .prepare_or_restore(&client, &Request::Head, expiry())
            .unwrap();
        let before = fs::read(path.join("journal")).unwrap();
        journal.files.callback = Some(Box::new(move |point, path| {
            if point == Point::Prepared {
                if replace_directory {
                    fs::rename(path, path.with_extension("held"))?;
                    std::fs::DirBuilder::new().mode(0o700).create(path)?;
                } else {
                    fs::rename(path.join("lock"), path.join("old-lock"))?;
                    let lock = OpenOptions::new()
                        .write(true)
                        .create_new(true)
                        .mode(0o600)
                        .open(path.join("lock"))?;
                    lock.sync_all()?;
                }
            }
            Ok(())
        }));
        assert!(journal.record_attempt().is_err());
        assert!(journal.status().is_err());
        let actual = if replace_directory {
            path.with_extension("held")
        } else {
            path.clone()
        };
        assert_eq!(fs::read(actual.join("journal")).unwrap(), before);
        assert!(actual.join("prepared").is_file());
    }
}

#[test]
fn journal_hard_links_symlinks_fifo_oversize_and_broad_modes_refuse_before_decode() {
    for fault in 0..5 {
        let f = Fixture::new();
        let client = f.client(address());
        let path = f.path();
        let journal = Journal::initialize(&path, &client, [41; 32], 1, &f.plan()).unwrap();
        drop(journal);
        let current = path.join("journal");
        if fault == 0 {
            fs::hard_link(&current, path.join("extra-link")).unwrap();
        }
        if fault == 1 {
            fs::rename(&current, path.join("old")).unwrap();
            symlink(path.join("old"), &current).unwrap();
        }
        if fault == 2 {
            fs::remove_file(&current).unwrap();
            assert!(std::process::Command::new("mkfifo")
                .arg("-m")
                .arg("600")
                .arg(&current)
                .status()
                .unwrap()
                .success());
        }
        if fault == 3 {
            File::options()
                .write(true)
                .open(&current)
                .unwrap()
                .set_len(MAX_METADATA as u64 + 1)
                .unwrap();
        }
        if fault == 4 {
            fs::set_permissions(&current, Permissions::from_mode(0o640)).unwrap();
        }
        assert!(Journal::open(&path, &client, [41; 32], 1).is_err());
    }
}

#[test]
fn journal_changed_held_blob_or_prepared_predecessor_never_becomes_a_new_publication() {
    for bad_predecessor in [false, true] {
        let f = Fixture::new();
        let client = f.client(address());
        let path = f.path();
        let mut journal = Journal::initialize(&path, &client, [41; 32], 1, &f.plan()).unwrap();
        journal
            .prepare_or_restore(&client, &Request::Head, expiry())
            .unwrap();
        let before = fs::read(path.join("journal")).unwrap();
        journal.files.fail_at = Some(Point::Prepared);
        assert!(journal.record_attempt().is_err());
        drop(journal);
        if bad_predecessor {
            let mut next = encoded_record(&path, "prepared");
            next.previous = Some([0; 32]);
            fault_write(&path.join("prepared"), &serde_json::to_vec(&next).unwrap());
        } else {
            let record = encoded_record(&path, "journal");
            let file = blob_path(&path, &record.operations[0].wire);
            let mut raw = fs::read(&file).unwrap();
            raw[8 + 178] ^= 1;
            fault_write(&file, &raw);
        }
        assert!(Journal::open(&path, &client, [41; 32], 1).is_err());
        assert_eq!(fs::read(path.join("journal")).unwrap(), before);
        assert!(path.join("prepared").is_file());
    }
}

#[test]
fn journal_actual_fsynced_candidate_inode_is_bound_for_fresh_and_existing_pending() {
    for mode in 0..3 {
        let f = Fixture::new();
        let client = f.client(address());
        let path = f.path();
        let mut journal = Journal::initialize(&path, &client, [41; 32], 1, &f.plan()).unwrap();
        let before = fs::read(path.join("journal")).unwrap();
        let body = serde_json::to_vec(&Request::Head).unwrap();
        let name = if mode == 0 {
            "prepared".to_owned()
        } else {
            format!(
                "blob-{}-pending",
                hex::encode(hash(b"pq-parent-blob-v1", &[&body]))
            )
        };
        if mode == 2 {
            fault_write(&path.join(&name), &body);
        }
        let replaced = Arc::new(AtomicBool::new(false));
        let observed = replaced.clone();
        journal.files.callback = Some(Box::new(move |point, root| {
            let target = root.join(&name);
            if point == Point::WriteSynced
                && target.is_file()
                && !observed.swap(true, Ordering::SeqCst)
            {
                let raw = fs::read(&target)?;
                let replacement = root.join("replacement-fault");
                let mut file = OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(&replacement)?;
                file.write_all(&raw)?;
                drop(file); // Intentionally not the synchronized inode.
                fs::rename(replacement, target)?;
            }
            Ok(())
        }));
        assert!(journal
            .prepare_or_restore(&client, &Request::Head, expiry())
            .is_err());
        assert!(replaced.load(Ordering::SeqCst));
        assert!(journal.status().is_err());
        assert_eq!(fs::read(path.join("journal")).unwrap(), before);
    }
}

#[test]
fn journal_parent_entry_sync_rechecks_the_named_root_before_initialization_returns() {
    let directory = tempfile::tempdir().unwrap();
    let parent = directory.path().join("parent");
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&parent)
        .unwrap();
    let path = parent.join("campaign");
    let held_parent = directory.path().join("held-parent");
    let old = parent.clone();
    let held = held_parent.clone();
    let reached = Arc::new(AtomicBool::new(false));
    let observed = reached.clone();
    let result = Files::acquire_with_fault(
        &path,
        true,
        Box::new(move |point, _| {
            if point == Point::ParentSynced {
                observed.store(true, Ordering::SeqCst);
                fs::rename(&old, &held)?;
                std::fs::DirBuilder::new().mode(0o700).create(&old)?;
            }
            Ok(())
        }),
    );
    assert!(result.is_err());
    assert!(reached.load(Ordering::SeqCst));
    assert!(held_parent.join("campaign/lock").is_file());
    assert!(!path.exists());
}

#[test]
fn journal_expiry_fence_prepared_cut_is_sticky_and_cold_completion_never_reopens() {
    let f = Fixture::new();
    let client = f.client(address());
    let path = f.path();
    let mut journal = Journal::initialize(&path, &client, [41; 32], 1, &f.plan()).unwrap();
    journal
        .prepare_or_restore(&client, &Request::Head, crate::ingress::now().unwrap() + 2)
        .unwrap();
    journal.record_attempt().unwrap();
    let before = encoded_record(&path, "journal");
    thread::sleep(Duration::from_secs(3));
    journal.files.fail_at = Some(Point::Prepared);
    assert!(journal.record_attempt().is_err());
    assert!(journal.pending_request().is_err());
    assert!(journal.status().is_err());
    assert_eq!(encoded_record(&path, "journal"), before);
    assert_eq!(
        encoded_record(&path, "prepared").pending_fence,
        Some(PendingFence::ExpiredUnconfirmed)
    );
    drop(journal);
    let error = match Journal::open(&path, &client, [41; 32], 1) {
        Ok(_) => panic!("prepared expiry fence reopened"),
        Err(error) => error,
    };
    assert!(error.to_string().contains("PQ_RECOVERY_FENCED"));
    let after = encoded_record(&path, "journal");
    assert_eq!(after.operations, before.operations);
    assert_eq!(after.epoch, before.epoch);
    assert_eq!(after.pending_fence, Some(PendingFence::ExpiredUnconfirmed));
    assert!(!path.join("prepared").exists());
    assert!(Journal::open(&path, &client, [41; 32], 1).is_err());
}

#[test]
fn journal_expiry_after_durable_attempt_keeps_the_reservation_and_fences_all_reentry() {
    let f = Fixture::new();
    let client = f.client(address());
    let path = f.path();
    let mut journal = Journal::initialize(&path, &client, [41; 32], 1, &f.plan()).unwrap();
    let prepared = journal
        .prepare_or_restore(&client, &Request::Head, crate::ingress::now().unwrap() + 2)
        .unwrap();
    let delayed = Arc::new(AtomicBool::new(false));
    let observed = delayed.clone();
    journal.files.callback = Some(Box::new(move |point, _| {
        if point == Point::Published && !observed.swap(true, Ordering::SeqCst) {
            thread::sleep(Duration::from_secs(3));
        }
        Ok(())
    }));
    assert!(journal.record_attempt().is_err());
    assert!(delayed.load(Ordering::SeqCst));
    assert!(journal.recovery_plan().is_err());
    assert!(journal.cursor().is_err());
    let after = encoded_record(&path, "journal");
    assert_eq!(after.operations[0].attempts, 1);
    assert_eq!(after.pending_fence, Some(PendingFence::ExpiredUnconfirmed));
    assert_eq!(
        fs::read(blob_path(&path, &after.operations[0].wire)).unwrap(),
        prepared.wire()
    );
    drop(journal);
    assert!(Journal::open(&path, &client, [41; 32], 1).is_err());
}

#[test]
fn journal_direct_send_expiry_fence_requires_exact_prepared_and_prior_attempt() {
    let f = Fixture::new();
    let path = f.path();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let client = f.client(listener.local_addr().unwrap());
    let mut journal = Journal::initialize(&path, &client, [41; 32], 1, &f.plan()).unwrap();
    let prepared = journal
        .prepare_or_restore(&client, &Request::Head, crate::ingress::now().unwrap() + 2)
        .unwrap();
    let unused = fs::read(path.join("journal")).unwrap();
    assert!(journal.fence_expired_unconfirmed(&prepared).is_err());
    assert_eq!(fs::read(path.join("journal")).unwrap(), unused);
    journal.record_attempt().unwrap();
    let before = encoded_record(&path, "journal");
    thread::sleep(Duration::from_secs(3));
    let error = match client.send(&prepared, Duration::from_secs(2)) {
        Ok(_) => panic!("expired request was sent"),
        Err(error) => error,
    };
    assert!(error.to_string().contains("PQ_NETWORK_EXPIRED_UNCONFIRMED"));
    assert_eq!(
        listener.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
    let other = client.prepare(9, expiry(), Request::Head).unwrap();
    assert!(journal.fence_expired_unconfirmed(&other).is_err());
    assert_eq!(encoded_record(&path, "journal"), before);
    journal.fence_expired_unconfirmed(&prepared).unwrap();
    assert!(journal.status().is_err());
    assert!(journal.pending_request().is_err());
    assert!(journal.cursor().is_err());
    assert!(journal.reserve_read().is_err());
    let after = encoded_record(&path, "journal");
    assert_eq!(after.pending_fence, Some(PendingFence::ExpiredUnconfirmed));
    assert_eq!(after.operations, before.operations);
    assert_eq!(after.epoch, before.epoch);
    assert_eq!(after.reads, before.reads);
    assert_eq!(after.parents, before.parents);
    drop(journal);
    let error = match Journal::open(&path, &client, [41; 32], 1) {
        Ok(_) => panic!("local send expiry conclusion reopened"),
        Err(error) => error,
    };
    assert!(error.to_string().contains("PQ_RECOVERY_FENCED"));
}

#[test]
fn journal_pre_io_recheck_binds_named_snapshot_without_changing_durable_budget() {
    let f = Fixture::new();
    let client = f.client(address());
    let path = f.path();
    let mut journal = Journal::initialize(&path, &client, [41; 32], 1, &f.plan()).unwrap();
    journal
        .prepare_or_restore(&client, &Request::Head, expiry())
        .unwrap();
    journal.record_attempt().unwrap();
    let before = fs::read(path.join("journal")).unwrap();
    journal.recheck().unwrap();
    assert_eq!(fs::read(path.join("journal")).unwrap(), before);
    assert_eq!(journal.status().unwrap().used_calls, 1);
    fs::rename(path.join("journal"), path.join("retained-original")).unwrap();
    fault_write(&path.join("journal"), &before); // Equal bytes, a different named inode.
    assert!(journal.recheck().is_err());
    assert!(journal.status().is_err());
    assert!(journal.cursor().is_err());
    assert!(journal.reserve_read().is_err());
    assert!(journal.record_attempt().is_err());
    assert_eq!(fs::read(path.join("journal")).unwrap(), before);
    assert_eq!(encoded_record(&path, "journal").operations[0].attempts, 1);
}
