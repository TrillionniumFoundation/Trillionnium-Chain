//! Actual >4096-block V3 continuity plus unknown-caller public History and a
//! separate native verifier. This is a local logical-time experiment, not WAN,
//! sustained public readiness or independent hardware measurement.
use serde_json::json;
use std::{
    fs,
    net::TcpListener,
    path::Path,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread,
    time::{Duration, Instant},
};
use trnm_crypto_primitives::{
    qualified_work_task::{
        lifecycle_v2::verify_lifecycle_admission, DevelopmentTaskAdmission, TaskMaterial,
    },
    sign_hex, signing_key_from_hex,
};
use trnm_mvcc_fee::qualified_task_lifecycle::slot_key;
use trnm_pon_node::{
    development_public,
    ingress::{
        self,
        public_v2::{self, PublicPolicy, PublicServer},
        DevelopmentIdentity, Page, Request,
    },
    Node, Packet, Result, Settings,
};
use trnm_protocol::{
    pon_wire::{hash, Envelope},
    qualified_work_task::{
        lifecycle_v2::{DemandLeaseV2, SignedLifecycleTaskV2},
        lifecycle_v3::{AtomicRenewTaskV3, ATOMIC_RENEW_TAG, PROFILE},
    },
};
const BLOCKS: u64 = 4105;
fn codec<E: std::fmt::Debug>(e: E) -> trnm_pon_node::Error {
    format!("CODEC:{e:?}").into()
}
fn signature(who: u64, message: &[u8]) -> Result<[u8; 64]> {
    let key = signing_key_from_hex(&hex::encode(hash(b"DEV-ONLY-KEY", &[&who.to_le_bytes()])))
        .map_err(codec)?;
    Ok(hex::decode(sign_hex(&key, message))
        .map_err(codec)?
        .try_into()
        .map_err(|_| "SIGNATURE")?)
}
fn material<'a>(model: &'a [u8], input: &'a [u8], a: &'a [u32], b: &'a [u32]) -> TaskMaterial<'a> {
    TaskMaterial { model, input, a, b }
}
fn admission(
    signed: &SignedLifecycleTaskV2,
    lease: &DemandLeaseV2,
    material: TaskMaterial<'_>,
    height: u64,
) -> Result<DevelopmentTaskAdmission> {
    verify_lifecycle_admission(&signed.encode().map_err(codec)?, material, lease, height)
        .map_err(|e| format!("TASK_ADMISSION:{e:?}").into())
}
fn renewal(
    node: &Node,
    signed: &SignedLifecycleTaskV2,
    lease: &DemandLeaseV2,
    height: u64,
) -> Result<(Vec<u8>, DemandLeaseV2, SignedLifecycleTaskV2)> {
    let mut renewed = lease.clone();
    renewed.revision += 1;
    renewed.not_before = height;
    renewed.expires = height + 1000;
    renewed.available_until = renewed.expires + 100;
    let sequence = node.read_active()?.2[&slot_key(0)?]["source_sequence"]
        .as_u64()
        .ok_or("SEQUENCE")?
        + 1;
    let mut manifest = signed.manifest.clone();
    manifest.source_record = renewed.bound_source_record().map_err(codec)?;
    manifest.withdrawal_head = renewed.withdrawal_frontier().map_err(codec)?;
    manifest.not_before = renewed.not_before;
    manifest.expires = renewed.expires;
    manifest.available_until = renewed.available_until;
    manifest.demand_nonce = sequence;
    let mut replacement = SignedLifecycleTaskV2 {
        lease_id: renewed.id().map_err(codec)?,
        manifest,
        signature: [0; 64],
    };
    replacement.signature = signature(0, &replacement.signing_message().map_err(codec)?)?;
    let atomic = AtomicRenewTaskV3 {
        lease: renewed.clone(),
        signed: replacement.clone(),
    };
    let sender = development_public(1)?;
    let mut tx = Envelope {
        network: node.settings().network(),
        sender,
        nonce: node.next_nonce(sender)?,
        expiry: height + 100,
        fee_limit: 1_000_000,
        tag: ATOMIC_RENEW_TAG,
        payload: atomic.encode().map_err(codec)?,
        signature: [0; 64],
    };
    tx.signature = signature(1, &tx.signing_digest().map_err(codec)?)?;
    Ok((tx.encode().map_err(codec)?, renewed, replacement))
}
fn identity(n: u8) -> DevelopmentIdentity {
    DevelopmentIdentity::from_secret_hex(&hex::encode([n; 32])).unwrap()
}
fn run(directory: &Path) -> Result<serde_json::Value> {
    let started = Instant::now();
    let wall = ingress::now()?;
    let genesis = wall - (BLOCKS + 8) * 10;
    let settings = Settings::development_with_profiles(
        Some(genesis),
        "native-public-evaluation-dev-v1",
        PROFILE,
    )?;
    fs::create_dir(directory.join("packets"))?;
    let source = json!({"schema":"native-ancestry-long-sync-source-v1","integration_lineage_base":"56a7dfea51669cd829df95c64cbecbe2c4080e56","source_scope":"compiled native observation; exact executed source and binary must be bound by the external runner","index_source":hex::encode(hash(b"ancestry-long-source-v1",&[include_bytes!("../src/ancestry_index.rs")])),"test_source":hex::encode(hash(b"ancestry-long-source-v1",&[include_bytes!("ancestry_long_sync.rs")])),"public_network_ready":false,"hardness_accepted":false,"independent_accepted":false});
    fs::write(
        directory.join("source.json"),
        serde_json::to_vec_pretty(&source)?,
    )?;
    fs::write(
        directory.join("config.json"),
        serde_json::to_vec_pretty(
            &json!({"blocks":BLOCKS,"renew_every":900,"task_profile":PROFILE,"evaluation_policy":"native-public-evaluation-dev-v1","genesis_timestamp":genesis,"network":hex::encode(settings.network()),"parameters":hex::encode(settings.parameters()),"genesis":hex::encode(settings.genesis()),"clock_scope":"10-second logical headers under observed wall clock; no real-time long-window claim","public_network_ready":false,"hardness_accepted":false,"production_activation":false}),
        )?,
    )?;
    let bootstrap = settings.bootstrap_lifecycle_task()?;
    let (model, input, a, b) = settings.bootstrap_task_material()?;
    let mut lease = bootstrap.lease;
    let mut signed = bootstrap.signed;
    let mut node = Node::open(&directory.join("validator"), settings.clone(), 2)?;
    let mut renewals = 0;
    let mut proof_bytes = 0_u64;
    let mut packet_bytes = 0_u64;
    let mut first = None;
    for height in 1..=BLOCKS {
        let active = node.active()?.0;
        let current = admission(&signed, &lease, material(&model, &input, &a, &b), height)?;
        let mut next = None;
        let txs = if height.is_multiple_of(900) {
            let (raw, newlease, newsigned) = renewal(&node, &signed, &lease, height)?;
            next = Some((newlease, newsigned));
            renewals += 1;
            vec![raw]
        } else {
            vec![]
        };
        let packet = node.make_with_task(
            active,
            txs,
            development_public(3)?,
            genesis + height * 10,
            4096,
            &current,
            material(&model, &input, &a, &b),
        )?;
        let encoded = packet.encode()?;
        proof_bytes += packet.proof.len() as u64;
        packet_bytes += encoded.len() as u64;
        fs::write(
            directory.join("packets").join(format!("{height:05}.bin")),
            encoded,
        )?;
        let id = node.admit(&packet, ingress::now()?)?;
        node.activate_observed(id, ingress::now()?)?;
        if height == 1 {
            first = Some(id);
        }
        if let Some((newlease, newsigned)) = next {
            lease = newlease;
            signed = newsigned;
        }
        if height.is_multiple_of(900) || height == 1001 || height == 4097 {
            let before = node.read_active()?;
            drop(node);
            node = Node::open(&directory.join("validator"), settings.clone(), 2)?;
            if node.read_active()? != before {
                return Err("REOPEN_STATE".into());
            }
        }
        if height.is_multiple_of(500) {
            println!(
                "{}",
                json!({"kind":"actual-pnw1-progress","height":height,"elapsed_ns":started.elapsed().as_nanos()})
            );
        }
    }
    let tip = node.active()?.0;
    let expected = node.read_active()?;
    drop(node);
    // A random altered active-row seal must refuse reopen without repair.
    let db = rusqlite::Connection::open(directory.join("validator/native.sqlite"))?;
    let seal: Vec<u8> = db.query_row(
        "SELECT seal FROM ancestry_jump WHERE block=? AND level=12",
        [tip.as_slice()],
        |r| r.get(0),
    )?;
    db.execute(
        "UPDATE ancestry_jump SET seal=? WHERE block=? AND level=12",
        rusqlite::params![[0_u8; 32].as_slice(), tip.as_slice()],
    )?;
    drop(db);
    let rejected = Node::open(&directory.join("validator"), settings.clone(), 2)
        .err()
        .ok_or("CORRUPTION_ACCEPTED")?;
    if rejected.to_string() != "ANCESTRY_INDEX_SEAL" {
        return Err(format!("CORRUPTION_ERROR:{rejected}").into());
    }
    let db = rusqlite::Connection::open(directory.join("validator/native.sqlite"))?;
    db.execute(
        "UPDATE ancestry_jump SET seal=? WHERE block=? AND level=12",
        rusqlite::params![seal, tip.as_slice()],
    )?;
    drop(db);
    let node = Node::open(&directory.join("validator"), settings.clone(), 2)?;
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let address = listener.local_addr()?;
    let stop = Arc::new(AtomicBool::new(false));
    let signal = stop.clone();
    let server_pin = identity(111).public_key().to_owned();
    let policy = PublicPolicy::new(8, Duration::from_secs(2))?;
    let worker = thread::spawn(move || {
        public_v2::serve_public_protected_v2(
            listener,
            node,
            Duration::from_secs(1800),
            signal,
            PublicServer::new(identity(111), policy).unwrap(),
        )
    });
    let sync_result = (|| -> Result<(u64, u64, u64)> {
        let mut confirmer = Node::open(&directory.join("confirmer"), settings.clone(), 2)?;
        let caller = identity(112);
        let head = public_v2::call_public_protected_v2(
            address,
            &Request::Head,
            &settings,
            &server_pin,
            &caller,
            policy,
        )?;
        if !head.ok || head.value["tip"] != hex::encode(tip) || head.value["height"] != BLOCKS {
            return Err("PUBLIC_HEAD".into());
        }
        let mut after = settings.genesis();
        let mut count = 0;
        let mut trials = 0;
        let mut solve_ns = 0;
        while after != tip {
            let reply = public_v2::call_public_protected_v2(
                address,
                &Request::History {
                    tip: hex::encode(tip),
                    after: hex::encode(after),
                },
                &settings,
                &server_pin,
                &caller,
                policy,
            )?;
            if !reply.ok {
                return Err(format!("PUBLIC_HISTORY_REFUSED:{}", reply.value).into());
            }
            trials += reply.solve_trials;
            solve_ns += reply.solve_elapsed_ns;
            let page: Page = serde_json::from_value(reply.value)?;
            if page.packets.len() != 1 {
                return Err("PAGE_COUNT".into());
            }
            if count == 0
                && Packet::decode(&hex::decode(&page.packets[0]).map_err(codec)?)?.id()?
                    != first.ok_or("FIRST")?
            {
                return Err("LONG_FIRST_PAGE".into());
            }
            after = ingress::receive_page(&mut confirmer, page, tip, after, ingress::now()?)?;
            count += 1;
            if count < BLOCKS && confirmer.active()?.0 != settings.genesis() {
                return Err("PARTIAL_SYNC_ACTIVATED".into());
            }
            if count.is_multiple_of(500) {
                println!(
                    "{}",
                    json!({"kind":"independent-native-fullsync-progress","height":count,"elapsed_ns":started.elapsed().as_nanos()})
                );
            }
        }
        let confirmed = confirmer.read_active()?;
        if count != BLOCKS || confirmed.0 != expected.0 || confirmed.2 != expected.2 {
            return Err("CONFIRMATION_STATE".into());
        }
        drop(confirmer);
        if Node::open(&directory.join("confirmer"), settings.clone(), 2)?.read_active()?
            != confirmed
        {
            return Err("CONFIRMER_REOPEN".into());
        }
        Ok((count, trials, solve_ns))
    })();
    stop.store(true, Ordering::SeqCst);
    let metrics = worker.join().map_err(|_| "SERVER_JOIN")??;
    let (confirmed, solve_trials, solve_ns) = sync_result?;
    let stats = Node::open(&directory.join("validator"), settings.clone(), 2)?.stats()?;
    for key in [
        "authenticated_sessions",
        "authenticated_pending",
        "authenticated_audit_rows",
        "authenticated_outbox_sessions",
        "authenticated_outbox_pending",
    ] {
        if stats[key] != 0 {
            return Err("GUEST_DURABLE_IDENTITY".into());
        }
    }
    Ok(
        json!({"schema":"native-ancestry-long-sync-observation-v1","passed":true,"blocks":BLOCKS,"confirmed_packets":confirmed,"renewals":renewals,"proof_bytes":proof_bytes,"packet_bytes":packet_bytes,"per_page_sql_hard_cap":1024,"pinned_tip":hex::encode(tip),"public_solver_trials":solve_trials,"public_solver_ns":solve_ns,"public_metrics":metrics,"corrupt_active_index_reopen_refused":true,"elapsed_ns":started.elapsed().as_nanos(),"scope":"actual PNW1/native ledger/V3 renewals and separate verifier over paid loopback public RPC; logical header time, development source keys, single host, no WAN or independent measurement claim","public_network_ready":false,"hardness_accepted":false,"independent_accepted":false,"production_activation":false}),
    )
}
#[test]
#[ignore = "release actual 4105-PNW1 block V3 chain and 4105 paid public full-sync pages; run in a quiet resource window"]
fn actual_v3_long_chain_public_full_sync_reopen_and_corrupt_index_refusal() {
    let temporary = tempfile::tempdir().unwrap();
    let directory = match std::env::var_os("TRNM_INDEX_EVIDENCE_DIRECTORY") {
        Some(path) => {
            let p = std::path::PathBuf::from(path);
            fs::create_dir(&p).unwrap();
            p
        }
        None => temporary.path().join("observation"),
    };
    if !directory.exists() {
        fs::create_dir(&directory).unwrap();
    }
    let result = run(&directory);
    let summary = match &result {
        Ok(value) => value.clone(),
        Err(error) => {
            json!({"schema":"native-ancestry-long-sync-observation-v1","passed":false,"error":error.to_string(),"public_network_ready":false,"hardness_accepted":false,"independent_accepted":false,"production_activation":false})
        }
    };
    fs::write(
        directory.join("summary.json"),
        serde_json::to_vec_pretty(&summary).unwrap(),
    )
    .unwrap();
    println!("{}", summary);
    result.unwrap();
}
