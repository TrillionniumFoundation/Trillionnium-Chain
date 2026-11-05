use super::*;
use crate::ingress::public_v3::{self as public, PublicPolicy, PublicServer};
use crate::{ingress, Node, Settings};
use std::{net::TcpListener, sync::mpsc, time::Duration};
use trnm_crypto_primitives::pon_work::{self, facts::WorkFactCache};
use trnm_protocol::pon_wire::{hash, Envelope};
fn identity(seed: u8) -> ingress::DevelopmentIdentity {
    ingress::DevelopmentIdentity::from_secret_hex(&hex::encode([seed; 32])).unwrap()
}
struct Stop(Arc<AtomicBool>);
impl Drop for Stop {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Release);
    }
}
#[test]
fn two_real_listeners_confirm_signed_work_while_bad_cached_request_is_in_flight() {
    let dir = tempfile::tempdir().unwrap();
    let client_dir = tempfile::tempdir().unwrap();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let settings = Settings::development(Some(now - 100)).unwrap();
    let mut n = Node::open(dir.path(), settings.clone(), 2).unwrap();
    n.enable_local_mempool(crate::PoolLimits {
        max_records: 16,
        max_bytes: 32768,
        max_group_members: 16,
        critical_reserve: 0,
        max_removals: 64,
        preview_miner: crate::development_public(0).unwrap(),
    })
    .unwrap();
    let key = trnm_crypto_primitives::signing_key_from_hex(&hex::encode(hash(
        b"DEV-ONLY-KEY",
        &[&1u64.to_le_bytes()],
    )))
    .unwrap();
    let txs: Vec<_> = (1..=8)
        .map(|nonce| {
            let mut payload = crate::development_public(21).unwrap().to_vec();
            payload.extend(1u64.to_le_bytes());
            let mut e = Envelope {
                network: settings.network(),
                sender: crate::development_public(1).unwrap(),
                nonce,
                expiry: 10000,
                fee_limit: 1_000_000,
                tag: 1,
                payload,
                signature: [0; 64],
            };
            e.signature = hex::decode(trnm_crypto_primitives::sign_hex(
                &key,
                &e.signing_digest().unwrap(),
            ))
            .unwrap()
            .try_into()
            .unwrap();
            e.encode().unwrap()
        })
        .collect();
    let p = n
        .make(
            settings.genesis(),
            txs.clone(),
            crate::development_public(0).unwrap(),
            now - 90,
            4096,
        )
        .unwrap();
    let owner = Arc::new(Mutex::new(n));
    let domain = ServiceMutationCpuDomain::standalone();
    let facts = WorkFactCache::new(4).unwrap();
    facts
        .verify(
            p.header.challenge(),
            p.header.work_task,
            p.header.target,
            &p.proof,
        )
        .unwrap();
    let mut bad = p.clone();
    let at = 4 + 8 * pon_work::CELLS;
    let old = u32::from_le_bytes(bad.proof[at..at + 4].try_into().unwrap());
    bad.proof[at..at + 4]
        .copy_from_slice(&(((u64::from(old) + 1) % pon_work::Q as u64) as u32).to_le_bytes());
    let stop = Arc::new(AtomicBool::new(false));
    let policy = PublicPolicy::new(8, Duration::from_secs(2)).unwrap();
    let (started_tx, started_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let release_rx = Mutex::new(release_rx);
    let waiting = AtomicBool::new(false);
    let mut client = Node::open(client_dir.path(), settings.clone(), 2).unwrap();
    thread::scope(|scope| {
        let servers: Vec<_> = (71..73)
            .map(|seed| {
                let listener = TcpListener::bind("127.0.0.1:0").unwrap();
                let address = listener.local_addr().unwrap();
                let server =
                    PublicServer::with_continuous_domain(identity(seed), policy, &domain).unwrap();
                assert!(server.mutation_cpu_domain().shares_domain_with(&domain));
                let n = owner.clone();
                let stopping = stop.clone();
                (
                    address,
                    seed,
                    scope.spawn(move || {
                        public::serve_public_protected_v3(
                            listener,
                            n,
                            Duration::from_secs(20),
                            stopping,
                            server,
                        )
                    }),
                )
            })
            .collect();
        let stop_guard = Stop(stop.clone());
        let bad_worker = scope.spawn(|| {
            ingress::dispatch_shared_with_metered_work_facts(
                &owner,
                ingress::Request::Submit {
                    packet: hex::encode(bad.encode().unwrap()),
                },
                &facts,
                &domain,
                &|| {
                    if facts.counters().hits > 0 && !waiting.swap(true, Ordering::AcqRel) {
                        started_tx.send(()).unwrap();
                        release_rx
                            .lock()
                            .unwrap()
                            .recv_timeout(Duration::from_secs(15))
                            .unwrap();
                    }
                    Ok(())
                },
            )
            .unwrap()
        });
        started_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        assert_eq!(domain.budget.lock().unwrap().in_flight, 1);
        for (address, seed, _) in &servers {
            let head = public::call_public_protected_v3(
                *address,
                &public::Request::Head,
                &settings,
                identity(*seed).public_key(),
                &identity(*seed + 10),
                policy,
            )
            .unwrap();
            assert!(head.ok);
            assert_eq!(head.value["height"], 0);
        }
        let accepted = public::call_public_protected_v3(
            servers[0].0,
            &public::Request::Submit {
                packet: hex::encode(p.encode().unwrap()),
            },
            &settings,
            identity(71).public_key(),
            &identity(85),
            policy,
        )
        .unwrap();
        assert!(accepted.ok, "{}", accepted.value);
        let mut tip = p.id().unwrap();
        for height in 2..=7 {
            let block = owner
                .lock()
                .unwrap()
                .make(
                    tip,
                    vec![],
                    crate::development_public(0).unwrap(),
                    now - 100 + height * 10,
                    4096,
                )
                .unwrap();
            let out = ingress::dispatch_shared_with_metered_work_facts(
                &owner,
                ingress::Request::Submit {
                    packet: hex::encode(block.encode().unwrap()),
                },
                &facts,
                &domain,
                &|| Ok(()),
            )
            .unwrap();
            assert!(out.native.is_ok());
            assert!(!out.cpu.accounting_unavailable);
            tip = block.id().unwrap();
        }
        // A separate client gets actual bytes over the other public socket and
        // runs its own original W1/M06 validation before depth/work confirmation.
        let mut after = settings.genesis();
        let mut pages = 0;
        while after != tip {
            let reply = public::call_public_protected_v3(
                servers[1].0,
                &public::Request::History {
                    tip: hex::encode(tip),
                    after: hex::encode(after),
                },
                &settings,
                identity(72).public_key(),
                &identity(86),
                policy,
            )
            .unwrap();
            assert!(reply.ok, "{}", reply.value);
            let packets = reply.value["packets"].as_array().unwrap();
            assert_eq!(packets.len(), 1);
            for bytes in packets {
                let packet =
                    crate::Packet::decode(&hex::decode(bytes.as_str().unwrap()).unwrap()).unwrap();
                after = client.admit(&packet, now).unwrap();
                client.activate(after).unwrap();
            }
            pages += 1;
            assert!(pages <= 7);
        }
        for tx in &txs {
            assert!(
                client
                    .confirmation(hash(b"tx-id", &[tx]), p.id().unwrap(), now)
                    .unwrap()
                    .confirmed
            );
        }
        assert_eq!(
            client.read_active().unwrap(),
            owner.lock().unwrap().read_active().unwrap()
        );
        // Bad request has remained alive during the entire honest confirmation.
        assert_eq!(domain.budget.lock().unwrap().in_flight, 1);
        release_tx.send(()).unwrap();
        let rejected = bad_worker.join().unwrap();
        assert_eq!(rejected.native.err().unwrap().to_string(), "WORK:Product");
        assert!(!rejected.cpu.accounting_unavailable);
        drop(stop_guard);
        for (_, _, server) in servers {
            server.join().unwrap().unwrap();
        }
        assert_eq!(domain.budget.lock().unwrap().in_flight, 0);
        println!("METERED_FACT_NETWORK listeners=2 honest_confirmed_transactions=8 native_blocks=7 downloaded_pages=7 concurrent_bad_requests=1 bad_rejected=true shared_domains=1 independent_client=true saturation_claim=false");
    });
    let state = client.read_active().unwrap();
    drop(client);
    let reopened = Node::open(client_dir.path(), settings, 2).unwrap();
    assert_eq!(reopened.read_active().unwrap(), state);
}
