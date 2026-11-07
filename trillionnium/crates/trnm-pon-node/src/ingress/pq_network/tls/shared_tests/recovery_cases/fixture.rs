use super::*;
use trnm_protocol::pon_wire::Hash;

pub(super) struct Harness {
    producer: Option<Node>,
    producer_dir: tempfile::TempDir,
    _server_dir: tempfile::TempDir,
    pub packets: Vec<crate::Packet>,
    pub settings: Settings,
    pub policy: Arc<PqNetworkPolicy>,
    pub owner: Arc<Mutex<Node>>,
    pub native_address: SocketAddr,
    history_address: SocketAddr,
    fixture: Fixture,
    plain: PqClient,
    tls: Option<PqTlsClient>,
    identity: PqPublicIdentity,
    history_policy: PublicPolicy,
    stop: Arc<AtomicBool>,
    native_thread: Option<thread::JoinHandle<Result<PqNetworkMetrics>>>,
    history_thread: Option<thread::JoinHandle<Result<crate::ingress::public_v3::PublicMetrics>>>,
}
fn transfer(
    settings: &Settings,
    signer: &PqNativeSigningKey,
    sender: Hash,
    recipient: Hash,
    nonce: u64,
    now: u64,
) -> Vec<u8> {
    let common = account_wire::Common {
        context: account_wire::ChainContext {
            network: settings.network(),
            parameters: settings.parameters(),
            genesis: settings.genesis(),
        },
        account: sender,
        nonce,
        expires_at: now + 300,
        max_fee: 100_000,
        generation: 1,
    };
    let witnesses = [account_wire::WitnessKey {
        role: 1,
        generation: 1,
        key_id: sender,
        spki: None,
    }];
    let mut payload = recipient.to_vec();
    payload.extend(7_u64.to_le_bytes());
    payload.extend(0_u16.to_be_bytes());
    let statement = account_wire::signing_statement_for_profile(
        AccountProfile::ApplicationV6,
        &common,
        1,
        &payload,
        &witnesses,
        0,
    )
    .unwrap();
    let signature = signer.sign_exact_message(&statement).unwrap();
    let mut frame = statement.to_vec();
    frame.extend((signature.len() as u16).to_be_bytes());
    frame.extend(signature);
    account_wire::encode_for_profile(
        AccountProfile::ApplicationV6,
        &common,
        1,
        &payload,
        &witnesses,
        &[frame],
    )
    .unwrap()
}
impl Harness {
    pub fn new(encrypted: bool, count: usize) -> Self {
        let fixture = Fixture::new();
        let now = crate::ingress::now().unwrap();
        let keys: Vec<_> = [84, 85, 86].into_iter().map(fixtures::key).collect();
        let accounts: Vec<_> = keys
            .iter()
            .map(|key| GenesisAccount {
                spki: key.public_key_to_der().unwrap(),
                balance: 1_000_000,
            })
            .collect();
        let ids: Vec<_> = accounts
            .iter()
            .map(|a| ml_dsa_65_key_id_from_spki(&a.spki).unwrap())
            .collect();
        let application = ApplicationPolicy {
            evaluators: ids.iter().take(2).copied().collect::<BTreeSet<_>>(),
            evaluation_profile: trnm_mvcc_fee::public_evaluation::PROFILE.into(),
            model_profile: "linear-expert-dev-v1".into(),
        };
        let settings =
            Settings::native_pq_application_v6(&accounts, now - 100, &application).unwrap();
        let peer = fixture.peer.signer().public_spki().to_vec();
        let policy = Arc::new(if encrypted {
            PqNetworkPolicy::new_tls13(
                &settings,
                fixture.server.signer().public_spki(),
                1,
                [peer],
                fixture.policy.tls_pins().unwrap().clone(),
            )
            .unwrap()
        } else {
            PqNetworkPolicy::new(&settings, fixture.server.signer().public_spki(), 1, [peer])
                .unwrap()
        });
        let producer_dir = tempfile::tempdir().unwrap();
        let server_dir = tempfile::tempdir().unwrap();
        let mut producer =
            Node::open_with_pq_network(producer_dir.path(), settings.clone(), 1, &policy).unwrap();
        let owner = Arc::new(Mutex::new(
            Node::open_with_pq_network(server_dir.path(), settings.clone(), 1, &policy).unwrap(),
        ));
        let signer = PqNativeSigningKey::from_owned_key(keys[0].clone(), ids[0]).unwrap();
        let mut packets = Vec::new();
        let mut parent = settings.genesis();
        for height in 1..=count {
            let transaction = transfer(&settings, &signer, ids[0], ids[1], height as u64, now);
            let packet = producer
                .make_consensus_maintenance(
                    parent,
                    vec![transaction],
                    ids[0],
                    now - 50 + height as u64,
                    4096,
                )
                .unwrap();
            parent = producer.admit(&packet, now).unwrap();
            producer.activate_observed(parent, now).unwrap();
            assert!(packet
                .encode_for_settings(&settings)
                .unwrap()
                .starts_with(b"PQP6"));
            packets.push(packet);
        }
        let native_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let native_address = native_listener.local_addr().unwrap();
        let history_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let history_address = history_listener.local_addr().unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let history_policy = PublicPolicy::development();
        let identity = PqPublicIdentity::from_signing_key(fixture.peer.signer());
        let history_server = PublicServer::new_pq_history(
            PqPublicIdentity::from_signing_key(fixture.server.signer()),
            history_policy,
        )
        .unwrap();
        let plain = PqClient::new(policy.clone(), fixture.peer.signer()).unwrap();
        let tls = encrypted.then(|| {
            PqTlsClient::new(
                policy.clone(),
                fixture.peer.signer(),
                fixture.peer.tls(&fixture.ca),
            )
            .unwrap()
        });
        let native_owner = owner.clone();
        let native_stop = stop.clone();
        let native_thread = if encrypted {
            let server = PqTlsServer::new(
                policy.clone(),
                fixture.server.signer(),
                fixture.server.tls(&fixture.ca),
            )
            .unwrap();
            thread::spawn(move || {
                serve_pq_tls13_shared(
                    native_listener,
                    native_owner,
                    Duration::from_secs(30),
                    native_stop,
                    server,
                )
            })
        } else {
            let server = PqServer::new(policy.clone(), fixture.server.signer()).unwrap();
            thread::spawn(move || {
                serve_pq_authenticated_shared(
                    native_listener,
                    native_owner,
                    Duration::from_secs(30),
                    native_stop,
                    server,
                )
            })
        };
        let history_owner = owner.clone();
        let history_stop = stop.clone();
        let history_thread = thread::spawn(move || {
            serve_public_protected_v3(
                history_listener,
                history_owner,
                Duration::from_secs(30),
                history_stop,
                history_server,
            )
        });
        let selected = Self {
            producer: Some(producer),
            producer_dir,
            _server_dir: server_dir,
            packets,
            settings,
            policy,
            owner,
            native_address,
            history_address,
            fixture,
            plain,
            tls,
            identity,
            history_policy,
            stop,
            native_thread: Some(native_thread),
            history_thread: Some(history_thread),
        };
        // A socket binding is not an installed paid CPU owner. Finish one
        // actual pinned Head before starting the independently bounded campaign.
        let client = selected.client(native_address);
        let (ready, metrics) = client.read_history(
            selected.producer(),
            &HistoryRequest::Head,
            Instant::now() + Duration::from_secs(5),
        );
        let ready = ready.unwrap();
        assert!(ready.ok && metrics.solution_found);
        assert_eq!(ready.value["tip"], hex::encode(selected.settings.genesis()));
        selected
    }
    pub fn producer(&self) -> &Node {
        self.producer.as_ref().unwrap()
    }
    pub fn client(&self, native_address: SocketAddr) -> PinnedPqRecoveryClient<'_> {
        let transport = match self.tls.as_ref() {
            Some(client) => PqRecoveryTransport::HybridTlsLoopback(client),
            None => PqRecoveryTransport::AuthenticatedLoopback(&self.plain),
        };
        PinnedPqRecoveryClient::new(
            self.producer(),
            transport,
            native_address,
            self.history_address,
            &self.identity,
            self.history_policy,
        )
        .unwrap()
    }
    pub fn recover(
        &self,
        address: SocketAddr,
        packet: &crate::Packet,
        campaign: PqRecoveryCampaign<'_>,
    ) -> Result<PqSubmitRecoveryOutcome> {
        submit_with_pq_parent_recovery(self.producer(), &self.client(address), packet, campaign)
    }
    pub fn reopen(&mut self) {
        drop(self.producer.take());
        self.producer = Some(
            Node::open_with_pq_network(
                self.producer_dir.path(),
                self.settings.clone(),
                1,
                &self.policy,
            )
            .unwrap(),
        );
    }
    pub fn scripted_server(&self) -> PqServer {
        PqServer::new(self.policy.clone(), self.fixture.server.signer()).unwrap()
    }
    pub fn records(&self) -> u64 {
        self.owner
            .lock()
            .unwrap()
            .pq_network_status(&self.policy)
            .unwrap()["records"]
            .as_u64()
            .unwrap()
    }
}
impl Drop for Harness {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(worker) = self.native_thread.take() {
            let result = worker.join();
            if thread::panicking() {
                if !matches!(&result, Ok(Ok(_))) {
                    eprintln!("native recovery join during panic: {result:?}");
                }
            } else {
                result.unwrap().unwrap();
            }
        }
        if let Some(worker) = self.history_thread.take() {
            let result = worker.join();
            if thread::panicking() {
                if !matches!(&result, Ok(Ok(_))) {
                    eprintln!("history recovery join during panic: {result:?}");
                }
            } else {
                result.unwrap().unwrap();
            }
        }
    }
}
