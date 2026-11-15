use super::*;
use openssl::pkey::{KeyType, PKey};
use std::net::TcpListener;
use std::sync::Arc;
use trnm_crypto_primitives::pq_auth::PqNativeSigningKey;
use trnm_protocol::pq_frame::ml_dsa_65_key_id_from_spki;
use zeroize::Zeroizing;

fn signing(seed: u8) -> PqNativeSigningKey {
    let key = PKey::private_key_from_seed(None, KeyType::ML_DSA_65, None, &[seed; 32]).unwrap();
    let id = ml_dsa_65_key_id_from_spki(&key.public_key_to_der().unwrap()).unwrap();
    PqNativeSigningKey::from_owned_key(key, id).unwrap()
}
fn identity(seed: u8) -> PqPublicIdentity {
    PqPublicIdentity::from_owned_seed(Zeroizing::new([seed; 32]), signing(seed).public_key_id())
        .unwrap()
}
struct Fixture {
    _directory: tempfile::TempDir,
    node: Node,
    native: PqClient,
    history: PqPublicIdentity,
}
impl Fixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let settings =
            crate::Settings::development(Some(crate::ingress::now().unwrap() - 100)).unwrap();
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
        let node = Node::open_with_pq_network(directory.path(), settings, 1, &policy).unwrap();
        Self {
            _directory: directory,
            node,
            native: PqClient::new(policy, signing(72)).unwrap(),
            history: identity(72),
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
}

#[test]
fn paired_context_binds_real_native_owner_peer_history_policy_and_endpoints() {
    let f = Fixture::new();
    let address = SocketAddr::from(([127, 0, 0, 1], 12001));
    let first = f.client(address);
    assert_eq!(first.context_id(), f.client(address).context_id());
    assert_ne!(
        first.context_id(),
        f.client(SocketAddr::from(([127, 0, 0, 1], 12002)))
            .context_id()
    );
    let changed = PinnedPqRecoveryClient::new(
        &f.node,
        PqRecoveryTransport::AuthenticatedLoopback(&f.native),
        address,
        address,
        &f.history,
        PublicPolicy::new(15, Duration::from_secs(2)).unwrap(),
    )
    .unwrap();
    assert_ne!(first.context_id(), changed.context_id());
    assert_eq!(first.peer_key_id(), signing(72).public_key_id());
    first.validate_for_node(&f.node).unwrap();
    let directory = tempfile::tempdir().unwrap();
    let next_policy = Arc::new(
        PqNetworkPolicy::new(
            f.node.settings(),
            signing(71).public_spki(),
            2,
            [
                signing(72).public_spki().to_vec(),
                signing(73).public_spki().to_vec(),
            ],
        )
        .unwrap(),
    );
    let next_node =
        Node::open_with_pq_network(directory.path(), f.node.settings().clone(), 1, &next_policy)
            .unwrap();
    let next_native = PqClient::new(next_policy, signing(72)).unwrap();
    let next = PinnedPqRecoveryClient::new(
        &next_node,
        PqRecoveryTransport::AuthenticatedLoopback(&next_native),
        address,
        address,
        &f.history,
        PublicPolicy::development(),
    )
    .unwrap();
    assert_ne!(first.context_id(), next.context_id());
    assert!(first.validate_for_node(&next_node).is_err());
}

#[test]
fn paired_context_refuses_classical_owner_wrong_caller_and_nonloopback_before_io() {
    let f = Fixture::new();
    let address = SocketAddr::from(([127, 0, 0, 1], 0));
    let directory = tempfile::tempdir().unwrap();
    let classical = Node::open(directory.path(), f.node.settings().clone(), 1).unwrap();
    assert!(PinnedPqRecoveryClient::new(
        &classical,
        PqRecoveryTransport::AuthenticatedLoopback(&f.native),
        address,
        address,
        &f.history,
        PublicPolicy::development(),
    )
    .is_err());
    assert!(PinnedPqRecoveryClient::new(
        &f.node,
        PqRecoveryTransport::AuthenticatedLoopback(&f.native),
        address,
        address,
        &identity(73),
        PublicPolicy::development(),
    )
    .is_err());
    assert!(PinnedPqRecoveryClient::new(
        &f.node,
        PqRecoveryTransport::AuthenticatedLoopback(&f.native),
        address,
        SocketAddr::from(([192, 0, 2, 1], 9)),
        &f.history,
        PublicPolicy::development(),
    )
    .is_err());
}

#[test]
fn paired_history_mutation_and_expired_epoch_refuse_without_tcp() {
    let f = Fixture::new();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let client = f.client(listener.local_addr().unwrap());
    let (mutating, _) = client.read_history(
        &f.node,
        &HistoryRequest::Submit {
            packet: "00".into(),
        },
        Instant::now() + Duration::from_secs(2),
    );
    assert_eq!(
        mutating.unwrap_err().to_string(),
        "PQ_PARENT_RECOVERY_HISTORY_READ_ONLY"
    );
    let (late, _) = client.read_history(&f.node, &HistoryRequest::Head, Instant::now());
    assert_eq!(late.unwrap_err().to_string(), "SUBMIT_RECOVERY_DEADLINE");
    assert_eq!(
        listener.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
}

#[test]
fn historical_request_metadata_is_exact_payload_bound_without_live_conversion() {
    let f = Fixture::new();
    let client = f.client(SocketAddr::from(([127, 0, 0, 1], 0)));
    let expiry = crate::ingress::now().unwrap() + 30;
    let prepared = client.prepare(4, expiry, Request::Head).unwrap();
    let metadata = client
        .audit_retained_request(prepared.wire(), &Request::Head)
        .unwrap();
    assert_eq!(metadata, (4, expiry, prepared.operation_id()));
    assert!(client
        .audit_retained_request(
            prepared.wire(),
            &Request::Submit {
                packet: "00".into()
            },
        )
        .is_err());
    let restored = client.restore_prepared(prepared.wire()).unwrap();
    assert_eq!(restored.wire(), prepared.wire());
}

#[test]
fn selected_native_account_codec_identifies_npq6_packet_without_classical_decode() {
    use std::collections::BTreeSet;
    use trnm_mvcc_fee::pon_executor::pq_accounts_v2::{
        application_v6::ApplicationPolicy, GenesisAccount,
    };
    let now = crate::ingress::now().unwrap();
    let accounts: Vec<_> = [81u8, 82, 83]
        .into_iter()
        .map(|seed| GenesisAccount {
            spki: identity(seed).public_spki().to_vec(),
            balance: 1_000_000,
        })
        .collect();
    let application = ApplicationPolicy {
        evaluators: accounts
            .iter()
            .take(2)
            .map(|account| ml_dsa_65_key_id_from_spki(&account.spki).unwrap())
            .collect::<BTreeSet<_>>(),
        evaluation_profile: trnm_mvcc_fee::public_evaluation::PROFILE.into(),
        model_profile: "linear-expert-dev-v1".into(),
    };
    let settings = Settings::native_pq_application_v6(&accounts, now - 100, &application).unwrap();
    let policy = Arc::new(
        PqNetworkPolicy::new(
            &settings,
            signing(71).public_spki(),
            1,
            [signing(72).public_spki().to_vec()],
        )
        .unwrap(),
    );
    let directory = tempfile::tempdir().unwrap();
    let node = Node::open_with_pq_network(directory.path(), settings.clone(), 1, &policy).unwrap();
    let packet = node
        .make_consensus_maintenance(
            settings.genesis(),
            vec![],
            ml_dsa_65_key_id_from_spki(&accounts[0].spki).unwrap(),
            now - 50,
            4096,
        )
        .unwrap();
    let bytes = packet.encode_for_settings(&settings).unwrap();
    assert!(bytes.starts_with(b"PQP6"));
    assert!(crate::Packet::decode(&bytes).is_err());
    let native = PqClient::new(policy, signing(72)).unwrap();
    let history = identity(72);
    let address = SocketAddr::from(([127, 0, 0, 1], 0));
    let client = PinnedPqRecoveryClient::new(
        &node,
        PqRecoveryTransport::AuthenticatedLoopback(&native),
        address,
        address,
        &history,
        PublicPolicy::development(),
    )
    .unwrap();
    let request = Request::Submit {
        packet: hex::encode(bytes),
    };
    assert_eq!(
        client.packet_id(&request).unwrap(),
        Some(packet.id().unwrap())
    );
    assert_eq!(client.packet_id(&Request::Head).unwrap(), None);
    assert!(client
        .packet_id(&Request::Submit {
            packet: "00".into()
        })
        .is_err());
    client.validate_for_node(&node).unwrap();
}
