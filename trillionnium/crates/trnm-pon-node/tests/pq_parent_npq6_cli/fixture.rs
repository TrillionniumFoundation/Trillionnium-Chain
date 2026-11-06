use super::*;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    path::Path,
    process::{Command, Stdio},
    sync::Arc,
};
use trnm_crypto_primitives::pq_auth::PqNativeSigningKey;
use trnm_pon_node::pq_application_v6::{ApplicationPolicy, GenesisAccount};
use trnm_protocol::{
    pon_wire::Hash,
    pq_frame::ml_dsa_65_key_id_from_spki,
    pq_native_accounts_v2::{self as account_wire, AccountProfile},
};

pub(super) struct Profile {
    pub tls: Fixture,
    pub accounts: Vec<GenesisAccount>,
    pub application: ApplicationPolicy,
    signer: PqNativeSigningKey,
    sender: Hash,
    recipient: Hash,
}
impl Profile {
    pub fn new() -> Self {
        let mut tls = Fixture::new();
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
            .map(|account| ml_dsa_65_key_id_from_spki(&account.spki).unwrap())
            .collect();
        let application = ApplicationPolicy {
            evaluators: ids.iter().take(2).copied().collect::<BTreeSet<_>>(),
            evaluation_profile: trnm_mvcc_fee::public_evaluation::PROFILE.into(),
            model_profile: "linear-expert-dev-v1".into(),
        };
        tls.settings = Settings::native_pq_application_v6(
            &accounts,
            tls.settings.genesis_time(),
            &application,
        )
        .unwrap();
        tls.policy = Arc::new(
            PqNetworkPolicy::new_tls13(
                &tls.settings,
                tls.server.signer().public_spki(),
                1,
                [
                    tls.peer.signer().public_spki().to_vec(),
                    tls.other.signer().public_spki().to_vec(),
                ],
                tls.policy.tls_pins().unwrap().clone(),
            )
            .unwrap(),
        );
        Self {
            tls,
            accounts,
            application,
            signer: PqNativeSigningKey::from_owned_key(keys[0].clone(), ids[0]).unwrap(),
            sender: ids[0],
            recipient: ids[1],
        }
    }
    pub fn configuration(&self) -> Value {
        json!({"schema":"native-pq-parent-npq6-tls-loopback-config-v1",
            "owner_profile":"network_v2","genesis_time":self.tls.settings.genesis_time(),
            "network":hex::encode(self.tls.settings.network()),
            "parameters":hex::encode(self.tls.settings.parameters()),
            "genesis":hex::encode(self.tls.settings.genesis()),"generation":1,
            "server_spki":hex::encode(self.tls.server.signer().public_spki()),
            "peer_spkis":[hex::encode(self.tls.peer.signer().public_spki()),
                hex::encode(self.tls.other.signer().public_spki())],
            "ca_certificate_sha256":hex::encode(self.tls.policy.tls_pins().unwrap().ca_certificate_sha256()),
            "server_name":self.tls.policy.tls_pins().unwrap().server_name(),
            "accounts":self.accounts.iter().map(|account|
                json!({"spki":hex::encode(&account.spki),"balance":account.balance})).collect::<Vec<_>>(),
            "application":{"evaluators":self.application.evaluators.iter().map(hex::encode).collect::<Vec<_>>(),
                "evaluation_profile":self.application.evaluation_profile,
                "model_profile":self.application.model_profile}})
    }
    pub fn command(&self, files: &Path, store: &Path, name: &str, server: bool) -> Command {
        let command = support::command(&self.tls, files, store, name, server);
        with_configuration(command, files, &self.configuration())
    }
    pub fn pair(&self, files: &Path, store: &Path) -> Command {
        let mut command = self.command(files, store, "pq-parent-tls-serve", true);
        command.args([
            "--native-listen",
            "127.0.0.1:0",
            "--history-listen",
            "127.0.0.1:0",
            "--seconds",
            "30",
        ]);
        command
    }
    pub fn recover(
        &self,
        files: &Path,
        store: &Path,
        campaign: &Path,
        packet: &Path,
        bound: &Value,
        resume: bool,
    ) -> Command {
        let command = support::recovery(&self.tls, files, store, campaign, packet, bound, resume);
        with_configuration(command, files, &self.configuration())
    }
    pub fn head(&self, bound: &Value) -> Value {
        let identity = PqPublicIdentity::from_signing_key(self.tls.peer.signer());
        let (reply, metrics) = call_public_history_pq_v4(
            bound["history_listen"].as_str().unwrap().parse().unwrap(),
            &HistoryRequest::Head,
            &self.tls.settings,
            self.tls.server.signer().public_spki(),
            self.tls.server.signer().public_key_id(),
            &identity,
            support::history_policy(),
            Some(Instant::now() + Duration::from_secs(5)),
        );
        let reply = reply.unwrap();
        assert!(reply.ok && metrics.solution_found);
        reply.value
    }
    pub fn packets(&self, node: &mut Node, count: usize) -> Vec<trnm_pon_node::Packet> {
        let now = trnm_pon_node::ingress::now().unwrap();
        let mut parent = self.tls.settings.genesis();
        let mut result = Vec::new();
        for nonce in 1..=count {
            let common = account_wire::Common {
                context: account_wire::ChainContext {
                    network: self.tls.settings.network(),
                    parameters: self.tls.settings.parameters(),
                    genesis: self.tls.settings.genesis(),
                },
                account: self.sender,
                nonce: nonce as u64,
                expires_at: now + 300,
                max_fee: 100_000,
                generation: 1,
            };
            let witnesses = [account_wire::WitnessKey {
                role: 1,
                generation: 1,
                key_id: self.sender,
                spki: None,
            }];
            let mut payload = self.recipient.to_vec();
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
            let signature = self.signer.sign_exact_message(&statement).unwrap();
            let mut frame = statement.to_vec();
            frame.extend((signature.len() as u16).to_be_bytes());
            frame.extend(signature);
            let transaction = account_wire::encode_for_profile(
                AccountProfile::ApplicationV6,
                &common,
                1,
                &payload,
                &witnesses,
                &[frame],
            )
            .unwrap();
            let packet = node
                .make_consensus_maintenance(
                    parent,
                    vec![transaction],
                    self.sender,
                    self.tls.settings.genesis_time() + 50 + nonce as u64,
                    4096,
                )
                .unwrap();
            parent = node.admit(&packet, now).unwrap();
            node.activate_observed(parent, now).unwrap();
            assert!(packet
                .encode_for_settings(&self.tls.settings)
                .unwrap()
                .starts_with(b"PQP6"));
            result.push(packet);
        }
        result
    }
}
pub(super) fn with_configuration(command: Command, files: &Path, value: &Value) -> Command {
    with_raw_configuration(command, files, &serde_json::to_vec(value).unwrap())
}
pub(super) fn with_raw_configuration(command: Command, files: &Path, bytes: &[u8]) -> Command {
    support::put(&files.join("config.json"), bytes, false);
    let mut command = support::replace_arg(
        command,
        "--tls-config-sha256",
        hex::encode(Sha256::digest(bytes)),
    );
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    command
}
pub(super) fn refused(mut command: Command, store: &Path, expected: &str) {
    let output = command.output().unwrap();
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains(expected),
        "expected {expected}, actual {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        output.stdout.is_empty(),
        "a denied configuration must not bind listeners"
    );
    assert!(
        !store.exists(),
        "a denied configuration must not create an owner"
    );
}
