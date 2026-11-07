use super::*;
use openssl::pkey::{KeyType, PKey};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    io::Write,
    os::unix::fs::PermissionsExt,
    path::Path,
    process::{Command, Output, Stdio},
    sync::Arc,
};
use trnm_crypto_primitives::pq_auth::PqNativeSigningKey;
use trnm_mvcc_fee::pon_executor::{pq_accounts_v2::application_v6, Config};
use trnm_pon_node::pq_application_v6::{ApplicationPolicy, GenesisAccount};
use trnm_protocol::{
    pon_wire::{hash, Hash},
    pq_frame::ml_dsa_65_key_id_from_spki,
    pq_native_accounts_v2::{self as wire, AccountProfile},
};

#[path = "fixture/tasks.rs"]
mod tasks;

pub(super) struct Application {
    pub tls: Fixture,
    pub accounts: Vec<GenesisAccount>,
    pub application: ApplicationPolicy,
    pub ids: Vec<Hash>,
    pub cfg: Config,
    signers: Vec<PqNativeSigningKey>,
}
pub(super) struct Samples {
    pub packets: Vec<trnm_pon_node::Packet>,
    pub task: Hash,
    pub contribution: Hash,
}
impl Application {
    pub fn new() -> Self {
        let mut tls = Fixture::new();
        let keys: Vec<_> = [84, 85, 86, 87]
            .into_iter()
            .map(|seed| {
                PKey::private_key_from_seed(None, KeyType::ML_DSA_65, None, &[seed; 32]).unwrap()
            })
            .collect();
        let accounts: Vec<_> = keys
            .iter()
            .map(|key| GenesisAccount {
                spki: key.public_key_to_der().unwrap(),
                balance: 100_000_000,
            })
            .collect();
        let ids: Vec<_> = accounts
            .iter()
            .map(|a| ml_dsa_65_key_id_from_spki(&a.spki).unwrap())
            .collect();
        let application = ApplicationPolicy {
            evaluators: BTreeSet::from([ids[2], ids[3]]),
            evaluation_profile: trnm_mvcc_fee::public_evaluation::PROFILE.into(),
            model_profile: "linear-expert-dev-v1".into(),
        };
        let timestamp = tls.settings.genesis_time();
        let (cfg, _, genesis) =
            application_v6::genesis(&accounts, timestamp, &application).unwrap();
        tls.settings =
            Settings::native_pq_application_v6(&accounts, timestamp, &application).unwrap();
        assert_eq!(cfg.network, tls.settings.network());
        assert_eq!(cfg.parameters, tls.settings.parameters());
        assert_eq!(genesis, tls.settings.genesis());
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
        let signers = keys
            .into_iter()
            .zip(&ids)
            .map(|(key, id)| PqNativeSigningKey::from_owned_key(key, *id).unwrap())
            .collect();
        Self {
            tls,
            accounts,
            application,
            ids,
            cfg,
            signers,
        }
    }

    pub fn configuration(&self) -> Value {
        json!({"schema":"native-pq-application-local-config-v1",
            "owner_profile":"network_v2","genesis_time":self.tls.settings.genesis_time(),
            "network":hex::encode(self.tls.settings.network()),
            "parameters":hex::encode(self.tls.settings.parameters()),
            "genesis":hex::encode(self.tls.settings.genesis()),
            "network_policy":hex::encode(self.tls.policy.id()),"generation":1,
            "server_spki":hex::encode(self.tls.server.signer().public_spki()),
            "peer_spkis":[hex::encode(self.tls.peer.signer().public_spki()),
                hex::encode(self.tls.other.signer().public_spki())],
            "ca_certificate_sha256":hex::encode(self.tls.policy.tls_pins().unwrap().ca_certificate_sha256()),
            "server_name":self.tls.policy.tls_pins().unwrap().server_name(),
            "accounts":self.accounts.iter().map(|a|
                json!({"spki":hex::encode(&a.spki),"balance":a.balance})).collect::<Vec<_>>(),
            "application":{"evaluators":self.application.evaluators.iter().map(hex::encode).collect::<Vec<_>>(),
                "evaluation_profile":self.application.evaluation_profile,
                "model_profile":self.application.model_profile}})
    }
    pub fn open(&self, directory: &Path) -> Node {
        Node::open_with_pq_network(directory, self.tls.settings.clone(), 1, &self.tls.policy)
            .unwrap()
    }
    pub fn command(
        &self,
        files: &Path,
        directory: &Path,
        operation: &str,
        config: &Value,
    ) -> Command {
        self.command_with_pin(files, directory, operation, config, None)
    }
    pub fn command_with_pin(
        &self,
        files: &Path,
        directory: &Path,
        operation: &str,
        config: &Value,
        expected: Option<&str>,
    ) -> Command {
        let bytes = serde_json::to_vec(config).unwrap();
        let path = files.join("application.json");
        put(&path, &bytes);
        let mut command = Command::new(env!("CARGO_BIN_EXE_trnm-pon-node"));
        command
            .arg(operation)
            .arg("--development")
            .arg("--store")
            .arg(directory)
            .arg("--workers")
            .arg("1")
            .arg("--packet-stdin")
            .arg("--pq-application-config")
            .arg(path)
            .arg("--pq-application-config-sha256")
            .arg(
                expected
                    .map(str::to_owned)
                    .unwrap_or_else(|| hex::encode(Sha256::digest(&bytes))),
            )
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        command
    }
    pub fn call(
        &self,
        files: &Path,
        directory: &Path,
        operation: &str,
        packet: &trnm_pon_node::Packet,
    ) -> Value {
        let raw = packet.encode_for_settings(&self.tls.settings).unwrap();
        let config = self.configuration();
        let output = exchange(self.command(files, directory, operation, &config), &raw);
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let value: Value = serde_json::from_slice(&output.stdout).unwrap();
        let context = &value["pq_application_context"];
        assert_eq!(context.as_object().unwrap().len(), 10);
        assert_eq!(
            context["schema"],
            "native-pq-application-local-observation-v1"
        );
        assert_eq!(
            context["configuration_sha256"],
            hex::encode(Sha256::digest(serde_json::to_vec(&config).unwrap()))
        );
        assert_eq!(context["profile"], application_v6::PROFILE);
        assert_eq!(context["network"], config["network"]);
        assert_eq!(context["parameters"], config["parameters"]);
        assert_eq!(context["genesis"], config["genesis"]);
        assert_eq!(context["network_policy"], config["network_policy"]);
        assert_eq!(context["owner_profile"], "network_v2");
        assert_eq!(context["packet_sha256"], hex::encode(Sha256::digest(&raw)));
        assert_eq!(context["block"], hex::encode(packet.id().unwrap()));
        assert_eq!(context["block"], value["result"]["block"]);
        assert_eq!(value["whole_node_rollback_protection"], false);
        assert_eq!(value["production_activation"], false);
        value
    }
    fn signed(
        &self,
        who: usize,
        nonce: u64,
        kind: u8,
        payload: &[u8],
        source: Option<usize>,
    ) -> Vec<u8> {
        let common = wire::Common {
            context: wire::ChainContext {
                network: self.tls.settings.network(),
                parameters: self.tls.settings.parameters(),
                genesis: self.tls.settings.genesis(),
            },
            account: self.ids[who],
            nonce,
            generation: 1,
            expires_at: trnm_pon_node::ingress::now().unwrap() + 300,
            max_fee: 100_000,
        };
        let mut witnesses = vec![wire::WitnessKey {
            role: 1,
            generation: 1,
            key_id: self.ids[who],
            spki: None,
        }];
        let mut selected = vec![who];
        if let Some(index) = source {
            witnesses.push(wire::WitnessKey {
                role: 2,
                generation: 1,
                key_id: self.ids[index],
                spki: None,
            });
            selected.push(index);
        }
        let frames: Vec<_> = selected
            .into_iter()
            .enumerate()
            .map(|(index, key)| {
                let statement = wire::signing_statement_for_profile(
                    AccountProfile::ApplicationV6,
                    &common,
                    kind,
                    payload,
                    &witnesses,
                    index,
                )
                .unwrap();
                let signature = self.signers[key].sign_exact_message(&statement).unwrap();
                let mut frame = statement.to_vec();
                frame.extend((signature.len() as u16).to_be_bytes());
                frame.extend(signature);
                frame
            })
            .collect();
        wire::encode_for_profile(
            AccountProfile::ApplicationV6,
            &common,
            kind,
            payload,
            &witnesses,
            &frames,
        )
        .unwrap()
    }
    fn append(
        &self,
        node: &mut Node,
        packets: &mut Vec<trnm_pon_node::Packet>,
        rows: Vec<Vec<u8>>,
    ) {
        let height = packets.len() as u64 + 1;
        let parent = packets
            .last()
            .map(|p| p.id().unwrap())
            .unwrap_or(self.tls.settings.genesis());
        let packet = node
            .make_consensus_maintenance(
                parent,
                rows,
                self.ids[0],
                self.tls.settings.genesis_time() + 50 + height,
                4096,
            )
            .unwrap();
        let now = trnm_pon_node::ingress::now().unwrap();
        let id = node.admit(&packet, now).unwrap();
        node.activate_observed(id, now).unwrap();
        assert!(packet
            .encode_for_settings(&self.tls.settings)
            .unwrap()
            .starts_with(b"PQP6"));
        packets.push(packet);
    }
}
pub(super) fn put(path: &Path, data: &[u8]) {
    fs::write(path, data).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
}
pub(super) fn exchange(mut command: Command, packet: &[u8]) -> Output {
    let mut child = command.spawn().unwrap();
    if let Some(mut stdin) = child.stdin.take() {
        let _ = stdin.write_all(packet);
    }
    child.wait_with_output().unwrap()
}
