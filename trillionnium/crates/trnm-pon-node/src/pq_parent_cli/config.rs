use super::*;
use openssl::{
    pkey::{PKey, Private},
    x509::X509,
};
use sha2::{Digest, Sha256};
use std::{path::Path, sync::Arc};
use trnm_crypto_primitives::pq_auth::PqNativeSigningKey;
use trnm_pon_node::{
    digest,
    ingress::{
        pq_network::{tls::PqTlsIdentity, PqNetworkPolicy, PqTlsPins},
        public_v3::{PqPublicIdentity, PublicPolicy},
    },
    Node, Settings,
};
use trnm_protocol::pq_frame::ml_dsa_65_key_id_from_spki;

#[path = "config/npq6.rs"]
mod npq6;

/// Uses the original TLS schemas and protected same-FD input function. A
/// policy-pinned peer key may sign both distinct native and History domains;
/// observing a local key's bytes never adds it to the protected peer roster.
pub(super) struct Material {
    pub settings: Settings,
    pub policy: Arc<PqNetworkPolicy>,
    pub history: PublicPolicy,
    witness: Option<super::super::witness::Configuration>,
    key: PKey<Private>,
    certificate: X509,
    ca: X509,
}

pub(super) fn load(args: &BTreeMap<String, String>) -> Result<Material> {
    let bytes = input(need(args, "--tls-config")?, 262_144, false)?;
    let expected = digest(need(args, "--tls-config-sha256")?)?;
    let actual: [u8; 32] = Sha256::digest(bytes.as_slice()).into();
    ensure(actual == expected, "PQ_TLS_CONFIG_PIN")?;
    let (config, settings) = match npq6::decode(&bytes, args)? {
        Some(selected) => selected,
        None => {
            let config: Configuration = serde_json::from_slice(&bytes)?;
            match config.schema.as_str() {
                "native-pq-tls-loopback-config-v1"
                    if config.witness.is_none() && !args.contains_key("--witness-writer-key") => {}
                "native-pq-tls-loopback-config-v2" => {
                    ensure(config.witness.is_some(), "PQ_TLS_WITNESS_CONFIG_REQUIRED")?;
                    need(args, "--witness-writer-key")?;
                }
                _ => return Err("PQ_TLS_CONFIG_SCHEMA".into()),
            }
            let settings = Settings::development(Some(config.genesis_time))?;
            (config, settings)
        }
    };
    ensure(
        digest(&config.network)? == settings.network()
            && digest(&config.parameters)? == settings.parameters()
            && digest(&config.genesis)? == settings.genesis(),
        "PQ_NETWORK_CONTEXT",
    )?;
    let server_spki = spki(&config.server_spki)?;
    let peers = config
        .peer_spkis
        .iter()
        .map(|s| spki(s))
        .collect::<Result<Vec<_>>>()?;
    let policy = Arc::new(PqNetworkPolicy::new_tls13(
        &settings,
        &server_spki,
        config.generation,
        peers,
        PqTlsPins::new(digest(&config.ca_certificate_sha256)?, config.server_name)?,
    )?);
    let history = PublicPolicy::new(
        u8::try_from(number(args, "--admission-bits", 16)?).map_err(|_| "PUBLIC_POLICY")?,
        Duration::from_millis(number(args, "--admission-ttl-ms", 2000)?),
    )?;
    ensure(
        history.pq_history_id() == digest(need(args, "--history-policy-sha256")?)?,
        "PQ_PARENT_HISTORY_POLICY_PIN",
    )?;
    let key = PKey::private_key_from_pem(&input(need(args, "--tls-key")?, 32_768, true)?)
        .map_err(|_| "PQ_TLS_LOCAL_KEY")?;
    let certificate = X509::from_pem(&input(need(args, "--tls-cert")?, 32_768, false)?)
        .map_err(|_| "PQ_TLS_LOCAL_CERTIFICATE")?;
    let ca = X509::from_pem(&input(need(args, "--tls-ca")?, 32_768, false)?)
        .map_err(|_| "PQ_TLS_CA_CERTIFICATE")?;
    Ok(Material {
        settings,
        policy,
        history,
        witness: config.witness,
        key,
        certificate,
        ca,
    })
}

impl Material {
    pub fn tls_identity(&self) -> Result<PqTlsIdentity> {
        PqTlsIdentity::new(self.certificate.clone(), self.key.clone(), self.ca.clone())
    }
    pub fn signer(&self) -> Result<PqNativeSigningKey> {
        let public = self
            .key
            .public_key_to_der()
            .map_err(|_| "PQ_TLS_LOCAL_KEY")?;
        let id = ml_dsa_65_key_id_from_spki(&public).map_err(|_| "PQ_TLS_LOCAL_KEY")?;
        PqNativeSigningKey::from_owned_key(self.key.clone(), id)
            .map_err(|_| "PQ_TLS_LOCAL_KEY".into())
    }
    pub fn history_identity(&self) -> Result<PqPublicIdentity> {
        Ok(PqPublicIdentity::from_signing_key(self.signer()?))
    }
    pub fn witness_selected(&self) -> bool {
        self.witness.is_some()
    }
    pub fn open_node(self, args: &BTreeMap<String, String>, workers: usize) -> Result<Node> {
        let store = Path::new(need(args, "--store")?);
        match self.witness {
            Some(config) => config.open_node(
                store,
                self.settings,
                workers,
                &self.policy,
                need(args, "--witness-writer-key")?,
            ),
            None => Node::open_with_pq_network(store, self.settings, workers, &self.policy),
        }
    }
}
