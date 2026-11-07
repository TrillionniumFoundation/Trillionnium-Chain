//! Public, externally pinned NPQ6 genesis and existing-owner selection.
//! No migration anchor, stored row or peer may supply missing authority inputs.
use super::super::witness;
use super::{ensure, input, need, spki, BTreeMap, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use trnm_pon_node::{
    digest,
    ingress::pq_network::{PqNetworkPolicy, PqTlsPins},
    pq_application_v6::{ApplicationPolicy, GenesisAccount},
    Settings,
};

use trnm_protocol::pon_wire::Hash;

const SCHEMA: &str = "native-pq-application-local-config-v1";

#[derive(Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum OwnerProfile {
    NetworkV2,
    WitnessV4,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Account {
    spki: String,
    balance: u64,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Application {
    evaluators: Vec<String>,
    evaluation_profile: String,
    model_profile: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Configuration {
    schema: String,
    owner_profile: OwnerProfile,
    genesis_time: u64,
    network: String,
    parameters: String,
    genesis: String,
    network_policy: String,
    generation: u64,
    server_spki: String,
    peer_spkis: Vec<String>,
    ca_certificate_sha256: String,
    server_name: String,
    accounts: Vec<Account>,
    application: Application,
    #[serde(default, deserialize_with = "witness::present_configuration")]
    witness: Option<witness::Configuration>,
}

pub(super) struct Material {
    pub settings: Settings,
    pub policy: PqNetworkPolicy,
    pub witness: Option<witness::Configuration>,
    pub owner_profile: OwnerProfile,
    pub configuration_sha256: Hash,
}

pub(super) fn load(args: &BTreeMap<String, String>) -> Result<Material> {
    let bytes = input(need(args, "--pq-application-config")?, 262_144, false)?;
    let expected = digest(need(args, "--pq-application-config-sha256")?)?;
    let actual: Hash = Sha256::digest(bytes.as_slice()).into();
    ensure(actual == expected, "PQ_APPLICATION_CONFIG_PIN")?;
    let config: Configuration = serde_json::from_slice(&bytes)?;
    ensure(config.schema == SCHEMA, "PQ_APPLICATION_CONFIG_SCHEMA")?;
    match config.owner_profile {
        OwnerProfile::NetworkV2 => ensure(
            config.witness.is_none() && !args.contains_key("--witness-writer-key"),
            "PQ_APPLICATION_OWNER_SELECTION",
        )?,
        OwnerProfile::WitnessV4 => {
            let witness = config
                .witness
                .as_ref()
                .ok_or("PQ_TLS_WITNESS_CONFIG_REQUIRED")?;
            witness.require_existing_node()?;
            need(args, "--witness-writer-key")?;
        }
    }
    let accounts = config
        .accounts
        .into_iter()
        .map(|account| {
            Ok(GenesisAccount {
                spki: spki(&account.spki)?,
                balance: account.balance,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let mut evaluators = BTreeSet::new();
    for value in config.application.evaluators {
        ensure(
            evaluators.insert(digest(&value)?),
            "PQ_APPLICATION_DUPLICATE_EVALUATOR",
        )?;
    }
    let application = ApplicationPolicy {
        evaluators,
        evaluation_profile: config.application.evaluation_profile,
        model_profile: config.application.model_profile,
    };
    // The existing builder checks every account/key/issuance/profile and the
    // complete evaluator roster. This does not manufacture signed transactions.
    let settings =
        Settings::native_pq_application_v6(&accounts, config.genesis_time, &application)?;
    ensure(
        digest(&config.network)? == settings.network()
            && digest(&config.parameters)? == settings.parameters()
            && digest(&config.genesis)? == settings.genesis(),
        "PQ_NETWORK_CONTEXT",
    )?;
    let peers = config
        .peer_spkis
        .iter()
        .map(|value| spki(value))
        .collect::<Result<Vec<_>>>()?;
    let policy = PqNetworkPolicy::new_tls13(
        &settings,
        &spki(&config.server_spki)?,
        config.generation,
        peers,
        PqTlsPins::new(digest(&config.ca_certificate_sha256)?, config.server_name)?,
    )?;
    ensure(
        digest(&config.network_policy)? == policy.id(),
        "PQ_APPLICATION_NETWORK_POLICY",
    )?;
    Ok(Material {
        settings,
        policy,
        witness: config.witness,
        owner_profile: config.owner_profile,
        configuration_sha256: actual,
    })
}
