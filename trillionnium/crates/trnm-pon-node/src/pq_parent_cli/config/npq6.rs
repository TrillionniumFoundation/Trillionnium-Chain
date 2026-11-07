//! Explicit protected NPQ6 genesis selection for the parent CLI only.
//! Public genesis inputs create no migration, remote trust or production claim.
use super::super::super::witness;
use super::{digest, ensure, need, spki, BTreeMap, Configuration, Result, Settings};
use serde::Deserialize;
use std::collections::BTreeSet;
use trnm_pon_node::pq_application_v6::{ApplicationPolicy, GenesisAccount};

const SCHEMA: &str = "native-pq-parent-npq6-tls-loopback-config-v1";

#[derive(Deserialize)]
struct Selector {
    schema: String,
}
#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum OwnerProfile {
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
struct Npq6Configuration {
    schema: String,
    owner_profile: OwnerProfile,
    genesis_time: u64,
    network: String,
    parameters: String,
    genesis: String,
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

/// The selector grants nothing. Both selected formats are subsequently decoded
/// by their complete strict DTO; even duplicate schema keys remain rejected.
/// Legacy v1/v2 return to the original parser and original owner checks.
pub(super) fn decode(
    bytes: &[u8],
    args: &BTreeMap<String, String>,
) -> Result<Option<(Configuration, Settings)>> {
    let selector: Selector = serde_json::from_slice(bytes)?;
    if selector.schema != SCHEMA {
        return Ok(None);
    }
    let selected: Npq6Configuration = serde_json::from_slice(bytes)?;
    ensure(selected.schema == SCHEMA, "PQ_TLS_CONFIG_SCHEMA")?;
    match selected.owner_profile {
        OwnerProfile::NetworkV2 => ensure(
            selected.witness.is_none() && !args.contains_key("--witness-writer-key"),
            "PQ_PARENT_NPQ6_OWNER_SELECTION",
        )?,
        OwnerProfile::WitnessV4 => {
            ensure(selected.witness.is_some(), "PQ_TLS_WITNESS_CONFIG_REQUIRED")?;
            need(args, "--witness-writer-key")?;
        }
    }
    let accounts = selected
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
    for value in selected.application.evaluators {
        let id = digest(&value)?;
        ensure(
            hex::encode(id) == value,
            "PQ_PARENT_NPQ6_EVALUATOR_ENCODING",
        )?;
        ensure(evaluators.insert(id), "PQ_PARENT_NPQ6_DUPLICATE_EVALUATOR")?;
    }
    let application = ApplicationPolicy {
        evaluators,
        evaluation_profile: selected.application.evaluation_profile,
        model_profile: selected.application.model_profile,
    };
    // The existing constructor retains every account/SPKI/issuance/profile and
    // evaluator constraint. No migration anchor, stored state or peer response
    // can supply or replace any of these independently pinned genesis inputs.
    let settings =
        Settings::native_pq_application_v6(&accounts, selected.genesis_time, &application)?;
    let config = Configuration {
        schema: selected.schema,
        genesis_time: selected.genesis_time,
        network: selected.network,
        parameters: selected.parameters,
        genesis: selected.genesis,
        generation: selected.generation,
        server_spki: selected.server_spki,
        peer_spkis: selected.peer_spkis,
        ca_certificate_sha256: selected.ca_certificate_sha256,
        server_name: selected.server_name,
        witness: selected.witness,
    };
    // The caller still compares all three context digests and builds the
    // original pinned transport and owner before opening either listener.
    Ok(Some((config, settings)))
}
