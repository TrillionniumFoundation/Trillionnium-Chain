//! Explicit finite-fixture client placement. The old outer-process experiment
//! remains selectable only by its original test. The new named composition
//! always uses the real fixed-Host actor for import, confirmation and snapshot.
//! No failure in that actor can fall back to an outer-process Node.
use super::{active_position, history_context, history_verifier, replay, support};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{fs, net::SocketAddr, path::Path};
use trnm_pon_node::{ingress, Node, Packet, Settings};
use trnm_protocol::pon_wire::Hash;

pub(super) const COMPOSITION_SCHEMA: &str = "pon-pure-fixed-host-client-composition-v1";

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum ClientMode {
    OriginalOuter,
    FixedHostV1,
}

pub(super) enum Client {
    OriginalOuter(Box<Node>),
    FixedHostV1(Box<history_verifier::Verifier>),
}

impl Client {
    pub(super) fn start(
        path: &Path,
        settings: &Settings,
        seed: &[Packet],
        mode: ClientMode,
    ) -> Self {
        match mode {
            ClientMode::OriginalOuter => {
                let mut node =
                    Node::open_with_authenticated_state(path, settings.clone(), 1).unwrap();
                replay(&mut node, seed);
                Self::OriginalOuter(Box::new(node))
            }
            ClientMode::FixedHostV1 => {
                Self::FixedHostV1(Box::new(history_verifier::Verifier::start(
                    path,
                    history_context::StateBackendChoice::AuthenticatedV1,
                    seed,
                    history_verifier::ResourceProfile::Strict,
                    history_verifier::ExecutionProfile::PureClientV1,
                )))
            }
        }
    }

    pub(super) fn initial_tip(&self) -> Hash {
        match self {
            Self::OriginalOuter(node) => node.read_active().unwrap().0,
            Self::FixedHostV1(verifier) => {
                serde_json::from_value(verifier.ready()["initial_tip"].clone()).unwrap()
            }
        }
    }

    pub(super) fn import(
        &mut self,
        source: SocketAddr,
        page: Value,
        tip: Hash,
        after: Hash,
        clock: u64,
        epoch: u64,
    ) -> (Result<Hash, String>, Value) {
        let (result, mut measurement) = match self {
            Self::OriginalOuter(node) => {
                let started = support::monotonic().saturating_sub(epoch);
                let cpu = support::thread_cpu();
                let result = serde_json::from_value::<ingress::Page>(page)
                    .map_err(|error| error.to_string())
                    .and_then(|page| {
                        ingress::receive_public_page_from(node, source, page, tip, after, clock)
                            .map_err(|error| error.to_string())
                    });
                let measurement = json!({"started_ns":started,
                    "ended_ns":support::monotonic().saturating_sub(epoch),
                    "thread_cpu_ns":support::cpu_delta(cpu)});
                (result, measurement)
            }
            Self::FixedHostV1(verifier) => verifier.import(source, page, tip, after, clock, epoch),
        };
        measurement["succeeded"] = json!(result.is_ok());
        (result, measurement)
    }

    pub(super) fn confirmation(
        &mut self,
        transaction: Hash,
        included: Hash,
        clock: u64,
        epoch: u64,
    ) -> (Result<Value, String>, Value) {
        let (result, mut measurement) = match self {
            Self::OriginalOuter(node) => {
                let started = support::monotonic().saturating_sub(epoch);
                let result = node.confirmation(transaction, included, clock);
                let measurement = json!({"started_ns":started,
                    "ended_ns":support::monotonic().saturating_sub(epoch)});
                (
                    result
                        .map(|value| json!(value))
                        .map_err(|error| error.to_string()),
                    measurement,
                )
            }
            Self::FixedHostV1(verifier) => {
                verifier.confirmation(transaction, included, clock, epoch)
            }
        };
        measurement["succeeded"] = json!(result.is_ok());
        (result, measurement)
    }

    pub(super) fn snapshot_position(&mut self) -> (Hash, u64, u64) {
        match self {
            Self::OriginalOuter(node) => active_position(node),
            Self::FixedHostV1(verifier) => {
                let (active, _, height) = verifier.snapshot();
                (
                    active.0,
                    height.expect("explicit pure-client actual record height"),
                    active.1,
                )
            }
        }
    }

    pub(super) fn finish(self) -> Option<Value> {
        match self {
            Self::OriginalOuter(_) => None,
            Self::FixedHostV1(verifier) => Some(verifier.finish()),
        }
    }
}

/// The original report layout and all original service/cost predicates remain
/// intact. This additional closed namespace identifies the new composition;
/// the mandatory new reader also reads every actual actor IPC byte.
pub(super) fn bind_phase(report: &mut Value, process: Option<Value>, addresses: &[SocketAddr]) {
    if let Some(process) = process {
        report["client_execution_profile"] = json!(history_verifier::PURE_CLIENT_PROFILE);
        report["history_resource_profile"] = json!("strict-every-native-checkpoint-v1");
        report["state_backend"] = json!("authenticated-v1");
        report["addresses"] = json!(addresses
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>());
        report["history_verifier_process"] = process;
    }
}

pub(super) fn write_composition(root: &Path, mode: ClientMode, experiment: &str) {
    if mode == ClientMode::OriginalOuter {
        return;
    }
    let selector = match experiment {
        "pure-pressure" => "pure_pon_cold_shared_domain_pressure_fixed_host_client_v1",
        "receiver-owner-supplement" => {
            "receiver_owner::whole_receiver_owner_pressure_fixed_host_client_v1"
        }
        _ => panic!("closed pure-client composition required"),
    };
    let phases: Vec<_> = ["baseline", "from-zero", "correct-product-false-trace"]
        .into_iter()
        .map(|phase| {
            let file = format!("{phase}.json");
            let hash = fs::read(root.join(&file))
                .ok()
                .map(|raw| hex::encode(Sha256::digest(raw)));
            json!({"phase":phase,"file":file,"sha256":hash})
        })
        .collect();
    let manifest = fs::read(root.join("campaign.json")).unwrap();
    support::write_new(
        &root.join("client-composition.json"),
        &json!({
        "schema":COMPOSITION_SCHEMA,"client_execution_profile":history_verifier::PURE_CLIENT_PROFILE,
        "experiment":experiment,"native_selector":selector,
        "campaign_sha256":hex::encode(Sha256::digest(manifest)),"phases":phases,
        "receiver_outer_budget_changed":false,"attacker_outer_budget_changed":false,
        "window_ns":support::WINDOW_NS,"history_call_cap":64,
        "scope":"explicit new finite combination; public import, confirmation and final snapshot run only in the independent original fixed25-percent Host; original raw-layout service and cost predicates remain mandatory",
        "public_fairness_qualified":false,"production_qualified":false,
        "work_hardness_qualified":false,"installation_authorized":false}),
    );
}
