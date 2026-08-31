//! Shared H3b2b1 application-authority vector consumption and production JMT evidence.

#![cfg(test)]

use std::collections::{BTreeMap, BTreeSet};

use bytes::Bytes;
use serde_json::Value;
use sha2::{Digest, Sha256};
use trnm_consensus_types::{
    decode_consensus_parameters_v0_exact, decode_validator_key_proof_of_possession_v0_exact,
    ChainId, Epoch, GenesisHash, Height,
};

use crate::{
    auth_tree::{poco_snapshot_key_components, AuthWrite, InMemoryAuthTree},
    poco_application::{
        poco_application_mutation_root_v0, poco_application_operation_id_v0,
        registration_proof_bytes, validate_application_authority_projection_v0,
        AuthenticatedPocoApplicationContextV0, PocoApplicationApplyFailureV0,
        PocoApplicationAuthorityStateV0, PocoApplicationBlockOverlayV0,
        PocoApplicationDeterministicInvalidV0, PocoApplicationInvariantV0,
        PocoApplicationOperationBodyV0, PocoApplicationOperationV0,
    },
    poco_checkpoint::active_consensus_configuration,
    poco_nullifier::{
        derive_poco_nullifier_key_v0, PocoNullifierAccumulatorV0, PocoNullifierFamilyV0,
        PocoNullifierProofV0,
    },
    poco_semantics::{GovernanceApprovalV0, SemanticFactV0},
    poco_snapshot::{
        poco_snapshot_entry_key, poco_snapshot_manifest_key, PocoSnapshotEntryKindV0,
        PocoSnapshotEntryV0, PocoSnapshotManifestV0,
    },
    poco_transition::{
        auth_writes_from_sealed_poco_application_v0, decode_poco_snapshot_value_parts_v0_exact,
        take_and_validate_production_poco_projection_v0, PocoSnapshotMutationV0, PocoWritePermitV0,
        ProductionPocoProjectionV0,
    },
};

const APPLICATION_AUTHORITY_VECTOR: &str = include_str!(
    "../../../../docs/protocol/poco-bft-v0/vectors/poco-application-authority-v0.json"
);

fn vector() -> Value {
    serde_json::from_str(APPLICATION_AUTHORITY_VECTOR).expect("valid application-authority vector")
}

pub(crate) fn operation_sequence_authoring_value_v0() -> Value {
    let path = std::env::var_os("TRNM_POCO_APPLICATION_SEQUENCE_DRAFT")
        .expect("operation-sequence export requires TRNM_POCO_APPLICATION_SEQUENCE_DRAFT");
    let raw = std::fs::read(&path).unwrap_or_else(|error| {
        panic!(
            "read operation-sequence draft {}: {error}",
            std::path::PathBuf::from(&path).display()
        )
    });
    serde_json::from_slice(&raw).unwrap_or_else(|error| {
        panic!(
            "decode operation-sequence draft {}: {error}",
            std::path::PathBuf::from(path).display()
        )
    })
}

fn at<'a>(value: &'a Value, pointer: &str) -> &'a Value {
    value
        .pointer(pointer)
        .unwrap_or_else(|| panic!("missing vector field {pointer}"))
}

fn string(value: &Value, pointer: &str) -> String {
    at(value, pointer)
        .as_str()
        .unwrap_or_else(|| panic!("vector field {pointer} is not a string"))
        .to_owned()
}

fn integer(value: &Value, pointer: &str) -> u64 {
    let field = at(value, pointer);
    field.as_u64().unwrap_or_else(|| {
        field
            .as_str()
            .unwrap_or_else(|| panic!("vector field {pointer} is not an integer"))
            .parse()
            .unwrap_or_else(|_| panic!("vector field {pointer} is not a canonical u64"))
    })
}

fn bytes(value: &Value, pointer: &str) -> Vec<u8> {
    hex::decode(string(value, pointer))
        .unwrap_or_else(|_| panic!("vector field {pointer} is not hex"))
}

fn hash32(value: &Value, pointer: &str) -> [u8; 32] {
    bytes(value, pointer)
        .try_into()
        .unwrap_or_else(|_| panic!("vector field {pointer} is not Hash32"))
}

fn source_writes(value: &Value) -> Vec<AuthWrite> {
    let logical_key = bytes(value, "/authority_successor/source/logical_key_hex");
    let envelope = bytes(value, "/authority_successor/source/envelope_hex");
    let entry = PocoSnapshotEntryV0::new(
        PocoSnapshotEntryKindV0::ApplicationAuthorityState,
        logical_key.clone(),
        envelope.clone(),
    )
    .expect("exact vector source entry");
    assert_eq!(
        entry.canonical_bytes(),
        bytes(value, "/authority_successor/source/entry_cev0_hex")
    );

    let state_bytes = bytes(value, "/authority_successor/source/canonical_json_hex");
    let state = PocoApplicationAuthorityStateV0::decode_exact(&state_bytes)
        .expect("exact vector source authority state");
    assert_eq!(
        state.revision(),
        integer(value, "/authority_successor/source/state/revision")
    );
    let parts = decode_poco_snapshot_value_parts_v0_exact(
        PocoSnapshotEntryKindV0::ApplicationAuthorityState,
        &logical_key,
        &envelope,
    )
    .expect("exact vector source authority envelope");
    assert_eq!(parts.payload, state_bytes);
    assert_eq!(parts.verified.revision(), state.revision());

    let manifest_bytes = bytes(value, "/authority_successor/source/manifest_hex");
    let manifest =
        PocoSnapshotManifestV0::decode_exact(&manifest_bytes).expect("exact source manifest");
    assert_eq!(manifest.entry_count(), 1);
    assert_eq!(
        manifest.entries_root(),
        hash32(value, "/authority_successor/source/entries_root_hex")
    );
    assert_eq!(
        manifest,
        PocoSnapshotManifestV0::from_entries(manifest.cutoff_height(), &[entry])
            .expect("recompute vector source manifest")
    );

    vec![
        AuthWrite::put_poco_snapshot(
            PocoWritePermitV0::test_only(),
            poco_snapshot_entry_key(
                PocoSnapshotEntryKindV0::ApplicationAuthorityState,
                &logical_key,
            )
            .expect("application authority physical key"),
            envelope,
        )
        .expect("source authority write"),
        AuthWrite::put_poco_snapshot(
            PocoWritePermitV0::test_only(),
            poco_snapshot_manifest_key().expect("manifest physical key"),
            manifest_bytes,
        )
        .expect("source manifest write"),
    ]
}

fn source_tree(value: &Value, writes_at_version_one: bool) -> InMemoryAuthTree {
    let writes = source_writes(value);
    let mut tree = InMemoryAuthTree::default();
    if writes_at_version_one {
        tree.put_value_set(0, std::iter::empty())
            .expect("empty pre-activation version");
        tree.put_value_set(1, writes)
            .expect("authenticated vector source version");
    } else {
        tree.put_value_set(0, writes)
            .expect("alternate authenticated source history");
        tree.put_value_set(1, std::iter::empty())
            .expect("alternate no-op source version");
    }
    tree
}

fn projection_at(tree: &InMemoryAuthTree, version: u64) -> ProductionPocoProjectionV0 {
    let mut live = tree
        .verified_live_values(version)
        .expect("verified production source values");
    let projection = take_and_validate_production_poco_projection_v0(version, &mut live)
        .expect("valid production source projection")
        .expect("active PoCO projection");
    assert!(live.is_empty(), "fixture must contain only namespace 8");
    projection
}

fn production_projection_at(tree: &InMemoryAuthTree, version: u64) -> ProductionPocoProjectionV0 {
    let mut live = tree
        .verified_live_values(version)
        .expect("verified full application source values");
    take_and_validate_production_poco_projection_v0(version, &mut live)
        .expect("valid production PoCO projection in full application state")
        .expect("active PoCO projection in full application state")
}

fn optional_hash32(value: &Value, pointer: &str) -> Option<[u8; 32]> {
    let field = value.pointer(pointer)?;
    let encoded = field.as_str()?;
    if encoded.is_empty() {
        return None;
    }
    Some(
        hex::decode(encoded)
            .unwrap_or_else(|_| panic!("vector field {pointer} is not hex"))
            .try_into()
            .unwrap_or_else(|_| panic!("vector field {pointer} is not Hash32")),
    )
}

fn history_auth_writes(history: &Value) -> Vec<AuthWrite> {
    history["writes"]
        .as_array()
        .expect("sequence history writes")
        .iter()
        .map(|write| {
            let key = hex::decode(
                write["physical_key_hex"]
                    .as_str()
                    .expect("history physical key"),
            )
            .expect("decode history physical key");
            let value = write["value_hex"]
                .as_str()
                .map(|encoded| hex::decode(encoded).expect("decode history value"));
            let is_poco = poco_snapshot_key_components(&key)
                .expect("parse history authenticated key")
                .is_some();
            match (is_poco, value) {
                (true, Some(value)) => {
                    AuthWrite::put_poco_snapshot(PocoWritePermitV0::test_only(), key, value)
                        .expect("history PoCO put")
                }
                (true, None) => {
                    AuthWrite::delete_poco_snapshot(PocoWritePermitV0::test_only(), key)
                        .expect("history PoCO delete")
                }
                (false, Some(value)) => AuthWrite::put(key, value).expect("history domain put"),
                (false, None) => AuthWrite::delete(key).expect("history domain delete"),
            }
        })
        .collect()
}

pub(crate) fn authenticated_tree_from_sequence_initial_v0(
    initial: &Value,
) -> (InMemoryAuthTree, u64, [u8; 32], ProductionPocoProjectionV0) {
    let history = initial["history"]
        .as_array()
        .expect("sequence initial history");
    assert!(!history.is_empty(), "sequence initial history is empty");
    let mut tree = InMemoryAuthTree::default();
    let mut prior_version = None;
    for item in history {
        let version = item["version"].as_u64().expect("history version");
        if let Some(prior) = prior_version {
            assert_eq!(
                version,
                prior + 1,
                "sequence initial history is not contiguous"
            );
        }
        let root = tree
            .put_value_set(version, history_auth_writes(item))
            .unwrap_or_else(|error| panic!("sequence history version {version}: {error:#}"))
            .0;
        assert_eq!(
            hex::encode(root),
            item["jmt_root_hex"].as_str().expect("history JMT root"),
            "sequence history root drift at version {version}"
        );
        prior_version = Some(version);
    }
    let version = initial["version"]
        .as_u64()
        .expect("sequence initial version");
    assert_eq!(
        prior_version,
        Some(version),
        "sequence initial version differs from history head"
    );
    let root = tree.root_hash(version).expect("sequence initial root").0;
    assert_eq!(
        hex::encode(root),
        initial["jmt_root_hex"]
            .as_str()
            .expect("sequence initial JMT root"),
        "sequence initial root drift"
    );
    let projection = production_projection_at(&tree, version);
    validate_application_authority_projection_v0(&projection)
        .expect("sequence initial authority projection");
    assert_eq!(
        hex::encode(projection.manifest().encode()),
        initial["projection"]["manifest_hex"]
            .as_str()
            .expect("sequence initial manifest"),
        "sequence initial manifest drift"
    );
    assert_eq!(
        hex::encode(projection.manifest().entries_root()),
        initial["projection"]["entries_root_hex"]
            .as_str()
            .expect("sequence initial entries root"),
        "sequence initial entries-root drift"
    );
    (tree, version, root, projection)
}

fn evidence_domain_hash_v0(domain: &[u8], encoded: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for frame in [b"trnm.cev0.hash.v0".as_slice(), domain, encoded] {
        hasher.update(
            u32::try_from(frame.len())
                .expect("bounded evidence hash frame")
                .to_be_bytes(),
        );
        hasher.update(frame);
    }
    hasher.finalize().into()
}

struct BusinessIntentBodyV0<'a> {
    kind: &'a str,
    body: &'a serde_json::Map<String, Value>,
}

impl serde::Serialize for BusinessIntentBodyV0<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeMap;

        let ordered_fields: &[&str] = match self.kind {
            "authorize_consumer_key" => &[
                "kind",
                "consumer_id_hex",
                "consumer_key_id_hex",
                "public_key_hex",
                "active_from_height",
                "decision_id_hex",
            ],
            "revoke_consumer_key" => &[
                "kind",
                "consumer_id_hex",
                "consumer_key_id_hex",
                "public_key_hex",
                "active_from_height",
                "revoked_at_height",
                "decision_id_hex",
            ],
            "prune_revoked_consumer_key" => &["kind", "consumer_id_hex", "consumer_key_id_hex"],
            "define_meter_policy" => &["kind", "policy", "decision_id_hex"],
            "retire_meter_policy" => &[
                "kind",
                "meter_id_hex",
                "meter_version",
                "retired_at_height",
                "decision_id_hex",
            ],
            "prune_retired_meter" => &["kind", "meter_id_hex", "meter_version"],
            "fund_settlement" => &[
                "kind",
                "certificate_id_hex",
                "settlement_commitment_hex",
                "reserved_units",
                "funding_decision_id_hex",
            ],
            "accept_certificate" => &[
                "kind",
                "certificate_id_hex",
                "funding_decision_id_hex",
                "acceptance_decision_id_hex",
                "meter_decision_id_hex",
                "evidence_decision_id_hex",
            ],
            "release_settlement" => &["kind", "certificate_id_hex", "release_decision_id_hex"],
            "open_challenge" => &[
                "kind",
                "certificate_id_hex",
                "challenge_id_hex",
                "opening_decision_id_hex",
            ],
            "resolve_challenge" => &[
                "kind",
                "certificate_id_hex",
                "challenge_id_hex",
                "resolution",
                "resolution_decision_id_hex",
            ],
            "propose_governance" => &[
                "kind",
                "target_epoch",
                "phase",
                "parameters_hash_hex",
                "activation_height",
                "proposal_decision_id_hex",
            ],
            "approve_governance" => &[
                "kind",
                "target_epoch",
                "parameters_hash_hex",
                "activation_height",
                "decision_id_hex",
            ],
            "register_validator" => &[
                "kind",
                "validator_id_hex",
                "target_epoch",
                "registration_decision_id_hex",
            ],
            "rotate_validator" => &[
                "kind",
                "validator_id_hex",
                "target_epoch",
                "previous_history_head_hex",
                "previous_registration_nonce",
                "registration_decision_id_hex",
            ],
            "revoke_validator" => &["kind", "validator_id_hex", "revocation_decision_id_hex"],
            "prune_revoked_validator_history" => &["kind", "validator_id_hex"],
            "prune_expired_certificate" => &["kind", "certificate_id_hex"],
            other => panic!("unknown business-intent operation kind {other}"),
        };
        let dynamic_field = match self.kind {
            "authorize_consumer_key" => Some("active_from_height"),
            "register_validator" => Some("target_epoch"),
            _ => None,
        };
        let decision_fields: &[&str] = match self.kind {
            "authorize_consumer_key" | "revoke_consumer_key" => &["decision_id_hex"],
            "define_meter_policy" | "retire_meter_policy" => &["decision_id_hex"],
            "fund_settlement" => &["funding_decision_id_hex"],
            "accept_certificate" => &[
                "acceptance_decision_id_hex",
                "meter_decision_id_hex",
                "evidence_decision_id_hex",
            ],
            "release_settlement" => &["release_decision_id_hex"],
            "open_challenge" => &["challenge_id_hex", "opening_decision_id_hex"],
            "resolve_challenge" => &["resolution_decision_id_hex"],
            "propose_governance" => &["proposal_decision_id_hex"],
            "approve_governance" => &["decision_id_hex"],
            "register_validator" | "rotate_validator" => &["registration_decision_id_hex"],
            "revoke_validator" => &["revocation_decision_id_hex"],
            _ => &[],
        };
        let mut map = serializer.serialize_map(None)?;
        for field in ordered_fields {
            if dynamic_field == Some(*field) {
                continue;
            }
            if *field == "policy" {
                map.serialize_entry(
                    field,
                    &BusinessIntentMeterPolicyV0 {
                        policy: self.body["policy"]
                            .as_object()
                            .expect("business-intent meter policy"),
                    },
                )?;
            } else if decision_fields.contains(field) {
                map.serialize_entry(field, &"0".repeat(64))?;
            } else {
                map.serialize_entry(
                    field,
                    self.body
                        .get(*field)
                        .unwrap_or_else(|| panic!("business-intent body field {field}")),
                )?;
            }
        }
        map.end()
    }
}

struct BusinessIntentMeterPolicyV0<'a> {
    policy: &'a serde_json::Map<String, Value>,
}

impl serde::Serialize for BusinessIntentMeterPolicyV0<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeMap;

        let mut map = serializer.serialize_map(None)?;
        for field in [
            "meter_id_hex",
            "meter_version",
            "task_id_hex",
            "output_commitment_hex",
            "unit_scale",
            "evidence_policy",
            "per_certificate_cap",
            "rolling_cap",
            "rolling_epoch_span",
            "retention_blocks",
            "retired_at_height",
        ] {
            map.serialize_entry(
                field,
                self.policy
                    .get(field)
                    .unwrap_or_else(|| panic!("business-intent meter field {field}")),
            )?;
        }
        map.end()
    }
}

#[derive(serde::Serialize)]
struct BusinessIntentConsumerKeyFactV1 {
    consumer_id_hex: String,
    consumer_key_id_hex: String,
    public_key_hex: String,
    state: u8,
}

#[derive(serde::Serialize)]
struct BusinessIntentMeterFactV1 {
    meter_id_hex: String,
    meter_version: u32,
    unit_scale: String,
    state: u8,
}

#[derive(serde::Serialize)]
struct BusinessIntentSettlementFactV1 {
    certificate_id_hex: String,
    commitment_hex: String,
    state: u8,
}

#[derive(serde::Serialize)]
struct BusinessIntentValidatorProofV1 {
    schema_version: u16,
    genesis_hash_hex: String,
    chain_id_utf8: String,
    validator_id_hex: String,
    public_key_hex: String,
    registration_nonce: String,
}

#[derive(serde::Serialize)]
struct BusinessIntentValidatorFactV1 {
    validator_id_hex: String,
    consensus_key_hex: String,
    registration_nonce: String,
    proof: BusinessIntentValidatorProofV1,
    state: u8,
}

#[derive(serde::Serialize)]
struct BusinessIntentLifecycleFactV1 {
    state: u8,
}

#[derive(serde::Serialize)]
struct BusinessIntentGovernanceFactV1 {
    target_epoch: String,
    phase: u8,
    parameters_hash_hex: String,
    activation_height: String,
    approved: bool,
}

#[derive(serde::Serialize)]
#[serde(untagged)]
enum BusinessIntentSemanticFactV1 {
    ConsumerKey(BusinessIntentConsumerKeyFactV1),
    Meter(BusinessIntentMeterFactV1),
    Settlement(BusinessIntentSettlementFactV1),
    Validator(BusinessIntentValidatorFactV1),
    Lifecycle(BusinessIntentLifecycleFactV1),
    Governance(BusinessIntentGovernanceFactV1),
}

#[derive(serde::Serialize)]
struct BusinessIntentSemanticItemV1 {
    kind: u8,
    logical_key_hex: String,
    action: &'static str,
    identity_hex: Option<String>,
    fact: Option<BusinessIntentSemanticFactV1>,
}

fn take_business_intent_bytes<'a>(bytes: &'a [u8], offset: &mut usize) -> &'a [u8] {
    let length_end = offset
        .checked_add(4)
        .expect("business-intent length offset overflow");
    let length = u32::from_be_bytes(
        bytes
            .get(*offset..length_end)
            .expect("business-intent framed length")
            .try_into()
            .expect("business-intent u32 width"),
    ) as usize;
    let value_end = length_end
        .checked_add(length)
        .expect("business-intent value offset overflow");
    let value = bytes
        .get(length_end..value_end)
        .expect("business-intent framed value");
    *offset = value_end;
    value
}

fn business_intent_semantic_item_v1(change: &Value) -> BusinessIntentSemanticItemV1 {
    let kind = u8::try_from(
        change["kind"]
            .as_u64()
            .expect("business-intent semantic kind"),
    )
    .expect("business-intent semantic kind fits u8");
    let logical_key_hex = change["logical_key_hex"]
        .as_str()
        .expect("business-intent semantic logical key")
        .to_string();
    let Some(next_value_hex) = change["next_value_hex"].as_str() else {
        return BusinessIntentSemanticItemV1 {
            kind,
            logical_key_hex,
            action: "delete",
            identity_hex: None,
            fact: None,
        };
    };
    let value = hex::decode(next_value_hex).expect("decode business-intent semantic value");
    let kind_value =
        PocoSnapshotEntryKindV0::from_u8(kind).expect("business-intent semantic kind is canonical");
    let logical_key =
        hex::decode(&logical_key_hex).expect("decode business-intent semantic logical key");
    let parts = decode_poco_snapshot_value_parts_v0_exact(kind_value, &logical_key, &value)
        .expect("exact business-intent semantic value");
    let identity_hex = Some(hex::encode(parts.identity));
    let fact = match parts.fact {
        SemanticFactV0::ConsumerKeyAuthorization {
            public_key,
            revoked_at,
            ..
        } => {
            let mut offset = 0;
            let consumer_id = take_business_intent_bytes(parts.identity, &mut offset);
            let consumer_key_id = take_business_intent_bytes(parts.identity, &mut offset);
            assert_eq!(
                offset,
                parts.identity.len(),
                "consumer-key identity trailing bytes"
            );
            BusinessIntentSemanticFactV1::ConsumerKey(BusinessIntentConsumerKeyFactV1 {
                consumer_id_hex: hex::encode(consumer_id),
                consumer_key_id_hex: hex::encode(consumer_key_id),
                public_key_hex: hex::encode(public_key),
                state: if revoked_at.is_some() { 2 } else { 1 },
            })
        }
        SemanticFactV0::MeterDefinition {
            unit_scale,
            retired_at,
            ..
        } => {
            let mut offset = 0;
            let meter_id = take_business_intent_bytes(parts.identity, &mut offset);
            let version_end = offset
                .checked_add(4)
                .expect("meter version offset overflow");
            let meter_version = u32::from_be_bytes(
                parts
                    .identity
                    .get(offset..version_end)
                    .expect("meter version bytes")
                    .try_into()
                    .expect("meter version width"),
            );
            assert_eq!(
                version_end,
                parts.identity.len(),
                "meter identity trailing bytes"
            );
            BusinessIntentSemanticFactV1::Meter(BusinessIntentMeterFactV1 {
                meter_id_hex: hex::encode(meter_id),
                meter_version,
                unit_scale: unit_scale.to_string(),
                state: if retired_at.is_some() { 2 } else { 1 },
            })
        }
        SemanticFactV0::Settlement {
            commitment, state, ..
        } => BusinessIntentSemanticFactV1::Settlement(BusinessIntentSettlementFactV1 {
            certificate_id_hex: hex::encode(parts.identity),
            commitment_hex: hex::encode(commitment),
            state: state as u8,
        }),
        SemanticFactV0::ValidatorRegistration {
            consensus_key,
            registration_nonce,
            state,
            ..
        } => {
            let proof = decode_validator_key_proof_of_possession_v0_exact(
                registration_proof_bytes(parts.payload)
                    .expect("business-intent validator registration proof bytes"),
            )
            .expect("exact business-intent validator proof");
            let fields = proof.fields();
            BusinessIntentSemanticFactV1::Validator(BusinessIntentValidatorFactV1 {
                validator_id_hex: hex::encode(parts.identity),
                consensus_key_hex: hex::encode(consensus_key),
                registration_nonce: registration_nonce.to_string(),
                proof: BusinessIntentValidatorProofV1 {
                    schema_version: fields.schema_version,
                    genesis_hash_hex: hex::encode(fields.genesis_hash.as_bytes()),
                    chain_id_utf8: fields.chain_id.as_str().to_string(),
                    validator_id_hex: hex::encode(fields.validator_id.as_bytes()),
                    public_key_hex: hex::encode(fields.public_key.as_bytes()),
                    registration_nonce: fields.registration_nonce.to_string(),
                },
                state: state as u8,
            })
        }
        SemanticFactV0::RevocationOrChallenge { state, .. } => {
            BusinessIntentSemanticFactV1::Lifecycle(BusinessIntentLifecycleFactV1 {
                state: state as u8,
            })
        }
        SemanticFactV0::RolloutOrGovernance {
            target_epoch,
            phase,
            parameters_hash,
            activation_height,
            approval,
        } => {
            assert_eq!(
                approval,
                GovernanceApprovalV0::Approved,
                "business-intent governance fact is not approved"
            );
            BusinessIntentSemanticFactV1::Governance(BusinessIntentGovernanceFactV1 {
                target_epoch: target_epoch.to_string(),
                phase: phase as u8,
                parameters_hash_hex: hex::encode(parameters_hash),
                activation_height: activation_height.to_string(),
                approved: true,
            })
        }
        other => panic!("unsupported business-intent semantic fact {other:?}"),
    };
    BusinessIntentSemanticItemV1 {
        kind,
        logical_key_hex,
        action: "put",
        identity_hex,
        fact: Some(fact),
    }
}

fn business_intent_semantic_items_v1(operation: &Value) -> Vec<BusinessIntentSemanticItemV1> {
    operation["semantic_changes"]
        .as_array()
        .expect("business-intent semantic changes")
        .iter()
        .map(business_intent_semantic_item_v1)
        .collect()
}

struct BusinessIntentPreimageV0<'a> {
    kind: &'a str,
    body: &'a serde_json::Map<String, Value>,
    semantic_intent: &'a [BusinessIntentSemanticItemV1],
}

impl serde::Serialize for BusinessIntentPreimageV0<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeMap;

        let mut map = serializer.serialize_map(Some(3))?;
        map.serialize_entry("operation_kind", self.kind)?;
        map.serialize_entry(
            "body",
            &BusinessIntentBodyV0 {
                kind: self.kind,
                body: self.body,
            },
        )?;
        map.serialize_entry("semantic_intent", self.semantic_intent)?;
        map.end()
    }
}

pub(crate) fn application_business_intent_digest_v0(raw_operation: &[u8]) -> [u8; 32] {
    PocoApplicationOperationV0::decode_exact(raw_operation)
        .expect("exact business-intent operation");
    let operation: Value =
        serde_json::from_slice(raw_operation).expect("business-intent operation JSON");
    let kind = operation["body"]["kind"]
        .as_str()
        .expect("business-intent operation kind");
    let semantic_intent = business_intent_semantic_items_v1(&operation);
    let canonical = serde_json::to_vec(&BusinessIntentPreimageV0 {
        kind,
        body: operation["body"]
            .as_object()
            .expect("business-intent operation body"),
        semantic_intent: &semantic_intent,
    })
    .expect("canonical business-intent preimage");
    evidence_domain_hash_v0(b"trnm.poco-bft.application-business-intent.v1", &canonical)
}

pub(crate) fn validate_application_sequence_business_lineage_v0(
    sequence: &Value,
    retained_source: &Value,
) {
    let negatives = sequence["negatives"]
        .as_array()
        .expect("sequence negatives");
    if negatives.is_empty() {
        return;
    }
    assert_eq!(negatives.len(), 1, "automaton negative count");
    let negative = &negatives[0];
    let raw_operations = application_sequence_negative_raw_operations_v0(negative);
    assert_eq!(raw_operations.len(), 1, "frozen negative operation count");
    let negative_value: Value =
        serde_json::from_slice(&raw_operations[0]).expect("negative business-intent JSON");
    let negative_kind = negative_value["body"]["kind"]
        .as_str()
        .expect("negative business-intent kind");
    let digest = application_business_intent_digest_v0(&raw_operations[0]);
    assert_eq!(
        hex::encode(digest),
        negative["base_positive"]["normalized_business_intent_digest_hex"]
            .as_str()
            .expect("negative business-intent digest"),
        "negative business-intent digest drift"
    );
    match sequence["execution_scope"].as_str() {
        Some("full_application_store") => {
            assert_eq!(
                negative["base_positive"]["source"].as_str(),
                Some("sequence_step")
            );
            let step_id = negative["base_positive"]["step_id"]
                .as_str()
                .expect("base-positive step ID");
            let operation_index = negative["base_positive"]["operation_index"]
                .as_u64()
                .expect("base-positive operation index") as usize;
            let step = sequence["steps"]
                .as_array()
                .expect("sequence steps")
                .iter()
                .find(|step| step["id"].as_str() == Some(step_id))
                .expect("base-positive step");
            let raw = hex::decode(
                step["operations"][operation_index]["raw_operation_json_hex"]
                    .as_str()
                    .expect("base-positive raw operation"),
            )
            .expect("decode base-positive raw operation");
            assert_eq!(
                application_business_intent_digest_v0(&raw),
                digest,
                "negative differs from successful business intent"
            );
        }
        Some("isolated_prune_transition_kernel") => {
            assert_eq!(
                negative["base_positive"]["source"].as_str(),
                Some("source_lineage")
            );
            assert!(negative["base_positive"]["step_id"].is_null());
            assert!(negative["base_positive"]["operation_index"].is_null());
            let lineage = &retained_source["lineage_base_intent"];
            let digest_hex = hex::encode(digest);
            assert_eq!(
                lineage["operation_kind"].as_str(),
                Some(negative_kind),
                "isolated source lineage operation kind drift"
            );
            assert_eq!(
                lineage["normalized_business_intent_digest_hex"].as_str(),
                Some(digest_hex.as_str()),
                "isolated source lineage digest drift"
            );
            assert_eq!(
                lineage["subjects"], sequence["subjects"],
                "isolated source lineage subjects drift"
            );
        }
        other => panic!("unknown sequence execution scope {other:?}"),
    }
}

#[derive(serde::Serialize)]
struct OrderedRequestContextV0<'a> {
    chain_id_utf8: &'a Value,
    genesis_hash_hex: &'a Value,
    source_version: &'a Value,
    source_root_hex: &'a Value,
    target_height: &'a Value,
    active_epoch: &'a Value,
    active_parameters_cev0_hex: &'a Value,
    active_parameters_hash_hex: &'a Value,
    authority_signer_commitment_hex: &'a Value,
}

fn ordered_request_context_v0(value: &Value) -> OrderedRequestContextV0<'_> {
    OrderedRequestContextV0 {
        chain_id_utf8: &value["chain_id_utf8"],
        genesis_hash_hex: &value["genesis_hash_hex"],
        source_version: &value["source_version"],
        source_root_hex: &value["source_root_hex"],
        target_height: &value["target_height"],
        active_epoch: &value["active_epoch"],
        active_parameters_cev0_hex: &value["active_parameters_cev0_hex"],
        active_parameters_hash_hex: &value["active_parameters_hash_hex"],
        authority_signer_commitment_hex: &value["authority_signer_commitment_hex"],
    }
}

#[derive(serde::Serialize)]
struct OrderedRequestAuthorityV0<'a> {
    envelope_hex: &'a Value,
    revision: &'a Value,
    last_target_height: &'a Value,
    nullifier_root_hex: &'a Value,
    nullifier_count: &'a Value,
}

fn ordered_request_authority_v0(value: &Value) -> OrderedRequestAuthorityV0<'_> {
    OrderedRequestAuthorityV0 {
        envelope_hex: &value["envelope_hex"],
        revision: &value["revision"],
        last_target_height: &value["last_target_height"],
        nullifier_root_hex: &value["nullifier_root_hex"],
        nullifier_count: &value["nullifier_count"],
    }
}

#[derive(serde::Serialize)]
struct OrderedRequestSourceV0<'a> {
    version: &'a Value,
    jmt_root_hex: &'a Value,
    manifest_hex: &'a Value,
    authority: OrderedRequestAuthorityV0<'a>,
}

fn ordered_request_source_v0(value: &Value) -> OrderedRequestSourceV0<'_> {
    OrderedRequestSourceV0 {
        version: &value["version"],
        jmt_root_hex: &value["jmt_root_hex"],
        manifest_hex: &value["manifest_hex"],
        authority: ordered_request_authority_v0(&value["authority"]),
    }
}

#[derive(serde::Serialize)]
struct OrderedRequestBasePositiveV0<'a> {
    source: &'a Value,
    step_id: &'a Value,
    operation_index: &'a Value,
    normalized_business_intent_digest_hex: &'a Value,
}

#[derive(serde::Serialize)]
struct OrderedRequestFaultModelV0<'a> {
    kind: &'a Value,
    authenticated_source_relation: &'a Value,
    expected_first_error_stage: &'a Value,
    expected_first_error_code: &'a Value,
}

#[derive(serde::Serialize)]
struct OrderedRequestExpectedRejectV0<'a> {
    stage: &'a Value,
    error_code: &'a Value,
}

#[derive(serde::Serialize)]
struct OrderedStepRequestV0<'a> {
    schema: &'static str,
    schema_version: u16,
    source_export_sha256_hex: &'a Value,
    sequence_id: &'a Value,
    step_id: &'a Value,
    execution_scope: &'a Value,
    activation_prerequisite: &'a Value,
    context: OrderedRequestContextV0<'a>,
    raw_operation_json_hexes: Vec<&'a Value>,
    operation_ids_hex: Vec<&'a Value>,
    operation_root_hex: &'a Value,
    operation_count: &'a Value,
}

#[derive(serde::Serialize)]
struct OrderedNegativeRequestV0<'a> {
    schema: &'static str,
    schema_version: u16,
    source_export_sha256_hex: &'a Value,
    sequence_id: &'a Value,
    negative_id: &'a Value,
    execution_scope: &'a Value,
    context: OrderedRequestContextV0<'a>,
    source: OrderedRequestSourceV0<'a>,
    base_positive: OrderedRequestBasePositiveV0<'a>,
    fault_model: OrderedRequestFaultModelV0<'a>,
    raw_operation_json_hexes: &'a Value,
    expected_reject: OrderedRequestExpectedRejectV0<'a>,
    expected_writes: &'a Value,
    expected_unchanged: OrderedRequestSourceV0<'a>,
}

fn ordered_json_sha256_v0<T: serde::Serialize>(value: &T) -> [u8; 32] {
    Sha256::digest(serde_json::to_vec(value).expect("ordered JSON digest input")).into()
}

pub(crate) fn application_sequence_step_request_sha256_v0(
    sequence: &Value,
    step: &Value,
) -> [u8; 32] {
    let operations = step["operations"].as_array().expect("sequence operations");
    ordered_json_sha256_v0(&OrderedStepRequestV0 {
        schema: "trnm.poco-bft.application-operation-rust-step-request.v0",
        schema_version: 0,
        source_export_sha256_hex: &sequence["source_export_sha256_hex"],
        sequence_id: &sequence["id"],
        step_id: &step["id"],
        execution_scope: &sequence["execution_scope"],
        activation_prerequisite: &sequence["activation_prerequisite"],
        context: ordered_request_context_v0(&step["context"]),
        raw_operation_json_hexes: operations
            .iter()
            .map(|operation| &operation["raw_operation_json_hex"])
            .collect(),
        operation_ids_hex: operations
            .iter()
            .map(|operation| &operation["operation_id_hex"])
            .collect(),
        operation_root_hex: &step["operation_root_hex"],
        operation_count: &step["operation_count"],
    })
}

pub(crate) fn application_sequence_negative_request_sha256_v0(
    sequence: &Value,
    negative: &Value,
) -> [u8; 32] {
    let base = &negative["base_positive"];
    let fault = &negative["fault_model"];
    let rejection = &negative["expected_reject"];
    ordered_json_sha256_v0(&OrderedNegativeRequestV0 {
        schema: "trnm.poco-bft.application-operation-rust-negative-request.v0",
        schema_version: 0,
        source_export_sha256_hex: &sequence["source_export_sha256_hex"],
        sequence_id: &sequence["id"],
        negative_id: &negative["id"],
        execution_scope: &sequence["execution_scope"],
        context: ordered_request_context_v0(&negative["context"]),
        source: ordered_request_source_v0(&negative["source"]),
        base_positive: OrderedRequestBasePositiveV0 {
            source: &base["source"],
            step_id: &base["step_id"],
            operation_index: &base["operation_index"],
            normalized_business_intent_digest_hex: &base["normalized_business_intent_digest_hex"],
        },
        fault_model: OrderedRequestFaultModelV0 {
            kind: &fault["kind"],
            authenticated_source_relation: &fault["authenticated_source_relation"],
            expected_first_error_stage: &fault["expected_first_error_stage"],
            expected_first_error_code: &fault["expected_first_error_code"],
        },
        raw_operation_json_hexes: &negative["raw_operation_json_hexes"],
        expected_reject: OrderedRequestExpectedRejectV0 {
            stage: &rejection["stage"],
            error_code: &rejection["error_code"],
        },
        expected_writes: &negative["expected_writes"],
        expected_unchanged: ordered_request_source_v0(&negative["expected_unchanged"]),
    })
}

pub(crate) fn application_sequence_raw_operations_v0(step: &Value) -> Vec<Vec<u8>> {
    step["operations"]
        .as_array()
        .expect("sequence step operations")
        .iter()
        .map(|operation| {
            let raw = hex::decode(
                operation["raw_operation_json_hex"]
                    .as_str()
                    .expect("raw operation hex"),
            )
            .expect("decode raw operation");
            PocoApplicationOperationV0::decode_exact(&raw).expect("exact sequence operation");
            let expected_operation_id: [u8; 32] = hex::decode(
                operation["operation_id_hex"]
                    .as_str()
                    .expect("operation ID hex"),
            )
            .expect("decode operation ID")
            .try_into()
            .expect("Hash32 operation ID");
            assert_eq!(
                poco_application_operation_id_v0(&raw).expect("sequence operation ID"),
                expected_operation_id
            );
            raw
        })
        .collect()
}

pub(crate) fn application_sequence_negative_raw_operations_v0(negative: &Value) -> Vec<Vec<u8>> {
    negative["raw_operation_json_hexes"]
        .as_array()
        .expect("negative raw operations")
        .iter()
        .map(|encoded| {
            let raw = hex::decode(encoded.as_str().expect("negative raw operation hex"))
                .expect("decode negative raw operation");
            PocoApplicationOperationV0::decode_exact(&raw)
                .expect("exact negative sequence operation");
            raw
        })
        .collect()
}

fn sequence_context(
    value: &Value,
    sequence: &Value,
    context: &Value,
) -> AuthenticatedPocoApplicationContextV0 {
    let parameter_bytes = hex::decode(
        context["active_parameters_cev0_hex"]
            .as_str()
            .expect("sequence active parameters"),
    )
    .expect("decode sequence active parameters");
    let parameters = decode_consensus_parameters_v0_exact(&parameter_bytes)
        .expect("exact sequence active parameters");
    AuthenticatedPocoApplicationContextV0::new(
        context["source_version"]
            .as_u64()
            .expect("sequence source version"),
        hex::decode(
            context["source_root_hex"]
                .as_str()
                .expect("sequence source root"),
        )
        .expect("decode sequence source root")
        .try_into()
        .expect("Hash32 sequence source root"),
        Height::new(
            context["target_height"]
                .as_u64()
                .expect("sequence target height"),
        ),
        ChainId::new(
            value
                .pointer("/authenticated_context/chain_id_utf8")
                .and_then(Value::as_str)
                .or_else(|| {
                    sequence
                        .pointer("/initial/active_genesis/chain_id_utf8")
                        .and_then(Value::as_str)
                })
                .expect("sequence chain ID"),
        )
        .expect("bounded sequence chain ID"),
        GenesisHash::new(
            hex::decode(
                value
                    .pointer("/authenticated_context/genesis_hash_hex")
                    .and_then(Value::as_str)
                    .or_else(|| {
                        sequence
                            .pointer("/initial/active_genesis/genesis_hash_hex")
                            .and_then(Value::as_str)
                    })
                    .expect("sequence genesis hash"),
            )
            .expect("decode sequence genesis hash")
            .try_into()
            .expect("Hash32 sequence genesis hash"),
        ),
        Epoch::new(
            context["active_epoch"]
                .as_u64()
                .expect("sequence active epoch"),
        ),
        parameters,
        hex::decode(
            context["authority_signer_commitment_hex"]
                .as_str()
                .expect("sequence authority signer commitment"),
        )
        .expect("decode sequence authority signer commitment")
        .try_into()
        .expect("Hash32 sequence authority signer commitment"),
    )
    .expect("authenticated sequence application context")
}

fn context(value: &Value, source_root: [u8; 32]) -> AuthenticatedPocoApplicationContextV0 {
    let parameter_bytes = bytes(value, "/authenticated_context/active_parameters_cev0_hex");
    let parameters = decode_consensus_parameters_v0_exact(&parameter_bytes)
        .expect("exact vector active parameters");
    assert_eq!(
        parameters.hash().as_bytes(),
        &hash32(value, "/authenticated_context/active_parameters_hash_hex")
    );
    AuthenticatedPocoApplicationContextV0::new(
        integer(value, "/authenticated_context/source_version"),
        source_root,
        Height::new(integer(value, "/authenticated_context/target_height")),
        ChainId::new(&string(value, "/authenticated_context/chain_id_utf8"))
            .expect("bounded vector chain ID"),
        GenesisHash::new(hash32(value, "/authenticated_context/genesis_hash_hex")),
        Epoch::new(integer(value, "/authenticated_context/active_epoch")),
        parameters,
        hash32(
            value,
            "/authenticated_context/authority_signer_commitment_hex",
        ),
    )
    .expect("authenticated vector application context")
}

fn raw_operation(value: &Value) -> Vec<u8> {
    let raw = bytes(value, "/authority_successor/operation/canonical_json_hex");
    PocoApplicationOperationV0::decode_exact(&raw).expect("exact vector application operation");
    raw
}

fn canonical_mutation_from_vector(mutation: &Value) -> Vec<u8> {
    fn frame(output: &mut Vec<u8>, value: &[u8]) {
        output.extend_from_slice(
            &u32::try_from(value.len())
                .expect("bounded vector mutation frame")
                .to_be_bytes(),
        );
        output.extend_from_slice(value);
    }
    fn optional_frame(output: &mut Vec<u8>, value: Option<&str>) {
        match value {
            Some(value) => {
                output.push(1);
                frame(
                    output,
                    &hex::decode(value).expect("decode vector optional mutation value"),
                );
            }
            None => output.push(0),
        }
    }

    let mut encoded = Vec::new();
    encoded.extend_from_slice(&0u16.to_be_bytes());
    encoded.push(mutation["kind"].as_u64().expect("mutation kind") as u8);
    frame(
        &mut encoded,
        &hex::decode(
            mutation["logical_key_hex"]
                .as_str()
                .expect("mutation logical key"),
        )
        .expect("decode mutation logical key"),
    );
    optional_frame(&mut encoded, mutation["expected_value_hex"].as_str());
    optional_frame(&mut encoded, mutation["next_value_hex"].as_str());
    encoded
}

#[derive(serde::Serialize)]
struct PocoApplicationSequenceMutationExportV0 {
    kind: u8,
    logical_key_hex: String,
    expected_value_hex: Option<String>,
    next_value_hex: Option<String>,
    canonical_cev0_hex: String,
}

#[derive(serde::Serialize)]
struct PocoApplicationSequenceEntryExportV0 {
    kind: u8,
    logical_key_hex: String,
    value_hex: String,
    canonical_entry_cev0_hex: String,
}

#[derive(Clone, serde::Serialize)]
pub(crate) struct PocoApplicationAuthoritySummaryExportV0 {
    pub(crate) envelope_hex: String,
    pub(crate) revision: u64,
    pub(crate) last_target_height: u64,
    pub(crate) nullifier_root_hex: String,
    pub(crate) nullifier_count: u64,
}

#[derive(Clone, serde::Serialize)]
pub(crate) struct PocoApplicationProductionContextExportV0 {
    pub(crate) chain_id_utf8: String,
    pub(crate) genesis_hash_hex: String,
    pub(crate) source_version: u64,
    pub(crate) source_root_hex: String,
    pub(crate) target_height: u64,
    pub(crate) active_epoch: u64,
    pub(crate) active_parameters_cev0_hex: String,
    pub(crate) active_parameters_hash_hex: String,
    pub(crate) authority_signer_commitment_hex: String,
}

pub(crate) fn production_context_from_projection(
    projection: &ProductionPocoProjectionV0,
    source_version: u64,
    source_root: [u8; 32],
    target_height: u64,
    active_epoch: u64,
    authority_signer_commitment: [u8; 32],
) -> (
    AuthenticatedPocoApplicationContextV0,
    PocoApplicationProductionContextExportV0,
) {
    let (validator_set, parameters) =
        active_consensus_configuration(projection).expect("authenticated active configuration");
    assert_eq!(
        validator_set.consensus_parameters_hash(),
        parameters.hash(),
        "validator-set/parameter hash drift"
    );
    let authenticated = AuthenticatedPocoApplicationContextV0::new(
        source_version,
        source_root,
        Height::new(target_height),
        validator_set.chain_id(),
        validator_set.genesis_hash(),
        Epoch::new(active_epoch),
        parameters,
        authority_signer_commitment,
    )
    .expect("production-derived application context");
    let exported = PocoApplicationProductionContextExportV0 {
        chain_id_utf8: String::from_utf8(validator_set.chain_id().as_bytes().to_vec())
            .expect("application chain ID UTF-8"),
        genesis_hash_hex: hex::encode(validator_set.genesis_hash().as_bytes()),
        source_version,
        source_root_hex: hex::encode(source_root),
        target_height,
        active_epoch,
        active_parameters_cev0_hex: hex::encode(parameters.canonical_bytes()),
        active_parameters_hash_hex: hex::encode(parameters.hash().as_bytes()),
        authority_signer_commitment_hex: hex::encode(authority_signer_commitment),
    };
    (authenticated, exported)
}

#[derive(serde::Serialize)]
struct PocoApplicationSequenceSourceExportV0 {
    version: u64,
    jmt_root_hex: String,
    manifest_hex: String,
    authority: PocoApplicationAuthoritySummaryExportV0,
}

#[derive(serde::Serialize)]
struct PocoApplicationSequenceOperationExportV0 {
    raw_json_hexes: Vec<String>,
    operation_ids_hex: Vec<String>,
    operation_root_hex: String,
    operation_count: u32,
}

#[derive(serde::Serialize)]
struct PocoApplicationSequenceMutationsExportV0 {
    mutation_root_hex: String,
    mutation_count: u32,
    items: Vec<PocoApplicationSequenceMutationExportV0>,
}

#[derive(serde::Serialize)]
struct PocoApplicationSequenceTargetExportV0 {
    version: u64,
    jmt_root_hex: String,
    manifest_hex: String,
    entries_root_hex: String,
    entries: Vec<PocoApplicationSequenceEntryExportV0>,
    authority: PocoApplicationAuthoritySummaryExportV0,
}

#[derive(serde::Serialize)]
pub(crate) struct PocoApplicationStoreRunExportV0 {
    target_jmt_root_hex: String,
    receipts_root_hex: String,
    receipt_bytes_hexes: Vec<String>,
}

#[derive(serde::Serialize)]
struct PocoApplicationStateFingerprintExportV0 {
    version: u64,
    jmt_root_hex: String,
    manifest_hex: String,
    entries_root_hex: String,
    authority_envelope_hex: String,
}

#[derive(serde::Serialize)]
struct PocoApplicationStoreFailpointExportV0 {
    failpoint: &'static str,
    call_returned_error: bool,
    restart_state: PocoApplicationStateFingerprintExportV0,
}

fn application_state_fingerprint_v0(
    version: u64,
    root: [u8; 32],
    projection: &ProductionPocoProjectionV0,
) -> PocoApplicationStateFingerprintExportV0 {
    let authority = authority_summary(projection);
    PocoApplicationStateFingerprintExportV0 {
        version,
        jmt_root_hex: hex::encode(root),
        manifest_hex: hex::encode(projection.manifest().encode()),
        entries_root_hex: hex::encode(projection.manifest().entries_root()),
        authority_envelope_hex: authority.envelope_hex,
    }
}

#[derive(serde::Serialize)]
pub(crate) struct PocoApplicationScopeEvidenceExportV0 {
    kind: &'static str,
    ordered_signed_tx_hexes: Vec<String>,
    process_proposal: PocoApplicationStoreRunExportV0,
    finalize_block: PocoApplicationStoreRunExportV0,
    sqlite_commit: PocoApplicationStateFingerprintExportV0,
    sqlite_restart: PocoApplicationStateFingerprintExportV0,
    snapshot_v3_restore: PocoApplicationStateFingerprintExportV0,
    snapshot_v4_restore: PocoApplicationStateFingerprintExportV0,
    sqlite_failpoint_outcomes: Vec<PocoApplicationStoreFailpointExportV0>,
}

#[derive(serde::Serialize)]
pub(crate) struct PocoApplicationSequenceStepExportV0 {
    schema: &'static str,
    schema_version: u16,
    source_export_sha256_hex: String,
    draft_request_sha256_hex: String,
    sequence_id: String,
    step_id: String,
    execution_scope: String,
    context: PocoApplicationProductionContextExportV0,
    source: PocoApplicationSequenceSourceExportV0,
    operation: PocoApplicationSequenceOperationExportV0,
    scope_evidence: Option<PocoApplicationScopeEvidenceExportV0>,
    mutations: PocoApplicationSequenceMutationsExportV0,
    target: PocoApplicationSequenceTargetExportV0,
    next_production_context: PocoApplicationProductionContextExportV0,
}

#[derive(Clone, serde::Serialize)]
struct PocoApplicationSequenceTargetAfterExportV0 {
    version: u64,
    jmt_root_hex: String,
    manifest_hex: String,
    authority: PocoApplicationAuthoritySummaryExportV0,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub(crate) struct PocoApplicationRejectedNullifierExportV0 {
    family: u8,
    identifier_hex: String,
    key_hex: String,
    proof_source_root_hex: String,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub(crate) struct PocoApplicationActualRejectionExportV0 {
    stage: &'static str,
    error_code: &'static str,
    classifier_priority: u8,
    error_chain_sha256_hex: String,
    rejected_nullifier: Option<PocoApplicationRejectedNullifierExportV0>,
}

#[derive(serde::Serialize)]
struct PocoApplicationFullStoreNegativeExecutionExportV0 {
    kind: &'static str,
    ordered_signed_tx_hexes: Vec<String>,
    process_proposal_status: &'static str,
    process_executor_actual: PocoApplicationActualRejectionExportV0,
    independent_executor_actual: PocoApplicationActualRejectionExportV0,
    finalize_block_not_invoked_after_reject: bool,
    pending_after_reject: Option<serde_json::Value>,
    sqlite_restart: PocoApplicationStateFingerprintExportV0,
}

#[derive(serde::Serialize)]
struct PocoApplicationKernelNegativeExecutionExportV0 {
    kind: &'static str,
    kernel: PocoApplicationActualRejectionExportV0,
}

#[derive(serde::Serialize)]
#[serde(untagged)]
enum PocoApplicationNegativeExecutionExportV0 {
    FullStore(Box<PocoApplicationFullStoreNegativeExecutionExportV0>),
    Kernel(PocoApplicationKernelNegativeExecutionExportV0),
}

#[derive(serde::Serialize)]
pub(crate) struct PocoApplicationSequenceNegativeExportV0 {
    schema: &'static str,
    schema_version: u16,
    source_export_sha256_hex: String,
    draft_request_sha256_hex: String,
    sequence_id: String,
    negative_id: String,
    execution_scope: String,
    context: PocoApplicationProductionContextExportV0,
    source: PocoApplicationSequenceSourceExportV0,
    raw_operation_json_hexes: Vec<String>,
    actual_rejection: PocoApplicationActualRejectionExportV0,
    execution_evidence: PocoApplicationNegativeExecutionExportV0,
    writes: u32,
    target_after: PocoApplicationSequenceTargetAfterExportV0,
}

pub(crate) struct FullApplicationStoreScopeEvidenceInputV0<'a> {
    pub(crate) signed_txs: &'a [Bytes],
    pub(crate) source_version: u64,
    pub(crate) source_root: [u8; 32],
    pub(crate) source_projection: &'a ProductionPocoProjectionV0,
    pub(crate) target_version: u64,
    pub(crate) target_root: [u8; 32],
    pub(crate) process_body: &'a crate::poco_checkpoint::CheckpointBodyEvidenceV0,
    pub(crate) finalize_body: &'a crate::poco_checkpoint::CheckpointBodyEvidenceV0,
    pub(crate) sqlite_commit_projection: &'a ProductionPocoProjectionV0,
    pub(crate) sqlite_restart_projection: &'a ProductionPocoProjectionV0,
    pub(crate) snapshot_v3_projection: &'a ProductionPocoProjectionV0,
    pub(crate) snapshot_v4_projection: &'a ProductionPocoProjectionV0,
}

pub(crate) fn full_application_store_scope_evidence_v0(
    input: FullApplicationStoreScopeEvidenceInputV0<'_>,
) -> PocoApplicationScopeEvidenceExportV0 {
    let FullApplicationStoreScopeEvidenceInputV0 {
        signed_txs,
        source_version,
        source_root,
        source_projection,
        target_version,
        target_root,
        process_body,
        finalize_body,
        sqlite_commit_projection,
        sqlite_restart_projection,
        snapshot_v3_projection,
        snapshot_v4_projection,
    } = input;
    assert_eq!(process_body, finalize_body);
    let run =
        |body: &crate::poco_checkpoint::CheckpointBodyEvidenceV0| PocoApplicationStoreRunExportV0 {
            target_jmt_root_hex: hex::encode(target_root),
            receipts_root_hex: hex::encode(body.receipts_root()),
            receipt_bytes_hexes: body.encoded_receipts().iter().map(hex::encode).collect(),
        };
    let source_fingerprint =
        || application_state_fingerprint_v0(source_version, source_root, source_projection);
    let target_fingerprint = |projection: &ProductionPocoProjectionV0| {
        application_state_fingerprint_v0(target_version, target_root, projection)
    };
    PocoApplicationScopeEvidenceExportV0 {
        kind: "full_application_store",
        ordered_signed_tx_hexes: signed_txs.iter().map(hex::encode).collect(),
        process_proposal: run(process_body),
        finalize_block: run(finalize_body),
        sqlite_commit: target_fingerprint(sqlite_commit_projection),
        sqlite_restart: target_fingerprint(sqlite_restart_projection),
        snapshot_v3_restore: target_fingerprint(snapshot_v3_projection),
        snapshot_v4_restore: target_fingerprint(snapshot_v4_projection),
        sqlite_failpoint_outcomes: vec![
            PocoApplicationStoreFailpointExportV0 {
                failpoint: "before_sql_commit",
                call_returned_error: true,
                restart_state: source_fingerprint(),
            },
            PocoApplicationStoreFailpointExportV0 {
                failpoint: "after_sql_commit_before_status",
                call_returned_error: true,
                restart_state: target_fingerprint(sqlite_restart_projection),
            },
        ],
    }
}

fn rejected_nullifier_from_operations_v0(
    source_projection: &ProductionPocoProjectionV0,
    raw_operations: &[Vec<u8>],
) -> Option<PocoApplicationRejectedNullifierExportV0> {
    let authority = application_authority_state(source_projection);
    let mut accumulator = PocoNullifierAccumulatorV0::from_authenticated_parts(
        authority
            .nullifier_root()
            .expect("authenticated source nullifier root"),
        authority.nullifier_count(),
    )
    .expect("authenticated source nullifier head");
    for raw in raw_operations {
        PocoApplicationOperationV0::decode_exact(raw).expect("exact rejected operation");
        let value: Value = serde_json::from_slice(raw).expect("decoded rejected operation JSON");
        for (field, inserts) in [
            ("nullifier_non_membership_checks", false),
            ("nullifier_insertions", true),
        ] {
            for item in value[field]
                .as_array()
                .expect("canonical rejected nullifier list")
            {
                let family = PocoNullifierFamilyV0::from_u8(
                    item["family"].as_u64().expect("nullifier family") as u8,
                )
                .expect("known rejected nullifier family");
                let identifier: [u8; 32] = hex::decode(
                    item["identifier_hex"]
                        .as_str()
                        .expect("nullifier identifier"),
                )
                .expect("decode nullifier identifier")
                .try_into()
                .expect("Hash32 nullifier identifier");
                let proof = PocoNullifierProofV0::decode_exact(
                    &hex::decode(item["proof_hex"].as_str().expect("nullifier proof"))
                        .expect("decode nullifier proof"),
                )
                .expect("exact rejected nullifier proof");
                let key = derive_poco_nullifier_key_v0(family, identifier);
                assert_eq!(proof.key(), key, "rejected proof key substitution");
                let result = if inserts {
                    accumulator
                        .verify_non_membership_and_compute_insertion(key, &proof)
                        .map(|inserted| {
                            accumulator = inserted
                                .target_accumulator()
                                .expect("valid intermediate nullifier accumulator");
                        })
                } else {
                    accumulator.verify_non_membership(key, &proof)
                };
                if result.is_err() {
                    return Some(PocoApplicationRejectedNullifierExportV0 {
                        family: family.code(),
                        identifier_hex: hex::encode(identifier),
                        key_hex: hex::encode(key),
                        proof_source_root_hex: hex::encode(proof.non_membership_root()),
                    });
                }
            }
        }
    }
    None
}

pub(crate) fn classify_application_rejection_v0(
    error: &anyhow::Error,
    source_projection: &ProductionPocoProjectionV0,
    raw_operations: &[Vec<u8>],
) -> PocoApplicationActualRejectionExportV0 {
    let typed = error
        .chain()
        .find_map(|cause| cause.downcast_ref::<PocoApplicationApplyFailureV0>());
    let rejected_operation = raw_operations
        .last()
        .and_then(|raw| PocoApplicationOperationV0::decode_exact(raw).ok());
    let typed_rule = typed.and_then(|failure| {
        let operation = rejected_operation.as_ref()?;
        match (failure, operation.evidence_body()) {
            (
                PocoApplicationApplyFailureV0::DeterministicallyInvalid(
                    PocoApplicationDeterministicInvalidV0::ProtocolWindowOrCap,
                ),
                PocoApplicationOperationBodyV0::ResolveChallenge { .. },
            ) => Some(("authority", "challenge_not_pending", 3)),
            (
                PocoApplicationApplyFailureV0::DeterministicallyInvalid(
                    PocoApplicationDeterministicInvalidV0::ProtocolWindowOrCap,
                ),
                PocoApplicationOperationBodyV0::ApproveGovernance { .. },
            ) => Some((
                "authority",
                "governance_approval_lacks_authenticated_proposal",
                3,
            )),
            (
                PocoApplicationApplyFailureV0::DeterministicallyInvalid(
                    PocoApplicationDeterministicInvalidV0::ProtocolWindowOrCap,
                ),
                PocoApplicationOperationBodyV0::RegisterValidator { .. }
                | PocoApplicationOperationBodyV0::RotateValidator { .. },
            ) => Some(("authority", "validator_consensus_key_already_active", 3)),
            (
                PocoApplicationApplyFailureV0::DeterministicallyInvalid(
                    PocoApplicationDeterministicInvalidV0::ChallengeNotPending,
                ),
                _,
            ) => Some(("authority", "challenge_not_pending", 3)),
            (
                PocoApplicationApplyFailureV0::DeterministicallyInvalid(
                    PocoApplicationDeterministicInvalidV0::GovernanceApprovalMissing,
                ),
                _,
            ) => Some((
                "authority",
                "governance_approval_lacks_authenticated_proposal",
                3,
            )),
            (
                PocoApplicationApplyFailureV0::DeterministicallyInvalid(
                    PocoApplicationDeterministicInvalidV0::ValidatorConsensusKeyAlreadyActive,
                ),
                _,
            ) => Some(("authority", "validator_consensus_key_already_active", 3)),
            (
                PocoApplicationApplyFailureV0::DeterministicallyInvalid(
                    PocoApplicationDeterministicInvalidV0::NullifierNonMembershipRootMismatch,
                ),
                _,
            ) => Some(("proof", "nullifier_non_membership_root_mismatch", 5)),
            (
                PocoApplicationApplyFailureV0::Invariant(
                    PocoApplicationInvariantV0::AuthenticatedOverlay,
                ),
                _,
            ) if operation.evidence_has_nullifier_non_membership_checks() => {
                Some(("proof", "nullifier_non_membership_root_mismatch", 5))
            }
            _ => None,
        }
    });
    let rules = [
        (
            "challenge is not pending",
            "authority",
            "challenge_not_pending",
            3_u8,
        ),
        (
            "governance approval lacks authenticated proposal",
            "authority",
            "governance_approval_lacks_authenticated_proposal",
            3,
        ),
        (
            "validator consensus key is already active in registration history",
            "authority",
            "validator_consensus_key_already_active",
            3,
        ),
        (
            "PoCO nullifier non-membership root mismatch",
            "proof",
            "nullifier_non_membership_root_mismatch",
            5,
        ),
    ];
    let messages = error.chain().map(ToString::to_string).collect::<Vec<_>>();
    let (stage, error_code, classifier_priority) = if let Some(typed_rule) = typed_rule {
        typed_rule
    } else {
        let (_, stage, error_code, priority) = rules
            .into_iter()
            .filter(|(message, ..)| messages.iter().any(|item| item == message))
            .min_by_key(|(_, _, _, priority)| *priority)
            .unwrap_or_else(|| {
                panic!(
                    "unclassified PoCO application rejection: {error:#}; operation={rejected_operation:?}"
                )
            });
        (stage, error_code, priority)
    };
    let rejected_nullifier = (stage == "proof")
        .then(|| rejected_nullifier_from_operations_v0(source_projection, raw_operations))
        .flatten()
        .or_else(|| {
            assert_ne!(
                stage, "proof",
                "proof rejection lacks exact failed nullifier"
            );
            None
        });
    let error_chain = if matches!(
        typed,
        Some(PocoApplicationApplyFailureV0::DeterministicallyInvalid(
            PocoApplicationDeterministicInvalidV0::NullifierNonMembershipRootMismatch
        ))
    ) {
        rejected_nullifier
            .as_ref()
            .filter(|nullifier| {
                raw_operations.iter().any(|raw| {
                    PocoApplicationOperationV0::decode_exact(raw)
                        .map(|operation| {
                            operation.evidence_has_nullifier_insertion(
                                nullifier.family,
                                &nullifier.identifier_hex,
                            )
                        })
                        .unwrap_or(false)
                })
            })
            .map(|nullifier| {
                format!(
                    "verify PoCO nullifier insertion family {} identifier {}: PoCO nullifier non-membership root mismatch",
                    nullifier.family, nullifier.identifier_hex
                )
            })
            .unwrap_or_else(|| "PoCO nullifier non-membership root mismatch".to_string())
    } else {
        messages.join(": ")
    };
    PocoApplicationActualRejectionExportV0 {
        stage,
        error_code,
        classifier_priority,
        error_chain_sha256_hex: hex::encode(Sha256::digest(error_chain.as_bytes())),
        rejected_nullifier,
    }
}

fn negative_source_and_target_after_v0(
    context: &PocoApplicationProductionContextExportV0,
    source_root: [u8; 32],
    source_projection: &ProductionPocoProjectionV0,
) -> (
    PocoApplicationSequenceSourceExportV0,
    PocoApplicationSequenceTargetAfterExportV0,
) {
    assert_eq!(context.source_root_hex, hex::encode(source_root));
    let authority = authority_summary(source_projection);
    (
        PocoApplicationSequenceSourceExportV0 {
            version: context.source_version,
            jmt_root_hex: hex::encode(source_root),
            manifest_hex: hex::encode(source_projection.manifest().encode()),
            authority: authority.clone(),
        },
        PocoApplicationSequenceTargetAfterExportV0 {
            version: context.source_version,
            jmt_root_hex: hex::encode(source_root),
            manifest_hex: hex::encode(source_projection.manifest().encode()),
            authority,
        },
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn full_application_store_negative_event_v0(
    source_export_sha256: [u8; 32],
    draft_request_sha256: [u8; 32],
    sequence_id: &str,
    negative_id: &str,
    context: PocoApplicationProductionContextExportV0,
    source_root: [u8; 32],
    source_projection: &ProductionPocoProjectionV0,
    raw_operations: &[Vec<u8>],
    signed_txs: &[Bytes],
    process_actual: PocoApplicationActualRejectionExportV0,
    independent_actual: PocoApplicationActualRejectionExportV0,
    restart_version: u64,
    restart_root: [u8; 32],
    restart_projection: &ProductionPocoProjectionV0,
) -> PocoApplicationSequenceNegativeExportV0 {
    assert_eq!(process_actual, independent_actual);
    assert_eq!(restart_version, context.source_version);
    assert_eq!(restart_root, source_root);
    assert_eq!(restart_projection, source_projection);
    let (source, target_after) =
        negative_source_and_target_after_v0(&context, source_root, source_projection);
    PocoApplicationSequenceNegativeExportV0 {
        schema: "trnm.poco-bft.application-operation-rust-negative-event.v0",
        schema_version: 0,
        source_export_sha256_hex: hex::encode(source_export_sha256),
        draft_request_sha256_hex: hex::encode(draft_request_sha256),
        sequence_id: sequence_id.to_string(),
        negative_id: negative_id.to_string(),
        execution_scope: "full_application_store".to_string(),
        context,
        source,
        raw_operation_json_hexes: raw_operations.iter().map(hex::encode).collect(),
        actual_rejection: process_actual.clone(),
        execution_evidence: PocoApplicationNegativeExecutionExportV0::FullStore(Box::new(
            PocoApplicationFullStoreNegativeExecutionExportV0 {
                kind: "full_application_store",
                ordered_signed_tx_hexes: signed_txs.iter().map(hex::encode).collect(),
                process_proposal_status: "reject",
                process_executor_actual: process_actual,
                independent_executor_actual: independent_actual,
                finalize_block_not_invoked_after_reject: true,
                pending_after_reject: None,
                sqlite_restart: application_state_fingerprint_v0(
                    restart_version,
                    restart_root,
                    restart_projection,
                ),
            },
        )),
        writes: 0,
        target_after,
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn isolated_kernel_negative_event_v0(
    source_export_sha256: [u8; 32],
    draft_request_sha256: [u8; 32],
    sequence_id: &str,
    negative_id: &str,
    context: PocoApplicationProductionContextExportV0,
    source_root: [u8; 32],
    source_projection: &ProductionPocoProjectionV0,
    raw_operations: &[Vec<u8>],
    actual: PocoApplicationActualRejectionExportV0,
) -> PocoApplicationSequenceNegativeExportV0 {
    let (source, target_after) =
        negative_source_and_target_after_v0(&context, source_root, source_projection);
    PocoApplicationSequenceNegativeExportV0 {
        schema: "trnm.poco-bft.application-operation-rust-negative-event.v0",
        schema_version: 0,
        source_export_sha256_hex: hex::encode(source_export_sha256),
        draft_request_sha256_hex: hex::encode(draft_request_sha256),
        sequence_id: sequence_id.to_string(),
        negative_id: negative_id.to_string(),
        execution_scope: "isolated_prune_transition_kernel".to_string(),
        context,
        source,
        raw_operation_json_hexes: raw_operations.iter().map(hex::encode).collect(),
        actual_rejection: actual.clone(),
        execution_evidence: PocoApplicationNegativeExecutionExportV0::Kernel(
            PocoApplicationKernelNegativeExecutionExportV0 {
                kind: "isolated_prune_transition_kernel",
                kernel: actual,
            },
        ),
        writes: 0,
        target_after,
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn application_sequence_step_event_v0(
    source_export_sha256: [u8; 32],
    draft_request_sha256: [u8; 32],
    sequence_id: &str,
    step_id: &str,
    execution_scope: &str,
    authenticated_context: AuthenticatedPocoApplicationContextV0,
    context: PocoApplicationProductionContextExportV0,
    source_root: [u8; 32],
    source_projection: &ProductionPocoProjectionV0,
    target_root: [u8; 32],
    target_projection: &ProductionPocoProjectionV0,
    raw_operations: &[Vec<u8>],
    scope_evidence: Option<PocoApplicationScopeEvidenceExportV0>,
    next_production_context: PocoApplicationProductionContextExportV0,
) -> PocoApplicationSequenceStepExportV0 {
    assert!(!raw_operations.is_empty());
    assert_eq!(context.source_root_hex, hex::encode(source_root));
    assert_eq!(context.source_version + 1, context.target_height);
    assert_eq!(
        next_production_context.source_version,
        context.target_height
    );
    assert_eq!(
        next_production_context.source_root_hex,
        hex::encode(target_root)
    );
    assert_eq!(
        scope_evidence.is_some(),
        execution_scope == "full_application_store",
        "isolated prune evidence cannot claim full ApplicationStore execution"
    );

    let mut overlay =
        PocoApplicationBlockOverlayV0::from_projection(authenticated_context, source_projection)
            .expect("production-derived sequence overlay");
    let operation_ids = raw_operations
        .iter()
        .map(|raw| {
            PocoApplicationOperationV0::decode_exact(raw)
                .expect("exact operation-sequence operation");
            poco_application_operation_id_v0(raw).expect("production operation ID")
        })
        .collect::<Vec<_>>();
    for raw in raw_operations {
        overlay
            .apply_raw(raw)
            .expect("apply exact operation-sequence operation");
    }
    let sealed = overlay.seal().expect("seal operation-sequence block");
    assert_eq!(
        usize::try_from(sealed.operation_count()).unwrap(),
        raw_operations.len()
    );
    assert_eq!(sealed.target_manifest(), target_projection.manifest());
    assert_eq!(sealed.target_manifest().encode().len(), 47);

    let mutations = exact_projection_mutations(source_projection, target_projection);
    assert_eq!(
        usize::try_from(sealed.mutation_count()).unwrap(),
        mutations.len()
    );
    assert_eq!(
        poco_application_mutation_root_v0(&mutations),
        sealed.mutation_root(),
        "exported canonical mutations do not reproduce the sealed application root"
    );
    let source_authority = authority_summary(source_projection);
    let target_authority = authority_summary(target_projection);
    assert_eq!(
        target_authority.revision,
        source_authority.revision.checked_add(1).unwrap(),
        "one sealed block increments authority revision exactly once"
    );
    assert_eq!(target_authority.last_target_height, context.target_height);
    let target_height = context.target_height;

    PocoApplicationSequenceStepExportV0 {
        schema: "trnm.poco-bft.application-operation-rust-step-event.v0",
        schema_version: 0,
        source_export_sha256_hex: hex::encode(source_export_sha256),
        draft_request_sha256_hex: hex::encode(draft_request_sha256),
        sequence_id: sequence_id.to_string(),
        step_id: step_id.to_string(),
        execution_scope: execution_scope.to_string(),
        context,
        source: PocoApplicationSequenceSourceExportV0 {
            version: sealed.source_version(),
            jmt_root_hex: hex::encode(source_root),
            manifest_hex: hex::encode(source_projection.manifest().encode()),
            authority: source_authority,
        },
        operation: PocoApplicationSequenceOperationExportV0 {
            raw_json_hexes: raw_operations.iter().map(hex::encode).collect(),
            operation_ids_hex: operation_ids.into_iter().map(hex::encode).collect(),
            operation_root_hex: hex::encode(sealed.operation_root()),
            operation_count: sealed.operation_count(),
        },
        scope_evidence,
        mutations: PocoApplicationSequenceMutationsExportV0 {
            mutation_root_hex: hex::encode(sealed.mutation_root()),
            mutation_count: sealed.mutation_count(),
            items: export_mutations(&mutations),
        },
        target: PocoApplicationSequenceTargetExportV0 {
            version: target_height,
            jmt_root_hex: hex::encode(target_root),
            manifest_hex: hex::encode(target_projection.manifest().encode()),
            entries_root_hex: hex::encode(target_projection.manifest().entries_root()),
            entries: export_entries(target_projection),
            authority: target_authority,
        },
        next_production_context,
    }
}

pub(crate) struct PocoApplicationIsolatedSequenceReplayV0 {
    pub(crate) step_events: Vec<PocoApplicationSerializedEventV0>,
    pub(crate) negative_event: Option<PocoApplicationSerializedEventV0>,
}

pub(crate) struct PocoApplicationSerializedEventV0 {
    pub(crate) value: Value,
    pub(crate) raw: Vec<u8>,
}

pub(crate) fn serialize_application_sequence_event_v0<T: serde::Serialize>(
    event: &T,
) -> PocoApplicationSerializedEventV0 {
    // Serialize the typed struct directly.  Converting through `Value` first
    // would let serde_json's map backend reorder fields and destroy the frozen
    // machine-readable evidence contract.
    let raw = serde_json::to_vec(event).expect("serialize typed application sequence event");
    let value = serde_json::from_slice(&raw).expect("decode typed application sequence event");
    PocoApplicationSerializedEventV0 { value, raw }
}

pub(crate) fn replay_isolated_application_sequence_v0(
    sequence: &Value,
) -> PocoApplicationIsolatedSequenceReplayV0 {
    assert_eq!(
        sequence["execution_scope"].as_str(),
        Some("isolated_prune_transition_kernel"),
        "isolated replay received a full-store sequence"
    );
    let sequence_id = sequence["id"].as_str().expect("sequence id");
    let source_export_sha256: [u8; 32] = hex::decode(
        sequence["source_export_sha256_hex"]
            .as_str()
            .expect("sequence source digest"),
    )
    .expect("decode sequence source digest")
    .try_into()
    .expect("Hash32 sequence source digest");
    let (mut tree, initial_version, initial_root, initial_projection) =
        authenticated_tree_from_sequence_initial_v0(&sequence["initial"]);
    assert_eq!(
        initial_version,
        sequence["initial"]["production_context"]["source_version"]
            .as_u64()
            .expect("initial production source version")
    );
    assert_eq!(
        hex::encode(initial_root),
        sequence["initial"]["production_context"]["source_root_hex"]
            .as_str()
            .expect("initial production source root")
    );
    validate_application_authority_projection_v0(&initial_projection)
        .expect("isolated initial cross-entry projection");

    let mut step_events = Vec::new();
    for step in sequence["steps"].as_array().expect("sequence steps") {
        let step_id = step["id"].as_str().expect("sequence step id");
        let context_value = &step["context"];
        let source_version = context_value["source_version"]
            .as_u64()
            .expect("step source version");
        assert_eq!(
            tree.latest_version(),
            Some(source_version),
            "isolated {sequence_id}/{step_id} does not start at the live tree head"
        );
        let source_root = tree.root_hash(source_version).expect("step source root").0;
        assert_eq!(
            hex::encode(source_root),
            context_value["source_root_hex"]
                .as_str()
                .expect("step source root hex"),
            "isolated {sequence_id}/{step_id} source root drift"
        );
        let source_projection = production_projection_at(&tree, source_version);
        validate_application_authority_projection_v0(&source_projection)
            .expect("isolated step source projection");
        let active_epoch = context_value["active_epoch"]
            .as_u64()
            .expect("step active epoch");
        let signer_commitment: [u8; 32] = hex::decode(
            context_value["authority_signer_commitment_hex"]
                .as_str()
                .expect("step signer commitment"),
        )
        .expect("decode step signer commitment")
        .try_into()
        .expect("Hash32 step signer commitment");
        let target_height = context_value["target_height"]
            .as_u64()
            .expect("step target height");
        assert_eq!(
            target_height,
            source_version.checked_add(1).expect("step height overflow"),
            "isolated target is not the next JMT version"
        );
        let (authenticated_context, context) = production_context_from_projection(
            &source_projection,
            source_version,
            source_root,
            target_height,
            active_epoch,
            signer_commitment,
        );
        assert_eq!(
            serde_json::to_value(&context).expect("serialize production context"),
            *context_value,
            "isolated step context is not production-derived"
        );
        let raw_operations = application_sequence_raw_operations_v0(step);
        let mut overlay = PocoApplicationBlockOverlayV0::from_projection(
            authenticated_context.clone(),
            &source_projection,
        )
        .expect("isolated production overlay");
        for raw in &raw_operations {
            overlay
                .apply_raw(raw)
                .unwrap_or_else(|error| panic!("isolated {sequence_id}/{step_id}: {error:#}"));
        }
        let sealed = overlay.seal().expect("seal isolated operation block");
        let writes = auth_writes_from_sealed_poco_application_v0(&sealed)
            .expect("convert isolated sealed writes");
        let planned = tree
            .plan_put_value_set(target_height, writes)
            .expect("plan isolated full JMT target");
        let target_root = planned.root_hash.0;
        tree.apply(planned).expect("apply isolated full JMT target");
        let target_projection = production_projection_at(&tree, target_height);
        validate_application_authority_projection_v0(&target_projection)
            .expect("isolated target cross-entry projection");
        assert_eq!(target_projection.manifest(), sealed.target_manifest());
        let (_, next_context) = production_context_from_projection(
            &target_projection,
            target_height,
            target_root,
            target_height.checked_add(1).expect("next height overflow"),
            active_epoch,
            signer_commitment,
        );
        let event = application_sequence_step_event_v0(
            source_export_sha256,
            application_sequence_step_request_sha256_v0(sequence, step),
            sequence_id,
            step_id,
            "isolated_prune_transition_kernel",
            authenticated_context,
            context,
            source_root,
            &source_projection,
            target_root,
            &target_projection,
            &raw_operations,
            None,
            next_context,
        );
        step_events.push(serialize_application_sequence_event_v0(&event));
    }

    let negative_event = sequence["negatives"]
        .as_array()
        .expect("sequence negatives")
        .first()
        .map(|negative| {
            assert_eq!(
                sequence["negatives"].as_array().unwrap().len(),
                1,
                "isolated automaton must have one negative"
            );
            let negative_id = negative["id"].as_str().expect("negative id");
            let source_version = tree.latest_version().expect("negative source version");
            let source_root = tree
                .root_hash(source_version)
                .expect("negative source root")
                .0;
            let source_projection = production_projection_at(&tree, source_version);
            let context_value = &negative["context"];
            let signer_commitment: [u8; 32] = hex::decode(
                context_value["authority_signer_commitment_hex"]
                    .as_str()
                    .expect("negative signer commitment"),
            )
            .expect("decode negative signer commitment")
            .try_into()
            .expect("Hash32 negative signer commitment");
            let (authenticated_context, context) = production_context_from_projection(
                &source_projection,
                source_version,
                source_root,
                context_value["target_height"]
                    .as_u64()
                    .expect("negative target height"),
                context_value["active_epoch"]
                    .as_u64()
                    .expect("negative active epoch"),
                signer_commitment,
            );
            assert_eq!(
                serde_json::to_value(&context).expect("serialize negative context"),
                *context_value,
                "isolated negative context is not production-derived"
            );
            let raw_operations = application_sequence_negative_raw_operations_v0(negative);
            assert_eq!(
                raw_operations.len(),
                1,
                "isolated frozen negative must contain one operation"
            );
            let source_snapshot = tree.encode_snapshot().expect("negative source snapshot");
            let mut overlay = PocoApplicationBlockOverlayV0::from_projection(
                authenticated_context,
                &source_projection,
            )
            .expect("isolated negative overlay");
            let error = overlay
                .apply_raw(&raw_operations[0])
                .expect_err("isolated negative unexpectedly executed");
            assert_eq!(overlay.operation_count(), 0);
            assert_eq!(
                tree.encode_snapshot().expect("negative unchanged tree"),
                source_snapshot,
                "isolated negative changed authenticated history"
            );
            let actual =
                classify_application_rejection_v0(&error, &source_projection, &raw_operations);
            let event = isolated_kernel_negative_event_v0(
                source_export_sha256,
                application_sequence_negative_request_sha256_v0(sequence, negative),
                sequence_id,
                negative_id,
                context,
                source_root,
                &source_projection,
                &raw_operations,
                actual,
            );
            serialize_application_sequence_event_v0(&event)
        });

    PocoApplicationIsolatedSequenceReplayV0 {
        step_events,
        negative_event,
    }
}

fn application_authority_state(
    projection: &ProductionPocoProjectionV0,
) -> PocoApplicationAuthorityStateV0 {
    let entry = projection
        .entries()
        .iter()
        .find(|entry| entry.kind == PocoSnapshotEntryKindV0::ApplicationAuthorityState)
        .expect("production projection lacks application authority state");
    let parts =
        decode_poco_snapshot_value_parts_v0_exact(entry.kind, &entry.logical_key, &entry.value)
            .expect("exact application authority envelope");
    PocoApplicationAuthorityStateV0::decode_exact(parts.payload)
        .expect("exact application authority state")
}

pub(crate) fn authority_summary(
    projection: &ProductionPocoProjectionV0,
) -> PocoApplicationAuthoritySummaryExportV0 {
    let entry = projection
        .entries()
        .iter()
        .find(|entry| entry.kind == PocoSnapshotEntryKindV0::ApplicationAuthorityState)
        .expect("production projection lacks application authority state");
    let authority = application_authority_state(projection);
    PocoApplicationAuthoritySummaryExportV0 {
        envelope_hex: hex::encode(&entry.value),
        revision: authority.revision(),
        last_target_height: authority.last_target_height(),
        nullifier_root_hex: hex::encode(
            authority
                .nullifier_root()
                .expect("authenticated nullifier root"),
        ),
        nullifier_count: authority.nullifier_count(),
    }
}

fn exact_projection_mutations(
    source: &ProductionPocoProjectionV0,
    target: &ProductionPocoProjectionV0,
) -> Vec<PocoSnapshotMutationV0> {
    // This is an evidence-only diff between two independently authenticated,
    // production-validated projections.  Do not route it back through the
    // generic H3b2b0 single-entry semantic graph: application-authorized
    // cross-entry transitions (for example validator rotation and private
    // release/prune tombstones) have already been authorized atomically by
    // the production planner and intentionally are not generic mutations.
    validate_application_authority_projection_v0(source)
        .expect("source projection cross-entry authority before evidence diff");
    validate_application_authority_projection_v0(target)
        .expect("target projection cross-entry authority before evidence diff");
    let source = source
        .entries()
        .iter()
        .map(|entry| ((entry.kind, entry.logical_key.clone()), entry.value.clone()))
        .collect::<BTreeMap<_, _>>();
    let target = target
        .entries()
        .iter()
        .map(|entry| ((entry.kind, entry.logical_key.clone()), entry.value.clone()))
        .collect::<BTreeMap<_, _>>();
    let keys = source
        .keys()
        .chain(target.keys())
        .cloned()
        .collect::<BTreeSet<_>>();
    keys.into_iter()
        .filter_map(|(kind, logical_key)| {
            let expected = source.get(&(kind, logical_key.clone())).cloned();
            let next = target.get(&(kind, logical_key.clone())).cloned();
            if expected == next {
                return None;
            }
            assert!(
                expected.is_some() || next.is_some(),
                "union key absent from both projections"
            );
            Some(PocoSnapshotMutationV0 {
                kind,
                logical_key,
                expected_value: expected,
                next_value: next,
            })
        })
        .collect()
}

fn export_mutations(
    mutations: &[PocoSnapshotMutationV0],
) -> Vec<PocoApplicationSequenceMutationExportV0> {
    mutations
        .iter()
        .map(|mutation| PocoApplicationSequenceMutationExportV0 {
            kind: mutation.kind as u8,
            logical_key_hex: hex::encode(&mutation.logical_key),
            expected_value_hex: mutation.expected_value.as_ref().map(hex::encode),
            next_value_hex: mutation.next_value.as_ref().map(hex::encode),
            canonical_cev0_hex: hex::encode(mutation.canonical_bytes()),
        })
        .collect()
}

fn export_entries(
    projection: &ProductionPocoProjectionV0,
) -> Vec<PocoApplicationSequenceEntryExportV0> {
    projection
        .entries()
        .iter()
        .map(|entry| PocoApplicationSequenceEntryExportV0 {
            kind: entry.kind as u8,
            logical_key_hex: hex::encode(&entry.logical_key),
            value_hex: hex::encode(&entry.value),
            canonical_entry_cev0_hex: hex::encode(entry.canonical_bytes()),
        })
        .collect()
}

fn assert_nullifier_proofs(value: &Value) {
    let insertions = at(value, "/nullifier/sequential_insertions")
        .as_array()
        .expect("nullifier insertions array");
    for insertion in insertions {
        let proof_bytes = hex::decode(
            insertion["proof_hex"]
                .as_str()
                .expect("nullifier proof hex"),
        )
        .expect("decode nullifier proof hex");
        let proof = PocoNullifierProofV0::decode_exact(&proof_bytes)
            .expect("production exact nullifier proof");
        assert_eq!(proof.canonical_bytes(), proof_bytes);
        let family = PocoNullifierFamilyV0::from_u8(
            insertion["family"].as_u64().expect("nullifier family") as u8,
        )
        .expect("known nullifier family");
        let identifier: [u8; 32] = hex::decode(
            insertion["identifier_hex"]
                .as_str()
                .expect("nullifier identifier"),
        )
        .expect("decode nullifier identifier")
        .try_into()
        .expect("Hash32 nullifier identifier");
        let expected_key = derive_poco_nullifier_key_v0(family, identifier);
        assert_eq!(proof.key(), expected_key);
        let source = PocoNullifierAccumulatorV0::from_authenticated_parts(
            hex::decode(
                insertion["source_root_hex"]
                    .as_str()
                    .expect("nullifier source root"),
            )
            .expect("decode nullifier source root")
            .try_into()
            .expect("Hash32 nullifier source root"),
            insertion["source_count"]
                .as_str()
                .expect("nullifier source count")
                .parse()
                .expect("u64 nullifier source count"),
        )
        .expect("authenticated nullifier source");
        let applied = source
            .verify_non_membership_and_compute_insertion(expected_key, &proof)
            .expect("verified nullifier insertion");
        let target_root = <[u8; 32]>::try_from(
            hex::decode(
                insertion["target_root_hex"]
                    .as_str()
                    .expect("nullifier target root"),
            )
            .expect("decode nullifier target root"),
        )
        .expect("Hash32 nullifier target root");
        assert_eq!(applied.target_root(), target_root);
        assert_eq!(
            applied.target_count(),
            insertion["target_count"]
                .as_str()
                .expect("nullifier target count")
                .parse::<u64>()
                .expect("u64 nullifier target count")
        );
    }
}

fn replace_once(raw: &[u8], needle: &str, replacement: &str) -> Vec<u8> {
    let raw = std::str::from_utf8(raw).expect("canonical operation UTF-8");
    assert_eq!(raw.matches(needle).count(), 1, "mutation must be unique");
    raw.replacen(needle, replacement, 1).into_bytes()
}

fn mutated_proof_operation(value: &Value, mutation: &Value) -> Vec<u8> {
    let raw = raw_operation(value);
    let base_id = mutation["base"].as_str().expect("negative proof base");
    let base = at(value, "/nullifier/sequential_insertions")
        .as_array()
        .expect("nullifier insertion array")
        .iter()
        .find(|item| item["id"].as_str() == Some(base_id))
        .expect("negative proof base exists");
    let family = base["family"].as_u64().expect("base proof family");
    let original_hex = base["proof_hex"].as_str().expect("base proof hex");
    match mutation["action"].as_str().expect("negative proof action") {
        "family" => replace_once(
            &raw,
            &format!("\"family\":{family}"),
            &format!(
                "\"family\":{}",
                mutation["family"].as_u64().expect("substitute family")
            ),
        ),
        action => {
            let mut proof = hex::decode(original_hex).expect("decode base proof");
            match action {
                "xor" => {
                    let offset = mutation["offset"].as_u64().expect("xor offset") as usize;
                    proof[offset] ^= mutation["mask"].as_u64().expect("xor mask") as u8;
                }
                "append" => proof.extend_from_slice(
                    &hex::decode(mutation["hex"].as_str().expect("append hex"))
                        .expect("decode append hex"),
                ),
                "truncate" => {
                    let count = mutation["bytes"].as_u64().expect("truncate bytes") as usize;
                    proof.truncate(proof.len() - count);
                }
                other => panic!("unknown negative proof action {other}"),
            }
            replace_once(&raw, original_hex, &hex::encode(proof))
        }
    }
}

#[test]
fn vector_source_root_probe_and_exact_decoders() {
    let value = vector();
    let tree = source_tree(&value, true);
    let root = tree.root_hash(1).expect("source root").0;
    eprintln!(
        "poco application vector source JMT root: {}",
        hex::encode(root)
    );
    assert_nullifier_proofs(&value);
    let _ = projection_at(&tree, 1);
    let raw = raw_operation(&value);
    assert_eq!(
        poco_application_operation_id_v0(&raw).expect("exact production operation ID"),
        hash32(&value, "/authority_successor/operation/operation_id_hex")
    );
}

#[test]
fn shared_vector_drives_overlay_single_jmt_and_exact_target() {
    let value = vector();
    let mut tree = source_tree(&value, true);
    let source_root = tree.root_hash(1).expect("source root").0;
    assert_eq!(
        source_root,
        hash32(&value, "/authenticated_context/source_root_hex")
    );
    assert_eq!(
        source_root,
        hash32(&value, "/authority_successor/source/jmt_root_hex")
    );
    let source_projection = projection_at(&tree, 1);
    validate_application_authority_projection_v0(&source_projection)
        .expect("source cross-entry integrity");
    let source_snapshot = tree.encode_snapshot().expect("source tree snapshot");
    let raw = raw_operation(&value);
    let mut overlay = PocoApplicationBlockOverlayV0::from_projection(
        context(&value, source_root),
        &source_projection,
    )
    .expect("production application overlay");
    overlay.apply_raw(&raw).expect("apply vector operation");
    let sealed = overlay.seal().expect("seal vector operation");
    assert_eq!(
        sealed.operation_count(),
        integer(&value, "/authority_successor/operation/operation_count") as u32
    );
    assert_eq!(
        sealed.operation_root(),
        hash32(
            &value,
            "/authority_successor/operation/ordered_operation_root_hex"
        )
    );
    assert_eq!(
        sealed.mutation_count(),
        integer(&value, "/authority_successor/mutation_count") as u32
    );
    assert_eq!(
        sealed.mutation_root(),
        hash32(&value, "/authority_successor/mutation_root_hex")
    );
    assert_eq!(
        sealed.target_manifest().encode(),
        bytes(&value, "/authority_successor/target/manifest_hex")
    );
    assert_eq!(
        sealed.target_manifest().entries_root(),
        hash32(&value, "/authority_successor/target/entries_root_hex")
    );

    let expected_mutations = at(&value, "/authority_successor/mutations")
        .as_array()
        .expect("expected mutations");
    let namespace_writes = sealed.namespace_writes().collect::<Vec<_>>();
    assert_eq!(
        namespace_writes.len(),
        expected_mutations.len() + 1,
        "one manifest plus every mutation"
    );
    for mutation in expected_mutations {
        assert_eq!(
            canonical_mutation_from_vector(mutation),
            hex::decode(
                mutation["canonical_cev0_hex"]
                    .as_str()
                    .expect("canonical mutation bytes"),
            )
            .expect("decode canonical mutation bytes")
        );
        let kind = PocoSnapshotEntryKindV0::from_u8(
            mutation["kind"].as_u64().expect("mutation kind") as u8,
        )
        .expect("known mutation kind");
        let logical_key = hex::decode(
            mutation["logical_key_hex"]
                .as_str()
                .expect("mutation logical key"),
        )
        .expect("decode mutation logical key");
        let key = poco_snapshot_entry_key(kind, &logical_key).expect("physical mutation key");
        let expected_value = mutation["next_value_hex"]
            .as_str()
            .map(|encoded| hex::decode(encoded).expect("decode next mutation value"));
        assert!(namespace_writes.iter().any(|(actual_key, actual_value)| {
            *actual_key == key.as_slice() && *actual_value == expected_value.as_deref()
        }));
    }

    let writes = auth_writes_from_sealed_poco_application_v0(&sealed)
        .expect("convert sealed application writes");
    let planned = tree
        .plan_put_value_set(2, writes)
        .expect("one real target JMT plan");
    eprintln!(
        "poco application vector target JMT root: {}",
        hex::encode(planned.root_hash.0)
    );
    assert_eq!(
        planned.root_hash.0,
        hash32(&value, "/authority_successor/target/jmt_root_hex")
    );
    let target_root = tree.apply(planned).expect("apply target JMT plan").0;
    assert_eq!(
        target_root,
        hash32(&value, "/authority_successor/target/jmt_root_hex")
    );
    assert_ne!(
        tree.encode_snapshot().expect("target tree snapshot"),
        source_snapshot,
        "successful authority transition must change authenticated storage"
    );
    assert_eq!(
        tree.root_hash(1).expect("retained source root").0,
        source_root
    );

    let target_projection = projection_at(&tree, 2);
    validate_application_authority_projection_v0(&target_projection)
        .expect("target cross-entry integrity");
    assert_eq!(
        target_projection.manifest().encode(),
        bytes(&value, "/authority_successor/target/manifest_hex")
    );
    let expected_authority = bytes(&value, "/authority_successor/target/envelope_hex");
    let expected_settlement = bytes(&value, "/authority_successor/target/settlement_value_hex");
    assert!(target_projection.entries().iter().any(|entry| {
        entry.kind == PocoSnapshotEntryKindV0::ApplicationAuthorityState
            && entry.value == expected_authority
    }));
    assert!(target_projection.entries().iter().any(|entry| {
        entry.kind == PocoSnapshotEntryKindV0::Settlement && entry.value == expected_settlement
    }));
}

#[test]
fn shared_reject_corpus_is_atomic_and_preserves_source_head() {
    let value = vector();
    let tree = source_tree(&value, true);
    let source_root = tree.root_hash(1).expect("source root").0;
    let source_projection = projection_at(&tree, 1);
    let source_snapshot = tree.encode_snapshot().expect("source snapshot");
    let raw = raw_operation(&value);

    let negative_proofs = at(&value, "/nullifier/negative_mutations")
        .as_array()
        .expect("negative proof corpus");
    for mutation in negative_proofs {
        let mut overlay = PocoApplicationBlockOverlayV0::from_projection(
            context(&value, source_root),
            &source_projection,
        )
        .expect("fresh production overlay");
        let rejected = mutated_proof_operation(&value, mutation);
        assert!(
            overlay.apply_raw(&rejected).is_err(),
            "negative proof {} was accepted",
            mutation["id"].as_str().expect("negative proof id")
        );
        assert_eq!(overlay.operation_count(), 0);
        assert_eq!(overlay.expected_state_revision(), 1);
        overlay
            .apply_raw(&raw)
            .expect("valid operation after rejected candidate");
        let sealed = overlay.seal().expect("seal after rejected candidate");
        assert_eq!(
            sealed.mutation_root(),
            hash32(&value, "/authority_successor/mutation_root_hex")
        );
        assert_eq!(
            tree.encode_snapshot().expect("unchanged source snapshot"),
            source_snapshot
        );
        assert_eq!(
            tree.root_hash(1).expect("unchanged source root").0,
            source_root
        );
    }

    let raw_text = std::str::from_utf8(&raw).expect("operation UTF-8");
    let target = integer(&value, "/authenticated_context/target_height");
    let revision = integer(&value, "/authority_successor/source/state/revision");
    let mut rejected_operations = vec![
        replace_once(
            &raw,
            &format!("\"target_height\":{target}"),
            &format!("\"target_height\":{}", target + 1),
        ),
        replace_once(
            &raw,
            &format!("\"expected_state_revision\":{revision}"),
            &format!("\"expected_state_revision\":{}", revision + 1),
        ),
    ];
    let mut trailing = raw.clone();
    trailing.push(b' ');
    rejected_operations.push(trailing);
    assert!(raw_text.contains("\"nullifier_insertions\""));
    for rejected in rejected_operations {
        let mut overlay = PocoApplicationBlockOverlayV0::from_projection(
            context(&value, source_root),
            &source_projection,
        )
        .expect("fresh production overlay");
        assert!(overlay.apply_raw(&rejected).is_err());
        assert_eq!(overlay.operation_count(), 0);
    }

    let mut wrong_root = source_root;
    wrong_root[0] ^= 1;
    let mut overlay = PocoApplicationBlockOverlayV0::from_projection(
        context(&value, wrong_root),
        &source_projection,
    )
    .expect("structurally valid wrong-root context");
    assert!(overlay.apply_raw(&raw).is_err());
    assert_eq!(overlay.operation_count(), 0);

    let mut overlay = PocoApplicationBlockOverlayV0::from_projection(
        context(&value, source_root),
        &source_projection,
    )
    .expect("duplicate-operation overlay");
    overlay.apply_raw(&raw).expect("first operation");
    assert!(overlay.apply_raw(&raw).is_err());
    assert_eq!(overlay.operation_count(), 1);
    assert_eq!(
        overlay
            .seal()
            .expect("seal after duplicate rejection")
            .mutation_root(),
        hash32(&value, "/authority_successor/mutation_root_hex")
    );
    assert_eq!(
        tree.encode_snapshot().expect("final source snapshot"),
        source_snapshot
    );
}

#[test]
fn equal_root_different_history_replans_and_stale_jmt_plan_fails() {
    let value = vector();
    let primary = source_tree(&value, true);
    let alternate = source_tree(&value, false);
    let source_root = primary.root_hash(1).expect("primary source root").0;
    assert_eq!(
        alternate.root_hash(1).expect("alternate source root").0,
        source_root
    );
    assert_eq!(
        primary
            .verified_live_values(1)
            .expect("primary live values"),
        alternate
            .verified_live_values(1)
            .expect("alternate live values")
    );
    assert_ne!(
        primary.encode_snapshot().expect("primary history"),
        alternate.encode_snapshot().expect("alternate history")
    );

    let raw = raw_operation(&value);
    let mut primary_overlay = PocoApplicationBlockOverlayV0::from_projection(
        context(&value, source_root),
        &projection_at(&primary, 1),
    )
    .expect("primary overlay");
    primary_overlay.apply_raw(&raw).expect("primary operation");
    let primary_plan = primary_overlay.seal().expect("primary sealed plan");
    let writes =
        auth_writes_from_sealed_poco_application_v0(&primary_plan).expect("primary target writes");

    let mut alternate_overlay = PocoApplicationBlockOverlayV0::from_projection(
        context(&value, source_root),
        &projection_at(&alternate, 1),
    )
    .expect("alternate overlay");
    alternate_overlay
        .apply_raw(&raw)
        .expect("alternate operation");
    let alternate_writes = auth_writes_from_sealed_poco_application_v0(
        &alternate_overlay.seal().expect("alternate sealed plan"),
    )
    .expect("alternate target writes");

    let mut primary_applied = primary.clone();
    let mut alternate_applied = alternate.clone();
    let primary_root = primary_applied
        .put_value_set(2, writes.clone())
        .expect("primary target apply");
    let alternate_root = alternate_applied
        .put_value_set(2, alternate_writes)
        .expect("alternate target apply");
    assert_eq!(primary_root, alternate_root);
    assert_eq!(
        primary_applied
            .verified_live_values(2)
            .expect("primary target values"),
        alternate_applied
            .verified_live_values(2)
            .expect("alternate target values")
    );

    let stale = primary
        .plan_put_value_set(2, writes)
        .expect("plan against source head");
    let mut advanced = primary;
    advanced
        .put_value_set(2, std::iter::empty())
        .expect("advance source with no-op version");
    let advanced_root = advanced.root_hash(2).expect("advanced root");
    assert!(advanced.apply(stale).is_err());
    assert_eq!(advanced.root_hash(2), Some(advanced_root));
    assert_eq!(
        advanced
            .verified_live_values(2)
            .expect("stale rejection values"),
        advanced
            .verified_live_values(1)
            .expect("source values after no-op")
    );
}

/// Iterative vector-authoring aid.  This deliberately consumes only already
/// canonical, authority-valid raw operations: it never rewrites a placeholder
/// source root, decision ID, proof, or semantic value.  Authors can therefore
/// add one step, run this ignored test to obtain its full application JMT root,
/// then bind that root into the next step's authenticated decision preimage.
#[test]
#[ignore = "manual iterative operation-sequence full-JMT root exporter"]
fn export_partial_operation_sequence_full_jmt_roots() {
    let value = operation_sequence_authoring_value_v0();
    let value = &value;
    let sequences = value
        .pointer("/operation_sequences/sequences")
        .or_else(|| value.pointer("/sequences"))
        .expect("operation sequence corpus")
        .as_array()
        .expect("operation sequence array");
    assert!(!sequences.is_empty(), "operation sequence corpus is empty");

    for sequence in sequences {
        let sequence_id = sequence["id"].as_str().expect("sequence id");
        let initial = &sequence["initial"];
        let history = initial["history"]
            .as_array()
            .expect("sequence initial history");
        assert!(!history.is_empty(), "sequence initial history is empty");

        let mut tree = InMemoryAuthTree::default();
        let mut prior_version = None;
        for item in history {
            let version = item["version"].as_u64().expect("history version");
            if let Some(prior) = prior_version {
                assert_eq!(
                    version,
                    prior + 1,
                    "sequence {sequence_id} history is not contiguous"
                );
            }
            let root = tree
                .put_value_set(version, history_auth_writes(item))
                .unwrap_or_else(|error| {
                    panic!("sequence {sequence_id} history version {version}: {error:#}")
                })
                .0;
            if let Some(expected) = item["jmt_root_hex"]
                .as_str()
                .filter(|encoded| !encoded.is_empty())
            {
                assert_eq!(
                    hex::encode(root),
                    expected,
                    "sequence {sequence_id} history root drift at version {version}"
                );
            }
            eprintln!(
                "{}",
                serde_json::json!({
                    "sequence_id": sequence_id,
                    "stage": "history",
                    "version": version,
                    "full_jmt_root_hex": hex::encode(root),
                })
            );
            prior_version = Some(version);
        }

        let initial_version = initial["version"]
            .as_u64()
            .expect("sequence initial version");
        assert_eq!(
            prior_version,
            Some(initial_version),
            "sequence {sequence_id} initial version differs from history head"
        );
        let initial_root = tree
            .root_hash(initial_version)
            .expect("sequence initial root")
            .0;
        if let Some(expected) = initial["jmt_root_hex"]
            .as_str()
            .filter(|encoded| !encoded.is_empty())
        {
            assert_eq!(
                hex::encode(initial_root),
                expected,
                "sequence {sequence_id} initial root drift"
            );
        }
        let initial_projection = production_projection_at(&tree, initial_version);
        validate_application_authority_projection_v0(&initial_projection).unwrap_or_else(|error| {
            panic!("sequence {sequence_id} initial authority projection: {error:#}")
        });
        eprintln!(
            "{}",
            serde_json::json!({
                "sequence_id": sequence_id,
                "stage": "initial",
                "version": initial_version,
                "full_jmt_root_hex": hex::encode(initial_root),
                "manifest_hex": hex::encode(initial_projection.manifest().encode()),
                "entries_root_hex": hex::encode(initial_projection.manifest().entries_root()),
            })
        );

        let steps = sequence["steps"].as_array().expect("sequence steps array");
        for step in steps {
            let step_id = step["id"].as_str().expect("sequence step id");
            let context_value = &step["context"];
            let source_version = context_value["source_version"]
                .as_u64()
                .expect("step source version");
            assert_eq!(
                tree.latest_version(),
                Some(source_version),
                "sequence {sequence_id}/{step_id} does not start at the live tree head"
            );
            let source_root = tree.root_hash(source_version).expect("step source root").0;
            let claimed_source_root: [u8; 32] = hex::decode(
                context_value["source_root_hex"]
                    .as_str()
                    .expect("step source root hex"),
            )
            .expect("decode step source root")
            .try_into()
            .expect("Hash32 step source root");
            assert_eq!(
                claimed_source_root, source_root,
                "sequence {sequence_id}/{step_id} authority context is not bound to the real full JMT source root"
            );

            let source_projection = production_projection_at(&tree, source_version);
            validate_application_authority_projection_v0(&source_projection).unwrap_or_else(
                |error| panic!("sequence {sequence_id}/{step_id} source projection: {error:#}"),
            );
            let raw = hex::decode(
                step["raw_operation_json_hex"]
                    .as_str()
                    .expect("step raw operation"),
            )
            .expect("decode step raw operation");
            PocoApplicationOperationV0::decode_exact(&raw).unwrap_or_else(|error| {
                panic!("sequence {sequence_id}/{step_id} exact operation decode: {error:#}")
            });
            let target_height = context_value["target_height"]
                .as_u64()
                .expect("sequence target height");
            let authenticated_context = sequence_context(value, sequence, context_value);
            let mut overlay = PocoApplicationBlockOverlayV0::from_projection(
                authenticated_context,
                &source_projection,
            )
            .unwrap_or_else(|error| {
                panic!("sequence {sequence_id}/{step_id} construct overlay: {error:#}")
            });
            overlay.apply_raw(&raw).unwrap_or_else(|error| {
                panic!("sequence {sequence_id}/{step_id} apply operation: {error:#}")
            });
            let sealed = overlay.seal().unwrap_or_else(|error| {
                panic!("sequence {sequence_id}/{step_id} seal operation: {error:#}")
            });

            if let Some(expected) = optional_hash32(step, "/operation_root_hex") {
                assert_eq!(
                    sealed.operation_root(),
                    expected,
                    "sequence {sequence_id}/{step_id} operation root drift"
                );
            }
            if let Some(expected) = step["operation_count"].as_u64() {
                assert_eq!(
                    u64::from(sealed.operation_count()),
                    expected,
                    "sequence {sequence_id}/{step_id} operation count drift"
                );
            }
            if let Some(expected) = optional_hash32(step, "/mutation_root_hex") {
                assert_eq!(
                    sealed.mutation_root(),
                    expected,
                    "sequence {sequence_id}/{step_id} mutation root drift"
                );
            }
            if let Some(expected) = step["mutation_count"].as_u64() {
                assert_eq!(
                    u64::from(sealed.mutation_count()),
                    expected,
                    "sequence {sequence_id}/{step_id} mutation count drift"
                );
            }

            let writes = auth_writes_from_sealed_poco_application_v0(&sealed)
                .expect("convert exported sealed application writes");
            let planned = tree
                .plan_put_value_set(target_height, writes)
                .unwrap_or_else(|error| {
                    panic!("sequence {sequence_id}/{step_id} plan full JMT: {error:#}")
                });
            let target_root = planned.root_hash.0;
            tree.apply(planned).unwrap_or_else(|error| {
                panic!("sequence {sequence_id}/{step_id} apply full JMT: {error:#}")
            });
            let target_projection = production_projection_at(&tree, target_height);
            validate_application_authority_projection_v0(&target_projection).unwrap_or_else(
                |error| panic!("sequence {sequence_id}/{step_id} target projection: {error:#}"),
            );
            assert_eq!(
                target_projection.manifest(),
                sealed.target_manifest(),
                "sequence {sequence_id}/{step_id} applied manifest differs from sealed plan"
            );

            if let Some(expected) = optional_hash32(step, "/target/jmt_root_hex") {
                assert_eq!(
                    target_root, expected,
                    "sequence {sequence_id}/{step_id} target full JMT root drift"
                );
            }
            if let Some(expected) = step
                .pointer("/target/manifest_hex")
                .and_then(Value::as_str)
                .filter(|encoded| !encoded.is_empty())
            {
                assert_eq!(
                    hex::encode(target_projection.manifest().encode()),
                    expected,
                    "sequence {sequence_id}/{step_id} target manifest drift"
                );
            }
            if let Some(expected) = optional_hash32(step, "/target/entries_root_hex") {
                assert_eq!(
                    target_projection.manifest().entries_root(),
                    expected,
                    "sequence {sequence_id}/{step_id} target entries root drift"
                );
            }
            eprintln!(
                "{}",
                serde_json::json!({
                    "sequence_id": sequence_id,
                    "stage": "step",
                    "step_id": step_id,
                    "source_version": source_version,
                    "source_full_jmt_root_hex": hex::encode(source_root),
                    "target_version": target_height,
                    "target_full_jmt_root_hex": hex::encode(target_root),
                    "manifest_hex": hex::encode(target_projection.manifest().encode()),
                    "entries_root_hex": hex::encode(target_projection.manifest().entries_root()),
                    "operation_root_hex": hex::encode(sealed.operation_root()),
                    "mutation_root_hex": hex::encode(sealed.mutation_root()),
                })
            );
        }
    }
}
