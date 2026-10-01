//! Public-only development bootstrap. Network and parameters commit the descriptor;
//! offline approvals then commit that context; genesis commits the verified state.
//! Neither strict keys nor signatures prove independent operators or honest demand.
pub mod offline;
use crate::{ensure, BootstrapTaskMaterial, Result, Settings};
use serde::{Deserialize, Serialize};
use serde_json::json;
use trnm_crypto_primitives::{pon_work, qualified_work_task::derive_matrices, verify_hex_strict};
pub use trnm_mvcc_fee::deployment_actors::{
    BootstrapMaterialSpec, GenesisAllocation, OperatorDeploymentSpec, PROFILE, SPEC_BYTES,
};
use trnm_mvcc_fee::{
    deployment_actors::{self},
    pon_executor::{self, Config, State},
    qualified_task_lifecycle,
};
use trnm_protocol::{
    pon_wire::{hash, Hash},
    qualified_work_task::{
        lifecycle_v2::{DemandLeaseV2, SignedLifecycleTaskV2},
        QualifiedWorkTask, TaskPurpose, LOGICAL_MULTIPLY_ADD_UNITS, MATRIX_ARTIFACT_BYTES,
    },
};
pub const BOOTSTRAP_BYTES: usize = 8192;
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BootstrapTemplate {
    pub schema: String,
    pub spec_hash: String,
    pub network: String,
    pub parameters: String,
    pub lease: String,
    pub unsigned_statement: String,
    pub source_public: String,
    pub requester_public: String,
    pub source_message: String,
    pub requester_message: String,
    pub production_activation: bool,
    pub public_network_ready: bool,
    pub independent_governance_accepted: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ActorApproval {
    pub schema: String,
    pub role: String,
    pub spec_hash: String,
    pub network: String,
    pub parameters: String,
    pub public_key: String,
    pub message: String,
    pub signature: String,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BootstrapBundle {
    pub schema: String,
    pub spec_hash: String,
    pub network: String,
    pub parameters: String,
    pub lease: String,
    pub signed_statement: String,
    pub requester_approval: ActorApproval,
}
pub fn canonical<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    Ok(deployment_actors::canonical(value)?)
}
pub fn decode<T: serde::de::DeserializeOwned + Serialize>(raw: &[u8]) -> Result<T> {
    Ok(deployment_actors::decode(raw, BOOTSTRAP_BYTES)?)
}
fn bytes(raw: &str, size: usize) -> Result<Vec<u8>> {
    ensure(
        raw.len() == size * 2
            && raw
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "ACTOR_ENCODING",
    )?;
    Ok(hex::decode(raw).map_err(|_| "ACTOR_ENCODING")?)
}
fn material(
    spec: &OperatorDeploymentSpec,
    model: &[u8],
    input: &[u8],
) -> Result<BootstrapTaskMaterial> {
    ensure(
        model.len() == MATRIX_ARTIFACT_BYTES as usize
            && input.len() == MATRIX_ARTIFACT_BYTES as usize,
        "ACTOR_MATERIAL_LENGTH",
    )?;
    ensure(
        hash(b"artifact", &[model]) == deployment_actors::digest(&spec.bootstrap.model)?
            && hash(b"qualified-task-input-v1", &[input])
                == deployment_actors::digest(&spec.bootstrap.input)?,
        "ACTOR_MATERIAL",
    )?;
    let (a, b) = derive_matrices(model, input).map_err(|_| "ACTOR_MATERIAL")?;
    Ok((model.to_vec(), input.to_vec(), a, b))
}
fn objects(
    spec: &OperatorDeploymentSpec,
    model: &[u8],
    input: &[u8],
) -> Result<(
    Config,
    BootstrapTaskMaterial,
    DemandLeaseV2,
    SignedLifecycleTaskV2,
)> {
    let app = Config::installed_with_operator_actors(spec)?;
    let material = material(spec, model, input)?;
    let mut lease = DemandLeaseV2 {
        slot: 0,
        purpose: TaskPurpose::Maintenance,
        network: app.network,
        parameters: app.parameters,
        demand_id: [1; 32],
        requester: deployment_actors::operator_key(&spec.requester)?,
        source: deployment_actors::operator_key(&spec.source)?,
        source_record: deployment_actors::digest(&spec.bootstrap.source_record)?,
        authorization_scope: deployment_actors::digest(&spec.bootstrap.authorization_scope)?,
        availability_manifest: deployment_actors::digest(&spec.bootstrap.availability_manifest)?,
        availability_root: deployment_actors::digest(&spec.bootstrap.availability_root)?,
        generation: 1,
        revision: 1,
        not_before: 0,
        expires: 1000,
        available_until: 1100,
        cost_class: 1,
    };
    lease.demand_id = lease.derived_demand_id();
    let model_id = deployment_actors::digest(&spec.bootstrap.model)?;
    let mut manifest = QualifiedWorkTask {
        purpose: TaskPurpose::Maintenance,
        cost_class: 1,
        numeric_encoding: 1,
        hardness_status: 0,
        reuse: 1,
        network: app.network,
        parameters: app.parameters,
        work_profile: QualifiedWorkTask::profile_id(),
        source: lease.source,
        demand_id: lease.demand_id,
        source_record: lease.bound_source_record().map_err(|_| "ACTOR_LEASE")?,
        model: model_id,
        layer: QualifiedWorkTask::layer_id(model_id),
        input: deployment_actors::digest(&spec.bootstrap.input)?,
        recipe: QualifiedWorkTask::recipe_id(),
        matrix_task: pon_work::task_id(&material.2, &material.3).map_err(|_| "ACTOR_MATERIAL")?,
        availability_manifest: lease.availability_manifest,
        availability_root: lease.availability_root,
        authorization_scope: lease.authorization_scope,
        withdrawal_head: lease.withdrawal_frontier().map_err(|_| "ACTOR_LEASE")?,
        output_meter: [1; 32],
        rows: 64,
        inner: 64,
        columns: 64,
        demand_nonce: 1,
        not_before: 0,
        expires: 1000,
        available_until: 1100,
        logical_multiply_add_units: LOGICAL_MULTIPLY_ADD_UNITS,
        model_bytes: MATRIX_ARTIFACT_BYTES,
        input_bytes: MATRIX_ARTIFACT_BYTES,
        useful_output_limit: 0,
    };
    manifest.output_meter = manifest.derived_output_meter();
    let signed = SignedLifecycleTaskV2 {
        lease_id: lease.id().map_err(|_| "ACTOR_LEASE")?,
        manifest,
        signature: [0; 64],
    };
    Ok((app, material, lease, signed))
}
fn requester_message(
    spec: Hash,
    app: &Config,
    lease: &DemandLeaseV2,
    signed: &SignedLifecycleTaskV2,
) -> Result<Hash> {
    Ok(hash(
        b"operator-genesis-requester-approval-v1",
        &[
            &spec,
            &app.network,
            &app.parameters,
            &lease.encode().map_err(|_| "ACTOR_LEASE")?,
            &signed.manifest.id().map_err(|_| "ACTOR_STATEMENT")?,
        ],
    ))
}
pub fn prepare(
    spec: &OperatorDeploymentSpec,
    model: &[u8],
    input: &[u8],
) -> Result<BootstrapTemplate> {
    let (app, _, lease, signed) = objects(spec, model, input)?;
    Ok(BootstrapTemplate {
        schema: "pon-native-operator-bootstrap-template-v1".into(),
        spec_hash: hex::encode(spec.id()?),
        network: hex::encode(app.network),
        parameters: hex::encode(app.parameters),
        lease: hex::encode(lease.encode().map_err(|_| "ACTOR_LEASE")?),
        unsigned_statement: hex::encode(signed.encode().map_err(|_| "ACTOR_STATEMENT")?),
        source_public: spec.source.clone(),
        requester_public: spec.requester.clone(),
        source_message: hex::encode(signed.signing_message().map_err(|_| "ACTOR_STATEMENT")?),
        requester_message: hex::encode(requester_message(spec.id()?, &app, &lease, &signed)?),
        production_activation: false,
        public_network_ready: false,
        independent_governance_accepted: false,
    })
}
/// The signer must independently re-run prepare with actual descriptor/material,
/// compare this public template, and pin the secret's actual public key to the role.
pub fn approval(
    template: &BootstrapTemplate,
    role: &str,
    signature: String,
) -> Result<ActorApproval> {
    bytes(&signature, 64)?;
    let (public_key, message) = match role {
        "source" => (&template.source_public, &template.source_message),
        "requester" => (&template.requester_public, &template.requester_message),
        _ => return Err("ACTOR_ROLE".into()),
    };
    let result = ActorApproval {
        schema: "pon-native-operator-approval-v1".into(),
        role: role.into(),
        spec_hash: template.spec_hash.clone(),
        network: template.network.clone(),
        parameters: template.parameters.clone(),
        public_key: public_key.clone(),
        message: message.clone(),
        signature,
    };
    verify_approval(template, &result, role)?;
    Ok(result)
}
fn verify_approval(template: &BootstrapTemplate, a: &ActorApproval, role: &str) -> Result<()> {
    let (public, message) = match role {
        "source" => (&template.source_public, &template.source_message),
        "requester" => (&template.requester_public, &template.requester_message),
        _ => return Err("ACTOR_ROLE".into()),
    };
    ensure(
        a.schema == "pon-native-operator-approval-v1"
            && a.role == role
            && a.spec_hash == template.spec_hash
            && a.network == template.network
            && a.parameters == template.parameters
            && &a.public_key == public
            && &a.message == message,
        "ACTOR_APPROVAL_CONTEXT",
    )?;
    bytes(&a.signature, 64)?;
    verify_hex_strict(public, &bytes(message, 32)?, &a.signature)
        .map_err(|_| "ACTOR_APPROVAL_SIGNATURE")?;
    Ok(())
}
pub fn assemble(
    template: &BootstrapTemplate,
    source: &ActorApproval,
    requester: &ActorApproval,
) -> Result<BootstrapBundle> {
    verify_approval(template, source, "source")?;
    verify_approval(template, requester, "requester")?;
    let mut signed = SignedLifecycleTaskV2::decode(&bytes(
        &template.unsigned_statement,
        trnm_protocol::qualified_work_task::lifecycle_v2::LIFECYCLE_TASK_BYTES,
    )?)
    .map_err(|_| "ACTOR_STATEMENT")?;
    ensure(signed.signature == [0; 64], "ACTOR_TEMPLATE")?;
    signed.signature = bytes(&source.signature, 64)?
        .try_into()
        .map_err(|_| "ACTOR_SIGNATURE")?;
    Ok(BootstrapBundle {
        schema: "pon-native-operator-bootstrap-bundle-v1".into(),
        spec_hash: template.spec_hash.clone(),
        network: template.network.clone(),
        parameters: template.parameters.clone(),
        lease: template.lease.clone(),
        signed_statement: hex::encode(signed.encode().map_err(|_| "ACTOR_STATEMENT")?),
        requester_approval: requester.clone(),
    })
}
impl Settings {
    /// Public descriptor/material/signatures only. No actor private key is read
    /// or used to sign here; genesis follows both verified offline approvals.
    pub fn development_with_operator_actors(
        spec: &OperatorDeploymentSpec,
        bundle: &BootstrapBundle,
        model: &[u8],
        input: &[u8],
    ) -> Result<Self> {
        let expected = prepare(spec, model, input)?;
        ensure(
            bundle.schema == "pon-native-operator-bootstrap-bundle-v1"
                && bundle.spec_hash == expected.spec_hash
                && bundle.network == expected.network
                && bundle.parameters == expected.parameters
                && bundle.lease == expected.lease,
            "ACTOR_BOOTSTRAP_CONTEXT",
        )?;
        verify_approval(&expected, &bundle.requester_approval, "requester")?;
        let (app, material, lease, mut unsigned) = objects(spec, model, input)?;
        let signed = SignedLifecycleTaskV2::decode(&bytes(
            &bundle.signed_statement,
            trnm_protocol::qualified_work_task::lifecycle_v2::LIFECYCLE_TASK_BYTES,
        )?)
        .map_err(|_| "ACTOR_STATEMENT")?;
        unsigned.signature = signed.signature;
        ensure(unsigned == signed, "ACTOR_BOOTSTRAP_STATEMENT")?;
        let bootstrap = qualified_task_lifecycle::bootstrap_from_signed(&app, lease, signed)?;
        let mut initial = State::new();
        initial.insert("meta:issued".into(), json!(spec.issued()?));
        initial.insert("model:current".into(), json!(hex::encode([0; 32])));
        initial.extend(bootstrap.state.clone());
        for a in &spec.allocations {
            initial.insert(
                format!("account:{}", a.public_key),
                json!({"balance":a.balance,"nonce":0}),
            );
        }
        let genesis = hash(
            b"genesis",
            &[
                &app.network,
                &app.parameters,
                &pon_executor::root(&initial)?,
                &spec.genesis_timestamp.to_le_bytes(),
            ],
        );
        Ok(Self {
            app,
            genesis,
            initial,
            operator_bootstrap: Some(bootstrap),
            operator_material: Some(material),
        })
    }
    pub fn operator_actor_profile(&self) -> Option<&str> {
        self.app.params["actor_profile"].as_str()
    }
}
