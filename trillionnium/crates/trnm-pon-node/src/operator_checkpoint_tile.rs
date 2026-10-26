//! Explicit complete-original installation and offline operator approvals. This
//! immutable material check never replaces the actual parent/State/source owner.
use crate::{
    ensure,
    operator_deployment::{self, ActorApproval, BootstrapBundle, BootstrapTemplate},
    Result, Settings,
};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{
    fs::OpenOptions,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};
use trnm_crypto_primitives::verify_hex_strict;
pub use trnm_mvcc_fee::deployment_checkpoint_tile_v1::{
    OperatorCheckpointTileSpecV1, PROFILE, SPEC_BYTES,
};
use trnm_mvcc_fee::{
    checkpoint_tile_material_v1::{self, CheckedCheckpointTileMaterialV1},
    checkpoint_tile_policy_v1, deployment_actors,
    pon_executor::{self, Config, State},
    qualified_task_lifecycle,
};
use trnm_protocol::{
    pon_wire::{hash, Hash},
    qualified_work_task::lifecycle_v2::{
        DemandLeaseV2, SignedLifecycleTaskV2, LIFECYCLE_TASK_BYTES,
    },
};
pub const TEMPLATE_SCHEMA: &str = "pon-native-checkpoint-bootstrap-template-v1";
pub const APPROVAL_SCHEMA: &str = "pon-native-checkpoint-approval-v1";
pub const BUNDLE_SCHEMA: &str = "pon-native-checkpoint-bootstrap-bundle-v1";

#[derive(Clone, Debug)]
pub struct CheckpointTileRuntimePaths {
    checkpoint: PathBuf,
    activation: PathBuf,
}
impl CheckpointTileRuntimePaths {
    pub fn new(checkpoint: PathBuf, activation: PathBuf) -> Self {
        Self {
            checkpoint,
            activation,
        }
    }
    pub fn replay(
        &self,
        app: &Config,
        model: &[u8],
        input: &[u8],
    ) -> Result<CheckedCheckpointTileMaterialV1> {
        let policy = app
            .checkpoint_tile_policy()?
            .ok_or("CHECKPOINT_POLICY_REQUIRED")?;
        ensure(
            <[u8; 32]>::from(Sha256::digest(model)) == deployment_actors::digest(&policy.a_sha256)?
                && <[u8; 32]>::from(Sha256::digest(input))
                    == deployment_actors::digest(&policy.b_sha256)?,
            "CHECKPOINT_MATRIX_SHA",
        )?;
        let activation = operator_deployment::offline::read_public(
            &self.activation,
            checkpoint_tile_material_v1::MAX_ACTIVATION_BYTES as u64,
        )?;
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
            .open(&self.checkpoint)
            .map_err(|_| "CHECKPOINT_FILE")?;
        let before = file.metadata().map_err(|_| "CHECKPOINT_FILE")?;
        ensure(
            before.file_type().is_file()
                && before.nlink() == 1
                && before.len() == policy.checkpoint_bytes
                && before.mode() & 0o022 == 0,
            "CHECKPOINT_FILE",
        )?;
        let start = Instant::now();
        let checked = checkpoint_tile_material_v1::derive_checkpoint_tile_material_v1(
            &mut file,
            &activation,
            model,
            input,
            &policy.context(app)?,
            |_| {
                if start.elapsed() < Duration::from_secs(90) {
                    Ok(())
                } else {
                    Err("CHECKPOINT_REPLAY_WALL")
                }
            },
        )?;
        let after = file.metadata().map_err(|_| "CHECKPOINT_FILE")?;
        let identity = |m: &std::fs::Metadata| {
            (
                m.dev(),
                m.ino(),
                m.len(),
                m.mtime(),
                m.mtime_nsec(),
                m.ctime(),
                m.ctime_nsec(),
            )
        };
        ensure(
            identity(&before) == identity(&after),
            "CHECKPOINT_FILE_CHANGED",
        )?;
        policy.check_replay(&checked)?;
        Ok(checked)
    }
}
fn bytes(raw: &str, size: usize) -> Result<Vec<u8>> {
    ensure(
        raw.len() == size * 2
            && raw
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "CHECKPOINT_ACTOR_ENCODING",
    )?;
    hex::decode(raw).map_err(|_| "CHECKPOINT_ACTOR_ENCODING".into())
}
fn objects(
    spec: &OperatorCheckpointTileSpecV1,
    model: &[u8],
    input: &[u8],
) -> Result<(
    Config,
    crate::BootstrapTaskMaterial,
    DemandLeaseV2,
    SignedLifecycleTaskV2,
)> {
    let app = Config::installed_with_operator_checkpoint_tile(spec)?;
    operator_deployment::objects_with_config(&spec.actors, model, input, app)
}
fn requester_message(
    spec: Hash,
    app: &Config,
    lease: &DemandLeaseV2,
    signed: &SignedLifecycleTaskV2,
    descriptor: Hash,
) -> Result<Hash> {
    Ok(hash(
        b"operator-checkpoint-genesis-requester-v1",
        &[
            &spec,
            &app.network,
            &app.parameters,
            &descriptor,
            &lease.encode().map_err(|_| "ACTOR_LEASE")?,
            &signed.manifest.id().map_err(|_| "ACTOR_STATEMENT")?,
        ],
    ))
}
pub fn prepare(
    spec: &OperatorCheckpointTileSpecV1,
    model: &[u8],
    input: &[u8],
    paths: &CheckpointTileRuntimePaths,
) -> Result<BootstrapTemplate> {
    let (app, _, lease, signed) = objects(spec, model, input)?;
    let checked = paths.replay(&app, model, input)?;
    Ok(BootstrapTemplate {
        schema: TEMPLATE_SCHEMA.into(),
        spec_hash: hex::encode(spec.id()?),
        network: hex::encode(app.network),
        parameters: hex::encode(app.parameters),
        lease: hex::encode(lease.encode().map_err(|_| "ACTOR_LEASE")?),
        unsigned_statement: hex::encode(signed.encode().map_err(|_| "ACTOR_STATEMENT")?),
        source_public: spec.actors.source.clone(),
        requester_public: spec.actors.requester.clone(),
        source_message: hex::encode(signed.signing_message().map_err(|_| "ACTOR_STATEMENT")?),
        requester_message: hex::encode(requester_message(
            spec.id()?,
            &app,
            &lease,
            &signed,
            checked.descriptor_id(),
        )?),
        production_activation: false,
        public_network_ready: false,
        independent_governance_accepted: false,
    })
}
fn verify_approval(template: &BootstrapTemplate, a: &ActorApproval, role: &str) -> Result<()> {
    ensure(
        template.schema == TEMPLATE_SCHEMA
            && !template.production_activation
            && !template.public_network_ready
            && !template.independent_governance_accepted,
        "CHECKPOINT_TEMPLATE",
    )?;
    let (public, message) = match role {
        "source" => (&template.source_public, &template.source_message),
        "requester" => (&template.requester_public, &template.requester_message),
        _ => return Err("ACTOR_ROLE".into()),
    };
    ensure(
        a.schema == APPROVAL_SCHEMA
            && a.role == role
            && a.spec_hash == template.spec_hash
            && a.network == template.network
            && a.parameters == template.parameters
            && &a.public_key == public
            && &a.message == message,
        "CHECKPOINT_APPROVAL_CONTEXT",
    )?;
    bytes(&a.signature, 64)?;
    verify_hex_strict(public, &bytes(message, 32)?, &a.signature)
        .map_err(|_| "CHECKPOINT_APPROVAL_SIGNATURE".into())
}
pub fn approval(
    template: &BootstrapTemplate,
    role: &str,
    signature: String,
) -> Result<ActorApproval> {
    let (public, message) = match role {
        "source" => (&template.source_public, &template.source_message),
        "requester" => (&template.requester_public, &template.requester_message),
        _ => return Err("ACTOR_ROLE".into()),
    };
    let a = ActorApproval {
        schema: APPROVAL_SCHEMA.into(),
        role: role.into(),
        spec_hash: template.spec_hash.clone(),
        network: template.network.clone(),
        parameters: template.parameters.clone(),
        public_key: public.clone(),
        message: message.clone(),
        signature,
    };
    verify_approval(template, &a, role)?;
    Ok(a)
}
pub fn sign_approval_from_file(
    spec: &OperatorCheckpointTileSpecV1,
    template: &BootstrapTemplate,
    model: &[u8],
    input: &[u8],
    paths: &CheckpointTileRuntimePaths,
    role: &str,
    secret: &Path,
) -> Result<ActorApproval> {
    let expected = prepare(spec, model, input, paths)?;
    ensure(*template == expected, "CHECKPOINT_TEMPLATE")?;
    let (public, message) = match role {
        "source" => (&expected.source_public, &expected.source_message),
        "requester" => (&expected.requester_public, &expected.requester_message),
        _ => return Err("ACTOR_ROLE".into()),
    };
    let signature = operator_deployment::offline::sign_pinned_digest_from_file(
        public,
        bytes(message, 32)?
            .try_into()
            .map_err(|_| "CHECKPOINT_ACTOR_ENCODING")?,
        secret,
    )?;
    approval(&expected, role, hex::encode(signature))
}
pub fn assemble(
    template: &BootstrapTemplate,
    source: &ActorApproval,
    requester: &ActorApproval,
) -> Result<BootstrapBundle> {
    verify_approval(template, source, "source")?;
    verify_approval(template, requester, "requester")?;
    let mut signed =
        SignedLifecycleTaskV2::decode(&bytes(&template.unsigned_statement, LIFECYCLE_TASK_BYTES)?)
            .map_err(|_| "ACTOR_STATEMENT")?;
    ensure(signed.signature == [0; 64], "CHECKPOINT_TEMPLATE")?;
    signed.signature = bytes(&source.signature, 64)?
        .try_into()
        .map_err(|_| "ACTOR_SIGNATURE")?;
    Ok(BootstrapBundle {
        schema: BUNDLE_SCHEMA.into(),
        spec_hash: template.spec_hash.clone(),
        network: template.network.clone(),
        parameters: template.parameters.clone(),
        lease: template.lease.clone(),
        signed_statement: hex::encode(signed.encode().map_err(|_| "ACTOR_STATEMENT")?),
        requester_approval: requester.clone(),
    })
}
impl Settings {
    pub fn development_with_operator_checkpoint_tile(
        spec: &OperatorCheckpointTileSpecV1,
        bundle: &BootstrapBundle,
        model: &[u8],
        input: &[u8],
        paths: CheckpointTileRuntimePaths,
    ) -> Result<Self> {
        let expected = prepare(spec, model, input, &paths)?;
        ensure(
            bundle.schema == BUNDLE_SCHEMA
                && bundle.spec_hash == expected.spec_hash
                && bundle.network == expected.network
                && bundle.parameters == expected.parameters
                && bundle.lease == expected.lease,
            "CHECKPOINT_BOOTSTRAP_CONTEXT",
        )?;
        verify_approval(&expected, &bundle.requester_approval, "requester")?;
        let (app, material, lease, mut unsigned) = objects(spec, model, input)?;
        let signed =
            SignedLifecycleTaskV2::decode(&bytes(&bundle.signed_statement, LIFECYCLE_TASK_BYTES)?)
                .map_err(|_| "ACTOR_STATEMENT")?;
        unsigned.signature = signed.signature;
        ensure(unsigned == signed, "CHECKPOINT_BOOTSTRAP_STATEMENT")?;
        let boot = qualified_task_lifecycle::bootstrap_from_signed(&app, lease, signed)?;
        let mut initial = State::new();
        initial.insert("meta:issued".into(), json!(spec.actors.issued()?));
        initial.insert("model:current".into(), json!(hex::encode([0; 32])));
        initial.extend(boot.state.clone());
        for a in &spec.actors.allocations {
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
                &spec.actors.genesis_timestamp.to_le_bytes(),
            ],
        );
        Ok(Self {
            app,
            genesis,
            initial,
            operator_bootstrap: Some(boot),
            operator_material: Some(material),
            checkpoint_tile_paths: Some(paths),
        })
    }
    pub(crate) fn replay_checkpoint_tile_material(&self) -> Result<()> {
        if self.task_profile() != checkpoint_tile_policy_v1::PROFILE {
            ensure(
                self.checkpoint_tile_paths.is_none(),
                "CHECKPOINT_MATERIAL_UNEXPECTED",
            )?;
            return Ok(());
        }
        let paths = self
            .checkpoint_tile_paths
            .as_ref()
            .ok_or("CHECKPOINT_MATERIAL_REQUIRED")?;
        let (model, input, _, _) = self
            .operator_material
            .as_ref()
            .ok_or("CHECKPOINT_MATERIAL_REQUIRED")?;
        paths.replay(&self.app, model, input)?;
        Ok(())
    }
}
