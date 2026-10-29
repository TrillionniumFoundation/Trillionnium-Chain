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
    fs::{self, File, OpenOptions},
    marker::PhantomData,
    os::unix::fs::{FileExt, MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    rc::Rc,
    sync::Arc,
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
/// Local owner checkpoints only. These never enter an activation or signature.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ReplayProgress {
    Material(checkpoint_tile_material_v1::MaterialProgress),
    ActivationRead(u64),
    SecondCheckpointHash(u64),
    SecondActivationHash(u64),
    Settings,
}
type ReplayCheck<'a> = &'a dyn Fn(ReplayProgress) -> Result<()>;
type FileIdentity = (u64, u64, u64, u64, u32, u32, u32, i64, i64, i64, i64);
fn file_identity(m: &fs::Metadata) -> FileIdentity {
    (
        m.dev(),
        m.ino(),
        m.len(),
        m.nlink(),
        m.mode(),
        m.uid(),
        m.gid(),
        m.mtime(),
        m.mtime_nsec(),
        m.ctime(),
        m.ctime_nsec(),
    )
}
struct HeldOriginal {
    path: PathBuf,
    file: File,
    identity: FileIdentity,
}
impl HeldOriginal {
    fn open(path: &Path, limit: u64) -> Result<Self> {
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
            .open(path)?;
        let m = file.metadata()?;
        ensure(
            m.is_file() && m.nlink() == 1 && m.len() <= limit && m.mode() & 0o022 == 0,
            "CHECKPOINT_FILE",
        )?;
        let held = Self {
            path: path.to_owned(),
            file,
            identity: file_identity(&m),
        };
        held.ready()?;
        Ok(held)
    }
    fn ready(&self) -> Result<()> {
        ensure(
            file_identity(&self.file.metadata()?) == self.identity
                && file_identity(&fs::symlink_metadata(&self.path)?) == self.identity,
            "CHECKPOINT_FILE_CHANGED",
        )
    }
    fn scan(
        &self,
        phase: fn(u64) -> ReplayProgress,
        progress: ReplayCheck<'_>,
        collect: bool,
    ) -> Result<(Hash, Vec<u8>)> {
        self.ready()?;
        let mut hasher = Sha256::new();
        let mut bytes = Vec::new();
        let mut buffer = [0u8; 65_536];
        let mut offset = 0;
        progress(phase(offset))?;
        while offset < self.identity.2 {
            let amount = (self.identity.2 - offset).min(buffer.len() as u64) as usize;
            let n = self.file.read_at(&mut buffer[..amount], offset)?;
            ensure(n > 0, "CHECKPOINT_FILE_CHANGED")?;
            hasher.update(&buffer[..n]);
            if collect {
                bytes.extend_from_slice(&buffer[..n]);
            }
            offset += n as u64;
            progress(phase(offset))?;
        }
        ensure(
            self.file.read_at(&mut [0u8; 1], offset)? == 0,
            "CHECKPOINT_FILE_CHANGED",
        )?;
        self.ready()?;
        Ok((hasher.finalize().into(), bytes))
    }
}

/// An owned one-shot material result, never a Clone flag on general Settings.
pub(crate) struct PreparedHistoryCheckpoint {
    settings: Settings,
    seal: StartupMaterialSeal,
}
impl PreparedHistoryCheckpoint {
    pub(crate) fn settings(&self) -> &Settings {
        &self.settings
    }
    pub(crate) fn into_parts(self) -> (Settings, StartupMaterialSeal) {
        (self.settings, self.seal)
    }
}
pub(crate) struct StartupMaterialSeal {
    checked: CheckedCheckpointTileMaterialV1,
    checkpoint: HeldOriginal,
    activation: HeldOriginal,
    scope: crate::store::history_effect_v6::StartupScope,
    spec_sha256: Hash,
    bundle_sha256: Hash,
    settings_sha256: Hash,
    task_windows: Option<Arc<trnm_mvcc_fee::model_task_windows_v1::TaskWindows>>,
    _owner_thread: PhantomData<Rc<()>>,
}
pub(crate) struct CurrentStartupMaterial<'a> {
    pub scope: crate::store::history_effect_v6::StartupScope,
    pub spec: &'a [u8],
    pub bundle: &'a [u8],
    pub model: &'a [u8],
    pub input: &'a [u8],
}
pub(crate) struct HistoryCheckpointInput<'a> {
    pub spec: &'a [u8],
    pub bundle: &'a [u8],
    pub model: &'a [u8],
    pub input: &'a [u8],
}
fn settings_digest(settings: &Settings) -> Result<Hash> {
    let boot = settings
        .operator_bootstrap
        .as_ref()
        .ok_or("CHECKPOINT_BOOTSTRAP_CONTEXT")?;
    let app = &settings.app;
    let raw = operator_deployment::canonical(&json!({
        "network":app.network,"parameters":app.parameters,"family":app.family,"plan":app.plan,
        "evaluators":app.evaluators,"fees":app.fees,"params":app.params,"model_registry":app.model_registry,
        "genesis":settings.genesis,"initial":settings.initial,"material":settings.operator_material,
        "lease":hex::encode(boot.lease.encode().map_err(|_|"ACTOR_LEASE")?),
        "statement":hex::encode(boot.signed.encode().map_err(|_|"ACTOR_STATEMENT")?),"bootstrap_state":boot.state
    }))?;
    Ok(Sha256::digest(raw).into())
}
impl StartupMaterialSeal {
    pub(crate) fn verify_and_consume(
        self,
        settings: &Settings,
        current: CurrentStartupMaterial<'_>,
        progress: ReplayCheck<'_>,
    ) -> Result<()> {
        progress(ReplayProgress::Settings)?;
        ensure(
            self.scope.same_operation(&current.scope),
            "HISTORY_V6_STARTUP_SEAL_SCOPE",
        )?;
        ensure(
            self.spec_sha256 == Hash::from(Sha256::digest(current.spec))
                && self.bundle_sha256 == Hash::from(Sha256::digest(current.bundle))
                && self.settings_sha256 == settings_digest(settings)?,
            "HISTORY_V6_STARTUP_SEAL_CONTEXT",
        )?;
        ensure(
            match (&self.task_windows, &settings.app.task_windows) {
                (None, None) => true,
                (Some(a), Some(b)) => Arc::ptr_eq(a, b),
                _ => false,
            },
            "HISTORY_V6_STARTUP_SEAL_CONTEXT",
        )?;
        let policy = settings
            .app
            .checkpoint_tile_policy()?
            .ok_or("CHECKPOINT_POLICY_REQUIRED")?;
        let (model, input, _, _) = settings
            .operator_material
            .as_ref()
            .ok_or("CHECKPOINT_MATERIAL_REQUIRED")?;
        ensure(
            model == current.model
                && input == current.input
                && Hash::from(Sha256::digest(current.model))
                    == deployment_actors::digest(&policy.a_sha256)?
                && Hash::from(Sha256::digest(current.input))
                    == deployment_actors::digest(&policy.b_sha256)?,
            "CHECKPOINT_MATRIX_SHA",
        )?;
        let paths = settings
            .checkpoint_tile_paths
            .as_ref()
            .ok_or("CHECKPOINT_MATERIAL_REQUIRED")?;
        ensure(
            paths.checkpoint == self.checkpoint.path && paths.activation == self.activation.path,
            "HISTORY_V6_STARTUP_SEAL_CONTEXT",
        )?;
        let (checkpoint, _) =
            self.checkpoint
                .scan(ReplayProgress::SecondCheckpointHash, progress, false)?;
        let (activation, _) =
            self.activation
                .scan(ReplayProgress::SecondActivationHash, progress, false)?;
        let context = policy.context(&settings.app)?;
        ensure(
            checkpoint == context.checkpoint_sha256 && activation == context.activation_sha256,
            "HISTORY_V6_STARTUP_SEAL_BYTES",
        )?;
        policy.check_replay(&self.checked)?;
        self.checkpoint.ready()?;
        self.activation.ready()?;
        progress(ReplayProgress::Settings)
    }
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
    template_from_checked(spec, &app, &lease, &signed, checked.descriptor_id())
}
fn template_from_checked(
    spec: &OperatorCheckpointTileSpecV1,
    app: &Config,
    lease: &DemandLeaseV2,
    signed: &SignedLifecycleTaskV2,
    descriptor_id: Hash,
) -> Result<BootstrapTemplate> {
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
            app,
            lease,
            signed,
            descriptor_id,
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
        Self::checkpoint_settings_from_expected(
            spec,
            bundle,
            model,
            input,
            paths,
            &expected,
            &|_| Ok(()),
        )
    }
    pub(crate) fn prepare_history_checkpoint(
        material: HistoryCheckpointInput<'_>,
        paths: CheckpointTileRuntimePaths,
        scope: crate::store::history_effect_v6::StartupScope,
        progress: ReplayCheck<'_>,
    ) -> Result<PreparedHistoryCheckpoint> {
        progress(ReplayProgress::Settings)?;
        let spec = OperatorCheckpointTileSpecV1::decode(material.spec)?;
        let bundle: BootstrapBundle = operator_deployment::decode(material.bundle)?;
        let (model, input) = (material.model, material.input);
        progress(ReplayProgress::Settings)?;
        let (app, _, lease, signed) = objects(&spec, model, input)?;
        let policy = app
            .checkpoint_tile_policy()?
            .ok_or("CHECKPOINT_POLICY_REQUIRED")?;
        ensure(
            Hash::from(Sha256::digest(model)) == deployment_actors::digest(&policy.a_sha256)?
                && Hash::from(Sha256::digest(input))
                    == deployment_actors::digest(&policy.b_sha256)?,
            "CHECKPOINT_MATRIX_SHA",
        )?;
        let activation = HeldOriginal::open(
            &paths.activation,
            checkpoint_tile_material_v1::MAX_ACTIVATION_BYTES as u64,
        )?;
        let (_, activation_raw) =
            activation.scan(ReplayProgress::ActivationRead, progress, true)?;
        let mut checkpoint = HeldOriginal::open(&paths.checkpoint, policy.checkpoint_bytes)?;
        ensure(
            checkpoint.identity.2 == policy.checkpoint_bytes,
            "CHECKPOINT_FILE",
        )?;
        let start = Instant::now();
        let mut first_error = None;
        let checked = checkpoint_tile_material_v1::derive_checkpoint_tile_material_v1_with_progress(
            &mut checkpoint.file,
            &activation_raw,
            model,
            input,
            &policy.context(&app)?,
            |event| {
                let result = ensure(
                    start.elapsed() < Duration::from_secs(90),
                    "CHECKPOINT_REPLAY_WALL",
                )
                .and_then(|_| progress(ReplayProgress::Material(event)));
                if let Err(error) = result {
                    first_error = Some(error);
                    Err("CHECKPOINT_OWNER_BOUNDARY_ABORT")
                } else {
                    Ok(())
                }
            },
        );
        if let Some(error) = first_error {
            return Err(error);
        }
        let checked = checked?;
        checkpoint.ready()?;
        activation.ready()?;
        policy.check_replay(&checked)?;
        let expected =
            template_from_checked(&spec, &app, &lease, &signed, checked.descriptor_id())?;
        let settings = Self::checkpoint_settings_from_expected(
            &spec, &bundle, model, input, paths, &expected, progress,
        )?;
        let seal = StartupMaterialSeal {
            checked,
            checkpoint,
            activation,
            scope,
            // The original codecs accept one final LF. Bind the exact protected
            // bytes actually decoded, including that legal LF, without normalizing.
            spec_sha256: Sha256::digest(material.spec).into(),
            bundle_sha256: Sha256::digest(material.bundle).into(),
            settings_sha256: settings_digest(&settings)?,
            task_windows: settings.app.task_windows.clone(),
            _owner_thread: PhantomData,
        };
        progress(ReplayProgress::Settings)?;
        Ok(PreparedHistoryCheckpoint { settings, seal })
    }
    fn checkpoint_settings_from_expected(
        spec: &OperatorCheckpointTileSpecV1,
        bundle: &BootstrapBundle,
        model: &[u8],
        input: &[u8],
        paths: CheckpointTileRuntimePaths,
        expected: &BootstrapTemplate,
        progress: ReplayCheck<'_>,
    ) -> Result<Self> {
        progress(ReplayProgress::Settings)?;
        ensure(
            bundle.schema == BUNDLE_SCHEMA
                && bundle.spec_hash == expected.spec_hash
                && bundle.network == expected.network
                && bundle.parameters == expected.parameters
                && bundle.lease == expected.lease,
            "CHECKPOINT_BOOTSTRAP_CONTEXT",
        )?;
        verify_approval(expected, &bundle.requester_approval, "requester")?;
        progress(ReplayProgress::Settings)?;
        let (app, material, lease, mut unsigned) = objects(spec, model, input)?;
        let signed =
            SignedLifecycleTaskV2::decode(&bytes(&bundle.signed_statement, LIFECYCLE_TASK_BYTES)?)
                .map_err(|_| "ACTOR_STATEMENT")?;
        unsigned.signature = signed.signature;
        ensure(unsigned == signed, "CHECKPOINT_BOOTSTRAP_STATEMENT")?;
        let boot = qualified_task_lifecycle::bootstrap_from_signed(&app, lease, signed)?;
        progress(ReplayProgress::Settings)?;
        let mut initial = State::new();
        initial.insert("meta:issued".into(), json!(spec.actors.issued()?));
        initial.insert("model:current".into(), json!(hex::encode([0; 32])));
        initial.extend(boot.state.clone());
        for (index, a) in spec.actors.allocations.iter().enumerate() {
            if index.is_multiple_of(32) {
                progress(ReplayProgress::Settings)?;
            }
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
        progress(ReplayProgress::Settings)?;
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
