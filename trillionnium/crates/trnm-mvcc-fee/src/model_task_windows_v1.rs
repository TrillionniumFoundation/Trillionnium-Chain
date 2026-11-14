//! Operator-pinned, owner-signed external task windows for unpublished V5.
//! All bytes are installed before genesis; candidates cannot select or replace
//! the task root. Source integrity does not establish truthful labels, independent
//! administration, availability on other peers, or prospective efficacy.
use crate::model_evidence_v3::Task;
use crate::pon_executor::{canonical, Config, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::sync::Arc;
use trnm_protocol::pon_wire::{hash, Hash};

pub const MAX_MANIFEST_BYTES: usize = 1_048_576;
pub const MAX_WINDOWS: usize = 8;
pub const MAX_ROWS: usize = 32;
pub const MAX_SOURCE_BYTES: usize = 8192;
pub const SCHEMA: &str = "native-model-task-windows-manifest-v1";
pub const FEATURE_PROFILE: &str = "signed-ascii-token-hash-256-clipped8-plus-bias-v1";

/// Explicit local configuration pins; none is supplied by a candidate transaction.
#[derive(Clone, Copy)]
pub struct PinnedTaskWindows<'a> {
    pub raw: &'a [u8],
    pub sha256: Hash,
    pub owner: Hash,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TaskInput {
    pub source_path: String,
    pub content_sha256: String,
    pub content_utf8_hex: String,
    pub label: u8,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WindowInput {
    pub activate_round: u64,
    /// SHA256 of the canonical source repository/path/content-hash snapshot.
    pub source_revision: String,
    pub tasks_root: String,
    pub tasks: Vec<TaskInput>,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SignedTaskWindows {
    pub schema: String,
    pub feature_profile: String,
    pub owner: String,
    pub owner_revision: u64,
    pub source_repository: String,
    pub source_class: String,
    pub windows: Vec<WindowInput>,
    pub signature: String,
}
#[derive(Clone)]
pub(crate) struct Window {
    activate_round: u64,
    source_revision: Hash,
    root: Hash,
    tasks: Vec<Task>,
}
/// Only strict decoding, content reconstruction and owner verification construct it.
#[derive(Clone)]
pub struct TaskWindows {
    sha256: Hash,
    owner: Hash,
    owner_revision: u64,
    id: Hash,
    source_class: String,
    windows: Vec<Window>,
}
fn check(ok: bool, error: &'static str) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(error)
    }
}
fn digest(value: &str) -> Result<Hash> {
    check(
        value.len() == 64
            && value
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "TASK_WINDOW_HASH",
    )?;
    let mut out = [0; 32];
    hex::decode_to_slice(value, &mut out).map_err(|_| "TASK_WINDOW_HASH")?;
    Ok(out)
}
fn source_bytes(task: &TaskInput) -> Result<Vec<u8>> {
    check(
        !task.content_utf8_hex.is_empty()
            && task.content_utf8_hex.len() <= 2 * MAX_SOURCE_BYTES
            && task.content_utf8_hex.len().is_multiple_of(2)
            && task
                .content_utf8_hex
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "TASK_WINDOW_CONTENT",
    )?;
    let content = hex::decode(&task.content_utf8_hex).map_err(|_| "TASK_WINDOW_CONTENT")?;
    // This precise family tokenizes ASCII source snippets; arbitrary text-model
    // preprocessing needs a separately specified numeric/feature contract.
    check(
        content.is_ascii() && !content.contains(&0),
        "TASK_WINDOW_CONTENT",
    )?;
    let content_hash: Hash = Sha256::digest(&content).into();
    check(
        content_hash == digest(&task.content_sha256)?,
        "TASK_WINDOW_CONTENT_HASH",
    )?;
    Ok(content)
}
fn valid_path(path: &str) -> bool {
    !path.is_empty()
        && path.len() <= 256
        && path.is_ascii()
        && !path.starts_with('/')
        && !path.contains('\\')
        && path
            .split('/')
            .all(|part| !part.is_empty() && part != "." && part != "..")
}
/// Independently reproducible source revision, including repository and exact
/// included paths/contents. This is not a claim that a remote Git tree was fetched.
pub fn source_revision(repository: &str, tasks: &[TaskInput]) -> Result<Hash> {
    check(
        !repository.is_empty() && repository.len() <= 256 && repository.is_ascii(),
        "TASK_WINDOW_SOURCE",
    )?;
    check((3..=MAX_ROWS).contains(&tasks.len()), "TASK_WINDOW_COUNT")?;
    let mut previous = None;
    for task in tasks {
        check(
            valid_path(&task.source_path)
                && previous.is_none_or(|path: &str| path < task.source_path.as_str()),
            "TASK_WINDOW_ORDER",
        )?;
        source_bytes(task)?;
        previous = Some(task.source_path.as_str());
    }
    let files: Vec<_> = tasks
        .iter()
        .map(|task| json!({"source_path":task.source_path,"content_sha256":task.content_sha256}))
        .collect();
    Ok(Sha256::digest(canonical(
        &json!({"source_repository":repository,"files":files}),
    )?)
    .into())
}
fn features(content: &[u8]) -> Vec<i16> {
    let mut counts = [0_i16; 256];
    let mut at = 0;
    let mut tokens = 0;
    while at < content.len() && tokens < 1024 {
        if !(content[at].is_ascii_alphabetic() || content[at] == b'_') {
            at += 1;
            continue;
        }
        let start = at;
        at += 1;
        while at < content.len() && (content[at].is_ascii_alphanumeric() || content[at] == b'_') {
            at += 1;
        }
        let token = content[start..at].to_ascii_lowercase();
        if token.starts_with(b"trnm")
            || [b"m00".as_slice(), b"m04", b"m10"].contains(&token.as_slice())
        {
            continue;
        }
        let digest = Sha256::digest(&token);
        let index = usize::from(u16::from_le_bytes([digest[0], digest[1]])) % 256;
        counts[index] += if digest[2] & 1 == 1 { 1 } else { -1 };
        tokens += 1;
    }
    let mut result: Vec<_> = counts.into_iter().map(|value| value.clamp(-8, 8)).collect();
    result.push(8);
    result
}
fn task_rows(
    family: Hash,
    repository: &str,
    revision: Hash,
    inputs: &[TaskInput],
) -> Result<Vec<Task>> {
    check(
        source_revision(repository, inputs)? == revision,
        "TASK_WINDOW_SOURCE_REVISION",
    )?;
    let mut contents = BTreeSet::new();
    let mut labels = BTreeSet::new();
    let mut rows = Vec::new();
    for input in inputs {
        check(
            input.label < 3 && contents.insert(digest(&input.content_sha256)?),
            "TASK_WINDOW_TASK_ALIAS",
        )?;
        labels.insert(input.label);
        let features = features(&source_bytes(input)?);
        let encoded: Vec<_> = features
            .iter()
            .flat_map(|value| value.to_le_bytes())
            .collect();
        let id = hash(
            b"native-model-task-window-row-v1",
            &[
                &family,
                repository.as_bytes(),
                &revision,
                input.source_path.as_bytes(),
                &digest(&input.content_sha256)?,
                &[input.label],
                &encoded,
            ],
        );
        rows.push(Task {
            id: hex::encode(id),
            source_group: hex::encode(Sha256::digest(input.source_path.as_bytes())),
            source_path: input.source_path.clone(),
            source_content_sha256: input.content_sha256.clone(),
            label: usize::from(input.label),
            features,
        });
    }
    check(labels.len() == 3, "TASK_WINDOW_CLASSES")?;
    Ok(rows)
}
pub fn tasks_root(
    family: Hash,
    repository: &str,
    revision: Hash,
    tasks: &[TaskInput],
) -> Result<Hash> {
    let rows = task_rows(family, repository, revision, tasks)?;
    Ok(hash(
        b"native-model-task-window-tasks-v1",
        &[&canonical(
            &serde_json::to_value(rows).map_err(|_| "TASK_WINDOW_ENCODING")?,
        )?],
    ))
}
/// Producer convenience only; native loading verifies the exact owner signature.
pub fn signing_digest(family: Hash, manifest: &SignedTaskWindows) -> Result<Hash> {
    let mut value = serde_json::to_value(manifest).map_err(|_| "TASK_WINDOW_ENCODING")?;
    value
        .as_object_mut()
        .ok_or("TASK_WINDOW_ENCODING")?
        .remove("signature");
    Ok(hash(
        b"native-model-task-windows-owner-v1",
        &[&family, &canonical(&value)?],
    ))
}
impl TaskWindows {
    fn decode(cfg: &Config, pinned: PinnedTaskWindows<'_>) -> Result<Self> {
        check(
            !pinned.raw.is_empty() && pinned.raw.len() <= MAX_MANIFEST_BYTES,
            "TASK_WINDOW_LENGTH",
        )?;
        let content_hash: Hash = Sha256::digest(pinned.raw).into();
        check(content_hash == pinned.sha256, "TASK_WINDOW_PIN")?;
        let manifest: SignedTaskWindows =
            serde_json::from_slice(pinned.raw).map_err(|_| "TASK_WINDOW_ENCODING")?;
        check(
            manifest.schema == SCHEMA
                && manifest.feature_profile == FEATURE_PROFILE
                && manifest.owner_revision > 0
                && manifest.owner == hex::encode(pinned.owner)
                && matches!(
                    manifest.source_class.as_str(),
                    "controlled-source" | "external-source-unqualified"
                ),
            "TASK_WINDOW_OWNER",
        )?;
        trnm_crypto_primitives::verify_hex_strict(
            &manifest.owner,
            &signing_digest(cfg.family, &manifest)?,
            &manifest.signature,
        )
        .map_err(|_| "TASK_WINDOW_SIGNATURE")?;
        check(
            (1..=MAX_WINDOWS).contains(&manifest.windows.len()),
            "TASK_WINDOW_COUNT",
        )?;
        let legacy = crate::model_evidence_v3::installed_policy()?;
        let mut contents: BTreeSet<_> = legacy["tasks"]
            .as_array()
            .ok_or("CONFIG")?
            .iter()
            .map(|row| digest(row["source_content_sha256"].as_str().ok_or("CONFIG")?))
            .collect::<Result<_>>()?;
        let mut roots = BTreeSet::new();
        let mut previous = None;
        let mut windows = Vec::new();
        for input in &manifest.windows {
            check(
                input.activate_round <= u64::MAX / 128
                    && previous.is_none_or(|round| round < input.activate_round),
                "TASK_WINDOW_ACTIVATION",
            )?;
            let revision = digest(&input.source_revision)?;
            let tasks = task_rows(
                cfg.family,
                &manifest.source_repository,
                revision,
                &input.tasks,
            )?;
            let root = tasks_root(
                cfg.family,
                &manifest.source_repository,
                revision,
                &input.tasks,
            )?;
            check(digest(&input.tasks_root)? == root, "TASK_WINDOW_ROOT")?;
            check(
                roots.insert(root)
                    && tasks.iter().all(|task| {
                        contents
                            .insert(digest(&task.source_content_sha256).expect("validated digest"))
                    }),
                "TASK_WINDOW_REPEATED_DATA",
            )?;
            windows.push(Window {
                activate_round: input.activate_round,
                source_revision: revision,
                root,
                tasks,
            });
            previous = Some(input.activate_round);
        }
        let id = hash(
            b"native-model-task-windows-manifest-v1",
            &[&canonical(
                &serde_json::to_value(&manifest).map_err(|_| "TASK_WINDOW_ENCODING")?,
            )?],
        );
        Ok(Self {
            sha256: pinned.sha256,
            owner: pinned.owner,
            owner_revision: manifest.owner_revision,
            id,
            source_class: manifest.source_class,
            windows,
        })
    }
    pub(crate) fn selected(&self, generation: u64) -> Option<&Window> {
        self.windows
            .iter()
            .rev()
            .find(|window| window.activate_round <= generation)
    }
    fn metadata(&self) -> Value {
        let schedule: Vec<_> = self.windows.iter().map(|window| json!({"activate_round":window.activate_round,
            "source_revision":hex::encode(window.source_revision),"tasks_root":hex::encode(window.root)})).collect();
        json!({"schema":SCHEMA,"sha256":hex::encode(self.sha256),"manifest":hex::encode(self.id),
            "owner":hex::encode(self.owner),"owner_revision":self.owner_revision,"source_class":self.source_class,
            "schedule":schedule,"independent_accepted":false,"prospective_accepted":false})
    }
}
impl Window {
    pub(crate) fn tasks(&self) -> &[Task] {
        &self.tasks
    }
    pub(crate) fn root(&self) -> Hash {
        self.root
    }
    pub(crate) fn metadata(&self, owner: &TaskWindows) -> Value {
        json!({"manifest":hex::encode(owner.id),"owner":hex::encode(owner.owner),"owner_revision":owner.owner_revision,
            "source_revision":hex::encode(self.source_revision),"source_class":owner.source_class,
            "activate_round":self.activate_round,"tasks_root":hex::encode(self.root),
            "independent_accepted":false,"prospective_accepted":false})
    }
}
pub(crate) fn install(cfg: &mut Config, pinned: PinnedTaskWindows<'_>) -> Result<()> {
    crate::model_evolution_v5::check_context(cfg)?;
    check(cfg.task_windows.is_none(), "TASK_WINDOW_INSTALLED")?;
    let windows = TaskWindows::decode(cfg, pinned)?;
    cfg.params["model_task_windows"] = windows.metadata();
    let label = format!(
        "{}-task-windows-{}",
        cfg.params["chain_label"].as_str().ok_or("CONFIG")?,
        hex::encode(windows.sha256)
    );
    cfg.params["chain_label"] = json!(label);
    cfg.network = hash(b"network", &[label.as_bytes()]);
    let wire: Value = serde_json::from_str(include_str!("../../../../config/pon/ledger-v1.json"))
        .map_err(|_| "CONFIG")?;
    let work: Value =
        serde_json::from_str(include_str!("../../../../config/pon/work-profile-v1.json"))
            .map_err(|_| "CONFIG")?;
    cfg.parameters = hash(
        b"parameters",
        &[
            &canonical(&cfg.params)?,
            &canonical(&wire)?,
            &canonical(&work)?,
            &canonical(&cfg.model_registry)?,
        ],
    );
    cfg.plan = hash(
        b"plan",
        &[
            b"native-integer-model-task-windows-plan-v1",
            &cfg.plan,
            &windows.id,
            &windows.sha256,
            &windows.owner,
        ],
    );
    cfg.task_windows = Some(Arc::new(windows));
    Ok(())
}
pub(crate) fn selected(cfg: &Config, generation: u64) -> Result<Option<(&TaskWindows, &Window)>> {
    match &cfg.task_windows {
        Some(windows) => {
            check(
                crate::model_evolution_v5::enabled(cfg)
                    && cfg.params["model_task_windows"] == windows.metadata(),
                "TASK_WINDOW_CONTEXT",
            )?;
            Ok(windows
                .selected(generation)
                .map(|window| (windows.as_ref(), window)))
        }
        None => {
            check(
                cfg.params.get("model_task_windows").is_none(),
                "TASK_WINDOW_CONTEXT",
            )?;
            Ok(None)
        }
    }
}
