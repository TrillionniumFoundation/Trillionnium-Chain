//! Explicit dual-authority repair of exactly one complete V6 publication.
//! Ordinary V6 open/signatures/events are unchanged. The fresh repair domain
//! acknowledges exact existing bytes; it cannot synthesize a frame, settle CPU,
//! forgive debt, rewind spend, create a Node or continue a reorganization.
use super::*;
use serde::{Deserialize, Serialize};

const DOMAIN: &[u8] = b"TRNM-HISTORY-JOURNAL-PUBLICATION-REPAIR-V1";

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::store::history_effect_v6) struct Authorization {
    pub schema: String,
    pub identity: Identity,
    pub prefix_anchor: Anchor,
    pub published_anchor: Anchor,
    pub frame_sha256: String,
    pub frame_bytes: u64,
    pub issued_ns: u64,
    pub expires_ns: u64,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Configuration {
    schema: String,
    identity: Identity,
    journal_path: PathBuf,
    outside_latest_anchor: Anchor,
    signed_publication: Vec<u8>,
}
/// A bounded protected local file pins authority keys and an external exact
/// latest anchor. No journal-derived anchor is promoted to authority by parsing.
pub struct ProtectedHistoryJournalPublicationV1Input {
    config: Configuration,
    expected_uid: u32,
    _file: File,
}
impl ProtectedHistoryJournalPublicationV1Input {
    pub fn load(path: &Path, expected_uid: u32, expected_sha256: &str) -> Result<Self> {
        let (raw, file) = policy::protected_file(path, expected_uid, expected_sha256)?;
        let config: Configuration = serde_json::from_slice(&raw)?;
        ensure(
            config.schema == "restricted-history-journal-publication-input-v1",
            "HISTORY_PUBLICATION_CONFIGURATION",
        )?;
        config.identity.validate()?;
        config.outside_latest_anchor.validate()?;
        ensure(config.journal_path.is_absolute(), "HISTORY_V6_JOURNAL_PATH")?;
        Ok(Self {
            config,
            expected_uid,
            _file: file,
        })
    }
}
pub(in crate::store::history_effect_v6) fn message(
    role: u8,
    body: &Authorization,
) -> Result<Vec<u8>> {
    let raw = policy::encoded(body)?;
    ensure(
        raw.len() <= policy::MAX_ENVELOPE,
        "HISTORY_PUBLICATION_ENVELOPE",
    )?;
    let mut result = DOMAIN.to_vec();
    result.extend([b'P', role]);
    result.extend((raw.len() as u32).to_le_bytes());
    result.extend(raw);
    Ok(result)
}
fn authenticate(config: &Configuration) -> Result<Authorization> {
    let raw = &config.signed_publication;
    ensure(
        !raw.is_empty() && raw.len() <= policy::MAX_ENVELOPE,
        "HISTORY_PUBLICATION_ENVELOPE",
    )?;
    let envelope: policy::Envelope<Authorization> = serde_json::from_slice(raw)?;
    for (role, key, signature) in [
        (
            1,
            &config.identity.registry_key,
            &envelope.registry_signature,
        ),
        (2, &config.identity.task_key, &envelope.task_signature),
    ] {
        trnm_crypto_primitives::verify_hex_strict(key, &message(role, &envelope.body)?, signature)
            .map_err(|_| "HISTORY_PUBLICATION_SIGNATURE")?;
    }
    let body = envelope.body;
    body.prefix_anchor.validate()?;
    body.published_anchor.validate()?;
    policy::id(&body.frame_sha256, 32)?;
    let at = policy::now()?;
    ensure(
        body.schema == "restricted-history-journal-publication-authorization-v1"
            && body.identity == config.identity
            && body.published_anchor == config.outside_latest_anchor
            && body.published_anchor.sequence == body.prefix_anchor.sequence + 1
            && body.published_anchor.digest == body.frame_sha256
            && body.frame_bytes > 0
            && body.frame_bytes <= MAX_RECORD
            && body.issued_ns <= at
            && at < body.expires_ns
            && body.expires_ns - body.issued_ns <= 86_400_000_000_000,
        "HISTORY_PUBLICATION_AUTHORIZATION",
    )?;
    Ok(body)
}
fn same_file(held: &fs::Metadata, visible: &fs::Metadata) -> bool {
    held.dev() == visible.dev()
        && held.ino() == visible.ino()
        && held.len() == visible.len()
        && held.uid() == visible.uid()
        && held.mode() == visible.mode()
        && !visible.file_type().is_symlink()
}
fn visible(file: &File, path: &Path, expected_links: u64) -> Result<()> {
    let held = file.metadata()?;
    let named = fs::symlink_metadata(path)?;
    ensure(
        held.is_file()
            && held.nlink() == expected_links
            && same_file(&held, &named)
            && named.nlink() == expected_links,
        "HISTORY_PUBLICATION_FILE_CHANGED",
    )
}

/// Complete the exact already-written frame selected by fresh outside dual
/// signatures. This is an idempotent publication operation, not effect recovery.
/// Missing/partial/conflicting bytes remain retained on disk; no frame is ever
/// invented, truncated, overwritten or discarded. A crash during this repair
/// leaves one of the same explicitly repairable one/two-link states.
pub fn repair_history_journal_publication_v1(
    input: ProtectedHistoryJournalPublicationV1Input,
) -> Result<Value> {
    repair_with_validation(input, |_, frame| {
        ensure(
            !matches!(frame.event, Event::SettledEpochReconciledV1 { .. }),
            "HISTORY_PUBLICATION_EPOCH_PINS_REQUIRED",
        )?;
        ensure(
            !matches!(frame.event, Event::ReorgContinuationPreparedV1 { .. }),
            "HISTORY_REORG_V1_PUBLICATION_VALIDATION_REQUIRED",
        )?;
        ensure(
            !matches!(frame.event, Event::LifecycleReconciledV1 { .. }),
            "HISTORY_LIFECYCLE_V1_PUBLICATION_VALIDATION_REQUIRED",
        )?;
        ensure(
            !matches!(frame.event, Event::StartupNoNativeClosedV1 { .. }),
            "HISTORY_PUBLICATION_NO_NATIVE_PINS_REQUIRED",
        )
    })
}
pub(in crate::store::history_effect_v6) fn repair_with_validation<G>(
    input: ProtectedHistoryJournalPublicationV1Input,
    validate: impl FnOnce(&Journal, &Frame) -> Result<G>,
) -> Result<Value> {
    let config = input.config;
    let authorization = authenticate(&config)?;
    // Do not create a journal or even its owner lock during administrative repair.
    let mut journal = Journal::lock_directory(
        &config.journal_path,
        input.expected_uid,
        &config.identity,
        false,
    )?;
    let sequence = authorization.published_anchor.sequence;
    let pending_name = format!("pending-{sequence:020}");
    let final_name = format!("{sequence:020}-{}.json", authorization.frame_sha256);
    let pending = journal.path.join(&pending_name);
    let final_path = journal.path.join(&final_name);
    let mut prefix = Vec::new();
    let (mut has_pending, mut has_final) = (false, false);
    for entry in fs::read_dir(&journal.path)? {
        let entry = entry?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| "HISTORY_V6_JOURNAL_FILE")?;
        if name == "owner.lock" {
            continue;
        }
        if name == pending_name {
            has_pending = true;
            continue;
        }
        if name == final_name {
            has_final = true;
            continue;
        }
        ensure(
            name.len() == 90 && name.ends_with(".json") && name.as_bytes()[20] == b'-',
            "HISTORY_PUBLICATION_UNEXPECTED_TAIL",
        )?;
        ensure(prefix.len() < 4096, "HISTORY_V6_JOURNAL_CAPACITY")?;
        prefix.push((name, entry.path()));
    }
    ensure(
        has_pending || has_final,
        "HISTORY_PUBLICATION_MISSING_FRAME",
    )?;
    prefix.sort();
    for (name, path) in prefix {
        let raw = journal.read_record(&path)?;
        let frame: Frame = serde_json::from_slice(&raw)?;
        ensure(
            policy::encoded(&frame)? == raw
                && name == format!("{:020}-{}.json", frame.sequence, policy::digest(&raw))
                && frame.sequence <= authorization.prefix_anchor.sequence,
            "HISTORY_PUBLICATION_PREFIX",
        )?;
        journal.apply_frame(frame, policy::digest(&raw))?;
    }
    ensure(
        journal.anchor() == authorization.prefix_anchor,
        "HISTORY_PUBLICATION_PREFIX",
    )?;
    let before = journal.observation();
    let source = if has_pending { &pending } else { &final_path };
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(source)?;
    let metadata = file.metadata()?;
    let links = if has_pending && has_final { 2 } else { 1 };
    ensure(
        metadata.is_file()
            && metadata.uid() == input.expected_uid
            && metadata.mode() & 0o077 == 0
            && metadata.nlink() == links
            && metadata.len() == authorization.frame_bytes,
        "HISTORY_PUBLICATION_FILE",
    )?;
    visible(&file, source, links)?;
    if has_pending && has_final {
        visible(&file, &final_path, 2)?;
    }
    let mut raw = Vec::new();
    std::io::Read::by_ref(&mut file)
        .take(MAX_RECORD + 1)
        .read_to_end(&mut raw)?;
    ensure(
        raw.len() as u64 == authorization.frame_bytes
            && policy::digest(&raw) == authorization.frame_sha256,
        "HISTORY_PUBLICATION_FRAME_DIGEST",
    )?;
    let frame: Frame = serde_json::from_slice(&raw)?;
    ensure(
        policy::encoded(&frame)? == raw,
        "HISTORY_V6_JOURNAL_CANONICAL",
    )?;
    // Full original replay checks the signed grant, nonce, lifetime ceiling,
    // allowance, marker and CPU receipt. A valid digest alone is insufficient.
    let _held_validation = validate(&journal, &frame)?;
    journal.apply_frame(frame, authorization.frame_sha256.clone())?;
    ensure(
        journal.anchor() == authorization.published_anchor,
        "HISTORY_PUBLICATION_ANCHOR",
    )?;
    visible(&file, source, links)?;
    journal.ready()?;
    file.sync_all()?;
    if !has_final {
        fs::hard_link(&pending, &final_path)?;
        #[cfg(all(test, target_os = "linux"))]
        super::super::tests::publication::repair_cut(&config.signed_publication, "linked");
    }
    journal.dir.sync_all()?;
    if has_pending {
        visible(&file, &pending, 2)?;
        visible(&file, &final_path, 2)?;
        fs::remove_file(&pending)?;
        #[cfg(all(test, target_os = "linux"))]
        super::super::tests::publication::repair_cut(&config.signed_publication, "unlinked");
    }
    journal.dir.sync_all()?;
    visible(&file, &final_path, 1)?;
    journal.ready()?;
    ensure(
        journal.read_record(&final_path)? == raw,
        "HISTORY_PUBLICATION_FILE_CHANGED",
    )?;
    Ok(serde_json::json!({
        "schema":"restricted-history-journal-publication-result-v1",
        "signed_publication_sha256":policy::digest(&config.signed_publication),
        "prefix_anchor":authorization.prefix_anchor,
        "externally_pinned_latest_anchor":config.outside_latest_anchor,
        "frame_sha256":authorization.frame_sha256,"frame_bytes":authorization.frame_bytes,
        "original_pending_name_present":has_pending,"original_final_name_present":has_final,
        "already_published":!has_pending && has_final,
        "before":before,"journal":journal.observation(),
        "existing_frame_bytes_preserved":true,"new_journal_event_created":false,
        "native_effect_repeated":false,"cpu_receipt_created":false,
        "new_cpu_epoch_created":false,"physical_power_loss_qualified":false,
        "production_qualified":false
    }))
}
