//! Read-only port of `formal/release-finality-v2/verify_certificate.py`.
//!
//! The receiving owner must supply independently trusted committee/context pins.
//! A valid certificate does not establish key custody, independent operators,
//! model quality, permission, Cell retention, installation or production finality.
//! In particular, `model` commits to artifact bytes under the existing V2 profile;
//! it must not be reinterpreted as a TCR1 release ID or whole-model availability.
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::fmt;
use trnm_crypto_primitives::{verify_hex_strict, verifying_key_from_hex};

pub const INPUT_LIMIT: usize = 2_097_152;
const PREFIX: &[u8] = b"TRNM-RELEASE-FINALITY-V2\0";
type Hash = [u8; 32];
type Result<T> = std::result::Result<T, VerificationError>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VerificationError {
    Size,
    Canonical,
    Shape,
    Integer,
    Digest,
    Committee,
    Context,
    Statement,
    Certificate,
    Vote,
    Signature,
}
impl fmt::Display for VerificationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "release certificate: {self:?}")
    }
}
impl std::error::Error for VerificationError {}

/// Statement facts only. These digests carry no model-installation authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReleaseStatementV2 {
    pub context: Hash,
    pub model: Hash,
    pub evaluation: Hash,
    pub availability: Hash,
    pub retention_height: u64,
    pub state_root: Hash,
    pub next_committee: Option<Hash>,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReleaseContextV2 {
    pub genesis: Hash,
    pub epoch: u64,
    pub committee: Hash,
    pub height: u64,
    pub parent: Hash,
    pub parent_model: Hash,
}
/// Constructible only by successful verification; intentionally not deserializable.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedReleaseStatementV2 {
    value: Hash,
    context: ReleaseContextV2,
    statement: ReleaseStatementV2,
    commit_view: u64,
    signers: (usize, usize),
}
impl VerifiedReleaseStatementV2 {
    pub fn value(&self) -> Hash {
        self.value
    }
    pub fn context(&self) -> &ReleaseContextV2 {
        &self.context
    }
    pub fn statement(&self) -> &ReleaseStatementV2 {
        &self.statement
    }
    pub fn commit_view(&self) -> u64 {
        self.commit_view
    }
    /// Availability and commit signer counts, respectively; not operator counts.
    pub fn signer_counts(&self) -> (usize, usize) {
        self.signers
    }
    pub fn finality_certificate_valid(&self) -> bool {
        true
    }
    pub fn model_quality_accepted(&self) -> bool {
        false
    }
    pub fn long_term_availability_accepted(&self) -> bool {
        false
    }
    pub fn hepta_final_use(&self) -> bool {
        false
    }
    pub fn production_activation(&self) -> bool {
        false
    }
}

fn require(ok: bool, error: VerificationError) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(error)
    }
}
fn shape(value: &Value, fields: &str) -> Result<()> {
    let object = value.as_object().ok_or(VerificationError::Shape)?;
    require(
        object.len() == fields.split_whitespace().count()
            && fields
                .split_whitespace()
                .all(|key| object.contains_key(key)),
        VerificationError::Shape,
    )
}
fn number(value: &Value, min: u64) -> Result<u64> {
    let n = value.as_u64().ok_or(VerificationError::Integer)?;
    require(n >= min && n < 1 << 63, VerificationError::Integer)?;
    Ok(n)
}
fn hash(value: &Value) -> Result<Hash> {
    let text = value.as_str().ok_or(VerificationError::Digest)?;
    require(
        text.len() == 64
            && text
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        VerificationError::Digest,
    )?;
    let mut bytes = [0; 32];
    hex::decode_to_slice(text, &mut bytes).map_err(|_| VerificationError::Digest)?;
    Ok(bytes)
}
// Every string admitted by the V2 grammar is ASCII. Explicit sorted emission
// remains correct even if another workspace member enables preserve_order.
fn canonical(value: &Value) -> Result<Vec<u8>> {
    fn emit(value: &Value, out: &mut Vec<u8>) -> Result<()> {
        match value {
            Value::Object(map) => {
                out.push(b'{');
                let mut entries: Vec<_> = map.iter().collect();
                entries.sort_unstable_by_key(|(key, _)| *key);
                for (i, (key, value)) in entries.into_iter().enumerate() {
                    if i > 0 {
                        out.push(b',');
                    }
                    emit(&Value::String(key.clone()), out)?;
                    out.push(b':');
                    emit(value, out)?;
                }
                out.push(b'}');
            }
            Value::Array(items) => {
                out.push(b'[');
                for (i, item) in items.iter().enumerate() {
                    if i > 0 {
                        out.push(b',');
                    }
                    emit(item, out)?;
                }
                out.push(b']');
            }
            Value::String(text) if !text.is_ascii() => return Err(VerificationError::Canonical),
            _ => serde_json::to_writer(out, value).map_err(|_| VerificationError::Canonical)?,
        }
        Ok(())
    }
    let mut out = Vec::new();
    emit(value, &mut out)?;
    require(out.len() <= INPUT_LIMIT, VerificationError::Size)?;
    Ok(out)
}
fn load(data: &[u8]) -> Result<Value> {
    require(data.len() <= INPUT_LIMIT, VerificationError::Size)?;
    let value: Value = serde_json::from_slice(data).map_err(|_| VerificationError::Canonical)?;
    // This exact round trip also rejects duplicate keys: a parsed map cannot
    // re-emit both occurrences. No normalized/last-key-wins bytes are accepted.
    require(canonical(&value)? == data, VerificationError::Canonical)?;
    Ok(value)
}
fn identity(value: &Value) -> Result<Hash> {
    let mut hasher = Sha256::new();
    hasher.update(PREFIX);
    hasher.update(canonical(value)?);
    Ok(hasher.finalize().into())
}
fn body(value: &Value, phase: &str, context: Hash, statement: Hash) -> Result<u64> {
    shape(value, "context view phase value")?;
    let view = number(&value["view"], u64::from(phase == "commit"))?;
    require(
        value["phase"] == phase
            && hash(&value["context"])? == context
            && hash(&value["value"])? == statement
            && (phase != "availability" || view == 0),
        VerificationError::Certificate,
    )?;
    Ok(view)
}
fn certificate(
    cert: &Value,
    phase: &str,
    context: Hash,
    statement: Hash,
    members: &[&str],
    q: u64,
) -> Result<(u64, usize)> {
    shape(cert, "body votes")?;
    let view = body(&cert["body"], phase, context, statement)?;
    let expected = canonical(&cert["body"])?;
    let votes = cert["votes"].as_array().ok_or(VerificationError::Vote)?;
    require(
        votes.len() as u64 >= q && votes.len() <= members.len(),
        VerificationError::Vote,
    )?;
    let mut previous = None;
    for vote in votes {
        shape(vote, "body signer signature")?;
        // Verify each actual nested body, not a reconstructed enclosing body.
        body(&vote["body"], phase, context, statement)?;
        let actual = canonical(&vote["body"])?;
        let signer = vote["signer"].as_str().ok_or(VerificationError::Vote)?;
        require(
            actual == expected
                && members.binary_search(&signer).is_ok()
                && previous.is_none_or(|last| last < signer),
            VerificationError::Vote,
        )?;
        let signature = vote["signature"]
            .as_str()
            .ok_or(VerificationError::Signature)?;
        let mut message = PREFIX.to_vec();
        message.extend(actual);
        verify_hex_strict(signer, &message, signature).map_err(|_| VerificationError::Signature)?;
        previous = Some(signer);
    }
    Ok((view, votes.len()))
}

/// All three inputs are independently bounded canonical V2 bytes. The second and
/// third inputs MUST be pinned by the receiver, never selected from this bundle.
/// This reads certificates only: no votes, locks, stores, networking or effects.
pub fn verify_certificate(
    bundle_bytes: &[u8],
    trusted_committee_bytes: &[u8],
    trusted_context_bytes: &[u8],
) -> Result<VerifiedReleaseStatementV2> {
    let b = load(bundle_bytes)?;
    let m = load(trusted_committee_bytes)?;
    let c = load(trusted_context_bytes)?;
    shape(&m, "schema genesis epoch members fault_bound quorum")?;
    require(
        m["schema"] == "trnm-release-committee-v2",
        VerificationError::Committee,
    )?;
    let genesis = hash(&m["genesis"])?;
    let epoch = number(&m["epoch"], 0)?;
    let f = number(&m["fault_bound"], 0)? as u128;
    let q = number(&m["quorum"], 1)?;
    let ids = m["members"]
        .as_array()
        .ok_or(VerificationError::Committee)?;
    require((1..=32).contains(&ids.len()), VerificationError::Committee)?;
    let mut members = Vec::with_capacity(ids.len());
    for id in ids {
        hash(id)?;
        let text = id.as_str().ok_or(VerificationError::Committee)?;
        let key = verifying_key_from_hex(text).map_err(|_| VerificationError::Committee)?;
        require(
            !key.is_weak() && members.last().is_none_or(|last| *last < text),
            VerificationError::Committee,
        )?;
        members.push(text);
    }
    let n = members.len() as u128;
    let wide_q = u128::from(q);
    require(
        n > 3 * f && 2 * wide_q > n + f && wide_q <= n - f,
        VerificationError::Committee,
    )?;
    shape(
        &c,
        "profile genesis epoch committee height parent parent_model",
    )?;
    let committee = identity(&m)?;
    require(
        c["profile"] == "trnm-release-finality-v2"
            && hash(&c["genesis"])? == genesis
            && number(&c["epoch"], 0)? == epoch
            && hash(&c["committee"])? == committee,
        VerificationError::Context,
    )?;
    let context = ReleaseContextV2 {
        genesis,
        epoch,
        committee,
        height: number(&c["height"], 1)?,
        parent: hash(&c["parent"])?,
        parent_model: hash(&c["parent_model"])?,
    };
    shape(&b, "context statement availability commit")?;
    require(
        canonical(&b["context"])? == canonical(&c)?,
        VerificationError::Context,
    )?;
    let context_id = identity(&c)?;
    let s = &b["statement"];
    shape(
        s,
        "context model evaluation availability retention_height state_root next_committee",
    )?;
    require(
        hash(&s["context"])? == context_id,
        VerificationError::Statement,
    )?;
    let statement = ReleaseStatementV2 {
        context: context_id,
        model: hash(&s["model"])?,
        evaluation: hash(&s["evaluation"])?,
        availability: hash(&s["availability"])?,
        retention_height: number(&s["retention_height"], context.height)?,
        state_root: hash(&s["state_root"])?,
        next_committee: if s["next_committee"].is_null() {
            None
        } else {
            Some(hash(&s["next_committee"])?)
        },
    };
    let value = identity(s)?;
    let (_, availability_signers) = certificate(
        &b["availability"],
        "availability",
        context_id,
        value,
        &members,
        q,
    )?;
    let (commit_view, commit_signers) =
        certificate(&b["commit"], "commit", context_id, value, &members, q)?;
    Ok(VerifiedReleaseStatementV2 {
        value,
        context,
        statement,
        commit_view,
        signers: (availability_signers, commit_signers),
    })
}
