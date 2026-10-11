//! Explicit same-operator recovery of a fully known fsynced prefix after a real
//! outside-owned SIGKILL. No CleanClose invention, refund or volatile burst.
use crate::operator_continuous_history::{Anchor, Identity};
use crate::operator_task_policy::PolicyError;
use serde::{Deserialize, Serialize};
use trnm_crypto_primitives::verify_hex_strict;
type Result<T> = std::result::Result<T, PolicyError>;
const DOMAIN: &[u8] = b"TRNM-RESTRICTED-CONTINUOUS-KNOWN-UNCLEAN-RESTART1";
fn check(value: bool) -> Result<()> {
    if value {
        Ok(())
    } else {
        Err(PolicyError::ExternalContext)
    }
}
fn id(v: &str) -> Result<()> {
    check(
        v.len() == 64
            && v.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
    )
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct RecoveryBody {
    pub schema: String,
    pub identity: Identity,
    pub prior_journal: Anchor,
    pub exact_usage_digest: String,
    pub actual_parent: String,
    pub actual_generation: u64,
    pub closed_process_receipt_sha256: String,
    pub process_start_scope: String,
    pub native_task: String,
    pub instance_class: String,
    pub known_scope_total_cpu_ns: u64,
    pub closed_process_total_cpu_ns: u64,
    pub residual_cpu_ns: u64,
    pub actual_wait4: bool,
    pub signal: i32,
    pub all_owned_children_reaped: bool,
    pub adopted_descendants: Vec<String>,
    pub issued_ns: u64,
    pub expires_ns: u64,
}
impl RecoveryBody {
    pub(crate) fn validate(&self) -> Result<()> {
        self.identity.validate()?;
        check(
            self.schema == "restricted-continuous-known-unclean-restart-v1"
                && self.prior_journal.sequence > 0
                && self.actual_wait4
                && self.signal == 9
                && self.all_owned_children_reaped
                && self.adopted_descendants.is_empty()
                && self
                    .known_scope_total_cpu_ns
                    .checked_add(self.residual_cpu_ns)
                    == Some(self.closed_process_total_cpu_ns)
                && matches!(
                    self.instance_class.as_str(),
                    "zero" | "structured" | "dense"
                )
                && self.expires_ns > self.issued_ns
                && self.expires_ns - self.issued_ns <= 86_400_000_000_000,
        )?;
        for value in [
            &self.prior_journal.digest,
            &self.exact_usage_digest,
            &self.actual_parent,
            &self.closed_process_receipt_sha256,
            &self.process_start_scope,
            &self.native_task,
        ] {
            id(value)?;
        }
        Ok(())
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    body: RecoveryBody,
    registry_signature: String,
    task_signature: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Authority {
    pub identity: Identity,
    pub expected: RecoveryBody,
    pub envelope_sha256: String,
    pub body_digest: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Input {
    pub raw: Vec<u8>,
    pub authority: Authority,
}
#[derive(Clone)]
pub(crate) struct Verified {
    pub body: RecoveryBody,
    pub digest: String,
}
fn message(body: &RecoveryBody, role: u8) -> Result<Vec<u8>> {
    body.validate()?;
    let raw = serde_json::to_vec(body).map_err(|_| PolicyError::Input)?;
    check(raw.len() <= 4096)?;
    let mut out = DOMAIN.to_vec();
    out.push(role);
    out.extend_from_slice(&(raw.len() as u32).to_le_bytes());
    out.extend_from_slice(&raw);
    Ok(out)
}
pub(crate) fn body_digest(body: &RecoveryBody) -> Result<String> {
    Ok(crate::operator_task_policy::digest_bytes(&message(
        body, 0,
    )?))
}
pub(crate) fn authenticate(input: &Input, expected: &Identity, now: u64) -> Result<Verified> {
    check(!input.raw.is_empty() && input.raw.len() <= 65536)?;
    let e = &input.authority;
    e.identity.validate()?;
    id(&e.envelope_sha256)?;
    id(&e.body_digest)?;
    let v: Envelope = serde_json::from_slice(&input.raw).map_err(|_| PolicyError::Input)?;
    let b = &v.body;
    b.validate()?;
    check(
        e.identity == *expected
            && e.expected.identity == *expected
            && b == &e.expected
            && crate::operator_task_policy::digest_bytes(&input.raw) == e.envelope_sha256
            && body_digest(b)? == e.body_digest
            && b.issued_ns <= now
            && now < b.expires_ns,
    )?;
    verify_hex_strict(
        &expected.registry_key,
        &message(b, 1)?,
        &v.registry_signature,
    )
    .map_err(|_| PolicyError::Signature)?;
    verify_hex_strict(&expected.task_key, &message(b, 2)?, &v.task_signature)
        .map_err(|_| PolicyError::Signature)?;
    Ok(Verified {
        body: v.body,
        digest: e.body_digest.clone(),
    })
}
#[cfg(all(test, target_os = "linux"))]
pub(crate) mod tests {
    use super::*;
    use crate::operator_continuous_test_support::{identity, signed};
    pub(crate) fn verified(anchor: Anchor, usage: String) -> Verified {
        let body = RecoveryBody {
            schema: "restricted-continuous-known-unclean-restart-v1".into(),
            identity: identity(),
            prior_journal: anchor,
            exact_usage_digest: usage,
            actual_parent: "40".repeat(32),
            actual_generation: 0,
            closed_process_receipt_sha256: "91".repeat(32),
            process_start_scope: "95".repeat(32),
            native_task: "10".repeat(32),
            instance_class: "structured".into(),
            known_scope_total_cpu_ns: 1,
            closed_process_total_cpu_ns: 2,
            residual_cpu_ns: 1,
            actual_wait4: true,
            signal: 9,
            all_owned_children_reaped: true,
            adopted_descendants: Vec::new(),
            issued_ns: 1,
            expires_ns: 2,
        };
        let (raw, digest) = signed(DOMAIN, &body);
        let authority = Authority {
            identity: identity(),
            expected: body,
            envelope_sha256: crate::operator_task_policy::digest_bytes(&raw),
            body_digest: digest,
        };
        authenticate(&Input { raw, authority }, &identity(), 1).unwrap()
    }
    #[test]
    fn mode5_unclean_restart_requires_both_original_keys_exact_external_prefix_and_real_close_shape(
    ) {
        let mut v = verified(
            Anchor {
                sequence: 1,
                digest: "92".repeat(32),
            },
            "93".repeat(32),
        );
        assert!(v.body.validate().is_ok());
        v.body.actual_wait4 = false;
        assert!(v.body.validate().is_err());
        v.body.actual_wait4 = true;
        v.body.signal = 0;
        assert!(v.body.validate().is_err());
        v.body.signal = 9;
        v.body.adopted_descendants.push("unknown".into());
        assert!(v.body.validate().is_err());
        let v = verified(
            Anchor {
                sequence: 1,
                digest: "92".repeat(32),
            },
            "93".repeat(32),
        );
        let (raw, digest) = signed(DOMAIN, &v.body);
        let mut authority = Authority {
            identity: identity(),
            expected: v.body.clone(),
            envelope_sha256: crate::operator_task_policy::digest_bytes(&raw),
            body_digest: digest,
        };
        authority.expected.prior_journal.digest = "94".repeat(32);
        assert!(authenticate(&Input { raw, authority }, &identity(), 1).is_err());
    }
}
