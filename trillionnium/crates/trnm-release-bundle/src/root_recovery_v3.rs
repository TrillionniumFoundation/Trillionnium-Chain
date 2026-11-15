//! Native, bounded dual-family root authorization kernel.
//!
//! All five operations use the fixed ML-DSA-87 AND SLH-DSA-SHA2-256s
//! policy. Times are Unix seconds with an exclusive expiry, not V2 heights.
//! This kernel does not own storage, clocks, external effects or FinalUse.
//! A durable owner must pin enrollment, replay events, preserve uncertainty,
//! and compare its complete head to an independently retained fresh anchor.

use sha2::{Digest, Sha512};
use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    fmt,
};
use trnm_crypto_primitives::pq_root_v3::{
    approval_message_v3, operation_commitment_v3, DualFamilyRosterV3, RootCryptoErrorV3,
    RootSignatureV3, VerificationBudgetV3, MAX_STATEMENT_BYTES_V3,
};

pub type DigestV3 = [u8; 64];
pub const MAX_ROOT_OPERATIONS_V3: usize = 128;
pub const MAX_ROOT_REVOCATIONS_V3: usize = 128;
pub const MAX_ROOT_ENVELOPE_BYTES_V3: usize = 524_288;
pub const MAX_RELEASE_INTENT_PART_BYTES_V3: usize = 8192;
pub const MAX_ROOT_ARTIFACT_BYTES_V3: u64 = 64 * 1024 * 1024;
const POLICY: &[u8] = b"TRNM/RootRecovery/Policy/v3\0";
const STATEMENT: &[u8] = b"TRNM/RootRecovery/Statement/UnixSeconds/v3\0";
const ENVELOPE: &[u8] = b"TRNM/RootRecovery/Envelope/v3\0";
const STATE: &[u8] = b"TRNM/RootRecovery/State/v3\0";
const INTENT: &[u8] = b"TRNM/RootRecovery/ReleaseIntent/v3\0";

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RootErrorV3 {
    Codec,
    Policy,
    Context,
    Expired,
    Nonce,
    Revoked,
    Capacity,
    Intent,
    Crypto(String),
}
impl fmt::Display for RootErrorV3 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "native root V3 refused: {self:?}")
    }
}
impl Error for RootErrorV3 {}
impl From<RootCryptoErrorV3> for RootErrorV3 {
    fn from(value: RootCryptoErrorV3) -> Self {
        Self::Crypto(value.to_string())
    }
}
pub type RootResultV3<T> = Result<T, RootErrorV3>;

pub fn digest_v3(domain: &[u8], bytes: &[u8]) -> DigestV3 {
    let mut hash = Sha512::new();
    hash.update((domain.len() as u64).to_be_bytes());
    hash.update(domain);
    hash.update((bytes.len() as u64).to_be_bytes());
    hash.update(bytes);
    hash.finalize().into()
}
fn nonzero<const N: usize>(value: &[u8; N]) -> bool {
    value != &[0; N]
}
fn blob(out: &mut Vec<u8>, bytes: &[u8]) -> RootResultV3<()> {
    let length = u32::try_from(bytes.len()).map_err(|_| RootErrorV3::Capacity)?;
    out.extend(length.to_be_bytes());
    out.extend(bytes);
    Ok(())
}

struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}
impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8], domain: &[u8], maximum: usize) -> RootResultV3<Self> {
        if bytes.len() > maximum || !bytes.starts_with(domain) {
            return Err(RootErrorV3::Codec);
        }
        Ok(Self {
            bytes,
            offset: domain.len(),
        })
    }
    fn take(&mut self, count: usize) -> RootResultV3<&'a [u8]> {
        let end = self.offset.checked_add(count).ok_or(RootErrorV3::Codec)?;
        let value = self.bytes.get(self.offset..end).ok_or(RootErrorV3::Codec)?;
        self.offset = end;
        Ok(value)
    }
    fn fixed<const N: usize>(&mut self) -> RootResultV3<[u8; N]> {
        self.take(N)?.try_into().map_err(|_| RootErrorV3::Codec)
    }
    fn u8(&mut self) -> RootResultV3<u8> {
        Ok(self.fixed::<1>()?[0])
    }
    fn u32(&mut self) -> RootResultV3<u32> {
        Ok(u32::from_be_bytes(self.fixed()?))
    }
    fn u64(&mut self) -> RootResultV3<u64> {
        Ok(u64::from_be_bytes(self.fixed()?))
    }
    fn blob(&mut self, maximum: usize) -> RootResultV3<&'a [u8]> {
        let size = self.u32()? as usize;
        if size > maximum {
            return Err(RootErrorV3::Capacity);
        }
        self.take(size)
    }
    fn finish(self) -> RootResultV3<()> {
        if self.offset != self.bytes.len() {
            return Err(RootErrorV3::Codec);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RootPolicyV3 {
    pub roster: DualFamilyRosterV3,
    pub expires_at_unix: u64,
}
impl RootPolicyV3 {
    pub fn encode(&self) -> RootResultV3<Vec<u8>> {
        if self.expires_at_unix == 0 {
            return Err(RootErrorV3::Policy);
        }
        let mut out = POLICY.to_vec();
        out.extend(self.expires_at_unix.to_be_bytes());
        blob(&mut out, &self.roster.encode())?;
        if out.len() > 16384 {
            return Err(RootErrorV3::Capacity);
        }
        Ok(out)
    }
    pub fn decode(bytes: &[u8]) -> RootResultV3<Self> {
        let mut r = Reader::new(bytes, POLICY, 16384)?;
        let expires_at_unix = r.u64()?;
        let roster = DualFamilyRosterV3::decode(r.blob(16000)?)?;
        r.finish()?;
        let value = Self {
            roster,
            expires_at_unix,
        };
        if value.encode()? != bytes {
            return Err(RootErrorV3::Codec);
        }
        Ok(value)
    }
    pub fn commitment(&self) -> RootResultV3<DigestV3> {
        Ok(digest_v3(
            b"TRNM/RootRecovery/PolicyCommitment/v3\0",
            &self.encode()?,
        ))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ReleaseUseV3 {
    Install = 1,
    Launch = 2,
    FinalUse = 3,
}

/// Exact bytes of the complete selected release and execution contract.
/// Their interpretation still belongs to the native M15 sink. These bytes
/// cannot be replaced by only a program hash or a caller-supplied PASS flag.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReleaseIntentV3 {
    pub kind: ReleaseUseV3,
    pub bundle: Vec<u8>,
    pub contract: Vec<u8>,
    pub artifact_sha512: DigestV3,
    pub artifact_size: u64,
    pub attempt: [u8; 32],
}
impl ReleaseIntentV3 {
    pub fn from_bytes(
        kind: ReleaseUseV3,
        bundle: &[u8],
        contract: &[u8],
        artifact: &[u8],
        attempt: [u8; 32],
    ) -> RootResultV3<Self> {
        if bundle.is_empty()
            || contract.is_empty()
            || artifact.is_empty()
            || bundle.len() > MAX_RELEASE_INTENT_PART_BYTES_V3
            || contract.len() > MAX_RELEASE_INTENT_PART_BYTES_V3
            || artifact.len() as u64 > MAX_ROOT_ARTIFACT_BYTES_V3
        {
            return Err(RootErrorV3::Intent);
        }
        let value = Self {
            kind,
            bundle: bundle.to_vec(),
            contract: contract.to_vec(),
            artifact_sha512: digest_v3(b"TRNM/RootRecovery/ActualArtifact/v3\0", artifact),
            artifact_size: artifact.len() as u64,
            attempt,
        };
        value.encode()?;
        Ok(value)
    }
    pub fn matches_bytes(&self, bundle: &[u8], contract: &[u8], artifact: &[u8]) -> bool {
        self.bundle == bundle
            && self.contract == contract
            && self.artifact_size == artifact.len() as u64
            && self.artifact_sha512 == digest_v3(b"TRNM/RootRecovery/ActualArtifact/v3\0", artifact)
    }
    pub fn encode(&self) -> RootResultV3<Vec<u8>> {
        if self.bundle.is_empty()
            || self.contract.is_empty()
            || self.bundle.len() > MAX_RELEASE_INTENT_PART_BYTES_V3
            || self.contract.len() > MAX_RELEASE_INTENT_PART_BYTES_V3
            || self.artifact_size == 0
            || self.artifact_size > MAX_ROOT_ARTIFACT_BYTES_V3
            || !nonzero(&self.artifact_sha512)
            || !nonzero(&self.attempt)
        {
            return Err(RootErrorV3::Intent);
        }
        let mut out = INTENT.to_vec();
        out.push(self.kind as u8);
        blob(&mut out, &self.bundle)?;
        blob(&mut out, &self.contract)?;
        out.extend(self.artifact_sha512);
        out.extend(self.artifact_size.to_be_bytes());
        out.extend(self.attempt);
        Ok(out)
    }
    pub fn decode(bytes: &[u8]) -> RootResultV3<Self> {
        let mut r = Reader::new(bytes, INTENT, 2 * MAX_RELEASE_INTENT_PART_BYTES_V3 + 256)?;
        let kind = match r.u8()? {
            1 => ReleaseUseV3::Install,
            2 => ReleaseUseV3::Launch,
            3 => ReleaseUseV3::FinalUse,
            _ => return Err(RootErrorV3::Codec),
        };
        let value = Self {
            kind,
            bundle: r.blob(MAX_RELEASE_INTENT_PART_BYTES_V3)?.to_vec(),
            contract: r.blob(MAX_RELEASE_INTENT_PART_BYTES_V3)?.to_vec(),
            artifact_sha512: r.fixed()?,
            artifact_size: r.u64()?,
            attempt: r.fixed()?,
        };
        r.finish()?;
        if value.encode()? != bytes {
            return Err(RootErrorV3::Codec);
        }
        Ok(value)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RootActionV3 {
    Normal { intent: ReleaseIntentV3 },
    Rotate { next: RootPolicyV3 },
    Revoke { keys: Vec<DigestV3> },
    Recover { next: RootPolicyV3 },
    PolicyChange { next: RootPolicyV3 },
}
impl RootActionV3 {
    pub fn successor(&self) -> Option<&RootPolicyV3> {
        match self {
            Self::Rotate { next } | Self::Recover { next } | Self::PolicyChange { next } => {
                Some(next)
            }
            _ => None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RootStatementV3 {
    pub scope: DigestV3,
    pub generation: u64,
    pub sequence: u64,
    pub predecessor: DigestV3,
    pub nonce: [u8; 32],
    pub valid_from_unix: u64,
    pub expires_at_unix: u64,
    pub action: RootActionV3,
}
impl RootStatementV3 {
    pub fn encode(&self) -> RootResultV3<Vec<u8>> {
        if !nonzero(&self.scope)
            || !nonzero(&self.predecessor)
            || !nonzero(&self.nonce)
            || self.generation == 0
            || self.sequence == 0
            || self.valid_from_unix >= self.expires_at_unix
        {
            return Err(RootErrorV3::Context);
        }
        let mut out = STATEMENT.to_vec();
        out.extend(self.scope);
        out.extend(self.generation.to_be_bytes());
        out.extend(self.sequence.to_be_bytes());
        out.extend(self.predecessor);
        out.extend(self.nonce);
        out.extend(self.valid_from_unix.to_be_bytes());
        out.extend(self.expires_at_unix.to_be_bytes());
        match &self.action {
            RootActionV3::Normal { intent } => {
                out.push(1);
                blob(&mut out, &intent.encode()?)?;
            }
            RootActionV3::Rotate { next } => {
                out.push(2);
                blob(&mut out, &next.encode()?)?;
            }
            RootActionV3::Revoke { keys } => {
                if keys.is_empty()
                    || keys.len() > 6
                    || keys.iter().any(|k| !nonzero(k))
                    || keys.windows(2).any(|w| w[0] >= w[1])
                {
                    return Err(RootErrorV3::Policy);
                }
                out.push(3);
                out.push(keys.len() as u8);
                for key in keys {
                    out.extend(key);
                }
            }
            RootActionV3::Recover { next } => {
                out.push(4);
                blob(&mut out, &next.encode()?)?;
            }
            RootActionV3::PolicyChange { next } => {
                out.push(5);
                blob(&mut out, &next.encode()?)?;
            }
        }
        if out.len() > MAX_STATEMENT_BYTES_V3 {
            return Err(RootErrorV3::Capacity);
        }
        Ok(out)
    }
    pub fn decode(bytes: &[u8]) -> RootResultV3<Self> {
        let mut r = Reader::new(bytes, STATEMENT, MAX_STATEMENT_BYTES_V3)?;
        let scope = r.fixed()?;
        let generation = r.u64()?;
        let sequence = r.u64()?;
        let predecessor = r.fixed()?;
        let nonce = r.fixed()?;
        let valid_from_unix = r.u64()?;
        let expires_at_unix = r.u64()?;
        let action = match r.u8()? {
            1 => RootActionV3::Normal {
                intent: ReleaseIntentV3::decode(r.blob(MAX_STATEMENT_BYTES_V3)?)?,
            },
            2 => RootActionV3::Rotate {
                next: RootPolicyV3::decode(r.blob(16384)?)?,
            },
            3 => {
                let count = r.u8()?;
                if !(1..=6).contains(&count) {
                    return Err(RootErrorV3::Policy);
                }
                let mut keys = Vec::new();
                for _ in 0..count {
                    keys.push(r.fixed()?);
                }
                RootActionV3::Revoke { keys }
            }
            4 => RootActionV3::Recover {
                next: RootPolicyV3::decode(r.blob(16384)?)?,
            },
            5 => RootActionV3::PolicyChange {
                next: RootPolicyV3::decode(r.blob(16384)?)?,
            },
            _ => return Err(RootErrorV3::Codec),
        };
        r.finish()?;
        let value = Self {
            scope,
            generation,
            sequence,
            predecessor,
            nonce,
            valid_from_unix,
            expires_at_unix,
            action,
        };
        if value.encode()? != bytes {
            return Err(RootErrorV3::Codec);
        }
        Ok(value)
    }
    pub fn signing_message(&self) -> RootResultV3<Vec<u8>> {
        Ok(approval_message_v3(&self.encode()?)?)
    }
    pub fn operation_id(&self) -> RootResultV3<DigestV3> {
        Ok(operation_commitment_v3(&self.encode()?)?)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RootEnvelopeV3 {
    pub statement: RootStatementV3,
    pub approvals: Vec<RootSignatureV3>,
    pub successor_possessions: Vec<RootSignatureV3>,
}
fn signature_bytes(out: &mut Vec<u8>, rows: &[RootSignatureV3], count: usize) -> RootResultV3<()> {
    if rows.len() != count {
        return Err(RootErrorV3::Codec);
    }
    let mut rows: Vec<_> = rows.iter().collect();
    rows.sort_by_key(|row| row.signer);
    if rows.windows(2).any(|w| w[0].signer == w[1].signer) {
        return Err(RootErrorV3::Codec);
    }
    out.push(rows.len() as u8);
    for row in rows {
        if !nonzero(&row.signer) || !matches!(row.signature.len(), 4627 | 29792) {
            return Err(RootErrorV3::Codec);
        }
        out.extend(row.signer);
        blob(out, &row.signature)?;
    }
    Ok(())
}
fn read_signatures(r: &mut Reader<'_>, count: usize) -> RootResultV3<Vec<RootSignatureV3>> {
    if usize::from(r.u8()?) != count {
        return Err(RootErrorV3::Codec);
    }
    let mut rows = Vec::new();
    for _ in 0..count {
        rows.push(RootSignatureV3 {
            signer: r.fixed()?,
            signature: r.blob(29792)?.to_vec(),
        });
    }
    if rows.windows(2).any(|w| w[0].signer >= w[1].signer) {
        return Err(RootErrorV3::Codec);
    }
    Ok(rows)
}
impl RootEnvelopeV3 {
    pub fn encode(&self) -> RootResultV3<Vec<u8>> {
        let mut out = ENVELOPE.to_vec();
        blob(&mut out, &self.statement.encode()?)?;
        signature_bytes(&mut out, &self.approvals, 4)?;
        let expected = if self.statement.action.successor().is_some() {
            6
        } else {
            0
        };
        signature_bytes(&mut out, &self.successor_possessions, expected)?;
        if out.len() > MAX_ROOT_ENVELOPE_BYTES_V3 {
            return Err(RootErrorV3::Capacity);
        }
        Ok(out)
    }
    pub fn decode(bytes: &[u8]) -> RootResultV3<Self> {
        let mut r = Reader::new(bytes, ENVELOPE, MAX_ROOT_ENVELOPE_BYTES_V3)?;
        let statement = RootStatementV3::decode(r.blob(MAX_STATEMENT_BYTES_V3)?)?;
        let approvals = read_signatures(&mut r, 4)?;
        let expected = if statement.action.successor().is_some() {
            6
        } else {
            0
        };
        let successor_possessions = read_signatures(&mut r, expected)?;
        r.finish()?;
        let value = Self {
            statement,
            approvals,
            successor_possessions,
        };
        if value.encode()? != bytes {
            return Err(RootErrorV3::Codec);
        }
        Ok(value)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RetainedIntent {
    intent: ReleaseIntentV3,
    generation: u64,
    policy: DigestV3,
    valid_from: u64,
    expires_at: u64,
    approvers: Vec<DigestV3>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RootStateV3 {
    scope: DigestV3,
    policy: RootPolicyV3,
    generation: u64,
    sequence: u64,
    time_floor: u64,
    nonces: BTreeSet<[u8; 32]>,
    revoked: BTreeSet<DigestV3>,
    intents: BTreeMap<DigestV3, RetainedIntent>,
}
impl RootStateV3 {
    pub fn bootstrap(scope: DigestV3, policy: RootPolicyV3, now: u64) -> RootResultV3<Self> {
        policy.encode()?;
        if !nonzero(&scope) || policy.expires_at_unix <= now {
            return Err(RootErrorV3::Policy);
        }
        Ok(Self {
            scope,
            policy,
            generation: 1,
            sequence: 0,
            time_floor: now,
            nonces: BTreeSet::new(),
            revoked: BTreeSet::new(),
            intents: BTreeMap::new(),
        })
    }
    pub fn scope(&self) -> DigestV3 {
        self.scope
    }
    pub fn sequence(&self) -> u64 {
        self.sequence
    }
    pub fn generation(&self) -> u64 {
        self.generation
    }
    pub fn policy(&self) -> &RootPolicyV3 {
        &self.policy
    }
    pub fn revoked(&self) -> &BTreeSet<DigestV3> {
        &self.revoked
    }
    pub fn time_floor(&self) -> u64 {
        self.time_floor
    }
    pub fn nonce_count(&self) -> usize {
        self.nonces.len()
    }
    pub fn encode(&self) -> RootResultV3<Vec<u8>> {
        let mut out = STATE.to_vec();
        out.extend(self.scope);
        out.extend(self.generation.to_be_bytes());
        out.extend(self.sequence.to_be_bytes());
        out.extend(self.time_floor.to_be_bytes());
        blob(&mut out, &self.policy.encode()?)?;
        out.extend((self.nonces.len() as u32).to_be_bytes());
        for nonce in &self.nonces {
            out.extend(nonce);
        }
        out.extend((self.revoked.len() as u32).to_be_bytes());
        for key in &self.revoked {
            out.extend(key);
        }
        out.extend((self.intents.len() as u32).to_be_bytes());
        for (operation, value) in &self.intents {
            out.extend(operation);
            out.extend(value.generation.to_be_bytes());
            out.extend(value.policy);
            out.extend(value.valid_from.to_be_bytes());
            out.extend(value.expires_at.to_be_bytes());
            blob(&mut out, &value.intent.encode()?)?;
            for signer in &value.approvers {
                out.extend(signer);
            }
        }
        Ok(out)
    }
    pub fn checkpoint(&self) -> DigestV3 {
        // All state fields are private and only validated transitions construct it.
        digest_v3(
            b"TRNM/RootRecovery/Checkpoint/v3\0",
            &self.encode().expect("validated bounded root state"),
        )
    }
    pub fn check_current(&self, operation: DigestV3, now: u64) -> RootResultV3<&ReleaseIntentV3> {
        let value = self.intents.get(&operation).ok_or(RootErrorV3::Intent)?;
        if now < self.time_floor
            || now < value.valid_from
            || now >= value.expires_at
            || now >= self.policy.expires_at_unix
        {
            return Err(RootErrorV3::Expired);
        }
        if value.generation != self.generation || value.policy != self.policy.commitment()? {
            return Err(RootErrorV3::Context);
        }
        if value.approvers.iter().any(|key| self.revoked.contains(key)) {
            return Err(RootErrorV3::Revoked);
        }
        Ok(&value.intent)
    }
    /// Applies only after real cryptographic verification. A failed call leaves
    /// this state byte-identical. Attempted cryptographic verification keeps
    /// its reservations charged; earlier contextual refusals do not reserve it.
    pub fn apply(
        &mut self,
        envelope: &RootEnvelopeV3,
        now: u64,
        budget: &mut VerificationBudgetV3,
    ) -> RootResultV3<DigestV3> {
        budget.checkpoint()?;
        envelope.encode()?;
        let statement = &envelope.statement;
        if statement.scope != self.scope
            || statement.generation != self.generation
            || Some(statement.sequence) != self.sequence.checked_add(1)
            || statement.predecessor != self.checkpoint()
        {
            return Err(RootErrorV3::Context);
        }
        if now < self.time_floor
            || now < statement.valid_from_unix
            || now >= statement.expires_at_unix
            || (now >= self.policy.expires_at_unix
                && !matches!(statement.action, RootActionV3::Recover { .. }))
        {
            return Err(RootErrorV3::Expired);
        }
        if self.nonces.contains(&statement.nonce) {
            return Err(RootErrorV3::Nonce);
        }
        if self.nonces.len() >= MAX_ROOT_OPERATIONS_V3 {
            return Err(RootErrorV3::Capacity);
        }
        if envelope
            .approvals
            .iter()
            .any(|row| self.revoked.contains(&row.signer))
        {
            return Err(RootErrorV3::Revoked);
        }
        if let Some(next) = statement.action.successor() {
            if next.expires_at_unix <= now
                || next
                    .roster
                    .key_ids()
                    .iter()
                    .any(|key| self.revoked.contains(key))
            {
                return Err(RootErrorV3::Policy);
            }
            self.generation
                .checked_add(1)
                .ok_or(RootErrorV3::Capacity)?;
        }
        if let RootActionV3::Revoke { keys } = &statement.action {
            let members = self.policy.roster.key_ids();
            if keys
                .iter()
                .any(|key| !members.contains(key) || self.revoked.contains(key))
            {
                return Err(RootErrorV3::Revoked);
            }
            if self.revoked.len() + keys.len() > MAX_ROOT_REVOCATIONS_V3 {
                return Err(RootErrorV3::Capacity);
            }
        }
        let mut approvers = self.policy.roster.verify_quorum(
            &statement.signing_message()?,
            &envelope.approvals,
            budget,
        )?;
        approvers.sort();
        if let Some(next) = statement.action.successor() {
            next.roster.verify_possessions(
                &statement.encode()?,
                &envelope.successor_possessions,
                budget,
            )?;
        }
        let operation = statement.operation_id()?;
        let mut candidate = self.clone();
        match &statement.action {
            RootActionV3::Normal { intent } => {
                if candidate.intents.contains_key(&operation) {
                    return Err(RootErrorV3::Nonce);
                }
                candidate.intents.insert(
                    operation,
                    RetainedIntent {
                        intent: intent.clone(),
                        generation: self.generation,
                        policy: self.policy.commitment()?,
                        valid_from: statement.valid_from_unix,
                        expires_at: statement.expires_at_unix,
                        approvers,
                    },
                );
            }
            RootActionV3::Revoke { keys } => {
                candidate.revoked.extend(keys);
            }
            RootActionV3::Rotate { next }
            | RootActionV3::Recover { next }
            | RootActionV3::PolicyChange { next } => {
                candidate.policy = next.clone();
                candidate.generation += 1;
            }
        }
        candidate.sequence = statement.sequence;
        candidate.time_floor = now;
        candidate.nonces.insert(statement.nonce);
        candidate.encode()?;
        budget.checkpoint()?;
        *self = candidate;
        Ok(operation)
    }
}

#[cfg(test)]
#[path = "root_recovery_v3_tests.rs"]
mod tests;
