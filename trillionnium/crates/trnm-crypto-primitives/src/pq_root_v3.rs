//! Fixed V3 root cryptography: ML-DSA-87 2-of-3 AND SLH-DSA-SHA2-256s 2-of-3.
//!
//! A roster contains exactly six canonical SPKI keys and no selectable threshold
//! or alternate suite. ML-DSA-87 acceptance uses the existing RustCrypto verifier;
//! SLH-DSA-SHA2-256s acceptance uses in-process OpenSSL EVP. Both must succeed.
//! The native methods exist only with `pq-native-openssl`; there is no fallback.
//! The linked OpenSSL build and provider configuration remain trusted build/host
//! inputs, just as in the existing native adapter. This module does not attest
//! their provenance, device independence or resistance to side channels.
//!
//! Root owners must construct the complete canonical statement from trusted
//! state, including action, scope, policy, generation, sequence, nonce, validity,
//! payload and successor. Signatures cover those complete bytes, never a digest
//! substituted by this module. The operation commitment excludes selected
//! witnesses and signature bytes. Private immutable rosters do not grant a root
//! role, consume a nonce, persist a journal or authorize an external effect.
//!
//! One shared budget reserves every attempted verification and input byte before
//! arithmetic. Its absolute monotonic deadline is checked before and after each
//! call; it cannot preempt an EVP call already in progress. Failed verification
//! never refunds reservations or returns a successful observation.

use sha2::{Digest, Sha512};
use std::fmt;
use std::time::{Duration, Instant};

#[cfg(feature = "pq-native-openssl")]
use std::sync::{Arc, OnceLock};

#[cfg(feature = "pq-native-openssl")]
use crate::pq_candidate::{CandidateAlgorithm, CandidateVerifier};
#[cfg(feature = "pq-native-openssl")]
use openssl::{pkey::PKey, sign::Verifier};

pub type KeyIdV3 = [u8; 64];
pub const MAX_STATEMENT_BYTES_V3: usize = 32_768;
pub const MAX_MESSAGE_BYTES_V3: usize = MAX_STATEMENT_BYTES_V3 + 256;
pub const MAX_VERIFICATIONS_V3: u16 = 4_096;
pub const MAX_VERIFICATION_INPUT_BYTES_V3: u64 = 524_288;
pub const MAX_CUMULATIVE_BYTES_V3: u64 = 67_108_864;
pub const VERIFICATION_LIFETIME_V3: Duration = Duration::from_secs(60);
pub const KEY_DOMAIN_V3: &[u8] = b"TRNM/RootV3/Key/v3\0";
pub const APPROVAL_DOMAIN_V3: &[u8] = b"TRNM/RootV3/Approval/v3\0";
pub const OPERATION_DOMAIN_V3: &[u8] = b"TRNM/RootV3/Operation/v3\0";
pub const POSSESSION_DOMAIN_V3: &[u8] = b"TRNM/RootV3/SuccessorPossession/v3\0";
pub const ROSTER_DOMAIN_V3: &[u8] = b"TRNM/RootV3/RosterCommitment/v3\0";
const ROSTER_WIRE_DOMAIN: &[u8] = b"TRNM/RootV3/RosterWire/v3\0";
// AND=1, families=2, then (suite, quorum, roster size) for both fixed suites.
const ROSTER_RULES: [u8; 8] = [1, 2, 1, 2, 3, 2, 2, 3];
const ML_DSA_87_SPKI_PREFIX: &[u8] =
    b"\x30\x82\x0a\x32\x30\x0b\x06\x09\x60\x86\x48\x01\x65\x03\x04\x03\x13\x03\x82\x0a\x21\x00";
const SLH_DSA_SHA2_256S_SPKI_PREFIX: &[u8] =
    b"\x30\x50\x30\x0b\x06\x09\x60\x86\x48\x01\x65\x03\x04\x03\x18\x03\x41\x00";
pub const ENCODED_ROSTER_BYTES_V3: usize =
    ROSTER_WIRE_DOMAIN.len() + ROSTER_RULES.len() + 6 * 5 + 3 * (2_614 + 82);

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum RootSuiteV3 {
    MlDsa87,
    SlhDsaSha2_256s,
}
impl RootSuiteV3 {
    pub const ALL: [Self; 2] = [Self::MlDsa87, Self::SlhDsaSha2_256s];

    pub const fn name(self) -> &'static str {
        match self {
            Self::MlDsa87 => "ML-DSA-87",
            Self::SlhDsaSha2_256s => "SLH-DSA-SHA2-256s",
        }
    }
    pub const fn public_key_bytes(self) -> usize {
        match self {
            Self::MlDsa87 => 2_592,
            Self::SlhDsaSha2_256s => 64,
        }
    }
    pub const fn signature_bytes(self) -> usize {
        match self {
            Self::MlDsa87 => 4_627,
            Self::SlhDsaSha2_256s => 29_792,
        }
    }
    pub const fn spki_bytes(self) -> usize {
        self.spki_prefix().len() + self.public_key_bytes()
    }
    const fn spki_prefix(self) -> &'static [u8] {
        match self {
            Self::MlDsa87 => ML_DSA_87_SPKI_PREFIX,
            Self::SlhDsaSha2_256s => SLH_DSA_SHA2_256S_SPKI_PREFIX,
        }
    }
    const fn wire_tag(self) -> u8 {
        match self {
            Self::MlDsa87 => 1,
            Self::SlhDsaSha2_256s => 2,
        }
    }
    fn from_wire_tag(tag: u8) -> Result<Self, RootCryptoErrorV3> {
        match tag {
            1 => Ok(Self::MlDsa87),
            2 => Ok(Self::SlhDsaSha2_256s),
            _ => Err(RootCryptoErrorV3::Suite),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RootCryptoErrorV3 {
    Suite,
    PublicKeyEncoding,
    RosterSize,
    RosterFamilies,
    DuplicateKey,
    RosterEncoding,
    MessageLength,
    SignerSet,
    SignatureLength,
    SignatureRejected,
    Budget,
    OpenSslVersion,
    NativeBackend,
}
impl fmt::Display for RootCryptoErrorV3 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::Suite => "unknown V3 root suite",
            Self::PublicKeyEncoding => "noncanonical V3 public key or wrong suite OID/length",
            Self::RosterSize => "V3 root roster requires exactly six keys",
            Self::RosterFamilies => "V3 root roster requires three keys in each fixed family",
            Self::DuplicateKey => "V3 root roster contains duplicate key identities",
            Self::RosterEncoding => "noncanonical, truncated or trailing V3 roster encoding",
            Self::MessageLength => "V3 complete statement or message length is outside its bound",
            Self::SignerSet => {
                "V3 root signatures do not cover the required distinct roster members"
            }
            Self::SignatureLength => "V3 root signature length does not match its pinned suite",
            Self::SignatureRejected => "V3 root signature rejected",
            Self::Budget => "V3 shared verification budget exhausted, expired or cancelled",
            Self::OpenSslVersion => {
                "V3 SLH verification requires the pinned OpenSSL 3.5-or-newer build"
            }
            Self::NativeBackend => "V3 native verification backend rejected the operation",
        };
        f.write_str(message)
    }
}
impl std::error::Error for RootCryptoErrorV3 {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RootPublicKeyV3 {
    pub suite: RootSuiteV3,
    pub spki: Vec<u8>,
}
impl RootPublicKeyV3 {
    /// Identity commits to the suite and the complete canonical DER, not a label
    /// accepted from a signature. An equally sized SHAKE key is not a SHA2 key.
    pub fn id(&self) -> Result<KeyIdV3, RootCryptoErrorV3> {
        if self.spki.len() != self.suite.spki_bytes()
            || !self.spki.starts_with(self.suite.spki_prefix())
        {
            return Err(RootCryptoErrorV3::PublicKeyEncoding);
        }
        Ok(commitment(
            KEY_DOMAIN_V3,
            &[self.suite.name().as_bytes(), &self.spki],
        ))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RootSignatureV3 {
    pub signer: KeyIdV3,
    pub signature: Vec<u8>,
}

/// Construction validates every member, including the two unused quorum keys.
/// A caller must pin this complete immutable roster through its trusted owner.
/// An untrusted, self-consistent roster never establishes current authority.
#[derive(Clone)]
pub struct DualFamilyRosterV3 {
    keys: Vec<RootPublicKeyV3>,
    ids: Vec<KeyIdV3>,
    // Only the first, fixed ML-DSA family has expanded RustCrypto key material.
    // These slots are private to this immutable, canonically ordered roster.
    // Clones share successful key expansion, never signature or authority results.
    // Expansion is lazy so construction/decoding cannot bypass the caller's
    // reservation and deadline checks before native arithmetic.
    #[cfg(feature = "pq-native-openssl")]
    ml_dsa_verifiers: Arc<[OnceLock<Box<CandidateVerifier>>; 3]>,
}
impl fmt::Debug for DualFamilyRosterV3 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DualFamilyRosterV3")
            .field("keys", &self.keys)
            .field("ids", &self.ids)
            .finish()
    }
}
impl PartialEq for DualFamilyRosterV3 {
    fn eq(&self, other: &Self) -> bool {
        self.keys == other.keys && self.ids == other.ids
    }
}
impl Eq for DualFamilyRosterV3 {}
impl DualFamilyRosterV3 {
    pub fn from_keys(keys: Vec<RootPublicKeyV3>) -> Result<Self, RootCryptoErrorV3> {
        if keys.len() != 6 {
            return Err(RootCryptoErrorV3::RosterSize);
        }
        let mut entries = keys
            .into_iter()
            .map(|key| key.id().map(|id| (id, key)))
            .collect::<Result<Vec<_>, _>>()?;
        for suite in RootSuiteV3::ALL {
            if entries.iter().filter(|(_, key)| key.suite == suite).count() != 3 {
                return Err(RootCryptoErrorV3::RosterFamilies);
            }
        }
        let mut distinct = entries.iter().map(|(id, _)| *id).collect::<Vec<_>>();
        distinct.sort_unstable();
        if distinct.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(RootCryptoErrorV3::DuplicateKey);
        }
        entries.sort_unstable_by_key(|entry| (entry.1.suite, entry.0));
        let (ids, keys) = entries.into_iter().unzip();
        Ok(Self {
            keys,
            ids,
            #[cfg(feature = "pq-native-openssl")]
            ml_dsa_verifiers: Arc::new(std::array::from_fn(|_| OnceLock::new())),
        })
    }

    pub fn keys(&self) -> &[RootPublicKeyV3] {
        &self.keys
    }
    /// Canonical suite order, then SHA512 identity order within each family.
    pub fn key_ids(&self) -> Vec<KeyIdV3> {
        self.ids.clone()
    }
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(ENCODED_ROSTER_BYTES_V3);
        out.extend_from_slice(ROSTER_WIRE_DOMAIN);
        out.extend_from_slice(&ROSTER_RULES);
        for key in &self.keys {
            out.push(key.suite.wire_tag());
            out.extend_from_slice(&(key.spki.len() as u32).to_be_bytes());
            out.extend_from_slice(&key.spki);
        }
        out
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, RootCryptoErrorV3> {
        if bytes.len() != ENCODED_ROSTER_BYTES_V3 || !bytes.starts_with(ROSTER_WIRE_DOMAIN) {
            return Err(RootCryptoErrorV3::RosterEncoding);
        }
        let mut cursor = RosterReader {
            bytes,
            offset: ROSTER_WIRE_DOMAIN.len(),
        };
        if cursor.take(ROSTER_RULES.len())? != ROSTER_RULES {
            return Err(RootCryptoErrorV3::RosterEncoding);
        }
        let mut keys = Vec::with_capacity(6);
        for _ in 0..6 {
            let suite = RootSuiteV3::from_wire_tag(cursor.take(1)?[0])?;
            let length = u32::from_be_bytes(
                cursor
                    .take(4)?
                    .try_into()
                    .map_err(|_| RootCryptoErrorV3::RosterEncoding)?,
            ) as usize;
            if length != suite.spki_bytes() {
                return Err(RootCryptoErrorV3::PublicKeyEncoding);
            }
            keys.push(RootPublicKeyV3 {
                suite,
                spki: cursor.take(length)?.to_vec(),
            });
        }
        if cursor.offset != bytes.len() {
            return Err(RootCryptoErrorV3::RosterEncoding);
        }
        let roster = Self::from_keys(keys)?;
        // The constructor sorts convenient in-memory input. The wire decoder
        // requires that order already, so one roster has only one encoding.
        if roster.encode() != bytes {
            return Err(RootCryptoErrorV3::RosterEncoding);
        }
        Ok(roster)
    }
    pub fn commitment(&self) -> KeyIdV3 {
        commitment(ROSTER_DOMAIN_V3, &[&self.encode()])
    }

    /// Generic mathematical quorum verification. The trusted caller constructs
    /// and compares its fixed V3 domain and complete expected statement before
    /// this call. Root approval callers use `approval_message_v3`.
    #[cfg(feature = "pq-native-openssl")]
    pub fn verify_quorum(
        &self,
        message: &[u8],
        signatures: &[RootSignatureV3],
        budget: &mut VerificationBudgetV3,
    ) -> Result<Vec<KeyIdV3>, RootCryptoErrorV3> {
        budget.reserve(4, verification_input_bytes(message.len(), signatures, 1))?;
        check_message(message)?;
        let ordered = self.checked_signatures(signatures, 2)?;
        native_version()?;
        for (index, signature) in &ordered {
            budget.checkpoint()?;
            self.verify_signature(*index, message, signature)?;
            budget.checkpoint()?;
        }
        Ok(ordered
            .into_iter()
            .map(|(index, _)| self.ids[index])
            .collect())
    }

    /// Every one of the successor roster's six keys proves possession of its
    /// exact role in this complete transition. This cannot replace old-root
    /// authorization. The caller shares the same budget with the old quorum.
    #[cfg(feature = "pq-native-openssl")]
    pub fn verify_possessions(
        &self,
        complete_statement: &[u8],
        signatures: &[RootSignatureV3],
        budget: &mut VerificationBudgetV3,
    ) -> Result<Vec<KeyIdV3>, RootCryptoErrorV3> {
        budget.reserve(
            6,
            verification_input_bytes(complete_statement.len().saturating_add(256), signatures, 6),
        )?;
        check_statement(complete_statement)?;
        let ordered = self.checked_signatures(signatures, 3)?;
        native_version()?;
        for (index, signature) in &ordered {
            budget.checkpoint()?;
            let message = possession_message_v3(complete_statement, self, self.ids[*index])?;
            self.verify_signature(*index, &message, signature)?;
            budget.checkpoint()?;
        }
        Ok(ordered
            .into_iter()
            .map(|(index, _)| self.ids[index])
            .collect())
    }

    #[cfg(feature = "pq-native-openssl")]
    fn checked_signatures<'a>(
        &self,
        signatures: &'a [RootSignatureV3],
        per_family: usize,
    ) -> Result<Vec<(usize, &'a [u8])>, RootCryptoErrorV3> {
        if signatures.len() != per_family * 2 {
            return Err(RootCryptoErrorV3::SignerSet);
        }
        let mut selected = Vec::with_capacity(signatures.len());
        for row in signatures {
            let index = self
                .ids
                .iter()
                .position(|id| *id == row.signer)
                .ok_or(RootCryptoErrorV3::SignerSet)?;
            if row.signature.len() != self.keys[index].suite.signature_bytes() {
                return Err(RootCryptoErrorV3::SignatureLength);
            }
            selected.push((index, row.signature.as_slice()));
        }
        selected.sort_unstable_by_key(|(index, _)| *index);
        if selected.windows(2).any(|pair| pair[0].0 == pair[1].0)
            || RootSuiteV3::ALL.iter().any(|suite| {
                selected
                    .iter()
                    .filter(|(index, _)| self.keys[*index].suite == *suite)
                    .count()
                    != per_family
            })
        {
            return Err(RootCryptoErrorV3::SignerSet);
        }
        Ok(selected)
    }
}

/// Finite owner-supplied reservation, not a measurement of cryptographic risk.
/// A caller must carry the same instance through replay, current authorization,
/// successor possession and independent receipt verification. It is not Clone.
#[derive(Debug)]
pub struct VerificationBudgetV3 {
    maximum: u16,
    attempts: u16,
    charged_bytes: u64,
    deadline: Instant,
    cancelled: bool,
}
impl VerificationBudgetV3 {
    pub fn new(max_verifications: u16) -> Result<Self, RootCryptoErrorV3> {
        Self::with_deadline(max_verifications, Instant::now() + VERIFICATION_LIFETIME_V3)
    }
    pub fn with_deadline(
        max_verifications: u16,
        deadline: Instant,
    ) -> Result<Self, RootCryptoErrorV3> {
        if max_verifications == 0
            || max_verifications > MAX_VERIFICATIONS_V3
            || deadline <= Instant::now()
        {
            return Err(RootCryptoErrorV3::Budget);
        }
        Ok(Self {
            maximum: max_verifications,
            attempts: 0,
            charged_bytes: 0,
            deadline,
            cancelled: false,
        })
    }
    pub fn attempts(&self) -> u16 {
        self.attempts
    }
    pub fn charged_bytes(&self) -> u64 {
        self.charged_bytes
    }
    pub fn cancel(&mut self) {
        self.cancelled = true;
    }
    pub fn checkpoint(&self) -> Result<(), RootCryptoErrorV3> {
        if self.cancelled
            || self.attempts > self.maximum
            || self.charged_bytes > MAX_CUMULATIVE_BYTES_V3
            || Instant::now() >= self.deadline
        {
            Err(RootCryptoErrorV3::Budget)
        } else {
            Ok(())
        }
    }
    #[cfg(any(feature = "pq-native-openssl", test))]
    fn reserve(&mut self, verifications: u16, bytes: u64) -> Result<(), RootCryptoErrorV3> {
        // Charge before checking, including malformed input and failed calls.
        // Saturation cannot reset or wrap an exhausted owner budget.
        self.attempts = self.attempts.saturating_add(verifications);
        self.charged_bytes = self.charged_bytes.saturating_add(bytes);
        if bytes > MAX_VERIFICATION_INPUT_BYTES_V3 {
            self.cancelled = true;
        }
        self.checkpoint()
    }
}

pub fn approval_message_v3(complete_statement: &[u8]) -> Result<Vec<u8>, RootCryptoErrorV3> {
    check_statement(complete_statement)?;
    Ok(frame(APPROVAL_DOMAIN_V3, &[complete_statement]))
}

pub fn operation_commitment_v3(complete_statement: &[u8]) -> Result<KeyIdV3, RootCryptoErrorV3> {
    check_statement(complete_statement)?;
    Ok(commitment(OPERATION_DOMAIN_V3, &[complete_statement]))
}

pub fn possession_message_v3(
    complete_statement: &[u8],
    successor: &DualFamilyRosterV3,
    signer: KeyIdV3,
) -> Result<Vec<u8>, RootCryptoErrorV3> {
    check_statement(complete_statement)?;
    let index = successor
        .ids
        .iter()
        .position(|id| *id == signer)
        .ok_or(RootCryptoErrorV3::SignerSet)?;
    let message = frame(
        POSSESSION_DOMAIN_V3,
        &[
            complete_statement,
            &successor.commitment(),
            successor.keys[index].suite.name().as_bytes(),
            &signer,
        ],
    );
    check_message(&message)?;
    Ok(message)
}

fn commitment(domain: &[u8], parts: &[&[u8]]) -> KeyIdV3 {
    let mut hash = Sha512::new();
    hash.update(domain);
    for part in parts {
        hash.update((part.len() as u64).to_be_bytes());
        hash.update(part);
    }
    hash.finalize().into()
}
fn frame(domain: &[u8], parts: &[&[u8]]) -> Vec<u8> {
    let mut out =
        Vec::with_capacity(domain.len() + parts.iter().map(|part| 8 + part.len()).sum::<usize>());
    out.extend_from_slice(domain);
    for part in parts {
        out.extend_from_slice(&(part.len() as u64).to_be_bytes());
        out.extend_from_slice(part);
    }
    out
}
fn check_statement(statement: &[u8]) -> Result<(), RootCryptoErrorV3> {
    if statement.is_empty() || statement.len() > MAX_STATEMENT_BYTES_V3 {
        Err(RootCryptoErrorV3::MessageLength)
    } else {
        Ok(())
    }
}
fn check_message(message: &[u8]) -> Result<(), RootCryptoErrorV3> {
    if message.is_empty() || message.len() > MAX_MESSAGE_BYTES_V3 {
        Err(RootCryptoErrorV3::MessageLength)
    } else {
        Ok(())
    }
}
#[cfg(feature = "pq-native-openssl")]
fn verification_input_bytes(
    message_bytes: usize,
    signatures: &[RootSignatureV3],
    copies: u64,
) -> u64 {
    // Do not iterate an attacker-sized signature collection. Oversized shape
    // spends and fences this budget before arithmetic or allocation.
    if signatures.len() > 6 {
        return u64::MAX;
    }
    signatures.iter().fold(
        (message_bytes as u64)
            .saturating_mul(copies)
            .saturating_add(ENCODED_ROSTER_BYTES_V3 as u64),
        |total, row| {
            total
                .saturating_add(64)
                .saturating_add(row.signature.len() as u64)
        },
    )
}
#[cfg(feature = "pq-native-openssl")]
fn native_version() -> Result<(), RootCryptoErrorV3> {
    if openssl::version::number() < 0x3050_0000 {
        Err(RootCryptoErrorV3::OpenSslVersion)
    } else {
        Ok(())
    }
}
#[cfg(feature = "pq-native-openssl")]
impl DualFamilyRosterV3 {
    fn verify_signature(
        &self,
        index: usize,
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), RootCryptoErrorV3> {
        let key = &self.keys[index];
        match key.suite {
            RootSuiteV3::MlDsa87 => self
                .ml_dsa_verifier(index)?
                .verify(message, signature)
                .map_err(|_| RootCryptoErrorV3::SignatureRejected),
            RootSuiteV3::SlhDsaSha2_256s => {
                // OID, AlgorithmIdentifier parameters, BIT STRING and all lengths
                // were checked for all six immutable keys during construction.
                // EVP keys and provider state are deliberately not cached here.
                let public = PKey::public_key_from_der(&key.spki)
                    .map_err(|_| RootCryptoErrorV3::NativeBackend)?;
                if public
                    .public_key_to_der()
                    .map_err(|_| RootCryptoErrorV3::NativeBackend)?
                    != key.spki
                {
                    return Err(RootCryptoErrorV3::PublicKeyEncoding);
                }
                let mut verifier = Verifier::new_without_digest(&public)
                    .map_err(|_| RootCryptoErrorV3::NativeBackend)?;
                match verifier.verify_oneshot(signature, message) {
                    Ok(true) => Ok(()),
                    Ok(false) => Err(RootCryptoErrorV3::SignatureRejected),
                    Err(_) => Err(RootCryptoErrorV3::NativeBackend),
                }
            }
        }
    }

    fn ml_dsa_verifier(&self, index: usize) -> Result<&CandidateVerifier, RootCryptoErrorV3> {
        // The constructor fixes ML-DSA-87 at indices 0..3. No public API can
        // mutate these keys, replace a slot, or import cached expanded material.
        let slot = self
            .ml_dsa_verifiers
            .get(index)
            .ok_or(RootCryptoErrorV3::Suite)?;
        if slot.get().is_none() {
            let expanded = CandidateVerifier::from_pinned_raw(
                CandidateAlgorithm::MlDsa87,
                &self.keys[index].spki[ML_DSA_87_SPKI_PREFIX.len()..],
            )
            .map_err(|_| RootCryptoErrorV3::PublicKeyEncoding)?;
            // Concurrent callers may expand this same immutable key. Keep the
            // first successful value; failures are never retained or promoted.
            let _ = slot.set(Box::new(expanded));
        }
        slot.get()
            .map(Box::as_ref)
            .ok_or(RootCryptoErrorV3::NativeBackend)
    }
}

struct RosterReader<'a> {
    bytes: &'a [u8],
    offset: usize,
}
impl<'a> RosterReader<'a> {
    fn take(&mut self, count: usize) -> Result<&'a [u8], RootCryptoErrorV3> {
        let end = self
            .offset
            .checked_add(count)
            .ok_or(RootCryptoErrorV3::RosterEncoding)?;
        let selected = self
            .bytes
            .get(self.offset..end)
            .ok_or(RootCryptoErrorV3::RosterEncoding)?;
        self.offset = end;
        Ok(selected)
    }
}

#[cfg(test)]
mod tests;
