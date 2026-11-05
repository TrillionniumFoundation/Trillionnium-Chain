//! Versioned cryptographic configuration, selected by a trusted protocol owner.
//!
//! An identifier commits to the complete descriptor AND network, genesis,
//! parameters, namespace, protocol version and activation interval. A received
//! identifier is only compared with an owner's selection; it never selects a
//! weaker verifier. These types authenticate neither the supplied protocol state
//! nor an application's roles, funds, nonce, CURRENT or FinalUse authority.
//!
//! Existing TPQ1/NPQ2..6/PNQ2 bytes are unchanged. Their configuration is an
//! explicit legacy mapping. CPQ1 and both parameter experiments are candidates,
//! and cannot be selected for current effects by this registry.

use sha2::{Digest, Sha512};

const CONFIG_DOMAIN: &[u8] = b"TRNM/CryptoProfile/Configuration/v1\0";
const ENVELOPE_DOMAIN: &[u8] = b"TRNM/CryptoProfile/Envelope/v1\0";
const COMMITMENT_DOMAIN: &[u8] = b"TRNM/CryptoProfile/Commitment/v1\0";
const CPQ1_MAGIC: &[u8; 4] = b"CPQ1";
const CANDIDATE_MESSAGE_ENCODING: &[u8] = b"message:envelope-domain,profile-id64,work-config-digest64,BE16-purpose,BE64-owner-generation,BE64-key-epoch,BE64-sequence,BE64-valid-from-inclusive,BE64-valid-until-inclusive,BE16-signer-count,sorted-unique-signer-id64s,BE32-payload-length,payload;no-tail";
const CANDIDATE_WIRE_ENCODING: &[u8] = b"wire:magic4,BE32-message-length,message,signer-count-times(BE32-key-length,raw-key,BE32-signature-length,raw-signature);signer-order-from-message;no-tail";
const CANDIDATE_COMMITMENT_ENCODING: &[u8] =
    b"commitment:SHA512(commitment-domain,profile-id64,U8-hash-purpose,BE64-byte-length,bytes)";
const WORK_PROFILE_BYTES: &[u8] = include_bytes!("../../../../config/pon/work-profile-v1.json");
pub const NATIVE_WORK_PROFILE_NAME: &str = "pon-matmul-transcript-64-v1";
pub const MAX_SIGNED_MESSAGE_BYTES: usize = 65_536;
pub const CANDIDATE_MAX_WIRE_BYTES: usize = 131_072;
pub const CANDIDATE_MAX_SIGNERS: usize = 8;
pub const CANDIDATE_MAX_ATTEMPTS: u64 = 64;
pub const CANDIDATE_MAX_CUMULATIVE_BYTES: u64 = 8_388_608;
const MAX_HISTORY_PROFILES: usize = 16;
pub const CANDIDATE_HEADER_BYTES: usize = ENVELOPE_DOMAIN.len() + 176;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProfileError {
    Encoding,
    UnknownProfile,
    ProfileMismatch,
    InvalidBinding,
    Inactive,
    CandidateOnly,
    UnsupportedPurpose,
    HistoricalOnly,
    StaleState,
    WorkProfileBoundary,
    Size,
    SignerSet,
    Budget,
}
impl std::fmt::Display for ProfileError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "crypto profile rejected: {self:?}")
    }
}
impl std::error::Error for ProfileError {}

/// Fixed 64-byte ID, with exactly one lowercase hexadecimal text encoding.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct CryptoProfileId([u8; 64]);
impl CryptoProfileId {
    pub fn as_bytes(&self) -> &[u8; 64] {
        &self.0
    }
    pub fn to_hex(self) -> String {
        hex::encode(self.0)
    }
    pub fn from_hex(value: &str) -> Result<Self, ProfileError> {
        if value.len() != 128
            || !value
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(ProfileError::Encoding);
        }
        let mut bytes = [0; 64];
        hex::decode_to_slice(value, &mut bytes).map_err(|_| ProfileError::Encoding)?;
        Ok(Self(bytes))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CryptoProfile {
    LegacyMlDsa65V1,
    CandidateMlDsa65V1,
    CandidateMlDsa87V1,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ProfileScope {
    NativeAccounts = 1,
    NativePeer = 2,
    Operator = 3,
    WholeSystemCandidate = 4,
}

/// Values MUST come from authenticated protocol/configuration state, never an
/// incoming envelope. This module does not authenticate or persist that state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProfileBinding {
    pub network: [u8; 32],
    pub parameters: [u8; 32],
    pub genesis: [u8; 32],
    pub protocol_version: u32,
    pub scope: ProfileScope,
    pub activation_height: u64,
    /// Declared exclusive end, committed into the immutable profile ID. None is
    /// encoded as a tag plus zero, not a sentinel height. A later trusted
    /// retirement uses RetiredCryptoProfile without rebinding this descriptor.
    pub retirement_height: Option<u64>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum CryptoPurpose {
    Account = 1,
    Migration = 2,
    Task = 3,
    Operator = 4,
    Peer = 5,
    Governance = 6,
    Release = 7,
    Current = 8,
    FinalUse = 9,
    Recovery = 10,
}
impl CryptoPurpose {
    const ALL: [Self; 10] = [
        Self::Account,
        Self::Migration,
        Self::Task,
        Self::Operator,
        Self::Peer,
        Self::Governance,
        Self::Release,
        Self::Current,
        Self::FinalUse,
        Self::Recovery,
    ];
    fn domain(self) -> &'static [u8] {
        match self {
            Self::Account => b"TRNM/CPQ1/account/v1\0",
            Self::Migration => b"TRNM/CPQ1/migration/v1\0",
            Self::Task => b"TRNM/CPQ1/task/v1\0",
            Self::Operator => b"TRNM/CPQ1/operator/v1\0",
            Self::Peer => b"TRNM/CPQ1/peer/v1\0",
            Self::Governance => b"TRNM/CPQ1/governance/v1\0",
            Self::Release => b"TRNM/CPQ1/release/v1\0",
            Self::Current => b"TRNM/CPQ1/CURRENT/v1\0",
            Self::FinalUse => b"TRNM/CPQ1/FinalUse/v1\0",
            Self::Recovery => b"TRNM/CPQ1/recovery/v1\0",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum HashPurpose {
    KeyIdentity = 1,
    Payload = 2,
    StateCommitment = 3,
    ReleaseCommitment = 4,
    ProofCommitment = 5,
    Address = 6,
    MerkleNode = 7,
    ProofTranscript = 8,
    WorkChallenge = 9,
    WorkTicket = 10,
}
impl HashPurpose {
    const ALL: [Self; 10] = [
        Self::KeyIdentity,
        Self::Payload,
        Self::StateCommitment,
        Self::ReleaseCommitment,
        Self::ProofCommitment,
        Self::Address,
        Self::MerkleNode,
        Self::ProofTranscript,
        Self::WorkChallenge,
        Self::WorkTicket,
    ];
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HashRule {
    Sha256,
    Sha384,
    Sha512,
    /// Existing PNW1 SHA-256 relation, not a switchable signature hash helper.
    ExternalNativeWork,
    /// No implementation or authority is implied for this legacy scope.
    NotIntegrated,
}
impl HashRule {
    pub fn output_bytes(self) -> Option<usize> {
        match self {
            Self::Sha256 | Self::ExternalNativeWork => Some(32),
            Self::Sha384 => Some(48),
            Self::Sha512 => Some(64),
            Self::NotIntegrated => None,
        }
    }
    fn code(self) -> u8 {
        match self {
            Self::Sha256 => 1,
            Self::Sha384 => 2,
            Self::Sha512 => 3,
            Self::ExternalNativeWork => 4,
            Self::NotIntegrated => 0,
        }
    }
}

impl CryptoProfile {
    pub fn is_candidate(self) -> bool {
        self != Self::LegacyMlDsa65V1
    }
    pub fn algorithm(self) -> &'static str {
        match self {
            Self::LegacyMlDsa65V1 | Self::CandidateMlDsa65V1 => "ML-DSA-65",
            Self::CandidateMlDsa87V1 => "ML-DSA-87",
        }
    }
    pub fn public_key_bytes(self) -> usize {
        match self {
            Self::LegacyMlDsa65V1 | Self::CandidateMlDsa65V1 => 1_952,
            Self::CandidateMlDsa87V1 => 2_592,
        }
    }
    pub fn signature_bytes(self) -> usize {
        match self {
            Self::LegacyMlDsa65V1 | Self::CandidateMlDsa65V1 => 3_309,
            Self::CandidateMlDsa87V1 => 4_627,
        }
    }
    pub fn hash_rule(self, purpose: HashPurpose) -> HashRule {
        if matches!(
            purpose,
            HashPurpose::WorkChallenge | HashPurpose::WorkTicket
        ) {
            return HashRule::ExternalNativeWork;
        }
        if self.is_candidate() {
            return HashRule::Sha512;
        }
        match purpose {
            HashPurpose::KeyIdentity => HashRule::Sha256,
            HashPurpose::Payload => HashRule::Sha384,
            _ => HashRule::NotIntegrated,
        }
    }
    pub fn bind(self, binding: ProfileBinding) -> Result<BoundCryptoProfile, ProfileError> {
        if binding.network == [0; 32]
            || binding.parameters == [0; 32]
            || binding.genesis == [0; 32]
            || binding
                .retirement_height
                .is_some_and(|end| end <= binding.activation_height)
        {
            return Err(ProfileError::InvalidBinding);
        }
        let supported = match (self.is_candidate(), binding.scope) {
            (true, ProfileScope::WholeSystemCandidate) => binding.protocol_version == 1,
            (false, ProfileScope::NativeAccounts) => (2..=6).contains(&binding.protocol_version),
            (false, ProfileScope::NativePeer) => binding.protocol_version == 2,
            // The operator signs a different full-message grammar. Until its
            // complete domains and compound bounds are registered, fail closed.
            (false, ProfileScope::Operator) => false,
            _ => false,
        };
        if !supported {
            return Err(ProfileError::InvalidBinding);
        }
        let mut bound = BoundCryptoProfile {
            profile: self,
            binding,
            id: CryptoProfileId([0; 64]),
        };
        bound.id = CryptoProfileId(Sha512::digest(bound.canonical_configuration()).into());
        Ok(bound)
    }
}

/// Exact bytes of the existing work configuration are bound separately. This
/// digest is not a new W1 algorithm, new challenge, or evidence of work security.
pub fn native_work_configuration_digest() -> [u8; 64] {
    let mut hash = Sha512::new();
    hash.update(b"TRNM/CryptoProfile/ExternalWork/v1\0");
    hash.update((WORK_PROFILE_BYTES.len() as u64).to_be_bytes());
    hash.update(WORK_PROFILE_BYTES);
    hash.finalize().into()
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BoundCryptoProfile {
    profile: CryptoProfile,
    binding: ProfileBinding,
    id: CryptoProfileId,
}
fn field(out: &mut Vec<u8>, value: &[u8]) {
    out.extend_from_slice(&(value.len() as u32).to_be_bytes());
    out.extend_from_slice(value);
}
impl BoundCryptoProfile {
    pub fn id(&self) -> CryptoProfileId {
        self.id
    }
    pub fn profile(&self) -> CryptoProfile {
        self.profile
    }
    pub fn binding(&self) -> &ProfileBinding {
        &self.binding
    }
    pub fn active_at(&self, height: u64) -> bool {
        height >= self.binding.activation_height
            && self
                .binding
                .retirement_height
                .is_none_or(|end| height < end)
    }
    /// Fixed field order, explicit lengths and big-endian integers. No JSON,
    /// unknown fields, normalization, algorithm negotiation or platform usize.
    pub fn canonical_configuration(&self) -> Vec<u8> {
        let mut out = CONFIG_DOMAIN.to_vec();
        out.push(match self.profile {
            CryptoProfile::LegacyMlDsa65V1 => 1,
            CryptoProfile::CandidateMlDsa65V1 => 2,
            CryptoProfile::CandidateMlDsa87V1 => 3,
        });
        field(&mut out, self.profile.algorithm().as_bytes());
        field(
            &mut out,
            b"FIPS204-Pure-empty-context;complete-canonical-message;no-HashMLDSA",
        );
        field(
            &mut out,
            b"deterministic-or-hedged;verification-cannot-attest-signing-randomness",
        );
        field(
            &mut out,
            if self.profile.is_candidate() {
                b"FIPS204-raw-public-key;raw-signature;CPQ1"
            } else {
                b"strict-DER-SPKI-id-ml-dsa-65-no-parameters;raw-signature;legacy-owner-wire"
            },
        );
        out.extend_from_slice(&(self.profile.public_key_bytes() as u32).to_be_bytes());
        out.extend_from_slice(&(self.profile.signature_bytes() as u32).to_be_bytes());
        out.extend_from_slice(&self.binding.network);
        out.extend_from_slice(&self.binding.parameters);
        out.extend_from_slice(&self.binding.genesis);
        out.push(self.binding.scope as u8);
        out.extend_from_slice(&self.binding.protocol_version.to_be_bytes());
        out.extend_from_slice(&self.binding.activation_height.to_be_bytes());
        out.push(u8::from(self.binding.retirement_height.is_some()));
        out.extend_from_slice(&self.binding.retirement_height.unwrap_or(0).to_be_bytes());
        if self.profile.is_candidate() {
            field(&mut out, b"CPQ1;candidate-only;no-current-effects");
            // These are the actual domains and magic consumed below, plus the
            // exact field order/width contract. A same-length domain or magic
            // change must not silently retain an earlier configuration ID.
            for bytes in [
                ENVELOPE_DOMAIN,
                COMMITMENT_DOMAIN,
                CPQ1_MAGIC.as_slice(),
                CANDIDATE_MESSAGE_ENCODING,
                CANDIDATE_WIRE_ENCODING,
                CANDIDATE_COMMITMENT_ENCODING,
            ] {
                field(&mut out, bytes);
            }
            for purpose in CryptoPurpose::ALL {
                out.extend_from_slice(&(purpose as u16).to_be_bytes());
                field(&mut out, purpose.domain());
            }
        } else {
            self.encode_legacy_domains(&mut out);
        }
        for purpose in HashPurpose::ALL {
            let rule = self.profile.hash_rule(purpose);
            out.extend_from_slice(&[
                purpose as u8,
                rule.code(),
                rule.output_bytes().unwrap_or(0) as u8,
            ]);
        }
        if self.profile.is_candidate() {
            for limit in [
                MAX_SIGNED_MESSAGE_BYTES as u64,
                CANDIDATE_MAX_WIRE_BYTES as u64,
                CANDIDATE_MAX_ATTEMPTS,
                CANDIDATE_MAX_CUMULATIVE_BYTES,
                CANDIDATE_MAX_SIGNERS as u64,
            ] {
                out.extend_from_slice(&limit.to_be_bytes());
            }
        } else {
            self.encode_legacy_limits(&mut out);
        }
        field(&mut out, b"owner-limits-are-cumulative;failed-verification-is-charged;wall-clock-not-consensus-validity");
        field(&mut out, NATIVE_WORK_PROFILE_NAME.as_bytes());
        out.extend_from_slice(&native_work_configuration_digest());
        out.push(u8::from(self.profile.is_candidate()));
        out.push(0); // Whole-system qualification is never supplied by this registry.
        out
    }
    fn legacy_account_profile(&self) -> crate::pq_native_accounts_v2::AccountProfile {
        use crate::pq_native_accounts_v2::AccountProfile;
        match self.binding.protocol_version {
            2 => AccountProfile::AccountsV2,
            3 => AccountProfile::QuotaV3,
            4 => AccountProfile::TasksV4,
            5 => AccountProfile::TasksV5,
            6 => AccountProfile::ApplicationV6,
            _ => unreachable!("binding was checked before construction"),
        }
    }
    fn encode_legacy_domains(&self, out: &mut Vec<u8>) {
        use crate::{pq_frame as frame, pq_legacy_profile as peer};
        // Read the SAME bytes/constants used by the existing parser and owners.
        // A changed domain/OID/limit therefore produces a different profile ID.
        field(out, frame::TPQ1_MAGIC);
        out.extend_from_slice(&[
            frame::TPQ1_VERSION,
            frame::TPQ1_ALGORITHM,
            frame::FIRST_PURPOSE,
            frame::LAST_PURPOSE,
            0,
        ]);
        for bytes in [frame::DOMAIN, frame::PUBLIC_KEY_ID_DOMAIN, frame::PAYLOAD_TAG,
            frame::ML_DSA_65_SPKI_PREFIX.as_slice(),
            b"TPQ1:network32,owner-context32,key-id32,BE64-generation,BE64-sequence,BE64-expiry,SHA384-payload,BE16-signature-length",
            b"payload:SHA384(domain,payload-tag,BE64-length,bytes);key-id:SHA256(key-domain,SPKI)"]
        { field(out, bytes); }
        match self.binding.scope {
            ProfileScope::NativeAccounts => {
                let profile = self.legacy_account_profile();
                for bytes in [profile.name().as_bytes(), profile.prefix().as_slice(), profile.packet_prefix().as_slice(),
                    profile.statement_domain(), profile.context_domain(), profile.wire_domain(),
                    b"owner-context:SHA256(domain,network,parameters,genesis,account,profile-name,kind,role);wire-id:SHA256(wire-domain,BE32-length,raw);statement-id:SHA384(statement-domain,body,witness-descriptors)"]
                { field(out, bytes); }
            }
            ProfileScope::NativePeer => {
                for bytes in [peer::PROFILE.as_bytes(), peer::REQUEST_MAGIC.as_slice(), peer::RESPONSE_MAGIC.as_slice(),
                    peer::POLICY_DOMAIN, peer::PEER_CONTEXT_DOMAIN, peer::OPERATION_DOMAIN, peer::RESPONSE_BYTES_DOMAIN,
                    peer::RESPONSE_SCHEMA.as_bytes(), peer::TRANSPORT_MODE.as_bytes(),
                    b"TRNM-PON1\0", b"SHA256:LE16-tag-length,tag,LE32-part-length,part;policy:canonical-PolicyRecord-JSON"]
                { field(out, bytes); }
                out.extend_from_slice(&[
                    peer::PEER_PURPOSE,
                    peer::REQUEST_DIRECTION,
                    peer::RESPONSE_DIRECTION,
                ]);
            }
            _ => unreachable!("unregistered legacy scope cannot bind"),
        }
    }
    fn encode_legacy_limits(&self, out: &mut Vec<u8>) {
        use crate::{
            pq_frame as frame, pq_legacy_profile as peer, pq_native_accounts_v2 as account,
        };
        // Named limits avoid aliases between transaction counts, verifier counts
        // and wire sizes. No zero means an unspecified or unlimited resource.
        fn limit(out: &mut Vec<u8>, name: &[u8], n: u64) {
            field(out, name);
            out.extend_from_slice(&n.to_be_bytes());
        }
        for (name, value) in [
            (b"signed-message-bytes".as_slice(), MAX_SIGNED_MESSAGE_BYTES),
            (b"TPQ1-payload-bytes", frame::TPQ1_MAX_PAYLOAD_BYTES),
            (b"TPQ1-unsigned-bytes", frame::TPQ1_UNSIGNED_BYTES),
            (b"TPQ1-signed-bytes", frame::TPQ1_SIGNED_BYTES),
            (b"raw-public-key-bytes", frame::ML_DSA_65_PUBLIC_KEY_BYTES),
            (b"SPKI-bytes", frame::ML_DSA_65_SPKI_BYTES),
            (b"signature-bytes", frame::ML_DSA_65_SIGNATURE_BYTES),
        ] {
            limit(out, name, value as u64);
        }
        match self.binding.scope {
            ProfileScope::NativeAccounts => {
                let profile = self.legacy_account_profile();
                for (name, value) in [
                    (
                        b"transaction-envelope-bytes".as_slice(),
                        profile.maximum_bytes(),
                    ),
                    (b"transactions-per-packet", profile.maximum_transactions()),
                    (b"verifications-per-packet", profile.maximum_verifications()),
                    (
                        b"transaction-bytes-per-packet",
                        account::MAX_TRANSACTION_BYTES,
                    ),
                    (b"prefix-bytes", account::PREFIX_BYTES),
                    (b"common-bytes", account::COMMON_BYTES),
                    (
                        b"witness-descriptor-bytes",
                        account::WITNESS_DESCRIPTOR_BYTES,
                    ),
                    (b"resolved-witness-bytes", account::RESOLVED_WITNESS_BYTES),
                    (b"carried-witness-bytes", account::CARRIED_WITNESS_BYTES),
                    (b"minimum-envelope-bytes", account::MIN_BYTES),
                    (b"maximum-payload-bytes", profile.maximum_payload_bytes()),
                    (b"transfer-base-bytes", account::TRANSFER_BASE_BYTES),
                    (b"transfer-memo-bytes", account::TRANSFER_MAX_MEMO_BYTES),
                    (
                        b"conflict-envelope-bytes",
                        account::MAX_CONFLICT_ENVELOPE_BYTES,
                    ),
                    (
                        b"conflict-extra-verifications",
                        account::CONFLICT_EVIDENCE_VERIFICATIONS,
                    ),
                ] {
                    limit(out, name, value as u64);
                }
                field(
                    out,
                    b"signer-roles-and-count:exact-native-account-kind-registry",
                );
                // Serialize the actual role/count/carried-key table. A new
                // command or changed signer policy cannot reuse this ID.
                for kind in 0..=u8::MAX {
                    out.push(kind);
                    match account::roles(profile, kind) {
                        Ok(roles) => {
                            out.extend_from_slice(&[1, roles.len() as u8]);
                            for (role, carried) in roles {
                                out.extend_from_slice(&[*role, u8::from(*carried)]);
                            }
                        }
                        Err(_) => out.push(0),
                    }
                }
            }
            ProfileScope::NativePeer => {
                for (name, value) in [
                    (b"wire-bytes".as_slice(), peer::MAX_WIRE as u64),
                    (
                        b"signed-payload-bytes",
                        peer::MAX_SIGNED_PAYLOAD_BYTES as u64,
                    ),
                    (b"ledger-bytes", peer::MAX_LEDGER_BYTES),
                    (b"ledger-records", peer::MAX_RECORDS),
                    (b"ingress-connections", peer::MAX_INGRESS_CONNECTIONS),
                    (b"ingress-bytes", peer::MAX_INGRESS_BYTES),
                    (b"inbound-verifications", peer::MAX_INBOUND_VERIFICATIONS),
                    (b"pinned-peer-roster", peer::MAX_PEERS as u64),
                    (
                        b"lifetime-seconds-local-admission",
                        peer::MAX_LIFETIME_SECONDS,
                    ),
                    (b"signers-per-direction", 1),
                ] {
                    limit(out, name, value);
                }
            }
            _ => unreachable!("unregistered legacy scope cannot bind"),
        }
    }
    pub fn require_claim(&self, claimed: CryptoProfileId) -> Result<(), ProfileError> {
        if self.id != claimed {
            return Err(ProfileError::ProfileMismatch);
        }
        Ok(())
    }
    /// Candidate SHA-512 commitment for one specific use. PNW1 challenge/ticket
    /// and all existing hashes are deliberately outside this API.
    pub fn commitment(&self, purpose: HashPurpose, bytes: &[u8]) -> Result<[u8; 64], ProfileError> {
        if matches!(
            purpose,
            HashPurpose::WorkChallenge | HashPurpose::WorkTicket
        ) {
            return Err(ProfileError::WorkProfileBoundary);
        }
        if self.profile.hash_rule(purpose) != HashRule::Sha512 {
            return Err(ProfileError::UnsupportedPurpose);
        }
        if bytes.len() > MAX_SIGNED_MESSAGE_BYTES {
            return Err(ProfileError::Size);
        }
        let mut hash = Sha512::new();
        hash.update(COMMITMENT_DOMAIN);
        hash.update(self.id.as_bytes());
        hash.update([purpose as u8]);
        hash.update((bytes.len() as u64).to_be_bytes());
        hash.update(bytes);
        Ok(hash.finalize().into())
    }
}

/// A retirement interval supplied by the authenticated protocol state owner.
/// The original descriptor and ID are immutable; this registration only narrows
/// the historical interval. Construction validates bounds, not the authority or
/// persistence of the caller's state, nor acceptance of any historical record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RetiredCryptoProfile {
    profile: BoundCryptoProfile,
    effective_retirement_height: u64,
}
impl RetiredCryptoProfile {
    pub fn from_trusted_state(
        profile: BoundCryptoProfile,
        effective_retirement_height: u64,
    ) -> Result<Self, ProfileError> {
        if profile.profile.is_candidate()
            || effective_retirement_height <= profile.binding.activation_height
            || profile
                .binding
                .retirement_height
                .is_some_and(|declared_end| effective_retirement_height > declared_end)
        {
            return Err(ProfileError::InvalidBinding);
        }
        Ok(Self {
            profile,
            effective_retirement_height,
        })
    }
    /// Returns the original descriptor; its active_at does not include this
    /// effective cutoff. Historical eligibility uses the policy's select_historical.
    pub fn profile(&self) -> &BoundCryptoProfile {
        &self.profile
    }
    pub fn effective_retirement_height(&self) -> u64 {
        self.effective_retirement_height
    }
    fn active_at(&self, height: u64) -> bool {
        self.profile.active_at(height) && height < self.effective_retirement_height
    }
}

/// A snapshot supplied by the trusted state owner. A fresh snapshot/generation
/// must be checked at final use; a mathematical verification cache cannot do it.
pub struct CryptoProfilePolicy {
    current: BoundCryptoProfile,
    height: u64,
    state_generation: u64,
    history: Vec<RetiredCryptoProfile>,
}
pub struct CurrentCryptoProfile<'a> {
    selected: &'a BoundCryptoProfile,
    state_generation: u64,
}
pub struct HistoricalCryptoProfile<'a> {
    selected: &'a BoundCryptoProfile,
    record_height: u64,
}
impl CurrentCryptoProfile<'_> {
    pub fn selected(&self) -> &BoundCryptoProfile {
        self.selected
    }
}
impl HistoricalCryptoProfile<'_> {
    pub fn selected(&self) -> &BoundCryptoProfile {
        self.selected
    }
    pub fn record_height(&self) -> u64 {
        self.record_height
    }
}
impl CryptoProfilePolicy {
    fn require_history_limits(
        state_generation: u64,
        history_len: usize,
    ) -> Result<(), ProfileError> {
        if state_generation == 0 || history_len > MAX_HISTORY_PROFILES {
            return Err(ProfileError::InvalidBinding);
        }
        Ok(())
    }
    /// Compatibility path for retirement heights declared in the descriptor.
    /// Open-ended historical descriptors still require an explicit trusted
    /// registration through from_trusted_state_with_retirements.
    pub fn from_trusted_state(
        current: BoundCryptoProfile,
        height: u64,
        state_generation: u64,
        history: Vec<BoundCryptoProfile>,
    ) -> Result<Self, ProfileError> {
        Self::require_history_limits(state_generation, history.len())?;
        let history = history
            .into_iter()
            .map(|profile| {
                let end = profile
                    .binding
                    .retirement_height
                    .ok_or(ProfileError::InvalidBinding)?;
                RetiredCryptoProfile::from_trusted_state(profile, end)
            })
            .collect::<Result<Vec<_>, _>>()?;
        Self::from_trusted_state_with_retirements(current, height, state_generation, history)
    }
    /// The owner independently authenticates the effective retirement schedule.
    /// Neither a received profile ID nor historical message bytes may choose it.
    pub fn from_trusted_state_with_retirements(
        current: BoundCryptoProfile,
        height: u64,
        state_generation: u64,
        history: Vec<RetiredCryptoProfile>,
    ) -> Result<Self, ProfileError> {
        Self::require_history_limits(state_generation, history.len())?;
        for (i, old) in history.iter().enumerate() {
            let profile = &old.profile;
            if profile.binding.network != current.binding.network
                || profile.binding.genesis != current.binding.genesis
                || profile.binding.scope != current.binding.scope
                || profile.id == current.id
                || history[..i]
                    .iter()
                    .any(|previous| previous.profile.id == profile.id)
                || old.effective_retirement_height > current.binding.activation_height
                || history[..i].iter().any(|previous| {
                    profile.binding.activation_height < previous.effective_retirement_height
                        && previous.profile.binding.activation_height
                            < old.effective_retirement_height
                })
            {
                return Err(ProfileError::InvalidBinding);
            }
        }
        Ok(Self {
            current,
            height,
            state_generation,
            history,
        })
    }
    pub fn select_current(
        &self,
        claim: CryptoProfileId,
    ) -> Result<CurrentCryptoProfile<'_>, ProfileError> {
        self.current.require_claim(claim)?;
        if self.current.profile.is_candidate() {
            return Err(ProfileError::CandidateOnly);
        }
        if !self.current.active_at(self.height) {
            return Err(ProfileError::Inactive);
        }
        Ok(CurrentCryptoProfile {
            selected: &self.current,
            state_generation: self.state_generation,
        })
    }
    /// Checks the registered interval and supplied height only. The owner must
    /// separately authenticate that this record was accepted at that height.
    /// The result carries no current-effect authority.
    pub fn select_historical(
        &self,
        claim: CryptoProfileId,
        record_height: u64,
    ) -> Result<HistoricalCryptoProfile<'_>, ProfileError> {
        if record_height > self.height {
            return Err(ProfileError::Inactive);
        }
        let (selected, active) = if self.current.id == claim {
            (&self.current, self.current.active_at(record_height))
        } else {
            let retired = self
                .history
                .iter()
                .find(|entry| entry.profile.id == claim)
                .ok_or(ProfileError::UnknownProfile)?;
            (&retired.profile, retired.active_at(record_height))
        };
        if selected.profile.is_candidate() {
            return Err(ProfileError::CandidateOnly);
        }
        if !active {
            return Err(ProfileError::Inactive);
        }
        Ok(HistoricalCryptoProfile {
            selected,
            record_height,
        })
    }
    /// This takes only a CurrentCryptoProfile, never a HistoricalCryptoProfile.
    /// It rechecks configuration/generation; the owner still rechecks all roles,
    /// revocations, balances, nonce and final-use conditions before commit.
    ///
    /// ```compile_fail
    /// use trnm_protocol::crypto_profile::{CryptoProfilePolicy, HistoricalCryptoProfile};
    /// fn misuse(policy: &CryptoProfilePolicy, old: &HistoricalCryptoProfile<'_>) {
    ///     policy.recheck_current(old).unwrap();
    /// }
    /// ```
    pub fn recheck_current(&self, selected: &CurrentCryptoProfile<'_>) -> Result<(), ProfileError> {
        if self.state_generation != selected.state_generation
            || self.current.id != selected.selected.id
        {
            return Err(ProfileError::StaleState);
        }
        self.select_current(self.current.id).map(|_| ())
    }
}

/// Complete candidate signing context. Ordered signer IDs must be derived from
/// independently pinned raw keys with this profile's KeyIdentity commitment.
pub struct CandidateEnvelope<'a> {
    pub purpose: CryptoPurpose,
    pub owner_generation: u64,
    pub key_epoch: u64,
    pub sequence: u64,
    pub valid_from_height: u64,
    pub valid_until_height: u64,
    pub signer_ids: &'a [[u8; 64]],
    pub payload: &'a [u8],
}
/// Syntax and trusted-context equality only; no cryptographic success or effect.
pub struct UnverifiedCandidateSignatures<'a> {
    message: &'a [u8],
    signatures: Vec<&'a [u8]>,
}
impl<'a> UnverifiedCandidateSignatures<'a> {
    pub fn message(&self) -> &'a [u8] {
        self.message
    }
    pub fn signatures(&self) -> &[&'a [u8]] {
        &self.signatures
    }
}
impl BoundCryptoProfile {
    pub fn candidate_message(
        &self,
        envelope: &CandidateEnvelope<'_>,
    ) -> Result<Vec<u8>, ProfileError> {
        if !self.profile.is_candidate() {
            return Err(ProfileError::CandidateOnly);
        }
        if envelope.owner_generation == 0
            || envelope.key_epoch == 0
            || envelope.sequence == 0
            || envelope.valid_until_height < envelope.valid_from_height
            || !self.active_at(envelope.valid_from_height)
            || !self.active_at(envelope.valid_until_height)
        {
            return Err(ProfileError::InvalidBinding);
        }
        if envelope.signer_ids.is_empty()
            || envelope.signer_ids.len() > CANDIDATE_MAX_SIGNERS
            || envelope.signer_ids.contains(&[0; 64])
            || envelope
                .signer_ids
                .windows(2)
                .any(|pair| pair[0] >= pair[1])
        {
            return Err(ProfileError::SignerSet);
        }
        let size = CANDIDATE_HEADER_BYTES
            .checked_add(envelope.signer_ids.len() * 64)
            .and_then(|n| n.checked_add(envelope.payload.len()))
            .ok_or(ProfileError::Size)?;
        if size > MAX_SIGNED_MESSAGE_BYTES {
            return Err(ProfileError::Size);
        }
        let mut out = Vec::with_capacity(size);
        out.extend_from_slice(ENVELOPE_DOMAIN);
        out.extend_from_slice(self.id.as_bytes());
        out.extend_from_slice(&native_work_configuration_digest());
        out.extend_from_slice(&(envelope.purpose as u16).to_be_bytes());
        for n in [
            envelope.owner_generation,
            envelope.key_epoch,
            envelope.sequence,
            envelope.valid_from_height,
            envelope.valid_until_height,
        ] {
            out.extend_from_slice(&n.to_be_bytes());
        }
        out.extend_from_slice(&(envelope.signer_ids.len() as u16).to_be_bytes());
        for id in envelope.signer_ids {
            out.extend_from_slice(id);
        }
        out.extend_from_slice(&(envelope.payload.len() as u32).to_be_bytes());
        out.extend_from_slice(envelope.payload);
        debug_assert_eq!(out.len(), size);
        Ok(out)
    }
    /// The caller fixes the entire expected context; received bytes only compare.
    /// No candidate or historical result can be converted into current authority.
    pub fn check_candidate_message(
        &self,
        claim: CryptoProfileId,
        received: &[u8],
        expected: &CandidateEnvelope<'_>,
    ) -> Result<(), ProfileError> {
        self.require_claim(claim)?;
        if received.len() > MAX_SIGNED_MESSAGE_BYTES {
            return Err(ProfileError::Size);
        }
        if self.candidate_message(expected)? != received {
            return Err(ProfileError::Encoding);
        }
        Ok(())
    }
    /// Exact complete CPQ1 wire, including length fields, every raw key and every
    /// signature. Signature mathematics must be checked by the crypto owner.
    pub fn candidate_wire(
        &self,
        envelope: &CandidateEnvelope<'_>,
        keys: &[&[u8]],
        signatures: &[&[u8]],
    ) -> Result<Vec<u8>, ProfileError> {
        if keys.len() != envelope.signer_ids.len() || signatures.len() != keys.len() {
            return Err(ProfileError::SignerSet);
        }
        let message = self.candidate_message(envelope)?;
        let per_signer = self.profile.public_key_bytes() + self.profile.signature_bytes() + 8;
        let size = 8usize
            .checked_add(message.len())
            .and_then(|n| n.checked_add(keys.len() * per_signer))
            .ok_or(ProfileError::Size)?;
        if size > CANDIDATE_MAX_WIRE_BYTES {
            return Err(ProfileError::Size);
        }
        let mut out = Vec::with_capacity(size);
        out.extend_from_slice(CPQ1_MAGIC);
        out.extend_from_slice(&(message.len() as u32).to_be_bytes());
        out.extend_from_slice(&message);
        for ((key, signature), id) in keys.iter().zip(signatures).zip(envelope.signer_ids) {
            if key.len() != self.profile.public_key_bytes()
                || signature.len() != self.profile.signature_bytes()
                || self.commitment(HashPurpose::KeyIdentity, key)? != *id
            {
                return Err(ProfileError::SignerSet);
            }
            field(&mut out, key);
            field(&mut out, signature);
        }
        debug_assert_eq!(out.len(), size);
        Ok(out)
    }
    /// The trusted owner supplies all expected fields and its complete key set.
    /// A caller reserves its cumulative budget BEFORE this bounded parser.
    pub fn check_candidate_wire<'a>(
        &self,
        wire: &'a [u8],
        expected: &CandidateEnvelope<'_>,
        pinned_keys: &[&[u8]],
    ) -> Result<UnverifiedCandidateSignatures<'a>, ProfileError> {
        if wire.len() > CANDIDATE_MAX_WIRE_BYTES || wire.len() < 8 {
            return Err(ProfileError::Size);
        }
        if &wire[..4] != CPQ1_MAGIC {
            return Err(ProfileError::Encoding);
        }
        if pinned_keys.len() != expected.signer_ids.len() {
            return Err(ProfileError::SignerSet);
        }
        let expected_message = self.candidate_message(expected)?;
        let message_len =
            u32::from_be_bytes(wire[4..8].try_into().map_err(|_| ProfileError::Encoding)?) as usize;
        if message_len != expected_message.len() {
            return Err(ProfileError::Size);
        }
        let end = 8usize.checked_add(message_len).ok_or(ProfileError::Size)?;
        let message = wire.get(8..end).ok_or(ProfileError::Size)?;
        if message != expected_message {
            return Err(ProfileError::Encoding);
        }
        let mut at = end;
        let mut signatures = Vec::with_capacity(pinned_keys.len());
        for (key, id) in pinned_keys.iter().zip(expected.signer_ids) {
            if key.len() != self.profile.public_key_bytes()
                || self.commitment(HashPurpose::KeyIdentity, key)? != *id
            {
                return Err(ProfileError::SignerSet);
            }
            let key_len = read_u32(wire, &mut at)?;
            if key_len != self.profile.public_key_bytes() {
                return Err(ProfileError::Size);
            }
            if take(wire, &mut at, key_len)? != *key {
                return Err(ProfileError::SignerSet);
            }
            let signature_len = read_u32(wire, &mut at)?;
            if signature_len != self.profile.signature_bytes() {
                return Err(ProfileError::Size);
            }
            signatures.push(take(wire, &mut at, signature_len)?);
        }
        if at != wire.len() {
            return Err(ProfileError::Encoding);
        }
        Ok(UnverifiedCandidateSignatures {
            message,
            signatures,
        })
    }
}

fn take<'a>(bytes: &'a [u8], at: &mut usize, count: usize) -> Result<&'a [u8], ProfileError> {
    let end = at.checked_add(count).ok_or(ProfileError::Size)?;
    let result = bytes.get(*at..end).ok_or(ProfileError::Size)?;
    *at = end;
    Ok(result)
}
fn read_u32(bytes: &[u8], at: &mut usize) -> Result<usize, ProfileError> {
    let raw: [u8; 4] = take(bytes, at, 4)?
        .try_into()
        .map_err(|_| ProfileError::Size)?;
    Ok(u32::from_be_bytes(raw) as usize)
}

/// Deterministic candidate resource accounting, shared across a complete batch.
/// Reserve before parsing/hashing/verifying. Invalid attempts are not refunded.
/// Time and CPU admission remain the existing runtime owner's separate policy.
pub struct CandidateVerificationBudget {
    attempts: u64,
    bytes: u64,
    exhausted: bool,
}
impl Default for CandidateVerificationBudget {
    fn default() -> Self {
        Self::new()
    }
}
impl CandidateVerificationBudget {
    pub fn new() -> Self {
        Self {
            attempts: 0,
            bytes: 0,
            exhausted: false,
        }
    }
    pub fn attempts(&self) -> u64 {
        self.attempts
    }
    pub fn charged_bytes(&self) -> u64 {
        self.bytes
    }
    pub fn reserve(&mut self, wire_bytes: usize, verifications: usize) -> Result<(), ProfileError> {
        if self.exhausted {
            return Err(ProfileError::Budget);
        }
        let attempts = self
            .attempts
            .checked_add(u64::try_from(verifications).map_err(|_| ProfileError::Budget)?);
        let bytes = self
            .bytes
            .checked_add(u64::try_from(wire_bytes).map_err(|_| ProfileError::Budget)?);
        match (attempts, bytes) {
            (Some(a), Some(b)) => {
                self.attempts = a;
                self.bytes = b;
            }
            _ => {
                self.exhausted = true;
                return Err(ProfileError::Budget);
            }
        }
        if verifications == 0
            || verifications > CANDIDATE_MAX_SIGNERS
            || wire_bytes > CANDIDATE_MAX_WIRE_BYTES
            || self.attempts > CANDIDATE_MAX_ATTEMPTS
            || self.bytes > CANDIDATE_MAX_CUMULATIVE_BYTES
        {
            self.exhausted = true;
            return Err(ProfileError::Budget);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
