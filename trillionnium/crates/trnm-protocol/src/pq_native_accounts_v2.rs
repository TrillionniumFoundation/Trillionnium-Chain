//! NPQ2 command framing. Every returned value is unverified; current State key
//! resolution and real ML-DSA verification remain the M06/M01 owners' work.
//! Ordinary witnesses omit SPKI; this module never invents their public keys.
use crate::pq_frame::{
    ml_dsa_65_key_id_from_spki, payload_commitment, preflight_unverified, PqFrameExpectation,
    ML_DSA_65_SPKI_BYTES, TPQ1_SIGNED_BYTES, TPQ1_UNSIGNED_BYTES,
};
use sha2::{Digest, Sha256, Sha384};

pub const PROFILE: &str = "pon-native-pq-accounts-v2";
pub const PACKET_PREFIX: &[u8; 8] = b"PQP2\x02\0\0\0";
pub const PREFIX_BYTES: usize = 16;
pub const COMMON_BYTES: usize = 160;
pub const WITNESS_DESCRIPTOR_BYTES: usize = 46;
pub const RESOLVED_WITNESS_BYTES: usize = WITNESS_DESCRIPTOR_BYTES + TPQ1_SIGNED_BYTES;
pub const CARRIED_WITNESS_BYTES: usize = RESOLVED_WITNESS_BYTES + ML_DSA_65_SPKI_BYTES;
pub const MIN_BYTES: usize = 3_741;
pub const MAX_BYTES: usize = 9_432;
pub const MAX_TRANSACTION_BYTES: usize = 524_288;
pub const MAX_TRANSACTIONS: usize = 256;
pub const REGISTER: u8 = 0x80;
pub const ROTATE: u8 = 0x81;
pub const CLAIM: u8 = 0x82;
/// Explicit wire selection; parsing never negotiates a profile from the input.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AccountProfile {
    AccountsV2,
    QuotaV3,
    TasksV4,
    TasksV5,
}
impl AccountProfile {
    pub fn name(self) -> &'static str {
        match self {
            Self::AccountsV2 => PROFILE,
            Self::QuotaV3 => "pon-native-pq-quota-v3",
            Self::TasksV4 => "pon-native-pq-tasks-v4",
            Self::TasksV5 => "pon-native-pq-tasks-v5",
        }
    }
    pub fn packet_prefix(self) -> &'static [u8; 8] {
        match self {
            Self::AccountsV2 => PACKET_PREFIX,
            Self::QuotaV3 => b"PQP3\x03\0\0\0",
            Self::TasksV4 => b"PQP4\x04\0\0\0",
            Self::TasksV5 => b"PQP5\x05\0\0\0",
        }
    }
    fn prefix(self) -> &'static [u8; 5] {
        match self {
            Self::AccountsV2 => b"NPQ2\x02",
            Self::QuotaV3 => b"NPQ3\x03",
            Self::TasksV4 => b"NPQ4\x04",
            Self::TasksV5 => b"NPQ5\x05",
        }
    }
    fn statement_domain(self) -> &'static [u8] {
        match self {
            Self::AccountsV2 => b"TRNM/PoN/NativePQCommandStatement/v2\0",
            Self::QuotaV3 => b"TRNM/PoN/NativePQQuotaStatement/v3\0",
            Self::TasksV4 => b"TRNM/PoN/NativePQTaskStatement/v4\0",
            Self::TasksV5 => b"TRNM/PoN/NativePQTaskStatement/v5\0",
        }
    }
    fn context_domain(self) -> &'static [u8] {
        match self {
            Self::AccountsV2 => b"TRNM/PoN/NativePQAccountContext/v2\0",
            Self::QuotaV3 => b"TRNM/PoN/NativePQQuotaContext/v3\0",
            Self::TasksV4 => b"TRNM/PoN/NativePQTaskContext/v4\0",
            Self::TasksV5 => b"TRNM/PoN/NativePQTaskContext/v5\0",
        }
    }
    fn wire_domain(self) -> &'static [u8] {
        match self {
            Self::AccountsV2 => b"TRNM/PoN/NativePQCommandWire/v2\0",
            Self::QuotaV3 => b"TRNM/PoN/NativePQQuotaWire/v3\0",
            Self::TasksV4 => b"TRNM/PoN/NativePQTaskWire/v4\0",
            Self::TasksV5 => b"TRNM/PoN/NativePQTaskWire/v5\0",
        }
    }
}
const _: () = assert!(RESOLVED_WITNESS_BYTES == 3_533 && CARRIED_WITNESS_BYTES == 5_507);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChainContext {
    pub network: [u8; 32],
    pub parameters: [u8; 32],
    pub genesis: [u8; 32],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Common {
    pub context: ChainContext,
    pub account: [u8; 32],
    pub nonce: u64,
    pub expires_at: u64,
    pub max_fee: u64,
    pub generation: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WitnessKey {
    /// Exact purpose/role, not a caller-supplied permission decision.
    pub role: u8,
    pub generation: u64,
    pub key_id: [u8; 32],
    /// None means the actual current State owner must resolve the public key.
    pub spki: Option<Vec<u8>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Length,
    Encoding,
    Context,
    Key,
    Frame,
}

#[derive(Debug)]
pub struct UnverifiedWitness<'a> {
    pub role: u8,
    pub generation: u64,
    pub key_id: [u8; 32],
    pub spki: Option<&'a [u8]>,
    pub frame: &'a [u8],
}

#[derive(Debug)]
pub struct UnverifiedEnvelope<'a> {
    raw: &'a [u8],
    profile: AccountProfile,
    pub common: Common,
    pub kind: u8,
    pub payload: &'a [u8],
    witnesses: Vec<UnverifiedWitness<'a>>,
    core: Vec<u8>,
}

fn bytes<const N: usize>(raw: &[u8], at: usize) -> Result<[u8; N], Error> {
    raw.get(at..at.checked_add(N).ok_or(Error::Length)?)
        .ok_or(Error::Length)?
        .try_into()
        .map_err(|_| Error::Length)
}
fn number(raw: &[u8], at: usize) -> Result<u64, Error> {
    Ok(u64::from_be_bytes(bytes(raw, at)?))
}
fn roles(profile: AccountProfile, kind: u8) -> Result<&'static [(u8, bool)], Error> {
    match kind {
        1..=5 => Ok(&[(1, false)]),
        10 if matches!(
            profile,
            AccountProfile::QuotaV3 | AccountProfile::TasksV4 | AccountProfile::TasksV5
        ) =>
        {
            Ok(&[(1, false)])
        }
        11 if matches!(
            profile,
            AccountProfile::QuotaV3 | AccountProfile::TasksV4 | AccountProfile::TasksV5
        ) =>
        {
            Ok(&[(1, false), (2, false)])
        }
        18..=20 if profile == AccountProfile::TasksV5 => Ok(&[(1, false)]),
        21 | 22 if profile == AccountProfile::TasksV5 => Ok(&[(1, false), (2, false)]),
        18 | 20 if profile == AccountProfile::TasksV4 => Ok(&[(1, false)]),
        21 if profile == AccountProfile::TasksV4 => Ok(&[(1, false), (2, false)]),
        REGISTER => Ok(&[(2, true)]),
        ROTATE => Ok(&[(3, false), (4, true)]),
        CLAIM => Ok(&[(5, false), (6, true)]),
        _ => Err(Error::Encoding),
    }
}
pub fn changes_authority(kind: u8) -> bool {
    matches!(kind, REGISTER | ROTATE | CLAIM)
}

fn check(profile: AccountProfile, common: &Common, kind: u8, payload: &[u8]) -> Result<(), Error> {
    if [
        common.context.network,
        common.context.parameters,
        common.context.genesis,
        common.account,
    ]
    .contains(&[0; 32])
        || common.nonce == 0
        || common.expires_at == 0
    {
        return Err(Error::Context);
    }
    match kind {
        1 => {
            if payload.len() < 42 || payload.len() > 554 {
                return Err(Error::Length);
            }
            let memo = u16::from_be_bytes(bytes(payload, 40)?) as usize;
            if payload.len() != 42 + memo || memo > 512 || bytes::<32>(payload, 0)? == [0; 32] {
                return Err(Error::Encoding);
            }
        }
        2 if payload.len() == 80 => {}
        3 if payload.len() == 32 => {}
        4 | 5 if payload.len() == 64 => {}
        10 if matches!(
            profile,
            AccountProfile::QuotaV3 | AccountProfile::TasksV4 | AccountProfile::TasksV5
        ) && payload.len() == 112 => {}
        11 if matches!(
            profile,
            AccountProfile::QuotaV3 | AccountProfile::TasksV4 | AccountProfile::TasksV5
        ) && payload.len() == 72 => {}
        18 if profile == AccountProfile::TasksV4 => {
            crate::qualified_work_task::pq_lifecycle_v4::DemandLeaseV4::decode(payload)
                .map_err(|_| Error::Encoding)?;
        }
        20 if profile == AccountProfile::TasksV4 => {
            crate::qualified_work_task::pq_lifecycle_v4::DemandRevocationV4::decode(payload)
                .map_err(|_| Error::Encoding)?;
        }
        21 if profile == AccountProfile::TasksV4 => {
            crate::qualified_work_task::pq_lifecycle_v4::TaskRegistrationV4::decode(payload)
                .map_err(|_| Error::Encoding)?;
        }
        18 if profile == AccountProfile::TasksV5 => {
            crate::qualified_work_task::pq_lifecycle_v5::DemandLeaseV5::decode(payload)
                .map_err(|_| Error::Encoding)?;
        }
        19 if profile == AccountProfile::TasksV5 => {
            crate::qualified_work_task::pq_lifecycle_v5::DemandRenewalV5::decode(payload)
                .map_err(|_| Error::Encoding)?;
        }
        20 if profile == AccountProfile::TasksV5 => {
            crate::qualified_work_task::pq_lifecycle_v5::DemandRevocationV5::decode(payload)
                .map_err(|_| Error::Encoding)?;
        }
        21 if profile == AccountProfile::TasksV5 => {
            crate::qualified_work_task::pq_lifecycle_v5::TaskRegistrationV5::decode(payload)
                .map_err(|_| Error::Encoding)?;
        }
        22 if profile == AccountProfile::TasksV5 => {
            crate::qualified_work_task::pq_lifecycle_v5::AtomicRenewTaskV5::decode(payload)
                .map_err(|_| Error::Encoding)?;
        }
        REGISTER if payload.len() == 8 && number(payload, 0)? == 1 => {}
        ROTATE if payload.len() == 56 => {
            if common.generation.checked_add(1) != Some(number(payload, 0)?)
                || bytes::<48>(payload, 8)? == [0; 48]
            {
                return Err(Error::Context);
            }
        }
        CLAIM if payload.len() == 216 => {
            if number(payload, 208)? != 1
                || bytes::<32>(payload, 112)? != common.account
                || bytes::<48>(payload, 0)? == [0; 48]
                || bytes::<32>(payload, 48)? == [0; 32]
                || bytes::<32>(payload, 80)? == [0; 32]
                || bytes::<48>(payload, 160)? == [0; 48]
            {
                return Err(Error::Context);
            }
        }
        _ => return Err(Error::Length),
    }
    if matches!(kind, REGISTER | CLAIM) != (common.generation == 0) {
        return Err(Error::Context);
    }
    Ok(())
}

fn prefix_body(
    profile: AccountProfile,
    common: &Common,
    kind: u8,
    payload: &[u8],
) -> Result<Vec<u8>, Error> {
    let roles = roles(profile, kind)?;
    check(profile, common, kind, payload)?;
    let mut raw = Vec::with_capacity(PREFIX_BYTES + COMMON_BYTES + payload.len());
    raw.extend(profile.prefix());
    raw.extend([kind, roles.len() as u8, 0]);
    raw.extend(((COMMON_BYTES + payload.len()) as u32).to_be_bytes());
    raw.extend([0; 4]);
    for field in [
        common.context.network,
        common.context.parameters,
        common.context.genesis,
        common.account,
    ] {
        raw.extend(field);
    }
    for field in [
        common.nonce,
        common.expires_at,
        common.max_fee,
        common.generation,
    ] {
        raw.extend(field.to_be_bytes());
    }
    raw.extend(payload);
    Ok(raw)
}

fn key_bytes(
    profile: AccountProfile,
    common: &Common,
    kind: u8,
    payload: &[u8],
    keys: &[WitnessKey],
) -> Result<Vec<Vec<u8>>, Error> {
    let expected = roles(profile, kind)?;
    if keys.len() != expected.len() {
        return Err(Error::Encoding);
    }
    let mut output = Vec::with_capacity(keys.len());
    for (key, &(role, carried)) in keys.iter().zip(expected) {
        if key.role != role
            || key.generation == 0
            || key.key_id == [0; 32]
            || key.spki.is_some() != carried
        {
            return Err(Error::Key);
        }
        let generation = match role {
            1 | 3 => common.generation,
            2 if matches!(
                profile,
                AccountProfile::QuotaV3 | AccountProfile::TasksV4 | AccountProfile::TasksV5
            ) && kind == 11 =>
            {
                key.generation
            }
            2 if profile == AccountProfile::TasksV4 && kind == 21 => key.generation,
            2 if profile == AccountProfile::TasksV5 && matches!(kind, 21 | 22) => key.generation,
            2 | 6 => 1,
            4 => number(payload, 0)?,
            5 => key.generation, // Independently pinned anchor generation is checked by State.
            _ => return Err(Error::Encoding),
        };
        if key.generation != generation {
            return Err(Error::Key);
        }
        let mut raw = vec![role, 0x65, 0, 0];
        raw.extend(key.generation.to_be_bytes());
        raw.extend(key.key_id);
        raw.extend(
            (if carried {
                ML_DSA_65_SPKI_BYTES as u16
            } else {
                0
            })
            .to_be_bytes(),
        );
        if let Some(spki) = &key.spki {
            if ml_dsa_65_key_id_from_spki(spki).map_err(|_| Error::Key)? != key.key_id {
                return Err(Error::Key);
            }
            raw.extend(spki);
        }
        output.push(raw);
    }
    Ok(output)
}

/// Canonical new-domain statement shared by every role. Signature bytes are
/// excluded; every descriptor and every carried new public key is included.
pub fn signing_core_for_profile(
    profile: AccountProfile,
    common: &Common,
    kind: u8,
    payload: &[u8],
    keys: &[WitnessKey],
) -> Result<Vec<u8>, Error> {
    let body = prefix_body(profile, common, kind, payload)?;
    let descriptors = key_bytes(profile, common, kind, payload, keys)?;
    let mut output = profile.statement_domain().to_vec();
    output.extend(body);
    for descriptor in descriptors {
        output.extend(descriptor);
    }
    Ok(output)
}

pub fn owner_context_for_profile(
    profile: AccountProfile,
    common: &Common,
    kind: u8,
    role: u8,
) -> Result<[u8; 32], Error> {
    if !roles(profile, kind)?
        .iter()
        .any(|&(expected, _)| expected == role)
        || [
            common.context.network,
            common.context.parameters,
            common.context.genesis,
            common.account,
        ]
        .contains(&[0; 32])
    {
        return Err(Error::Context);
    }
    let mut hash = Sha256::new();
    hash.update(profile.context_domain());
    hash.update(common.context.network);
    hash.update(common.context.parameters);
    hash.update(common.context.genesis);
    hash.update(common.account);
    hash.update(profile.name().as_bytes());
    hash.update([kind, role]);
    Ok(hash.finalize().into())
}

pub fn signing_statement_for_profile(
    profile: AccountProfile,
    common: &Common,
    kind: u8,
    payload: &[u8],
    keys: &[WitnessKey],
    index: usize,
) -> Result<[u8; TPQ1_UNSIGNED_BYTES], Error> {
    let core = signing_core_for_profile(profile, common, kind, payload, keys)?;
    let key = keys.get(index).ok_or(Error::Encoding)?;
    let mut raw = [0; TPQ1_UNSIGNED_BYTES];
    raw[..8].copy_from_slice(&[b'T', b'P', b'Q', b'1', 1, 0x65, key.role, 0]);
    raw[8..40].copy_from_slice(&common.context.network);
    raw[40..72].copy_from_slice(&owner_context_for_profile(profile, common, kind, key.role)?);
    raw[72..104].copy_from_slice(&key.key_id);
    raw[104..112].copy_from_slice(&key.generation.to_be_bytes());
    raw[112..120].copy_from_slice(&common.nonce.to_be_bytes());
    raw[120..128].copy_from_slice(&common.expires_at.to_be_bytes());
    raw[128..].copy_from_slice(&payload_commitment(&core).map_err(|_| Error::Length)?);
    Ok(raw)
}

/// Strict framing, not cryptographic verification. Invalid signatures can still
/// be encoded; the returned raw bytes confer no account or transaction authority.
pub fn encode_for_profile(
    profile: AccountProfile,
    common: &Common,
    kind: u8,
    payload: &[u8],
    keys: &[WitnessKey],
    frames: &[Vec<u8>],
) -> Result<Vec<u8>, Error> {
    let mut raw = prefix_body(profile, common, kind, payload)?;
    let descriptors = key_bytes(profile, common, kind, payload, keys)?;
    if frames.len() != descriptors.len() {
        return Err(Error::Length);
    }
    for (descriptor, frame) in descriptors.into_iter().zip(frames) {
        if frame.len() != TPQ1_SIGNED_BYTES {
            return Err(Error::Length);
        }
        raw.extend(descriptor);
        raw.extend(frame);
    }
    UnverifiedEnvelope::decode_for_profile(&raw, profile)?;
    Ok(raw)
}

impl<'a> UnverifiedEnvelope<'a> {
    pub fn decode(raw: &'a [u8]) -> Result<Self, Error> {
        Self::decode_for_profile(raw, AccountProfile::AccountsV2)
    }
    pub fn decode_for_profile(raw: &'a [u8], profile: AccountProfile) -> Result<Self, Error> {
        if !(MIN_BYTES..=MAX_BYTES).contains(&raw.len()) {
            return Err(Error::Length);
        }
        if &raw[..5] != profile.prefix() || raw[7] != 0 || raw[12..16] != [0; 4] {
            return Err(Error::Encoding);
        }
        let kind = raw[5];
        let expected = roles(profile, kind)?;
        let body_len = u32::from_be_bytes(bytes(raw, 8)?) as usize;
        let max_payload = if profile == AccountProfile::TasksV5 {
            crate::qualified_work_task::pq_lifecycle_v5::ATOMIC_RENEW_TASK_BYTES
        } else if profile == AccountProfile::TasksV4 {
            crate::qualified_work_task::pq_lifecycle_v4::TASK_REGISTRATION_BYTES
        } else {
            554
        };
        if raw[6] as usize != expected.len()
            || !(COMMON_BYTES..=COMMON_BYTES + max_payload).contains(&body_len)
        {
            return Err(Error::Length);
        }
        let end = PREFIX_BYTES + body_len;
        let body = raw.get(PREFIX_BYTES..end).ok_or(Error::Length)?;
        let common = Common {
            context: ChainContext {
                network: bytes(body, 0)?,
                parameters: bytes(body, 32)?,
                genesis: bytes(body, 64)?,
            },
            account: bytes(body, 96)?,
            nonce: number(body, 128)?,
            expires_at: number(body, 136)?,
            max_fee: number(body, 144)?,
            generation: number(body, 152)?,
        };
        let payload = &body[COMMON_BYTES..];
        check(profile, &common, kind, payload)?;
        let mut pos = end;
        let mut witnesses = Vec::with_capacity(expected.len());
        let mut keys = Vec::with_capacity(expected.len());
        for &(role, carried) in expected {
            let descriptor = raw
                .get(pos..pos + WITNESS_DESCRIPTOR_BYTES)
                .ok_or(Error::Length)?;
            if descriptor[..4] != [role, 0x65, 0, 0] {
                return Err(Error::Encoding);
            }
            let length = u16::from_be_bytes(bytes(descriptor, 44)?) as usize;
            if length != if carried { ML_DSA_65_SPKI_BYTES } else { 0 } {
                return Err(Error::Key);
            }
            pos += WITNESS_DESCRIPTOR_BYTES;
            let key = raw.get(pos..pos + length).ok_or(Error::Length)?;
            pos += length;
            let frame = raw.get(pos..pos + TPQ1_SIGNED_BYTES).ok_or(Error::Length)?;
            pos += TPQ1_SIGNED_BYTES;
            let generation = number(descriptor, 4)?;
            let key_id = bytes(descriptor, 12)?;
            let spki = carried.then_some(key);
            keys.push(WitnessKey {
                role,
                generation,
                key_id,
                spki: spki.map(<[u8]>::to_vec),
            });
            witnesses.push(UnverifiedWitness {
                role,
                generation,
                key_id,
                spki,
                frame,
            });
        }
        if pos != raw.len() {
            return Err(Error::Length);
        }
        let core = signing_core_for_profile(profile, &common, kind, payload, &keys)?;
        for witness in &witnesses {
            preflight_unverified(
                witness.frame,
                &PqFrameExpectation {
                    purpose: witness.role,
                    network: common.context.network,
                    owner_context: owner_context_for_profile(profile, &common, kind, witness.role)?,
                    signer_key_id: witness.key_id,
                    owner_generation: witness.generation,
                    operation_sequence: common.nonce,
                    expires_at: common.expires_at,
                    now: 0,
                    payload: &core,
                },
            )
            .map_err(|_| Error::Frame)?;
        }
        Ok(Self {
            raw,
            profile,
            common,
            kind,
            payload,
            witnesses,
            core,
        })
    }
    pub fn raw(&self) -> &'a [u8] {
        self.raw
    }
    pub fn witnesses(&self) -> &[UnverifiedWitness<'a>] {
        &self.witnesses
    }
    pub fn core(&self) -> &[u8] {
        &self.core
    }
    pub fn statement_id(&self) -> [u8; 48] {
        Sha384::digest(&self.core).into()
    }
    pub fn wire_id(&self) -> [u8; 32] {
        let mut hash = Sha256::new();
        hash.update(self.profile.wire_domain());
        hash.update((self.raw.len() as u32).to_be_bytes());
        hash.update(self.raw);
        hash.finalize().into()
    }
}

// The original NPQ2 public entry points remain exact NPQ2-only wrappers.
pub fn signing_core(
    common: &Common,
    kind: u8,
    payload: &[u8],
    keys: &[WitnessKey],
) -> Result<Vec<u8>, Error> {
    signing_core_for_profile(AccountProfile::AccountsV2, common, kind, payload, keys)
}
pub fn owner_context(common: &Common, kind: u8, role: u8) -> Result<[u8; 32], Error> {
    owner_context_for_profile(AccountProfile::AccountsV2, common, kind, role)
}
pub fn signing_statement(
    common: &Common,
    kind: u8,
    payload: &[u8],
    keys: &[WitnessKey],
    index: usize,
) -> Result<[u8; TPQ1_UNSIGNED_BYTES], Error> {
    signing_statement_for_profile(
        AccountProfile::AccountsV2,
        common,
        kind,
        payload,
        keys,
        index,
    )
}
pub fn encode(
    common: &Common,
    kind: u8,
    payload: &[u8],
    keys: &[WitnessKey],
    frames: &[Vec<u8>],
) -> Result<Vec<u8>, Error> {
    encode_for_profile(
        AccountProfile::AccountsV2,
        common,
        kind,
        payload,
        keys,
        frames,
    )
}

#[cfg(test)]
mod tests;
