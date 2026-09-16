//! Explicit public-native candidate policy and chain-relative client clock.
//! This is deployment input; it neither activates production nor creates load.
use anyhow::{anyhow, ensure, Context, Result};
use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt},
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};
use trnm_application_tx_builder_v0::BuiltCanonicalTxV0;
use trnm_mempool::{AdmissionReject, CanonicalSignerId};
use trnm_native_execution_v0::AuthorizedSignerV0;
use trnm_poco_node::{
    CanonicalAdmissionContextResolverV0, CanonicalSignerIdentityResolverV0,
    NativeAdmissionProfileV1,
};

pub const NATIVE_CLIENT_PROFILE_V1: &str = "native-public-candidate-v1";
pub const MAX_PROFILE_BYTES_V1: u64 = 64 * 1024;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct NativeClientSignerV1 {
    pub signer_id: String,
    pub canonical_identity: String,
    pub signer_role: String,
    pub public_key_hex: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct NativeClientProfileV1 {
    pub schema: String,
    pub chain_id: String,
    pub wall_clock_epoch_ms: u64,
    pub signers: Vec<NativeClientSignerV1>,
    pub governance_signer_id: String,
    pub socket_basename: String,
    pub maximum_pending: usize,
    pub maximum_pending_bytes: usize,
    pub maximum_outer_bytes: usize,
    pub maximum_batch_transactions: usize,
    pub maximum_batch_bytes: usize,
    pub block_cadence_ms: u64,
    pub maximum_clock_skew_ms: u64,
    pub drain_timeout_ms: u64,
    pub production_activation: bool,
}

fn fixed_hex(value: &str) -> Result<[u8; 32]> {
    ensure!(
        value.len() == 64
            && value
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "profile hash/key must be lowercase 32-byte hex"
    );
    hex::decode(value)?
        .try_into()
        .map_err(|_| anyhow!("profile hash/key length"))
}
fn canonical_identity(id: &str) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"trnm.native-public.signer.v1\0");
    digest.update((id.len() as u64).to_be_bytes());
    digest.update(id.as_bytes());
    digest.finalize().into()
}
pub fn unix_now_ms_v1() -> Result<u64> {
    u64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis())
        .context("Unix clock exceeds u64")
}
impl NativeClientProfileV1 {
    pub fn canonical_bytes_v1(&self) -> Result<Vec<u8>> {
        Ok(serde_json::to_vec(self)?)
    }
    pub fn digest_v1(&self) -> Result<[u8; 32]> {
        Ok(Sha256::digest(self.canonical_bytes_v1()?).into())
    }
    pub fn validate_v1(&self, chain: &str, consensus_keys: &[[u8; 32]]) -> Result<()> {
        ensure!(
            self.schema == NATIVE_CLIENT_PROFILE_V1
                && self.chain_id == chain
                && !self.production_activation,
            "unsupported native client profile"
        );
        ensure!(
            self.wall_clock_epoch_ms > 0 && !self.signers.is_empty() && self.signers.len() <= 100,
            "native profile epoch/signer bounds"
        );
        ensure!(
            self.socket_basename.len() <= 48
                && self.socket_basename.ends_with(".sock")
                && self.socket_basename.bytes().all(|b| b.is_ascii_lowercase()
                    || b.is_ascii_digit()
                    || matches!(b, b'-' | b'.')),
            "native socket basename is not canonical"
        );
        ensure!(
            self.maximum_pending > 0
                && self.maximum_pending <= 256
                && self.maximum_pending_bytes > 0
                && self.maximum_pending_bytes <= 16 * 1024 * 1024
                && self.maximum_outer_bytes > 0
                && self.maximum_outer_bytes <= 256 * 1024
                && self.maximum_outer_bytes <= self.maximum_pending_bytes,
            "native admission limits outside candidate bounds"
        );
        ensure!(
            self.maximum_batch_transactions > 0
                && self.maximum_batch_transactions <= 64
                && self.maximum_batch_bytes >= self.maximum_outer_bytes + 8
                && self.maximum_batch_bytes <= 1024 * 1024,
            "native batch bounds"
        );
        ensure!(
            (250..=10_000).contains(&self.block_cadence_ms)
                && (1..=5_000).contains(&self.maximum_clock_skew_ms)
                && (1_000..=60_000).contains(&self.drain_timeout_ms),
            "native cadence/skew/drain bounds"
        );
        let mut identities = BTreeSet::new();
        let mut ids = BTreeSet::new();
        let mut keys = BTreeSet::new();
        for signer in &self.signers {
            let key = fixed_hex(&signer.public_key_hex)?;
            ensure!(
                !signer.signer_id.is_empty()
                    && signer.signer_id.len() <= 256
                    && signer.signer_id.trim() == signer.signer_id
                    && signer.signer_id.is_ascii(),
                "native signer ID bound"
            );
            ensure!(
                fixed_hex(&signer.canonical_identity)? == canonical_identity(&signer.signer_id)
                    && identities.insert(&signer.canonical_identity)
                    && ids.insert(&signer.signer_id)
                    && keys.insert(key)
                    && !consensus_keys.contains(&key),
                "duplicate/aliased native application identity or consensus key overlap"
            );
            AuthorizedSignerV0::new(
                signer.signer_id.clone(),
                signer.signer_role.clone(),
                signer.public_key_hex.clone(),
            )?;
        }
        ensure!(
            self.signers
                .iter()
                .any(|s| s.signer_id == self.governance_signer_id && s.signer_role == "operator"),
            "native governance signer missing operator authority"
        );
        Ok(())
    }
    pub fn load_v1(
        path: &Path,
        expected: [u8; 32],
        chain: &str,
        consensus_keys: &[[u8; 32]],
    ) -> Result<Self> {
        let metadata = fs::symlink_metadata(path)?;
        ensure!(
            metadata.is_file()
                && !metadata.file_type().is_symlink()
                && metadata.len() <= MAX_PROFILE_BYTES_V1,
            "native profile must be a bounded regular file"
        );
        let mut bytes = Vec::new();
        File::open(path)?
            .take(MAX_PROFILE_BYTES_V1 + 1)
            .read_to_end(&mut bytes)?;
        ensure!(
            bytes.len() as u64 <= MAX_PROFILE_BYTES_V1
                && <[u8; 32]>::from(Sha256::digest(&bytes)) == expected,
            "native profile manifest hash mismatch"
        );
        let profile: Self = serde_json::from_slice(&bytes)?;
        ensure!(
            profile.canonical_bytes_v1()? == bytes,
            "native profile must have exact canonical JSON bytes"
        );
        profile.validate_v1(chain, consensus_keys)?;
        Ok(profile)
    }
    pub fn authorized_signers_v1(&self) -> Result<Vec<AuthorizedSignerV0>> {
        self.signers
            .iter()
            .map(|s| {
                AuthorizedSignerV0::new(
                    s.signer_id.clone(),
                    s.signer_role.clone(),
                    s.public_key_hex.clone(),
                )
            })
            .collect()
    }
    pub fn admission_profile_v1(&self) -> Result<NativeAdmissionProfileV1> {
        Ok(NativeAdmissionProfileV1 {
            profile_digest: self.digest_v1()?,
            maximum_pending: self.maximum_pending,
            maximum_pending_bytes: self.maximum_pending_bytes,
            maximum_outer_bytes: self.maximum_outer_bytes,
        })
    }
    pub fn chain_now_ms_v1(&self) -> Result<u64> {
        unix_now_ms_v1()?
            .checked_sub(self.wall_clock_epoch_ms)
            .context("TIME_UNREADY: candidate epoch lies in the future")
    }
    pub fn proposal_timestamp_v1(&self, parent: u64, maximum_step: u64) -> Result<(u64, bool)> {
        let now = self.chain_now_ms_v1()?;
        ensure!(
            parent
                <= now
                    .checked_add(self.maximum_clock_skew_ms)
                    .context("clock skew overflow")?,
            "TIME_UNREADY: authenticated parent is ahead of local chain clock"
        );
        let timestamp = now
            .max(parent.checked_add(1).context("parent clock overflow")?)
            .min(
                parent
                    .checked_add(maximum_step)
                    .context("parent step overflow")?,
            );
        Ok((
            timestamp,
            now.saturating_sub(parent) <= self.maximum_clock_skew_ms,
        ))
    }
}

#[derive(Debug, Clone)]
pub struct NativeProfileSignerResolverV1(pub NativeClientProfileV1);
impl CanonicalSignerIdentityResolverV0 for NativeProfileSignerResolverV1 {
    fn resolve_canonical_signer_id_v0(
        &self,
        tx: &BuiltCanonicalTxV0,
    ) -> Result<CanonicalSignerId, AdmissionReject> {
        let envelope = tx.envelope();
        let signer = self
            .0
            .signers
            .iter()
            .find(|s| {
                s.signer_id == envelope.signer_id
                    && s.signer_role == envelope.signer_role
                    && s.public_key_hex == envelope.public_key_hex
            })
            .ok_or(AdmissionReject::CanonicalValidationFailed)?;
        CanonicalSignerId::from_bytes(
            fixed_hex(&signer.canonical_identity)
                .map_err(|_| AdmissionReject::CanonicalValidationFailed)?,
        )
    }
}
#[derive(Debug, Clone)]
pub struct NativeProfileClockV1(pub NativeClientProfileV1);
impl CanonicalAdmissionContextResolverV0 for NativeProfileClockV1 {
    fn chain_id_v0(&self) -> &str {
        &self.0.chain_id
    }
    fn now_unix_ms_v0(&self) -> u64 {
        self.0.chain_now_ms_v1().unwrap_or(0)
    }
}

/// Explicit isolated campaign generation. Fails on an occupied path; secret
/// bytes are written only to this owner-controlled directory and never returned.
pub fn generate_isolated_native_client_profile_v1(
    directory: &Path,
    chain_id: &str,
) -> Result<NativeClientProfileV1> {
    ensure!(
        directory.is_absolute() && !directory.exists(),
        "isolated client key namespace must be fresh and absolute"
    );
    let epoch = unix_now_ms_v1()?
        .checked_sub(3_000)
        .context("campaign epoch underflow")?;
    fs::DirBuilder::new().mode(0o700).create(directory)?;
    let mut signers = Vec::new();
    for (name, role) in [("operator", "operator"), ("client", "hepta")] {
        let id = format!("did:trnm:native-client:{name}");
        let mut seed = [0u8; 32];
        getrandom::getrandom(&mut seed).map_err(|_| anyhow!("OS entropy unavailable"))?;
        let key = SigningKey::from_bytes(&seed);
        let mut output = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(directory.join(format!("{name}.key")))?;
        output.write_all(hex::encode(seed).as_bytes())?;
        output.sync_all()?;
        signers.push(NativeClientSignerV1 {
            canonical_identity: hex::encode(canonical_identity(&id)),
            signer_id: id,
            signer_role: role.to_owned(),
            public_key_hex: hex::encode(key.verifying_key().to_bytes()),
        });
    }
    let profile = NativeClientProfileV1 {
        schema: NATIVE_CLIENT_PROFILE_V1.to_owned(),
        chain_id: chain_id.to_owned(),
        wall_clock_epoch_ms: epoch,
        governance_signer_id: signers[0].signer_id.clone(),
        signers,
        socket_basename: "native-client.sock".to_owned(),
        maximum_pending: 256,
        maximum_pending_bytes: 16 * 1024 * 1024,
        maximum_outer_bytes: 256 * 1024,
        maximum_batch_transactions: 64,
        maximum_batch_bytes: 1024 * 1024,
        block_cadence_ms: 250,
        maximum_clock_skew_ms: 5_000,
        drain_timeout_ms: 30_000,
        production_activation: false,
    };
    profile.validate_v1(chain_id, &[])?;
    let mut public = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(directory.join("native-client-profile.json"))?;
    public.write_all(&profile.canonical_bytes_v1()?)?;
    public.sync_all()?;
    File::open(directory)?.sync_all()?;
    ensure!(
        fs::metadata(directory)?.permissions().mode() & 0o777 == 0o700,
        "candidate key directory permissions changed"
    );
    Ok(profile)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn isolated_profile_retains_owner_keys_and_exact_public_pin_v1() {
        let temp = tempfile::tempdir().unwrap();
        let directory = temp.path().join("isolated");
        let profile =
            generate_isolated_native_client_profile_v1(&directory, "trnm-client-test").unwrap();
        let loaded = NativeClientProfileV1::load_v1(
            &directory.join("native-client-profile.json"),
            profile.digest_v1().unwrap(),
            "trnm-client-test",
            &[],
        )
        .unwrap();
        assert_eq!(profile, loaded);
        assert_eq!(
            fs::metadata(&directory).unwrap().permissions().mode() & 0o777,
            0o700
        );
        for name in ["operator", "client"] {
            let path = directory.join(format!("{name}.key"));
            assert_eq!(
                fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
            let secret = fs::read_to_string(path).unwrap();
            assert!(!String::from_utf8(profile.canonical_bytes_v1().unwrap())
                .unwrap()
                .contains(&secret));
        }
        assert!(
            generate_isolated_native_client_profile_v1(&directory, "trnm-client-test").is_err()
        );
        assert!(NativeClientProfileV1::load_v1(
            &directory.join("native-client-profile.json"),
            [7; 32],
            "trnm-client-test",
            &[]
        )
        .is_err());
        let mut changed = profile.clone();
        changed.signers[1].canonical_identity = changed.signers[0].canonical_identity.clone();
        assert!(changed.validate_v1("trnm-client-test", &[]).is_err());
        let key = fixed_hex(&profile.signers[0].public_key_hex).unwrap();
        assert!(profile.validate_v1("trnm-client-test", &[key]).is_err());
        changed = profile.clone();
        changed.maximum_pending = 257;
        assert!(changed.validate_v1("trnm-client-test", &[]).is_err());
        changed = profile;
        changed.wall_clock_epoch_ms = unix_now_ms_v1().unwrap() + 60_000;
        assert!(changed.chain_now_ms_v1().is_err());
    }
}
