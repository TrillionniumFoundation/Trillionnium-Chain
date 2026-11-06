//! Separate UID/key/storage ownership for the independent M15 frontier service.
use super::frontier::{hash, invalid, Digest32, Frontier, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use trnm_crypto_primitives::pq_auth::{PqNativeSigningKey, PqNativeVerifier};

const PATH: &str = "/etc/trillionnium/m15-frontier-service-v1.json";
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Clock {
    pub socket: PathBuf,
    pub server_key_id: Digest32,
    pub server_spki_hex: String,
    pub requester_seed: PathBuf,
    pub requester_key_id: Digest32,
    pub binding: Digest32,
}
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Configuration {
    pub schema_version: u32,
    pub profile: String,
    pub service_uid: u32,
    pub owner_uid: u32,
    pub directory: PathBuf,
    pub socket: PathBuf,
    pub namespace: Digest32,
    pub initial_root_digest: Digest32,
    pub clock_contract: super::clock_contract::Contract,
    pub owner_binding: Digest32,
    pub owner_key_id: Digest32,
    pub owner_spki_hex: String,
    pub signer_seed: PathBuf,
    pub signer_key_id: Digest32,
    pub clock: Clock,
    // These are independent pre-stop pins, not values inferred from this DB.
    // Reopen of a newer/older database needs explicit external reconciliation.
    pub expected_frontier: Option<Frontier>,
    pub expected_time_floor: u64,
}
pub(super) fn verifier(spki: &str, key_id: Digest32) -> Result<PqNativeVerifier> {
    let bytes = hex::decode(spki).map_err(std::io::Error::other)?;
    if hex::encode(&bytes) != spki {
        return Err(invalid("M15 service public-key encoding"));
    }
    PqNativeVerifier::from_pinned_spki(&bytes, key_id).map_err(std::io::Error::other)
}
impl Configuration {
    pub fn load() -> Result<Self> {
        let value: Self = super::codec::decode(&configuration_bytes()?, 65536)?;
        value.validate()?;
        Ok(value)
    }
    pub fn validate(&self) -> Result<()> {
        self.clock_contract.validate()?;
        // The frontier principal also signs its clock requests in REQUEST's
        // distinct domain. There is no fourth private key outside the owner's
        // three service/release-role separation commitment.
        let keys = [
            self.owner_key_id,
            self.signer_key_id,
            self.clock.server_key_id,
        ];
        if self.schema_version != 1
            || self.profile != "trnm-m15-independent-frontier-v1"
            || self.namespace == [0; 32]
            || self.initial_root_digest == [0; 32]
            || self.owner_binding == [0; 32]
            || self.clock.binding == [0; 32]
            || self.service_uid == 0
            || self.owner_uid == 0
            || self.service_uid == self.owner_uid
            || self.clock.requester_key_id != self.signer_key_id
            || self.clock.requester_seed != self.signer_seed
            || self.service_uid != rustix::process::geteuid().as_raw()
            || !self.directory.is_absolute()
            || !self.socket.is_absolute()
            || !self.clock.socket.is_absolute()
            || keys.contains(&[0; 32])
            || keys.iter().collect::<std::collections::BTreeSet<_>>().len() != 3
        {
            return Err(invalid("M15 independent service identity/configuration"));
        }
        let expected_binding = hash(
            b"TRNM/M15/ProtectedOwner/Binding/v1\0",
            &super::trust_wire::canonical(&(
                self.namespace,
                self.initial_root_digest,
                self.clock.server_key_id,
                self.signer_key_id,
                self.owner_key_id,
                &self.clock_contract,
            ))?,
        );
        if self.owner_binding != expected_binding {
            return Err(invalid("M15 owner/service clock-root contract binding"));
        }
        verifier(&self.owner_spki_hex, self.owner_key_id)?;
        verifier(&self.clock.server_spki_hex, self.clock.server_key_id)?;
        if let Some(frontier) = &self.expected_frontier {
            frontier.validate(self.namespace)?;
        }
        Ok(())
    }
    pub fn revalidate(&self) -> Result<()> {
        if &Self::load()? != self {
            return Err(invalid("M15 service deployment changed"));
        }
        Ok(())
    }
    pub fn core_digest(&self) -> Result<Digest32> {
        Ok(hash(
            b"TRNM/M15/IndependentServiceBinding/v1\0",
            &super::codec::encode(
                &(
                    self.schema_version,
                    &self.profile,
                    self.service_uid,
                    self.owner_uid,
                    &self.directory,
                    &self.socket,
                    self.namespace,
                    self.owner_binding,
                    self.owner_key_id,
                    &self.owner_spki_hex,
                    &self.signer_seed,
                    self.signer_key_id,
                    &self.clock,
                    self.initial_root_digest,
                    &self.clock_contract,
                ),
                65536,
            )?,
        ))
    }
    pub fn signer(&self) -> Result<PqNativeSigningKey> {
        PqNativeSigningKey::from_owned_seed(
            super::protected::read_seed(&self.signer_seed)?,
            self.signer_key_id,
        )
        .map_err(std::io::Error::other)
    }
}

fn configuration_bytes() -> Result<Vec<u8>> {
    // Native component tests substitute only provisioning custody/path. The
    // product cannot select this route through a flag, environment or config.
    #[cfg(test)]
    if let Some(path) = super::service_faults::provisioning() {
        return Ok(super::protected::read_private(&path, 65536)?.to_vec());
    }
    super::system_root::read(Path::new(PATH))
}
