//! Exact typed M15 proofs. Candidate input cannot choose an observation time.
use super::frontier::{invalid, Digest32, Result};
use serde::de::{self, MapAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use std::collections::BTreeMap;
use std::io;
use trnm_protocol::pq_frame::ML_DSA_65_SIGNATURE_BYTES;
use trnm_release_bundle::pq_release::{
    PqReleaseMetadataV1, PqReleaseRoleKeysV1, PqReleaseRoleV1, PqReleaseRootV1,
    PqReleaseSignatureV1, MAX_RELEASE_KEYS_V1,
};

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PublicKey {
    pub key_id: Digest32,
    pub spki: Vec<u8>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Keys {
    pub threshold: u16,
    pub keys: Vec<PublicKey>,
}

impl Keys {
    fn kernel(&self) -> Result<PqReleaseRoleKeysV1> {
        if self.keys.is_empty() || self.keys.len() > MAX_RELEASE_KEYS_V1 {
            return Err(invalid("M15 complete root key bound"));
        }
        let mut keys = BTreeMap::new();
        let mut previous = None;
        for key in &self.keys {
            if previous.is_some_and(|p| p >= key.key_id) {
                return Err(invalid("M15 root key order or duplicate"));
            }
            previous = Some(key.key_id);
            keys.insert(key.key_id, key.spki.clone());
        }
        Ok(PqReleaseRoleKeysV1 {
            threshold: self.threshold,
            keys,
        })
    }
}

pub(super) fn role(value: u8) -> Result<PqReleaseRoleV1> {
    match value {
        1 => Ok(PqReleaseRoleV1::NodeSoftware),
        2 => Ok(PqReleaseRoleV1::ProtocolConfiguration),
        3 => Ok(PqReleaseRoleV1::CellManifest),
        4 => Ok(PqReleaseRoleV1::CellActivation),
        _ => Err(invalid("unknown M15 role")),
    }
}

// JSON emits integer map keys as strings. An internally tagged Publication or
// Record buffers them through Serde's ContentDeserializer, which cannot apply
// serde_json's usual string-to-integer map-key conversion. Decode the existing
// canonical v1 names explicitly; never round-trip through Value (which would
// discard duplicate keys). Serialization and signed/root bytes stay unchanged.
fn deserialize_roles<'de, D>(deserializer: D) -> std::result::Result<BTreeMap<u8, Keys>, D::Error>
where
    D: Deserializer<'de>,
{
    struct Roles;
    impl<'de> Visitor<'de> for Roles {
        type Value = BTreeMap<u8, Keys>;

        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("canonical M15 role names 1, 2, 3 and 4")
        }

        fn visit_map<A>(self, mut map: A) -> std::result::Result<Self::Value, A::Error>
        where
            A: MapAccess<'de>,
        {
            let mut roles = BTreeMap::new();
            while let Some(name) = map.next_key::<String>()? {
                let id = match name.as_str() {
                    "1" => 1,
                    "2" => 2,
                    "3" => 3,
                    "4" => 4,
                    _ => return Err(de::Error::custom("M15 noncanonical or unknown role name")),
                };
                if roles.contains_key(&id) {
                    return Err(de::Error::custom("M15 duplicate role name"));
                }
                roles.insert(id, map.next_value::<Keys>()?);
            }
            Ok(roles)
        }
    }
    deserializer.deserialize_map(Roles)
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Root {
    pub schema_version: u32,
    pub network_id: Digest32,
    pub generation: u64,
    pub expires_at: u64,
    pub previous_root_digest: Digest32,
    pub offline_root: Keys,
    #[serde(deserialize_with = "deserialize_roles")]
    pub roles: BTreeMap<u8, Keys>,
}

impl Root {
    pub fn kernel(&self) -> Result<PqReleaseRootV1> {
        if self.schema_version != 1 || self.roles.len() != 4 {
            return Err(invalid("M15 complete root schema and four roles required"));
        }
        let mut roles = BTreeMap::new();
        for (id, keys) in &self.roles {
            roles.insert(role(*id)?, keys.kernel()?);
        }
        let root = PqReleaseRootV1 {
            network_id: self.network_id,
            generation: self.generation,
            expires_at: self.expires_at,
            previous_root_digest: self.previous_root_digest,
            offline_root: self.offline_root.kernel()?,
            roles,
        };
        // This validates every key, quorum and cross-role separation. It is
        // mathematical/root identity validation, not current-use permission.
        root.digest().map_err(io::Error::other)?;
        Ok(root)
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Signature {
    pub key_id: Digest32,
    pub signature: Vec<u8>,
}

pub(super) fn signatures(values: &[Signature]) -> Result<Vec<PqReleaseSignatureV1>> {
    if values.is_empty()
        || values.len() > MAX_RELEASE_KEYS_V1
        || values
            .iter()
            .any(|v| v.signature.len() != ML_DSA_65_SIGNATURE_BYTES)
    {
        return Err(invalid("M15 signature set bound"));
    }
    Ok(values
        .iter()
        .map(|v| PqReleaseSignatureV1 {
            key_id: v.key_id,
            signature: v.signature.clone(),
        })
        .collect())
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Metadata {
    pub network_id: Digest32,
    pub role: u8,
    pub root_generation: u64,
    pub role_version: u64,
    pub expires_at: u64,
    pub expected_checkpoint: Digest32,
    pub previous_content: Option<Digest32>,
    pub content: Digest32,
    pub approved_content_rollback: bool,
}

impl Metadata {
    pub fn kernel(&self) -> Result<PqReleaseMetadataV1> {
        Ok(PqReleaseMetadataV1 {
            network_id: self.network_id,
            role: role(self.role)?,
            root_generation: self.root_generation,
            role_version: self.role_version,
            expires_at: self.expires_at,
            expected_checkpoint: self.expected_checkpoint,
            previous_content: self.previous_content,
            content: self.content,
            approved_content_rollback: self.approved_content_rollback,
        })
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "kind", deny_unknown_fields)]
pub(super) enum Publication {
    RootRotation {
        root: Root,
        old_signatures: Vec<Signature>,
        new_signatures: Vec<Signature>,
    },
    Release {
        metadata: Metadata,
        signatures: Vec<Signature>,
        bundle: Option<Box<super::bundle_wire::Bundle>>,
        configuration: Option<Box<super::execution_wire::ConfigurationPolicy>>,
    },
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ObservedPublication {
    pub schema_version: u32,
    pub publication: Publication,
    pub observed_at: u64,
    pub resulting_checkpoint: Digest32,
}
