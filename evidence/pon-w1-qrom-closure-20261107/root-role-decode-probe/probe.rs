use serde::{Serialize, Deserialize};
use std::collections::BTreeMap;
type Digest32 = [u8;32];
mod old {
use super::*;
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

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Root {
    pub schema_version: u32,
    pub network_id: Digest32,
    pub generation: u64,
    pub expires_at: u64,
    pub previous_root_digest: Digest32,
    pub offline_root: Keys,
    pub roles: BTreeMap<u8, Keys>,
}


#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "kind", deny_unknown_fields)]
pub(super) enum Publication { RootRotation { root: Root } }
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ObservedPublication { pub publication: Publication }
#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "record", deny_unknown_fields)]
pub(super) enum Record { Publication(ObservedPublication) }
}
mod fixed {
use super::*;
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

fn deserialize_roles<'de, D>(deserializer: D) -> std::result::Result<BTreeMap<u8, Keys>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    // JSON writes these integer map keys as strings. Internally tagged
    // Publication/Record buffer them before Root is decoded, so serde_json's
    // integer map-key conversion is no longer available. Read the same canonical
    // strings explicitly without changing serialization or authority checks.
    struct RolesVisitor;
    impl<'de> serde::de::Visitor<'de> for RolesVisitor {
        type Value = BTreeMap<u8, Keys>;

        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("unique canonical decimal u8 role keys")
        }

        fn visit_map<A>(self, mut map: A) -> std::result::Result<Self::Value, A::Error>
        where
            A: serde::de::MapAccess<'de>,
        {
            let mut roles = BTreeMap::new();
            while let Some(key) = map.next_key::<String>()? {
                let id = key.parse::<u8>().map_err(serde::de::Error::custom)?;
                if key != id.to_string() {
                    return Err(serde::de::Error::custom("M15 noncanonical root role key"));
                }
                if roles.contains_key(&id) {
                    return Err(serde::de::Error::custom("M15 duplicate root role key"));
                }
                roles.insert(id, map.next_value()?);
            }
            Ok(roles)
        }
    }
    deserializer.deserialize_map(RolesVisitor)
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


#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "kind", deny_unknown_fields)]
pub(super) enum Publication { RootRotation { root: Root } }
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ObservedPublication { pub publication: Publication }
#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "record", deny_unknown_fields)]
pub(super) enum Record { Publication(ObservedPublication) }
}

fn main() {
    let keys = old::Keys { threshold:1, keys:vec![] };
    let root = old::Root { schema_version:1, network_id:[19;32], generation:2,
        expires_at:100, previous_root_digest:[7;32], offline_root:keys.clone(),
        roles:(1..=4).map(|id| (id,keys.clone())).collect() };
    let root_raw=serde_json::to_string(&root).unwrap();
    assert!(serde_json::from_str::<old::Root>(&root_raw).is_ok());
    let publication=old::Publication::RootRotation { root };
    let publication_raw=serde_json::to_string(&publication).unwrap();
    let publication_error=serde_json::from_str::<old::Publication>(&publication_raw).err().unwrap().to_string();
    let record=old::Record::Publication(old::ObservedPublication { publication });
    let raw=serde_json::to_string(&record).unwrap();
    let record_error=serde_json::from_str::<old::Record>(&raw).err().unwrap().to_string();
    assert!(record_error.contains("invalid type: string \"1\", expected u8"));
    let parsed=serde_json::from_str::<fixed::Record>(&raw).unwrap();
    assert_eq!(serde_json::to_string(&parsed).unwrap(),raw);
    let mut rejection_count=0;
    for key in ["", "01", "+1", " 1", "1 ", "1.0", "1e0", "-1", "256", "18446744073709551616"] {
        let changed=raw.replacen(r#""roles":{"1":"#,&format!(r#""roles":{{"{key}":"#),1);
        assert_ne!(changed,raw);
        assert!(serde_json::from_str::<fixed::Record>(&changed).is_err());
        rejection_count+=1;
    }
    let duplicated=raw.replacen(r#""roles":{"#,
        r#""roles":{"1":{"threshold":1,"keys":[]},"#,1);
    assert!(serde_json::from_str::<fixed::Record>(&duplicated).is_err());
    let escaped=raw.replacen(r#""roles":{"1":"#,r#""roles":{"\u0031":"#,1);
    let escaped_decoded=serde_json::from_str::<fixed::Record>(&escaped).unwrap();
    assert_ne!(serde_json::to_string(&escaped_decoded).unwrap(),escaped);
    println!("{}",serde_json::json!({
        "scope":"Reduced Serde mechanism probe using extracted exact old/new Root, Keys, PublicKey declarations and changed role decoder; not production proof/authority or full regression execution",
        "old_direct_root_decode":true,
        "old_nested_publication_error":publication_error,
        "old_nested_record_error":record_error,
        "new_record_decode_and_bytes_equal_old_encoding":true,
        "noncanonical_or_out_of_range_key_rejections":rejection_count,
        "duplicate_role_key_rejected":true,
        "escaped_alias_requires_unchanged_codec_byte_comparison":true
    }));
}
