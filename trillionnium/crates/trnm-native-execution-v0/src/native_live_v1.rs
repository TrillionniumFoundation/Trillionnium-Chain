//! Bounded current-live native state codec and inert JMT root recomputation.
//!
//! This module deliberately excludes historical nodes, replay sets and signer
//! state. A successful result is a root fact for proof-bound staging only.

use std::collections::BTreeMap;

use anyhow::{ensure, Context, Result};
use jmt::{
    storage::{LeafNode, Node, NodeKey, TreeReader},
    KeyHash, RootHash, Sha256Jmt,
};
use sha2::{Digest, Sha256};
use trnm_consensus_crypto::validate_validator_set_strict_ed25519_v0;
use trnm_consensus_types::{BlockHeader, BlockKind, ConsensusParametersV0, ValidatorSet};

pub const NATIVE_CURRENT_LIVE_CODEC_VERSION_V1: u16 = 1;
pub const MAX_NATIVE_CURRENT_LIVE_BYTES_V1: usize = 256 * 1024 * 1024;
pub const NATIVE_CURRENT_LIVE_MAX_ENTRIES_V1: usize = 1_000_000;
pub const NATIVE_CURRENT_LIVE_MAX_KEY_BYTES_V1: usize = 64 * 1024;
pub const NATIVE_CURRENT_LIVE_MAX_VALUE_BYTES_V1: usize = 16 * 1024 * 1024;
pub const NATIVE_CURRENT_LIVE_MAX_CHUNK_BYTES_V1: usize = 1024 * 1024;
pub const NATIVE_CURRENT_LIVE_MAX_CHUNKS_V1: usize = 256;
const MAGIC_V1: &[u8; 13] = b"TRNM-NLIVE-V1";
const SCHEMA_TEXT_V1: &[u8] = b"trnm.native-current-live.v1|TRNM-NLIVE-V1|u16be-u64be-h32-h32-u32be|u32be-key-u32be-value|jmt-sha256|authenticated-state-v4";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeCurrentLiveEntryV1 {
    pub key: Vec<u8>,
    pub value: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeCurrentLiveExportV1 {
    pub application_version: u64,
    pub state_root: [u8; 32],
    pub schema_digest: [u8; 32],
    pub entries: Vec<NativeCurrentLiveEntryV1>,
}

pub fn native_current_live_schema_digest_v1() -> [u8; 32] {
    Sha256::digest(SCHEMA_TEXT_V1).into()
}

fn checked_total(total: &mut usize, add: usize) -> Result<()> {
    *total = total
        .checked_add(add)
        .context("native live byte overflow")?;
    ensure!(
        *total <= MAX_NATIVE_CURRENT_LIVE_BYTES_V1,
        "native live export exceeds byte bound"
    );
    Ok(())
}

impl NativeCurrentLiveExportV1 {
    pub fn encode(&self) -> Result<Vec<u8>> {
        ensure!(
            self.schema_digest == native_current_live_schema_digest_v1(),
            "native live schema digest"
        );
        ensure!(
            self.entries.len() <= NATIVE_CURRENT_LIVE_MAX_ENTRIES_V1,
            "native live entry bound"
        );
        ensure!(
            self.entries
                .windows(2)
                .all(|pair| pair[0].key < pair[1].key),
            "native live key ordering"
        );
        let mut out = Vec::new();
        let mut total = 0usize;
        out.extend_from_slice(MAGIC_V1);
        out.extend_from_slice(&NATIVE_CURRENT_LIVE_CODEC_VERSION_V1.to_be_bytes());
        out.extend_from_slice(&self.application_version.to_be_bytes());
        out.extend_from_slice(&self.state_root);
        out.extend_from_slice(&self.schema_digest);
        out.extend_from_slice(&(self.entries.len() as u32).to_be_bytes());
        checked_total(&mut total, out.len())?;
        for entry in &self.entries {
            ensure!(
                !entry.key.is_empty() && entry.key.len() <= NATIVE_CURRENT_LIVE_MAX_KEY_BYTES_V1,
                "native live key bound"
            );
            ensure!(
                !entry.value.is_empty()
                    && entry.value.len() <= NATIVE_CURRENT_LIVE_MAX_VALUE_BYTES_V1,
                "native live value bound"
            );
            checked_total(
                &mut total,
                8usize
                    .checked_add(entry.key.len())
                    .and_then(|n| n.checked_add(entry.value.len()))
                    .context("native live entry size overflow")?,
            )?;
            out.extend_from_slice(&(entry.key.len() as u32).to_be_bytes());
            out.extend_from_slice(&entry.key);
            out.extend_from_slice(&(entry.value.len() as u32).to_be_bytes());
            out.extend_from_slice(&entry.value);
        }
        ensure!(
            out.len() <= MAX_NATIVE_CURRENT_LIVE_BYTES_V1,
            "native live encoded bound"
        );
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        ensure!(
            bytes.len() <= MAX_NATIVE_CURRENT_LIVE_BYTES_V1,
            "native live encoded bound"
        );
        let mut cursor = 0usize;
        let take = |cursor: &mut usize, count: usize| -> Result<&[u8]> {
            let end = cursor
                .checked_add(count)
                .context("native live length overflow")?;
            ensure!(end <= bytes.len(), "native live truncated");
            let part = &bytes[*cursor..end];
            *cursor = end;
            Ok(part)
        };
        ensure!(
            take(&mut cursor, MAGIC_V1.len())? == MAGIC_V1,
            "native live magic"
        );
        ensure!(
            u16::from_be_bytes(take(&mut cursor, 2)?.try_into()?)
                == NATIVE_CURRENT_LIVE_CODEC_VERSION_V1,
            "native live codec version"
        );
        let application_version = u64::from_be_bytes(take(&mut cursor, 8)?.try_into()?);
        let state_root: [u8; 32] = take(&mut cursor, 32)?.try_into()?;
        let schema_digest: [u8; 32] = take(&mut cursor, 32)?.try_into()?;
        ensure!(
            schema_digest == native_current_live_schema_digest_v1(),
            "native live schema digest"
        );
        let count = u32::from_be_bytes(take(&mut cursor, 4)?.try_into()?) as usize;
        ensure!(
            count <= NATIVE_CURRENT_LIVE_MAX_ENTRIES_V1,
            "native live entry bound"
        );
        ensure!(
            count <= (bytes.len().saturating_sub(cursor) / 10),
            "native live entry framing bound"
        );
        let mut entries = Vec::with_capacity(count);
        let mut previous: Option<Vec<u8>> = None;
        for _ in 0..count {
            let key_len = u32::from_be_bytes(take(&mut cursor, 4)?.try_into()?) as usize;
            ensure!(
                (1..=NATIVE_CURRENT_LIVE_MAX_KEY_BYTES_V1).contains(&key_len),
                "native live key bound"
            );
            let key = take(&mut cursor, key_len)?.to_vec();
            if let Some(previous) = &previous {
                ensure!(
                    previous.as_slice() < key.as_slice(),
                    "native live key ordering"
                );
            }
            let value_len = u32::from_be_bytes(take(&mut cursor, 4)?.try_into()?) as usize;
            ensure!(
                (1..=NATIVE_CURRENT_LIVE_MAX_VALUE_BYTES_V1).contains(&value_len),
                "native live value bound"
            );
            let value = take(&mut cursor, value_len)?.to_vec();
            previous = Some(key.clone());
            entries.push(NativeCurrentLiveEntryV1 { key, value });
        }
        ensure!(cursor == bytes.len(), "native live trailing bytes");
        Ok(Self {
            application_version,
            state_root,
            schema_digest,
            entries,
        })
    }
}

struct EmptyTreeReader;
impl TreeReader for EmptyTreeReader {
    fn get_node_option(&self, _node_key: &NodeKey) -> anyhow::Result<Option<Node>> {
        Ok(None)
    }
    fn get_value_option(
        &self,
        _max_version: jmt::Version,
        _key_hash: KeyHash,
    ) -> anyhow::Result<Option<Vec<u8>>> {
        Ok(None)
    }
    fn get_rightmost_leaf(&self) -> anyhow::Result<Option<(NodeKey, LeafNode)>> {
        Ok(None)
    }
}

/// Recompute the actual native root and validate its application projection.
/// The header/context inputs are inert; only M15 binds this result to M13's
/// independently verified trust path. No execution-ready store is returned.
pub fn recompute_native_current_live_v1(
    encoded: &[u8],
    terminal_header: &BlockHeader,
    terminal_set: &ValidatorSet,
    terminal_parameters: &ConsensusParametersV0,
) -> Result<[u8; 32]> {
    let export = NativeCurrentLiveExportV1::decode(encoded)?;
    ensure!(
        matches!(
            terminal_header.block_kind(),
            BlockKind::Regular | BlockKind::EpochCheckpoint | BlockKind::EpochHandoff
        ),
        "native live terminal header is not an application block"
    );
    ensure!(
        export.application_version == terminal_header.height().get(),
        "native live height"
    );
    ensure!(
        export.state_root == *terminal_header.state_root().as_bytes(),
        "native live terminal root"
    );
    ensure!(
        terminal_header.genesis_hash() == terminal_set.genesis_hash()
            && terminal_header.chain_id() == terminal_set.chain_id()
            && terminal_header.epoch() == terminal_set.epoch()
            && terminal_header.validator_set_id() == terminal_set.id()
            && terminal_header.consensus_parameters_hash() == terminal_parameters.hash(),
        "native live terminal context"
    );
    terminal_set
        .validate_against_parameters(terminal_parameters)
        .map_err(|error| anyhow::anyhow!("native live validator parameters: {error:?}"))?;
    validate_validator_set_strict_ed25519_v0(terminal_set)
        .map_err(|error| anyhow::anyhow!("native live validator keys: {error:?}"))?;
    validate_live_semantics(&export, terminal_header, terminal_set)?;
    let mut values = BTreeMap::new();
    for entry in &export.entries {
        let key_hash = KeyHash::with::<Sha256>(&entry.key);
        ensure!(
            values.insert(key_hash, Some(entry.value.clone())).is_none(),
            "native live key collision"
        );
    }
    let (root, _) = Sha256Jmt::new(&EmptyTreeReader).put_value_set(values, 0)?;
    ensure!(
        root == RootHash(export.state_root),
        "native live rebuilt root"
    );
    Ok(root.0)
}

const STATE_KEY_PREFIX_V1: &[u8] = b"trnm/authenticated-state/v4\0";

fn validate_live_semantics(
    export: &NativeCurrentLiveExportV1,
    terminal_header: &BlockHeader,
    terminal_set: &ValidatorSet,
) -> Result<()> {
    let mut live = BTreeMap::new();
    for entry in &export.entries {
        let key = entry.key.as_slice();
        ensure!(
            key.starts_with(STATE_KEY_PREFIX_V1) && key.len() >= STATE_KEY_PREFIX_V1.len() + 3,
            "native live key is outside authenticated state"
        );
        let namespace = key[STATE_KEY_PREFIX_V1.len()];
        match namespace {
            1 => {
                let record = crate::store::AuthenticatedObjectRecordV0::decode(&entry.value)
                    .context("decode native object record")?;
                ensure!(
                    record.object_version() <= export.application_version,
                    "native object record is ahead of state head"
                );
                decode_single_component_key(key, 1)?;
            }
            4 => ensure!(
                key == crate::auth_tree::validator_state_key()?.as_slice(),
                "native lifecycle key is not current"
            ),
            8 => ensure!(
                crate::poco_snapshot::decode_poco_snapshot_physical_key_v0_exact(key)?.is_some(),
                "native PoCO key framing"
            ),
            _ => anyhow::bail!("native live contains unknown state namespace"),
        }
        ensure!(
            live.insert(entry.key.clone(), entry.value.clone())
                .is_none(),
            "duplicate native live key"
        );
    }
    let lifecycle =
        crate::complete::load_validator_lifecycle_from_live_v0(&live, export.application_version)?;
    crate::complete::validate_application_validator_projection_v0(
        terminal_set,
        &lifecycle.active_validators,
    )?;
    ensure!(
        terminal_header.chain_id().as_bytes() == lifecycle.chain_id.as_bytes(),
        "native lifecycle chain id differs from terminal"
    );
    let mut poco_live = live;
    crate::poco_transition::take_and_validate_production_poco_projection_v0(
        export.application_version,
        &mut poco_live,
    )?;
    Ok(())
}

fn decode_single_component_key(key: &[u8], expected_namespace: u8) -> Result<&[u8]> {
    ensure!(key.starts_with(STATE_KEY_PREFIX_V1), "state key prefix");
    let mut cursor = STATE_KEY_PREFIX_V1.len();
    ensure!(
        key.get(cursor) == Some(&expected_namespace),
        "state key namespace"
    );
    cursor += 1;
    ensure!(key.len() >= cursor + 2, "state key component count");
    let count = u16::from_be_bytes(key[cursor..cursor + 2].try_into()?) as usize;
    cursor += 2;
    ensure!(
        count == 1 && key.len() >= cursor + 4,
        "state key component count"
    );
    let length = u32::from_be_bytes(key[cursor..cursor + 4].try_into()?) as usize;
    cursor += 4;
    let end = cursor
        .checked_add(length)
        .context("state key length overflow")?;
    ensure!(
        length > 0 && end == key.len(),
        "state key component framing"
    );
    Ok(&key[cursor..end])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn export(entries: Vec<NativeCurrentLiveEntryV1>) -> NativeCurrentLiveExportV1 {
        NativeCurrentLiveExportV1 {
            application_version: 7,
            state_root: [9; 32],
            schema_digest: native_current_live_schema_digest_v1(),
            entries,
        }
    }

    #[test]
    fn native_live_codec_round_trips_canonical_sorted_leaves() {
        let bytes = export(vec![
            NativeCurrentLiveEntryV1 {
                key: b"a".to_vec(),
                value: b"one".to_vec(),
            },
            NativeCurrentLiveEntryV1 {
                key: b"b".to_vec(),
                value: b"two".to_vec(),
            },
        ])
        .encode()
        .unwrap();
        assert_eq!(
            NativeCurrentLiveExportV1::decode(&bytes).unwrap(),
            export(vec![
                NativeCurrentLiveEntryV1 {
                    key: b"a".to_vec(),
                    value: b"one".to_vec(),
                },
                NativeCurrentLiveEntryV1 {
                    key: b"b".to_vec(),
                    value: b"two".to_vec(),
                },
            ])
        );
    }

    #[test]
    fn native_live_codec_rejects_truncation_trailing_and_order_mutation() {
        let encoded = export(vec![NativeCurrentLiveEntryV1 {
            key: b"a".to_vec(),
            value: b"one".to_vec(),
        }])
        .encode()
        .unwrap();
        assert!(NativeCurrentLiveExportV1::decode(&encoded[..encoded.len() - 1]).is_err());
        let mut trailing = encoded.clone();
        trailing.push(0);
        assert!(NativeCurrentLiveExportV1::decode(&trailing).is_err());
        let mut reordered = export(vec![
            NativeCurrentLiveEntryV1 {
                key: b"b".to_vec(),
                value: b"two".to_vec(),
            },
            NativeCurrentLiveEntryV1 {
                key: b"a".to_vec(),
                value: b"one".to_vec(),
            },
        ]);
        assert!(reordered.encode().is_err());
        reordered.schema_digest = [0; 32];
        assert!(reordered.encode().is_err());
    }

    #[test]
    fn native_live_codec_rejects_empty_leaf_and_wrong_schema() {
        assert!(export(vec![NativeCurrentLiveEntryV1 {
            key: Vec::new(),
            value: b"value".to_vec(),
        }])
        .encode()
        .is_err());
        assert!(export(vec![NativeCurrentLiveEntryV1 {
            key: b"key".to_vec(),
            value: Vec::new(),
        }])
        .encode()
        .is_err());
        let mut bytes = export(vec![NativeCurrentLiveEntryV1 {
            key: b"key".to_vec(),
            value: b"value".to_vec(),
        }])
        .encode()
        .unwrap();
        bytes[13 + 2 + 8 + 32] ^= 1;
        assert!(NativeCurrentLiveExportV1::decode(&bytes).is_err());
    }
}
