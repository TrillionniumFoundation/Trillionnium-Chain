//! Candidate-local, offline-only `MIG-COMET-POCO` rehearsal.
//!
//! The production plan deliberately keeps legacy Comet migration outside the
//! live node.  This module supplies the missing *concrete* verifier boundary
//! for the C0 preparation rehearsal: a source export is checked against an
//! independently supplied finality witness and mapping preimages, a fresh
//! native JMT root is recomputed from those preimages, and target-validator
//! GenesisQC ceremony evidence is composed only after all of those checks
//! pass.  Nothing in this module starts a node, opens a Comet database, imports
//! WAL/Safety state, or changes an activation flag.
//!
//! Every public result is explicitly candidate-local.  Operators must still
//! provide a separately signed evidence envelope and pass the G5/C0 gates
//! before any production cutover can be considered.

use std::{
    collections::BTreeSet,
    fs::{self, File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};

use anyhow::{anyhow, ensure, Context, Result as AnyResult};
use borsh::{BorshDeserialize, BorshSerialize};
use ed25519_dalek::{Signature, VerifyingKey};
use fs2::FileExt;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use trnm_consensus_types::{
    CometStateExportV1, CometStateExportVerifierV1, GenesisQcCeremonyEvidenceV1,
    PocoTargetGenesisManifestV1, PocoTargetGenesisReplayContextV1,
    PocoTargetProjectionManifestVerifierV1, StateRoot, ValidationError, ValidatorSet,
    VerifiedCometStateExportV1, VerifiedPocoTargetGenesisCeremonyV1,
};
use trnm_finality_types::{decode_hash32, hash_domain, FinalityReceiptV1, ValidatorSetV1};

use crate::auth_tree::{namespaced_key, AuthWrite, InMemoryAuthTree, StateNamespace};

/// This is an offline rehearsal profile, never a node-start or activation
/// capability.  Keeping the flags in code makes accidental promotion to a
/// production feature machine-detectable.
pub const MIGRATION_SOURCE_FINALITY_REHEARSAL_V1: bool = true;
pub const MIGRATION_TARGET_JMT_REPLAY_REHEARSAL_V1: bool = true;
pub const MIGRATION_GENESIS_QC_CEREMONY_REHEARSAL_V1: bool = true;
pub const MIGRATION_REHEARSAL_PRODUCTION_ACTIVATION_V1: bool = false;
/// The rehearsal can persist the independently replayed target JMT snapshot
/// and reopen it with exact commitment/readback checks.  This is still an
/// offline candidate writer; it is not a node-start or cutover authority.
pub const MIGRATION_TARGET_JMT_WRITER_REHEARSAL_V1: bool = true;
pub const MIGRATION_TARGET_JMT_WRITER_PRODUCTION_ACTIVATION_V1: bool = false;

pub const MIGRATION_SOURCE_FINALITY_WITNESS_SCHEMA_V1: &str =
    "trnm_migration_source_finality_witness_v1";
pub const MIGRATION_MAPPING_SCHEMA_V1: &str = "trnm_migration_mapping_v1";
pub const MIGRATION_REPLAY_SCHEMA_V1: &str = "trnm_migration_target_replay_v1";

const MAX_MAPPING_LEAVES_PER_DOMAIN: usize = 1_000_000;
const MAX_MAPPING_COMPONENT_BYTES: usize = 1024 * 1024;
const MAX_MAPPING_TOTAL_BYTES: usize = 64 * 1024 * 1024;
const MAX_SOURCE_RECEIPT_BYTES: usize = 4 * 1024 * 1024;
const MAX_MIGRATION_JSON_BYTES: usize = 80 * 1024 * 1024;
// These bounds are enforced by a budgeted JSON preflight before serde starts
// constructing its recursive value tree. The depth cap protects the call
// stack; the node/member caps keep a small-value array/object bomb from
// consuming unbounded CPU even when the byte cap is not reached.
const MAX_MIGRATION_JSON_DEPTH: usize = 128;
const MAX_MIGRATION_JSON_NODES: usize = 4_000_000;
const MAX_MIGRATION_JSON_CONTAINER_ITEMS: usize = 1_000_000;

const SOURCE_VALIDATOR_SET_DIGEST_DOMAIN: &str = "trnm.migration.source-validator-set.v1";
const SOURCE_FINALITY_DIGEST_DOMAIN: &str = "trnm.migration.source-finality-proof.v1";
const MAPPING_PROFILE_DOMAIN: &str = "trnm.migration.mapping-profile.v1";
const MAPPING_LEAF_DOMAIN: &str = "trnm.migration.mapping-leaf.v1";
const MAPPING_NODE_DOMAIN: &str = "trnm.migration.mapping-node.v1";
const MAPPING_EMPTY_DOMAIN: &str = "trnm.migration.mapping-empty.v1";
const MAPPING_CATEGORY_DOMAIN: &str = "trnm.migration.mapping-category.v1";

const CATEGORY_OBJECTS: &str = "objects";
const CATEGORY_INDEXES: &str = "indexes";
const CATEGORY_RECEIPTS: &str = "receipts";
const CATEGORY_REJECTED_OBJECTS: &str = "rejected_objects";

const TARGET_JMT_RECORD_CODEC_V1: u16 = 1;
const TARGET_JMT_HEAD_CODEC_V1: u16 = 1;
const TARGET_JMT_MAX_RECORD_BYTES_V1: usize = 256 * 1024 * 1024;
const TARGET_JMT_MAX_SNAPSHOT_BYTES_V1: usize = 240 * 1024 * 1024;
const TARGET_JMT_HASH_DOMAIN_V1: &str = "trnm.migration.target-jmt-record.v1";

/// Parse a migration JSON object while rejecting duplicate keys at every
/// nesting level. `serde_json::Value` alone is not sufficient here: its map
/// parser keeps the last duplicate key, which could let a signed receipt and
/// the displayed/exported receipt differ. This helper is intentionally
/// generic so both the source witness and mapping use the same fail-closed
/// decoder.
pub fn decode_json_strict_v1<T: DeserializeOwned>(bytes: &[u8]) -> AnyResult<T> {
    ensure!(
        bytes.len() <= MAX_MIGRATION_JSON_BYTES,
        "migration JSON exceeds bounded input size"
    );
    scan_json_budget_v1(bytes)?;
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let value = StrictJsonValue::deserialize(&mut deserializer)?;
    deserializer.end()?;
    T::deserialize(value.into_value()).context("decode strict migration JSON")
}

/// Strict source-witness JSON decoder used by offline import tooling.
pub fn decode_source_finality_witness_json_v1(
    bytes: &[u8],
) -> AnyResult<MigrationSourceFinalityWitnessV1> {
    let witness: MigrationSourceFinalityWitnessV1 = decode_json_strict_v1(bytes)?;
    witness.validate_shape()?;
    Ok(witness)
}

/// Strict mapping JSON decoder used by offline import tooling.
pub fn decode_mapping_json_v1(bytes: &[u8]) -> AnyResult<MigrationMappingV1> {
    let mapping: MigrationMappingV1 = decode_json_strict_v1(bytes)?;
    mapping.validate()?;
    Ok(mapping)
}

/// Decode the exact bounded CEV1 source-export bytes before running the
/// importer-owned verifier.  The consensus-types decoder rejects trailing
/// bytes, schema drift and canonical-order changes; this wrapper only maps
/// its typed error into the offline tool's error channel.
pub fn decode_source_export_exact_v1(bytes: &[u8]) -> AnyResult<CometStateExportV1> {
    trnm_consensus_types::decode_comet_state_export_v1_exact(bytes)
        .map_err(|error| anyhow!("decode exact source export: {error:?}"))
}

/// Preflight a JSON byte stream with explicit structural budgets before the
/// recursive serde decoder runs. This is a small syntax scanner rather than
/// a second semantic decoder: serde remains responsible for the final type
/// conversion and duplicate-key rejection.  Keeping the budget check here
/// means a deeply nested or many-tiny-values input cannot first exhaust the
/// parser stack/CPU and only then fail type validation.
fn scan_json_budget_v1(bytes: &[u8]) -> AnyResult<()> {
    let mut scanner = JsonBudgetScanner {
        bytes,
        offset: 0,
        depth: 0,
        nodes: 0,
    };
    scanner.scan_value()?;
    scanner.skip_whitespace();
    ensure!(
        scanner.offset == bytes.len(),
        "migration JSON contains trailing bytes at offset {}",
        scanner.offset
    );
    Ok(())
}

struct JsonBudgetScanner<'a> {
    bytes: &'a [u8],
    offset: usize,
    depth: usize,
    nodes: usize,
}

impl JsonBudgetScanner<'_> {
    fn scan_value(&mut self) -> AnyResult<()> {
        self.skip_whitespace();
        self.bump_node()?;
        match self.peek() {
            Some(b'{') => self.scan_object(),
            Some(b'[') => self.scan_array(),
            Some(b'"') => self.scan_string(),
            Some(b't') => self.consume_literal(b"true"),
            Some(b'f') => self.consume_literal(b"false"),
            Some(b'n') => self.consume_literal(b"null"),
            Some(b'-' | b'0'..=b'9') => self.scan_number(),
            Some(byte) => Err(anyhow!(
                "invalid migration JSON value byte 0x{byte:02x} at offset {}",
                self.offset
            )),
            None => Err(anyhow!(
                "unexpected end of migration JSON at offset {}",
                self.offset
            )),
        }
    }

    fn scan_object(&mut self) -> AnyResult<()> {
        self.enter_container()?;
        self.offset += 1; // `{`
        self.skip_whitespace();
        if self.take_byte(b'}') {
            self.leave_container();
            return Ok(());
        }

        let mut items = 0usize;
        loop {
            items = items
                .checked_add(1)
                .ok_or_else(|| anyhow!("migration JSON object member count overflow"))?;
            ensure!(
                items <= MAX_MIGRATION_JSON_CONTAINER_ITEMS,
                "migration JSON object exceeds container-item budget of {} members",
                MAX_MIGRATION_JSON_CONTAINER_ITEMS
            );
            self.skip_whitespace();
            ensure!(
                self.peek() == Some(b'"'),
                "migration JSON object key must be a string at offset {}",
                self.offset
            );
            // Keys are covered by the member budget and byte cap; only values
            // count as structural nodes so a valid million-leaf mapping fits
            // within the node budget.
            self.scan_string()?;
            self.skip_whitespace();
            self.expect_byte(b':')?;
            self.scan_value()?;
            self.skip_whitespace();
            match self.peek() {
                Some(b',') => {
                    self.offset += 1;
                    self.skip_whitespace();
                }
                Some(b'}') => {
                    self.offset += 1;
                    break;
                }
                Some(byte) => {
                    return Err(anyhow!(
                        "expected ',' or '}}' in migration JSON object, found 0x{byte:02x} at offset {}",
                        self.offset
                    ));
                }
                None => {
                    return Err(anyhow!(
                        "unterminated migration JSON object at offset {}",
                        self.offset
                    ));
                }
            }
        }
        self.leave_container();
        Ok(())
    }

    fn scan_array(&mut self) -> AnyResult<()> {
        self.enter_container()?;
        self.offset += 1; // `[`
        self.skip_whitespace();
        if self.take_byte(b']') {
            self.leave_container();
            return Ok(());
        }

        let mut items = 0usize;
        loop {
            items = items
                .checked_add(1)
                .ok_or_else(|| anyhow!("migration JSON array item count overflow"))?;
            ensure!(
                items <= MAX_MIGRATION_JSON_CONTAINER_ITEMS,
                "migration JSON array exceeds container-item budget of {} items",
                MAX_MIGRATION_JSON_CONTAINER_ITEMS
            );
            self.scan_value()?;
            self.skip_whitespace();
            match self.peek() {
                Some(b',') => {
                    self.offset += 1;
                    self.skip_whitespace();
                }
                Some(b']') => {
                    self.offset += 1;
                    break;
                }
                Some(byte) => {
                    return Err(anyhow!(
                        "expected ',' or ']' in migration JSON array, found 0x{byte:02x} at offset {}",
                        self.offset
                    ));
                }
                None => {
                    return Err(anyhow!(
                        "unterminated migration JSON array at offset {}",
                        self.offset
                    ));
                }
            }
        }
        self.leave_container();
        Ok(())
    }

    fn scan_string(&mut self) -> AnyResult<()> {
        self.expect_byte(b'"')?;
        while let Some(byte) = self.next_byte() {
            match byte {
                b'"' => return Ok(()),
                b'\\' => {
                    let escaped = self
                        .next_byte()
                        .ok_or_else(|| anyhow!("unterminated escape in migration JSON string"))?;
                    match escaped {
                        b'"' | b'\\' | b'/' | b'b' | b'f' | b'n' | b'r' | b't' => {}
                        b'u' => {
                            for _ in 0..4 {
                                let digit = self.next_byte().ok_or_else(|| {
                                    anyhow!("truncated unicode escape in migration JSON string")
                                })?;
                                ensure!(
                                    digit.is_ascii_hexdigit(),
                                    "invalid unicode escape in migration JSON string"
                                );
                            }
                        }
                        _ => {
                            return Err(anyhow!(
                                "invalid escape byte 0x{escaped:02x} in migration JSON string"
                            ));
                        }
                    }
                }
                0x00..=0x1f => {
                    return Err(anyhow!("unescaped control byte in migration JSON string"));
                }
                _ => {}
            }
        }
        Err(anyhow!("unterminated migration JSON string"))
    }

    fn scan_number(&mut self) -> AnyResult<()> {
        if self.take_byte(b'-') {
            ensure!(
                self.peek().is_some(),
                "migration JSON number is missing digits"
            );
        }
        match self.peek() {
            Some(b'0') => {
                self.offset += 1;
                ensure!(
                    !matches!(self.peek(), Some(b'0'..=b'9')),
                    "migration JSON number has a leading zero"
                );
            }
            Some(b'1'..=b'9') => {
                self.offset += 1;
                while matches!(self.peek(), Some(b'0'..=b'9')) {
                    self.offset += 1;
                }
            }
            _ => return Err(anyhow!("migration JSON number is missing integer digits")),
        }
        if self.take_byte(b'.') {
            ensure!(
                matches!(self.peek(), Some(b'0'..=b'9')),
                "migration JSON fraction is missing digits"
            );
            while matches!(self.peek(), Some(b'0'..=b'9')) {
                self.offset += 1;
            }
        }
        if matches!(self.peek(), Some(b'e' | b'E')) {
            self.offset += 1;
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.offset += 1;
            }
            ensure!(
                matches!(self.peek(), Some(b'0'..=b'9')),
                "migration JSON exponent is missing digits"
            );
            while matches!(self.peek(), Some(b'0'..=b'9')) {
                self.offset += 1;
            }
        }
        Ok(())
    }

    fn consume_literal(&mut self, literal: &[u8]) -> AnyResult<()> {
        ensure!(
            self.bytes.get(self.offset..self.offset + literal.len()) == Some(literal),
            "invalid migration JSON literal at offset {}",
            self.offset
        );
        self.offset += literal.len();
        Ok(())
    }

    fn bump_node(&mut self) -> AnyResult<()> {
        self.nodes = self
            .nodes
            .checked_add(1)
            .ok_or_else(|| anyhow!("migration JSON node count overflow"))?;
        ensure!(
            self.nodes <= MAX_MIGRATION_JSON_NODES,
            "migration JSON exceeds {} structural nodes",
            MAX_MIGRATION_JSON_NODES
        );
        Ok(())
    }

    fn enter_container(&mut self) -> AnyResult<()> {
        self.depth = self
            .depth
            .checked_add(1)
            .ok_or_else(|| anyhow!("migration JSON depth overflow"))?;
        ensure!(
            self.depth <= MAX_MIGRATION_JSON_DEPTH,
            "migration JSON exceeds maximum depth {}",
            MAX_MIGRATION_JSON_DEPTH
        );
        Ok(())
    }

    fn leave_container(&mut self) {
        self.depth -= 1;
    }

    fn skip_whitespace(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\n' | b'\r' | b'\t')) {
            self.offset += 1;
        }
    }

    fn expect_byte(&mut self, expected: u8) -> AnyResult<()> {
        ensure!(
            self.take_byte(expected),
            "expected byte 0x{expected:02x} in migration JSON at offset {}",
            self.offset
        );
        Ok(())
    }

    fn take_byte(&mut self, expected: u8) -> bool {
        if self.peek() == Some(expected) {
            self.offset += 1;
            true
        } else {
            false
        }
    }

    fn next_byte(&mut self) -> Option<u8> {
        let byte = self.peek()?;
        self.offset += 1;
        Some(byte)
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.offset).copied()
    }
}

#[derive(Debug)]
enum StrictJsonValue {
    Null,
    Bool(bool),
    Number(serde_json::Number),
    String(String),
    Array(Vec<Self>),
    Object(Vec<(String, Self)>),
}

impl StrictJsonValue {
    fn into_value(self) -> serde_json::Value {
        match self {
            Self::Null => serde_json::Value::Null,
            Self::Bool(value) => serde_json::Value::Bool(value),
            Self::Number(value) => serde_json::Value::Number(value),
            Self::String(value) => serde_json::Value::String(value),
            Self::Array(values) => {
                serde_json::Value::Array(values.into_iter().map(Self::into_value).collect())
            }
            Self::Object(entries) => serde_json::Value::Object(
                entries
                    .into_iter()
                    .map(|(key, value)| (key, value.into_value()))
                    .collect(),
            ),
        }
    }
}

impl<'de> Deserialize<'de> for StrictJsonValue {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct StrictVisitor;

        impl<'de> serde::de::Visitor<'de> for StrictVisitor {
            type Value = StrictJsonValue;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("a JSON value with unique object keys")
            }

            fn visit_unit<E>(self) -> std::result::Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Ok(StrictJsonValue::Null)
            }

            fn visit_bool<E>(self, value: bool) -> std::result::Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Ok(StrictJsonValue::Bool(value))
            }

            fn visit_i64<E>(self, value: i64) -> std::result::Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Ok(StrictJsonValue::Number(serde_json::Number::from(value)))
            }

            fn visit_u64<E>(self, value: u64) -> std::result::Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Ok(StrictJsonValue::Number(serde_json::Number::from(value)))
            }

            fn visit_f64<E>(self, value: f64) -> std::result::Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                let number = serde_json::Number::from_f64(value)
                    .ok_or_else(|| E::custom("non-finite JSON number"))?;
                Ok(StrictJsonValue::Number(number))
            }

            fn visit_str<E>(self, value: &str) -> std::result::Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Ok(StrictJsonValue::String(value.to_string()))
            }

            fn visit_string<E>(self, value: String) -> std::result::Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Ok(StrictJsonValue::String(value))
            }

            fn visit_seq<A>(self, mut sequence: A) -> std::result::Result<Self::Value, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                let mut values = Vec::new();
                while let Some(value) = sequence.next_element::<StrictJsonValue>()? {
                    values.push(value);
                }
                Ok(StrictJsonValue::Array(values))
            }

            fn visit_map<A>(self, mut map: A) -> std::result::Result<Self::Value, A::Error>
            where
                A: serde::de::MapAccess<'de>,
            {
                let mut entries = Vec::new();
                let mut seen = BTreeSet::new();
                while let Some(key) = map.next_key::<String>()? {
                    if !seen.insert(key.clone()) {
                        return Err(serde::de::Error::custom(format!(
                            "duplicate JSON object key: {key}"
                        )));
                    }
                    let value = map.next_value::<StrictJsonValue>()?;
                    entries.push((key, value));
                }
                Ok(StrictJsonValue::Object(entries))
            }
        }

        deserializer.deserialize_any(StrictVisitor)
    }
}

/// Source-finality witness exported by an independent legacy-chain reader.
///
/// The witness is intentionally JSON-friendly because the old Comet tooling
/// is JSON based.  It is not accepted as a consensus wire object.  All digest
/// fields use strict lower-case 32-byte hex and the nested receipt/QC are
/// independently checked with the old protocol's exact signing preimages.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MigrationSourceFinalityWitnessV1 {
    pub schema: String,
    pub genesis_document_digest_hex: String,
    pub source_application_id_hex: String,
    pub source_store_id_hex: String,
    pub source_application_schema_digest_hex: String,
    pub source_runtime_profile_digest_hex: String,
    pub legacy_app_hash_hex: String,
    pub part_set_total: u32,
    pub part_set_hash_hex: String,
    pub receipt: FinalityReceiptV1,
    pub validator_set: ValidatorSetV1,
}

impl MigrationSourceFinalityWitnessV1 {
    /// Validate syntactic shape and canonical encodings before any expensive
    /// signature work.  Semantic checks involving a particular export happen
    /// in [`MigrationSourceVerifierV1`].
    pub fn validate_shape(&self) -> AnyResult<()> {
        ensure!(
            self.schema == MIGRATION_SOURCE_FINALITY_WITNESS_SCHEMA_V1,
            "unsupported migration source-finality witness schema"
        );
        for (label, value) in [
            (
                "genesis_document_digest_hex",
                &self.genesis_document_digest_hex,
            ),
            ("source_application_id_hex", &self.source_application_id_hex),
            ("source_store_id_hex", &self.source_store_id_hex),
            (
                "source_application_schema_digest_hex",
                &self.source_application_schema_digest_hex,
            ),
            (
                "source_runtime_profile_digest_hex",
                &self.source_runtime_profile_digest_hex,
            ),
            ("legacy_app_hash_hex", &self.legacy_app_hash_hex),
            ("part_set_hash_hex", &self.part_set_hash_hex),
        ] {
            let bytes = decode_hash32(label, value)?;
            ensure!(bytes != [0; 32], "{label} must be nonzero");
        }
        ensure!(self.part_set_total > 0, "part_set_total must be nonzero");
        ensure!(
            self.validator_set.validators.len() <= MAX_MAPPING_LEAVES_PER_DOMAIN,
            "source validator set is unreasonably large"
        );
        self.validator_set.validate()?;
        for pair in self.validator_set.validators.windows(2) {
            ensure!(
                pair[0].validator_id < pair[1].validator_id,
                "source validator set must be strictly ordered by validator_id"
            );
        }
        self.receipt.block_header.validate()?;
        ensure!(
            self.receipt.schema == trnm_finality_types::FINALITY_RECEIPT_SCHEMA_V1,
            "unsupported source finality receipt schema"
        );
        for pair in self.receipt.quorum_certificate.signatures.windows(2) {
            ensure!(
                pair[0].validator_id < pair[1].validator_id,
                "source quorum certificate signatures must be strictly ordered by validator_id"
            );
        }
        // Force the old receipt's own canonical hash preimage to be parsed now
        // and bound its allocation before any signature work.
        let receipt_bytes = self.receipt.unsigned_bytes()?;
        ensure!(
            receipt_bytes.len() <= MAX_SOURCE_RECEIPT_BYTES,
            "source finality receipt exceeds bounded witness size"
        );
        Ok(())
    }

    pub fn source_application_id(&self) -> AnyResult<[u8; 32]> {
        decode_hash32("source_application_id_hex", &self.source_application_id_hex)
    }

    pub fn source_store_id(&self) -> AnyResult<[u8; 32]> {
        decode_hash32("source_store_id_hex", &self.source_store_id_hex)
    }

    pub fn genesis_document_digest(&self) -> AnyResult<[u8; 32]> {
        decode_hash32(
            "genesis_document_digest_hex",
            &self.genesis_document_digest_hex,
        )
    }

    pub fn source_application_schema_digest(&self) -> AnyResult<[u8; 32]> {
        decode_hash32(
            "source_application_schema_digest_hex",
            &self.source_application_schema_digest_hex,
        )
    }

    pub fn source_runtime_profile_digest(&self) -> AnyResult<[u8; 32]> {
        decode_hash32(
            "source_runtime_profile_digest_hex",
            &self.source_runtime_profile_digest_hex,
        )
    }

    pub fn legacy_app_hash(&self) -> AnyResult<[u8; 32]> {
        decode_hash32("legacy_app_hash_hex", &self.legacy_app_hash_hex)
    }

    pub fn part_set_hash(&self) -> AnyResult<[u8; 32]> {
        decode_hash32("part_set_hash_hex", &self.part_set_hash_hex)
    }
}

/// One exact source key/value preimage in a migration category.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MigrationMappingLeafV1 {
    pub key_hex: String,
    pub value_hex: String,
}

impl MigrationMappingLeafV1 {
    fn decode(&self) -> AnyResult<(Vec<u8>, Vec<u8>)> {
        let key = decode_bytes("mapping key_hex", &self.key_hex, false)?;
        let value = decode_bytes("mapping value_hex", &self.value_hex, true)?;
        ensure!(!key.is_empty(), "mapping key must be nonempty");
        ensure!(
            key.len() <= MAX_MAPPING_COMPONENT_BYTES,
            "mapping key exceeds bound"
        );
        ensure!(
            value.len() <= MAX_MAPPING_COMPONENT_BYTES,
            "mapping value exceeds bound"
        );
        Ok((key, value))
    }
}

/// Frozen source-to-target mapping preimages.  Each category is sorted by raw
/// key and contains no duplicates; this is part of the migration commitment,
/// not a presentation convention.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MigrationMappingV1 {
    pub schema: String,
    pub objects: Vec<MigrationMappingLeafV1>,
    pub indexes: Vec<MigrationMappingLeafV1>,
    pub receipts: Vec<MigrationMappingLeafV1>,
    pub rejected_objects: Vec<MigrationMappingLeafV1>,
}

impl MigrationMappingV1 {
    pub fn validate(&self) -> AnyResult<()> {
        ensure!(
            self.schema == MIGRATION_MAPPING_SCHEMA_V1,
            "unsupported migration mapping schema"
        );
        let mut total_bytes = 0usize;
        for (category, leaves) in self.categories() {
            ensure!(
                leaves.len() <= MAX_MAPPING_LEAVES_PER_DOMAIN,
                "mapping category {category} exceeds leaf bound"
            );
            let mut previous: Option<Vec<u8>> = None;
            for leaf in leaves {
                let (key, value) = leaf.decode()?;
                total_bytes = total_bytes
                    .checked_add(key.len())
                    .and_then(|size| size.checked_add(value.len()))
                    .ok_or_else(|| anyhow!("mapping byte-size overflow"))?;
                ensure!(
                    total_bytes <= MAX_MAPPING_TOTAL_BYTES,
                    "mapping preimages exceed bounded total size"
                );
                if let Some(previous) = &previous {
                    ensure!(
                        previous.as_slice() < key.as_slice(),
                        "mapping category {category} must be strictly key-sorted"
                    );
                }
                previous = Some(key);
            }
        }
        Ok(())
    }

    pub fn categories(&self) -> [(&'static str, &[MigrationMappingLeafV1]); 4] {
        [
            (CATEGORY_OBJECTS, &self.objects),
            (CATEGORY_INDEXES, &self.indexes),
            (CATEGORY_RECEIPTS, &self.receipts),
            (CATEGORY_REJECTED_OBJECTS, &self.rejected_objects),
        ]
    }
}

/// Returns the four category roots in the export field order
/// (objects/indexes/receipts/rejected objects).
pub fn mapping_category_roots_v1(mapping: &MigrationMappingV1) -> AnyResult<[[u8; 32]; 4]> {
    mapping.validate()?;
    Ok([
        mapping_category_root_v1(CATEGORY_OBJECTS, &mapping.objects)?,
        mapping_category_root_v1(CATEGORY_INDEXES, &mapping.indexes)?,
        mapping_category_root_v1(CATEGORY_RECEIPTS, &mapping.receipts)?,
        mapping_category_root_v1(CATEGORY_REJECTED_OBJECTS, &mapping.rejected_objects)?,
    ])
}

/// Computes the mapping profile commitment.  The profile commits the schema
/// and ordered category labels; category preimages are committed separately
/// by the four export roots.
pub fn mapping_profile_digest_v1(mapping: &MigrationMappingV1) -> AnyResult<[u8; 32]> {
    mapping.validate()?;
    Ok(hash_domain(
        MAPPING_PROFILE_DOMAIN,
        &[
            mapping.schema.as_bytes(),
            CATEGORY_OBJECTS.as_bytes(),
            CATEGORY_INDEXES.as_bytes(),
            CATEGORY_RECEIPTS.as_bytes(),
            CATEGORY_REJECTED_OBJECTS.as_bytes(),
        ],
    ))
}

fn mapping_category_root_v1(
    category: &str,
    leaves: &[MigrationMappingLeafV1],
) -> AnyResult<[u8; 32]> {
    let mut hashes = Vec::with_capacity(leaves.len());
    for leaf in leaves {
        let (key, value) = leaf.decode()?;
        hashes.push(hash_domain(
            MAPPING_LEAF_DOMAIN,
            &[category.as_bytes(), &key, &value],
        ));
    }
    let merkle = if hashes.is_empty() {
        hash_domain(MAPPING_EMPTY_DOMAIN, &[category.as_bytes()])
    } else {
        merkle_root_v1(&hashes)
    };
    let count = (leaves.len() as u64).to_be_bytes();
    Ok(hash_domain(
        MAPPING_CATEGORY_DOMAIN,
        &[category.as_bytes(), &count, &merkle],
    ))
}

fn merkle_root_v1(leaves: &[[u8; 32]]) -> [u8; 32] {
    let mut level = leaves.to_vec();
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        for pair in level.chunks(2) {
            let right = pair.get(1).unwrap_or(&pair[0]);
            next.push(hash_domain(MAPPING_NODE_DOMAIN, &[&pair[0], right]));
        }
        level = next;
    }
    level[0]
}

fn decode_bytes(label: &str, value: &str, allow_empty: bool) -> AnyResult<Vec<u8>> {
    let decoded = hex::decode(value).map_err(|_| anyhow!("{label} must be lowercase hex"))?;
    ensure!(
        hex::encode(&decoded) == value,
        "{label} must use canonical lowercase hex"
    );
    if !allow_empty {
        ensure!(!decoded.is_empty(), "{label} must be nonempty");
    }
    Ok(decoded)
}

/// Canonical digest of the source validator set used by the migration
/// witness.  Validator order in the JSON is required to be canonical, while
/// this digest independently sorts a copy before hashing so an importer never
/// relies on incidental parser order.
pub fn source_validator_set_digest_v1(set: &ValidatorSetV1) -> AnyResult<[u8; 32]> {
    set.validate()?;
    let mut validators = set.validators.clone();
    validators.sort_by(|left, right| left.validator_id.cmp(&right.validator_id));
    let mut bytes = Vec::new();
    append_len_bytes(&mut bytes, set.validator_set_id.as_bytes());
    bytes.extend_from_slice(&set.quorum_power.to_be_bytes());
    for validator in validators {
        append_len_bytes(&mut bytes, validator.validator_id.as_bytes());
        append_len_bytes(&mut bytes, validator.public_key_hex.as_bytes());
        append_len_bytes(&mut bytes, validator.vote_endpoint.as_bytes());
        bytes.extend_from_slice(&validator.voting_power.to_be_bytes());
    }
    Ok(hash_domain(SOURCE_VALIDATOR_SET_DIGEST_DOMAIN, &[&bytes]))
}

/// Computes the digest bound to `CometStateExportV1.source_finality_proof_digest`.
/// The full receipt JSON, validator-set preimage, source identity fields and
/// part-set identity are all included; a bare block hash/QC id is insufficient.
pub fn source_finality_proof_digest_v1(
    witness: &MigrationSourceFinalityWitnessV1,
) -> AnyResult<[u8; 32]> {
    witness.validate_shape()?;
    let receipt_bytes =
        serde_json::to_vec(&witness.receipt).context("serialize source finality receipt")?;
    let validator_bytes = canonical_validator_set_bytes_v1(&witness.validator_set)?;
    let genesis = witness.genesis_document_digest()?;
    let app = witness.source_application_id()?;
    let store = witness.source_store_id()?;
    let schema = witness.source_application_schema_digest()?;
    let runtime = witness.source_runtime_profile_digest()?;
    let app_hash = witness.legacy_app_hash()?;
    let part_hash = witness.part_set_hash()?;
    let total = witness.part_set_total.to_be_bytes();
    Ok(hash_domain(
        SOURCE_FINALITY_DIGEST_DOMAIN,
        &[
            receipt_bytes.as_slice(),
            validator_bytes.as_slice(),
            &genesis,
            &app,
            &store,
            &schema,
            &runtime,
            &app_hash,
            &total,
            &part_hash,
        ],
    ))
}

fn canonical_validator_set_bytes_v1(set: &ValidatorSetV1) -> AnyResult<Vec<u8>> {
    set.validate()?;
    let mut validators = set.validators.clone();
    validators.sort_by(|left, right| left.validator_id.cmp(&right.validator_id));
    let mut bytes = Vec::new();
    append_len_bytes(&mut bytes, set.validator_set_id.as_bytes());
    bytes.extend_from_slice(&set.quorum_power.to_be_bytes());
    for validator in validators {
        append_len_bytes(&mut bytes, validator.validator_id.as_bytes());
        append_len_bytes(&mut bytes, validator.public_key_hex.as_bytes());
        append_len_bytes(&mut bytes, validator.vote_endpoint.as_bytes());
        bytes.extend_from_slice(&validator.voting_power.to_be_bytes());
    }
    Ok(bytes)
}

fn append_len_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
    out.extend_from_slice(bytes);
}

/// Concrete source verifier.  It owns no source database handle: the caller
/// must provide a witness and mapping produced by an independently audited
/// exporter.  This makes the dependency explicit and keeps the rehearsal
/// deterministic/replayable in CI.
pub struct MigrationSourceVerifierV1<'a> {
    witness: &'a MigrationSourceFinalityWitnessV1,
    mapping: &'a MigrationMappingV1,
}

impl<'a> MigrationSourceVerifierV1<'a> {
    pub fn new(
        witness: &'a MigrationSourceFinalityWitnessV1,
        mapping: &'a MigrationMappingV1,
    ) -> AnyResult<Self> {
        witness.validate_shape()?;
        mapping.validate()?;
        Ok(Self { witness, mapping })
    }

    fn verify_export_coordinates(&self, export: &CometStateExportV1) -> AnyResult<()> {
        let witness = self.witness;
        let receipt = &witness.receipt;
        let header = &receipt.block_header;
        ensure!(
            receipt.chain_id == export.source_chain_id().as_str(),
            "source receipt chain id does not match export"
        );
        ensure!(
            header.chain_id == receipt.chain_id,
            "source block header chain id does not match receipt"
        );
        ensure!(
            receipt.block_height == export.finalized_height().get(),
            "source receipt height does not match export finalized height"
        );
        ensure!(
            header.height == export.finalized_height().get(),
            "source header height does not match export finalized height"
        );
        let block_hash = header.block_hash()?;
        let block_hash_hex = hex::encode(block_hash);
        ensure!(
            block_hash_hex == receipt.block_hash_hex,
            "receipt block hash does not match header signing hash"
        );
        let exported_identity = export.finalized_block_identity();
        ensure!(
            block_hash == *exported_identity.block_hash(),
            "source block hash does not match Comet BlockID"
        );
        ensure!(
            witness.part_set_total == exported_identity.part_set_total(),
            "source part-set total does not match Comet BlockID"
        );
        ensure!(
            witness.part_set_hash()? == *exported_identity.part_set_hash(),
            "source part-set hash does not match Comet BlockID"
        );
        ensure!(
            receipt.state_root_hex == header.state_root_hex,
            "receipt state root does not match block header"
        );
        ensure!(
            receipt.transaction_root_hex == header.transaction_root_hex,
            "receipt transaction root does not match block header"
        );
        ensure!(
            receipt.validator_set_id == witness.validator_set.validator_set_id,
            "receipt validator set id does not match witness"
        );
        ensure!(
            receipt.quorum_certificate.validator_set_id == witness.validator_set.validator_set_id,
            "source QC validator set id does not match witness"
        );
        ensure!(
            receipt.quorum_certificate.height == receipt.block_height,
            "source QC height does not match receipt"
        );
        ensure!(
            receipt.quorum_certificate.block_hash_hex == receipt.block_hash_hex,
            "source QC block hash does not match receipt"
        );
        Ok(())
    }
}

impl MigrationSourceVerifierV1<'_> {
    fn verify_source_identity_any(&self, export: &CometStateExportV1) -> AnyResult<()> {
        self.verify_export_coordinates(export)?;
        let witness = self.witness;
        ensure!(
            witness.genesis_document_digest()?
                == *export.source_genesis_document_digest().as_bytes(),
            "source genesis document digest mismatch"
        );
        ensure!(
            witness.source_application_id()? == export.source_application_id(),
            "source application identity mismatch"
        );
        ensure!(
            witness.source_store_id()? == export.source_store_id(),
            "source store identity mismatch"
        );
        ensure!(
            witness.source_application_schema_digest()?
                == export.source_application_schema_digest(),
            "source application schema digest mismatch"
        );
        ensure!(
            witness.source_runtime_profile_digest()? == export.source_runtime_profile_digest(),
            "source runtime profile digest mismatch"
        );
        ensure!(
            witness.legacy_app_hash()? == *export.legacy_app_hash().as_bytes(),
            "legacy AppHash attestation mismatch"
        );
        let expected_validator_digest = source_validator_set_digest_v1(&witness.validator_set)?;
        ensure!(
            expected_validator_digest == export.source_validator_set_digest(),
            "source validator-set digest mismatch"
        );
        Ok(())
    }

    fn verify_source_finality_any(&self, export: &CometStateExportV1) -> AnyResult<()> {
        self.verify_export_coordinates(export)?;
        let witness = self.witness;
        let receipt = &witness.receipt;
        // Reuse the node-independent receipt verifier for transaction/object
        // inclusion and receipt-shape checks.  Its legacy QC check is not
        // sufficient on its own (it uses the compatibility Ed25519 path), so
        // the complete source validator set and every vote are still checked
        // with strict Ed25519 below.
        trnm_finality_verifier::verify_finality_receipt(receipt, &witness.validator_set)
            .context("verify source receipt inclusion proofs")?;
        // Admit the complete source validator set under strict Ed25519, not
        // only the signers present in this particular QC.  A weak/invalid
        // non-signing key would otherwise remain latent in the imported
        // authority set and could alter a later replay.
        for descriptor in &witness.validator_set.validators {
            let key_bytes =
                decode_hash32("source validator public key", &descriptor.public_key_hex)?;
            let key = VerifyingKey::from_bytes(&key_bytes)
                .map_err(|_| anyhow!("source validator public key is not a valid Ed25519 key"))?;
            ensure!(
                !key.is_weak(),
                "source validator public key is a weak Ed25519 point"
            );
        }
        // The old protocol verifier checks quorum, signer membership and
        // duplicate votes.  We additionally run strict Ed25519 verification
        // below because the legacy helper intentionally permits noncanonical
        // signatures for compatibility.
        receipt
            .quorum_certificate
            .verify(&receipt.chain_id, &witness.validator_set)
            .context("verify source Comet quorum certificate")?;
        let expected_receipt_hash = receipt.compute_receipt_hash()?;
        ensure!(
            hex::encode(expected_receipt_hash) == receipt.receipt_hash_hex,
            "source finality receipt hash mismatch"
        );
        let block_hash = receipt.block_header.block_hash()?;
        let mut seen = BTreeSet::new();
        for vote in &receipt.quorum_certificate.signatures {
            ensure!(
                seen.insert(vote.validator_id.clone()),
                "duplicate source vote signer"
            );
            let descriptor = witness
                .validator_set
                .descriptor(&vote.validator_id)
                .ok_or_else(|| anyhow!("source vote signer is not in validator set"))?;
            ensure!(
                descriptor.public_key_hex == vote.public_key_hex,
                "source vote public key mismatch"
            );
            ensure!(
                vote.height == receipt.block_height,
                "source vote height mismatch"
            );
            ensure!(
                vote.block_hash_hex == hex::encode(block_hash),
                "source vote block mismatch"
            );
            let key_bytes = decode_hash32("source vote public key", &vote.public_key_hex)?;
            let key = VerifyingKey::from_bytes(&key_bytes)
                .map_err(|_| anyhow!("source vote public key is not a valid Ed25519 key"))?;
            let sig_bytes = decode_bytes("source vote signature", &vote.signature_hex, false)?;
            ensure!(
                sig_bytes.len() == 64,
                "source vote signature must be 64 bytes"
            );
            let signature = Signature::from_slice(&sig_bytes)
                .map_err(|_| anyhow!("source vote signature is malformed"))?;
            let signing_bytes = trnm_finality_types::ValidatorVoteV1::signing_bytes(
                &receipt.chain_id,
                &witness.validator_set.validator_set_id,
                vote.height,
                &vote.block_hash_hex,
            );
            key.verify_strict(&signing_bytes, &signature)
                .map_err(|_| anyhow!("source vote strict Ed25519 verification failed"))?;
        }
        let expected_digest = source_finality_proof_digest_v1(witness)?;
        ensure!(
            expected_digest == export.source_finality_proof_digest(),
            "source finality proof digest mismatch"
        );
        Ok(())
    }

    fn verify_mapping_any(&self, export: &CometStateExportV1) -> AnyResult<()> {
        let roots = mapping_category_roots_v1(self.mapping)?;
        ensure!(
            roots[0] == export.exported_object_root(),
            "source object mapping root mismatch"
        );
        ensure!(
            roots[1] == export.exported_index_root(),
            "source index mapping root mismatch"
        );
        ensure!(
            roots[2] == export.exported_receipts_root(),
            "source receipts mapping root mismatch"
        );
        ensure!(
            roots[3] == export.rejected_objects_root(),
            "source rejected-object mapping root mismatch"
        );
        ensure!(
            mapping_profile_digest_v1(self.mapping)? == export.mapping_profile_digest(),
            "source mapping profile digest mismatch"
        );
        Ok(())
    }
}

fn into_consensus_result<T>(
    result: AnyResult<T>,
    stage: &'static str,
) -> trnm_consensus_types::Result<T> {
    result.map_err(|_| ValidationError::InvalidCertificate(stage))
}

impl CometStateExportVerifierV1 for MigrationSourceVerifierV1<'_> {
    fn verify_source_identity_v1(
        &self,
        export: &CometStateExportV1,
    ) -> trnm_consensus_types::Result<()> {
        into_consensus_result(
            self.verify_source_identity_any(export),
            "migration source identity verification failed",
        )
    }

    fn verify_source_finality_v1(
        &self,
        export: &CometStateExportV1,
    ) -> trnm_consensus_types::Result<()> {
        into_consensus_result(
            self.verify_source_finality_any(export),
            "migration source finality verification failed",
        )
    }

    fn verify_mapping_v1(&self, export: &CometStateExportV1) -> trnm_consensus_types::Result<()> {
        into_consensus_result(
            self.verify_mapping_any(export),
            "migration source mapping verification failed",
        )
    }
}

/// Construct and verify a source export in one explicit call.  The returned
/// token is required by the target replay API, preventing callers from
/// bypassing source finality/mapping checks with a raw export.
pub fn verify_source_export_rehearsal_v1(
    export: &CometStateExportV1,
    witness: &MigrationSourceFinalityWitnessV1,
    mapping: &MigrationMappingV1,
) -> AnyResult<VerifiedCometStateExportV1> {
    let verifier = MigrationSourceVerifierV1::new(witness, mapping)?;
    export
        .verify_with(&verifier)
        .map_err(|error| anyhow!(error.to_string()))
}

/// Candidate-local target replay verifier.  It projects each source mapping
/// leaf into a namespaced native authenticated tree and adds a configuration
/// binding for every migration coordinate.  The claimed root in the manifest
/// is never read by this verifier; only root-free replay context is accepted.
pub struct MigrationTargetReplayVerifierV1<'a> {
    mapping: &'a MigrationMappingV1,
}

/// Root-free target coordinates accepted by the offline replay helper.  This
/// mirrors `PocoTargetGenesisReplayContextV1` without exposing the manifest's
/// claimed root.  It lets an independent ceremony tool compute a candidate
/// root before constructing the typed manifest, while preserving the same
/// field set used by the production verification trait.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MigrationTargetReplayCoordinatesV1 {
    pub target_chain_id: trnm_consensus_types::ChainId,
    pub target_genesis_hash: trnm_consensus_types::GenesisHash,
    pub target_validator_set_digest: trnm_consensus_types::ValidatorSetId,
    pub target_protocol_version: trnm_consensus_types::ProtocolVersion,
    pub application_schema_digest: [u8; 32],
    pub runtime_profile_digest: [u8; 32],
}

impl MigrationTargetReplayCoordinatesV1 {
    pub fn validate(&self) -> AnyResult<()> {
        ensure!(
            !self.target_genesis_hash.is_zero(),
            "target genesis hash is zero"
        );
        ensure!(
            !self.target_validator_set_digest.is_zero(),
            "target validator-set digest is zero"
        );
        ensure!(
            self.target_protocol_version == trnm_consensus_types::ProtocolVersion::V0,
            "unsupported target protocol version"
        );
        ensure!(
            self.application_schema_digest != [0; 32],
            "target application schema digest is zero"
        );
        ensure!(
            self.runtime_profile_digest != [0; 32],
            "target runtime profile digest is zero"
        );
        Ok(())
    }

    fn from_context(context: &PocoTargetGenesisReplayContextV1) -> Self {
        Self {
            target_chain_id: context.target_chain_id(),
            target_genesis_hash: context.target_genesis_hash(),
            target_validator_set_digest: context.target_validator_set_digest(),
            target_protocol_version: context.target_protocol_version(),
            application_schema_digest: context.application_schema_digest(),
            runtime_profile_digest: context.runtime_profile_digest(),
        }
    }
}

impl<'a> MigrationTargetReplayVerifierV1<'a> {
    pub fn new(mapping: &'a MigrationMappingV1) -> AnyResult<Self> {
        mapping.validate()?;
        Ok(Self { mapping })
    }

    pub fn mapping(&self) -> &'a MigrationMappingV1 {
        self.mapping
    }

    /// Compute a candidate root from root-free coordinates.  This is the
    /// authoring/rehearsal path; it does not consume or compare a claimed
    /// manifest root.
    pub fn recompute_for_coordinates(
        &self,
        source: &VerifiedCometStateExportV1,
        coordinates: &MigrationTargetReplayCoordinatesV1,
    ) -> AnyResult<StateRoot> {
        coordinates.validate()?;
        ensure!(
            coordinates.target_chain_id != source.export().source_chain_id(),
            "migration target chain id must be fresh"
        );
        self.recompute_native_state_root_any_from_coordinates(
            source,
            coordinates,
            mapping_profile_digest_v1(self.mapping)?,
        )
    }
}

impl MigrationTargetReplayVerifierV1<'_> {
    fn recompute_native_state_root_any(
        &self,
        source: &VerifiedCometStateExportV1,
        context: &PocoTargetGenesisReplayContextV1,
        mapping_profile_digest: [u8; 32],
    ) -> AnyResult<StateRoot> {
        let coordinates = MigrationTargetReplayCoordinatesV1::from_context(context);
        self.recompute_native_state_root_any_from_coordinates(
            source,
            &coordinates,
            mapping_profile_digest,
        )
    }

    fn recompute_native_state_root_any_from_coordinates(
        &self,
        source: &VerifiedCometStateExportV1,
        coordinates: &MigrationTargetReplayCoordinatesV1,
        mapping_profile_digest: [u8; 32],
    ) -> AnyResult<StateRoot> {
        let tree =
            self.replay_tree_any_from_coordinates(source, coordinates, mapping_profile_digest)?;
        let root = tree
            .root_hash(0)
            .ok_or_else(|| anyhow!("target replay produced no authenticated root"))?;
        ensure!(root.0 != [0; 32], "target replay produced a zero root");
        Ok(StateRoot::new(root.0))
    }

    /// Build the exact replay tree used by both the root-only verifier and the
    /// durable rehearsal writer. Keeping one construction path prevents a
    /// persisted snapshot from drifting from the root that the typed manifest
    /// verifier checks.
    fn replay_tree_any_from_coordinates(
        &self,
        source: &VerifiedCometStateExportV1,
        coordinates: &MigrationTargetReplayCoordinatesV1,
        mapping_profile_digest: [u8; 32],
    ) -> AnyResult<InMemoryAuthTree> {
        coordinates.validate()?;
        ensure!(
            coordinates.target_chain_id != source.export().source_chain_id(),
            "migration target chain id must be fresh"
        );
        ensure!(
            mapping_profile_digest == mapping_profile_digest_v1(self.mapping)?,
            "target replay mapping profile mismatch"
        );
        let roots = mapping_category_roots_v1(self.mapping)?;
        let export = source.export();
        ensure!(
            roots[0] == export.exported_object_root(),
            "target object root mismatch"
        );
        ensure!(
            roots[1] == export.exported_index_root(),
            "target index root mismatch"
        );
        ensure!(
            roots[2] == export.exported_receipts_root(),
            "target receipts root mismatch"
        );
        ensure!(
            roots[3] == export.rejected_objects_root(),
            "target rejected-object root mismatch"
        );

        let mut writes = Vec::<(Vec<u8>, Vec<u8>)>::new();
        for (category, leaves) in self.mapping.categories() {
            for leaf in leaves {
                let (key, value) = leaf.decode()?;
                let auth_key = namespaced_key(
                    StateNamespace::Object,
                    &[
                        MIGRATION_REPLAY_SCHEMA_V1.as_bytes(),
                        category.as_bytes(),
                        &key,
                    ],
                )?;
                // Include the category/key framing in the value as well as the
                // key.  This prevents a future decoder from treating a raw
                // value as an object of a different migration domain.
                let mut auth_value = Vec::new();
                append_len_bytes(&mut auth_value, category.as_bytes());
                append_len_bytes(&mut auth_value, &key);
                append_len_bytes(&mut auth_value, &value);
                writes.push((auth_key, auth_value));
            }
        }

        let source_commitment = export
            .commitment_digest_v1()
            .map_err(|error| anyhow!(error.to_string()))?;
        let target_genesis = *coordinates.target_genesis_hash.as_bytes();
        let target_set = *coordinates.target_validator_set_digest.as_bytes();
        let target_chain_id = coordinates.target_chain_id;
        let target_chain = target_chain_id.as_bytes();
        let protocol = coordinates.target_protocol_version.get().to_be_bytes();
        let app_schema = coordinates.application_schema_digest;
        let runtime = coordinates.runtime_profile_digest;
        let profile = mapping_profile_digest;
        let config = [
            (
                b"source-export-commitment".as_slice(),
                source_commitment.as_slice(),
            ),
            (b"mapping-profile-digest".as_slice(), profile.as_slice()),
            (b"target-chain-id".as_slice(), target_chain),
            (b"target-genesis-hash".as_slice(), target_genesis.as_slice()),
            (b"target-validator-set".as_slice(), target_set.as_slice()),
            (b"target-protocol-version".as_slice(), protocol.as_slice()),
            (
                b"application-schema-digest".as_slice(),
                app_schema.as_slice(),
            ),
            (b"runtime-profile-digest".as_slice(), runtime.as_slice()),
        ];
        for (label, value) in config {
            let key = namespaced_key(
                StateNamespace::Config,
                &[MIGRATION_REPLAY_SCHEMA_V1.as_bytes(), label],
            )?;
            let mut encoded = Vec::new();
            append_len_bytes(&mut encoded, label);
            append_len_bytes(&mut encoded, value);
            writes.push((key, encoded));
        }
        writes.sort_by(|left, right| left.0.cmp(&right.0));
        let mut tree = InMemoryAuthTree::default();
        let plan = tree.plan_put_value_set(
            0,
            writes
                .into_iter()
                .map(|(key, value)| AuthWrite::put(key, value))
                .collect::<AnyResult<Vec<_>>>()?,
        )?;
        tree.apply(plan)?;
        Ok(tree)
    }
}

impl PocoTargetProjectionManifestVerifierV1 for MigrationTargetReplayVerifierV1<'_> {
    fn recompute_native_state_root_from_manifest_v1(
        &self,
        source: &VerifiedCometStateExportV1,
        context: &PocoTargetGenesisReplayContextV1,
        mapping_profile_digest: [u8; 32],
    ) -> trnm_consensus_types::Result<StateRoot> {
        into_consensus_result(
            self.recompute_native_state_root_any(source, context, mapping_profile_digest),
            "migration target JMT replay failed",
        )
    }
}

/// Recompute the target root without constructing a projection statement.
/// This is useful to author a manifest in an offline ceremony while keeping
/// the actual verification path root-free.
/// Verify a claimed target manifest/root through the complete typed projection
/// path.  Callers that need to author a new manifest should first run an
/// offline replay harness and capture the root; this API intentionally refuses
/// to manufacture a root from a claimed value.
pub fn verify_target_projection_rehearsal_v1(
    source: &VerifiedCometStateExportV1,
    mapping: &MigrationMappingV1,
    manifest: &PocoTargetGenesisManifestV1,
) -> AnyResult<StateRoot> {
    let projection = source
        .bind_target_projection_from_manifest_v1(manifest)
        .map_err(|error| anyhow!(error.to_string()))?;
    let verifier = MigrationTargetReplayVerifierV1::new(mapping)?;
    let verified = projection
        .verify_with_manifest_v1(source, manifest, &verifier)
        .map_err(|error| anyhow!(error.to_string()))?;
    Ok(verified.projection().claimed_state_root())
}

/// Compute the candidate native root from a verified source and root-free
/// target coordinates.  The caller can place the returned root into a typed
/// `PocoTargetGenesisManifestV1`, after which
/// `verify_target_projection_rehearsal_v1` must be run again.
pub fn recompute_target_state_root_v1(
    source: &VerifiedCometStateExportV1,
    mapping: &MigrationMappingV1,
    coordinates: &MigrationTargetReplayCoordinatesV1,
) -> AnyResult<StateRoot> {
    MigrationTargetReplayVerifierV1::new(mapping)?.recompute_for_coordinates(source, coordinates)
}

/// Durable candidate-only target replay commitment. The snapshot is an exact
/// Borsh encoding of the JMT state produced by the same replay function used
/// by the root-only verifier. It is not a node-start or cutover authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MigrationTargetJmtCommitmentV1 {
    pub source_export_commitment: [u8; 32],
    pub mapping_profile_digest: [u8; 32],
    pub target_state_root: StateRoot,
    pub record_digest: [u8; 32],
}

#[derive(Debug, Clone, BorshSerialize, BorshDeserialize, PartialEq, Eq)]
struct MigrationTargetJmtRecordV1 {
    codec_version: u16,
    source_export_commitment: [u8; 32],
    mapping_profile_digest: [u8; 32],
    target_chain_id: Vec<u8>,
    target_genesis_hash: [u8; 32],
    target_validator_set_digest: [u8; 32],
    target_protocol_version: u32,
    application_schema_digest: [u8; 32],
    runtime_profile_digest: [u8; 32],
    target_state_root: [u8; 32],
    tree_snapshot: Vec<u8>,
    record_digest: [u8; 32],
}

#[derive(Debug, Clone, Copy, BorshSerialize, BorshDeserialize, PartialEq, Eq)]
struct MigrationTargetJmtHeadV1 {
    codec_version: u16,
    record_digest: [u8; 32],
    target_state_root: [u8; 32],
}

/// Open handle for the candidate target JMT snapshot. The lock is held for
/// the lifetime of the handle, so a record and its head sidecar cannot race.
pub struct MigrationTargetJmtWriterV1 {
    path: PathBuf,
    head_path: PathBuf,
    _lock: File,
    record: MigrationTargetJmtRecordV1,
}

impl std::fmt::Debug for MigrationTargetJmtWriterV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("MigrationTargetJmtWriterV1")
            .field("path", &self.path)
            .field("head_path", &self.head_path)
            .field("record_digest", &self.record.record_digest)
            .field("target_state_root", &self.record.target_state_root)
            .finish_non_exhaustive()
    }
}

impl MigrationTargetJmtWriterV1 {
    /// Replays a verified source into a fresh durable target snapshot.
    /// Existing byte-identical state is accepted idempotently; divergent
    /// record/head/context is rejected rather than overwritten.
    pub fn write_verified_replay_v1(
        path: impl AsRef<Path>,
        source: &VerifiedCometStateExportV1,
        mapping: &MigrationMappingV1,
        coordinates: &MigrationTargetReplayCoordinatesV1,
    ) -> AnyResult<Self> {
        let path = prepare_target_jmt_path_v1(path.as_ref())?;
        let head_path = target_jmt_sidecar_path_v1(&path, ".head")?;
        let lock_path = target_jmt_sidecar_path_v1(&path, ".lock")?;
        let lock = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .open(&lock_path)
            .with_context(|| format!("open target JMT lock {}", lock_path.display()))?;
        ensure!(
            fs::symlink_metadata(&lock_path)
                .map(|metadata| metadata.is_file())
                .unwrap_or(false),
            "target JMT lock is not a regular file"
        );
        lock.try_lock_exclusive()
            .context("acquire exclusive target JMT rehearsal lock")?;

        let verifier = MigrationTargetReplayVerifierV1::new(mapping)?;
        let tree = verifier.replay_tree_any_from_coordinates(
            source,
            coordinates,
            mapping_profile_digest_v1(mapping)?,
        )?;
        let root = tree
            .root_hash(0)
            .ok_or_else(|| anyhow!("target replay produced no authenticated root"))?;
        ensure!(root.0 != [0; 32], "target replay produced a zero root");
        let snapshot = tree.encode_snapshot()?;
        ensure!(
            snapshot.len() <= TARGET_JMT_MAX_SNAPSHOT_BYTES_V1,
            "target JMT snapshot exceeds bounded rehearsal size"
        );
        let source_export_commitment = source
            .export()
            .commitment_digest_v1()
            .map_err(|error| anyhow!(error.to_string()))?;
        let mut record = MigrationTargetJmtRecordV1 {
            codec_version: TARGET_JMT_RECORD_CODEC_V1,
            source_export_commitment,
            mapping_profile_digest: mapping_profile_digest_v1(mapping)?,
            target_chain_id: coordinates.target_chain_id.as_bytes().to_vec(),
            target_genesis_hash: coordinates.target_genesis_hash.into_bytes(),
            target_validator_set_digest: coordinates.target_validator_set_digest.into_bytes(),
            target_protocol_version: coordinates.target_protocol_version.get(),
            application_schema_digest: coordinates.application_schema_digest,
            runtime_profile_digest: coordinates.runtime_profile_digest,
            target_state_root: root.0,
            tree_snapshot: snapshot,
            record_digest: [0; 32],
        };
        record.record_digest = target_jmt_record_digest_v1(&record)?;
        validate_target_jmt_record_v1(&record)?;

        if path.exists() {
            let existing = read_target_jmt_record_v1(&path)?;
            ensure!(
                existing == record,
                "existing target JMT record differs; refusing overwrite"
            );
            let head = read_target_jmt_head_v1(&head_path)?;
            ensure!(
                head.record_digest == record.record_digest
                    && head.target_state_root == record.target_state_root,
                "existing target JMT head differs from record"
            );
        } else {
            ensure!(
                !head_path.exists(),
                "target JMT head exists without its record"
            );
            let encoded = borsh::to_vec(&record).context("encode target JMT record")?;
            ensure!(
                encoded.len() <= TARGET_JMT_MAX_RECORD_BYTES_V1,
                "target JMT record exceeds bounded rehearsal size"
            );
            atomic_create_target_jmt_file_v1(&path, &encoded)?;
            let head = MigrationTargetJmtHeadV1 {
                codec_version: TARGET_JMT_HEAD_CODEC_V1,
                record_digest: record.record_digest,
                target_state_root: record.target_state_root,
            };
            let encoded_head = borsh::to_vec(&head).context("encode target JMT head")?;
            atomic_create_target_jmt_file_v1(&head_path, &encoded_head)?;
            ensure!(
                read_target_jmt_record_v1(&path)? == record,
                "target JMT record readback mismatch"
            );
            ensure!(
                read_target_jmt_head_v1(&head_path)? == head,
                "target JMT head readback mismatch"
            );
        }

        Ok(Self {
            path,
            head_path,
            _lock: lock,
            record,
        })
    }

    /// Opens an existing rehearsal snapshot and verifies its complete
    /// record/head/tree binding. No caller-supplied root is trusted.
    pub fn open_existing_v1(path: impl AsRef<Path>) -> AnyResult<Self> {
        let path = prepare_target_jmt_path_v1(path.as_ref())?;
        ensure!(path.is_file(), "target JMT record does not exist");
        let head_path = target_jmt_sidecar_path_v1(&path, ".head")?;
        let lock_path = target_jmt_sidecar_path_v1(&path, ".lock")?;
        let lock = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .open(&lock_path)
            .with_context(|| format!("open target JMT lock {}", lock_path.display()))?;
        ensure!(
            fs::symlink_metadata(&lock_path)
                .map(|metadata| metadata.is_file())
                .unwrap_or(false),
            "target JMT lock is not a regular file"
        );
        lock.try_lock_exclusive()
            .context("acquire exclusive target JMT rehearsal lock")?;
        let record = read_target_jmt_record_v1(&path)?;
        let head = read_target_jmt_head_v1(&head_path)?;
        ensure!(
            head.record_digest == record.record_digest
                && head.target_state_root == record.target_state_root,
            "target JMT head does not match record"
        );
        Ok(Self {
            path,
            head_path,
            _lock: lock,
            record,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn head_path(&self) -> &Path {
        &self.head_path
    }

    pub const fn commitment_v1(&self) -> MigrationTargetJmtCommitmentV1 {
        MigrationTargetJmtCommitmentV1 {
            source_export_commitment: self.record.source_export_commitment,
            mapping_profile_digest: self.record.mapping_profile_digest,
            target_state_root: StateRoot::new(self.record.target_state_root),
            record_digest: self.record.record_digest,
        }
    }

    /// Returns a verified clone of the persisted tree, not a general
    /// mutation handle.
    pub fn read_tree_v1(&self) -> AnyResult<InMemoryAuthTree> {
        let record = read_target_jmt_record_v1(&self.path)?;
        ensure!(
            record == self.record,
            "target JMT record changed while open"
        );
        InMemoryAuthTree::decode_snapshot(&record.tree_snapshot)
    }
}

/// Convenience function for callers that only need the durable commitment.
pub fn write_target_jmt_rehearsal_v1(
    path: impl AsRef<Path>,
    source: &VerifiedCometStateExportV1,
    mapping: &MigrationMappingV1,
    coordinates: &MigrationTargetReplayCoordinatesV1,
) -> AnyResult<MigrationTargetJmtCommitmentV1> {
    Ok(
        MigrationTargetJmtWriterV1::write_verified_replay_v1(path, source, mapping, coordinates)?
            .commitment_v1(),
    )
}

fn target_jmt_record_digest_v1(record: &MigrationTargetJmtRecordV1) -> AnyResult<[u8; 32]> {
    let mut unsigned = record.clone();
    unsigned.record_digest = [0; 32];
    let bytes = borsh::to_vec(&unsigned).context("encode target JMT record digest preimage")?;
    Ok(hash_domain(TARGET_JMT_HASH_DOMAIN_V1, &[&bytes]))
}

fn validate_target_jmt_record_v1(record: &MigrationTargetJmtRecordV1) -> AnyResult<()> {
    ensure!(
        record.codec_version == TARGET_JMT_RECORD_CODEC_V1,
        "unsupported target JMT record codec"
    );
    ensure!(
        record.source_export_commitment != [0; 32]
            && record.mapping_profile_digest != [0; 32]
            && record.target_genesis_hash != [0; 32]
            && record.target_validator_set_digest != [0; 32]
            && record.application_schema_digest != [0; 32]
            && record.runtime_profile_digest != [0; 32]
            && record.target_state_root != [0; 32]
            && record.record_digest != [0; 32],
        "target JMT record contains a zero commitment"
    );
    let chain_id = trnm_consensus_types::ChainId::from_bytes(&record.target_chain_id)
        .map_err(|_| anyhow!("target JMT record chain id is invalid"))?;
    ensure!(
        !chain_id.as_bytes().is_empty(),
        "target JMT chain id is empty"
    );
    ensure!(
        record.target_protocol_version == trnm_consensus_types::ProtocolVersion::V0.get(),
        "unsupported target JMT protocol version"
    );
    ensure!(
        record.tree_snapshot.len() <= TARGET_JMT_MAX_SNAPSHOT_BYTES_V1,
        "target JMT snapshot exceeds bound"
    );
    ensure!(
        target_jmt_record_digest_v1(record)? == record.record_digest,
        "target JMT record digest mismatch"
    );
    let tree = InMemoryAuthTree::decode_snapshot(&record.tree_snapshot)?;
    ensure!(
        tree.latest_version() == Some(0),
        "target JMT snapshot version is not zero"
    );
    ensure!(
        tree.root_hash(0)
            .is_some_and(|root| root.0 == record.target_state_root),
        "target JMT snapshot root mismatch"
    );
    Ok(())
}

fn prepare_target_jmt_path_v1(path: &Path) -> AnyResult<PathBuf> {
    ensure!(path.is_absolute(), "target JMT path must be absolute");
    ensure!(
        path.components().count() >= 3,
        "target JMT path is too broad"
    );
    let parent = path
        .parent()
        .ok_or_else(|| anyhow!("target JMT path has no parent"))?;
    fs::create_dir_all(parent)
        .with_context(|| format!("create target JMT parent {}", parent.display()))?;
    if let Ok(metadata) = fs::symlink_metadata(path) {
        ensure!(metadata.is_file(), "target JMT path is not a regular file");
    }
    if let Ok(metadata) = fs::symlink_metadata(parent) {
        ensure!(metadata.is_dir(), "target JMT parent is not a directory");
    }
    Ok(path.to_path_buf())
}

fn target_jmt_sidecar_path_v1(path: &Path, suffix: &str) -> AnyResult<PathBuf> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow!("target JMT path has no parent"))?;
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| anyhow!("target JMT path has no UTF-8 file name"))?;
    ensure!(
        !name.is_empty() && !name.starts_with('.'),
        "target JMT file name is invalid"
    );
    Ok(parent.join(format!(".{name}{suffix}")))
}

fn read_target_jmt_record_v1(path: &Path) -> AnyResult<MigrationTargetJmtRecordV1> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("stat target JMT record {}", path.display()))?;
    ensure!(
        metadata.is_file(),
        "target JMT record is not a regular file"
    );
    ensure!(
        metadata.len() as usize <= TARGET_JMT_MAX_RECORD_BYTES_V1,
        "target JMT record exceeds bound"
    );
    let bytes =
        fs::read(path).with_context(|| format!("read target JMT record {}", path.display()))?;
    let record: MigrationTargetJmtRecordV1 =
        borsh::from_slice(&bytes).context("decode target JMT record")?;
    validate_target_jmt_record_v1(&record)?;
    Ok(record)
}

fn read_target_jmt_head_v1(path: &Path) -> AnyResult<MigrationTargetJmtHeadV1> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("stat target JMT head {}", path.display()))?;
    ensure!(metadata.is_file(), "target JMT head is not a regular file");
    let bytes =
        fs::read(path).with_context(|| format!("read target JMT head {}", path.display()))?;
    let head: MigrationTargetJmtHeadV1 =
        borsh::from_slice(&bytes).context("decode target JMT head")?;
    ensure!(
        head.codec_version == TARGET_JMT_HEAD_CODEC_V1,
        "unsupported target JMT head codec"
    );
    ensure!(
        head.record_digest != [0; 32] && head.target_state_root != [0; 32],
        "target JMT head contains zero commitment"
    );
    Ok(head)
}

fn atomic_create_target_jmt_file_v1(path: &Path, bytes: &[u8]) -> AnyResult<()> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow!("target JMT file has no parent"))?;
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| anyhow!("target JMT file has no UTF-8 name"))?;
    let temporary = parent.join(format!(".{name}.tmp-{}", std::process::id()));
    let result = (|| -> std::io::Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        fs::rename(&temporary, path)?;
        if let Ok(directory) = File::open(parent) {
            let _ = directory.sync_all();
        }
        Ok(())
    })();
    if let Err(error) = result {
        let _ = fs::remove_file(&temporary);
        return Err(error)
            .with_context(|| format!("atomically write target JMT file {}", path.display()));
    }
    Ok(())
}

/// Full offline rehearsal: source proof -> target root -> target GenesisQC
/// ceremony. The Ed25519 verifier is intentionally fixed inside this entry
/// point; a permissive test/custom `SignatureVerifier` must not be able to
/// manufacture a seemingly verified migration token. The returned token is
/// inert and cannot activate a node.
pub fn run_migration_rehearsal_v1(
    export: &CometStateExportV1,
    witness: &MigrationSourceFinalityWitnessV1,
    mapping: &MigrationMappingV1,
    manifest: &PocoTargetGenesisManifestV1,
    evidence: &GenesisQcCeremonyEvidenceV1,
    trusted_target_set: &ValidatorSet,
) -> AnyResult<VerifiedPocoTargetGenesisCeremonyV1> {
    trnm_consensus_crypto::validate_validator_set_strict_ed25519_v0(trusted_target_set)
        .map_err(|error| anyhow!(error.to_string()))?;
    let source = verify_source_export_rehearsal_v1(export, witness, mapping)?;
    let projection = source
        .bind_target_projection_from_manifest_v1(manifest)
        .map_err(|error| anyhow!(error.to_string()))?;
    let replay = MigrationTargetReplayVerifierV1::new(mapping)?;
    let verified_projection = projection
        .verify_with_manifest_v1(&source, manifest, &replay)
        .map_err(|error| anyhow!(error.to_string()))?;
    evidence
        .verify_against_target_projection_v1(
            &verified_projection,
            trusted_target_set,
            &trnm_consensus_crypto::StrictEd25519Verifier,
        )
        .map_err(|error| anyhow!(error.to_string()))
}

/// The content-addressed values an independent importer must exchange after
/// a clean rehearsal.  Comparing these values is deliberately stricter than
/// comparing only a target root: it catches source-export, mapping, manifest,
/// projection, or target-quorum divergence between peers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MigrationRehearsalCommitmentsV1 {
    pub source_export_commitment: [u8; 32],
    pub mapping_profile_digest: [u8; 32],
    pub target_state_root: StateRoot,
    pub projection_commitment: [u8; 32],
    pub target_genesis_descriptor_commitment: [u8; 32],
    pub genesis_qc_evidence_commitment: [u8; 32],
}

impl MigrationRehearsalCommitmentsV1 {
    pub fn from_verified(ceremony: &VerifiedPocoTargetGenesisCeremonyV1) -> AnyResult<Self> {
        let projection = ceremony.projection().projection();
        let descriptor_commitment = ceremony
            .evidence()
            .binding()
            .descriptor_v1()
            .commitment_digest_v1()
            .map_err(|error| anyhow!(error.to_string()))?;
        Ok(Self {
            source_export_commitment: projection.source_export_commitment(),
            mapping_profile_digest: projection.mapping_profile_digest(),
            target_state_root: projection.claimed_state_root(),
            projection_commitment: ceremony.projection_commitment(),
            target_genesis_descriptor_commitment: descriptor_commitment,
            genesis_qc_evidence_commitment: ceremony.evidence_commitment(),
        })
    }
}

/// Cross-peer ceremony comparison for the C0 preparation rehearsal.  Each
/// side must have independently run `run_migration_rehearsal_v1`; equal roots
/// alone are not sufficient because two different source exports can replay to
/// the same root.
pub fn compare_cross_peer_rehearsals_v1(
    left: &VerifiedPocoTargetGenesisCeremonyV1,
    right: &VerifiedPocoTargetGenesisCeremonyV1,
) -> AnyResult<MigrationRehearsalCommitmentsV1> {
    let left_commitments = MigrationRehearsalCommitmentsV1::from_verified(left)?;
    let right_commitments = MigrationRehearsalCommitmentsV1::from_verified(right)?;
    ensure!(
        left_commitments == right_commitments,
        "independent migration rehearsals disagree on source/root/GenesisQC commitments"
    );
    Ok(left_commitments)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use trnm_consensus_types::{
        ChainId, CometFinalizedBlockIdentityV1, ConsensusParametersV0, ConsensusPublicKey, Epoch,
        GenesisHash, GenesisQcSignatureShareV1, GenesisQcV0, Height, LegacyCometAppHashV1,
        LegacyCometGenesisHashV1, PocoGenesisV1, ProtocolVersion, Signature64, Validator,
        ValidatorId, ValidatorSet, VotingPower,
    };
    use trnm_finality_types::crypto::sign_hex;
    use trnm_finality_types::{
        BlockHeaderV1, FinalityReceiptV1, MerkleProofV1, QuorumCertificateV1,
        ValidatorDescriptorV1, ValidatorSetV1, ValidatorVoteV1, BLOCK_HEADER_SCHEMA_V1,
        FINALITY_RECEIPT_SCHEMA_V1, VALIDATOR_VOTE_SCHEMA_V1,
    };

    const SOURCE_CHAIN: &str = "comet-source-v1";
    const TARGET_CHAIN: &str = "poco-target-v1";

    fn source_keys() -> [SigningKey; 4] {
        [
            SigningKey::from_bytes(&[0x11; 32]),
            SigningKey::from_bytes(&[0x12; 32]),
            SigningKey::from_bytes(&[0x13; 32]),
            SigningKey::from_bytes(&[0x14; 32]),
        ]
    }

    fn source_set_and_keys() -> (ValidatorSetV1, [SigningKey; 4]) {
        let keys = source_keys();
        let validators = keys
            .iter()
            .enumerate()
            .map(|(index, key)| ValidatorDescriptorV1 {
                validator_id: format!("validator-{index}"),
                public_key_hex: hex::encode(key.verifying_key().to_bytes()),
                vote_endpoint: format!("http://127.0.0.1:{}/v1/vote", 27_000 + index),
                voting_power: 1,
            })
            .collect();
        (
            ValidatorSetV1 {
                validator_set_id: "source-set-v1".to_string(),
                validators,
                quorum_power: 3,
            },
            keys,
        )
    }

    fn source_fixture() -> (
        CometStateExportV1,
        MigrationSourceFinalityWitnessV1,
        MigrationMappingV1,
    ) {
        let (validator_set, keys) = source_set_and_keys();
        let transaction_hash_hex = hex::encode(hash_domain(
            "trnm.migration.fixture.transaction.v1",
            &[b"migration-fixture-tx"],
        ));
        let transaction_leaf = hash_domain(
            "trnm.transaction.leaf.v1",
            &[transaction_hash_hex.as_bytes()],
        );
        let transaction_root_hex = hex::encode(transaction_leaf);
        let header = BlockHeaderV1 {
            schema: BLOCK_HEADER_SCHEMA_V1.to_string(),
            chain_id: SOURCE_CHAIN.to_string(),
            height: 42,
            previous_block_hash_hex: hex::encode([0x21; 32]),
            transaction_root_hex: transaction_root_hex.clone(),
            state_root_hex: hex::encode([0x23; 32]),
            validator_set_id: validator_set.validator_set_id.clone(),
            timestamp_unix_ms: 1_725_000_000,
        };
        let block_hash_hex = hex::encode(header.block_hash().unwrap());
        let signatures = keys
            .iter()
            .enumerate()
            .take(3)
            .map(|(index, key)| ValidatorVoteV1 {
                schema: VALIDATOR_VOTE_SCHEMA_V1.to_string(),
                validator_id: format!("validator-{index}"),
                validator_set_id: validator_set.validator_set_id.clone(),
                height: 42,
                block_hash_hex: block_hash_hex.clone(),
                public_key_hex: hex::encode(key.verifying_key().to_bytes()),
                signature_hex: sign_hex(
                    key,
                    &ValidatorVoteV1::signing_bytes(
                        SOURCE_CHAIN,
                        &validator_set.validator_set_id,
                        42,
                        &block_hash_hex,
                    ),
                ),
            })
            .collect::<Vec<_>>();
        let qc = QuorumCertificateV1 {
            validator_set_id: validator_set.validator_set_id.clone(),
            height: 42,
            block_hash_hex: block_hash_hex.clone(),
            signatures,
        };
        let mut receipt = FinalityReceiptV1 {
            schema: FINALITY_RECEIPT_SCHEMA_V1.to_string(),
            chain_id: SOURCE_CHAIN.to_string(),
            command_id: "migration-cutoff-42".to_string(),
            domain_command_fingerprint_hex: None,
            transaction_hash_hex,
            transaction_index: 0,
            block_height: 42,
            block_hash_hex: block_hash_hex.clone(),
            block_header: header.clone(),
            state_root_hex: header.state_root_hex.clone(),
            transaction_root_hex: header.transaction_root_hex.clone(),
            object_ref: None,
            transaction_inclusion_proof: MerkleProofV1 {
                tree_domain: "trnm.transactions.v1".to_string(),
                leaf_hash_hex: hex::encode(transaction_leaf),
                leaf_index: 0,
                leaf_count: 1,
                steps: Vec::new(),
            },
            object_inclusion_proof: None,
            validator_set_id: validator_set.validator_set_id.clone(),
            quorum_certificate: qc,
            receipt_hash_hex: String::new(),
        };
        receipt.receipt_hash_hex = hex::encode(receipt.compute_receipt_hash().unwrap());

        let mapping = MigrationMappingV1 {
            schema: MIGRATION_MAPPING_SCHEMA_V1.to_string(),
            objects: vec![
                MigrationMappingLeafV1 {
                    key_hex: "01".to_string(),
                    value_hex: "aabb".to_string(),
                },
                MigrationMappingLeafV1 {
                    key_hex: "02".to_string(),
                    value_hex: "cc".to_string(),
                },
            ],
            indexes: vec![MigrationMappingLeafV1 {
                key_hex: "10".to_string(),
                value_hex: "dd".to_string(),
            }],
            receipts: vec![MigrationMappingLeafV1 {
                key_hex: "20".to_string(),
                value_hex: "eeff".to_string(),
            }],
            rejected_objects: vec![MigrationMappingLeafV1 {
                key_hex: "30".to_string(),
                value_hex: "00".to_string(),
            }],
        };
        let roots = mapping_category_roots_v1(&mapping).unwrap();
        let witness = MigrationSourceFinalityWitnessV1 {
            schema: MIGRATION_SOURCE_FINALITY_WITNESS_SCHEMA_V1.to_string(),
            genesis_document_digest_hex: hex::encode([0x31; 32]),
            source_application_id_hex: hex::encode([0x32; 32]),
            source_store_id_hex: hex::encode([0x33; 32]),
            source_application_schema_digest_hex: hex::encode([0x34; 32]),
            source_runtime_profile_digest_hex: hex::encode([0x35; 32]),
            legacy_app_hash_hex: hex::encode([0x36; 32]),
            part_set_total: 1,
            part_set_hash_hex: hex::encode([0x37; 32]),
            receipt,
            validator_set,
        };
        let finality_digest = source_finality_proof_digest_v1(&witness).unwrap();
        let export = CometStateExportV1::new(
            ChainId::new(SOURCE_CHAIN).unwrap(),
            LegacyCometGenesisHashV1::new([0x31; 32]).unwrap(),
            [0x32; 32],
            [0x33; 32],
            Height::new(42),
            CometFinalizedBlockIdentityV1::new(
                witness.receipt.block_header.block_hash().unwrap(),
                1,
                [0x37; 32],
            )
            .unwrap(),
            finality_digest,
            LegacyCometAppHashV1::new([0x36; 32]).unwrap(),
            roots[0],
            roots[1],
            roots[2],
            roots[3],
            source_validator_set_digest_v1(&witness.validator_set).unwrap(),
            [0x34; 32],
            [0x35; 32],
            mapping_profile_digest_v1(&mapping).unwrap(),
        )
        .unwrap();
        (export, witness, mapping)
    }

    fn target_set_and_keys() -> (ValidatorSet, [SigningKey; 4]) {
        let keys = [
            SigningKey::from_bytes(&[0x41; 32]),
            SigningKey::from_bytes(&[0x42; 32]),
            SigningKey::from_bytes(&[0x43; 32]),
            SigningKey::from_bytes(&[0x44; 32]),
        ];
        let mut validators = (0..4)
            .map(|index| {
                Validator::new(
                    ValidatorId::from_bytes(format!("target-validator-{index}").as_bytes())
                        .unwrap(),
                    ConsensusPublicKey::new(keys[index].verifying_key().to_bytes()),
                    VotingPower::new(1).unwrap(),
                )
                .unwrap()
            })
            .collect::<Vec<_>>();
        validators.sort_by_key(Validator::id);
        let parameters = ConsensusParametersV0::reference_shadow_v0();
        let set = ValidatorSet::new(
            GenesisHash::new([0x91; 32]),
            ChainId::new(TARGET_CHAIN).unwrap(),
            ProtocolVersion::V0,
            Epoch::new(0),
            parameters.hash(),
            validators,
        )
        .unwrap();
        (set, keys)
    }

    #[test]
    fn source_finality_mapping_and_target_root_rehearsal_are_concrete() {
        let (export, witness, mapping) = source_fixture();
        let export_bytes = export.try_canonical_bytes_v1().unwrap();
        assert_eq!(
            decode_source_export_exact_v1(&export_bytes).unwrap(),
            export
        );
        let source = verify_source_export_rehearsal_v1(&export, &witness, &mapping).unwrap();
        let (target_set, target_keys) = target_set_and_keys();
        let coordinates = MigrationTargetReplayCoordinatesV1 {
            target_chain_id: target_set.chain_id(),
            target_genesis_hash: target_set.genesis_hash(),
            target_validator_set_digest: target_set.id(),
            target_protocol_version: ProtocolVersion::V0,
            application_schema_digest: [0x61; 32],
            runtime_profile_digest: [0x62; 32],
        };
        let root = recompute_target_state_root_v1(&source, &mapping, &coordinates).unwrap();
        let manifest = PocoTargetGenesisManifestV1::new(
            coordinates.target_chain_id,
            coordinates.target_genesis_hash,
            coordinates.target_validator_set_digest,
            coordinates.target_protocol_version,
            coordinates.application_schema_digest,
            coordinates.runtime_profile_digest,
            root,
        )
        .unwrap();
        let descriptor = PocoGenesisV1::new_from_unverified_export_v1(
            &export,
            coordinates.target_chain_id,
            coordinates.target_genesis_hash,
            manifest.commitment_digest_v1().unwrap(),
            root,
            target_set.id(),
            ProtocolVersion::V0,
        )
        .unwrap();
        let qc = GenesisQcV0::new(
            target_set.genesis_hash(),
            target_set.chain_id(),
            &target_set,
        )
        .unwrap();
        let binding = descriptor
            .bind_genesis_qc_v1_with_trusted_set(qc, &target_set)
            .unwrap();
        let ids = target_set
            .validators()
            .iter()
            .take(3)
            .map(Validator::id)
            .collect::<Vec<_>>();
        let unsigned = GenesisQcCeremonyEvidenceV1::new(
            binding.clone(),
            ids.iter()
                .map(|id| {
                    GenesisQcSignatureShareV1::new(*id, Signature64::from_array([0; 64])).unwrap()
                })
                .collect(),
        )
        .unwrap();
        let signing_root = unsigned.signing_root_v1().unwrap();
        let evidence = GenesisQcCeremonyEvidenceV1::new(
            binding,
            ids.iter()
                .map(|id| {
                    let index = target_set
                        .validators()
                        .iter()
                        .position(|validator| validator.id() == *id)
                        .unwrap();
                    let signature = target_keys[index].sign(signing_root.as_bytes());
                    GenesisQcSignatureShareV1::new(
                        *id,
                        Signature64::from_array(signature.to_bytes()),
                    )
                    .unwrap()
                })
                .collect(),
        )
        .unwrap();
        let verified = run_migration_rehearsal_v1(
            &export,
            &witness,
            &mapping,
            &manifest,
            &evidence,
            &target_set,
        )
        .unwrap();
        // The second peer consumes freshly decoded canonical artifacts rather
        // than sharing in-memory references with the first run.
        let replayed_export = decode_source_export_exact_v1(&export_bytes).unwrap();
        let replayed_witness =
            decode_source_finality_witness_json_v1(&serde_json::to_vec(&witness).unwrap()).unwrap();
        let replayed_mapping =
            decode_mapping_json_v1(&serde_json::to_vec(&mapping).unwrap()).unwrap();
        let second_verified = run_migration_rehearsal_v1(
            &replayed_export,
            &replayed_witness,
            &replayed_mapping,
            &manifest,
            &evidence,
            &target_set,
        )
        .unwrap();
        let commitments = compare_cross_peer_rehearsals_v1(&verified, &second_verified).unwrap();
        assert_eq!(commitments.target_state_root, root);
        assert_eq!(
            verified.projection().projection().claimed_state_root(),
            root
        );

        // A ceremony share is bound to the descriptor/projection signing root;
        // changing one byte cannot be laundered through the type-state token.
        let mut tampered_shares = evidence.signatures().to_vec();
        let first = &tampered_shares[0];
        let mut tampered_signature = *first.signature().as_bytes();
        tampered_signature[0] ^= 1;
        tampered_shares[0] = GenesisQcSignatureShareV1::new(
            first.validator_id(),
            Signature64::from_array(tampered_signature),
        )
        .unwrap();
        let tampered_evidence =
            GenesisQcCeremonyEvidenceV1::new(evidence.binding().clone(), tampered_shares).unwrap();
        assert!(run_migration_rehearsal_v1(
            &export,
            &witness,
            &mapping,
            &manifest,
            &tampered_evidence,
            &target_set,
        )
        .is_err());
    }

    #[test]
    fn tampered_source_signature_is_rejected() {
        let (export, mut witness, mapping) = source_fixture();
        let signature = &mut witness.receipt.quorum_certificate.signatures[0].signature_hex;
        let mut bytes = hex::decode(signature.as_str()).unwrap();
        bytes[0] ^= 1;
        *signature = hex::encode(bytes);
        assert!(verify_source_export_rehearsal_v1(&export, &witness, &mapping).is_err());
    }

    #[test]
    fn tampered_source_inclusion_proof_is_rejected() {
        let (export, mut witness, mapping) = source_fixture();
        witness.receipt.transaction_inclusion_proof.leaf_hash_hex = hex::encode([0xFA; 32]);
        assert!(verify_source_export_rehearsal_v1(&export, &witness, &mapping).is_err());
    }

    #[test]
    fn unsorted_or_duplicate_mapping_is_rejected() {
        let (export, witness, mut mapping) = source_fixture();
        mapping.objects.swap(0, 1);
        assert!(verify_source_export_rehearsal_v1(&export, &witness, &mapping).is_err());
        let (_, _, mut duplicate) = source_fixture();
        duplicate.objects.push(duplicate.objects[0].clone());
        assert!(mapping_category_roots_v1(&duplicate).is_err());
    }

    #[test]
    fn source_validator_and_signer_order_is_canonical() {
        let (export, mut witness, mapping) = source_fixture();
        witness.validator_set.validators.swap(0, 1);
        let error = verify_source_export_rehearsal_v1(&export, &witness, &mapping).unwrap_err();
        assert!(error
            .to_string()
            .contains("validator set must be strictly ordered"));

        let (export, mut witness, mapping) = source_fixture();
        witness.receipt.quorum_certificate.signatures.swap(0, 1);
        let error = verify_source_export_rehearsal_v1(&export, &witness, &mapping).unwrap_err();
        assert!(error
            .to_string()
            .contains("quorum certificate signatures must be strictly ordered"));

        let (export, mut witness, mapping) = source_fixture();
        witness.validator_set.validators[1].validator_id =
            witness.validator_set.validators[0].validator_id.clone();
        let error = verify_source_export_rehearsal_v1(&export, &witness, &mapping).unwrap_err();
        assert!(error.to_string().contains("duplicate validator_id"));
    }

    #[test]
    fn claimed_target_root_mismatch_is_rejected() {
        let (export, witness, mapping) = source_fixture();
        let source = verify_source_export_rehearsal_v1(&export, &witness, &mapping).unwrap();
        let (target_set, _) = target_set_and_keys();
        let coordinates = MigrationTargetReplayCoordinatesV1 {
            target_chain_id: target_set.chain_id(),
            target_genesis_hash: target_set.genesis_hash(),
            target_validator_set_digest: target_set.id(),
            target_protocol_version: ProtocolVersion::V0,
            application_schema_digest: [0x61; 32],
            runtime_profile_digest: [0x62; 32],
        };
        let root = recompute_target_state_root_v1(&source, &mapping, &coordinates).unwrap();
        let manifest = PocoTargetGenesisManifestV1::new(
            coordinates.target_chain_id,
            coordinates.target_genesis_hash,
            coordinates.target_validator_set_digest,
            coordinates.target_protocol_version,
            coordinates.application_schema_digest,
            coordinates.runtime_profile_digest,
            StateRoot::new([0xFE; 32]),
        )
        .unwrap();
        assert_ne!(root, manifest.initial_state_root());
        assert!(verify_target_projection_rehearsal_v1(&source, &mapping, &manifest).is_err());
    }

    #[test]
    fn strict_json_decoder_rejects_duplicate_nested_keys() {
        let top_level = br#"{"schema":"one","schema":"two"}"#;
        assert!(decode_json_strict_v1::<serde_json::Value>(top_level).is_err());
        let nested = br#"{"outer":{"key":1,"key":2}}"#;
        assert!(decode_json_strict_v1::<serde_json::Value>(nested).is_err());
        // The ordinary serde_json parser is intentionally shown as a contrast:
        // it keeps the final duplicate value, so callers must use this helper.
        let permissive: serde_json::Value = serde_json::from_slice(top_level).unwrap();
        assert_eq!(permissive["schema"], "two");
    }

    #[test]
    fn strict_json_decoder_rejects_excessive_nesting_before_serde() {
        let mut deeply_nested = Vec::with_capacity(MAX_MIGRATION_JSON_DEPTH * 2 + 1);
        deeply_nested.extend(std::iter::repeat_n(b'[', MAX_MIGRATION_JSON_DEPTH + 1));
        deeply_nested.push(b'0');
        deeply_nested.extend(std::iter::repeat_n(b']', MAX_MIGRATION_JSON_DEPTH + 1));
        let error = decode_json_strict_v1::<serde_json::Value>(&deeply_nested).unwrap_err();
        assert!(error.to_string().contains("maximum depth"));
    }

    #[test]
    fn strict_json_decoder_rejects_container_and_node_budget_overruns() {
        let mut oversized_array = Vec::with_capacity(MAX_MIGRATION_JSON_CONTAINER_ITEMS * 2);
        oversized_array.push(b'[');
        for index in 0..=MAX_MIGRATION_JSON_CONTAINER_ITEMS {
            if index != 0 {
                oversized_array.push(b',');
            }
            oversized_array.push(b'0');
        }
        oversized_array.push(b']');
        let error = decode_json_strict_v1::<serde_json::Value>(&oversized_array).unwrap_err();
        assert!(error.to_string().contains("container"));

        // Keep the outer container below its one-million-item budget while
        // exceeding the global node budget with four scalar members per
        // object.  This exercises the two limits independently.
        const NODES_PER_OBJECT: usize = 5; // object + four scalar values
        let object_count = (MAX_MIGRATION_JSON_NODES - 1) / NODES_PER_OBJECT + 1;
        let mut oversized_nodes = Vec::with_capacity(object_count * 28);
        oversized_nodes.push(b'[');
        for index in 0..object_count {
            if index != 0 {
                oversized_nodes.push(b',');
            }
            oversized_nodes.extend_from_slice(br#"{"a":0,"b":0,"c":0,"d":0}"#);
        }
        oversized_nodes.push(b']');
        let error = decode_json_strict_v1::<serde_json::Value>(&oversized_nodes).unwrap_err();
        assert!(error.to_string().contains("structural nodes"));
    }

    #[test]
    fn target_jmt_writer_persists_reopens_and_rejects_divergence() {
        let (export, witness, mapping) = source_fixture();
        let source = verify_source_export_rehearsal_v1(&export, &witness, &mapping).unwrap();
        let (target_set, _) = target_set_and_keys();
        let coordinates = MigrationTargetReplayCoordinatesV1 {
            target_chain_id: target_set.chain_id(),
            target_genesis_hash: target_set.genesis_hash(),
            target_validator_set_digest: target_set.id(),
            target_protocol_version: ProtocolVersion::V0,
            application_schema_digest: [0x61; 32],
            runtime_profile_digest: [0x62; 32],
        };
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let parent = std::env::temp_dir().join(format!(
            "trnm-migration-target-jmt-{}-{unique}",
            std::process::id()
        ));
        let path = parent.join("target.jmt");
        let commitment = write_target_jmt_rehearsal_v1(&path, &source, &mapping, &coordinates)
            .expect("write durable target replay");
        let reopened =
            MigrationTargetJmtWriterV1::open_existing_v1(&path).expect("reopen target replay");
        assert_eq!(reopened.commitment_v1(), commitment);
        let tree = reopened.read_tree_v1().expect("read back target tree");
        assert_eq!(
            tree.root_hash(0).map(|root| StateRoot::new(root.0)),
            Some(commitment.target_state_root)
        );
        drop(reopened);

        // A changed target coordinate cannot overwrite an existing source
        // commitment, even when the caller uses the same output pathname.
        let changed = MigrationTargetReplayCoordinatesV1 {
            target_chain_id: ChainId::new("poco-target-other-v1").unwrap(),
            ..coordinates
        };
        assert!(write_target_jmt_rehearsal_v1(&path, &source, &mapping, &changed).is_err());

        // Corrupting the record is detected by the self-authenticating digest
        // before the snapshot can be exposed.
        let mut bytes = fs::read(&path).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 1;
        fs::write(&path, bytes).unwrap();
        assert!(MigrationTargetJmtWriterV1::open_existing_v1(&path).is_err());

        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(parent.join(".target.jmt.head"));
        let _ = fs::remove_file(parent.join(".target.jmt.lock"));
        let _ = fs::remove_dir(&parent);
    }
}
