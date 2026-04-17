use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use thiserror::Error;
use trnm_types::{ProofType, TaskObject};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationBackendFamily {
    Tee,
    Zk,
}

impl VerificationBackendFamily {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Tee => "tee",
            Self::Zk => "zk",
        }
    }

    pub fn from_proof_type(proof_type: ProofType) -> Option<Self> {
        match proof_type {
            ProofType::Fraud => None,
            ProofType::Tee => Some(Self::Tee),
            ProofType::Zk => Some(Self::Zk),
        }
    }
}

impl std::fmt::Display for VerificationBackendFamily {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerificationBackendKind {
    Noop,
    Custom(String),
}

impl Default for VerificationBackendKind {
    fn default() -> Self {
        Self::Noop
    }
}

impl VerificationBackendKind {
    pub fn key(&self) -> &str {
        match self {
            Self::Noop => "noop",
            Self::Custom(key) => key.as_str(),
        }
    }

    pub fn normalized_key(&self) -> String {
        self.key().trim().to_ascii_lowercase()
    }

    pub fn system_hint(&self) -> Option<String> {
        backend_system_hint(self.key())
    }
}

pub fn normalize_backend_token(raw: &str) -> Option<String> {
    let normalized = raw
        .trim()
        .to_ascii_lowercase()
        .chars()
        .map(|ch| if ch.is_ascii_alphanumeric() { ch } else { ' ' })
        .collect::<String>();
    let collapsed = normalized.split_whitespace().collect::<Vec<_>>().join(" ");
    if collapsed.is_empty() || collapsed == "noop" {
        None
    } else {
        Some(collapsed)
    }
}

pub fn contains_forbidden_opaque_token_chars(raw: &str) -> bool {
    raw.chars()
        .any(|ch| !ch.is_ascii() || ch.is_whitespace() || ch.is_control())
}

pub fn backend_token_family_hint(raw: &str) -> Option<VerificationBackendFamily> {
    let normalized = normalize_backend_token(raw)?;
    match normalized.split_whitespace().next()? {
        "zk" => Some(VerificationBackendFamily::Zk),
        "tee" => Some(VerificationBackendFamily::Tee),
        _ => None,
    }
}

pub fn backend_system_hint(raw: &str) -> Option<String> {
    let normalized = normalize_backend_token(raw)?;
    let parts = normalized.split_whitespace().collect::<Vec<_>>();

    match parts.as_slice() {
        ["zk", system, ..] | ["tee", system, ..] => normalize_zk_system(system),
        [system, ..] => normalize_zk_system(system),
        _ => None,
    }
}

pub fn normalize_zk_system(raw: &str) -> Option<String> {
    let normalized = raw
        .trim()
        .to_ascii_lowercase()
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .collect::<String>();

    match normalized.as_str() {
        "groth16" | "plonk" | "halo2" | "stark" | "risc0" | "sp1" => Some(normalized),
        _ => None,
    }
}

pub fn backend_token_zk_system_hints(raw: &str) -> Vec<String> {
    let mut seen = HashSet::new();
    normalize_backend_token(raw)
        .into_iter()
        .flat_map(|token| {
            token
                .split_whitespace()
                .filter_map(normalize_zk_system)
                .filter(|system| seen.insert(system.clone()))
                .collect::<Vec<_>>()
        })
        .collect()
}

/// Back-compat alias kept because current verification wiring and tests already
/// speak in ZK-oriented terms, even though the platform registry now serves both
/// TEE and ZK families.
pub type ZkBackendKind = VerificationBackendKind;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZkFeatureFlags {
    pub zk_platform_v0: bool,
    pub zk_backend_router: bool,
    pub zk_payload_v0_envelope: bool,
    // RETIRE-R2 tracked in:
    // docs/release/TRNM_POCO_BEHAVIOR_RISK_RETIREMENT_PLAN_2026-04-15.md
    // Second-round hard cut: default launch path is now compatibility-closed for legacy receipt
    // aliases. Replay/import flows must opt back in explicitly if they still need old shapes.
    pub zk_allow_legacy_receipt_aliases: bool,
    pub zk_allow_backend_fallback: bool,
    pub zk_explicit_backend_required: bool,
}

impl Default for ZkFeatureFlags {
    fn default() -> Self {
        Self {
            zk_platform_v0: false,
            zk_backend_router: false,
            zk_payload_v0_envelope: false,
            zk_allow_legacy_receipt_aliases: false,
            zk_allow_backend_fallback: false,
            zk_explicit_backend_required: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerificationBackendConfig {
    pub tee_backend: VerificationBackendKind,
    pub zk_backend: VerificationBackendKind,
    pub zk_features: ZkFeatureFlags,
}

impl Default for VerificationBackendConfig {
    fn default() -> Self {
        Self {
            tee_backend: VerificationBackendKind::Noop,
            zk_backend: VerificationBackendKind::Noop,
            zk_features: ZkFeatureFlags::default(),
        }
    }
}

impl VerificationBackendConfig {
    /// Selects the configured backend kind for a verification family.
    pub fn kind_for_family(&self, family: VerificationBackendFamily) -> &VerificationBackendKind {
        match family {
            VerificationBackendFamily::Tee => &self.tee_backend,
            VerificationBackendFamily::Zk => &self.zk_backend,
        }
    }

    /// Returns the backend selector for a proof type when that proof family is
    /// backend-capable. Fraud stays backendless by design.
    pub fn kind_for_proof_type(&self, proof_type: ProofType) -> Option<&VerificationBackendKind> {
        VerificationBackendFamily::from_proof_type(proof_type)
            .map(|family| self.kind_for_family(family))
    }
}
