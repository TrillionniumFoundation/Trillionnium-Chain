//! Frozen-v0 authenticated-key and write primitives used by the native engine.
//!
//! This is an active, zero-Comet extraction of the consensus key format.  It
//! deliberately exposes only canonical key construction and inert writes;
//! JMT planning and persistence remain owned by the native execution store.

#![allow(dead_code)]

use anyhow::{ensure, Context, Result};

use crate::poco_transition::PocoWritePermitV0;

const KEY_DOMAIN: &[u8] = b"trnm/authenticated-state/v4";
const POCO_SNAPSHOT_KEY_PREFIX: &[u8] = b"trnm/authenticated-state/v4\0\x08";

/// Consensus-state namespace discriminants are frozen wire/state values.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub(crate) enum StateNamespace {
    Object = 1,
    ValidatorLifecycle = 4,
    PocoSnapshot = 8,
}

pub(crate) fn namespaced_key(namespace: StateNamespace, components: &[&[u8]]) -> Result<Vec<u8>> {
    ensure!(
        !components.is_empty(),
        "authenticated key needs a component"
    );
    ensure!(
        components.len() <= u16::MAX as usize,
        "too many authenticated key components"
    );
    let mut key = Vec::with_capacity(KEY_DOMAIN.len() + 8);
    key.extend_from_slice(KEY_DOMAIN);
    key.push(0);
    key.push(namespace as u8);
    key.extend_from_slice(&(components.len() as u16).to_be_bytes());
    for component in components {
        ensure!(
            !component.is_empty(),
            "authenticated key components must be non-empty"
        );
        let len = u32::try_from(component.len())
            .context("authenticated key component exceeds u32::MAX bytes")?;
        key.extend_from_slice(&len.to_be_bytes());
        key.extend_from_slice(component);
    }
    Ok(key)
}

pub(crate) fn validator_state_key() -> Result<Vec<u8>> {
    namespaced_key(StateNamespace::ValidatorLifecycle, &[b"current"])
}

pub(crate) fn poco_snapshot_key_components(key: &[u8]) -> Result<Option<Vec<&[u8]>>> {
    if !key.starts_with(POCO_SNAPSHOT_KEY_PREFIX) {
        return Ok(None);
    }
    let mut cursor = POCO_SNAPSHOT_KEY_PREFIX.len();
    ensure!(
        key.len() >= cursor.saturating_add(2),
        "PoCO snapshot key component count is truncated"
    );
    let component_count = u16::from_be_bytes(
        key[cursor..cursor + 2]
            .try_into()
            .expect("component count length checked"),
    ) as usize;
    cursor += 2;
    ensure!(
        (1..=3).contains(&component_count),
        "PoCO snapshot key component count is invalid"
    );
    let mut components = Vec::with_capacity(component_count);
    for _ in 0..component_count {
        ensure!(
            key.len() >= cursor.saturating_add(4),
            "PoCO snapshot key component length is truncated"
        );
        let length = u32::from_be_bytes(
            key[cursor..cursor + 4]
                .try_into()
                .expect("component length checked"),
        ) as usize;
        cursor += 4;
        ensure!(length > 0, "PoCO snapshot key component is empty");
        let end = cursor
            .checked_add(length)
            .context("PoCO snapshot key component length overflow")?;
        ensure!(end <= key.len(), "PoCO snapshot key component is truncated");
        components.push(&key[cursor..end]);
        cursor = end;
    }
    ensure!(cursor == key.len(), "PoCO snapshot key has trailing bytes");
    Ok(Some(components))
}

/// Inert canonical write.  Construction of namespace-8 writes is gated by
/// the private PoCO planner permit; no write is itself execution authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct AuthWrite {
    key: Vec<u8>,
    value: Option<Vec<u8>>,
}

impl AuthWrite {
    pub(crate) fn put(key: Vec<u8>, value: Vec<u8>) -> Result<Self> {
        ensure!(!key.is_empty(), "authenticated key must be non-empty");
        ensure!(
            !key.starts_with(POCO_SNAPSHOT_KEY_PREFIX),
            "PoCO snapshot writes require the atomic PoCO planner"
        );
        Ok(Self {
            key,
            value: Some(value),
        })
    }

    pub(crate) fn put_poco_snapshot(
        _permit: PocoWritePermitV0,
        key: Vec<u8>,
        value: Vec<u8>,
    ) -> Result<Self> {
        ensure!(
            key.starts_with(POCO_SNAPSHOT_KEY_PREFIX),
            "sealed PoCO write is outside the PoCO snapshot namespace"
        );
        Ok(Self {
            key,
            value: Some(value),
        })
    }

    pub(crate) fn delete_poco_snapshot(_permit: PocoWritePermitV0, key: Vec<u8>) -> Result<Self> {
        ensure!(
            key.starts_with(POCO_SNAPSHOT_KEY_PREFIX),
            "sealed PoCO delete is outside the PoCO snapshot namespace"
        );
        Ok(Self { key, value: None })
    }

    pub(crate) fn key(&self) -> &[u8] {
        &self.key
    }

    pub(crate) fn value(&self) -> Option<&[u8]> {
        self.value.as_deref()
    }
}
