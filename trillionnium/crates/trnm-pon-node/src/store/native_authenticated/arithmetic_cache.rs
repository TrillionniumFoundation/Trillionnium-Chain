//! Optional arithmetic memoization owned by one native Node. No database read,
//! validity verdict, block selection or ancestry is cached here. The separate
//! history material binds codec/hash results to complete current SQL bytes.
#[cfg(test)]
use super::complete;
use super::StateCommitment;
use crate::account_archive_execution::state_witness::commitment_from_complete_state_with_lifts;
use crate::account_archive_prototype::native_store::LiftCache;
use crate::{Result, Settings};
use std::cell::RefCell;
use std::collections::VecDeque;
use std::io::{self, Write};
use trnm_mvcc_fee::pon_executor::State;
use trnm_protocol::pon_wire::Hash;

// The normal parent, child and genesis may all be revisited during one commit.
const MAX_COMPLETE_ENTRIES: usize = 3;
const MAX_COMPLETE_BYTES: usize = 4 * 1024 * 1024;

struct CompleteEntry {
    context: [Hash; 3],
    bytes: Vec<u8>,
    value: StateCommitment,
}

// One independent root arithmetic entry keeps the repeated genesis root from
// depending on parent/child complete-commitment eviction. It owns at most the
// same 4 MiB exact-input bound and contains no database identity or verdict.
struct RootEntry {
    context: [Hash; 3],
    bytes: Vec<u8>,
    value: Hash,
}

#[derive(Default)]
pub(crate) struct ArithmeticCache {
    complete: RefCell<VecDeque<CompleteEntry>>,
    root: RefCell<Option<RootEntry>>,
    pub(crate) lifts: LiftCache,
    pub(crate) history: super::history_arithmetic::HistoryArithmetic,
    #[cfg(test)]
    hits: std::cell::Cell<usize>,
    #[cfg(test)]
    root_hits: std::cell::Cell<usize>,
}

impl ArithmeticCache {
    /// Reuse only the full root already computed from these exact complete
    /// actual bytes. Unlike `complete`, a miss does not run account/conservation
    /// checks before the original state-root grammar or change its error order.
    /// Caller-owned State is serialized anew; no SQL observation is reused.
    pub(crate) fn state_root(&self, settings: &Settings, state: &State) -> Result<Hash> {
        let context = [
            settings.network(),
            settings.parameters(),
            settings.genesis(),
        ];
        let bytes = bounded_bytes(state);
        if let (Some(bytes), Ok(entries)) = (bytes.as_ref(), self.complete.try_borrow()) {
            if let Some(entry) = entries.iter().find(|entry| {
                entry.context == context && entry.bytes.as_slice() == bytes.as_slice()
            }) {
                #[cfg(test)]
                self.root_hits.set(self.root_hits.get() + 1);
                return Ok(entry.value.state_root);
            }
        }
        if let (Some(bytes), Ok(root)) = (bytes.as_ref(), self.root.try_borrow()) {
            if let Some(entry) = root.as_ref().filter(|entry| {
                entry.context == context && entry.bytes.as_slice() == bytes.as_slice()
            }) {
                #[cfg(test)]
                self.root_hits.set(self.root_hits.get() + 1);
                return Ok(entry.value);
            }
        }
        let value = trnm_mvcc_fee::pon_executor::root(state).map_err(crate::Error::from)?;
        if let (Some(bytes), Ok(mut entry)) = (bytes, self.root.try_borrow_mut()) {
            *entry = Some(RootEntry {
                context,
                bytes,
                value,
            });
        }
        Ok(value)
    }

    pub(crate) fn complete(&self, settings: &Settings, state: &State) -> Result<StateCommitment> {
        let context = [
            settings.network(),
            settings.parameters(),
            settings.genesis(),
        ];
        // Serialize actual complete input, not a caller's root or Value equality:
        // signed zero and integer/float representations must remain distinct.
        // Oversize input uses the original full calculation without retention.
        let bytes = bounded_bytes(state);
        if let (Some(bytes), Ok(entries)) = (bytes.as_ref(), self.complete.try_borrow()) {
            if let Some(entry) = entries.iter().find(|entry| {
                entry.context == context && entry.bytes.as_slice() == bytes.as_slice()
            }) {
                #[cfg(test)]
                self.hits.set(self.hits.get() + 1);
                return Ok(entry.value.clone());
            }
        }
        let value = commitment_from_complete_state_with_lifts(settings, state, Some(&self.lifts))
            .map_err(|error| {
            crate::Error::from(format!("NATIVE_STATE_COMMITMENT:{error:?}")).local_integrity()
        })?;
        if let (Some(bytes), Ok(mut entries)) = (bytes, self.complete.try_borrow_mut()) {
            if entries.len() == MAX_COMPLETE_ENTRIES {
                entries.pop_front();
            }
            entries.push_back(CompleteEntry {
                context,
                bytes,
                value: value.clone(),
            });
        }
        Ok(value)
    }
}

struct BoundedBytes(Vec<u8>);
impl Write for BoundedBytes {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self
            .0
            .len()
            .checked_add(bytes.len())
            .is_none_or(|n| n > MAX_COMPLETE_BYTES)
        {
            return Err(io::Error::other("arithmetic input retention bound"));
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
fn bounded_bytes(state: &State) -> Option<Vec<u8>> {
    let mut bytes = BoundedBytes(Vec::new());
    serde_json::to_writer(&mut bytes, state).ok()?;
    Some(bytes.0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn arithmetic_cache_binds_exact_complete_bytes_context_and_has_fixed_retention() {
        let settings = Settings::development(Some(1000)).unwrap();
        let other = Settings::development(Some(1001)).unwrap();
        let cache = ArithmeticCache::default();
        let first = cache.complete(&settings, &settings.initial).unwrap();
        assert_eq!(cache.complete(&settings, &settings.initial).unwrap(), first);
        assert_eq!(cache.hits.get(), 1);
        let foreign = cache.complete(&other, &settings.initial).unwrap();
        assert_eq!(foreign, complete(&other, &settings.initial).unwrap());
        assert_ne!(foreign.genesis, first.genesis);
        assert_eq!(cache.hits.get(), 1);
        for marker in 0..5 {
            let mut changed = settings.initial.clone();
            changed.insert("arithmetic-cache-test".into(), json!(marker));
            assert_eq!(
                cache.complete(&settings, &changed).unwrap(),
                complete(&settings, &changed).unwrap()
            );
            assert!(cache.complete.borrow().len() <= MAX_COMPLETE_ENTRIES);
        }
        let retained = cache.complete.borrow();
        assert!(retained
            .iter()
            .all(|entry| entry.bytes.len() <= MAX_COMPLETE_BYTES));
        assert_eq!(retained.len(), MAX_COMPLETE_ENTRIES);
    }

    #[test]
    fn arithmetic_cache_preserves_exact_numeric_encoding_and_invalid_input_errors() {
        let settings = Settings::development(Some(1000)).unwrap();
        let cache = ArithmeticCache::default();
        let mut state = settings.initial.clone();
        let mut encodings = Vec::new();
        for number in [json!(0), json!(0.0), json!(-0.0)] {
            state.insert("arithmetic-cache-test".into(), number);
            encodings.push(bounded_bytes(&state).unwrap());
            match (
                cache.complete(&settings, &state),
                complete(&settings, &state),
            ) {
                (Ok(cached), Ok(reference)) => assert_eq!(cached, reference),
                (Err(cached), Err(reference)) => {
                    // The installed root rejects float encodings with RANGE;
                    // a cached integer zero must never promote either float.
                    assert_eq!(cached.to_string(), reference.to_string());
                    assert_eq!(cached.kind(), reference.kind());
                }
                _ => panic!("warm arithmetic changed the reference acceptance"),
            }
        }
        assert_ne!(encodings[0], encodings[1]);
        assert_ne!(encodings[1], encodings[2]);
        assert_eq!(cache.hits.get(), 0);
        state.insert(
            "account:malformed".into(),
            json!({"balance": 1, "nonce": 0}),
        );
        assert_eq!(
            cache.complete(&settings, &state).unwrap_err().to_string(),
            complete(&settings, &state).unwrap_err().to_string()
        );
        let oversized = State::from([("large".into(), json!("x".repeat(MAX_COMPLETE_BYTES)))]);
        assert!(bounded_bytes(&oversized).is_none());
    }

    #[test]
    fn full_root_reuse_compares_actual_bytes_and_keeps_original_error_order() {
        let settings = Settings::development(Some(1000)).unwrap();
        let cache = ArithmeticCache::default();
        let first = cache.complete(&settings, &settings.initial).unwrap();
        assert_eq!(
            cache.state_root(&settings, &settings.initial).unwrap(),
            first.state_root
        );
        assert_eq!(cache.root_hits.get(), 1);
        let other = Settings::development(Some(1001)).unwrap();
        assert_eq!(
            cache.state_root(&other, &settings.initial).unwrap(),
            first.state_root
        );
        assert_eq!(cache.root_hits.get(), 1);
        for value in [
            json!(0),
            json!(0.0),
            json!(-0.0),
            json!({"balance": 1, "nonce": 0}),
        ] {
            let mut changed = settings.initial.clone();
            changed.insert("account:malformed".into(), value);
            let observed = cache.state_root(&settings, &changed);
            let reference = trnm_mvcc_fee::pon_executor::root(&changed).map_err(crate::Error::from);
            match (observed, reference) {
                (Ok(left), Ok(right)) => assert_eq!(left, right),
                (Err(left), Err(right)) => {
                    assert_eq!(left.to_string(), right.to_string());
                    assert_eq!(left.kind(), right.kind());
                }
                _ => panic!("exact-input root reuse changed the original acceptance"),
            }
        }
        assert_eq!(cache.root_hits.get(), 1);
        assert_eq!(
            cache.state_root(&settings, &settings.initial).unwrap(),
            first.state_root
        );
        assert_eq!(cache.root_hits.get(), 2);
    }

    #[test]
    fn separate_root_arithmetic_entry_survives_complete_eviction_and_is_bounded() {
        let settings = Settings::development(Some(1000)).unwrap();
        let cache = ArithmeticCache::default();
        let genesis_root = cache.state_root(&settings, &settings.initial).unwrap();
        for marker in 0..5 {
            let mut changed = settings.initial.clone();
            changed.insert("arithmetic-cache-test".into(), json!(marker));
            cache.complete(&settings, &changed).unwrap();
        }
        assert_eq!(
            cache.state_root(&settings, &settings.initial).unwrap(),
            genesis_root
        );
        assert_eq!(cache.root_hits.get(), 1);
        assert_eq!(cache.complete.borrow().len(), MAX_COMPLETE_ENTRIES);
        assert!(cache.root.borrow().as_ref().unwrap().bytes.len() <= MAX_COMPLETE_BYTES);
        let mut changed = settings.clone();
        changed.initial.insert("root-only-input".into(), json!(1));
        let expected = trnm_mvcc_fee::pon_executor::root(&changed.initial).unwrap();
        assert_ne!(expected, genesis_root);
        assert_eq!(
            cache.state_root(&changed, &changed.initial).unwrap(),
            expected
        );
        assert_eq!(cache.root_hits.get(), 1);
        assert_eq!(
            cache.state_root(&changed, &changed.initial).unwrap(),
            expected
        );
        assert_eq!(cache.root_hits.get(), 2);
        // Invalid inputs cannot replace an exact successful entry.
        let retained = cache.root.borrow().as_ref().unwrap().bytes.clone();
        changed
            .initial
            .insert("root-only-input".into(), json!(-0.0));
        assert!(cache.state_root(&changed, &changed.initial).is_err());
        assert_eq!(cache.root.borrow().as_ref().unwrap().bytes, retained);
    }
}
