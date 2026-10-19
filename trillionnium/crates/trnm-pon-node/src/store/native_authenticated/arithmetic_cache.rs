//! Optional arithmetic memoization owned by one native Node. No database read,
//! parsed record, validity verdict, block selection or history is cached here.
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

#[derive(Default)]
pub(crate) struct ArithmeticCache {
    complete: RefCell<VecDeque<CompleteEntry>>,
    pub(crate) lifts: LiftCache,
    #[cfg(test)]
    hits: std::cell::Cell<usize>,
}

impl ArithmeticCache {
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
}
