//! Optional arithmetic memoization owned by one native Node. No database read,
//! validity verdict, block selection or ancestry is cached here. The separate
//! history material binds codec/hash results to complete current SQL bytes.
#[cfg(test)]
use super::complete;
use super::StateCommitment;
use crate::account_archive_execution::state_witness::commitment_from_complete_state_with_root;
use crate::account_archive_prototype::native_store::LiftCache;
use crate::{Result, Settings};
use std::cell::RefCell;
use std::collections::VecDeque;
use std::io::{self, Write};
use trnm_mvcc_fee::pon_executor::State;
use trnm_protocol::pon_wire::Hash;

mod root_arithmetic;
use root_arithmetic::RootArithmetic;

// The normal parent, child and genesis may all be revisited during one commit.
const MAX_COMPLETE_ENTRIES: usize = 3;
const MAX_COMPLETE_BYTES: usize = 4 * 1024 * 1024;

struct CompleteEntry {
    context: [Hash; 3],
    bytes: Vec<u8>,
    value: StateCommitment,
}

// One independent root arithmetic entry retains only the actual initial State.
// Historical parent/child roots must not replace it during unactivated branch
// import. It owns the same 4 MiB exact-input bound and no database verdict.
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
    root_arithmetic: RootArithmetic,
    #[cfg(test)]
    hits: std::cell::Cell<usize>,
    #[cfg(test)]
    root_hits: std::cell::Cell<usize>,
}

impl ArithmeticCache {
    /// Opaque M06 tree material only. Its private canonical map is re-compared
    /// with the complete actual State at the original root-calculation point.
    pub(crate) fn offer_root_material(
        &self,
        settings: &Settings,
        snapshot: Option<&trnm_mvcc_fee::pon_commitment::CheckedCommitment>,
    ) {
        self.root_arithmetic.offer(settings, snapshot);
    }

    pub(crate) fn observation(&self) -> serde_json::Value {
        let mut value = self.history.observation();
        value["complete_root_arithmetic"] = self.root_arithmetic.observation();
        value["account_node_decode_arithmetic"] = self.lifts.decode_observation();
        value
    }

    fn complete_root(
        &self,
        settings: &Settings,
        state: &State,
    ) -> trnm_mvcc_fee::pon_executor::Result<Hash> {
        let _measurement = self.history.observe(super::HistoryStage::CompleteStateRoot);
        // The separate root entry is genesis arithmetic. It must not evict the
        // offered successor tree or force a large child->genesis->child rebuild.
        // Exact current bytes and namespace, never a caller's digest, select it.
        let context = [
            settings.network(),
            settings.parameters(),
            settings.genesis(),
        ];
        if let (Some(bytes), Ok(entry)) = (bounded_bytes(state), self.root.try_borrow()) {
            if let Some(entry) = entry.as_ref().filter(|entry| {
                entry.context == context && entry.bytes.as_slice() == bytes.as_slice()
            }) {
                self.root_arithmetic.exact_root_hit();
                return Ok(entry.value);
            }
        }
        self.root_arithmetic.calculate(settings, state)
    }

    fn retain_initial_complete_root(
        &self,
        settings: &Settings,
        context: [Hash; 3],
        bytes: &[u8],
        value: Hash,
    ) {
        // Complete-cache hits must warm the independent initial root too. A
        // later FIFO eviction must not turn a genesis check into a destructive
        // rewrite of the offered successor's mathematical tree. The existing
        // entry is only exact-input arithmetic; context alone never returns it.
        let vacant = self
            .root
            .try_borrow()
            .is_ok_and(|entry| entry.as_ref().is_none_or(|entry| entry.context != context));
        if !vacant || bounded_bytes(&settings.initial).as_deref() != Some(bytes) {
            return;
        }
        if let Ok(mut entry) = self.root.try_borrow_mut() {
            *entry = Some(RootEntry {
                context,
                bytes: bytes.to_vec(),
                value,
            });
        }
    }

    /// Reuse exact complete bytes or derive from the same bounded opaque M06
    /// arithmetic used by complete_root. Unlike `complete`, a miss does not run
    /// account/conservation checks before the original state-root grammar.
    /// Caller-owned State is serialized anew; no SQL observation is reused.
    pub(crate) fn state_root(&self, settings: &Settings, state: &State) -> Result<Hash> {
        trnm_mvcc_fee::pon_executor::pq_native_v1::validate_state(state, &settings.app)
            .map_err(crate::Error::from)?;
        if settings.is_native_pq_v4() {
            trnm_mvcc_fee::pon_executor::pq_accounts_v2::validate_state(state, &settings.app)
                .map_err(crate::Error::from)?;
        }
        let _measurement = self
            .history
            .observe(super::HistoryStage::PersistedStateRoot);
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
                self.retain_initial_complete_root(settings, context, bytes, entry.value.state_root);
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
        // A complete actual-input comparison, not a claimed block/root or a
        // Value equality, identifies initial arithmetic. In particular, changed
        // settings with the same context and integer/float encodings still run
        // the original root grammar. Do not rewrite a large current tree into
        // genesis merely to calculate this independent, bounded root entry.
        let initial_input = state.len() == settings.initial.len()
            && bytes
                .as_deref()
                .is_some_and(|actual| bounded_bytes(&settings.initial).as_deref() == Some(actual));
        let value = if initial_input {
            trnm_mvcc_fee::pon_executor::root(state)
        } else {
            self.root_arithmetic.calculate(settings, state)
        }
        .map_err(crate::Error::from)?;
        if let (true, Some(bytes), Ok(mut entry)) =
            (initial_input, bytes, self.root.try_borrow_mut())
        {
            *entry = Some(RootEntry {
                context,
                bytes,
                value,
            });
        }
        Ok(value)
    }

    pub(crate) fn complete(&self, settings: &Settings, state: &State) -> Result<StateCommitment> {
        let _measurement = self
            .history
            .observe(super::HistoryStage::CompleteCommitment);
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
                self.root_arithmetic.complete_hit();
                #[cfg(test)]
                self.hits.set(self.hits.get() + 1);
                return Ok(entry.value.clone());
            }
        }
        self.root_arithmetic.complete_computation();
        let value =
            commitment_from_complete_state_with_root(settings, state, Some(&self.lifts), || {
                self.complete_root(settings, state)
            })
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
        let material = trnm_mvcc_fee::pon_commitment::derive_snapshot(
            &settings.initial,
            None,
            trnm_mvcc_fee::pon_commitment::CacheLimits::default(),
        )
        .unwrap();
        cache.offer_root_material(&settings, material.snapshot.as_ref());
        let before_material = cache.observation()["complete_root_arithmetic"]["counters"]
            ["material_uses"]
            .as_u64()
            .unwrap();
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
        assert_eq!(
            cache.observation()["complete_root_arithmetic"]["counters"]["material_uses"],
            before_material + 4,
            "root-only misses must reach actual-state opaque arithmetic, including original error fallback"
        );
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

    #[test]
    fn initial_root_survives_unactivated_branch_roots_without_whole_tree_churn() {
        let settings = Settings::development(Some(1000)).unwrap();
        let cache = ArithmeticCache::default();
        // The native genesis check can first hit a complete commitment. That
        // must also warm the independent root entry before this FIFO evicts it.
        let initial = cache.complete(&settings, &settings.initial).unwrap();
        assert_eq!(
            cache.state_root(&settings, &settings.initial).unwrap(),
            initial.state_root
        );
        let mut funded = settings.initial.clone();
        for index in 0..64u64 {
            let owner = trnm_protocol::pon_wire::hash(
                b"initial-root-arithmetic-account-v1",
                &[&index.to_le_bytes()],
            );
            funded.insert(
                format!("account:{}", hex::encode(owner)),
                json!({"balance":0,"nonce":index}),
            );
        }
        let prepared = trnm_mvcc_fee::pon_commitment::derive_snapshot(
            &funded,
            None,
            trnm_mvcc_fee::pon_commitment::CacheLimits::default(),
        )
        .unwrap();
        cache.offer_root_material(&settings, prepared.snapshot.as_ref());
        let before = cache.observation()["complete_root_arithmetic"]["counters"]
            ["actual_changed_keys"]
            .as_u64()
            .unwrap();
        for marker in 0..6u64 {
            let mut historical = funded.clone();
            historical.insert("historical-root-marker".into(), json!(marker));
            let expected = trnm_mvcc_fee::pon_executor::root(&historical).unwrap();
            assert_eq!(cache.state_root(&settings, &historical).unwrap(), expected);
            assert_eq!(
                cache.complete(&settings, &historical).unwrap().state_root,
                expected
            );
            assert_eq!(
                cache.state_root(&settings, &settings.initial).unwrap(),
                initial.state_root
            );
        }
        let after = cache.observation()["complete_root_arithmetic"]["counters"]
            ["actual_changed_keys"]
            .as_u64()
            .unwrap();
        assert_eq!(
            after - before,
            6,
            "six actual marker changes must not remove and rebuild the 64 unchanged accounts for genesis checks"
        );
        let retained = cache.root.borrow();
        assert_eq!(
            retained.as_ref().unwrap().bytes,
            bounded_bytes(&settings.initial).unwrap()
        );
        assert!(retained.as_ref().unwrap().bytes.len() <= MAX_COMPLETE_BYTES);
        assert_eq!(cache.complete.borrow().len(), MAX_COMPLETE_ENTRIES);
    }
}
