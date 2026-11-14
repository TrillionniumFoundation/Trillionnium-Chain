//! Bounded arithmetic material for the original complete historical replay.
//!
//! A block id and the root read by the caller from actual SQL are indexes only.
//! Every use still enters the original checked_snapshot: it canonically encodes
//! every actual State key/value, plans every difference, applies the complete
//! change set and compares the resulting root. State, records, deltas, eligibility
//! and successful validation results are never returned by this cache.
use super::{CheckedCommitment, Hash, Node, PreparedCommitment, Result, State};
use std::collections::VecDeque;

const MAX_ENTRIES: usize = 8;
const MAX_PAYLOAD_BYTES: usize = 2 * 1024 * 1024;
const MAX_RETAINED_CHARGE_BYTES: usize = 16 * 1024 * 1024;

#[derive(Default)]
pub(super) struct HistoricalCommitments {
    material: VecDeque<(Hash, CheckedCommitment, bool)>,
    replay_anchor: Option<Hash>,
    payload: usize,
    retained: usize,
}
impl HistoricalCommitments {
    #[cfg(test)]
    pub(super) fn entries(&self) -> usize {
        self.material.len()
    }
    #[cfg(test)]
    pub(super) fn payload_bytes(&self) -> usize {
        self.payload
    }
    #[cfg(test)]
    pub(super) fn retained_charge_bytes(&self) -> usize {
        self.retained
    }
    pub(super) fn clear(&mut self) {
        self.material.clear();
        self.replay_anchor = None;
        self.payload = 0;
        self.retained = 0;
    }
    pub(super) fn candidate(&self, block: Hash, current_root: Hash) -> Option<CheckedCommitment> {
        self.material
            .iter()
            .find(|(id, snapshot, _)| *id == block && snapshot.root() == current_root)
            .map(|(_, snapshot, _)| snapshot.clone())
    }
    fn remove(&mut self, index: usize) {
        if let Some((_, snapshot, _)) = self.material.remove(index) {
            self.payload -= snapshot.payload_bytes();
            self.retained -= snapshot.retained_charge_bytes();
        }
    }
    // A fresh SQL snapshot selects only an eviction preference. No state or
    // validation is returned, and a different anchor releases every preference.
    pub(super) fn begin_replay(&mut self, anchor: Hash) {
        if self.replay_anchor != Some(anchor) {
            for (_, _, preferred) in &mut self.material {
                *preferred = false;
            }
            self.replay_anchor = Some(anchor);
        }
    }
    pub(super) fn retain(&mut self, block: Hash, snapshot: Option<&CheckedCommitment>) {
        self.retain_preferred(block, snapshot, false);
    }
    pub(super) fn retain_preferred(
        &mut self,
        block: Hash,
        snapshot: Option<&CheckedCommitment>,
        preferred: bool,
    ) {
        if let Some(index) = self.material.iter().position(|(id, _, _)| *id == block) {
            self.remove(index);
        }
        let Some(snapshot) = snapshot else {
            return;
        };
        let payload = snapshot.payload_bytes();
        let retained = snapshot.retained_charge_bytes();
        if payload > MAX_PAYLOAD_BYTES || retained > MAX_RETAINED_CHARGE_BYTES {
            return;
        }
        // Different forks may share a snapshot anchor. Their first seven
        // locators must not accumulate more than seven protected candidates.
        if preferred && self.material.iter().filter(|(_, _, keep)| *keep).count() >= MAX_ENTRIES - 1
        {
            if let Some(index) = self.material.iter().position(|(_, _, keep)| *keep) {
                self.remove(index);
            }
        }
        // Shared Arc versions are deliberately charged in full per entry. This
        // is extra retained software charge, separate from the original 512 MiB
        // per-call commitment workspace charge, and bounds neither total Node
        // memory nor process RSS. Refusal only discards optional material.
        loop {
            let Some(next_payload) = self.payload.checked_add(payload) else {
                self.clear();
                return;
            };
            let Some(next_retained) = self.retained.checked_add(retained) else {
                self.clear();
                return;
            };
            if self.material.len() < MAX_ENTRIES
                && next_payload <= MAX_PAYLOAD_BYTES
                && next_retained <= MAX_RETAINED_CHARGE_BYTES
            {
                self.material
                    .push_back((block, snapshot.clone(), preferred));
                self.payload = next_payload;
                self.retained = next_retained;
                return;
            }
            // Keep at most seven prefix candidates, leaving a rotating tail
            // for the current parent binding. Byte pressure can evict preferred
            // material too; the existing budgets always take precedence.
            let victim = self
                .material
                .iter()
                .position(|(_, _, keep)| !keep)
                .unwrap_or(0);
            self.remove(victim);
        }
    }
}
impl Node {
    pub(super) fn checked_historical_commitment(
        &self,
        block: Hash,
        actual: &State,
        current_root: Hash,
        original_prior: Option<&CheckedCommitment>,
        prefer_replay_prefix: bool,
    ) -> Result<PreparedCommitment> {
        // No RefCell guard crosses canonical computation or caller progress.
        // A miss, changed current SQL root or over-budget entry uses the original
        // predecessor/None. Internal tree mismatch follows its original full-root
        // fallback; a changed actual value must still pass the full root check.
        let material = self
            .historical_commitment_cache
            .borrow()
            .candidate(block, current_root);
        let prepared =
            self.checked_commitment(actual, current_root, material.as_ref().or(original_prior))?;
        self.historical_commitment_cache
            .borrow_mut()
            .retain_preferred(block, prepared.snapshot.as_ref(), prefer_replay_prefix);
        // changed_keys is relative to the selected arithmetic material. Zero
        // does not certify unchanged SQL, eligibility or a validation result.
        Ok(prepared)
    }
}
