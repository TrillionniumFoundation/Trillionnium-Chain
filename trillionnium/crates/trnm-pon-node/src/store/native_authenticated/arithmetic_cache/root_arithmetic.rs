//! One bounded opaque StateTree, used only for complete-input root arithmetic.
//!
//! The native owner may offer M06's private canonical map/tree. No supplied
//! digest is an answer: derive_snapshot re-encodes every current State value,
//! compares the complete key set and applies every real addition/change/removal.
//! Missing/foreign/refused material uses the original complete root function.
//! SQL reads, typed decoding, account graphs, metadata and validity stay outside.
use crate::Settings;
use serde::Serialize;
use serde_json::{json, Value};
use std::cell::{Cell, RefCell};
use trnm_mvcc_fee::pon_commitment::{self, CacheLimits, CheckedCommitment, CommitmentMethod};
use trnm_mvcc_fee::pon_executor::{self, State};
use trnm_protocol::pon_wire::Hash;

const MAX_PAYLOAD_BYTES: usize = 2 * 1024 * 1024;
const MAX_RETAINED_CHARGE_BYTES: usize = 16 * 1024 * 1024;
// Conservative fixed software charge for the entry, context and Arc handles,
// additional to M06's canonical-map and compressed-tree charges.
const ENTRY_CHARGE: usize = 1024;

struct Material {
    context: [Hash; 3],
    snapshot: CheckedCommitment,
    charged: usize,
}

#[derive(Clone, Copy, Default, Serialize)]
struct Counters {
    offers: u64,
    offers_retained: u64,
    offers_absent_or_refused: u64,
    offers_borrow_conflicts: u64,
    complete_hits: u64,
    complete_computations: u64,
    exact_root_hits: u64,
    calculations: u64,
    material_uses: u64,
    context_misses: u64,
    cold_roots: u64,
    derived_checked_apply: u64,
    derived_rebuilt_tree: u64,
    derived_full_root: u64,
    actual_changed_keys: u64,
    original_error_fallbacks: u64,
}

#[derive(Default)]
pub(super) struct RootArithmetic {
    material: RefCell<Option<Material>>,
    counters: Cell<Counters>,
}
impl RootArithmetic {
    fn count(&self, action: impl FnOnce(&mut Counters)) {
        let mut counters = self.counters.get();
        action(&mut counters);
        self.counters.set(counters);
    }
    pub(super) fn complete_hit(&self) {
        self.count(|c| c.complete_hits = c.complete_hits.saturating_add(1));
    }
    pub(super) fn complete_computation(&self) {
        self.count(|c| c.complete_computations = c.complete_computations.saturating_add(1));
    }
    pub(super) fn exact_root_hit(&self) {
        self.count(|c| c.exact_root_hits = c.exact_root_hits.saturating_add(1));
    }

    /// Bound a clone of opaque mathematical material, not an admission permit.
    /// Arc contents are charged in full even when another owner already holds
    /// them. Refusal discards the old optional entry instead of enlarging a pool.
    pub(super) fn offer(&self, settings: &Settings, snapshot: Option<&CheckedCommitment>) {
        self.count(|c| c.offers = c.offers.saturating_add(1));
        let next = snapshot.and_then(|snapshot| {
            let charged = snapshot.retained_charge_bytes().checked_add(ENTRY_CHARGE)?;
            (snapshot.payload_bytes() <= MAX_PAYLOAD_BYTES && charged <= MAX_RETAINED_CHARGE_BYTES)
                .then(|| Material {
                    context: [
                        settings.network(),
                        settings.parameters(),
                        settings.genesis(),
                    ],
                    snapshot: snapshot.clone(),
                    charged,
                })
        });
        if let Ok(mut material) = self.material.try_borrow_mut() {
            self.count(|c| {
                if next.is_some() {
                    c.offers_retained = c.offers_retained.saturating_add(1);
                } else {
                    c.offers_absent_or_refused = c.offers_absent_or_refused.saturating_add(1);
                }
            });
            *material = next;
        } else {
            self.count(|c| c.offers_borrow_conflicts = c.offers_borrow_conflicts.saturating_add(1));
        }
    }

    pub(super) fn calculate(
        &self,
        settings: &Settings,
        actual: &State,
    ) -> pon_executor::Result<Hash> {
        self.count(|c| c.calculations = c.calculations.saturating_add(1));
        let context = [
            settings.network(),
            settings.parameters(),
            settings.genesis(),
        ];
        // No RefCell guard crosses a calculation or any caller's operation.
        let prior = self.material.try_borrow().ok().and_then(|material| {
            let material = material.as_ref()?;
            if material.context != context {
                self.count(|c| c.context_misses = c.context_misses.saturating_add(1));
                return None;
            }
            Some(material.snapshot.clone())
        });
        let Some(prior) = prior else {
            self.count(|c| c.cold_roots = c.cold_roots.saturating_add(1));
            return pon_executor::root(actual);
        };
        self.count(|c| c.material_uses = c.material_uses.saturating_add(1));
        // The existing M06 algorithm keeps canonical error order, actual row
        // bounds and an original-full-root fallback for budget/internal mismatch.
        // This call never compares against or accepts a record/header root claim.
        match pon_commitment::derive_snapshot(
            actual,
            Some(&prior),
            CacheLimits {
                max_payload_bytes: MAX_PAYLOAD_BYTES,
                ..CacheLimits::default()
            },
        ) {
            Ok(prepared) => {
                self.count(|c| {
                    match prepared.observation.method {
                        CommitmentMethod::CheckedApply => {
                            c.derived_checked_apply = c.derived_checked_apply.saturating_add(1)
                        }
                        CommitmentMethod::RebuiltTree => {
                            c.derived_rebuilt_tree = c.derived_rebuilt_tree.saturating_add(1)
                        }
                        CommitmentMethod::FullRoot(_) => {
                            c.derived_full_root = c.derived_full_root.saturating_add(1)
                        }
                    }
                    c.actual_changed_keys = c.actual_changed_keys.saturating_add(
                        u64::try_from(prepared.observation.changed_keys).unwrap_or(u64::MAX),
                    );
                });
                // The temporary result obeys M06's existing workspace bound;
                // only the single retained tree is subject to the tighter cap.
                self.offer(settings, prepared.snapshot.as_ref());
                Ok(prepared.root)
            }
            Err(_) => {
                // Optional arithmetic may not introduce a cache-specific error.
                // Run the original grammar to keep its exact canonical/limit
                // error (or valid root). No caller cancellation is caught here.
                self.count(|c| {
                    c.original_error_fallbacks = c.original_error_fallbacks.saturating_add(1)
                });
                pon_executor::root(actual)
            }
        }
    }

    pub(super) fn observation(&self) -> Value {
        let retained = self.material.try_borrow().ok().map(|material| {
            material.as_ref().map(|material| {
                json!({"keys":material.snapshot.keys(),
                    "payload_bytes":material.snapshot.payload_bytes(),
                    "retained_software_charge_bytes":material.charged})
            })
        });
        json!({"schema":"pon-native-complete-root-arithmetic-v1",
            "scope":"one opaque canonical map/tree; every current State key and canonical value is compared or rebuilt; no stored state, row-set, root claim or validity verdict is supplied",
            "retained_material":retained,
            "retention_observation_available":retained.is_some(),
            "entry_limit":1,"payload_limit_bytes":MAX_PAYLOAD_BYTES,
            "retained_software_charge_limit_bytes":MAX_RETAINED_CHARGE_BYTES,
            "charge_is_process_rss_bound":false,
            "temporary_workspace_is_separate":true,
            "has_consensus_authority":false,"counters":self.counters.get()})
    }
}

#[cfg(test)]
mod tests;
