//! One bounded opaque entry, used only for complete-input root arithmetic.
//!
//! The native owner may offer M06's private canonical map/tree. No supplied
//! digest is an answer: derive_snapshot re-encodes every current State value,
//! compares the complete key set and applies every real addition/change/removal.
//! When canonical payloads do not fit, an alternate entry stores only original
//! leaf hashes and partition-root arithmetic. Every actual row is still encoded,
//! bounded and hashed before any reuse. The entry and byte limits are unchanged.
//! SQL reads, typed decoding, account graphs, metadata and validity stay outside.
use crate::Settings;
use serde::Serialize;
use serde_json::{json, Value};
use std::cell::{Cell, RefCell};
use trnm_mvcc_fee::pon_commitment::{self, CacheLimits, CheckedCommitment, CommitmentMethod};
use trnm_mvcc_fee::pon_executor::{self, State};
use trnm_protocol::pon_wire::{Hash, StateRootArithmetic};

const MAX_PAYLOAD_BYTES: usize = 2 * 1024 * 1024;
const MAX_RETAINED_CHARGE_BYTES: usize = 16 * 1024 * 1024;
// Conservative fixed software charge for the entry, context and handles,
// additional to M06's canonical-map/tree or the original-hash array charges.
const ENTRY_CHARGE: usize = 1024;

struct Material {
    context: [Hash; 3],
    source: MaterialSource,
    charged: usize,
}

enum MaterialSource {
    Canonical(CheckedCommitment),
    Partitions(StateRootArithmetic),
}

impl Material {
    fn payload_bytes(&self) -> usize {
        match &self.source {
            MaterialSource::Canonical(snapshot) => snapshot.payload_bytes(),
            MaterialSource::Partitions(arithmetic) => arithmetic.retained_payload_bytes(),
        }
    }
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
    partition_inputs_hashed: u64,
    partition_roots_reused: u64,
    partition_roots_computed: u64,
    partition_retention_refusals: u64,
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
                    source: MaterialSource::Canonical(snapshot.clone()),
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
        // Take the sole entry, so no RefCell guard crosses a calculation. A
        // conflicting observation retains the original full-root behavior.
        let prior = match self.material.try_borrow_mut() {
            Ok(mut material) => material.take(),
            Err(_) => {
                self.count(|c| c.cold_roots = c.cold_roots.saturating_add(1));
                return pon_executor::root(actual);
            }
        };
        let prior = prior.filter(|material| {
            let matches = material.context == context;
            if !matches {
                self.count(|c| c.context_misses = c.context_misses.saturating_add(1));
            }
            matches
        });
        let material = if let Some(prior) = prior {
            self.count(|c| c.material_uses = c.material_uses.saturating_add(1));
            prior
        } else {
            self.count(|c| c.cold_roots = c.cold_roots.saturating_add(1));
            Material {
                context,
                source: MaterialSource::Partitions(StateRootArithmetic::new(
                    MAX_PAYLOAD_BYTES.min(MAX_RETAINED_CHARGE_BYTES.saturating_sub(ENTRY_CHARGE)),
                )),
                charged: ENTRY_CHARGE,
            }
        };
        let Material {
            source, charged, ..
        } = material;
        let prior = match source {
            MaterialSource::Canonical(prior) => prior,
            MaterialSource::Partitions(arithmetic) => {
                return self.calculate_partitions(settings, actual, arithmetic);
            }
        };
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
                self.restore(Material {
                    context,
                    source: MaterialSource::Canonical(prior),
                    charged,
                });
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

    fn restore(&self, material: Material) {
        if let Ok(mut retained) = self.material.try_borrow_mut() {
            *retained = Some(material);
        }
    }

    /// The complete commitment also calculates the actual non-account partition.
    /// Reuse hash partitions when that alternate material is present. Keep an
    /// offered M06 full-state tree intact: removing/reinserting all its accounts
    /// for this independent root would undo its existing small-state benefit.
    pub(super) fn calculate_non_accounts(
        &self,
        settings: &Settings,
        actual: &State,
    ) -> pon_executor::Result<Hash> {
        let use_partitions = self.material.try_borrow().is_ok_and(|material| {
            material.as_ref().is_some_and(|material| {
                material.context
                    == [
                        settings.network(),
                        settings.parameters(),
                        settings.genesis(),
                    ]
                    && matches!(&material.source, MaterialSource::Partitions(_))
            })
        });
        if use_partitions {
            self.calculate(settings, actual)
        } else {
            pon_executor::root(actual)
        }
    }

    fn calculate_partitions(
        &self,
        settings: &Settings,
        actual: &State,
        mut arithmetic: StateRootArithmetic,
    ) -> pon_executor::Result<Hash> {
        let result = pon_executor::root_with_arithmetic(actual, &mut arithmetic);
        if result.is_ok() {
            let observation = arithmetic.observation();
            self.count(|c| {
                c.partition_inputs_hashed = c
                    .partition_inputs_hashed
                    .saturating_add(observation.input_keys as u64);
                c.partition_roots_reused = c
                    .partition_roots_reused
                    .saturating_add(observation.reused_partitions as u64);
                c.partition_roots_computed = c
                    .partition_roots_computed
                    .saturating_add(observation.computed_partitions as u64);
                if observation.retention_refused {
                    c.partition_retention_refusals =
                        c.partition_retention_refusals.saturating_add(1);
                }
            });
            // A refused calculation publishes no entry; the returned root was
            // computed by the original complete reducer over actual leaf hashes.
            if observation.retention_refused {
                return result;
            }
        }
        self.restore(Material {
            context: [
                settings.network(),
                settings.parameters(),
                settings.genesis(),
            ],
            charged: arithmetic.retained_payload_bytes() + ENTRY_CHARGE,
            source: MaterialSource::Partitions(arithmetic),
        });
        match result {
            Ok(root) => Ok(root),
            Err(_) => {
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
                let (kind, keys) = match &material.source {
                    MaterialSource::Canonical(snapshot) => {
                        ("canonical-map-and-tree", snapshot.keys())
                    }
                    MaterialSource::Partitions(arithmetic) => (
                        "original-leaf-hashes-and-partition-roots",
                        arithmetic.observation().input_keys,
                    ),
                };
                json!({"kind":kind,"keys":keys,
                    "payload_bytes":material.payload_bytes(),
                    "retained_software_charge_bytes":material.charged})
            })
        });
        json!({"schema":"pon-native-complete-root-arithmetic-v2",
            "scope":"one opaque canonical map/tree OR original leaf-hash/partition-root entry; every current State key and canonical value is encoded and compared or hashed; no stored state, row-set, root claim or validity verdict is supplied",
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
