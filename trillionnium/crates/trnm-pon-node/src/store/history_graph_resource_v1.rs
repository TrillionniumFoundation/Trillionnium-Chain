//! One explicit ordinary-History resource-policy epoch, atomically coupled to
//! the ORIGINAL durable public CPU marker. This is not a signed V6 operation.
//! A new policy can neither clear an old active epoch nor refund unknown debt.
use super::*;
use crate::ingress::history_graph_resource_v1::{self as profile, SharedCounters};
use crate::ingress::public_v3::ServiceMutationCpuDomain;
use std::sync::{Arc, Mutex};

pub(super) const KEY: &str = "ordinary-history-graph-resource-policy-v1";
const CPU_KEY: &str = "ordinary-public-v3-epoch-v1";
const CPU_ACTIVE: &[u8] = b"active-v1";
const MAX_BINDING_BYTES: usize = 16_384;

fn read(db: &Connection, key: &str) -> Result<Option<Vec<u8>>> {
    // A present oversized/NULL/non-BLOB value is an error, never an absent key.
    db.query_row(
        "SELECT CASE WHEN length(value)<=16384 THEN value ELSE NULL END FROM metadata WHERE key=?1",
        [key],
        |row| row.get(0),
    )
    .optional()
    .map_err(|error| Error::from(error).local_integrity())
}

fn matches_current(db: &Connection, expected: &[u8]) -> Result<()> {
    // Read both markers in one statement/snapshot. Separate autocommit reads
    // could otherwise combine values from two concurrent committed epochs.
    // NULL, oversized and non-BLOB rows remain errors, never an absent pair.
    let pair: Option<(Vec<u8>, Vec<u8>)> = db
        .query_row(
            "SELECT CASE WHEN length(cpu.value)<=16384 THEN cpu.value ELSE NULL END, \
             CASE WHEN length(policy.value)<=16384 THEN policy.value ELSE NULL END \
             FROM metadata AS cpu JOIN metadata AS policy ON policy.key=?2 \
             WHERE cpu.key=?1",
            params![CPU_KEY, KEY],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(|error| Error::from(error).local_integrity())?;
    ensure(
        pair.is_some_and(|(cpu, policy)| cpu == CPU_ACTIVE && policy == expected),
        "HISTORY_GRAPH_RESOURCE_BINDING_V1",
    )
}

/// A fresh SQL query at each full fence, with no retained Row/transaction or
/// successful verdict. The original Node connection ALSO checks its current
/// uncommitted marker immediately before COMMIT, so a local trigger cannot hide
/// behind this separate reader's committed view.
pub(crate) struct Epoch {
    expected: Vec<u8>,
    reader: Mutex<Connection>,
}

/// A private LIVE capability, never serialized or reconstructed from metadata.
/// Only a completed original CPU domain and a known rolled-back kernel-refused
/// close can create it. An unknown/cold epoch retains its original crash fence.
pub(super) struct KnownPendingClose {
    expected: Vec<u8>,
    cpu: ServiceMutationCpuDomain,
    observed_import: bool,
}
impl Epoch {
    pub(crate) fn verify(&self) -> Result<()> {
        let db = self
            .reader
            .lock()
            .map_err(|_| "HISTORY_GRAPH_RESOURCE_BINDING_V1")?;
        ensure(db.is_autocommit(), "HISTORY_GRAPH_RESOURCE_BINDING_V1")?;
        let result = matches_current(&db, &self.expected);
        ensure(db.is_autocommit(), "HISTORY_GRAPH_RESOURCE_BINDING_V1")?;
        result
    }
}

impl Node {
    pub(crate) fn require_history_graph_resource_ordinary(&self) -> Result<()> {
        ensure(
            self.owner_policy.is_none()
                && self.continuous_owner.is_none()
                && self.mining_owner.is_none()
                && self.history_effect_owner.is_none(),
            "HISTORY_GRAPH_RESOURCE_ORDINARY_ONLY_V1",
        )
    }
    /// Only explicit ordinary imports may select the new graph strategy.
    /// Existing V6, continuous, task and mining owners keep their strict APIs.
    pub(crate) fn begin_history_graph_resource_v1(
        &mut self,
        parent_observation: &Value,
        resource: &dyn Fn() -> Result<()>,
    ) -> Result<Epoch> {
        self.require_history_graph_resource_ordinary()?;
        ensure(
            !self.public_service_epoch_unknown,
            "OWNER_PUBLIC_SERVICE_UNCLEAN_EPOCH",
        )?;
        ensure(
            self.public_service_epoch_listeners == 0
                && self.history_graph_resource_binding.is_none()
                && self.history_graph_resource_pending.is_none(),
            "HISTORY_GRAPH_RESOURCE_PROFILE_V1",
        )?;
        self.namespace()?;
        let mut nonce = [0u8; 32];
        File::open("/dev/urandom")?.read_exact(&mut nonce)?;
        let expected = serde_json::to_vec(&serde_json::json!({
            "schema":"ordinary-history-graph-resource-binding-v1",
            "profile":profile::PROFILE,"maximum_node_bodies_between_full_checks":profile::MAX_NODE_BODIES,
            "policy_digest":profile::policy_digest(),"epoch_nonce":hex::encode(nonce),
            "cpu_epoch_key":CPU_KEY,"cpu_epoch_value":hex::encode(CPU_ACTIVE),
            "fixed_parent_observation":parent_observation,
            "signed_v6_authority":false,"new_cpu_credit_granted":false,
        }))?;
        ensure(
            expected.len() <= MAX_BINDING_BYTES,
            "HISTORY_GRAPH_RESOURCE_BINDING_V1",
        )?;
        // Open first, so an open failure cannot leave a half-started epoch.
        let reader = Connection::open_with_flags(
            self.directory.join("native.sqlite"),
            OpenFlags::SQLITE_OPEN_READ_ONLY,
        )?;
        reader.busy_timeout(Duration::from_millis(50))?;
        let tx = rusqlite::Transaction::new_unchecked(
            &self.db,
            rusqlite::TransactionBehavior::Immediate,
        )?;
        ensure(
            read(&tx, CPU_KEY)?.is_none(),
            "OWNER_PUBLIC_SERVICE_UNCLEAN_EPOCH",
        )?;
        ensure(
            read(&tx, KEY)?.is_none(),
            "HISTORY_GRAPH_RESOURCE_BINDING_V1",
        )?;
        ensure(
            tx.execute(
                "INSERT INTO metadata(key,value) VALUES(?1,?2)",
                params![CPU_KEY, CPU_ACTIVE],
            )? == 1,
            "OWNER_PUBLIC_SERVICE_EPOCH_CORRUPT",
        )?;
        ensure(
            tx.execute(
                "INSERT INTO metadata(key,value) VALUES(?1,?2)",
                params![KEY, &expected],
            )? == 1,
            "HISTORY_GRAPH_RESOURCE_BINDING_V1",
        )?;
        matches_current(&tx, &expected)?;
        resource()?;
        tx.commit()?;
        self.public_service_epoch_listeners = 1;
        self.history_graph_resource_binding = Some(expected.clone());
        let epoch = Epoch {
            expected,
            reader: Mutex::new(reader),
        };
        if let Err(error) = epoch.verify() {
            self.public_service_epoch_unknown = true;
            return Err(error);
        }
        Ok(epoch)
    }

    /// No source-commit/binary string is authority here. The exact live nonce
    /// and marker are retained from the original begin; provenance is reported
    /// by the actual executable and independent source evidence outside this
    /// local settlement rule. Upgrading cannot erase or reissue old CPU debt.
    pub(crate) fn finish_history_graph_resource_v1(
        &mut self,
        epoch: &Epoch,
        clean: bool,
        resource: &dyn Fn() -> Result<()>,
    ) -> Result<()> {
        let domain = match self.public_service_cpu_domain() {
            Ok(domain) => domain,
            Err(error) => {
                self.public_service_epoch_unknown = true;
                self.history_graph_resource_pending = None;
                return Err(error);
            }
        };
        let mut kernel_refused_after_known_rollback = false;
        let result = (|| {
            self.namespace()?;
            ensure(
                self.public_service_epoch_listeners == 1
                    && self.history_graph_resource_binding.as_deref()
                        == Some(epoch.expected.as_slice()),
                "HISTORY_GRAPH_RESOURCE_BINDING_V1",
            )?;
            matches_current(&self.db, &epoch.expected)?;
            if !clean || self.public_service_epoch_unknown {
                self.public_service_epoch_unknown = true;
                self.public_service_epoch_listeners = 0;
                self.history_graph_resource_pending = None;
                return Ok(());
            }
            // Hold the ORIGINAL CPU mutex through the short close transaction.
            // A cloned public domain cannot start between quiescence and COMMIT.
            // This callback performs only SQL and a pure fresh KernelBudget
            // check; it must not recursively acquire a CPU accounting handle.
            domain.with_known_quiescent_history_close(|| {
                let tx = rusqlite::Transaction::new_unchecked(
                    &self.db,
                    rusqlite::TransactionBehavior::Immediate,
                )?;
                matches_current(&tx, &epoch.expected)?;
                ensure(
                    tx.execute(
                        "DELETE FROM metadata WHERE key=?1 AND value=?2",
                        params![CPU_KEY, CPU_ACTIVE],
                    )? == 1,
                    "OWNER_PUBLIC_SERVICE_EPOCH_CORRUPT",
                )?;
                ensure(
                    tx.execute(
                        "DELETE FROM metadata WHERE key=?1 AND value=?2",
                        params![KEY, &epoch.expected],
                    )? == 1,
                    "HISTORY_GRAPH_RESOURCE_BINDING_V1",
                )?;
                ensure(
                    read(&tx, CPU_KEY)?.is_none() && read(&tx, KEY)?.is_none(),
                    "HISTORY_GRAPH_RESOURCE_BINDING_V1",
                )?;
                if let Err(error) = resource() {
                    // Drop alone is not a known rollback receipt. Only this exact
                    // kernel branch, after explicit successful rollback and fresh
                    // original-marker readback, may retain the LIVE retry token.
                    tx.rollback()?;
                    ensure(self.db.is_autocommit(), "HISTORY_GRAPH_RESOURCE_BINDING_V1")?;
                    matches_current(&self.db, &epoch.expected)?;
                    kernel_refused_after_known_rollback = true;
                    return Err(error);
                }
                tx.commit()?;
                self.public_service_epoch_listeners = 0;
                self.history_graph_resource_binding = None;
                self.history_graph_resource_pending = None;
                Ok(())
            })
        })();
        if result.is_err() {
            if kernel_refused_after_known_rollback {
                let observed_import = self
                    .history_graph_resource_counters
                    .lock()
                    .is_ok_and(|c| c.imports > c.imports_closed);
                self.history_graph_resource_pending = Some(KnownPendingClose {
                    expected: epoch.expected.clone(),
                    cpu: domain,
                    observed_import,
                });
            } else if result
                .as_ref()
                .err()
                .is_some_and(|error| error.is(crate::ErrorCode::PublicMutationCpuBudget))
                && self
                    .history_graph_resource_pending
                    .as_ref()
                    .is_some_and(|pending| {
                        pending.expected == epoch.expected
                            && pending.cpu.shares_domain_with(&domain)
                    })
            {
                // A later same-domain operation may still be finishing. The
                // existing live token survives, but no new token, close or
                // refund is produced until a fresh mutex-held quiescence check.
            } else {
                self.public_service_epoch_unknown = true;
                self.history_graph_resource_pending = None;
            }
        }
        result
    }

    pub(crate) fn resume_history_graph_resource_settlement_v1(
        &mut self,
        parent_observation: &Value,
        kernel: &dyn Fn() -> Result<()>,
    ) -> Result<()> {
        self.require_history_graph_resource_ordinary()?;
        // Missing includes cold Node::open, even with well-formed old rows.
        // Those rows are evidence of debt, never authority to invent this token.
        let pending = self
            .history_graph_resource_pending
            .as_ref()
            .ok_or("HISTORY_GRAPH_RESOURCE_PROFILE_V1")?;
        let expected = pending.expected.clone();
        let cpu = pending.cpu.clone();
        let observed_import = pending.observed_import;
        let prepared = (|| {
            ensure(
                !self.public_service_epoch_unknown
                    && self.public_service_epoch_listeners == 1
                    && self.history_graph_resource_binding.as_deref() == Some(expected.as_slice())
                    && self.public_service_cpu_domain()?.shares_domain_with(&cpu),
                "HISTORY_GRAPH_RESOURCE_BINDING_V1",
            )?;
            self.namespace()?;
            matches_current(&self.db, &expected)?;
            let binding: Value = serde_json::from_slice(&expected)?;
            let original_parent = binding
                .get("fixed_parent_observation")
                .and_then(Value::as_object)
                .ok_or("HISTORY_GRAPH_RESOURCE_BINDING_V1")?;
            let current_parent = parent_observation
                .as_object()
                .ok_or("HISTORY_GRAPH_RESOURCE_BINDING_V1")?;
            let mut original_identity = original_parent.clone();
            let mut current_identity = current_parent.clone();
            for key in [
                "cpu_quota_us",
                "cpu_period_us",
                "cpu_burst_us",
                "memory_bytes",
                "swap_bytes",
                "tasks",
            ] {
                ensure(
                    original_identity.contains_key(key) == current_identity.contains_key(key),
                    "HISTORY_GRAPH_RESOURCE_BINDING_V1",
                )?;
                original_identity.remove(key);
                current_identity.remove(key);
            }
            ensure(
                original_identity == current_identity,
                "HISTORY_GRAPH_RESOURCE_BINDING_V1",
            )?;
            let original_limits_restored = original_parent == current_parent;
            let reader = Connection::open_with_flags(
                self.directory.join("native.sqlite"),
                OpenFlags::SQLITE_OPEN_READ_ONLY,
            )?;
            reader.busy_timeout(Duration::from_millis(50))?;
            Ok((
                Epoch {
                    expected,
                    reader: Mutex::new(reader),
                },
                original_limits_restored,
            ))
        })();
        let (epoch, original_limits_restored) = match prepared {
            Ok(prepared) => prepared,
            Err(error) => {
                self.public_service_epoch_unknown = true;
                self.history_graph_resource_pending = None;
                return Err(error);
            }
        };
        if !original_limits_restored {
            // A freshly opened KernelBudget may accept a currently stricter
            // limit as its own baseline. It may NOT replace this epoch's old
            // baseline or poison a legitimate early retry. No SQL is changed;
            // the actual original limits must be restored before close.
            let refusal = cpu.with_known_quiescent_history_close(|| {
                Err("PUBLIC_HOST_KERNEL_LIMITS_CHANGED".into())
            });
            if refusal
                .as_ref()
                .err()
                .is_some_and(|error| error.is(crate::ErrorCode::PublicMutationCpuUnavailable))
            {
                self.public_service_epoch_unknown = true;
                self.history_graph_resource_pending = None;
            }
            return refusal;
        }
        self.finish_history_graph_resource_v1(&epoch, true, kernel)?;
        if observed_import {
            profile::count(&self.history_graph_resource_counters, |c| {
                c.imports_closed = c
                    .imports_closed
                    .checked_add(1)
                    .ok_or("HISTORY_GRAPH_RESOURCE_OBSERVATION_V1")?;
                Ok(())
            })?;
        }
        Ok(())
    }

    pub(crate) fn require_strict_history_resource_profile(&self) -> Result<()> {
        ensure(
            self.history_graph_resource_binding.is_none() && read(&self.db, KEY)?.is_none(),
            "HISTORY_GRAPH_RESOURCE_PROFILE_V1",
        )
    }

    pub(super) fn check_history_graph_resource_before_commit(&self) -> Result<()> {
        if let Some(expected) = &self.history_graph_resource_binding {
            matches_current(&self.db, expected)?;
        } else if self.public_service_epoch_listeners != 0 {
            self.require_strict_history_resource_profile()?;
        }
        Ok(())
    }

    pub(crate) fn history_graph_resource_counters(&self) -> SharedCounters {
        Arc::clone(&self.history_graph_resource_counters)
    }

    /// Observation of this exact explicit policy only. It grants no permission
    /// and does not reinterpret the separate signed V6/continuous task journals.
    pub fn history_graph_resource_observation_v1(&self) -> Result<Value> {
        let mut value = profile::observe(&self.history_graph_resource_counters)?;
        value["live_known_close_pending"] =
            serde_json::json!(self.history_graph_resource_pending.is_some());
        value["cold_epoch_recovery_granted"] = serde_json::json!(false);
        Ok(value)
    }
}

#[cfg(test)]
mod tests;
