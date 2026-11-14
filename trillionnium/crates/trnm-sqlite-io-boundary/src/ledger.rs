#[cfg(target_os = "linux")]
use crate::{DOMAIN, FILE_BYTES, GROWTH_QUANTUM_BYTES_V2, OBJECTS_PER_ROOT, RESERVATION_DOMAIN_V2};
#[cfg(target_os = "linux")]
use rusqlite::ffi;
use serde::Serialize;

#[cfg(target_os = "linux")]
pub(crate) type Code<T> = std::result::Result<T, i32>;

#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Identity {
    pub dev: u64,
    pub ino: u64,
}

#[cfg(target_os = "linux")]
const LIFECYCLE_EVENTS: usize = 1024;
#[cfg(target_os = "linux")]
const CLEANUP_EVENTS: usize = 256;
#[cfg(target_os = "linux")]
const EVENT_BYTES: usize = 512;

#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum GrowthPolicy {
    ExactV1,
    Reserve64KiBV2,
}

#[cfg(target_os = "linux")]
impl GrowthPolicy {
    pub fn domain(self) -> &'static str {
        match self {
            Self::ExactV1 => DOMAIN,
            Self::Reserve64KiBV2 => RESERVATION_DOMAIN_V2,
        }
    }
    pub fn quantum(self) -> Option<u64> {
        match self {
            Self::ExactV1 => None,
            Self::Reserve64KiBV2 => Some(GROWTH_QUANTUM_BYTES_V2),
        }
    }
    pub fn vfs_version(self) -> &'static str {
        match self {
            Self::ExactV1 => "v1",
            Self::Reserve64KiBV2 => "reservation-v2",
        }
    }
    fn reserved_endpoint(self, endpoint: u64) -> u64 {
        // Callers first require endpoint <= FILE_BYTES. FILE_BYTES is an exact
        // multiple of the fixed quantum, so rounding cannot cross that limit.
        match self {
            Self::ExactV1 => endpoint,
            Self::Reserve64KiBV2 => {
                endpoint.div_ceil(GROWTH_QUANTUM_BYTES_V2) * GROWTH_QUANTUM_BYTES_V2
            }
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct LifecycleReceipt {
    pub sequence: u64,
    pub action: &'static str,
    pub generation: u64,
    pub basename: String,
    pub device: Option<u64>,
    pub inode: Option<u64>,
    pub linked: bool,
    pub handles: u32,
    pub pending_opens: u32,
    pub shm_references: u32,
    pub high_water_bytes: u64,
    pub actual_last_bytes: u64,
    // Absent from every original V1 event and from non-reservation V2 events.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub requested_endpoint: Option<u64>,
}

#[derive(Clone, Debug, Serialize)]
pub struct ObjectReceipt {
    pub generation: u64,
    pub device: Option<u64>,
    pub inode: Option<u64>,
    pub basename: String,
    pub linked: bool,
    pub handles: u32,
    pub pending_opens: u32,
    pub shm_references: u32,
    pub high_water_bytes: u64,
    pub actual_last_bytes: u64,
    pub actual_last_allocated_blocks_512: u64,
    pub reserved_pending_open: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct SecondaryFailureReceipt {
    pub operation: &'static str,
    pub sqlite_code: i32,
}

#[derive(Clone, Debug, Serialize)]
pub struct RootReceipt {
    pub schema: &'static str,
    pub owner_pid: u32,
    pub root_device: u64,
    pub root_inode: u64,
    pub logical_bytes_limit: u64,
    pub retained_object_limit: usize,
    pub high_water_sum: u64,
    pub retained_logical_bytes_peak: u64,
    pub retained_objects_peak: usize,
    pub objects: Vec<ObjectReceipt>,
    pub failed: bool,
    pub first_failure: Option<String>,
    pub first_failure_sqlite_code: Option<i32>,
    pub secondary_failures: Vec<SecondaryFailureReceipt>,
    pub secondary_failures_complete: bool,
    pub callback_operations: u64,
    pub denied_operations: u64,
    pub allocated_blocks_hard_cap_implemented: bool,
    pub lifecycle: Vec<LifecycleReceipt>,
    pub cleanup_lifecycle: Vec<LifecycleReceipt>,
    pub lifecycle_complete: bool,
    pub lifecycle_serialized_bytes: usize,
    pub lifecycle_serialized_bytes_cap: usize,
    pub quarantined_actual_states: usize,
    pub quarantined_sqlite_codes: Vec<i32>,
    pub quarantine_entries_complete: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub growth_reservation_quantum_bytes: Option<u64>,
}

#[cfg(target_os = "linux")]
pub(crate) struct Object {
    pub receipt: ObjectReceipt,
    pub identity: Option<Identity>,
    pub main: bool,
}

#[cfg(target_os = "linux")]
pub(crate) struct Ledger {
    policy: GrowthPolicy,
    pub slots: [Option<Object>; OBJECTS_PER_ROOT],
    pub next_generation: u64,
    pub next_temp: u64,
    pub failed: Option<String>,
    pub first_failure_code: Option<i32>,
    pub secondary_failures: Vec<SecondaryFailureReceipt>,
    pub secondary_failures_complete: bool,
    pub operations: u64,
    pub denied: u64,
    pub active_main_handles: u32,
    pub lifecycle: Vec<LifecycleReceipt>,
    pub cleanup: Vec<LifecycleReceipt>,
    pub lifecycle_bytes: usize,
    pub lifecycle_complete: bool,
    next_event: u64,
    pub retained_logical_bytes_peak: u64,
    pub retained_objects_peak: usize,
}

#[cfg(target_os = "linux")]
impl Ledger {
    pub fn new() -> Self {
        Self::with_policy(GrowthPolicy::ExactV1)
    }
    pub fn with_policy(policy: GrowthPolicy) -> Self {
        Self {
            policy,
            slots: std::array::from_fn(|_| None),
            next_generation: 1,
            next_temp: 0,
            failed: None,
            first_failure_code: None,
            secondary_failures: Vec::new(),
            secondary_failures_complete: true,
            operations: 0,
            denied: 0,
            active_main_handles: 0,
            lifecycle: Vec::new(),
            cleanup: Vec::new(),
            lifecycle_bytes: 0,
            lifecycle_complete: true,
            next_event: 0,
            retained_logical_bytes_peak: 0,
            retained_objects_peak: 0,
        }
    }
    pub fn policy(&self) -> GrowthPolicy {
        self.policy
    }
    fn peak(&mut self) {
        self.retained_logical_bytes_peak = self.retained_logical_bytes_peak.max(
            self.slots
                .iter()
                .flatten()
                .map(|o| o.receipt.high_water_bytes)
                .sum(),
        );
        self.retained_objects_peak = self
            .retained_objects_peak
            .max(self.slots.iter().flatten().count());
    }
    pub fn fail<T>(&mut self, why: &str, code: i32) -> Code<T> {
        if self.failed.is_none() {
            self.failed = Some(why.chars().take(256).collect());
            self.first_failure_code = Some(code);
        }
        self.denied = self.denied.saturating_add(1);
        Err(code)
    }
    // Secondary observations never replace the earliest actual failure code.
    // This fixed failure-only bound does not extend ordinary lifecycle capacity.
    pub fn observe_secondary(&mut self, operation: &'static str, code: i32) {
        if self.secondary_failures.len() < 32 {
            self.secondary_failures.push(SecondaryFailureReceipt {
                operation,
                sqlite_code: code,
            });
        } else {
            self.secondary_failures_complete = false;
        }
    }
    pub fn admission(&mut self) -> Code<()> {
        self.operations = self.operations.saturating_add(1);
        if self.failed.is_some() {
            return Err(ffi::SQLITE_IOERR);
        }
        // Every admitted mutation reserves room for its bounded set of
        // before/after lifecycle records. Reaching this stricter evidence cap
        // fails admission instead of dropping old events or extending limits.
        if self.lifecycle.len() + 8 > LIFECYCLE_EVENTS {
            return self.fail("bounded lifecycle evidence capacity", ffi::SQLITE_FULL);
        }
        Ok(())
    }
    fn record(&mut self, slot: usize, action: &'static str, cleanup: bool) -> Code<()> {
        self.record_with_request(slot, action, cleanup, None)
    }
    fn record_with_request(
        &mut self,
        slot: usize,
        action: &'static str,
        cleanup: bool,
        requested_endpoint: Option<u64>,
    ) -> Code<()> {
        let object = self.slots[slot].as_ref().ok_or(ffi::SQLITE_IOERR)?;
        let r = &object.receipt;
        let event = LifecycleReceipt {
            sequence: self.next_event,
            action,
            generation: r.generation,
            basename: r.basename.clone(),
            device: r.device,
            inode: r.inode,
            linked: r.linked,
            handles: r.handles,
            pending_opens: r.pending_opens,
            shm_references: r.shm_references,
            high_water_bytes: r.high_water_bytes,
            actual_last_bytes: r.actual_last_bytes,
            requested_endpoint,
        };
        let bytes = serde_json::to_vec(&event)
            .map_err(|_| ffi::SQLITE_NOMEM)?
            .len();
        let full = if cleanup {
            self.cleanup.len() >= CLEANUP_EVENTS
        } else {
            self.lifecycle.len() >= LIFECYCLE_EVENTS
        };
        if bytes > EVENT_BYTES || full {
            self.lifecycle_complete = false;
            return self.fail(
                "bounded lifecycle record cannot be retained",
                ffi::SQLITE_FULL,
            );
        }
        self.next_event = self.next_event.checked_add(1).ok_or(ffi::SQLITE_FULL)?;
        self.lifecycle_bytes += bytes;
        if cleanup {
            self.cleanup.push(event);
        } else {
            self.lifecycle.push(event);
        }
        Ok(())
    }
    pub fn named(&self, name: &str) -> Option<usize> {
        self.slots.iter().position(|x| {
            x.as_ref()
                .is_some_and(|o| o.receipt.basename == name && o.receipt.linked)
        })
    }
    pub fn reserve_open(&mut self, name: &str, main: bool) -> Code<usize> {
        self.admission()?;
        if let Some(i) = self.named(name) {
            return Ok(i);
        }
        let Some(i) = self.slots.iter().position(Option::is_none) else {
            return self.fail("retained real-inode slot capacity", ffi::SQLITE_FULL);
        };
        let generation = self.next_generation;
        self.next_generation = generation.checked_add(1).ok_or(ffi::SQLITE_FULL)?;
        self.slots[i] = Some(Object {
            identity: None,
            main,
            receipt: ObjectReceipt {
                generation,
                device: None,
                inode: None,
                basename: name.to_owned(),
                linked: true,
                handles: 0,
                pending_opens: 0,
                shm_references: 0,
                high_water_bytes: 0,
                actual_last_bytes: 0,
                actual_last_allocated_blocks_512: 0,
                reserved_pending_open: true,
            },
        });
        self.peak();
        self.record(i, "reserve-open", false)?;
        Ok(i)
    }
    pub fn bind(
        &mut self,
        slot: usize,
        identity: Identity,
        length: u64,
        blocks: u64,
        linked: bool,
    ) -> Code<()> {
        self.bind_observed(slot, identity, length, blocks, linked, false)
    }
    /// Only callers observing a named inode BEFORE delegating xOpen, xShmMap
    /// or xDelete may establish its initial reservation from existing length.
    /// A post-delegation fstat must never silently authorize earlier growth.
    pub fn observe_existing_before_io(
        &mut self,
        slot: usize,
        identity: Identity,
        length: u64,
        blocks: u64,
        linked: bool,
    ) -> Code<()> {
        if self.policy == GrowthPolicy::Reserve64KiBV2 && !linked {
            return self.fail(
                "named pre-I/O observation must be linked",
                ffi::SQLITE_IOERR,
            );
        }
        self.bind_observed(slot, identity, length, blocks, linked, true)
    }
    fn bind_observed(
        &mut self,
        slot: usize,
        identity: Identity,
        length: u64,
        blocks: u64,
        linked: bool,
        before_io: bool,
    ) -> Code<()> {
        if length > FILE_BYTES {
            return self.fail("existing object exceeds per-inode cap", ffi::SQLITE_FULL);
        }
        if self
            .slots
            .iter()
            .enumerate()
            .any(|(i, o)| i != slot && o.as_ref().is_some_and(|o| o.identity == Some(identity)))
        {
            return self.fail("inode aliased across retained slots", ffi::SQLITE_IOERR);
        }
        let Some(object) = self.slots[slot].as_ref() else {
            return Err(ffi::SQLITE_IOERR);
        };
        if object.identity.is_some_and(|old| old != identity) {
            return self.fail("named inode replaced", ffi::SQLITE_IOERR);
        }
        let first = object.identity.is_none();
        let initial_observation = self.policy == GrowthPolicy::Reserve64KiBV2 && first && before_io;
        if self.policy == GrowthPolicy::Reserve64KiBV2
            && length > object.receipt.high_water_bytes
            && !initial_observation
        {
            return self.fail(
                "actual inode length exceeds prior reservation",
                ffi::SQLITE_FULL,
            );
        }
        let high_water = if self.policy == GrowthPolicy::ExactV1 || initial_observation {
            object
                .receipt
                .high_water_bytes
                .max(self.policy.reserved_endpoint(length))
        } else {
            object.receipt.high_water_bytes
        };
        if initial_observation {
            // Keep the original evidence admission margin; no event is merged,
            // discarded or moved out of the measured operation.
            self.admission()?;
        }
        let object = self.slots[slot].as_mut().ok_or(ffi::SQLITE_IOERR)?;
        object.identity = Some(identity);
        object.receipt.device = Some(identity.dev);
        object.receipt.inode = Some(identity.ino);
        object.receipt.linked = linked;
        object.receipt.high_water_bytes = high_water;
        object.receipt.actual_last_bytes = length;
        object.receipt.actual_last_allocated_blocks_512 = blocks;
        object.receipt.reserved_pending_open = false;
        self.peak();
        if first {
            if initial_observation {
                self.record_with_request(slot, "bind-existing-before-io-v2", false, Some(length))?;
            } else {
                self.record(slot, "bind-real-inode", false)?;
            }
        }
        Ok(())
    }
    pub fn reserve_growth(&mut self, slot: usize, endpoint: u64) -> Code<()> {
        self.admission()?;
        if endpoint > FILE_BYTES {
            return self.fail("pre-growth inode length cap", ffi::SQLITE_FULL);
        }
        let reservation = self.policy.reserved_endpoint(endpoint);
        let requested_endpoint = (self.policy == GrowthPolicy::Reserve64KiBV2).then_some(endpoint);
        let Some(object) = self.slots[slot].as_mut() else {
            return Err(ffi::SQLITE_IOERR);
        };
        let increased = endpoint > object.receipt.high_water_bytes;
        object.receipt.high_water_bytes = object.receipt.high_water_bytes.max(reservation);
        self.peak();
        if increased {
            self.record_with_request(slot, "reserve-growth", false, requested_endpoint)?;
        }
        Ok(())
    }
    pub fn reserve_handle(&mut self, slot: usize) -> Code<()> {
        self.admission()?;
        let object = self.slots[slot].as_mut().ok_or(ffi::SQLITE_IOERR)?;
        if object.receipt.handles + object.receipt.pending_opens >= 32 {
            return self.fail("per-inode actual+pending handle cap", ffi::SQLITE_FULL);
        }
        object.receipt.pending_opens += 1;
        if object.main {
            self.active_main_handles += 1;
        }
        self.record(slot, "reserve-handle", false)?;
        Ok(())
    }
    pub fn opened(&mut self, slot: usize) -> Code<()> {
        let object = self.slots[slot].as_mut().ok_or(ffi::SQLITE_IOERR)?;
        if object.receipt.pending_opens == 0 {
            return self.fail("missing reserved handle", ffi::SQLITE_IOERR);
        }
        object.receipt.pending_opens -= 1;
        object.receipt.handles += 1;
        self.record(slot, "opened", false)?;
        Ok(())
    }
    pub fn release_pending(&mut self, slot: usize, action: &'static str) {
        if let Some(object) = self.slots[slot].as_mut() {
            object.receipt.pending_opens = object.receipt.pending_opens.saturating_sub(1);
            if object.main {
                self.active_main_handles = self.active_main_handles.saturating_sub(1);
            }
        }
        let _ = self.record(slot, action, true);
        self.collect();
    }
    pub fn add_shm(&mut self, slot: usize) -> Code<()> {
        let object = self.slots[slot].as_mut().ok_or(ffi::SQLITE_IOERR)?;
        if object.receipt.shm_references >= 32 {
            return self.fail("SHM reference cap", ffi::SQLITE_FULL);
        }
        object.receipt.shm_references += 1;
        self.record(slot, "shm-reference", false)?;
        Ok(())
    }
    pub fn close_handle(&mut self, slot: usize) {
        if let Some(object) = self.slots[slot].as_mut() {
            object.receipt.handles = object.receipt.handles.saturating_sub(1);
            if object.main {
                self.active_main_handles = self.active_main_handles.saturating_sub(1);
            }
        }
        let _ = self.record(slot, "underlying-close", true);
        self.collect();
    }
    pub fn close_shm(&mut self, slot: usize) {
        if let Some(object) = self.slots[slot].as_mut() {
            object.receipt.shm_references = object.receipt.shm_references.saturating_sub(1);
        }
        let _ = self.record(slot, "underlying-shm-unmap", true);
        self.collect();
    }
    pub fn unlinked(&mut self, slot: usize) {
        if let Some(object) = self.slots[slot].as_mut() {
            object.receipt.linked = false;
        }
        let _ = self.record(slot, "unlinked", true);
        self.collect();
    }
    fn collect(&mut self) {
        for object in &mut self.slots {
            let release = object.as_ref().is_some_and(|o| {
                !o.receipt.linked
                && !o.receipt.reserved_pending_open && o.receipt.handles == 0 && o.receipt.pending_opens == 0
                && o.receipt.shm_references == 0
                // unixClose can defer a MAIN fd while another same-inode lock
                // exists. Never refund a main object until every main handle
                // in this root has completed its underlying close.
                && (!o.main || self.active_main_handles == 0)
            });
            if release {
                *object = None;
            }
        }
    }
}

#[cfg(all(test, target_os = "linux"))]
#[path = "reservation_v2_tests.rs"]
mod reservation_v2_tests;
