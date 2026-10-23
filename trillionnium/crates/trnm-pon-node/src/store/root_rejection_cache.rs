//! Volatile exact-packet M06 refusal facts. Never an admission or Work capability.
use super::*;

pub(super) const MAX_ENTRIES: usize = 32;
pub(super) const MAX_RETAINED_BYTES: usize = 2 * 1024 * 1024;
pub(super) const TTL_NS: u64 = 30_000_000_000;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) struct Scope {
    pub(super) context: Hash,
    pub(super) parent: Hash,
    pub(super) root: Hash,
}

// The only production constructor is at admission's final comparison, after
// real M06 and qualified output derivation. Generic ROOT errors cannot enter.
pub(super) struct FinalMismatch {
    pub(super) state: Hash,
    pub(super) receipts: Hash,
}
struct Entry {
    scope: Scope,
    packet: Box<[u8]>,
    mismatch: FinalMismatch,
    created_ns: u64,
}
pub(super) struct Cache {
    entries: [Option<Entry>; MAX_ENTRIES],
    last_ns: Option<u64>,
    unavailable: bool,
}
const _: () = assert!(
    std::mem::size_of::<Cache>() + std::mem::size_of::<RefCell<Option<Box<Cache>>>>()
        <= MAX_RETAINED_BYTES
);
impl Default for Cache {
    fn default() -> Self {
        Self {
            entries: std::array::from_fn(|_| None),
            last_ns: None,
            unavailable: false,
        }
    }
}
impl Cache {
    #[cfg(test)]
    pub(super) fn entries(&self) -> usize {
        self.entries.iter().flatten().count()
    }
    // Fixed metadata plus exact boxed packet lengths, including the Node's
    // optional-cache field. This is a software-retention bound, not an RSS or
    // allocator-overhead claim. Entries have no growing auxiliary collection.
    pub(super) fn retained_bytes(&self) -> usize {
        std::mem::size_of::<Self>()
            + std::mem::size_of::<RefCell<Option<Box<Self>>>>()
            + self
                .entries
                .iter()
                .flatten()
                .map(|entry| entry.packet.len())
                .sum::<usize>()
    }
    fn advance(&mut self, now: Option<u64>) -> Option<u64> {
        if self.unavailable {
            return None;
        }
        let Some(now) = now.filter(|now| self.last_ns.is_none_or(|last| *now >= last)) else {
            self.entries.iter_mut().for_each(|entry| *entry = None);
            self.unavailable = true;
            return None;
        };
        self.last_ns = Some(now);
        for slot in &mut self.entries {
            if slot
                .as_ref()
                .is_some_and(|entry| now - entry.created_ns >= TTL_NS)
            {
                *slot = None;
            }
        }
        Some(now)
    }
    pub(super) fn rejects(
        &mut self,
        scope: Scope,
        packet: &[u8],
        header: &Header,
        now: Option<u64>,
    ) -> bool {
        self.advance(now).is_some()
            && self.entries.iter().flatten().any(|entry| {
                entry.scope == scope
                    && entry.packet.as_ref() == packet
                    && (header.state != entry.mismatch.state
                        || header.receipts != entry.mismatch.receipts)
            })
    }
    pub(super) fn retain(
        &mut self,
        scope: Scope,
        packet: Vec<u8>,
        mismatch: FinalMismatch,
        now: Option<u64>,
    ) {
        let Some(now) = self.advance(now) else {
            return;
        };
        let fixed = std::mem::size_of::<Self>() + std::mem::size_of::<RefCell<Option<Box<Self>>>>();
        if packet.len() > MAX_RETAINED_BYTES.saturating_sub(fixed)
            || self
                .entries
                .iter()
                .flatten()
                .any(|entry| entry.scope == scope && entry.packet.as_ref() == packet)
        {
            return;
        }
        while self.entries.iter().all(Option::is_some)
            || self.retained_bytes() + packet.len() > MAX_RETAINED_BYTES
        {
            let oldest = self
                .entries
                .iter()
                .enumerate()
                .filter_map(|(index, entry)| entry.as_ref().map(|e| (index, e.created_ns)))
                .min_by_key(|(_, created)| *created)
                .map(|(index, _)| index);
            let Some(oldest) = oldest else { return };
            self.entries[oldest] = None;
        }
        let Some(slot) = self.entries.iter_mut().find(|slot| slot.is_none()) else {
            return;
        };
        *slot = Some(Entry {
            scope,
            packet: packet.into_boxed_slice(),
            mismatch,
            created_ns: now,
        });
    }
}

pub(super) fn now_ns() -> Option<u64> {
    use rustix::time::{clock_gettime_dynamic, ClockId, DynamicClockId};
    let time = clock_gettime_dynamic(DynamicClockId::Known(ClockId::Monotonic)).ok()?;
    let seconds = u64::try_from(time.tv_sec).ok()?;
    let nanos = u64::try_from(time.tv_nsec)
        .ok()
        .filter(|n| *n < 1_000_000_000)?;
    seconds.checked_mul(1_000_000_000)?.checked_add(nanos)
}
