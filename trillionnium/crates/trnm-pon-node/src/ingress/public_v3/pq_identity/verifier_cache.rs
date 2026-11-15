//! Bounded reuse of canonical ML-DSA public-key expansion, never a signature
//! verdict or current authority. Every call verifies its exact fresh message.
//! The owning AuthenticationBudget reserves attempts and bytes before this code;
//! its original measured interval accounts for lookup, expansion and verification.
//! The cache shares that volatile ListenerIntake epoch. It cannot replenish credit,
//! extend a cookie or supply a role/generation.
//!
//! Eight fixed slots retain only PqNativeVerifier's immutable key material.
//! Transient in-flight Arc references and the ordinary per-call verifier workspace
//! are additional; the slot bound is not a whole-process RSS claim. Locks cover
//! only bounded lookup/publication, never key expansion or signature verification.
//! Contention/poison means ordinary fully charged verification without retention.
use super::{PqNativeVerifier, Result};
#[cfg(test)]
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use trnm_protocol::pon_wire::Hash;

const MAX_VERIFIERS: usize = 8;

#[derive(Default)]
struct Entries {
    keys: [Option<Arc<PqNativeVerifier>>; MAX_VERIFIERS],
    replacement: usize,
}

#[derive(Default)]
pub(super) struct VerifierCache {
    entries: Mutex<Entries>,
    #[cfg(test)]
    expansions: AtomicU64,
    #[cfg(test)]
    hits: AtomicU64,
}

impl VerifierCache {
    fn cached(&self, spki: &[u8], expected: Hash) -> Option<Arc<PqNativeVerifier>> {
        let entries = self.entries.try_lock().ok()?;
        entries.keys.iter().flatten().find_map(|key| {
            // The digest alone is never an exact-key cache hit. Equality of
            // all canonical SPKI bytes also preserves algorithm/encoding checks.
            (key.public_key_id() == expected && key.public_spki().as_slice() == spki)
                .then(|| Arc::clone(key))
        })
    }

    fn publish(&self, key: Arc<PqNativeVerifier>) {
        let replaced = {
            let Ok(mut entries) = self.entries.try_lock() else {
                return;
            };
            // Another listener may have completed the same expansion while
            // this caller verified. It must not consume another retained slot.
            if entries.keys.iter().flatten().any(|existing| {
                existing.public_key_id() == key.public_key_id()
                    && existing.public_spki() == key.public_spki()
            }) {
                return;
            }
            let index = entries.replacement;
            entries.replacement = (index + 1) % MAX_VERIFIERS;
            entries.keys[index].replace(key)
        };
        // Free an evicted expansion outside the small publication lock.
        drop(replaced);
    }

    pub(super) fn verify(
        &self,
        spki: &[u8],
        expected: Hash,
        message: &[u8],
        signature: &[u8],
    ) -> Result<()> {
        let (key, fresh) = match self.cached(spki, expected) {
            Some(key) => {
                #[cfg(test)]
                self.hits.fetch_add(1, Ordering::Relaxed);
                (key, false)
            }
            None => {
                let key = PqNativeVerifier::from_pinned_spki(spki, expected)
                    .map_err(|_| "PUBLIC_CALLER_SIGNATURE")?;
                #[cfg(test)]
                self.expansions.fetch_add(1, Ordering::Relaxed);
                (Arc::new(key), true)
            }
        };
        key.verify_exact_message(message, signature)
            .map_err(|_| "PUBLIC_CALLER_SIGNATURE")?;
        // A malformed/unverified caller cannot churn the retained keys. An
        // existing key still performs full verification of every bad signature.
        if fresh {
            self.publish(key);
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "verifier_cache_tests.rs"]
mod tests;
