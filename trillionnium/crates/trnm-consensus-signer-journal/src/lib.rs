//! Independent, append-only anti-equivocation journal for PoCO-BFT v0 signers.
//!
//! This crate owns no private key and provides no production signing
//! implementation. A caller must supply both a signature producer and a
//! separately administered monotonic watermark. The SQLite journal is local
//! crash-recovery state; it is deliberately not treated as protection against
//! restoring or cloning its whole namespace.
//!
//! Before invoking the producer, the journal validates the complete
//! [`trnm_consensus_types::CanonicalSignIntentV0`], durably appends its intent
//! event, and advances the external watermark. A produced signature is
//! verified, durably appended as a second event, reflected in the external
//! watermark, and only then returned. Exact signed-intent replay reads the
//! persisted signature and never invokes the producer again.
//!
//! One unavoidable injected-producer window remains: a crash can occur after
//! an HSM/KMS has signed but before the signature event commits. Recovery may
//! invoke the producer again for the already prepared fingerprint. Therefore
//! the producer contract requires exact RFC 8032 Ed25519 replay; this journal
//! does not claim to manufacture that property for an external signer.
//!
//! This boundary is an anti-equivocation/replay journal, not Diem-style
//! SafetyRules. It does not persist or validate locked QC, preferred round, or
//! proposal ancestry, and its external watermark binds the signer event-chain
//! head rather than the complete `SafetyState` head. Consequently it cannot by
//! itself preserve HotStuff lock safety after a whole SafetyStore rollback.
//! Production activation remains blocked on a host-level reconciliation proof
//! that binds Core/SafetyState, this journal, and the external watermark.
//!
//! Journal v0 is Linux-only and assumes a local filesystem with reliable
//! SQLite POSIX locks, `flock`, `fsync`, and stable inode identity. It does not
//! certify NFS, SMB, FUSE, overlay filesystems, fork-after-open, or an
//! untrusted same-EUID process.

mod error;
mod hash;
mod model;
mod schema;
mod sqlite;

pub use error::{
    ExternalWatermarkErrorV0, SignatureProducerErrorV0, SignerJournalConflictV0,
    SignerJournalErrorV0,
};
pub use model::{
    ExternalMonotonicWatermarkV0, SignatureProducerV0, SignatureRequestV0, SignerJournalProfileV0,
    SignerWatermarkV0,
};
pub use sqlite::{JournalCapacityV0, SqliteSignerJournalV0};
