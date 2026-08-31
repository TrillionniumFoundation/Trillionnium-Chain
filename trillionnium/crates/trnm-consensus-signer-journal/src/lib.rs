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
//! Schema1 preserves the same boundary explicitly:
//! `safety_rules_evaluation=false`, `safe_vote_authority=false`, and
//! `production_activation=false`. Canonical Vote/Timeout intent revision and
//! shape are conflict/accounting inputs, not proof that locked-QC or proposal
//! ancestry rules passed. Any future runtime integration must first consume an
//! unforgeable, durably persisted SafetyRules admission in the same trust
//! domain before this journal may reach a signer producer.
//!
//! Proposal witnesses use the separate [`ProposalSignatureProducerV0`] seam.
//! They are not journaled by this crate and are not admitted by the current
//! Unix remote-signer protocol; callers must keep that seam disabled until a
//! proposal-specific durable conflict key and SafetyRules authorization are
//! implemented.
//!
//! Schema1 also has no atomic migration of a schema0 external-watermark scope.
//! It therefore cannot claim to prevent the same key from signing concurrently
//! through an old journal or another scope. Schema0 remains read-only to the
//! schema1 API; runtime wiring remains v0 and inactive.
//! Existing journals can be opened through a two-phase startup boundary:
//! [`PinnedSqliteSignerJournalV0`] authenticates and pins the local namespace
//! and observes the external watermark without advancing it; only its
//! owner-consuming activation may repair the single allowed local-first event
//! window and release an operational [`SqliteSignerJournalV0`]. This makes a
//! later cross-store startup refusal side-effect-free with respect to the
//! external watermark.
//!
//! Journal v0 is Linux-only and assumes a local filesystem with reliable
//! SQLite POSIX locks, `flock`, `fsync`, and stable inode identity. It does not
//! certify NFS, SMB, FUSE, overlay filesystems, fork-after-open, or an
//! untrusted same-EUID process.

mod error;
mod handoff_error_v1;
mod handoff_model_v1;
mod handoff_schema_v1;
mod handoff_sqlite_v1;
mod hash;
mod model;
mod schema;
mod sqlite;

pub use error::{
    ExternalWatermarkErrorV0, SignatureProducerErrorV0, SignerJournalConflictV0,
    SignerJournalErrorV0,
};
pub use handoff_error_v1::{HandoffSignerJournalConflictV1, HandoffSignerJournalErrorV1};
pub use handoff_model_v1::{
    HandoffSignatureProducerV1, HandoffSignatureRequestV1, HandoffSignerJournalProfileV1,
    StrictOldSetHandoffAdmissionV1,
};
pub use handoff_sqlite_v1::{
    inspect_signer_journal_schema_read_only_v1, SignerJournalSchemaKindV1,
    SqliteHandoffSignerJournalV1,
};
pub use model::{
    signer_journal_lifecycle_nonce_v0, ExternalMonotonicWatermarkInjectionV0,
    ExternalMonotonicWatermarkV0, ExternalWatermarkSemanticBindingV0,
    ExternalWatermarkSemanticFactsV0, ProposalSignatureProducerV0, ProposalSignatureRequestV0,
    SignatureProducerV0, SignatureRequestV0, SignerJournalProfileV0, SignerWatermarkV0,
};
pub use sqlite::{
    ConfirmedSignerNodeCheckpointFactsV0, JournalCapacityV0, PinnedSqliteSignerJournalV0,
    SignerExternalWatermarkRelationV0, SignerJournalActivationFailureV0,
    SignerJournalLifetimeInventoryV1, SignerJournalReconciliationFactsV0, SignerJournalTailFactsV0,
    SignerJournalTailStateV0, SignerNodeCheckpointIdentityV0, SignerPreparedIntentFactsV0,
    SqliteSignerJournalV0,
};
