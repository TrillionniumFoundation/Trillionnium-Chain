# PoCO AI-native v1 cross-plane fresh-readback candidate

## PoN target and current-source scope

This crate remains existing implementation/reference source; this documentation does
not turn it into a PoN runtime. Selected development profile: `pon-nakamoto-v1`.
Source owner: M13. Target responsibility: Work-verified sync, probabilistic clients and fresh-instance migration.
See [M13 technical contract](../../../docs/modules/M13_STATE_SYNC_MIGRATION_TECHNICAL_SPEC_V1.md) and the
[PoN protocol](../../../docs/protocol/pon-nakamoto-v1/README.md).

Reuse bounded download/staging, exact root reconstruction and classified legacy proof readers.
New PoN sync/confirmation proofs need explicit new codecs; WeakSubjectivityAnchorV0 cannot be
renamed a PoN work anchor.

## Retained implementation documentation

The source interfaces, stored formats, commands and tests below retain their actual
legacy/profile semantics. PoCO consensus is retired as the target. No old finality,
committee, vote, consumption weight or test pass is new neural-work/efficacy evidence.


This crate joins five independently authenticated local candidate stores: transaction-batch DA,
Agent/Market, Verify/Challenge, MVCC/Fee, and Consumption/Settlement. It takes two complete fresh
readback samples and accepts only when all identities, sequences, order heads, state roots,
journal-tail roots, typed lifecycle identifiers, and the selected certified DA batch remain exact.
The DA head and certificate are projected from one explicit SQLite read transaction; each
terminal receipt must also match the sampled store identity, sequence/height, Order head and
state root. The supplied Order-proof digest is still a trust input, not verified authority.

The result is deliberately narrow. It proves a stable read-only co-observation at one instant. It
does **not** create a cross-database transaction, whole-node checkpoint, anti-rollback authority,
Order proof, Node process integration, protocol implementation, production candidacy, or
activation. Those global claims remain false until a later Node-owned CAS consumes the five exact
store identities, sequences, roots, and journal tails.
