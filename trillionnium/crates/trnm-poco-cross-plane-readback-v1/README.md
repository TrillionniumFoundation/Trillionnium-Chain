# PoCO AI-native v1 cross-plane fresh-readback candidate

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
