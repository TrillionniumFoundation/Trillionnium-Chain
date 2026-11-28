# Borrowed selected manifest guard

The original adoption owner reads the complete selected TCV1 from its durable
catalog while holding a SQLite Immediate transaction. The new callback receives
a borrow of that actual catalog value, after the same execution-boundary,
filesystem lease, audited snapshot and selected-commitment checks.

`with_selected_commitment_guard` delegates to the manifest-bearing method and
discards the additional callback argument. Its check order, writer reservation,
before/after lease checks and transaction commit remain unchanged. This avoids
asking a later typed reader to accept a separately supplied candidate manifest
as the source of the selected file's payload pins.

The borrow lasts only through the callback. Copied metadata can outlive it but
is an observation that may become stale immediately. No method installs a model,
changes selection, authenticates a publisher or grants host execution, current
permission, withdrawal, resources, FinalUse, payment or settlement. A caller's
ordinary execution owner must hold its existing guards around any actual effect.

Two repository tests use the real existing SQLite owner fixture. They check the
selected catalog bytes, rejection of wrong/stale/unselected identities and
changed execution pins, exclusion of another cooperating writer while the
manifest is borrowed, and writer release after callback failure. They do not
substitute a mock owner or claim a real user/model adoption.

Those repository tests have been added for the corresponding complete-crate CI.
No local full-crate build or SQLite test execution is claimed in this layer.
The prior PFT loader/core gates are not rerun. Source review and formatting are
distinct from native type checking, runtime verification and scientific utility.
