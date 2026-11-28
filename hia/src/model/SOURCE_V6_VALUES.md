# Private detached Model Source V6 value hashes
The two bounded immutable operations correspond to the original public
`model_source_composition_v6::{allocation_root,release_id}`. They take
inert digest labels and numbers and return hash bytes only. They do not
construct leaves from payees, allocate or transfer anything, authorize
release, touch a store, sign, or enter consensus/production.

* `AV61\0\0\0\0` plus a little-endian u64 leaf count and exactly that many
  32-byte leaves. One to four leaves use the original bound. A singleton
  is unchanged; each adjacent pair is lexicographically ordered before
  hashing, never the entire list. An unpaired tail is duplicated at
  each level. The order of the pair groups is preserved.
* `RV61\0\0\0\0` plus 32-byte network, parameters, parent, and bundle;
  little-endian u64 budget; 32-byte root; and little-endian u64 total.
  The size is exactly 184 bytes. These are transcript fields only,
  without range/economic policy beyond their original typed widths.

Both use the original PoN domain framing, with separate exact V6 IDs.
The caller supplies 32 disjoint output bytes and 2,208 private scratch
bytes. Only success publishes 32 result bytes; extra output is not
touched. Status 1 is original allocation count, 100 private wire,
102 capacity, 103 internal hash. Original locked Cargo tests use only
generated labels and purely in-memory supplied leaves.
