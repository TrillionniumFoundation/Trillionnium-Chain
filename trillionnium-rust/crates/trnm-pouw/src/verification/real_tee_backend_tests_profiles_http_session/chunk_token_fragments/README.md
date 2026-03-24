# chunk_token_fragments recovery notes

This directory was found in a half-split state:

- `chunk_token_fragments.rs` already referenced five child modules
- only `token_fragment.rs` still existed on disk
- the four siblings (`fragment_slice.rs`, `slice_shard.rs`, `shard_unit.rs`, `unit_cell_atom.rs`) were missing
- no tracked Git history, stash entry, or local backup for the missing files was found

To remove the red-flag half-split state without inventing new behavior, the surviving `token_fragment.rs` content was repartitioned into five compile-safe modules:

- `token_fragment.rs` — token-fragment planner
- `fragment_slice.rs` — token-fragment exchange
- `slice_shard.rs` — projection-resolution adapter
- `shard_unit.rs` — fail-closed rejecting exchange stub
- `unit_cell_atom.rs` — panic-on-unreachable projection adapter stub

This preserves the exact recovered logic while matching the already-declared module layout.
