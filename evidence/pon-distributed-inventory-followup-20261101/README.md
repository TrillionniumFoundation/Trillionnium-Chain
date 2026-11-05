# Distributed native source inventory follow-up

Date: 2026-11-01. This fixes the source-inventory check reported by the
`repository-truth` CI job for Chain
`acd8f79f2dcc22ecdee1d1a5fd88d619d06f37c9`, tree
`4e83d2d4ba6b15ddd962ef08652dbeb24858c533`.
All strict PN0–PN6 exits remain HOLD. Prior execution evidence is retained
unchanged and is not promoted by this correction.

The [original generator](../../scripts/refresh_distributed_source_inventory.py)
produces an `include_bytes!` path inventory, not a list of stored hashes.
The checked-in inventory had 1,108 unique entries. The complete source Git tree
requires 1,127 under the original selection rules: the native crates' Rust/Cargo
files, configuration JSON/Rust/Cargo files, and the top-level Cargo manifest/lock.
The missing 19 entries were already present in the cea95 parent source: one
diverse-training configuration, three post-write readback files, and fifteen
SQLite I/O boundary files. The exact paths are retained in `receipt.json`.

Before regeneration, every one of the 1,127 selected local regular files was
checked against its blob in the complete acd8 Git tree. There were no missing
local entries, extra paths, duplicates or byte mismatches in that selected set.
The original generator's filesystem enumeration matched that complete Git set;
no absent historical archive was silently dropped. This selected-set check does
not claim that the whole sparse restored checkout is complete.

The unchanged original generator was then executed. Its only source change is
133 added lines for those 19 entries, with no removal. The original `--check`
first reproduced the failure, then passed after regeneration. Rustfmt for the
generated file and `git diff --check` passed. The current PQ corpus checker still
matches all 346 pins and explicitly reports HOLD_NO_GO.

The inventory SHA-256 changes from
`c8befc0550e2c0626f3ed6eb3aa0f46fdd6883cc38702b3db96c62c931788825` to
`7e441f33cafc4e44dda73dc7103d217576872f6f53612d45d3efe5d71f672eff`.
The original generator, CI gate, workloads and budgets are unchanged. The three
restored historical qualification manifests that identify earlier inventory
bytes keep their historical source identities. The active corpus and workflows
do not pin this inventory's old hash, so no companion hash change is needed.
The inventory embeds source bytes at build time; there is no hash cycle.

`receipt.json` preserves both inventory identities, exact full-tree set digests,
the 19 added paths with source blobs, and command stdout/stderr/exit codes.
This follow-up does not report a complete repository-truth job, native build,
performance gate, model loop, independent WAN run or migration acceptance.
The companion must select the actual successor commit/tree after publication.
