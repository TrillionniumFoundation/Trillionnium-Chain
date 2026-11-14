# Generated source inventory correction

The frozen checkpoint `81da33e609cb64b319e8cfcca7059e5c30d39044` passed the four cache-constructor tests, but its subsequent source-inventory check and workspace formatter failed. The API-side integration had accidentally omitted the opening and path of the existing `public_cli.rs` inventory entry while inserting the new cache test. That broke parsing for examples importing this inventory; the narrow cache tests did not compile those examples.

The repository generator `scripts/refresh_distributed_source_inventory.py` rebuilt the file. The correction restores the existing entry and refreshes its one corpus pin. It changes no runtime cache policy, work relation, consensus parameter or acceptance assertion.

The failed outputs are preserved in [initial-source-inventory.log](initial-source-inventory.log) and [initial-rust-format.log](initial-rust-format.log). After regeneration, the inventory check, workspace format check and whitespace check all exited 0; see [regenerated-checks.json](regenerated-checks.json). This local validation used 81da33e plus the correction. The successor commit containing this record is the code identity for the next clean-checkout execution; prior results are not relabeled.

Corrected inventory Git blob: `b7eb36f77d93bf2c3ae272b34c5b8e66de7d8f5e`.
Corrected corpus Git blob: `f7949392d9819682764859e9a18e1707b7469689`.
All broad qualification gates remain HOLD.
