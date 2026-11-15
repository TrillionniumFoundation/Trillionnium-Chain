# Actual Mac validation

Implementation commit: 5a9d07decd7101da11cc483dff0ca24b9c5ca0ae.
Implementation tree: f2b7a9fc2a26486319deeea18f62c5f41d4cf6d4.
This delivery child adds only these validation records.

The exact committed implementation passed 58 targeted Python controls (5 selector,
36 execution reader, 17 complete-block reader) and 43 negative source controls.
These are controls and byte-bound historical readbacks, not native business
throughput observations. The exact-commit receipt records all command arguments,
exit codes, raw stream digests and unchanged source bytes.

The first batch preserves missing contract_wire import failures and a new final
blank-line refusal in the development plan. Its 17 block and 43 source controls
passed. Original source dependencies were subsequently materialized, exactly one
extra final LF was removed from the plan, and the separate follow-up completed
58/58 targeted controls and reproduced the original CI readback byte-for-byte.
The earlier prepared receipt and failed batch are not rewritten.

The official PQ corpus and CI contract checks still refuse the sparse checkout
because required sources are absent. They are retained as failed commands;
complete guard validation belongs to a fresh full checkout. No Cargo graph,
Clippy, native build, original four-second or thirty-second campaign was run here.
SSH authentication identified ProfHepta. Setup transport failures and source
scope are retained separately. Production activation remains false; HOLD remains.
