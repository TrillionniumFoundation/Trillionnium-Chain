# PN1 transaction observer pointer type correction — original development RED retained

The first actual development `cargo check` of R6 source `ff2ba31a4a1816b217ac58dc74a847411c3c98a8` failed with Rust E0282 at `transaction_scope.rs:77`: the raw pointer obtained from SQLite clientdata needed its pointee type before `.is_null()` resolution. The fix explicitly declares `*mut Observer`, the same private type already required by this function and its subsequent checks. It changes no stored/signed format, runtime authority, original assertion, timeout, resource limit, claim or guard.

The original single Cargo child selected both Node and SQLite boundary with `--tests --locked --offline --message-format=json`. Actual parent/child identity and wait101 were retained; the external job ended FAILED1/output_complete/not timedout after39.006s. Normal C build-fence evidence was emitted, but the 14 new controls did not finish compilation and were not executed. The source, locks and original C bytes remained unchanged during that failed check.

This was a separate development typecheck with its own fixed560/620s bounds, 2CPU/group8GiB/AS3GiB, total8MiB raw output and fresh6GiB monitored target. It is not a release build, public prepare, native caller, three-FD/whole-writer/reader, W1 pricing or full4097 qualification. It neither consumes nor resets the original public1200s budget and164.257s remaining allocation. Old failed/expired runs stay failed.

A corrected typecheck may use only a valid conservative inherited cutoff inside that same original development window, retain every first-attempt/time/raw/target charge, and verify actual old writers terminal. No new620s window, prepared flag or partial ELF promotion is granted. Until actual corrected-source completion is independently recorded, typecheck qualification remains false. `task_complete=false`, `merge_ready=false`, **NO_GO**.

The ordinary archive retains the complete first RED, exact raw outputs, collector/source/clock/resource evidence and external terminal. Live target and temporary compiler artifacts are excluded, not deleted or refunded. Every original member was read back against `members.json`.
