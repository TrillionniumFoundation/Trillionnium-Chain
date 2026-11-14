# Worker artifact executor V2 — two narrow safeguards, prepared only

V1 and the original external V2 remain unchanged. This revision has not been transferred or executed. Preparation performed only immutable source reads plus AST parsing and compilation; no driver/helper/Cargo/format/Clippy/test/Host invocation occurred.

## Delta

1. The source receipt must contain exactly the eleven current producer fields. Schema, kind, head, candidate, tree, null fields and boolean fields require exact types and values. tracked_entries and tracked_bytes require type int, explicitly excluding bool, and positive values. Each command stdout must equal its sidecar bytes and the producer's canonical sorted, two-space JSON with one final newline. The after receipt and retained original before receipt must also match field by field with the same type, then match as raw bytes. Re-reading before's sidecar must still agree with the retained original before stdout; updating both later files cannot redefine that original input.
2. The selected artifact's safe open adds O_NONBLOCK and O_CLOEXEC to the existing O_RDONLY/O_NOFOLLOW flags. A path replaced by a FIFO between lstat and open cannot block waiting for a writer. Existing regular-file, identity, size, Git blob and SHA checks remain.

The summary schema is versioned v2. The fixed ten-method roster, two new controls, default harness, commands, environment, source-before/after sequencing, capture/timeout behavior and independent 180/1200/1200 component budgets are otherwise unchanged. The static review records exact AST equality for all old constants and nested capture helpers, plus the environment update and unchanged helper functions.

## Actual receipt reviewed

The fixed M8 head is ed0d35487f2a67239e4d646fd41c2c7acb5cc740, tree 1aa9c21812489080980bdc3c1c2bb43611e88354. The actual Mac prepublication source-before.json, source-after.json and both corresponding stdout files are the same 423 bytes, SHA256 a74be5eb0131658ed16c8e1988806ffa8886a3a6580a6cca2c5a41a1ee88538d. They report 41677 tracked entries and 3994947385 bytes, with exactly the eleven required fields.

These M8 values are provenance examples, not new hardcoded defaults. --head and --tree remain mandatory. Root's future launcher independently checks the expected M8 raw receipt; the generic driver validates positive typed counts and the complete before/after match.

## Files and execution boundary

producer.py is an exact copy of the new external executable. worker-v1-to-v2.patch.original is the complete V1-to-V2 diff. static-review.json and fixed-source-read.json bind the static checks, immutable M8 producer and real receipt origins. The V1 original copy and both original source scripts remain preserved.

No source, refs, stage, configuration, network or active ROG-run directory was modified. This component plan and any future pass do not establish hosted qualification or the separate four-second/16-worker confirmation requirement. Execution and ROG transfer still require root's explicit authorization.
