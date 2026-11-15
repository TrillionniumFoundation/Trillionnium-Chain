# Bounded initialization intent reads

Validated source `6665c7a923a5401b67bd663869b6b95765a735c2`, based on `8cd374d2679a7a7efbc4a0713185e790260f414a`.

## Defect and fix

The shared node startup path previously used an unbounded read of `initializing.json` after checking its pathname. A damaged large/sparse marker consumed its entire length before exact-context rejection. Replacing the file after that check with a FIFO could block startup; a symlink could be followed. This concerns a locally writable or corrupted namespace, not a demonstrated remote network attack.

The new read opens one descriptor with no-follow, nonblocking and close-on-exec flags, checks that descriptor is a regular single-link file, and consumes at most the expected canonical byte length plus one sentinel byte. The caller still requires exact canonical byte equality. Incorrect regular bytes retain `INITIALIZATION_CONTEXT`; descriptor type/link failures use `NAMESPACE`, and OS I/O errors remain I/O errors. No bad marker is deleted or silently rebuilt, and recovery remains before SQLite opening at the same startup point. Read bytes are bounded; no process RSS or filesystem-wide resource bound is claimed.

## Validation

Original Cargo test configuration: **161 ordinary tests passed, zero failed**, plus one existing ignored test. The special-file subprocess entry is intentionally ignored by ordinary discovery, but actually executes inside the new parent regression with a 30-second timeout and completion sentinel. It was also explicitly executed for a retained raw log covering 16 combinations of legacy/authenticated startup, direct/helper versus post-precheck substitution, and FIFO/directory/hardlink/symlink. That duplicate execution is not added to the 161 total.

Four new ordinary regressions cover exact error semantics for empty/truncated/changed/trailing/64 MiB sparse files, unchanged database and intent bytes on rejection, legacy/authenticated cold reopen and all four initialization fault hooks, bounded consumption including interrupted/erroring readers, and special-file refusal followed by genuine recovery. The finite excess counting-reader fixture fails promptly if its byte bound is removed. The fault-hook tests do not substitute for the existing true-process-cut integration suite, which was not rerun in this local validation.

Strict workspace/all-target/all-feature Clippy, formatting, 37 source controls, 100 CI controls, 526 source pins, 26 inline workflow pins, source inventory and the committed-source repository check passed. OpenSSL/provider and global original native campaign/Host F0 qualifications are separate. The existing CI gates remain, with exact-name checks added for all four new regressions.

See [verification](verification.json) and [raw logs, patch and reproduction job](raw-validation.zip). The subsequent evidence-only commit does not alter tested code. No activation, release or global blocker closure is claimed.
