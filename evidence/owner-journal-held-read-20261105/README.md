# Restricted-owner held-file read observation

This local functional observation closes the demonstrated FIFO-substitution
hang in `operator_task_policy::open_held`. It does not close any of the eight
release gates in the [development plan](../../docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md).

The ordinary restricted-owner startup reaches this reader through
`Node::open_with_operator_task_policy` and `Journal::open`, for the retained
owner lock and JSON records. A same-UID writer with access to the private journal
can replace a checked regular file with a FIFO before its read-only open. The
old open blocks before descriptor validation. This is a local availability
boundary, not a demonstrated remote authorization or signature bypass.

The fix adds `O_NONBLOCK` and keeps the existing descriptor identity checks and
lock lifecycle. A private post-path-check helper provides the deterministic
substitution seam. The retained test covers normal reads, wrong UID and
FIFO/directory/symlink/hardlink replacements. The parent requires a completion
marker, so a child test filter that executes no test cannot pass silently.
Regular filesystem I/O is still not preemptible and receives no hard deadline
claim from this flag.

## Failed observations preserved

- `owner-held-before.txt.gz`: an extracted-function syscall regression using the
  old open flags failed after the bounded child remained blocked for five seconds.
- `owner-held-after.txt.gz`: the corresponding initial extracted-function fix
  passed. These are preliminary component runs, not complete crate tests.
- `owner-held-clippy-initial.txt.gz`: actual crate checking rejected the initial
  test's unsafe FIFO helper under `forbid(unsafe_code)`. The retained test now
  uses safe `rustix::fs::mkfifoat`; no lint was weakened.
- `scanner-before.txt.gz`: the separate PQ source inventory regression reproduced
  acceptance of a same-size symlink substitution. `scanner-after.txt.gz` preserves
  all 15 passing scanner controls. That fix was published separately as
  `b58e36c5aa74343a0fe05e5b37f988c875c26acb`. The scanner still reports HOLD.

## Final native checks

The exact Rust inputs are listed in `owner-held-final-source.sha256`.
The locked, offline build used the repository's package optimization settings,
with `CARGO_PROFILE_TEST_DEBUG=0`, `CARGO_INCREMENTAL=0` and one Cargo build job
to avoid deleting other work from a low-disk environment. This is a functional
regression build, not the original resource or test-profile performance gate.

- `owner-held-native.txt.gz`: actual `trnm-pon-node` library regression passed.
- `owner-held-policy-tests.txt.gz`: all 18 selected owner-policy tests passed;
  the one ignored child helper was explicitly executed by its bounded parent.
  The other 1,130 library tests were not selected and are not claimed passed.
- `owner-held-clippy-final.txt.gz`: `cargo clippy --locked --offline
  -p trnm-pon-node --lib --tests -- -D warnings` passed on the final Rust source.
- Workspace formatting, locked/offline Cargo metadata, distributed source
  inventory, 16 project-boundary controls and 43 source-integrity controls passed.

The measurements above are local observations. No public service, complete
native-suite, PQ qualification, production activation or independent long-run
acceptance is inferred from them.
