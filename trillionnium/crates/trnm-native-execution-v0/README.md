# `trnm-native-execution-v0`

Active zero-Comet deterministic application and durable execution-artifact-P
owner for the frozen PoCO-BFT v0 profile.

For ordinary, non-empty successor blocks, the application:

- opens one exact authenticated parent JMT snapshot containing committed
  parameters, signer policy, replay indices, validator lifecycle, PoCO state,
  and runtime objects;
- verifies exact signed outer bytes and executes the body in order, so later
  transactions observe earlier in-block writes;
- applies runtime, validator-lifecycle, PoCO/cutoff, and mandatory system
  writes to one collision-checked state plan;
- independently derives the payload, complete post-state, receipts, and
  empty-evidence roots;
- exposes an independent immutable preview request with no block ID or
  caller-supplied roots, returning only the four derived roots, exact receipts,
  and request/write-plan fingerprints; final execution recomputes everything;
- atomically records the canonical `NativeExecutedBlockV0` artifact, complete
  target snapshot/overlay, replay sets, lifecycle record, store identity, and
  monotonic local sequence in SQLite; and
- performs an immutable fresh-connection readback and recomputes the complete
  target JMT/root before it can return `Valid`.

Prepared P records form a BlockId-keyed overlay DAG rather than a height-keyed
single slot. Sibling forks can coexist, and a child can execute from the exact
fresh-confirmed snapshot of a prepared parent. The application commit ID is
derived when P is created, so a child's parent commitment remains stable when
that parent is later finalized. Committing is permitted only for the exact
child of the current committed head; it atomically promotes that finalized
prefix, retains its prepared descendants, and prunes losing siblings.
A QC is never interpreted as an application commit or finality instruction.

The schema-v3 journal also contains one separate fresh-genesis state-sync
import path. Given an exact h1 execution request and a nonzero proof identifier,
it independently recomputes the full transition from the initialized genesis
snapshot, atomically installs the h1 application TrustedBase, and records a
checksummed proof/request/artifact/snapshot binding. It deliberately creates no
local durable-P row, validation job, completion, terminal fact, or speculative
overlay. Retry and reopen require byte-exact proof/request readback; a foreign
proof, a previously used store, row tampering, or schema-v2 store is rejected.
The proof identifier remains comparison input: this crate does not verify BFT
finality, so only the Node's consuming Core/Safety/signer commissioning join may
use the confirmed import.

`DurableNativeApplicationV0` implements `NativeApplicationV0`. Its public owner
is non-`Clone`, the durable-P record is private, a second process is excluded by
an owner lock, and reopen validates the complete committed-prefix/overlay DAG.
Store substitution,
sequence rollback, artifact/snapshot/lifecycle/replay substitution, schema
drift, malformed/WAL SQLite sidecars, broken ancestry, duplicate sequences,
and non-exact commit requests fail closed. A regular hot rollback journal left
by a killed writer is repaired only through SQLite's own write-transaction
rollback path, followed by database-and-directory fsync and immutable
readback; WAL/SHM or unverifiable sidecars remain fail-closed.
An applied-but-acknowledgment-lost commit is recovered by exact idempotent
readback; either metadata-only or P-only partial-commit third states are
permanently fenced. Unresolved prepared P records yield
`ValidationReplayRequired` with their exact count.

## Authority boundary

This is a durable application boundary, not a complete validator safety path.
It has no Core permit or Valid callback, no SafetyStore authority, no whole-node
checkpoint/CAS, no signer watermark, no `RequestSignature`, and no signing,
network, or broadcast capability. It is not wired into the default Node
process host and is not a production candidate.

The current tranche is also intentionally narrower than the whole frozen-v0
protocol:

- evidence must be empty;
- the committed validator set/epoch supplied at store creation remains the
  execution authority; activation/handoff and a returned validator-set update
  are not implemented;
- a local SQLite sequence detects in-file rollback but is not an external
  whole-machine anti-rollback authority;
- a three-boundary SIGKILL matrix (before SQLite commit, after commit, and
  after directory fsync) plus critical-page short-write tests now prove the
  local commit coordinator's atomic/replay behavior; this is not a full
  power-loss, filesystem, or multi-process takeover campaign;
- directory fsync is attempted at the application commit boundary, but no
  external anti-rollback, file-descriptor pinning, remote signer, or whole-node
  checkpoint evidence is claimed; and
- deterministic invalid executions currently use one closed rejection code;
  production-grade typed invalid classifications remain future work.

Accordingly, `durable_artifact_p=true` and
`native_application_v0_implementation=true` do not imply Core/Safety authority
or production activation. Those truth values remain false in package and
project status metadata.

## Fixed differential corpus and historical audit

The automatic boundary gate never builds or executes the excluded historical
`trnm-consensus-app` archive. It binds the archived authoring source, the
archive-local lockfile, and the raw SHA-256 of the committed runtime/JMT vector,
then runs only the zero-Comet active consumer. The complete durable target is
also recomputed from its authenticated snapshot during fresh readback; the
caller-provided expected roots are never treated as execution authority.
`native-complete-durable-p-v0.json` additionally pins the full four-root
ordinary-body result, transaction-byte digests, local durable sequences, and
authority-false boundary for the two-transaction overlay witness. Its raw file
digest is bound by the gate and the Rust test independently recomputes those
values from the frozen inputs.

An explicit local historical audit may re-author and compare the frozen
runtime/JMT vector:

```bash
legacy_target="$(mktemp -d "${TMPDIR:-/tmp}/trnm-poco-legacy-vector-target.XXXXXX")"
trap 'rm -rf -- "$legacy_target"' EXIT
CARGO_TARGET_DIR="$legacy_target" cargo test \
  --manifest-path trillionnium/crates/trnm-consensus-app/Cargo.toml \
  --locked --offline \
  checked_native_execution_differential_vector_is_legacy_reproducible_v0
```

That command intentionally compiles archived Tendermint/ABCI dependencies. It
is manual historical audit only; automatic workflows and the main truth gate
must never invoke it.
