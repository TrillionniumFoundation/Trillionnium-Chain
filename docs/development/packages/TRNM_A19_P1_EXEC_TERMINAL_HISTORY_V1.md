# A19 / P1-EXEC terminal finalization history v1

Status: **candidate-implemented / verification pending / no production activation**

This package records the repository-owned durable-history slice that follows
the G1-R4B application queue.  It is subordinate to the canonical Chain Plan
and cannot close the application, Core, recovery, release, or external gates.

## Exact boundary

```text
repository = TrillionniumFoundation/Trillionnium-Chain
candidate_branch = feature/chain-g1-external-blocker-closure-20260830
candidate_base = 1663abd8935be4e5819f5ff0c7ded250a3664097
implementation_refs = a34ae75d5, 75308f1d3, 4541832ea, b82bfe90c, 56f637686
plan = docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md
stage = G1-native-host-incomplete
authority = candidate
classification = candidate-non-normative
production_candidate = false
production_consensus_activation = false
```

The candidate source identity is recomputed from the final commit and tree at
each verification.  A generated report must not claim the hash of a future
commit that contains that report.

## Implemented candidate contract

`trnm-native-application` supplies the typed finalization intent and exact
application readback.  `trnm-native-application-sqlite` exports
`SqliteNativeFinalizationHistoryV0`, with the following contract:

```text
append exact successor -> NewlyAppended(record)
repeat the same sequence/bytes -> ExactReplay(record)
gap, parent drift, target/proof collision -> reject without mutation
audit/reopen -> recompute the complete ordered chain and committed head
```

Each record binds the parent and target heads, proof/body/overlay/JMT plan
digests, committed head, JMT root, application receipt digest and durable
sequence.  A record digest and a scope-bound hash chain are stored alongside
the canonical bytes.  SQLite uses strict tables, `synchronous=FULL`, WAL mode,
and a bounded one-million-entry history.  Schema, scope, initial head,
sequence, record bytes, target/proof identities and chain digests are checked
on every open/audit/readback.

The application queue remains responsible for ancestor ordering and fork
retention; this SQLite journal is the durable receipt/history projection, not a
Core acknowledgement or a finality authority.

## Verification already covered locally

The focused tests exercise:

- append, close/reopen, exact replay, sequence reads and chain audit;
- skipped sequence, conflicting replay and parent drift with unchanged state;
- tampered record and metadata rollback detection;
- persistent scope/initial-head identity and symlink rejection.

The candidate branch also runs the native-application queue tests and the
SQLite boundary/clippy checks.  Exact command results are recorded by the
final verification run, not inferred from a remote workflow or a fixture.

## Explicit non-claims and remaining handoffs

This slice does **not** provide:

```text
Core/Safety/checkpoint atomicity or a production finalization callback
authenticated body/parent/runtime/chain-context source loading
external monotonic anti-rollback or HSM custody
physical power-loss/controller-cache evidence
cross-database commit, production application integration or receipt ownership
independent review, real multi-host campaign, soak or activation evidence
```

The journal must fail closed if its path, schema, identity, chain head or
record bytes are replaced.  Path/descriptor identity hardening and adversarial
replacement tests are tracked as a follow-on candidate repair; until that
repair and an independent exact-source replay are accepted, A19 remains
`BLOCKED_UPSTREAM` for release purposes.  No local test changes any machine
truth or promotion flag.

## Required exact-head commands

```sh
bash scripts/project-preflight.sh --dev
cargo fmt --manifest-path trillionnium/Cargo.toml --all -- --check
cargo test --manifest-path trillionnium/Cargo.toml -p trnm-native-application --all-targets --locked
cargo test --manifest-path trillionnium/Cargo.toml -p trnm-native-application-sqlite --all-targets --locked
cargo clippy --manifest-path trillionnium/Cargo.toml -p trnm-native-application --all-targets --locked -- -D warnings
cargo clippy --manifest-path trillionnium/Cargo.toml -p trnm-native-application-sqlite --all-targets --locked -- -D warnings
```

Any change to the plan, protocol registry, application receipt, history schema,
toolchain, dependency lockfile or validator configuration invalidates this
candidate evidence and requires a fresh source-bound replay.
