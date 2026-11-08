# Actual native owner observation evidence

Date: 2026-11-07 UTC. Starting commit:
`f8362822b406463ac3dfcc911a0c3eda1686e32d`.

This directory contains an actual execution of the native PNP1 producer,
complete PNW1 verifier, admission/application-state path, confirmation and
activation in two fresh local owners. The returned census is complete for
the admitted rows presently retained in one source-schema-bound SQLite
snapshot. It does not claim complete world inventory or an authenticated
physical execution. The mathematical and API scope is specified in
[`NATIVE_OWNER_OBSERVATION_V1.md`](../../../formal/pon-nakamoto-v1/NATIVE_OWNER_OBSERVATION_V1.md).

## Recorded native result

`actual_native_owner_run.json` contains 11 censuses, 82 recorded actual native
calls, two native confirmation outputs and three explicit comparison pairs.
`packets/` contains the full bytes of 19 native-produced valid packets and
one deliberately malformed product control. The packet paths, native IDs,
SHA-256 digests and byte lengths are exported by the actual native example;
the verification manifest independently rereads every saved packet and
checks its digest and length. Hash agreement is an integrity check on these
files, not execution attestation.

Every produced valid block in this retained run has native weight 2. The
scores below are decoded from actual 512-bit native work fields, rather
than inserted into a synthetic model.

| Snapshot | Retained rows including genesis | Selected score | Eligible maximum | Raw selection deficit |
| --- | ---: | ---: | ---: | ---: |
| `alice_confirmed_a7` | 8 | 14 | 14 | 0 |
| `bob_unseen_a1` | 1 | 0 | 0 | 0 |
| `alice_before_hidden_branch` | 8 | 14 | 14 | 0 |
| `bob_hidden_b8` | 9 | 16 | 16 | 0 |
| `alice_after_hidden_branch` | 8 | 14 | 14 | 0 |
| `alice_a9_admitted_not_active` | 10 | 14 | 18 | 4 |
| `alice_future_ancestor_deferred` | 12 | 14 | 18 | 4 |
| `alice_after_b8_admitted` | 20 | 14 | 18 | 4 |
| `alice_after_strict_reorg_b8` | 20 | 16 | 18 | 2 |
| `alice_future_mature_pending` | 20 | 16 | 22 | 6 |
| `alice_after_select_mature` | 20 | 22 | 22 | 0 |

The initial transaction really satisfies the current native confirmation
rule: six successors **and** the configured required-work threshold. A real
tie leaves the incumbent selected; a strictly heavier submitted target
later removes the confirmed transaction, even though another admitted
eligible chain has still greater work. An individually current-time child
remains deferred behind its future-dated ancestor. Once the validation clock
matures, the maximum rises without automatically selecting it.

Alice's `local_view_commitment` is identical immediately before and after
Bob builds the hidden branch. The process-local attempt counters and actual
`Instant` readings differ. The experiment claims equality of the complete
logical local view, not byte identity of the timestamped JSON or equality
of every operating-system observation.

## Checks and preserved attempts

- `test-attempt-02.log.gz`: all 10 native integration tests passed. They cover
  Legacy and AuthenticatedV1 replay, actual two-owner reorganization,
  callback cancellation and budgets, owner incarnation, retained product /
  work / packet corruption, a prior filtering SQL view, a foreign
  data-changing commit, and explicit PNP2 growth refusal.
- `native-run-attempt-01.log`: actual example completed and exported the
  retained JSON plus all 20 packets.
- `clippy-attempt-01.log`: strict Clippy passed for the library, new test and
  actual example with `-D warnings`.
- `format-check.log`: workspace `cargo fmt --all -- --check` passed; an empty
  log is the normal successful output.
- `cargo-graph.json` and `cargo-graph.stderr`: the full locked/offline Cargo
  graph resolved successfully; stderr is empty.
- `pq-message-oracle-build.log`: the existing RustCrypto ML-DSA-65 message
  oracle built successfully for the separate lifecycle-certificate task.

Failed attempts remain available:

1. `build-attempt-01.log` failed because the separate growth-rehearsal `Node`
   literal lacked the new lazy observer initializer. That literal now
   initializes it to `None`. This first attempt also reported the host
   SQLite qualification warning because the direct Cargo invocation lacked
   the managed toolchain library directory in `LD_LIBRARY_PATH`; later
   commands supply that directory and preserve the original gate.
2. `build-attempt-02.log` exposed private-module/helper imports and an error
   conversion in the integration target. Public observation types are now
   reexported; example hashing uses its existing public SHA-256 dependency;
   the test performs an explicit decode-error conversion.
3. `test-attempt-01.log` passed 8 tests and failed two setup expectations.
   The foreign-writer test originally used a no-op SQL update, which SQLite
   may elide; it now commits an actual data change, and the documentation
   explicitly denies an audit log of every transaction attempt. The growth
   refusal test now opens the required growth namespace before asking the
   PNP1-only API to reject it. No production validation gate was weakened.

## Exact local reproduction

The run used the managed Rust 1.95.0 toolchain and a private Cargo home and
target. The manifests and lockfile were not edited. The explicit low-memory
compilation settings below apply to this local evidence run; they are not a
production performance profile or a resource-security calibration.

```sh
export NATIVE_OWNER_TOOLCHAIN=/workspace/scratch/270e2a9ce94f/toolchain/rustup/toolchains/1.95.0-x86_64-unknown-linux-gnu
export PATH="$NATIVE_OWNER_TOOLCHAIN/bin:$PATH"
export RUSTC="$NATIVE_OWNER_TOOLCHAIN/bin/rustc"
export LD_LIBRARY_PATH="$NATIVE_OWNER_TOOLCHAIN/lib"
export CARGO_HOME=/workspace/scratch/b9454e263603/native_w1_cargo_home
export CARGO_TARGET_DIR=/workspace/scratch/b9454e263603/native_w1_target
export CARGO_BUILD_JOBS=1
export CARGO_INCREMENTAL=0
export CARGO_PROFILE_TEST_DEBUG=0

cargo test --locked --offline --manifest-path trillionnium/Cargo.toml \
  -p trnm-pon-node --test native_owner_observation \
  --config 'profile.test.package.trnm-pon-node.opt-level=0' -- --test-threads=1

cargo run --profile test --locked --offline --manifest-path trillionnium/Cargo.toml \
  -p trnm-pon-node --example native_owner_observation_v1 \
  --config 'profile.test.package.trnm-pon-node.opt-level=0' -- NEW_OUTPUT_JSON

cargo clippy --profile test --locked --offline --manifest-path trillionnium/Cargo.toml \
  -p trnm-pon-node --lib --test native_owner_observation \
  --example native_owner_observation_v1 \
  --config 'profile.test.package.trnm-pon-node.opt-level=0' -- -D warnings

cargo metadata --locked --offline --manifest-path trillionnium/Cargo.toml --format-version 1
cargo fmt --manifest-path trillionnium/Cargo.toml --all -- --check
```

Use a fresh output directory: the example reserves its output file and
packet directory, refuses overwrite, and preserves a failed attempt.
The produced native executable is
`/workspace/scratch/b9454e263603/native_w1_target/debug/examples/native_owner_observation_v1`.
It can be invoked directly with a fresh JSON path; Cargo is not required to
run the already built binary.

The successful test log is losslessly gzip-archived because its original output
ends with a blank line. `retained-log-archive.json` records the original name,
byte length and SHA-256 together with the archive SHA-256. The existing raw-log
entry in `verification.json` is checked after decompression; original bytes and
their hash have not changed.

`verification.json` records the exact arguments, environment, toolchain,
file and binary hashes, packet readback and result counts. `source_bindings.json`
records focused hashes of the changed observation implementation and native
identity/work/state/configuration dependencies. These source bindings are
not a complete compiler provenance proof; the parent integration evidence
and normal source/CI gates remain separate.

## Qualification boundary

The supported local snapshot checks and actual execution were exercised.
`native_runtime_attested`, `exported_artifact_authenticated`,
`global_ready_attested`, `world_coverage_attested`,
`physical_clock_authenticated`, `probabilistic_environment_bound` and
`six_successor_risk_qualified` are false; `probability_bound` is null.

The local maximum does not cover received-but-unadmitted bytes, pending
jobs, previously deleted rows, remote/private branches, first-ready output
times, residual preprocessing, or all-world resource accounting. Local
admission times cannot be substituted for any of those quantities. The
header timestamps and validation clocks here are controlled experiment
inputs, not delay or mining-rate measurements. The native unit-work
relation also remains distinct from the research MU1 `16*u` credit. No
six-successor risk value is produced or retroactively justified by this
run.
