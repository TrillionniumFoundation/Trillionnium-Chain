# Existing Cell + explicit postprocessing v2

This crate extends the existing routed integer Cell with an explicit new
quantization/activation/terminal-decision relation. It links
[the existing Rust grouped operator](../../../trillionnium/crates/trnm-crypto-primitives/src/pon_routed_int257_grouped.rs),
and both direct and grouped producers use that original implementation. The
verifier reuses its independent scalar recomputation. The complete mathematical
contract and transport are in
[Useful Cell relation v2](../../../docs/development/specs/pon/USEFUL_CELL_NATIVE_POSTPROCESS_V2.md).

The result is a native correctness reference with complete witnesses, **not a
succinct or cheap proof**. State is read-only. STOP is this step's decision output,
not a mutable-state transition or a proof of subsequent continuations. The
profile has a new namespace, is unregistered and makes no consensus/Hepta
adoption, model-benefit, real-demand or mining-difficulty claim.

## Run from repository root

Use the repository-approved Rust toolchain and a dedicated target directory.
The checked-in Cargo.lock preserves the actual native package dependency graph.

```sh
bash scripts/project-preflight.sh
cargo test --locked --manifest-path formal/pon-nakamoto-v1/useful_cell_v2/Cargo.toml
cargo fmt --check --manifest-path formal/pon-nakamoto-v1/useful_cell_v2/Cargo.toml
cargo clippy --locked --manifest-path formal/pon-nakamoto-v1/useful_cell_v2/Cargo.toml --all-targets -- -D warnings
cargo build --release --locked --manifest-path formal/pon-nakamoto-v1/useful_cell_v2/Cargo.toml
python3 formal/pon-nakamoto-v1/useful_cell_v2/reproduce.py \
  --runner formal/pon-nakamoto-v1/useful_cell_v2/target/release/trnm-useful-cell-v2-reference \
  --out /tmp/useful-cell-v2-new-reproduction
```

With `CARGO_TARGET_DIR` set, use that directory's `release/` runner path. The
output directory must be new. The script emits canonical tasks, both native
binary claims, adversarial claims and `result.json`. It independently computes
all raw outputs using the existing Python scalar reference, computes every new
postprocess field, reconstructs the full binary frame and compares it byte for
byte with the Rust implementation. Its four-request known-answer commitment is
also locked in the Rust tests.

## Independent producer and consumer invocations

```sh
trnm-useful-cell-v2-reference produce expected-task.json new-claim.bin 20 grouped
trnm-useful-cell-v2-reference verify expected-task.json new-claim.bin 20
```

`direct` can replace `grouped`. The numeric origin is in caller-defined
nanoseconds; the CLI adds actual monotonic elapsed time during each process.
Provide compatible windows in the expected task. A produced claim path is
create-only so prior evidence is not overwritten. `verify` writes no claim.
Both commands return one JSON result only after full native verification.
The file CLI supports Unix regular files: it opens with nonblocking/no-follow
flags, then validates the opened descriptor's type and size. Writerless FIFOs,
directories, final-component symlinks and oversized files are rejected. Other
platforms fail explicitly at the file boundary; the in-memory relation remains
independent of this CLI. Ordinary filesystem/kernel waits still need an outer
process deadline when a hard service budget matters.

The consumer must obtain its expected task independently. In a source-backed
workflow, retain the existing artifact validator and source replay before
constructing this task. The JSON parser alone does not authenticate those inputs.
The synthetic fixture's provenance hashes are fixed test labels, not assertions
that a real program, model or source corpus was admitted.

## Scope of checks

- Exact original `3 x 257` base/router/delta coefficients, complete router and
  selected products, stable groups and original input order.
- Explicit signed division toward zero, quotient/remainder, clamp, optional
  ReLU, lowest-index argmax, margin and enabled/disabled STOP.
- Distinct input, contract and statement domains binding original model, full
  read-only state, provenance/use values, requests and time windows.
- Bounded exact 8,617-byte maximum claim decoding and 256 KiB maximum canonical
  task JSON parsing, including duplicate-key, shape, enum and numeric rejection.
- Rehashed false witnesses, different consumers/states/contexts, malformed
  frames, every single-byte tamper and completion crossing a deadline. Actual
  subprocess regressions also check task/claim FIFOs, symlinks, directories and
  oversized files under a finite watchdog.

No tests claim worst-case global service latency, preemption, proof soundness,
zero knowledge or useful model behavior. See [VALIDATION.md](VALIDATION.md) for
actual commands, outcomes, scope and preserved setup failures.
