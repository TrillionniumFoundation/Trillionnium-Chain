# Cell prefetch and local byte residency

Continuation of integration PR #688 from
`93e207c8d2ccb8509f78566223abc371b9d8118b`. This record contains source and
reproduction instructions for M09 byte staging, not a model-quality, GPU,
distributed-inference or production-activation receipt.

## Implemented behavior

`fetch_closure` shares the existing aggregate TCD1/TCR1 session and validates
every required member before reporting completion, without creating a marker.
The original `fetch_closure_to_file` and `fetch_release_to_file` keep their
create-only marker behavior. No protocol domain or persistent schema changes.

`CellResidencyV1::prefetch` is an explicit preparation operation supplied with
an owner's exact route prediction or cold-load selection. `prepare_cached`
recovers the same pinned mapping from the existing bounded disk cache without
network access. Neither method selects a version. Hot pins and the locally
selected mapping refuse eviction. Capacity exhaustion refuses the new admission
without replacing an existing resident or replenishing a transport reservation.

The resident pool shares immutable chunks by SHA-256 and length. Each file keeps
its own ordered mapping and complete payload hash; matching shared chunks do
not excuse a mismatching full payload or loader context. Aggregate retained
payload, closure count and chunk-reference count have explicit finite limits.
The retained-payload limit excludes allocator/metadata overhead, SQLite buffers,
one temporary chunk conversion and any tensor/device allocations by the host.

`with_local` and `with_selected` borrow exact prepared bytes with no store or
transport arguments. A borrowed result keeps the manager borrowed and prevents
mutable eviction in safe Rust. Owned Arcs never escape this pool. Lookups check
the owner's exact generation/profile/context/required roles and limits without
reading or hashing the weight payload. Their deadline bounds lookup admission;
the callback's computation and allocations remain the caller's responsibility.

`select_local` uses an owner-bound, monotonic CAS ticket plus an independent
absolute switch deadline. A stale ticket, including A -> B -> A, cannot change
the local selection. This process-local hint is not CURRENT or a use permit.
The actual Hepta owner must guard release selection, withdrawal, safe format and
shape checks, resource admission, tensor/device readback and FinalUse. Process
restart does not restore a local selection or hot pin from untrusted disk state.

The download deadline is fixed before acquisition and includes RAM staging.
Cancellation is checked before/after the complete fetch phase and at local
staging checkpoints. Fetch does not accept this external cancellation token:
it can continue downloading within its original deadline and byte/connection
budgets after the caller cancels. Synchronous
OS/SQLite calls are not hard real-time preemptible. A failed RAM admission may
leave verified disposable disk chunks, but no new resident or local selection.

## Reproduce

Use the repository's pinned Rust 1.95.0 toolchain, its unchanged workspace and
lockfile, and dependencies already present for offline commands:

```sh
bash scripts/project-preflight.sh
cargo metadata --locked --offline --manifest-path trillionnium/Cargo.toml --format-version 1 --no-deps
cargo test --locked --offline --manifest-path trillionnium/Cargo.toml -p trnm-data-availability --all-targets -- --test-threads=1
cargo test --locked --offline --manifest-path trillionnium/Cargo.toml -p trnm-data-availability --doc
cargo clippy --locked --offline --manifest-path trillionnium/Cargo.toml -p trnm-data-availability --all-targets -- -D warnings
cargo fmt --manifest-path trillionnium/Cargo.toml --all --check
cargo run --locked --offline --manifest-path trillionnium/Cargo.toml -p trnm-data-availability --example cell_residency_observer
python scripts/ci/test_ci_source_integrity.py
python scripts/ci/check_repository.py
```

The example starts a finite loopback TCP provider, prepares two versioned
closures sharing base/tokenizer bytes, stops and joins the provider, then
performs 1,000 local byte reads. It checks explicit cold miss, exact version,
generation, CAS conflict, quota, cancellation and expired-switch rejection.
Its fixtures are small deterministic bytes, not a tensor parser or model
forward. Download counters and unique resident-byte counts are component
observations; they do not establish WAN throughput, cold-load p99 or chain TPS.

The adjacent `reproduction.json` binds the actual validation observations to
source SHA-256 values, toolchain and commands. Failed checks remain recorded.

## Existing warm host and the remaining adapter

The reviewed Hepta source is
[`e0b4c82e`](https://github.com/TrillionniumFoundation/hepta-private-ci/tree/e0b4c82e129d42d98cb9a98bf97fe41d1e3b1b53).
Its `SmolLmNeuralReadPortV1` already retains a warm model before enabling the
ordinary cognitive request path. `start_physical` requires one model, one active
request and the existing 8-GiB grant. This is an existing fixed-model capability,
not evidence of dynamic multi-Cell residency from this change.

The current `SmolLmDriver::start` still launches the Python worker with protected
`--materials` and `--parent` files; `load` refuses a second live session. Chain's
`Plan.exec_owner` replaces its process image, so this process-local Arc pool
cannot survive that handoff as the new Hepta process's memory. The concrete next
adapter belongs on the existing `verify_controlled_cell_bytes` ->
`VerifiedCellMaterialV1::start_with_execution` -> `SmolLmDriver::start` path,
with the original authority/grant and loader checks retained. Shared prepared
bytes do not establish shared deserialized base tensors.

The reviewed Hepta V8 profile still pins Chain `73ab6e9a`; its historical source
qualification does not apply automatically to this new Chain source. A changed
worker/loader composition needs its own exact profile and physical readback.

## Acceptance still requiring the real owner/runtime

Integrate the resident views with the actual neuron route and loader owner,
reserve CPU/device memory, retain hot tensors, perform format/shape checks and
generation-fenced FinalUse, and read back the installed base/tokenizer/router/
Cell hashes before a real task. Measure the original cold and hot latency,
memory and failure cohorts with unchanged deadlines. The component cannot
supply these receipts or independently restore authority on restart.

Cross-node inference additionally needs its own activation and KV-cache
protocol, layer communication, scheduling and failure recovery. Those mechanisms
are outside this weight-preparation API and are not claimed by this record.
