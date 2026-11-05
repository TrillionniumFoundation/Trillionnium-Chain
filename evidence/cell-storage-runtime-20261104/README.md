# Cell runtime composition and bounded observations

This continuation uses the existing Chain integration PR #688, starting from
`47b4a62463d8e1371a175c74196d52d99c5fccb8` (tree
`c8f3b8e6f5a602edb380f89e1ad941b8d0d374fe`). Protected main was observed as
`dd6e1c3cbeacbdc532b0679297835b3a0aac78f0`. It follows the
[sole plan](../../docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md)
and [storage contract](../../docs/development/specs/pon/CELL_MODEL_STORAGE_V1.md).

The old residency continuation directory reported in #688 was absent in this
execution environment. These changes were implemented and tested from the
available exact source, not reconstructed by claiming the missing source's
identity or inheriting its earlier test results. The old 272,189,990-byte
cold-transfer failure and unexecuted native model load/query/unload remain open.

## Changes and boundaries

- Typed resident tensor admission reuses the existing complete safetensors
  parser and payload hash checks. It returns borrowed exact dtype/shape/ranges,
  supports safe cross-chunk F32 reads, and cannot outlive its resident manager.
  Cold misses have no disk or network fallback. This does not install a device
  tensor, authorize FinalUse or execute the real model.
- Complete-release retention enters through the ordinary Node funding owner,
  M12 effect journal and TCA2 root catalog. The root task and each original
  physical member have distinct immutable funding claims. Complete preflight
  grants no authorization; actual mutations repeat their owner checks.
  Pending/Done effects never copy again, repairs require separate original
  funding, and retirement checks the original journal plus the current native
  anchor before rooted GC. Partial state remains charged; no cross-store atomic
  transaction, native coin lock, provider payout or automatic renewal is claimed.
- Original prefetch cancellation now reaches the shared transport owner. A
  session remains cancelled after observing its caller's flag; bytes already
  read stay accounted, and honest peers are not quarantined for local expiry.
  Blocking connect/filesystem/SQLite boundaries remain cooperative.
- Opt-in provider Ready follows reader validation and listener setup. The real
  handoff waits for this event inside its unchanged 35-second aggregate window.
  Bounded pipe framing prevents a partial line from adding an unbounded wait.
- A five-workload observer performs actual fixed-base TCX1 retrieval over
  loopback, hashes every materialized target, and independently queries stored
  object counts after closing writers. It reports losing cases as well as
  savings. Its nine-version synthetic cohorts are not a real model distribution,
  a WAN campaign, or a long-term retention observation.

No stored encoding or existing signature domain is reinterpreted. New release
effect subjects/receipts use explicit v2 domains. Existing activation and
qualification flags remain false.

## Reproduce

Use the repository's Rust 1.95.0 toolchain, original Cargo profiles and lockfile,
one Cargo build job, and the complete locked dependency cache. Keep outputs
outside the checkout. The commands are in [reproduce.sh](reproduce.sh).

```bash
export CARGO_BUILD_JOBS=1
export RUSTC="$(rustup which rustc --toolchain 1.95.0)"
cell_source="$(git rev-parse HEAD)"
cell_receipts="$(mktemp -d)"
for scope in native checks clippy; do
  python3 scripts/ci/record_pq_native_command.py \
    --kind head --candidate "$cell_source" --tested "$cell_source" \
    --label "cell-runtime-$scope" --output "$cell_receipts" \
    -- bash evidence/cell-storage-runtime-20261104/reproduce.sh "$scope"
done
cargo run --manifest-path trillionnium/Cargo.toml --locked --offline \
  -p trnm-data-availability --example cell_delta_workload_observer \
  > "$cell_receipts/delta-workloads.json"
```

`native` includes all M09 library/CLI/example targets, compile-fail docs, the
complete M12 library, and the Node storage-service owner tests. It does not claim
the complete Node/Hepta business suite, all hardware targets, ordinary model
training/inference, or remote CI acceptance. `checks` covers source pins and
negative controls, closed graph metadata, formatting and repository links.

The composition also preserves concurrent `04be5f02` monetary-range and Growth
activation fixes. Five exact M06 conservation/capacity controls and two exact
Node activation controls cover their relevant overlap with the funding owner;
the existing named-libtest checker requires each selected control to execute.

The existing native SQLite build fence requires the absolute canonical compiler
path. Selecting Rust 1.95.0 through PATH alone does not satisfy that fence. The
first development Node build retained its `RUSTC must be absolute` observation;
later runs select the actual compiler without changing the fence or profiles.
Use the ordinary rustup Cargo entry point. Directly invoking the toolchain Cargo
binary omitted one of the original fence's required normal loader directories.
The failed early build was cached; only this checkout's SQLite boundary package
build outputs were cleared before the normal rustup entry passed the original
fence. No loader paths, native compiler flags or acceptance guards were injected.

The `7f766ae8` implementation source passed strict workspace/all-target Clippy
and 138 Python controls. Its native run reached M09 350, docs 9 and M12 46 before
Node test compilation was killed by SIGKILL; the shared cgroup OOM-kill counter
increased from 4 to 5. No Node test ran in that attempt. The source recorder also
lost access to the prior shared Git object directory. All 9,682 indexed source
entries were subsequently restored into this checkout's own object database and
verified against the unchanged `094208d1` tree. These failed/incomplete attempts
remain recorded separately from the composed source's later verification.

## Retained original failure

The new real-TCP cancellation regression was first applied as a test-only patch
to the exact baseline. The original native test exited 101: it observed two
payload requests after the first response set cancellation, instead of stopping
before the second member. This is an actual original-source failure, not an
assertion inferred from static review. The [small reproduction manifest](verification.json)
records the selector, source hashes and result. One older residency test
explicitly required completing all downloaded bytes after cancellation; its
expectation was updated to the new contract while retaining the original
selection, pin, capacity and fresh-session recovery checks. It is not reported
as an unchanged old assertion passing.

## Qualification remains open

Required external evidence remains: architecture/expert ABI and quantization
policy for a selected real model; ordinary Hepta model load/query/unload under
CURRENT/withdrawal/FinalUse; device/VRAM ownership and reclaim; native locked
funding, sustainable paid renewal and independent holding evidence; mature
discovery/eclipsing resistance; and the original three-independent-operator,
at-least-72-hour WAN retrieval/repair/recovery campaign. No component result
closes these requirements.
