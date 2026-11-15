# Cell persistent inventory composition and custody-window admission

## Result and source identity

This continuation adds an explicit combined persistent/rarest-first Cell
transport and fixes single-object custody admission before reservations. It
continues the existing draft integration PR #688. The candidate remains
**HOLD / NO-GO** for whole-chain, paid long-term custody, independent operation,
the original model cold-load cohort, and Hepta CURRENT/FinalUse acceptance.

| Source | Commit | Tree |
| --- | --- | --- |
| Starting integration | `b173c1f52d927522af67df30dd08ecfb2e3a1bb0` | `6fcdb1aca01da0f2495fea1c74802af05119c77f` |
| H1: implementation and regression controls | `4fca468163dc1d24ef12355963eeb7c96cbcc37c` | `68d25fbd91e4cb1345cb2c374902538542af6212` |
| H2: original failure diagnostics, final tested source | `c16c7e0e93cf5eb14f6dac140358441a47d82c7e` | `4aa564ca3eb297f6afa03976f16eacb6ffd7554a` |

H2 changes only the failure message/elapsed observation of an existing test and
its source pin after H1. Its one-second deadline, assertion condition, fixture,
checkpoint, and retry rules are unchanged. The delivery following H2 adds
evidence only; native results below belong to H2, with that source identity
retained explicitly.

## Implemented behavior

### Explicit inventory over persistent connections

`CellFetchTransportV2::PersistentRarestFirstV3` selects the fresh `TCQ3/TCS3`
namespace. Manifest and chunk requests keep their existing content meanings;
kind 3 requests an inventory page bound to the pinned TCM1 manifest, with
`start:u32be` and `count:u16be`, where count is 1 through 256. The response is the
existing canonical bounded bitfield.

Inventory, manifest, payload, and every member of a release share one connection
pool and the original frame, dial, response-byte, and absolute-deadline budgets.
Partial frames drop their connection; complete invalid objects remain subject
to quarantine and hash verification. Cancellation remains sticky, verified
prefixes remain available for a later explicit invocation, and a release-member
boundary does not replenish any budget.

The ordinary Cell, release, dependency closure, model-root, tensor, Ready, and
CLI entry points are connected. Consumers select
`--transport persistent-rarest-v3 --scheduling rarest-first-v1`; providers select
the V3 transport. Persistent request and per-connection caps remain explicit.
Single-Cell CLI reports use fresh `trnm.cell.fetch.persistent.rarest.v3` and
`trnm.cell.serve.persistent.rarest.v3` schema names. Existing V1/V2 selection and
namespace refusals remain in place.

This is sequential reuse per connection. It does not implement multiplexing,
a DHT, BEP 52 Merkle piece proofs, or a change to model execution authority.
TCM1 still contains the complete chunk-hash list and retains its finite bounds.

The 19 new transport tests cover actual loopback TCP, partial providers and
rarest ordering, malicious or empty hints, bounded inventory pages, exact
frame/byte/dial accounting, cancellation, original deadlines, verified-prefix
recovery, four release-family entry points, actual CLI provider/consumer
processes, and tensor cache-only completion. The explicit 269-chunk pagination
fixture uses 269 x 16 KiB chunks; it is a protocol fixture, not either historical
272 MB model cohort.

### Refuse inadmissible first custody work before creating holds

`retain_native_cell` and `repair_native_cell` now invoke the existing M12
`check_effects` preflight with the original policy, claim, operation, effect,
and service-height window before opening a new budget or reserving resources.
A first request rejected by this preflight leaves no new budget, claim, or
physical obligation. The actual mutations retain their original checks.

Already admitted Pending/Done effects retain exact identity, window, and
charged resources for readback-only recovery, including after the service
window or a legitimate reorganization. The fix does not make the separate
owners atomic, refund old costs, lock native cancellation, or initiate provider
payment.

Both new tests execute against Legacy, AuthenticatedV1, and
PermanentAccountGrowthV2. The retain case covers past/future windows, admission
inside the original window, and completed-effect recovery after expiry. The
repair case covers actual damage, separately funded repair, exact old recovery,
and refusal of newly funded work after the original storage term.

## Actual validation

All final native commands below use the committed H2 source, original Cargo
profiles and test limits, Rust 1.95.0, locked/offline dependencies, two build
jobs, and one test thread. Optional native PQ compilation uses the separately
verified pinned OpenSSL 3.5.9 provider. Before/after source manifests match.

| H2 scope | Actual result | Scope boundary |
| --- | ---: | --- |
| M09 all targets / all features | 387 passed, 0 failed, 0 ignored | 15 Cargo test contexts; no filtered tests |
| M09 documentation tests | 10 passed, 0 failed, 0 ignored | Includes compile-fail API controls |
| Node storage service, all features | 17 passed, 0 failed, 0 ignored | Complete storage-service selector; 1,152 unrelated Node tests filtered |
| M12 native budget, all features | 35 passed, 0 failed, 0 ignored | Complete native-budget selector; 11 other crate tests filtered |
| Strict Clippy | exit 0 | M09, Node, and service-settlement; all targets/all features; `-D warnings` |
| Formatting and generated inventory | exit 0 | Existing full-workspace format and inventory checks |
| Source/claim/boundary/CI negative suites | 268 passed | Corpus 37; repository 50; project boundary 16; source integrity 43; claim guard 22; CI contract 100 |
| Repository/Markdown validation | PASS | 3,345 local links on H2; 26 workspace packages |
| Locked Cargo graph | PASS | Default: 26 members / 175 packages; all features: 26 / 180 |

The final native/documentation scope contains **449 distinct passing tests**.
Local and remote repetitions are recorded separately and are not added to this
denominator. The code adds 21 test functions: 19 transport and two custody
window controls. Static review is a separate-agent review under the same
operator, not independent organizational, cryptographic, or WAN acceptance.

Source coverage now pins 531 actual blobs and requires 450 paths. The four new
test files are present in the fixed required set and exercised by the existing
omission/mutation controls. All acceptance/activation flags remain false. The
all-feature resolved graph and package identities are retained in
[cargo-all-features-graph.json](cargo-all-features-graph.json).

### Failures and interruptions remain evidence

- **Storage RED:** the original production code plus the two new tests builds
  successfully, then fails both budget-report assertions (exit 101). An expired
  retain request leaves a new 1,000-unit Storage hold; an expired new repair
  leaves another 200-unit Repair budget. The subsequent production-only fix
  passes all 17 storage-service tests. These RED/GREEN sources and binaries are
  kept separate from the final H2 all-feature run.
- **Initial development compile:** an E0583 integration-test module-path error
  is retained. The explicit child-module path fixes it; the following targeted
  run passes 21 tests, including 19 new controls.
- **H1 full M09 run:** 352 library tests pass and one old zero-byte repair
  reconciliation test fails with `no durable transition observed`; later
  integration targets do not execute in that invocation. The original error
  message hides the underlying return value. Its cause remains **UNATTRIBUTED**.
  H2 adds diagnostic detail only; a single diagnostic run and both complete H2
  runs pass under the original one-second budget. Success does not identify or
  erase the original failed cause.
- **Remote H1 preparation:** an incorrectly named local validation branch is
  refused by the existing preflight before a build. Renaming that local branch
  to the required `fix/chain-...` form preserves the rule; final execution uses
  H2. No H1 build result is inferred from the rejected preparation.
- **Local executor interruption:** four local source-gate returns are known;
  the remainder has no terminal local receipt. Complete H2 gates are run and
  retained remotely. The environment later recovers, and the original local
  failure/success logs are read back with exactly their previously observed
  SHA256 values. [Restoration record](local-executor-restoration.json).

The optional SQLite I/O-boundary build warning is retained in native build
logs. These runs make no additional qualification claim for that independent
boundary. No deadline, original cohort, ignore list, feature gate, or failed
observation is relaxed to obtain these results.

## Original cold cohort remains open

The original **272,189,990-byte** cohort remains
**HISTORICAL_FAILED + NOT_RUN / HOLD**: its manifest-header failure was recorded
at 2.041 seconds, consumer payload was zero, and the original total budget is
still 35 seconds. The exact original model materials, complete invocation, and
interrupted working-source identity were not recovered by this continuation.

Bounded searches on six configured operator hosts and three bounded Library
queries did not locate those materials. This is not an exhaustive proof of
absence. Search bounds, actual job identities, and receipt hashes are described
in the public [cold-cohort-status.json](cold-cohort-status.json); unrelated
host paths and private discovery records are excluded from this publication.

The historical **272,190,131-byte** successful transfer/cache-only
materialization is a different cohort. Its result stays scoped to its original
source, inputs, and record. Neither that result nor the new 269-chunk fixture
qualifies the original cohort or the Hepta CURRENT/FinalUse loop.

## Paid custody boundary

The native executor already has real TaskReserve debits, reserved-state
TaskCancel refunds, provider TaskReceipt transitions, and owner TaskAccept
provider credits. A receipt by itself does not pay: an unsettled task can still
expire and return its remaining amount to its owner. The Cell adapter observes
funding and records local effects; it does not submit these transactions or
establish a cancellation/reorg-resistant long-term monetary lock.

Byte-block reservations, original repair budgets, local target readback,
successor checks, and rooted physical GC remain useful implemented pieces.
Price accrual, funded renewal/exit, fresh network challenges tied to settlement,
repair finance, cancellation/reorg settlement, and historical rollback-window
policy still require their corresponding native and operational owners.
The source-bound [economic-boundary.json](economic-boundary.json) distinguishes
each actual transition from each missing composition.

## Evidence and reproduction

- [Local original records](local-records.tar.xz) and
  [their file manifest](local-records-manifest.json) retain complete actual
  local logs, commands, source-before/after records, and ELF identity inventories,
  including the H1 failure and interrupted local gate sequence.
- [Remote original records](remote-records.tar.xz) and their
  [file manifest](remote-records.manifest.json) retain RED/GREEN and final
  H2 build/test/Clippy/gate stdout, stderr, exit/command receipts, source hashes,
  provider verification, and runner scripts. Large source archives and ELF
  bodies remain in the isolated operator task directory, with their hashes;
  they are not duplicated into Git.
- [Static review](independent-review.json),
  [H1 binding](independent-review-binding.json), and
  [H2 diagnostic-delta binding](independent-review-h2-delta-binding.json)
  preserve actual reviewed file identities and review limitations.
- [Qualification matrix](qualification.json) binds the executable scopes,
  failures, archive hashes, and unchanged open gates.

For reproduction, use a fresh permitted development branch at H2 and run
`bash scripts/project-preflight.sh`. Prepare the original pinned native PQ
provider for the all-feature Node/M12/Clippy lane using the existing repository
provider preparation instructions. Keep the existing Cargo profiles, locked
dependencies, test deadlines, and fixture assertions. Raw runner command JSON
is authoritative; the principal Cargo selections are:

```sh
cargo test --locked --offline --manifest-path trillionnium/Cargo.toml \
  -p trnm-data-availability --all-targets --all-features -- --test-threads=1
cargo test --locked --offline --manifest-path trillionnium/Cargo.toml \
  -p trnm-data-availability --doc --all-features -- --test-threads=1
cargo test --locked --offline --manifest-path trillionnium/Cargo.toml \
  -p trnm-pon-node --all-features --lib storage_service::tests -- --test-threads=1
cargo test --locked --offline --manifest-path trillionnium/Cargo.toml \
  -p trnm-service-settlement --all-features --lib native_budget -- --test-threads=1
cargo clippy --locked --offline --manifest-path trillionnium/Cargo.toml \
  -p trnm-data-availability -p trnm-pon-node -p trnm-service-settlement \
  --all-targets --all-features -- -D warnings
```

Existing scope documents: [Cell storage specification](../../docs/development/specs/pon/CELL_MODEL_STORAGE_V1.md),
[sole development plan](../../docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md),
[original cohort continuation](../cell-contract-continuation-20261105/README.md),
and [distinct retry cohort](../cell-transient-capacity-retry-v1/README.md).
