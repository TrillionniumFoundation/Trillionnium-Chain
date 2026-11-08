# Cell storage network v3 continuation

**Reviewed component validation: PASS. All six end-to-end capability qualifications: HOLD_NO_GO.**

This continuation is stacked on #807 at `0dc13a92cc49e9a751a2b6cf7cc96524f1244a2a`. It adds the explicit native
PQ-v3 discovery namespace and joins complete TCV1 model/environment residency
to one caller-identified local task. It does not activate a chain, migrate the
existing discovery profiles, or certify an independently operated storage service.

## Source identities and actual execution

| Campaign | Exact implementation commit | Outcome |
| --- | --- | --- |
| Initial frozen source | `9170779008ec8abdd1fd27b8ff16f2c2462fdb47` | 16 of 19 commands passed; native crate, workspace Clippy and CI contract failed |
| Reviewed frozen source | `266d9be8e7f6a2ecb556a129b1be69e6ec9553a2` | 19 of 19 commands passed; no command timeout |

The reviewed native run executed **473 library tests, 34 integration/CLI tests
and 12 compile-fail doctests: 519 successful tests**, with zero failed, ignored
or filtered tests. All **45** new native names were explicitly required and
matched to successful log entries; compiling or listing a name was insufficient.

| New native group | Executed successfully |
| --- | ---: |
| Durable directory and lease/replay controls | 17 |
| Real directory mutex/writer/COMMIT deadlines | 6 |
| Native authentication and transport | 9 |
| Actual multi-source TCP competition | 2 |
| Real rendezvous expiry/revocation and withdrawal selection | 2 |
| Complete model/environment task residency | 9 |
| Total | 45 |

Native execution covers the complete `trnm-data-availability` crate with default
features. Whole-workspace all-target/all-feature Clippy and locked dependency
graphs are separate gates. The fuzz manifest check resolves its graph; it does
not execute a fuzzing campaign. The Clippy log retains the existing SQLite I/O
boundary build-script `UNQUALIFIED: RUSTC must be absolute` diagnostic; this run
does not claim qualification of that separate boundary.

The commands ran on shared Linux x86_64 with Rust 1.95.0, one Cargo build job,
one test thread, debug information disabled and incremental compilation disabled.
The unchanged OpenSSL 3.5.9 preparation script produced its pinned native
provider receipt and actual sign/verify/wrong-message smoke result. Its installed
binary, headers and static library digests were rechecked. It is used for the
optional differential build; canonical discovery uses native Rust ML-DSA-65.
This report makes no upstream full-provider-test or independent cryptographic
implementation qualification claim.

## What changed

- CDP3 statements bind fixed 300-second lease epochs. Expiry, withdrawal and
  authority expiry release active quota. Bounded current-epoch high water
  prevents replay until a monotonic atomic epoch transition retires the old
  signed scope. The 512-row and 16-MiB main-database limits are unchanged.
- Native bootstrap signatures bind the full query, fresh OS nonce, configured
  endpoint/key/generation, operation, response status/body and expiry. Provider
  and bootstrap trust rosters are distinct.
- Current authority filtering prevents retained expired/revoked-key rows from
  denying an otherwise valid lookup. Active providers precede withdrawals in
  the bounded reply. Durable history remains intact; not every withdrawal is
  guaranteed to reach every client in an eight-record reply.
- Source scheduling, signature work, actual connection/response bytes and the
  original absolute deadline remain bounded across discovery and payload work.
  Failed exchanges and signature attempts are included in the denominator.
- `admit_local_version` requires both actual immutable resident closures to
  match complete TCV1 before aggregate task RAM/reference admission. Shared
  allocations are charged once, independent references remain charged, and
  current component pins, cancellation and deadline are checked before byte use.
- The source guard now recognizes versioned `pq3`/`pq37` module names and PQ
  examples. Its negative controls reject unpinned additions. All 602 current
  pinned blobs and the native embedded source inventory were checked.

## Native example and actual bytes

The reviewed example actually fetched and re-read **40,960 bytes** with zero
initial cached chunks and no manifest cache hit. Full bytes and payload SHA-256
matched. Its four client operations used **8 connection attempts and 62,252
application response bytes**, including the expected post-withdrawal refusal.
Requests and transport overhead are outside that byte counter.

The refusal had an authenticated bootstrap response, a verified withdrawal,
zero rejected bootstraps/records/capacity rejections, and a client directory
with `active=0`, `tombstone=1`. Advertisement, withdrawal and the negative
control all remained in the original still-live lease epoch. Authentication
failure, signed denial, truncation or natural expiry cannot pass that control.
The finite bootstrap server recorded four record validations and four signing
attempts, charging **12 native primitive slots** including signing self-checks.

The example uses public fixture keys and finite loopback services on one host.
Its 10-second original client operation window is shared by the four client
phases; fixture preparation, server lifetime and joining are recorded separately.
This is not a whole-process hard-real-time or WAN performance measurement.

The separate complete-version tests read actual resident model and environment
bytes for two caller-identified tasks after cache removal. They do not execute
a model, install an operating environment or grant Hepta CURRENT/resource/FinalUse.

## Failed observations retained

- `development-build-01`: parallel implementation was incomplete; the native
  compiler reported a missing test module and an observation-shadow warning.
- `development-discovery-01`: rustc could not create a temporary directory
  because of actual ENOSPC. Only this task's reproducible build cache was
  rebuilt; original logs and cleanup/relocation receipts remain.
- `development-clippy-01`: actual type-complexity and large-error lints failed.
  The implementation was corrected without suppressing those lints.
- `frozen-01`: **458 library tests passed and 13 failed** with SQLite DiskFull;
  only 30 of the 43 then-new tests passed. No integration tests or doctests ran.
  Two `trnm-pon-node` Clippy drivers received SIGKILL. CI contract observed 31
  tests with 3 failures and 5 errors, including ENOSPC writes/copies. These
  were not timeouts; their precise shared-resource root cause is not asserted.
- `development-server-red-01`: the two new real rendezvous regressions failed
  against the unchanged initial transport blob: **0 passed / 2 failed**, from
  signed denial and withdrawal-first omission. The exact added red-test source was reconstructed after the run from its original creation patch; its bytes match the Git blob recorded before and after that run.

The initial runner parsed only successful harness totals, so its original
`native-results.json` omits the failed harness denominator. The additive
`initial-reconciliation.json` retains the actual 458/13 result and all new-case
groups without rewriting that record. All 19 original log digests were rechecked.
The initial example exited zero and checked its payload, but its then-broad
withdrawal assertion and epoch ambiguity were independently corrected; it is
not substituted for the reviewed negative control.

The reviewed run used a task-owned workspace `TMPDIR`, one build job and
resource sampling inside the same execution namespace. Protocol limits,
deadlines, test coverage and failure vetoes were not relaxed. Its runner preserves
failed harness counts, binds derived success to command exits, and bounds process
group cleanup on timeout. No timeout occurred in either frozen campaign.

Provider source/build intermediates were removed to release storage only after
the preparation receipt and logs were retained. Installed checked provider
inputs remain distinct from those reproducible intermediates. No private
provider smoke key is packaged.

## Reviewed command ledger

| Command label | Exit | Seconds |
| --- | ---: | ---: |
| `preflight` | 0 | 0.06 |
| `source-before` | 0 | 4.48 |
| `graph-default` | 0 | 0.22 |
| `graph-all-features` | 0 | 0.11 |
| `graph-fuzz` | 0 | 0.12 |
| `format` | 0 | 11.55 |
| `version-vector` | 0 | 0.06 |
| `native-list` | 0 | 13.52 |
| `p2p-complete` | 0 | 110.47 |
| `native-example` | 0 | 6.65 |
| `clippy-workspace` | 0 | 113.30 |
| `source-negative` | 0 | 2.92 |
| `pq-source-negative` | 0 | 29.81 |
| `ci-contract` | 0 | 13.97 |
| `repository` | 0 | 43.79 |
| `pq-source-pins` | 0 | 0.21 |
| `inventory` | 0 | 0.06 |
| `source-after` | 0 | 3.37 |
| `clean-worktree` | 0 | 0.03 |

The raw logs include 43 source-integrity negative tests, 37 PQ source negative
tests and the full CI contract suite. Source checks covered the exact committed
tree before and after execution, and the source worktree was clean at both ends.
The evidence delivery adds observation files and a sole-plan pointer only;
all reviewed implementation, tests, specifications, dependency files and source
pins remain byte-identical to `266d9be8e7f6a2ecb556a129b1be69e6ec9553a2`.

## Remaining acceptance gates

TCX1 reconstruction requires one complete base and a complete target manifest;
it does not recursively recover arbitrary delta ancestry. TMR1 bounds 16 direct
parents, not all historical lineage depth. Neither automatic periodic physical
snapshots nor indefinite retention of every uploaded version is established here.
Deduplication must be measured on actual encoding, quantization and updates.

Declared store/slot/domain IDs and same-host copies do not establish independent
operators or fault domains. Retained version sets require actual capacity and
funded leases. Renewal/repair planning does not execute payments, dispatch repair
or replace a missing sponsor. Public-WAN campaigns, original failed cohorts,
three independently administered domains and 72 hours of elapsed operation
retain their separate acceptance requirements.

No result establishes permissionless Sybil fairness, whole-host rollback
resistance, measured device/VRAM use, full-chain post-quantum qualification,
the real restricted-loader ABI inventory or the same-iteration Hepta next-task
loop. Existing v1/v2 profiles keep their documented limitations. All six
end-to-end capability gates remain **HOLD_NO_GO**.

## Files and reproducibility

- [Reviewed command summary](reviewed-summary.json) and
  [complete native cases and suite denominators](reviewed-native-results.json).
- [Reviewed byte/withdrawal example](reviewed-native-example.json),
  [environment and provider identities](reviewed-environment.json),
  [resource observations](reviewed-resource-summary.json), and
  [source bindings](source-bindings.json).
- [Initial failure reconciliation](initial-reconciliation.json).
- [All retained raw observations](raw-artifacts.tar.xz) and
  [per-file byte/SHA-256 manifest](raw-manifest.json).

Archive SHA-256: `81f013bdd990536d3be6a51c56c30f0c9cff6899a521c14dc0c081e4c1ccd478`.

The archive includes each actual runner, full command output, exact command argv,
before/after source receipts, actual public example records/payload/databases,
provider preparation logs and failed development observations. Paths in those
records describe the actual workspace; substitute local absolute paths when
reproducing the commands. The native example requires a fresh final directory:

```bash
bash scripts/project-preflight.sh
cargo test --locked --manifest-path trillionnium/Cargo.toml \
  -p trnm-data-availability -- --test-threads=1
cargo run --locked --manifest-path trillionnium/Cargo.toml \
  -p trnm-data-availability --example cell_discovery_pq_v3 -- \
  /absolute/path/to/a-new-run-directory
```

See the [v3 discovery contract](../../docs/development/specs/pon/CELL_PROVIDER_DISCOVERY_PQ_V3.md)
and [complete-version contract](../../docs/development/specs/pon/CELL_COMPLETE_VERSION_V1.md).
Remote GitHub Actions outcomes and review/merge decisions are separate from
the local observations above. The publication relay is not a runtime witness.
