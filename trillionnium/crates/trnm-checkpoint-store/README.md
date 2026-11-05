# trnm-checkpoint-store

Owner: M03. Reusable candidate component; no consensus activation.

Independent exact CAS and durable Unix service; generalized owner frontier only.

Domains and data schemas use a fresh portability namespace. Never open a deployed
historical database as an upgrade shortcut. Retained tests cover local behavior only.

## Provisioning and cold recovery

The V2 journal's sibling `head-v2` file detects an incomplete or inconsistent
local recovery. It cannot detect restoring a complete old journal together with
its matching old head. Cold restart therefore requires an independently retained
**full-journal checkpoint: record count and root across every scope**.

The daemon has three explicit commands:

```bash
trnm-external-node-checkpoint-v2 register-new /private/checkpoint.sock /private/checkpoint.log
trnm-external-node-checkpoint-v2 journal-checkpoint /private/checkpoint.sock /independent-recovery/checkpoint-000042.bin
trnm-external-node-checkpoint-v2 reopen /private/checkpoint.sock /private/checkpoint.log /independent-recovery/checkpoint-000042.bin
```

These paths are examples; the operator supplies actual private storage and an
independent recovery custodian. The parent of the socket and journal must be a
canonical private directory with mode `0700`.

- `register-new` is an explicit first-provisioning decision. It refuses existing
  journal, lock or head files, even an empty namespace. It must not replace
  recovery after missing storage.
- `journal-checkpoint` reads an already running, admitted owner without changing
  its journal or any business authority. It writes a **new** export file and
  refuses overwriting an existing pin. Export is a separate command; recovery
  never invokes it to manufacture its own expectation.
- `reopen` requires the caller's independently retained checkpoint file. It
  checks the expected byte length before bounded replay, validates the complete
  hash chain, and requires an exact count-and-root match **before** repairing a
  stale local head. Missing files are not reseeded. A shorter journal, equal-size
  fork, extra record or unknown newer tail is refused without head repair.

The old implicit `<socket> <log>` invocation is rejected. There is no automatic
fallback to the sibling head, empty registration, or an unanchored reopen.

### Independent retention is an external obligation

The export file has a separate `TRNMCPX1`, version-1, 84-byte canonical encoding;
the V2 sibling head cannot be used as an export. Its checksum validates encoding
integrity, **not authentication or freshness**. The recovery custodian must
authenticate and retain the latest required pin outside the journal's rollback
failure domain. Writing an export into another local directory does not establish
that independence. If every journal, custodian and backup rewinds together,
this component cannot prove that a later operation occurred.

This component does not automatically replicate each accepted CAS to a second
fault domain, synchronize an external pin before an effect, or qualify a remote
custodian. The caller must provide those guarantees before making a system-level
anti-rollback claim. A missing, stale or unavailable independent pin stops
recovery. Legitimate journal-ahead states also require external reconciliation;
the recovering local files cannot authorize a new expected pin themselves.

### Rust API and compatibility

`ExternalCheckpointAuthorityV2::register_new` provisions a new owner;
`reopen_with_external_checkpoint` requires an `ExternalJournalCheckpointV1`.
`journal_checkpoint_v1` exposes a read-only snapshot with private fields and
canonical encoding. The Unix client offers the same live snapshot query through
a separate `CJ1R` / `CJ1S` read-only protocol.

The existing V2 journal records, sibling head encoding and CAS wire are unchanged.
The old `open` constructor remains available for **structural qualification only**:
it cannot establish cold-recovery freshness and its owner cannot serve the daemon
or export a recovery pin. `run_daemon` now registers a new namespace only;
`run_daemon_with_external_checkpoint` performs an explicit pinned restart.

The separate `ledger-init`, `ledger-advance` and `ledger-resolve` commands retain
their existing source-or-target reconciliation scope. Those supplied per-operation
checkpoints do not replace the independent full-journal recovery pin.

## Verification

```bash
cargo test --locked -p trnm-checkpoint-store --all-targets --all-features
cargo clippy --locked -p trnm-checkpoint-store --all-targets --all-features -- -D warnings
cargo fmt -p trnm-checkpoint-store -- --check
```

The complete test suite requires permission to bind Unix sockets. Tests retain
the original transport coverage and include complete old-image restoration,
same-count forks, another scope's deletion, expected-length overflow, missing
storage, repair ordering, explicit CLI refusal and competing owner processes.
An environment-denied socket bind is a failed/unexecuted transport qualification,
not a passing negative security case.

Run from `trillionnium`. See [modules](../../../docs/modules/README.md) and
[ownership](../../../config/portability-inventory-v1.json).
