# Native packet-status observation v1

Status: controlled native implementation; independent product acceptance remains open.

This specification refines the existing M07/M08/M14 and Hepta reconciliation
boundary in the sole development plan,
`docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md`. It does not
change a consensus profile, storage schema, signed domain, or activation gate.

## Problem and original owner

`Node::exact_packet_observation` reports exact retained packet bytes and their
membership in the currently selected local ancestry. Before this change, the
local `trnm-pon-node packet-status` command first used the ordinary
`Node::open` or `Node::open_with_authenticated_state` path. That path calls
`Node::recover`, which can select an admitted higher-work block or complete an
unpublished reorg before the query runs.

That distinction matters after a lost acknowledgement. If admission completed
but activation did not, reconciliation must observe those two facts separately.
A status query must not finish the original owner's write as a side effect of
opening its store.

## Selected interface and backends

The local CLI now calls the native `observe_existing_packet` interface directly.
The interface accepts an independently selected `Settings`, the exact packet,
one of `PacketObservationBackend::LegacyV2` or
`PacketObservationBackend::AuthenticatedV1`, the existing worker count, and a
local snapshot byte limit. The CLI uses
`DEFAULT_PACKET_OBSERVATION_SNAPSHOT_BYTE_LIMIT`, currently 8 GiB.

The API returns only the existing
`pon-native-exact-packet-observation-v3` observation. It does not return a
mutable `Node`. The CLI retains its existing result envelope and clock-scope
label. A clock label does not turn this query into a confirmation check.

The selected scope is exactly `legacy-v2` and `authenticated-v1`. It does not
add support for Growth, PQ network owners, restricted task owners, continuous
owners, or migration. The existing Growth observer and live-owner
`Node::exact_packet_observation` entrypoints retain their own contracts.
Supplying outside-owner configuration to this cold local CLI is rejected;
the observation path cannot instantiate that owner's journal or policy.

## Source-preserving read path

The implementation reuses the existing
`store/growth/observer.rs::Snapshot` primitive:

1. Require an existing regular database and an existing original owner lock.
   Lock the original owner without creating a missing lock file. Refuse a live
   writer and preserve the existing no-follow, regular-file, single-link,
   namespace identity, and private-file checks.
2. Refuse initialization, migration, outside-owner markers, and any source
   WAL, SHM, or rollback journal. A pending recovery file is not an invitation
   for the reader to recover or remove it.
3. While holding the original owner lock, copy no more than the selected byte
   limit into a private temporary namespace outside the source directory.
   SQLite never opens the original source database.
4. Open the private copy with SQLite read-only and query-only settings. Reuse
   the existing schema/context checks, active State validation, authenticated
   history checks where selected, durable replay/outbox checks, native budget
   record validation, and ancestry validation.
5. Decode every original reorg journal field, including already completed
   records, through the same typed reader used by ordinary recovery. Retain
   the original highest-work candidate and activation-selection checks without
   advancing the tip or writing an intent. Refuse an unfinished native reorg
   before returning an observation. Skip
   `Node::recover` entirely. Retain the source identity checks and lock until
   exact-packet observation completes, then close SQLite before cleaning up
   the private snapshot.

The ordinary writer still executes its established recovery path. A packet
durably admitted before activation therefore yields `stored_exact=true`,
`active_chain_member=false`, and the original active tip and generation. A
subsequent ordinary writer open can recover and activate the heavier block.

The byte bound limits the temporary main-file copy. It is not a CPU deadline,
full-history replay bound, M12 reservation, disk-space reservation, or evidence
of sustainable storage cost. The existing complete-State and retained-history
validation costs remain. Advisory owner locking and source identity checks
retain the existing local filesystem trust assumptions.

## Refusals

| Condition | Result |
| --- | --- |
| Missing store or database | `PACKET_STATUS_EXISTING_STORE_REQUIRED`; no namespace creation |
| Missing original owner lock | Read-open failure; the query does not recreate the lock |
| Active original owner | `WRITER_BUSY` |
| Source initialization/WAL/SHM/rollback journal | `GROWTH_OBSERVATION_RECOVERY_REQUIRED` |
| Pending authenticated migration | `NATIVE_STATE_MIGRATION_PENDING` |
| Outside-owner marker | `OWNER_TASK_POLICY_REQUIRED` |
| Explicit outside-owner CLI configuration | `PACKET_STATUS_EXTERNAL_OWNER_UNSUPPORTED` |
| Incomplete native reorg | `REORG_IN_PROGRESS` |
| Wrong backend or stored context | Existing `SCHEMA` or `STORAGE_CONTEXT` refusal |
| Same packet identifier with different durable bytes | `DUPLICATE_CONTENT` |
| Source database exceeds the selected copy bound | `GROWTH_OBSERVATION_SNAPSHOT_LIMIT` |

The `GROWTH_OBSERVATION_*` diagnostics above retain the names of the reused
snapshot primitive. They do not assert that this new interface accepts a
Growth backend. Source replacement, symlinks, special files, hard links,
private-file replacement, and other snapshot-integrity failures retain that
primitive's existing fail-closed behavior.

## Hepta and authority boundary

Exact local retention and active membership are observations for the existing
operation's reconciliation. The result continues to set
`global_absence_authority`, `confirmation_authority`, `finality_authority`,
`execution_authority`, and `production_activation` to false.

A missing local packet does not prove that another peer failed to receive it.
An inactive retained packet does not erase an already executed local effect.
Neither result authorizes replay, compensation, an artifact admission, an
evaluation claim, a model installation, or Runtime FinalUse. Those decisions
remain with the original Learning Artifact Owner, Evaluation Owner,
`kernel.operations`, and Runtime owners and their current independent context.

## Regression evidence

`trillionnium/crates/trnm-pon-node/tests/native_packet_observer.rs` invokes the
actual `CARGO_BIN_EXE_trnm-pon-node` subprocess for both selected backends.
The admission-before-activation case detects the original CLI bug directly:
the CLI must return the live owner's pre-close observation byte-for-byte as
JSON values while preserving the source namespace. It then opens the ordinary
writer and checks that recovery still advances the selected tip.

The tests also cover a real durable native reorg intent interrupted at its
existing fault hook, live-owner refusal, recovery and policy markers, missing
store and missing owner lock, incorrect backend/context, changed duplicate
packet bytes, local copy-budget refusal, and local-only absence semantics.
Source assertions compare file contents, names, inode/device identity,
permissions, link count, ownership, mtime, and ctime without opening SQLite.
Access time is excluded because reading a source file can update it.

Run from the repository root after the project preflight:

```bash
bash scripts/project-preflight.sh
cargo test --locked --manifest-path trillionnium/Cargo.toml -p trnm-pon-node --test native_packet_observer
cargo test --locked --manifest-path trillionnium/Cargo.toml -p trnm-pon-node --test native_node packet_status
cargo test --locked --manifest-path trillionnium/Cargo.toml -p trnm-pon-node --lib native_growth_v2_packet_observer
cargo fmt --manifest-path trillionnium/Cargo.toml -p trnm-pon-node -- --check
cargo clippy --locked --manifest-path trillionnium/Cargo.toml -p trnm-pon-node --lib --bin trnm-pon-node --test native_packet_observer -- -D warnings
```

These commands are a verification recipe. Test source and this specification
are not a claim that a particular revision has passed execution; the exact
source revision and observed results belong in its validation record.
