# TRNM PoCO P2-STORE K/P writer-adoption matrix — 2026-08-26

Status: **audit evidence only; MIG-004 remains open**

This matrix records the production-shaped `trnm-poco-node` entry points which
touch the native application `P` store and proposal-validation `K` store.  The
`cross_store_lock` fence is advisory and requires every cooperating owner to
use it.  It does not make two SQLite databases one transaction and does not
cover an uncooperating process.

## Lock contract

* `acquire_exclusive_for_paths_v0(P, K)` derives and pins the one private
  authority root for a split operation.  The guard is held across the complete
  P/K mutation or paired readback and its descriptor/path identity is checked
  before successful return.
* `acquire_exclusive_for_store_path_v0(P)` is only for a bootstrap cut where K
  does not exist yet.  It derives the same root from `root/namespace/store`;
  once both namespaces exist, callers must use the paired-path helper.
* `acquire_shared_for_paths_v0(P, K)` protects a complete paired audit.  A
  shared reader and an exclusive writer are mutually exclusive, and rename /
  recreate of the root fails identity validation.
* A helper which is called while an outer exclusive guard is held receives that
  guard rather than recursively acquiring the same OS lock.  In particular,
  finalization passes its guard through the high-QC rebase/readback helper.

## Adoption matrix

| Boundary / mutation | Entry point | Evidence and lock window |
| --- | --- | --- |
| Plain fresh P genesis before K exists | `lab_authority::initialize_fresh_ordinary_genesis_v0`; deployed `deployed_lab_commissioning::commission_deployed_lab_ordinary_runtime_v0` | Exclusive single-P or paired-root guard spans `initialize` and exact head readback. |
| H1 trusted-base P install before K exists | `native_h1_state_sync_commissioning::commission_native_h1_state_sync_v0` | Exclusive single-store guard spans install and exact confirmation. |
| K schema/metadata initialization at host construction | `native_proposal_p_host::open_for_lab_v0` / `open_exact_v0` | Deployed config supplies the root; exclusive guard spans `SqliteProposalValidationStoreV0::open`. Isolated unit fixtures intentionally have no root capability. |
| Deployed recovery store reopen | `deployed_lab_recovery::reopen_deployed_lab_ordinary_cut_v0` | Exclusive paired guard spans P/K opens; a second exclusive window spans potentially mutating native `application.recover`; final terminal P/K join uses a shared guard. |
| Process-2 recovery store reopen | `deployed_lab_process2_recovery::recover_deployed_lab_process2_inner_v0` | Exclusive paired guard spans P/K opens; activation/session/cursor replay windows retain their own exclusive guard and identity checks. |
| Ordinary proposal P + K reservation | `native_proposal_p_host::execute_and_persist_p_v0` and anchor-successor reopen | Exclusive paired host guard spans native execute, K reserve, and artifact readback. |
| Core-D delivery / retry | `native_proposal_p_host::seal_valid_and_deliver_core_d_v0`, `retry_core_d_v0` | Exclusive paired host guard spans K transition and Core delivery/readback. |
| Safety-C + K acknowledgement / retry | `native_proposal_p_host::persist_safety_c_and_ack_k_inner_v0`, `retry_ack_k_inner_v0` | Exclusive paired host guard spans Safety confirmation, K acknowledgement, and retry result. |
| K checkpoint facts / terminal join | `native_proposal_p_host::confirm_anchor_successor_k_checkpoint_facts_v0`, `reconfirm_anchor_successor_k_checkpoint_facts_v0` | Shared paired guard protects P/K fact readback. Whole-node checkpoint CAS uses an exclusive paired guard. |
| Whole-node K checkpoint CAS | `native_proposal_p_host::checkpoint_k_whole_node_v0` | Exclusive paired guard spans K checkpoint transition, P/Safety/signer confirmation, CAS and target readback. |
| Finalization P commit + K closure | `lab_authority::PocoNodeLabPendingFinalizationOwnerV0::apply_and_ack_finalization_v0` | One exclusive root guard spans marker, native P commit/readback, Safety/K closure and checkpoint CAS. High-QC rebase receives the existing guard (no nested flock). |
| Certificate/timeout P/K rebase audits | `lab_authority::advance_certificate_v0`, `rebase_to_authoritative_high_qc_v0`, `preflight_authoritative_high_qc_retained_path_v0` | Certificate callers own an exclusive paired read/rebase window; rebase and checkpoint-owner helpers accept an outer guard when invoked from finalization. |
| Process-2 activation/session/cursor | `deployed_lab_process2_recovery` activation CAS, session open/resume, replay cursor reserve → deliver → safety-close → alias-close → checkpoint | Exclusive paired guards cover each mutation window, with final descriptor/path identity validation. |

## Deliberate exclusions and remaining blockers

* Direct SQLite/storage-crate fixtures and `native_application_owner` test
  scaffolding are not deployed owners; they remain useful unit evidence but do
  not establish production writer adoption.  Legacy authenticated-genesis
  modules, consensus-types/genesis schemas, and tx-builder core are outside
  this P2-STORE slice.
* The fence is not a distributed lock and does not prove cross-database atomic
  commit, SQLite WAL/SHM fsync ordering, power-loss rollback, disk-full
  recovery, or response-loss resolution.  File-descriptor binding for child
  database files and all external/uncooperating writers remain MIG-004 work.
* A successful identity check is a fail-closed boundary check, not a claim that
  a concurrent replacement cannot occur after the guard is dropped.

## Focused evidence

The lock module has four unit tests covering shared/exclusive mutual exclusion,
single-store bootstrap root derivation, mismatched roots, and rename/recreate
identity failure.  The feature-gated `trnm-poco-node` library suite exercises
the deployed host/recovery/anchor paths; the full lab slice currently reports
111 passing tests.  Formatting and lint commands remain part of the local
handoff; this document does not convert those local results into a release
gate.
