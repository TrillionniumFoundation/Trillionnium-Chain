# G1-R4A finalization-intent process matrix v1

Status: **SOURCE_IMPLEMENTED / EXECUTION_UNVERIFIED / candidate-only**

Authority:

- Canonical plan: [`../TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md`](../TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md)
- Package map: [`../TRNM_AI_NATIVE_BLOCKCHAIN_EXECUTION_PACKAGES_V1.md`](../TRNM_AI_NATIVE_BLOCKCHAIN_EXECUTION_PACKAGES_V1.md)
- Parent target: [`TRNM_G1_R4_FINALIZATION_RECOVERY_TARGET_V1.md`](TRNM_G1_R4_FINALIZATION_RECOVERY_TARGET_V1.md)
- Machine truth: [`../../../config/consensus-mainline.json`](../../../config/consensus-mainline.json)
- Package manifest: [`trnm-g1-r4a-manifest-v1.toml`](trnm-g1-r4a-manifest-v1.toml)

This slice advances only the durable finalization-intent fence. It does not
claim the complete application/Safety/checkpoint process matrix and does not
activate a validator, finalization driver, signer, network listener, or
production recovery endpoint.

## 1. Exact source boundary

Base source:

```text
branch = feature/chain-g1-r2b-real-core-adapter-20260828
commit = a259e0b28a2d9dea838f5ceac0e805803ac51dd4
tree   = 1715f5f5a614679e1ba45239a7a884c10f7bc5ae
```

The source keeps `finalization_intent_wal.rs` byte-identical and adds an
explicitly feature-gated Linux helper and integration test. `build.rs` derives
a test-only process module from the reviewed WAL, exact preimages, and four
reviewable support fragments; any WAL byte-length or splice drift aborts the
build. The default crate graph and production flags remain unchanged.

## 2. State machine covered

```text
NoMarker
  -> TempWrittenAndFsynced
  -> MarkerPublishedAndParentFsynced
  -> TempRemovedAndParentFsynced
  -> StableMarker
  -> MarkerUnlinked
  -> ParentFsynced
  -> NoMarker
```

The exact-derived test module adds a publication repair accepting only one
caller-independent synthetic tuple and only the two residues emitted by the
real publication algorithm:

1. one fsynced temporary file and no published marker; or
2. published and temporary names that are hard links to the same inode and
   decode to the exact same marker.

Conflicting bytes, path replacement, link-count drift, checksum mutation,
foreign markers, missing store identity, or unrelated residue fail closed.
The repair is compiled only by `lab-validator-runtime-test-support` and is not
part of the production API.

## 3. Real-process SIGKILL cuts

The integration matrix stops the helper after the real filesystem operation,
waits for a bound checkpoint line, sends SIGKILL from the parent process, and
reopens in a second process.

| Cut | Durable residue at kill | Required restart result |
|---|---|---|
| `write_temp_fsynced_before_publish` | exact temp only | publish exact marker, remove temp |
| `write_published_before_temp_cleanup` | marker + temp, same inode | retain marker, remove temp |
| `write_complete_before_return` | stable marker only | idempotent exact readback |
| `clear_unlinked_before_parent_fsync` | no marker | idempotent cleared state |
| `clear_complete_before_return` | no marker | idempotent cleared state |

The negative process case corrupts the fsynced temporary record after SIGKILL.
Restart must reject it, retain the temporary evidence, and must not fabricate a
published marker.

## 4. Evidence command

```sh
bash scripts/ci/check_finalization_intent_process_matrix_v1.sh
```

The gate runs formatting, the focused library tests, the Linux process matrix,
clippy with warnings denied, package truth checks, and the unchanged Cargo
offline-input guard in CI.

The focused gate is integrated into the existing trusted PoCO-BFT workflow,
not a new workflow outside the frozen CI inventory. At source publication time
no authorized runner result is attached; execution conclusions remain pending
until the exact commit/tree passes from a clean checkout.

## 5. Explicit non-claims

```text
finalization_intent_publication_repair_candidate=true
finalization_intent_process_sigkill_source=true
finalization_intent_process_sigkill_executed=false
application_commit_process_matrix_complete=false
safety_persist_process_matrix_complete=false
checkpoint_cas_process_matrix_complete=false
disk_full_matrix_complete=false
torn_write_matrix_complete=false
power_loss_matrix_complete=false
finality_verified=false
native_application_finality_permit_integration=false
native_application_recovery_integration=false
process_kill_matrix_complete=false
g1_r4_exit=false
production_candidate=false
production_consensus_activation=false
```

## 6. Locked next slice

The next R4 tranche must move the same independent-process discipline across
the real proof-bound operation:

```text
Core queue front
 -> intent durable
 -> application apply/readback
 -> Core receipt
 -> tag-3 Safety persist/readback
 -> whole-node checkpoint CAS
 -> Ready/reopen
```

It must inject SIGKILL, response loss, disk-full and torn-write at every edge,
then prove ascending multi-block finalization, exact queue/head CAS,
anti-rollback, duplicate-apply rejection and losing-fork reclamation. This
marker-only package cannot satisfy those exits.
