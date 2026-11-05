# Cell storage completion boundaries

This continues the existing #688 integration candidate from
`ffb43113b2e0065e6a8053bdb25fc5a9d7cf0637`, under the
[sole development plan](../../docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md)
and [eight-layer storage contract](../../docs/development/specs/pon/CELL_MODEL_STORAGE_V1.md).
It changes no stored namespace, signature domain, immutable retention term,
CURRENT/FinalUse owner or activation/qualification flag.

## Actual regressions and changes

Both classic and PQ discovery could contact a bootstrap after the enclosing
Cell operation had consumed its actual response-byte allowance. The new real-TCP
controls fail against the original source: a zero-byte allowance still changes
`connection_attempts` from zero to one. Both exchanges now check the existing
shared allowance before consuming a connection slot, dialing or sending a query
or announcement. Temporary reservations remain refundable. Each control also
covers exhaustion after an eight-byte partial header and a complete ten-byte
empty-directory response, with unused connection capacity in every case.

Release-marker publication previously permitted a successful result when the
no-replace link completed but the following filesystem work crossed the original
deadline. The original contract already allowed blocking calls to return late;
this change tightens completion status. Directory synchronization and temporary
cleanup finish first, then the original deadline is checked. A late completion
returns an error while the exact published marker stays available for same-pin
readback. No timeout undoes a completed publication or permits overwriting it.

All three new controls were actually run before the production fixes. Each
selected exactly one test and exited 101 with one failure. These were working-tree
regression runs, with exact source-byte hashes retained in
[red observations](red/results.json); they are not relabeled as clean-commit
qualification. The corresponding [classic](red/1.log), [PQ](red/2.log) and
[post-link](red/3.log) logs retain the original failures. The [test-only patch](red/regression.patch.gz)
records their source relative to the stated parent.

## Reproduce on exact committed source

Use the pinned Rust 1.95.0 toolchain, the unchanged lockfile and repository test
profiles. The reproduction entry point is [reproduce.sh](reproduce.sh).
Keep receipts outside the checkout; the existing recorder checks all tracked
bytes and clean source before and after each command.

```bash
export CARGO_BUILD_JOBS=1
storage_source="$(git rev-parse HEAD)"
storage_receipts="$(mktemp -d)"
for scope in native checks clippy; do
  python3 scripts/ci/record_pq_native_command.py \
    --kind head --candidate "$storage_source" --tested "$storage_source" \
    --label "storage-$scope" --output "$storage_receipts" \
    -- bash evidence/cell-storage-owner-boundaries-20261104/reproduce.sh "$scope"
done
```

The commands are retained here before their final committed-source execution.
Only completed exact-source receipts establish their result; this recipe itself
does not claim a pass. Failed attempts remain retained. Native scope includes
the complete M09 library, CLI integration, example targets and compile-fail
documentation tests. It does not execute the complete Node/Hepta runtime or an
independently operated WAN campaign.

## Coverage and remaining integration

| Layer | Current local implementation | Remaining gate |
| --- | --- | --- |
| Objects | Canonical content-addressed TCM1/TMR1/TMT1/TMA1, bounded dense tensor parsing and actual full-file readback. | Other codecs, expert ABI and real runtime architecture policy. |
| Deduplication | Shared chunk CAS, exact base/target delta and shared immutable physical duties where contexts match. | Cross-context physical aliases and semantic adapter rebasing. |
| Dependencies | Complete declared bounded DAG, exact file mappings, router roster and independent loader-context pins. | The actual model owner must enumerate its required material and verify lineage policy. |
| Transfer | Shared retry/time/byte budgets, verified resume and explicit rarest-first or persistent profiles. | Combined rarest-first/persistent protocol, metered default serial serving and WAN qualification. |
| Discovery | Signed records, TTL, persistent replay protection, bounded source/prefix diversity and exhausted-budget refusal. | A real DHT and independent Sybil/eclipse assessment. |
| Retention | Full TCA2 root catalog, physical reservation/readback, pending-intent recovery and repair accounting. | Node funded full-release integration, locked/payment-backed obligations, automatic paid renewal and independent replicas. |
| GC | All pending, acknowledged and expired-but-unretired roots protect complete members; repairs block premature retirement. | External owners must enumerate all promised versions; separate machine rollback/custody evidence remains required. |
| Use | Full byte and declared tensor validation before completion publication; late success is refused without losing published facts. | Ordinary Hepta compatibility, CURRENT, withdrawal/generation, resource and FinalUse checks on the exact bytes used. |

The retention/GC audit found the existing shared-base/tokenizer, pending-root,
lost-repair-ACK, cold-plan-recovery and successor-window controls already present;
no speculative rewrite is attributed to this change. Replica fields remain
declarations, not proof of independently held copies. Component tests cannot
establish funded long-term availability, real model efficacy or production use.
