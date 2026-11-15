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
Provision the complete locked dependency cache with
`cargo fetch --manifest-path trillionnium/Cargo.toml --locked` before the offline
metadata step; platform-specific dependencies also belong to that graph.

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

## Completed exact-source observations

Implementation commit: `0c0b0b0ba7a2e06ceb07820784a10a61fe56507a`.
Implementation tree: `24fa4359aacdfd00ea768c2d25f9dc49c1ab622b`.
The [verification and reproduction manifest](verification.json) retains complete
before/after source receipts, commands, compiler versions, log sizes/digests,
the failed initial attempt and the corrected unchanged-source retry.

| Executed scope | Result |
| --- | --- |
| Complete M09 library | 305 passed; zero failed, ignored or filtered |
| Eight CLI integration suites | 29 passed; zero failed, ignored or filtered |
| Compile-fail documentation | 8 passed; zero failed, ignored or filtered |
| Six Python source/claim/authority/closure/root suites | 127 distinct tests passed: 43 + 35 + 22 + 11 + 12 + 4 |
| Whole workspace / all targets strict Clippy | Passed, default features, unchanged dev profile, `-D warnings` |
| Format, native inventory, exact source pins and CI contract | Passed; 468 exact pinned blobs |
| Repository structure and Markdown links | Passed; 26 workspace packages, 1,135 Rust files, 2,913 local links |
| Complete locked/offline Cargo graph | Passed after cache provisioning; 175 resolved packages, unchanged lockfile |

The native total is **342 named tests**, including all original 41 retention and
26 archive cases. Zero-test binary/example harnesses are not counted. The three
new regressions actually pass inside the complete library run. The source recorder
rehashes **9,556 tracked entries / 954,119,358 bytes** before and after each
command; identities match throughout.

The first `checks` attempt exited **101** only at the final offline Cargo graph
step: the local dependency cache lacked the locked `anstyle-wincon v3.0.11`.
Its 127 Python tests, format/source checks and repository checker had passed,
but the overall failed command remains recorded as failed. After the locked
fetch, the original full checks command was rerun unchanged and passed. Repeated
test identities are not added to the unique count.

Native scope covers the complete M09 library, CLI integration, example targets
and compile-fail documentation tests. It does not execute the complete
Node/Hepta runtime or an independently operated WAN campaign.

## Concurrent delivery composition

The shared branch advanced through `ac4246dbd` to
`799cc427e5a26b5a4f94236b8716ee5fb744288c` while the code checkpoint ran.
The delivery preserves both incoming commits and all 16 non-plan evidence paths;
the sole plan combines both histories without conflict. Its source projection
verifies that `trillionnium`, `scripts`, `config`, `formal`, `.github` and the
toolchain pin remain byte-identical to the tested code checkpoint. The incoming
performance observation scripts remain attributed to their own evidence owner.

The final delivery adds this small verification manifest and result documentation.
The native and Clippy executions above stay bound to `0c0b0b0b`; the delivery
commit is not described as a new execution of the complete combined source.
Its complete raw source identity and repository structure are checked separately
before the expected-head update of the existing #688 branch.

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
