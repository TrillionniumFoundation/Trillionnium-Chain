# Retained Node: complete-log post-panic diagnosis

**Outcome: preserve the retained Node failure and keep qualification on HOLD.** The complete original run establishes four concrete failing boundaries. It does not establish that the new account-profile guard semantically rejected a valid configuration, nor does it establish an environmental, existing-base or guard-cost cause. No base execution comparison was performed.

This is a new successor to the six immutable pre-panic reports listed below. It incorporates the completed stdout, stderr and four terminal records; it does not rewrite earlier observations. This review used local reads, hashes, JSON parsing and consistency comparisons only. It did not run Cargo, change source or environment, rerun tests, adjust budgets or propose an optimization.

## Exact source, original command and actual scope

The desktop job was `1a1c8ba754b-135c4-1d3`. Its tested source was `cdd984808a088e6c2e13b1e1ae6630a94d500c89`, tree `1ed39b6ebe55cb00c238f26f6bfc9361ab93faec`. The comparison base referred to in earlier source inspections is `df927b6ffaecff293b9e9428e3ba516f47cd101a`; that base was not executed.

The original command, copied from its raw context and result, was:

```text
env CARGO_HOME=/home/qian-qi/chain-pq-a418-final-cargo-home TRNM_CI_TOOL_ROOT=/home/qian-qi/chain-pq-a418-final-ci-tools CARGO_TARGET_DIR=/data/chain-pq-a418-node-retained-target-20261111 cargo test --locked --offline --manifest-path trillionnium/Cargo.toml -p trnm-pon-node --all-targets --all-features -- --test-threads=1
```

The explicit `env` arguments override the recorder's baseline `CARGO_HOME` and `CARGO_TARGET_DIR`. The command returned **101**, after **9327.54999621096 seconds**, at `2026-11-11T06:26:28.622222+00:00`. Root's authoritative supervisor observation was failed exit 1 with complete durable output and no timeout or cancellation; the command failure is independently present in the raw result.

The four distinct terminal records are:

| Record | Actual result |
| --- | --- |
| `node-retained-data-preflight` | PASS, rc 0 |
| `node-retained-data-source-before` | PASS, rc 0 |
| `node-retained-data-all-targets` | FAIL, rc 101 |
| `node-retained-data-source-after` | PASS, rc 0 |

Only the Node `src/lib.rs` executable has a Cargo `Running` header. The parent suite reports **1,359 passed, 4 failed, 39 ignored, 0 measured, 0 filtered out**, totaling **1,402**, in **7,809.10 seconds** (stdout line 1477). Three nested child-process summaries of one passing test with 1,401 filtered tests are not added to that parent count. The library failure prevented the remaining integration targets from executing. All four new `store::account_profile_scope_tests` cases printed `ok` in this same parent run (lines 791–794). The 39 ignored cases remain unexecuted.

The final complete source guard finished at `2026-11-11T06:27:10.516448+00:00`. It verified the same Z/tree, clean source and **27,862 tracked entries**. A successful identity guard is not an additional native test pass and does not clear the retained command failure.

## Four observed failures

| Case | Actual panic and reached boundary | What remains unproven or unexecuted |
| --- | --- | --- |
| `actual_npq6_lost_ack_and_cold_resume_reuse_exact_wire_without_history_consuming_sequence` | `recovery_cases.rs:209:5`: cold Resume success assertion received `IO: Resource temporarily unavailable (os error 11)`; raw stdout lines 1446–1449. | The lower-level socket stage and reason for that retained I/O error are not recorded. Subsequent successful-Resume assertions were not reached. |
| `actual_npq6_plain_parent_recovery_and_cold_membership_keep_one_original_campaign` | `recovery_cases.rs:130:5`: cold Resume success assertion received `PUBLIC_CLIENT_DEADLINE`; lines 1451–1454. | The original ten-second campaign includes cold reopen and Resume without a renewed campaign budget. This error does not attribute elapsed time to a constituent call or the new guard. |
| `admitted_custom_genesis_over_eight_mib_keeps_original_held_schedule_and_cpu_owner` | `store/detached_admission/tests.rs:1058:31`: original native result unwrap received `PUBLIC_MUTATION_CPU_BUDGET`, code `PublicMutationCpuBudget`, kind `Capacity`; lines 1456–1462. Captured diagnostics say `authenticated_backend=false`. | The first, legacy-backend iteration failed; the later authenticated iteration in this same test did not execute. |
| `guarded_npq6_valid_submit_exact_replay_and_independent_process_restart` | `store/pq_rollback_witness/combined_tests.rs:586:6`: first send unwrap received `IO: Connection reset by peer (os error 104)`, kind `Transport`; lines 1464–1468. | The later successful-submit, exact replay and independent restart assertions were not reached. The reset alone does not identify an internal ingress, commit or witness failure. |

These full test names, exact panic references and raw line ranges are also stored in the paired JSON. None of these four actual panic errors reports `ACCOUNT_DEVELOPMENT_SCOPE_REQUIRED` or `PQ_ACCOUNT_PROFILE_UNAVAILABLE`. That observation is bounded to the recorded failures; it does not exclude indirect timing effects on their execution paths.

## Original large-parent CPU and refusal evidence

All three original diagnostic JSON records remain in stdout lines 1457–1459. The paired JSON retains their raw-line hashes and selected original values; the raw stream retains every arithmetic-stage field.

The legacy case recorded **8,625,548** complete key/canonical-value bytes, an **8,391,103-byte** held-capacity lower bound, and **2,871,025,464 ns** of elapsed original metered dispatch. Its recorded settlement satisfies:

```text
2,000,000,000 initial credit
+ 700,213,267 credited refill
- 2,728,308,769 paid CPU
= -28,095,502 remaining paid credit
```

`balance_identity_verified` is true. Both scoped workers were accounted for: two known, spawned, started and finished workers; `accounting_unavailable=false`; `live_refused=true`. Original CPU settlement records owner CPU of **2,727,098,194 ns**, scoped-worker CPU of **1,210,575 ns**, total CPU of **2,728,308,769 ns**, live paid CPU of **2,728,161,652 ns** and settlement residual of **147,117 ns**. The original refusal was preserved.

The post-outcome readback reports `active_state_unchanged_on_refusal=true` and no readback error. This supports that specific active-state observation; it does not assert global byte-for-byte storage immutability for every failure. The captured zero arithmetic-stage counters on this legacy backend do not mean that no work occurred and do not measure CPU spent in the new guard. The fixture's `host_qualified`, `all_honest_service_qualified` and `budget_depletion_demonstrated` flags remain false. The arithmetic above explains the observed balance, without granting any broader qualification.

## Witness cleanup and absent phase evidence

The original `TRNM_PQ_FIXTURE_CLEANUP` record at stdout line 1465 has `cleanup_complete=true`, `child_exit_observed=true`, `child_exit_success=true`, `worker_join_observed=true`, no child/worker cleanup error, and `primary_error_preserved=true`. Cleanup completion does not qualify the unexecuted replay/restart assertions or prove that the failed first send had no earlier effects.

An exact scan of **both complete canonical streams** found **zero** occurrences of `TRNM_PQ_PHASE_DIAGNOSTIC`. The separate 250 ms cap on each witness Current/CAS request is a source fact recorded in the preserved pre-panic analysis. The actual connection reset cannot be assigned to that cap, or to a particular witness/ingress/commit phase, from this run. No absence-of-phase inference is based on a truncated prefix.

## Causal boundary retained from the source reviews

The original fixture profiles were valid in the preserved source inspection. New Node/M06 guards are nevertheless reachable along these paths. Fixture and dependency-file equality alone therefore does not isolate these failures from the patch.

The NPQ6 paths reach additional complete PQ configuration-digest checks. Their incremental elapsed-time or CPU cost was not measured. The large-parent failure uses a valid classical development profile: its new guard checks scope and selector fields, without entering the PQ digest branch or adding canonicalization of the eight-MiB initial State. The new Node guard is outside the witness client's own 250 ms request implementation. These source boundaries narrow possible mechanisms; they are not a causal verdict.

The actual errors establish a retained I/O failure, a client deadline failure, a CPU-capacity refusal and a transport reset. They do not establish a new guard semantic refusal. They also do not clear guard-cost effects or prove an environmental or previously existing cause. There is **no actual base execution comparison**. The failures remain failures; no deadline, quota, CPU allowance, optimization setting, feature, roster or acceptance threshold was changed to obtain a pass.

## Evidence pins and README review

Canonical evidence root:

```text
/workspace/scratch/a4188f5c86b5/desktop-evidence/cdd984808a088e6c2e13b1e1ae6630a94d500c89/node-retained-data-evidence-v1
```

The four records are below `primary/validation/cdd984808a088e6c2e13b1e1ae6630a94d500c89/`. Every one of the export manifest's **20 original files** was independently read and checked against its exact byte count and SHA-256 in this review. All four records' stdout/stderr hashes match their raw result JSON. The canonical stdout is byte-identical to `coordination/data-node-stdout-observed-prefix-0-209668.log`.

| Evidence | Bytes | SHA-256 |
| --- | ---: | --- |
| `node-retained-data-all-targets/stdout.log` | 209668 | `3591e3a47da4904328b0eff2382a0d3f434c3673b7a859c2a3d6d10171f97435` |
| `node-retained-data-all-targets/stderr.log` | 4667 | `31d06d28bf2c70fbd4a022b1690062e38fbf61f931fdfe2ed7488854098e2500` |
| `node-retained-data-all-targets/result.json` | 1267 | `5bd2e262e23817041a8183f4bf5ecfcc3cb33f43d1727a002808eff178d2c3d3` |
| `node-retained-data-all-targets/context.json` | 4411 | `34fc3427b9bc3fdd82dc9c28965844dea6b965a78071e7b52da84d2440f3e845` |

The reviewed README is `coordination/delivery-evidence-README.completed-node.draft.md`, **23,437 bytes**, SHA-256 **`66f347097c6408a19689f87fa1709c423a1d3195d33f2be22a89d6f1edca886a`**. Its “Retained Node failure and exact observed limits” section (lines 201–262) accurately states the observed outcome, execution scope, CPU values, cleanup, absence of phase records and causal limits. **No factual or scope correction is required in that section.** This review does not grant hosted CI, full CI, release or production qualification.

The following pre-panic originals were rehashed and remain unchanged:

| Original snapshot | SHA-256 |
| --- | --- |
| `diagnostic_node_recovery_readonly.md` | `fa813f91f3e27694258eddcf196a25dbff0df7a1b8f85dee677ee1e249e1d983` |
| `diagnostic_node_recovery_readonly.json` | `04e0ccb41f8e00f6921e52a2bf12b48b805b2a6024a01ab0fc8e45fcac621c64` |
| `diagnostic_node_large_parent_pre_panic_addendum.md` | `cff1ddc924f9f4a6330c9290e6f710a4556285933a25708111d60cd8dd698338` |
| `diagnostic_node_large_parent_pre_panic_addendum.json` | `82e0f36e5d5d4791b0706d29780c3ecfecbe10bfd3e2df6f5169e106983d48b9` |
| `diagnostic_node_witness_pre_panic_addendum.md` | `bca796c7f8a46cb6b3d3af2d6be2fd22a4c4ffd2c36787e45555e945a69765aa` |
| `diagnostic_node_witness_pre_panic_addendum.json` | `b422ff812d0500cf194bf1398ee8b45f78684191e13ecc0e0b0bf900ca45ae81` |

The paired `diagnostic_node_post_panic.json` records receipt identities, selected captured diagnostics, original failure locations, explicit limitations and this review's read-only actions. Full raw output remains authoritative.
