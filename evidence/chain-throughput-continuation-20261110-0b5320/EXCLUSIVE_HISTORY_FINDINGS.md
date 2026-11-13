# Exclusive History: source-bound campaign findings and next experiment

## Status and provenance

This is a read-only diagnosis of the already executed original campaign on
`7d6567b92575d1d84766afd49d0720b6f197b0e0`, tree
`ea0f6792497d72cbad92cffdeeedbcba7b6f9a06`. It is **not** a rerun of that campaign
on the later History-writer/pool-budget fixes. It changes no production code,
resource profile, acceptance criterion, or release status.

- [Original Actions run](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42938943169).
- [Original campaign job](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42938943169/job/130255827002).
- Retained official artifact: `13820807612`.
- Profile: Rust 1.95.0 release, `AuthenticatedV1`, three campaigns, each with
  baseline/from-zero/late-product phases of 30 seconds, 0/24/24 external attacker
  processes, 1,024 signed seed transfers, four seed blocks and 21 business blocks.
- Receiver and independent verifier: the original shared fixed public parent,
  `cpu.max = 25000 100000`, 2 GiB memory limit. The external attack processes
  remain in the controller's separate original domain. This is one host, without
  independent administration or WAN qualification.

The independent readback already present in the preceding task was inspected
alongside its retained raw phase JSON. The two local derivative identities are:

| Readback file | Bytes | SHA-256 |
| --- | ---: | --- |
| `campaign-independent-readback.json` | 54,542 | `3d4a2f0e2d1f8b63026ebfb38aadf5680ec8b5a921854adc11d4e089c03cd261` |
| `campaign-history-stage-readback.json` | 1,137,915 | `8ddace9980debe19d6b4ed11d4ecd0bc6561b2d8b6e13a2ac3fc4c483b0f1a51` |

These filenames describe the inspected local derivatives, not a claim that this
document itself contains the complete original artifact. Original raw members
are in `run-{1,2,3}-raw/{baseline,from-zero,late-product}.json` in the artifact.
All three measured commands actually ran after a successful release build and
exited 101. Their durations were approximately 107.874, 107.760 and 107.673
seconds. There was no recorded phase-startup error or report-validation error.

## Actual business outcome

| Outcome | Count |
| --- | ---: |
| Complete campaigns | 0 / 3 |
| Complete phases | 0 / 9 |
| Scheduled signed confirmation rounds completed in their window | 3 / 27 |
| Confirmation rounds actually entered | 12 / 27 |
| Scheduled rounds not entered | 15 / 27 |
| Honest submissions attempted | 84 |
| Honest client acknowledgments inside the window | 84 |
| Honest receiver full-work acceptances | 84 |
| History calls / imports | 80 / 80 |
| Successful History imports | 71 / 80 |
| History import deadline errors | 9 |
| External load-generator client attempts | 19,439 |
| Remaining receiver records: full-work acceptances | 0 |
| Remaining receiver records: full-work rejections / unknown outcomes | 19,312 / 125 |

Each baseline confirmed one round. Neither attack mode confirmed a round. Every
phase retained `PUBLIC_REQUEST_DEADLINE` and unequal final receiver/client state.
The nine phases all lacked an observed genuine paid-credit depletion.

The receiver remainder is the complement after excluding records whose exact
digests matched the honest submission corpus. This inspection has not matched
every remaining receiver record to an individual external attack attempt. The
19,312 rejections and 125 unknown outcomes therefore describe the remaining
records, not independently established attacker attribution for every record;
the load-generator attempt count is a separate client-side observation.

These figures belong to this exact source and workload. In particular, **3/27
here does not replace or combine with the earlier `aaa3c539` observation of
6/27**. Acceptance, client acknowledgment, History return and signed confirmation
remain different facts. This run's 84 successful client acknowledgments do not
establish 84 completed business effects.

## Where the measured History cost went

The optional observer records real Host checks and real nested packet stages.
The following sums group the 80 actual imports by phase kind across the three
campaigns. Failed imports are included. Import CPU measures only the importing
thread. Host CPU instead sums each callback's own calling-thread CPU interval
into a shared observer, including callbacks invoked by scoped workers. These
are different measurement scopes: neither column measures all service CPU.

| Phase kind | Imports / successful | Import wall, s | Import calling-thread CPU, s | Host checkpoint calls | Host callback aggregate CPU, s | Raw Host / import CPU ratio |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Baseline | 38 / 35 | 78.163010 | 18.234401 | 388,019 | 15.995850 | 87.72% |
| From-zero | 21 / 18 | 79.715977 | 11.183079 | 219,883 | 9.698863 | 86.73% |
| Late-product | 21 / 18 | 79.677915 | 10.979527 | 215,649 | 9.538577 | 86.88% |

For example, the first baseline import recorded 9,279 checkpoint Host
validations and 379.120 ms of aggregate Host callback CPU; its importing thread
used 429.440 ms and its elapsed import time was 2.093 seconds. The percentage
column is only the arithmetic ratio of those differently scoped counters. It
is **not an exact removable share of import CPU**, because the Host numerator
may include scoped-worker callbacks absent from the importing-thread
denominator. The observer explicitly reports
`host_cpu_includes_each_calling_thread = true` in
[`observation.rs`](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/7d6567b92575d1d84766afd49d0720b6f197b0e0/trillionnium/crates/trnm-pon-node/src/ingress/history_import/observation.rs).
The host's CPU throttling and receiver/verifier placement also contribute to
wall time. These observations establish substantial measured callback work;
they do not establish that removing it would produce a proportional
confirmation improvement.

The measured packet Commit stage alone consumed 9.459291, 5.991998 and 6.011323
seconds of import-thread CPU across baseline, from-zero and late-product,
respectively. That stage includes substantial validation and readback, not just
the SQLite commit call.

By comparison, the retained client's actual `Transaction::commit` API intervals
were:

| Phase kind | SQL commit calls | Known calling-thread CPU, s | API wall, s |
| --- | ---: | ---: | ---: |
| Baseline | 62 | 0.026600 | 0.145546 |
| From-zero | 37 | 0.022362 | 0.476940 |
| Late-product | 36 | 0.022191 | 0.403761 |

These are the differences between the corresponding raw phase's
`client_native_history_arithmetic_after` and `_before` counters, summed across
the three runs. The observer's scope includes the actual Rust commit API and
its existing rollback-on-drop behavior. It does not isolate physical `fsync`,
all SQLite statement time, or other processes' persistence. The nested packet,
Host, import and SQL intervals **must not be added together**.

On this run, batching physical commits is therefore a weaker first hypothesis
than reducing repeated complete account-graph validation under a justified
transaction boundary.

## Source path and existing optimizations

The relevant fixed-source entry points are:

- [`ingress.rs`](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/7d6567b92575d1d84766afd49d0720b6f197b0e0/trillionnium/crates/trnm-pon-node/src/ingress.rs):
  `receive_public_page_from_before_observed` invokes the original Host validator
  at initial, checkpoint and final boundaries; the campaign used the exclusive
  owner path.
- [`host_kernel_parent.rs`](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/7d6567b92575d1d84766afd49d0720b6f197b0e0/trillionnium/crates/trnm-pon-node/src/host_kernel_parent.rs):
  `KernelBudget::check` freshly checks boot identity, parent identity/ownership,
  actual calling-thread cgroup membership and the five current limits. No
  successful Host verdict is cached.
- [`native_store.rs`](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/7d6567b92575d1d84766afd49d0720b6f197b0e0/trillionnium/crates/trnm-pon-node/src/account_archive_prototype/native_store.rs):
  `verify_account_values` calls the original progress callback for each actual
  account-graph node visited. The callback reaches the Host validator.
- [`native_authenticated.rs`](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/7d6567b92575d1d84766afd49d0720b6f197b0e0/trillionnium/crates/trnm-pon-node/src/store/native_authenticated.rs):
  `verify_state_with_readback` checks current Record, native block/deltas,
  complete State commitment and account graph; `publish_with_readback` performs
  parent validation, graph application, record insertion and post-write checks.
- [`post_write_readback.rs`](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/7d6567b92575d1d84766afd49d0720b6f197b0e0/trillionnium/crates/trnm-pon-node/src/store/native_authenticated/post_write_readback.rs):
  `PostWriteReadback` already permits bounded whole-root and subtree reuse for
  four named records within the original unchanged write transaction and closed
  schema. Writes or transaction replacement invalidate the corresponding scope.
- [`store.rs`](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/7d6567b92575d1d84766afd49d0720b6f197b0e0/trillionnium/crates/trnm-pon-node/src/store.rs):
  `persist_admission_execution` already writes an ordinary canonical snapshot
  for every authenticated block, retaining the existing 64-row non-genesis
  snapshot policy. Adding a legacy parent-replay prefix would not remove the
  dominant work for these recent authenticated blocks.

Existing node-decode/root arithmetic caches still read current SQL inputs and
do not confer database authority. The earlier isolated Host-parser component
experiment was rejected as insufficient justification for a service claim.
This investigation supplies no evidence that another small parser change would
close the original campaign. No reduced Host frequency or cached Host verdict
is proposed.

## Narrow next optimization proposal — not implemented

Empty confirmation blocks often preserve the account graph while changing
other state. A plausible narrowly bounded experiment is to avoid re-traversing
that unchanged graph across the one native commitment-record insertion:

1. Qualify the original closed-schema write transaction before the existing
   complete parent-graph verification. Bind the actual parent/root and preserve
   all current State, Record, delta and Host checks.
2. Permit a continuation only when the **actual canonical deltas** contain no
   account change and the original no-write scope remains current through
   application. Claimed empty transactions or equal aggregate balances are
   insufficient.
3. Preserve the checked graph only across the one exact
   `INSERT INTO native_state_commitments` performed by the private `save`
   implementation. There must be no callback in this handoff, no admitted
   trigger/virtual-table/UDF graph, no foreign connection and no arbitrary
   caller-supplied graph. Existing row-count and inserted-record readback checks
   must remain.
4. The new post-write scope may consume that graph only after the ordinary
   current child Record, complete State commitment and exact account Root are
   verified. Every later write, schema change, callback mutation or transaction
   replacement must disable or refuse reuse through the final commit boundary.

This crosses a write, unlike the existing no-write readback scope. It therefore
needs an explicitly reviewed one-effect contract and cannot be implemented by
resetting the scope after an arbitrary write or copying the existing cache.
Its eligibility may be too narrow to justify the added machinery. No speedup,
correctness closure or implementation approval is inferred here.

The minimum validation matrix for that experiment is:

| Obligation | Required comparison or negative case |
| --- | --- |
| State and packet equivalence | Independent original full traversal versus candidate on empty confirmation blocks, real account-changing blocks and interleaved branches; compare all durable rows and final state |
| Complete graph validity | Warm then damage a leaf, fork, missing child, wrong nonce, zero-balance existence or untouched subtree; preserve refusal and rollback |
| Write freshness | Real/no-row writes, failed writes, DDL, writable-schema changes, attach/temp objects and mutation followed by restoration through callbacks |
| Transaction ownership | Commit/begin ABA, rollback/begin ABA, savepoint controls, wrong connection and observer replacement |
| Handoff exclusivity | Trigger on the commitment table, insert suppression, wrong row count, changed existing graph, changed root and failed inserted-record readback |
| Resource semantics | Cancellation and deadline before/during graph work, before record insertion and after it; retain original Host boundaries for every operation actually executed |
| Recovery and cost | Cold reopen, original tip/generation/receipts; actual graph visits and scoped hits, then unchanged full campaign with source/binary/resource identities |

## Separate CPU/refill feasibility question

The original fixed Host parent permits at most 0.25 CPU on average, and the
actual campaign used `25000 100000` with zero configured CPU burst. The scalar
mutation domain refills at 250,000,000 CPU nanoseconds per wall second and starts
with 2,000,000,000 nanoseconds of credit. Its two concurrent start reservations
are 100,000,000 nanoseconds each. These constants are in
[`scalar_cpu.rs`](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/7d6567b92575d1d84766afd49d0720b6f197b0e0/trillionnium/crates/trnm-pon-node/src/ingress/public_v3/scalar_cpu.rs).

The measured receiver mutation charges are a subset of that capped parent's
CPU. The verifier, authentication and other uncharged work also consume parent
CPU. This makes exhaustion of the initial two-second scalar burst by steady
receiver pressure implausible under the equal long-run Host/refill rates.
The smallest sampled **paid** credit over all nine phases was approximately
1.976 seconds; none of the samples reported depletion. Stored credit is lower
while original start reservations are outstanding and is not interchangeable
with paid credit.

That is an inference and a concrete test-design question, **not a proved
impossibility theorem**. Kernel quota periods, finite scheduling bursts, live
sample/settlement delays, cooperative overshoot, domain membership, scope
coverage and unknown clocks must be included before deriving a strict bound.
The campaign's attack phases currently require genuine observed depletion as
well as signed confirmation. Faster confirmation alone will not satisfy that
conjunction if the tested resource arrangement cannot produce the required
depletion. Preserve the original failed result and criteria; study reachability
of the depletion predicate separately instead of widening the Host, reducing
the refill, adding credit/debt or relabeling the campaign successful.

## Closure boundary

The shared History writer handoff and ordinary mining pool cancellation fixes
address independently reproduced component failures. They do not by themselves
close the original **exclusive** History campaign. This report identifies the
account-graph/Host-check cost concentration and the separate depletion-coverage
question. Complete confirmation under pressure, sustained TPS, WAN service,
total retained-history bounds and production qualification remain unestablished
by these observations.
