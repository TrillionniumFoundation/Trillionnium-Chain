# Original-budget throughput engineering

This continuation repairs concrete cancellation/accounting boundaries on
`e4abb172147e941b62483652b0ceabaae4317624`, follows the actual failed hosted
comparison, and preserves the evidence needed to test the next implementation.
**Complete business liveness and measured throughput remain open.**
Application capacity, confirmation criteria, service resource budgets, native
work verification and the original campaign are unchanged.

## What actually ran

The first delivery, `7d6567b92575d1d84766afd49d0720b6f197b0e0`, was built
and executed in [run 42938943118](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42938943118).
Both exact Rust 1.95 release builds succeeded and both libtests listed 1,338
tests. The four mining controls met their before/fixed expectations: fixed
four passes, old production three specified assertion failures plus the
equivalence pass. Both jobs nevertheless failed the complete seven-control
comparison. Fixed History Continue finished detached execution but refused
the subsequent held Commit with `PUBLIC_MUTATION_CPU_BUDGET`; epoch close
then failed. Fixed Cancel passed its native assertions but failed the reader's
final-account requirement. Fixed Expire passed native and reader checks. The
three old History failures reached the intended actual CPU-debt injection but
also lacked the final flow required by that reader. They remain rejected
negative-control observations.

[The complete G2 packet](g2-component-native/README.md) retains every original
artifact member, both actual binaries, the original reports and full job logs
losslessly. The later read-only pre-close observation and revised reader cannot
retroactively qualify those earlier results.

## Runtime changes

1. Controlled registered mining now checks the caller's original control before
   material derivation and passes it through parent-state row scans and ancestry
   replay. Cancellation no longer waits until execution to observe these reads.
   Four native controls cover early errors, active rows, inactive ancestry,
   retry, packet equivalence, worker counts and cold reopen. This was the scope
   qualified by the G2 component comparison, not a complete service result.
2. Shared History import now distinguishes the scopes where the Node mutex is
   actually held from work performed after releasing it. Detached execution may
   wait for refill of its original CPU account after complete verified W1 work;
   held preparation, fallback and commit retain their refusal rules. The account,
   worker accounting, cancellation and original absolute deadline are retained.
   The follow-through now lets that same eligible operation wait for original
   free credit after detached workers join and before reacquiring the writer.
   An unqualified operation that passes the original paid check continues
   directly; it receives no new waiting right. Existing reservations remain
   intact, unknown/refused operations cannot revive, and held Commit may still
   refuse if concurrent work consumes the available headroom. This is not a
   commit-cost guarantee or evidence of improvement in the separate Exclusive
   campaign.
3. Ordinary pool mining now carries its original stop flag and run end through
   selection, parent reads, legacy/registered preparation, preview and
   post-search revalidation. Typed local cancellation remains distinct from
   SQL/native failures and cannot mark a cancelled group blocked. The original
   durable admit/activate/final-reconcile completion sequence stays intact;
   SQLite and other indivisible calls cannot be hard-preempted. New outer
   checkpoints use only the lightweight caller control, preserving the public
   owner's original Host observation sites.

The initial implementation source was
[`b7e38fdc2e43c468692abc52aec03737f2df7f1b`](https://github.com/TrillionniumFoundation/Trillionnium-Chain/commit/b7e38fdc2e43c468692abc52aec03737f2df7f1b),
tree `b75d318fc7b7b027a810f4a70a9cd91e0b3930f8`. Its parent
[`d6bbac6baf9e5356721ab56f7432058d07b6b49b`](https://github.com/TrillionniumFoundation/Trillionnium-Chain/commit/d6bbac6baf9e5356721ab56f7432058d07b6b49b)
retains old production behavior with the same seven native test bodies. The
G2 delivery added source bindings, the independent comparison runner and
evidence; its actual result is stated above.

The follow-through implementation is
[`85a905b9e47cea0d76144253abb4a483b58bc2be`](https://github.com/TrillionniumFoundation/Trillionnium-Chain/commit/85a905b9e47cea0d76144253abb4a483b58bc2be),
tree `e0741c360ea6890b1a729b1b4fad4fa6fc35a990`. Its ancestry retains two
explicit negative-control snapshots: ordinary-pool before
[`db93026b9314bfd8bc4350945036998f1b7d34aa`](https://github.com/TrillionniumFoundation/Trillionnium-Chain/commit/db93026b9314bfd8bc4350945036998f1b7d34aa)
and original-budget before V2
[`89fb2269b0dd306fbd32c36f464842c3d7daee2b`](https://github.com/TrillionniumFoundation/Trillionnium-Chain/commit/89fb2269b0dd306fbd32c36f464842c3d7daee2b).
The latter deliberately restores old production for its experiment; it is not
a deployable successor. The final implementation restores the fixes before any
branch publication. Exact production-library typechecking passed on the frozen
combined source. New native outcomes must come from the subsequent source-bound
hosted comparison, not from that typecheck or the earlier G2 execution.

## Evidence and actual limits

| Evidence | Actual observation | Scope |
| --- | --- | --- |
| [Original CI readback](ci-origin/README.md) | The exact `e4abb172` protocol-contract job built successfully, but its native acceptance manifest failed `CONFIRMATION_TARGET`. The separate 2-by-4-second experiment confirmed baseline 1/1 and pressure 0/1; both had 7/7 ACKs. | One original hosted experiment, not the earlier `aaa3c539` 3-by-30-second campaign. |
| [Recovery ordering](recovery-order/README.md) | The existing `work_order` covering index avoids SQLite's temporary ordering tree on the tested 4,099-row component fixture and preserves order. | Corrects documentation about an existing index; no new native recovery or TPS result. |
| [Source-lock review](source-lock-review/README.md) | Original mismatches are retained; current source bindings and their rejection controls are checked explicitly. | Source consistency does not qualify lifetime security, authority coverage or business liveness. |
| [CI roster controls](ci-python/README.md) | Nine Python controls verify the updated required History roster and retained omission/failure checks. | Expected 36-plus-one History roster, not an executed native `--list` or native pass count. |
| [Component runner review](component-runner-review/README.md) | Fourteen Python controls and independent source review check the native comparison reader's failure handling and exact negative-control sites. | Reader fixtures are not native execution or campaign evidence. |
| [Local build attempts](local-build-attempts/README.md) | Five unsuccessful preparation/build attempts; no native test case executed. The final two compiler processes terminated with SIGKILL. | No inferred cause and no pass inferred from partial build artifacts. |
| [Actual G2 component run](g2-component-native/README.md) | Both builds and all fourteen processes ran; mining expectations passed, History left both jobs failed. | Complete original packet, including binaries; no later reinterpretation as a pass. |
| [Pool before source](pool-before-source/README.md) | Exact old production, shared test bytes and test-only hooks; real patch/apply/byte-compare checks. | Native outcomes must be observed independently. |
| [Budget before V2 source](history-before-v2-source/README.md) | Exact old budget production with the shared new settled-flow observations. | No stub of the new API; fixed-only invariants do not count as old-arm coverage. |
| [History handoff review](history-handoff-review/README.md) | Frozen source, independent review and 17 V2 reader/refusal methods passed; an extra paid-allowance refusal was caught and corrected. | Source and constructed-reader checks, not native execution. |
| [Local continuation checks](local-continuation-checks/README.md) | Frozen combined production library typechecked with Rust 1.95 and unchanged input hashes. | No cfg(test) compilation or native execution in these local checks. |
| [Host parser component](host-parser-component/README.md) | Isolated parser savings were too small to justify a service claim; no fast path was applied. | In-memory component timings exclude fresh Host I/O and observation costs. |

The earlier expanded `pon-budget-controls.yml` revision compared three immutable subjects on
separate runners. Original-budget before V2 must show six designated failures
and one equivalence pass; ordinary-pool before must show five designated failures
and two equivalence/error passes. Fixed must pass their fourteen shared controls,
five additional original-account invariants and the complete ten-test pool
integration suite. Same-input checks are scoped to each shared group. The actual
libtest, integration harness and CLI binary are bound to the original compiler
and release profile, complete rosters and source-before/source-after receipts.
The [later continuation](../chain-throughput-continuation-20261110-0b5320/README.md)
adds the fourth reconciliation-scan lane and records the native fixture failure
and explicitly versioned old-pool subject correction. This paragraph describes
the earlier runner revision, not the current roster.

Every History case must expose the fully settled original account before epoch
close. A final unavailable account is only explainable by an observed known
negative balance, exact paid CPU identity, zero live owners/reservations and the
actual original close fence and durable marker. Unknown pre-close accounting
remains a failure. Continue still requires full import, activation and clean
close. Missing tests, compilation errors, signals, early fixture expiry and
unrelated panics fail the comparison. These component reports leave campaign
execution, complete-business qualification, TPS and production activation false.

## Remaining throughput work

- Establish complete original-budget service confirmation, including timeout
  reconciliation and retry effects. ACK, receiver admission and confirmation
  remain different observations; neither this code change nor Python test
  counts establishes the missing outcome.
- Profile and reduce complete state clones and repeated validation with explicit
  cache ownership and invalidation. Existing root/readback checks remain.
- Develop deterministic conflict-aware execution and persistence batching with
  crash recovery and idempotency evidence, after identifying the measured cost.
- Bound retained packets, deltas and authorization history with explicit archive,
  pruned and cold-recovery contracts. Existing snapshot/key/cache limits and
  bounded query batches do not bound all retained history.
- Compare higher block rates or DAG/parallel-chain options only against complete
  business outcomes under matched workloads. The current PQ profile's 6.4 and
  3.2 command/second conditional ceilings are unchanged and are not measured TPS.

This work does not request a protected-main merge or production activation.
