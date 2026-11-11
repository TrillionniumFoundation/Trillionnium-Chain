# Original-budget throughput engineering

This continuation repairs two concrete cancellation/accounting boundaries on
`e4abb172147e941b62483652b0ceabaae4317624` and preserves the evidence needed to
test them. **Complete business liveness and measured throughput remain open.**
Application capacity, confirmation criteria, service resource budgets, native
work verification and the original campaign are unchanged.

## Runtime changes

1. Controlled registered mining now checks the caller's original control before
   material derivation and passes it through parent-state row scans and ancestry
   replay. Cancellation no longer waits until execution to observe these reads.
   Four native controls cover early errors, active rows, inactive ancestry,
   retry, packet equivalence, worker counts and cold reopen. This does not change
   the separate ordinary pool-mining preparation path.
2. Shared History import now distinguishes the scopes where the Node mutex is
   actually held from work performed after releasing it. Detached execution may
   wait for refill of its original CPU account after complete verified W1 work;
   held preparation, fallback and commit retain their refusal rules. The account,
   worker accounting, cancellation and original absolute deadline are retained.
   Three native controls spend real measured CPU in the existing test hook and
   check continuation, cancellation and expiry without new credit. This does not
   establish improvement of the separate Exclusive-owner original campaign.

The implementation source is
[`b7e38fdc2e43c468692abc52aec03737f2df7f1b`](https://github.com/TrillionniumFoundation/Trillionnium-Chain/commit/b7e38fdc2e43c468692abc52aec03737f2df7f1b),
tree `b75d318fc7b7b027a810f4a70a9cd91e0b3930f8`. Its parent
[`d6bbac6baf9e5356721ab56f7432058d07b6b49b`](https://github.com/TrillionniumFoundation/Trillionnium-Chain/commit/d6bbac6baf9e5356721ab56f7432058d07b6b49b)
retains old production behavior with the same seven native test bodies. The
later delivery adds source bindings, the independent comparison runner and
evidence; it must not be confused with an already executed native result.

## Evidence and actual limits

| Evidence | Actual observation | Scope |
| --- | --- | --- |
| [Original CI readback](ci-origin/README.md) | The exact `e4abb172` protocol-contract job built successfully, but its native acceptance manifest failed `CONFIRMATION_TARGET`. The separate 2-by-4-second experiment confirmed baseline 1/1 and pressure 0/1; both had 7/7 ACKs. | One original hosted experiment, not the earlier `aaa3c539` 3-by-30-second campaign. |
| [Recovery ordering](recovery-order/README.md) | The existing `work_order` covering index avoids SQLite's temporary ordering tree on the tested 4,099-row component fixture and preserves order. | Corrects documentation about an existing index; no new native recovery or TPS result. |
| [Source-lock review](source-lock-review/README.md) | Original mismatches are retained; current source bindings and their rejection controls are checked explicitly. | Source consistency does not qualify lifetime security, authority coverage or business liveness. |
| [CI roster controls](ci-python/README.md) | Nine Python controls verify the updated required History roster and retained omission/failure checks. | Expected 36-plus-one History roster, not an executed native `--list` or native pass count. |
| [Component runner review](component-runner-review/README.md) | Fourteen Python controls and independent source review check the native comparison reader's failure handling and exact negative-control sites. | Reader fixtures are not native execution or campaign evidence. |
| [Local build attempts](local-build-attempts/README.md) | Five unsuccessful preparation/build attempts; no native test case executed. The final two compiler processes terminated with SIGKILL. | No inferred cause and no pass inferred from partial build artifacts. |

The new `pon-budget-controls.yml` lane builds one original-release-profile
libtest for each source on separate runners. It requires the actual test list,
binary identity, compiler profile and source-before/source-after receipts. The
old source must show six designated assertion failures and the packet-equivalence
control must pass. The fixed source must pass all seven. History failures count
only after real verified work, detached M06 execution and measured CPU debt;
missing tests, compilation errors, signals or early fixture expiry are failures
of the comparison. Its reports explicitly leave campaign execution, whole
business qualification, TPS measurement and production activation false.

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
