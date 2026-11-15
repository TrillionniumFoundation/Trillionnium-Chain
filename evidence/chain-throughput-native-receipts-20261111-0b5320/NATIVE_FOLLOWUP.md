# Original campaign follow-up and current verification boundary

This read-only follow-up keeps the executed original campaign on
`7d6567b92575d1d84766afd49d0720b6f197b0e0` separate from the current component
candidate `11e242dbaaae14a9d16282fe8deaf36827e98395`. It changes no runtime,
resource policy, acceptance criterion, qualification flag or activation state.

## Paid-credit depletion: original samples, not a newer campaign

The retained official artifact `13820807612` contains 83,977,458 bytes and has
SHA-256 `f06c618a51693b79fd8d7b7c910b5ce3dad96c1ee73901535688766f57b93b1a`.
It belongs to [run 42938943169](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42938943169).
The follow-up script reads all nine raw phase JSON members directly from this
verified archive. It does not execute or substitute a newer campaign.

| Original receiver sample observation | Result |
| --- | ---: |
| Samples across the nine phases | 3,996 |
| Missing actual flow or unknown meter observations | 0 |
| Observed samples satisfying the original depletion predicate | 0 |
| Independently recomputed samples satisfying that predicate | 0 |
| Samples with cumulative paid debit above 1.9 CPU-seconds | 667 |
| Balance-identity or predicate mismatches in the recomputation | 0 |
| Minimum sampled remaining paid credit | 1,976,183,348 ns |

The original [`paid_depletion` predicate](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/7d6567b92575d1d84766afd49d0720b6f197b0e0/trillionnium/crates/trnm-pon-node/tests/public_v3_multiprocess.rs)
requires the full original two-second starting credit, a verified flow identity,
remaining paid credit below 0.1 seconds, cumulative paid debit above 1.9 seconds,
no mutation CPU clock failure and available accounting. The campaign test file
is byte-identical in the reviewed current candidate, with SHA-256
`83a6a768cd501d748e31f5fbc613cf75c23cec9e9f711915d3742c8715b9fcdf`.

The actual identity is `remaining_paid_credit = initial + credited_refill -
paid_debit - settlement_discard`. Consequently, cumulative CPU use above 1.9 seconds is
insufficient by itself. Reserved credit, terminal refusals, unknown clocks or
negative stored credit cannot replace the original paid-credit condition.
Several attack phases accumulated more than 2.4 CPU-seconds of paid debit while
retaining close to two seconds of paid credit.

The fixed parent has a quarter-core CPU limit, while the scalar domain refills
at a quarter CPU-second per second. The equality of their long-run rates raises
a reachability question; it does not prove impossibility. Quota-period bursts,
sampling and settlement delays, integer rounding, discarded refill, cooperative
overshoot and exact accounting-domain coverage still matter. These samples do
not exclude every possible change between observations.

The sampled domain belongs to the receiver. The independent verifier's
exclusive History CPU is not this receiver account's paid debit. Both owners
run within the same phase process under the fixed Host limit; the service uses
a separate thread. Callback CPU aggregated across its calling
threads and the importing thread's own CPU likewise have different scopes.
Their ratio is not an exact removable cost fraction.

The original business result remains 3/27 timely planned confirmation rounds,
0/3 complete campaigns and 0/9 complete phases. Confirmation completion and
depletion coverage remain separate obligations. These observations neither
replace the earlier `aaa3c539` 6/27 result nor describe a current-source campaign.

## Account-graph work already removed and the remaining boundary

The relevant graph and arithmetic-cache implementation is unchanged from the
executed original campaign. The existing
[`PostWriteReadback`](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/11e242dbaaae14a9d16282fe8deaf36827e98395/trillionnium/crates/trnm-pon-node/src/store/native_authenticated/post_write_readback.rs)
scope supports four named records and bounded subtree reuse after the last
qualifying write. Existing node decoding still reads current SQL and reuses
parsing only for matching complete BLOB bytes and expected identity. Existing
`CurrentAccounts` reuse avoids a second parse of the same immutable State where
the current call already produced that projection.

In
[`publish_with_readback`](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/11e242dbaaae14a9d16282fe8deaf36827e98395/trillionnium/crates/trnm-pon-node/src/store/native_authenticated.rs),
parent verification and the subsequent parent Record read are separated by
original progress callbacks. Removing the latter would drop an observation of
possible callback effects. `save` also retains actual SQL readback of its newly
inserted Record; the constructed Rust object does not replace that check.

The
[`same_write_snapshot` boundary](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/11e242dbaaae14a9d16282fe8deaf36827e98395/trillionnium/crates/trnm-sqlite-io-boundary/src/transaction_scope.rs)
requires the same actual connection and active write transaction, unchanged
transaction-control epoch and unchanged potentially-writing statement count.
Zero-row writes, failed writes and rolled-back DDL still matter. A transaction
or savepoint ABA cannot restore an old scope merely by restoring the old rows.

The remaining pure codec/projection candidates have no measured benefit in
this campaign. They would not remove the main account-graph traversal or fresh
Host checks. No such optimization was added to the frozen candidate. In
particular, graph validity was not carried across a subsequent write without
the missing transaction, callback and closed-schema proof.

## Why the desktop component run is not the original business campaign

The current
[`run_native_phase_host.py`](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/11e242dbaaae14a9d16282fe8deaf36827e98395/scripts/ci/run_native_phase_host.py)
`outer` entry requires a real hosted CI context, the matching workspace and
run/attempt/job identity. Its `HOSTED_CI_ONLY_NO_LOCAL_PROVISION` refusal occurs
before provisioning; the source retains a negative control for this boundary.
The required external-actor placement is selected by
[`multiprocess_phase_host.rs`](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/11e242dbaaae14a9d16282fe8deaf36827e98395/trillionnium/crates/trnm-pon-node/tests/support/multiprocess_phase_host.rs).

Omitting that placement selects an older local route with a different resource
arrangement. It does not qualify the current fixed-Host campaign. The internal
`--inside` entry is for a previously established and checked service, not a
local provisioning substitute. The formal controller additionally requires
four CPUs, 16 GiB, nice 10, adequate CPU affinity and no tighter ancestor limit;
the receiver/verifier parent retains its separate quarter-core and 2 GiB limits.

The desktop component jobs are operator jobs with separately recorded limits;
they are not observed GitHub Actions jobs. No CI identity was fabricated, no
original launcher was bypassed, and no fixed public Host service was started
for this follow-up. The current-source original campaign remains assigned to
[run 42960214803](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42960214803).
The dated CI snapshot records its observed status; component execution does not
replace its eventual business result.

## Delivery scope

Current component changes address shared History writer handoff and ordinary
mining preparation/reconciliation cancellation. They preserve durable
admission/activation completion and the original paid account, deadline and
Host checks. They do not establish complete exclusive History confirmation,
cross-process retry equivalence, sustained TPS, WAN behavior, deterministic
parallel execution, new persistence batching or total retained-history bounds.
The repository's business and release HOLD remains.
