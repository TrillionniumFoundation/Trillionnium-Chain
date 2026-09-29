# E2 — actual twelve-command native execution

Implementation: `trillionnium/crates/trnm-mvcc-fee/src/pon_executor.rs`, in the existing
M06 owner. The M00 wire and M01 strict signatures are reused. No parallel consensus,
learning ledger or database writer is introduced. `execute_reference` remains the
independently coded Python oracle. Both implementations have the same experimental
revision2 context, not independently administered acceptance.

## Fixed ordering and validation

Execute mandatory candidate retirement, due expiry and reward maturity first. Split
canonical transactions into batches at most the configured worker count1/2/4/8. Each
worker reads one immutable snapshot and emits a private patch with exact key observations,
prefix-scan observations, writes, fee and receipt. Prefix observations include absent
keys, preventing phantom insertion from bypassing capacity/deadline checks.

In canonical order, publish a patch only when its observed keys AND prefix sets still
match the current state. Otherwise rerun that transaction exactly once against canonical
preceding state. A speculative error can be caused by a missing preceding nonce/funds,
so it also reruns once; a deterministic error then rejects the whole block. The borrowed
parent is never mutated. Finish fee/subsidy accounting, global conservation and root.

Maximum simultaneous workers=8; each transaction has at most one retry. No endless
optimistic loop. This implementation creates scoped workers for each small batch; a
resident pool is a later optimization requiring the same cancellation and ordering tests.

## Actual read/write and range conflicts

| Tag | Reads | Writes / serialization |
|---|---|---|
| transfer | sender balance/nonce, recipient | both accounts |
| reserve_task | sender, task absence, due/pending task+quota+release scans | sender, task |
| cancel_task | sender and task owner/status | sender, task refund/status |
| record_receipt | sender and provider/task binding | sender, task output/status |
| accept_task | sender, task, provider | both accounts, task |
| contribute | sender, current model, candidate range, artifact absence | sender, contribution, nullifier |
| evaluate | sender, candidate, current model, known evaluators | sender, candidate votes/status |
| publish_release | sender, current model, bundle, each allocation, due/pending scans | sender, bundle/candidates, release, current pointer |
| claim_reward | sender, release root/nullifier/deadline | sender, release claim/remaining |
| reserve_quota | sender, quota absence, due/pending scans | sender, quota |
| consume_quota | provider, quota, consumer signature | provider nonce/balance, quota |
| register_work | sender, work-task absence | sender, work-task admission |

All commands also consume their sender nonce and fee rule. A shared sponsor, provider,
release pointer or range creates real conflicts. Merely varying recipients is not an
independent workload. Global issued/subsidy state is handled once outside parallel patches.

## Real backend entry

`TRNM_NATIVE_EXECUTOR` explicitly selects the bounded native bridge; missing, inaccessible,
failed or timed-out binaries never fall back to Python. Parent/application input is capped
at16MiB for this offline bridge, native execution is30 seconds, and returned root is
recomputed by the caller. This bridge is not a public JSON RPC nor a persistent native
consensus/persistence host. Its smaller transport capacity is explicit backpressure.

## Specific acceptance

`NativeExecutionTests.test_all_twelve_tags_match_for_1_2_4_8_workers` compares complete
maps, receipts and roots, including signed publish/claim/free-use transitions.
`test_independent_senders_commit_without_false_conflicts` requires zero retries for
independent sender/recipient pairs. `test_hot_sender_degrades_to_serial_without_speculation`
requires bounded retries. The three-generation test retains exact payout and duplicate
rejection after old-candidate removal; it does not claim three successful ML generations.

Report execution-only duration separately from process startup, work verification,
block inclusion and confirmation. A local executor speedup is never public-chain TPS.

Before launching a batch, identical fixed sender bytes imply a mandatory shared nonce write. Such a batch executes serially with full validation and no speculation. Metrics report serial_conflict_batches and actual peak_inflight. Distinct senders sharing a recipient remain a real re-execution test; no valid transaction or signature is skipped.

The native bridge checks Network and full Parameters on every request and returns both identities. The caller rejects mismatches even when the transaction list is empty; stale binaries cannot silently supply old empty-block rules.
