# Revision12 state capacity and explicit maintenance continuity

This is a technical contract under the [sole development plan](../../../development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md).
The installed profile is `consensus-maintenance-continuity-dev-v1`. Its policy is
[continuity-v1.json](../../../../config/pon/continuity-v1.json). Historical profiles,
genesis constructors, signed bytes and fixed vectors keep their original meanings.
There is no in-place migration. A new network label, parameter commitment and genesis
select these rules, including a commitment to the existing V4 optional-task policy.

## Problem and scope

The original global state limit is 65,536 keys. Reward maturity deletes a reward row
and creates its recipient's account when absent; every next block also adds a reward
row. With a distinct reward recipient each height, the legacy genesis with seven rows
has `K(h)=7+h`. At the limit, the next mandatory maturity can exchange one reward for
one account without freeing room for the new reward. An empty block is then rejected.
Transactions cannot delete accounts, and deleting zero balances would lose nonce
protection. A cache fallback does not help: the complete root has the same key limit.

This revision preserves the global limit and introduces an admission invariant.
Optional state growth is rejected before publication; already accepted states retain
room for mandatory execution and existing-account maintenance mining. New-account
capacity is still finite. A persistent state tree with a separately bounded working
set, state-growth economics and an upgrade policy remains a later architectural task.

## State-key potential

For the state after height `h`, let:

- `K` be the actual state key count;
- `U` be the number of distinct absent accounts named by any unspent reward or any
  positive task, quota or release balance;
- `A` be the number of active contribution rows without their corresponding
  evaluation archive, when public evaluation is enabled;
- `R` be the number of immature block rewards, and `M=20` the maturity delay.

The exact reward maturities must be the last `min(h,M)` consecutive generated heights
plus `M`. Duplicates, missing maturity slots and records outside this interval reject.
The admission potential is

```text
P = K + U + A + (M - R) <= 65,536.
```

M06 validates this invariant for the parent at `h-1` and the completed successor at
`h`, before constructing or publishing its root. `STATE_CAPACITY` rejects the complete
candidate without changing the parent, account nonce, execution session or durable
active branch. Native reads, restored snapshots, branch activation and reorganization
publication also validate the selected profile's state contract.

### Why an existing-account empty successor fits

Every new account created by reward maturity or a funded expiry consumes one member
of `U`. Multiple liabilities for the same absent recipient reserve exactly one key.
Zero-amount rewards are included because the historical credit operation still creates
their account. Deleting a matured reward decreases `K`; a new block reward increases
it. Until the reward queue is full, `M-R` already reserves that new reward slot. Once
full, one reward matures before the new reward is inserted. The queue contribution to
`P` therefore stays constant for a miner whose account exists.

Creating an evaluation archive consumes its reservation in `A`. Candidate, archive,
artifact, task, quota, retired-release and integer-model cleanup only remove keys.
Expiry changes remaining funds and status within existing records; the only new key
it can require is the recipient account already counted in `U`. Optional lifecycle
output consumption updates an existing bounded slot record. Maintenance grants zero
useful-output credit and creates no extra output record.

Thus mandatory transitions followed by an existing-account maintenance reward cannot
increase `P` on a reachable, schema-valid accepted state. Each optional transaction's
result must still pass the completed-state invariant. The original per-key/value,
integer, signature, task, model, funds and proof checks remain in force; this argument
is about key capacity and does not replace those checks.

## Explicit genesis maintenance

The profile adds one immutable `consensus-maintenance-v1` state record. It binds the
network, parameters, exact policy, source classification, matrix task and both material
hashes. The source is the installed genesis policy's public deterministic fixture.
There is no invented requester, source signature, infinite lease or real-user demand.
Every node can reconstruct the committed bytes without an external signer:

```text
A[i] = (13*i + 17) mod 257
B[i] = (29*i + 31) mod 263
i = 0,...,4095; row-major 64 x 64; each field element is little-endian u32.
```

This material identity differs from the historical development bootstrap. The existing
full transcript relation and ticket predicate are still required for every accepted
block. Availability does not establish a costly attempt, an optimal computation,
PoW-equivalent security, useful model work, or production eligibility. Prepared or
structured-input attacks against the underlying experimental work primitive remain
the subject of its independent qualification program.

Maintenance selection is explicit:

- Native callers use `Node::make_consensus_maintenance` or supply the exact committed
  maintenance materials to the registered-material mining path.
- CLI callers pass `--consensus-maintenance` with the new task profile. It is mutually
  exclusive with `--task-bootstrap` and task manifest/material file options.
- An expired, revoked, unknown or malformed selected leased task remains rejected.
  No failed task causes a switch to maintenance, legacy work, random work or a hash-only
  predicate. Ordinary signed open/register/revoke/atomic-renew commands retain V4 rules.
- Leased registration of the reserved maintenance matrix identity is rejected with
  `CONTINUITY_TASK_RESERVED`, preventing an ambiguous task ID from changing the
  meaning of a source withdrawal or revocation.

For a disposable development store, the explicit local command is:

```bash
trnm-pon-node mine --development --store /tmp/trnm-continuity-example \
  --task-profile consensus-maintenance-continuity-dev-v1 \
  --evaluation-policy native-public-evaluation-dev-v1 \
  --genesis-time 1 --logical-now 1000 --timestamp 11 --consensus-maintenance \
  --output /tmp/trnm-continuity-example-1.packet
```

`mine-loop` and `serve --mine` accept the same explicit maintenance selection. Existing
pool, peer, actor and outside-owned-task admission requirements continue to apply.

## Verification and evidence boundaries

The focused native M06 tests are in
[continuity_v1.rs](../../../../trillionnium/crates/trnm-mvcc-fee/tests/continuity_v1.rs).
They exercise actual empty execution across reward maturation, distinct recipient
reservations, nonce preservation, expiry-recipient deduplication, archive reservations,
the fresh parameter context and malformed maturity/maintenance rejection.
Actual M06 boundary regressions also process twenty funded expiries in the configured
16-plus-4 batches at full potential, and close a valid frozen public evaluation into
its archive at full potential before checking retention cleanup. Absent expiry owners
are explicitly seeded robustness fixtures: current transaction-created funding owners
already have retained accounts. The retention fixture rebases the pending reward queue
and does not claim to have mined the intervening heights.

The native SQLite/proof tests are in
[continuity_tests.rs](../../../../trillionnium/crates/trnm-pon-node/src/continuity_tests.rs).
The capacity fixture explicitly creates a separate test genesis with dormant accounts
and exactly 20 reserved reward slots. Twenty real native packets fill the actual
65,536-key boundary. New recipient growth must reject atomically, an existing-account
signed transfer and next block must succeed, and close/reopen must preserve the active
state and nonces. This is a full native boundary fixture, not a claim that 65,000 account
creation transactions were mined from the installed default genesis. Separate tests
revoke every optional task, check that its selected materials still reject, explicitly
mine maintenance, reopen SQLite, and reject corrupted maintenance even when its state
root has been recomputed.

The separate `actual_capacity_reclaimed_after_refund_admits_new_account_and_reorganizes`
regression starts with one optional slot beyond the same20 reserved rewards. A real
signed quota occupies that slot at height1. At heights21 and22 a signed transfer to
an absent account must reject with `STATE_CAPACITY`, retaining the full active state
and its sender nonce; the height22 failed candidate also rolls back its tentative
mandatory refund. An accepted empty height22 refunds the quota but keeps the expired
row. At height23 the ordinary mandatory cleanup removes that row before the same
signed transfer admits its new recipient. Two actually heavier competing branches
then remove and restore the recipient through ordinary reorganization. Three cold
reopens check exact state and nonces. The fixture uses27 accepted native packets and
two rejected growth attempts; its preallocated genesis is explicit. It establishes
entry after a legitimate cleanup, not unlimited account growth when permanent
accounts alone consume all capacity.

The independent Python oracle and actual native comparison are
[continuity_oracle.py](../../../../formal/pon-nakamoto-v1/continuity_oracle.py) and
[test_continuity.py](../../../../formal/pon-nakamoto-v1/test_continuity.py). The
[native vector example](../../../../trillionnium/crates/trnm-mvcc-fee/examples/continuity_vectors.rs)
emits the actual context, materials and 24 native transition roots. Missing native
execution is a test failure, not a skipped success.

The separate [transition oracle](../../../../formal/pon-nakamoto-v1/continuity_transition_oracle.py)
and [comparison](../../../../formal/pon-nakamoto-v1/test_continuity_transitions.py)
own both small input fixtures and expected complete states, canonical roots, raw
receipts and capacity obligations. The bounded
[native bridge](../../../../trillionnium/crates/trnm-mvcc-fee/examples/continuity_transition_vectors.rs)
only executes the supplied M06 transitions and returns actual observations. Six
fixtures cover eleven successful transitions and one rejected malformed reward
queue: funded16-plus-4 expiry, cleanup before refund, strict deadlines, overlapping
recipients, zero rewards, public archive closure, age256/257 retention, orphan record
cleanup and old-round candidate cleanup. These seeded application states do not
claim signed reachability or replace the full-capacity Node regression. The original
24-vector schema and default context keep their meaning; public fixtures use the
actual evaluation-storage namespace. Missing native output or any mismatched full
row fails the comparison.

```bash
cargo test --locked -p trnm-mvcc-fee --test continuity_v1
cargo test --locked -p trnm-pon-node --lib continuity_tests -- --test-threads=1
cargo test --locked -p trnm-pon-node --test continuity_cli
cargo build --locked -p trnm-mvcc-fee --example continuity_vectors
cargo build --locked -p trnm-mvcc-fee --example continuity_transition_vectors
```

Run the Python test from `formal/pon-nakamoto-v1`, with `TRNM_CONTINUITY_BINARY` naming
that built example. Repository-wide tests, strict Clippy, formatting, source integrity
and Markdown checks remain required on the integrated exact commit.
Run `test_continuity_transitions.py -v` with
`TRNM_CONTINUITY_TRANSITIONS_BINARY` naming the separately built transition example.

### Development observations

The original focused revision workspace passed six M06 tests, four native Node tests, the
actual CLI test, and two independent Python/native tests. The existing V4 integration
suite passed its three ordinary tests; its explicitly ignored release-only 1001-height
campaign was not rerun here. Strict Clippy for all targets of the two changed packages
and formatting passed. These observations concern this bounded implementation and do
not confer work hardness, useful model quality or deployment acceptance.

The first CLI regression run exposed an incorrect test assertion against the established
outer JSON envelope: the command succeeded, while the test read `state` instead of
`result.state`. The assertion was corrected to the actual public contract and reran
successfully; no CLI envelope or existing command behavior was changed to hide it.
