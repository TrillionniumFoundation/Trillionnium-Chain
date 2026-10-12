# Native evaluation confirmed-round observation v2

`Node::evaluation_round_observation(candidate, observed_now, max_round_blocks)`
returns the private-constructed `EvaluationRoundObservation`. It supports a retained
native evaluation round on an admitted chain whose total height exceeds4096. The v1
observation and `evaluation-observe` command retain their complete genesis-prefix
semantics and bounds. No v1 result is silently reinterpreted as this v2 result.

## Explicit local round scope

The schema is `native-evaluation-confirmed-round-observation-v2`. Its confirmation
policy is `installed-depth-and-required-work/continuous-confirmed-round-prefix`.
The frozen candidate plan determines `round_start`; a caller supplies neither a
phase height nor a round-start override. For a positive round start, the base anchor
is the actual block at `round_start - 1`; for the first round it is genesis. That
predecessor is an unassessed boundary, with `clock_checked=false`,
`confirmation_evaluated=false` and `confirmed=false`.

The complete path from that base to the current active tip must fit the explicit
`max_round_blocks` bound, required in1..4096. The method traverses actual parent
records, checks every window header/id/context and fresh clock bound, consecutive
heights, and cumulative work against each actual target. It cross-checks the first
window block against the existing bounded, sealed derived ancestry-index lookup.
The actual sequential path remains necessary; the index does not become work,
state or confirmation authority. A retained older round that exceeds the requested
window is refused, with no truncated successful frontier.

Each assessed block must satisfy the installed confirmation depth and the installed
target-dependent required-work multiplier using the actual observed tip's work.
The confirmed round prefix starts with the first checked block and stops at the
first failure. It is absent when that first block is unconfirmed. A candidate's
confirmed phase is absent until its actual submission anchor is individually
confirmed and lies inside that consecutive round prefix. Admitted phase remains
separate. A later qualifying block cannot skip an earlier unconfirmed round block.

`global_confirmed_prefix=false` and `global_clock_history_checked=false` are always
explicit. Earlier rounds have not been freshly clock-audited or declared confirmed.
This local result must not replace a policy that requires complete genesis ancestry.

## State, membership and freshness

The existing native owner supplies root-checked active State, active tip and generation.
The candidate comes from its actual active contribution or retained native archive.
The method binds the plan to installed context, family, task/model contract, deadlines,
artifact, components and parent, and recomputes the existing frozen-round digest.
It checks the submission packet's transaction root and exact candidate tag6 membership.

Historical submission and closure States are reconstructed in memory from that actual
active State using the checked window's actual inverse deltas. Every undo requires
the current canonical value to equal the stored `after`; every resulting parent State
must match its committed root through the existing full actual-State commitment owner.
This avoids an unbounded search for historical snapshots. The reconstructed submission
must contain the same frozen plan and round. An actual closure ancestor must contain
the same immutable closed result. No native KV snapshot is accepted as a supplied
historical expectation, and no new M06 execution or proof replay is claimed.

The method checks the same tip and generation again before returning.
`check_evaluation_round_observation(prior, observed_now, max_round_blocks)` refuses a
different namespace/tip/generation, then reconstructs the current result with the fresh
clock. Extension and reorg require a new observation. `observed_now` is trusted local
caller input, not an independently authenticated time certificate.

Native archive retention still applies. Native deadlines, admitted-height execution,
tags14–17, adoption, reward claims, signed domains, database schema and chainwork are
unchanged. All finality, adoption/reward/execution authority, objective quality,
independent governance and public-readiness flags are false. This is an unsigned local
observation under the native local storage-integrity trust scope; it does not resist an
owner rewriting an entire database consistently or certify independent public custody.

## Executable local query and bounded regression

```text
trnm-pon-node evaluation-round-observe --development --store OWNED_CLOSED_STORE \
  --evaluation-policy native-public-evaluation-dev-v1 --candidate CANONICAL_HEX32 \
  --round-blocks 4096
```

Use the store's original context options. Canonical candidate hash and bound validate
before normal `Node::open`. Existing `--logical-now` is an explicit trusted local
test clock; the default is `ingress::now()`. No bare height, peer, authentication,
pool or mining options are accepted. Invalid, unknown, historical-profile,
clock-deferred and exceeded-window results preserve exit2. Normal exclusive Node
open/recovery may write checkpoints or recovery metadata; this is not an OS read-only
opener and cannot create a second owner over an active store.

Dedicated ordinary regressions compare the first round with v1, reject a candidate
beyond a round-prefix gap, and reject corrupt actual inverse deltas, committed roots
and derived ancestry seals. The explicit ignored long-chain campaign uses real PNW1
make/admit/activation for more than4097 blocks, actual signed candidate/commit/reveal,
mandatory positive and missing-reveal closure, actual native confirmation, retained
archive/restart/CLI equality and a heavier fork invalidating the observation.
Its timestamps are finite logical parent timestamps, not a live ten-second cadence or
WAN performance measurement. Software iteration bounds do not preempt SQLite,
state encoding or native execution and do not imply a wall-time SLA.
