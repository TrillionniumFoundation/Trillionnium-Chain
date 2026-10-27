# PN1/PN2 — Lease continuity and DAA adversarial research v1

Status: **SOURCE CANDIDATE / NOT QUALIFIED / NOT ACTIVATED**.
This is a scope-specific implementation note under the existing
[sole development plan](../../TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md),
**not** a replacement roadmap or a new consensus profile. It builds on the
existing [Q4 lease window](../../../protocol/pon-nakamoto-v1/details/QUALIFIED_TASK_LIFECYCLE_V4.md),
[Revision 12 explicit Maintenance](../../../protocol/pon-nakamoto-v1/details/CONTINUITY_V1.md)
and [work-cost/DAA evidence](../../../protocol/pon-nakamoto-v1/details/WORK_COST_DAA_BOUNDARIES.md).

## Frozen unchanged authority

- Native `consensus::retarget`: N=16, target spacing 10 s, MTP11, 120 s
  future deferral, 1/4..4 clamping; existing tested targets and cumulative
  required work are unchanged.
- Q4 QDL2/QWA2/PNX1 codecs, requester/source signatures, per-demand source
  sequence, tag22 atomic renewal and its signed overlap are unchanged.
- Revision 12's genesis-committed public Maintenance source is explicit.
  Invalid/revoked/expired selected tasks do **not** fallback automatically.
  Maintenance grants zero useful-output credit and no external export right.
- Source and requester are **actual independent authorities**, not identities
  produced by this work. Nothing signs, imports task material, authorizes
  Hepta FinalUse or rewinds its local revocation frontier.
- No source integrity or successful local test makes a production-ready node.
  Production and `work_profile_qualified` remain false.

## P0-A: genuine zero-lease native continuation

New `maintenance_reentry_without_lease.rs` starts Revision 12 from its
installed genesis, uses a truly signed tag20 to revoke the sole optional task,
and mines W1 public Maintenance. The following **Maintenance** block carries
a newly signed tag18 OPEN and tag21 source registration for a different model
and input. That new work becomes eligible only from its *next* block. It uses
a separate real W1 producer and both native storage implementations, and
an independent second Node checks the registered transaction's inclusion,
depth, required work and actual state. Both stores perform cold reopen.
The test uses deterministic **public development keys**, not independent
external task owners, real demand or public-network work hardness.

Close P0-A only with the specified real Node exits, correct full-work proof,
no unintended fallback, confirmed receipt and crash recovery on the final
source; keep independent operator/WAN and W1 security explicitly separate.

## P0-B: bounded Q4 lease recovery without automatic signing

Q4 OPEN requires `request.not_before >= containing_height`; tag22 renewal
has its own **distinct** signed overlap rule. The two must not be confused.
The checked reference `renewal_window_eligible` covers only preauthenticated
overlap facts; it cannot authenticate QDL2, QWA2 or a Hepta export grant.

The native `maintenance_slot_retention_v1.rs` test fills all 32 bounded
slots (including the installed slot0), revokes slot0 and lets the unregistered
optional demands expire. It rejects a second OPEN while the original slot is
retained, mines through height103 using only genesis Maintenance, rejects
pre-retirement recycling at height103, then admits a fresh signed requester
OPEN with generation33 at height104 and cold-reopens. It does **not** mint a
source-signed registration or claim the opened demand is eligible work.

Actual production scheduling remains OPEN: old and successor signatures must
be obtained from their OWN owners before the final lease expires; queue
preview does not reserve a height. Implement alerts with an independent
operation/outbox owner, explicit observed branch generation, source material
readback, remaining window, timeout and exact lost-ACK reconciliation. A
reorged on-chain lease state must never roll back local revocation.

Close P0-B only after stale-window, late inclusion, old/final lease loss,
32-slot saturation, available_until barrier, reorg, cold restart and exactly
once effect identities all pass their **native** source-bound tests.

## P0-C: work cost and source security qualification remain OPEN

The original W1 relation and full verification are unchanged.
Existing `pon_maintenance_cost`, `pon_w1_budget_report`,
`pon_rejection_cost`, original complete-cost collectors and material-class
oracles must be reused. No duplicate simulator or successful trace stub.

Freeze before measuring: actual selectable material, generic/structured/
periodic/split-limb/zero/rank-one/sparse producer strategies, reusable
preprocessing over 1/4/16/64 searches, honest and forged attempts, complete
producer CPU+wall+memory+energy when measurable, verifier FULL CPU, raw W1
ticket target, hardware, source byte identities, and attack budgets. A legal
optimized dispatcher may choose kernels, but must charge its own selection and
preprocessing. Compare **one executable complete miner strategy**, including
all misses/exhaustion, not a fictional minimum assembled after seeing samples.
The paid+unpaid hostile network verification campaign must count queued,
Busy, cancelled, rejected and confirmed honest requests using the same budget.

A cheap forged ticket is NOT valid work, and a hash/performance ratio is NOT
proof of computational hardness. External reviewers, GPU/ASIC and independent
operator service remain blockers. Do not activate a network based on this PR.

## P1-A: two independent fixed-point ASERT implementations

- Native Rust `trnm-pon-node/src/daa_research_v1.rs` evaluates only explicit
  `AsertResearchInputV1`. Not one Node call selects it.
- Python `formal/pon-nakamoto-v1/daa_research_v1.py` implements the ASERT
  polynomial independently using arbitrary-precision integers.
- Both use PoN **full 256-bit target bytes**, NOT Bitcoin BCH compact nBits.
  Consequently this is a new rounding/identity contract, not byte-compatible
  with BCH; BCH's deployment safety is not inherited.
- Exponent is `trunc(((parent_time-anchor_parent_time)-n*spacing)*65536/half_life)`;
  integer shift is floor(exponent/65536), fractional part is 0..65535.
  Factor is `65536 + ((195766423245049*x + 971821376*x*x +
  5127*x*x*x + 2^47) >> 48)`. Multiply *before* shifting, right-shift 16,
  clamp to 1..pow_limit, with a bounded 512-bit intermediate.
- Anchor height means the **first** new-rule block; anchor time means the
  timestamp of the anchor block's **parent**. Parent height must be at least
  anchor height. The same explicit type accepts a raw-clock experiment or
  the independently frozen MTP11-clock experiment. Anchor and parent clock
  definitions must match.
- Shared, frozen JSON cases include steady, +half-life, -half-life, negative
  fractional exponent, 80-height raw timestamp attack and MTP11 control.
  The Python oracle also copies the *current* 16-block adjustment arithmetic
  independently rather than modifying the original native function.

Rust uses only local u64/u128/i128 and 8×u64 scratch arithmetic without floats
or a new Cargo dependency. The Python test uses the same frozen outputs but
separate code. Integration tests still need the actual committed Rust binary.

No new consensus revision or activation is selected. P1-C is therefore OPEN.

## P1-B: paired adversarial input matrix, not actual PoN security evidence

`daa_research_v1.py` generates 80 legal timestamp checks under a deliberately
hypothetical, fixed local clock. Every 16th-period last timestamp is high while
the other heights use MTP11+1. The five old-rule interval calculations widen
the target 4× each when pow_limit is not hit. **No 80 W1 proofs were mined.**
Actual cumulative valid work must still select the branch.

`daa_adversarial_campaign_v1.py` adds paired deterministic synthetic arrivals
for the **same SHA-256-derived uniform draws per height**, comparing current
legacy16, raw-time ASERT, and MTP11-ASERT with 2/4/8-hour half-lives.
The five declared scenarios are steady, oscillating effective hashrate, sudden
loss, external lease outage (Maintenance remains available), and a
partition-inspired capacity reduction. Each arm measures 256 simulated block
intervals, gap median/p95/max, target, conditional accumulated required work
and time check outcomes. Exactly 35 arms are expected.

This is not genuine selfish mining, branching, eclipse, remote clock skew or
network healing. Those are **unmodelled**, not assumed to pass. The effective
work-share sensitivity is conditional on hypothetical legal producer advantage.

A full P1-B acceptance needs withheld-block fork simulators, private/visible
tips, attacker income and reward maturity, effective work distributions,
reorg-confirmation risks, clock offsets, packet loss and retained losing
branches, plus actual W1 and native packet replays.

## P1-C & P2: strict staged qualification

P1-C requires a NEW versioned consensus profile and genesis/parameter namespace,
**after** independent review of target rounding, time, work and activation.
Do not select research ASERT via config strings, env vars or a silent runtime
fallback. Validate real full W1 work, block inclusion, cumulative-work choice,
SQLite recovery, deep fork replay, timestamp boundaries and old-profile refusal.
Old Q4 and Rev12 golden bytes and historical data must remain unchanged.

P2 requires independently administered hosts and identities, realistic WAN
propagation, at least 72-hour registered availability and a preregistered
honest-client confirmation-risk threshold, as well as missing source/material,
host shutdown, renewal disagreement, corrupt proofs and attack load.
Same-admin SSH hosts or synthetic arrival draws are not independent acceptance.

## Exact instructions to execute on a clean unchanged checkout

```sh
bash scripts/project-preflight.sh --audit
cd formal/pon-nakamoto-v1
python3 -m unittest -v test_daa_research_v1 test_daa_adversarial_campaign_v1
python3 daa_research_v1.py
python3 daa_adversarial_campaign_v1.py 20261027
cd ../..
cargo test --locked --manifest-path trillionnium/Cargo.toml -p trnm-pon-node --lib daa_research_v1::tests
cargo test --locked --manifest-path trillionnium/Cargo.toml -p trnm-pon-node --test maintenance_reentry_without_lease
cargo test --locked --manifest-path trillionnium/Cargo.toml -p trnm-pon-node --test maintenance_slot_retention_v1 -- --test-threads=1
bash scripts/ci/ci_job.sh protocol-contract
```

Also perform the existing exact-head all-workspace strict Clippy, rustfmt,
negative integrity/registry contracts, target hardware cost comparisons and
source/evidence publication. The above are **commands to run**, not a claim that
they ran in this contribution. A local environment without checkout/Rust/owners
cannot issue the missing signed execution receipts.

## P0–P2 status at source submission

| Work package | Source status | Still required |
|---|---|---|
| P0-A | Existing Rev12 native continuity + new source-level reentry test | Exact-head test execution, recovery and confirmation receipts |
| P0-B | Existing Q4 atomic proof + 32-slot retention source test | Native execution and actual external renewal/outbox operator |
| P0-C | Existing native cost collectors; no W1 protocol change | Lowest legal cost, GPU/ASIC, hostile budget, third verifier |
| P1-A | Python and Rust ASERT research plus shared frozen vectors | Source-bound full test logs and independent differential review |
| P1-B | 80-time hypothesis and 35-arm paired synthetic campaign | True selfish mining, branch partitions, full W1 cost and native replay |
| P1-C | NOT implemented; no node selects research DAA | Explicit new consensus profile and signed qualification |
| P2 | NOT executed | Independent WAN owners, sustained attack and retained acceptance |

Any failure is a real failure and remains a blocker. Nothing here promotes
`runtime_implemented`, `work_profile_qualified`, `production_candidate`,
`public_testnet_ready` or `production_consensus_activation`.
