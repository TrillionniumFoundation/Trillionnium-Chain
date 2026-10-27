# Conditional PoN confirmation risk under task-source outage — research v1

Status: **research only, never release/security acceptance**. This subordinate
experiment supports the existing PN1/P1-B Work×DAA research. It does not create a
new roadmap, consensus revision, PoW mechanism, accepted model contribution,
signer, native miner, peer, or activation authority. Existing Q4 revision9,
Revision12 Maintenance, W1, legacy 16-block DAA and Node confirmation policy
are **unchanged**.

## Why this research is needed

When every optional Q4 task expires, Revision12 can still allow explicitly
selected genesis Maintenance proofs. However, miner groups may have unequal
fastest *valid* Maintenance producer costs. Nominal CPU/GPU ownership can then
misrepresent the economically effective share of valid tickets, independently
of whether timestamps and chainwork are verified correctly.

Given an assumed nominal fraction q and a legal production speed ratio s,
the conditional share is q_eff = q*s/(1-q+q*s). No measured W1 speedup or
hardware advantage is inferred from a chosen s. The published matrix varies
q over 1/10, 1/4, 3/10, 2/5 and s over 1, 3/2, 3, 8.

The exact rational negative-binomial calculation assumes two independent
constant-rate valid-ticket streams and an infinite biased catch-up random walk:
K is attacker tickets before the z-th honest ticket,
P(K=k)=C(z+k-1,k)*(1-q_eff)^z*q_eff^k.
If K<z, conditional eventual catch-up is
(q_eff/(1-q_eff))^(z-k) when q_eff<1/2; if K>=z, the
attacker has already caught up. This model assumes no network delay, no
selective withholding, constant difficulty and costs, and no admission or
expiry actions changing work streams. It is **not** a worst-case adversarial
common-prefix bound or a bound on real attack profitability.

The existing native confirmation predicate is also reproduced **arithmetically**
only: post-inclusion depth >= declared minimum AND cumulative expected work
delta >= required_work(inclusion_target)*multiplier. Inclusion membership,
real W1 verification, reorganization, timestamps, external-effect authority,
state roots and active-generation evidence are not supplied by this module.

## Reproducible source and regression

- `formal/pon-nakamoto-v1/pon_confirmation_risk_research.py`
- `formal/pon-nakamoto-v1/test_pon_confirmation_risk_research.py`

Run from `formal/pon-nakamoto-v1`:

```sh
python3 -m unittest -v test_pon_confirmation_risk_research.py
python3 pon_confirmation_risk_research.py --output /fresh/absent/campaign.json
```

The campaign has 64 ordered, hash-bound conditional scenarios. It prints
`cases` and `rows_sha256` for the canonical JSON row list. The local
isolated test run on 2026-10-26 passed **12/12** selectors and the campaign
produced `43c42b314c5fbad6e01b692bdb0c3661b4e8ebec04f22bf099030a7b73ef8556`.
These are standalone Python results, **not an exact-head repository run**:
the container has no complete Git checkout, Rust compiler, project cloud,
or independent operator fleet. The exact source blobs and input grid are
retained for later qualification.

The Monte Carlo subroutine has a bounded simulated attempt count, retains
all nonterminating races as `unfinished_censored`, and reports both
realized-hit lower and all-censored-success upper fractions. Its separate
`model_adjusted_estimate` is an analytic conditional continuation under
the **same** fixed-rate model; it is not a real observation or a security
upper bound. The sampler rejects float input, invalid fractional shares,
oversized trials/depth and unreasonable aggregate step budgets.

Examples under these fixed model assumptions at z=6:

| Nominal attacker | Legal speed ratio | Effective share | Eventual catch-up |
| --- | --- | --- | --- |
| 1/10 | 1 | 1/10 | 0.00059141 |
| 1/4 | 1 | 1/4 | 0.06865501 |
| 3/10 | 1 | 3/10 | 0.15644958 |
| 3/10 | 3 | 9/16 | 1 |

The final row is an **illustrative assumed legal speed advantage**, not a
measured W1 exploit. It demonstrates that an honest-rate majority assumption
can fail despite unchanged cumulative-work calculation and signed task rules.

## Strict remaining gates

P0-A/P0-B require original-native no-lease/task-reentry, Q4 32-slot
retention/recovery and independent client confirmation. P0-C requires
independent fastest complete valid W1 production across task/hardware/reuse
horizons, invalid-ticket amplification and honest service under attacker load.
P1-B requires measured partition, timestamp manipulation, nonlinear
cost/adaptive miners and actual W1 native confirmation-risk campaigns.
P1-C requires a separate reviewed genesis-bound DAA rule with real W1,
full native branch/reorg/reopen/client checks. P2 requires 72-hour
independent-operator WAN, real storage/material loss and funded repair.

**Nothing in this research permits issuance of a finality or release token,
main-branch merge, consensus profile activation or declaration that a public
security blocker has closed.**

## Coupled source outage × Maintenance readiness (additional research)

The added `post_outage_effective_share` explicitly models an outage of ALL
external signed task leases and independently assumed fractions of honest and
adversarial miners that are actually capable of choosing the already-committed
genesis Maintenance work. It does not infer readiness from signed demand slots
or silently switch a selected failed lease to Maintenance.

For nominal attacker compute share q, honest Maintenance readiness fraction
h, adversarial readiness fraction a, and legal valid-proof speed advantage s,
the conditional remaining honest capacity is `(1-q)*h`, adversarial capacity
is `q*a*s`, and effective q is their ratio when total capacity is positive.
If both remaining capacities vanish, the result is **None / no live work**,
NOT a zero-risk confirmation or proof that the chain can mine a block.

The distinct six-case deterministic output has digest
`ed892ce43519dc600b8ea468c6b42b1ba85816a9d385a0020df78f304ee3ede6`.
Under purely illustrative q=3/10, h=1/4, a=1, s=1, q_effective becomes 12/19:
the model predicts adversarial effective work majority despite the same
signed-task and cumulative-work rules. When both h and a are zero, the
conditional catch-up probability is null because no work source is operated.
A separate no-capacity outcome is not a double-spend attack probability.

Four new negative/positive tests check exact fractions, wrong types/ranges,
remaining live-work classification and unchanged 64 original scenarios.
The combined isolated Python suite on these source blobs passes 27/27
(16 new confirmation/outage tests plus 11 pre-existing mounted DAA/Lease
research tests). Current exact native Rust, operator-controlled networking,
real W1 proof cost and hardware liveness have **not** been executed here.

This strengthens the P0-C/P1-B threat matrix. It does not close the
P0-A original host integration, P0-B physical retention/lease renewal,
P0-C W1 cost qualification, P1-C versioned new-DAA core, or P2 WAN trials.
