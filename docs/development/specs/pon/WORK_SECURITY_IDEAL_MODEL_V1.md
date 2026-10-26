# P0-C / P1-B — idealized effective-work security screen (research only)

This is a subordinate research tool under the [sole Chain development plan](../../TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md). It neither replaces nor qualifies W1, the installed difficulty adjustment, PoN node/chainwork, Q4 or Revision 12 genesis Maintenance. All production-acceptance and activation flags remain **false**.

Executable files: [exact Fraction model](../../../../formal/pon-nakamoto-v1/work_security_math.py), [negative controls](../../../../formal/pon-nakamoto-v1/test_work_security_math.py), and [frozen illustrative report](../../../../formal/pon-nakamoto-v1/work_security_ideal_matrix_v1.json).

## Two distinct adversarial costs

The legitimate cost advantage `s` compares the **complete fastest currently observed legal** producer cost to a baseline on identical task, target, attempts, preparation horizon and hardware. Given nominal budget share `q`, the conditional effective-work fraction is `q*s/(1-q+q*s)`. Only verified valid PoN work counts toward chainwork; false traces and ticket-only hits never enter this formula.

The existing [actual W1 cost evidence](../../../protocol/pon-nakamoto-v1/details/WORK_COST_DAA_BOUNDARIES.md) reports a historically observed forged-candidate receiver-CPU/full-false-producer-CPU ratio of 5.177922–5.644848 on a **particular historical source and envelope**. The separate `verifier_pressure` function computes the resulting theoretical one-receiver CPU demand under matched, linear CPU capacity assumptions. That ratio is not a universal attacker lower bound, a current-node measurement or proof of public fairness.

## Exact idealized confirmation calculation

For effective adversarial fraction `q<1/2`, honest fraction `p=1-q`, and an honest chain that gained `z` blocks, let `K` be the adversary's private blocks found before the `z`th honest block. Assume independent Bernoulli block races, fixed rates, zero propagation delay and no strategically advantageous selfish mining. Then:

`Pr[K=k] = binom(z+k-1,k) * p^z * q^k`.

A deficit of `z-k` eventually closes with probability `(q/p)^(z-k)` in this idealized process. Sum the exact contributions for `k<z` and add `Pr[K>=z]` to calculate catch-up probability. For `q>=1/2`, the ideal infinite-time eventual catch-up probability is 1. Calculations use Python `fractions.Fraction` and bounded `z<=96`; decimal strings are presentation only. No floating-point arithmetic enters the probability.

The example 25% nominal share with a hypothetical 3x legal prover advantage reaches 50% effective work. Under the idealized model no finite confirmation depth guarantees safety. Even a theoretical risk below the proposed 1e-6 screen threshold never sets `production_security_qualified=true`.

## Input and scientific boundaries

The 48-row frozen report uses nominal q={0.10,0.25,0.30}, hypothetical legal s={1,1.5,3,8} and depths={6,12,24,48}. The exact file is deterministic; all 48 rows retain `production_security_qualified=false` and top-level `accepted_security_gate=false`. No task lease is signed, no W1 proof generated, no GPU/ASIC attack measured, no network modeled and no independent operator observed.

Run offline from `formal/pon-nakamoto-v1`:

`python3 -m unittest -v test_work_security_math.py`

To close real P0-C/P1-B, replace *assumed* input cost ratios with independently reviewed lowest-cost complete-producer, fastest honest-verifier and cheapest invalid-proof traces from exact native source, including malicious task choice, all preprocessing, accelerators, upstream proof transport, one full budget, honest head service and real network clocks. Explicitly compare source-outage/Maintenance and lease-backed task classes under equal validation targets. The actual network security model must add propagation, partitions, adaptive difficulty, withhold/ selfish-mining strategies and economic incentives; the idealized probabilities are **not** an upper bound for real reorg risk.
