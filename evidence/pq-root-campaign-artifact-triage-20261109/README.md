# PQ Root continuation — original hosted native campaign failure triage (HOLD)

**Status: HOLD_NO_GO / DENY_ALL.** Evidence-only continuation stacked on [#839](https://github.com/TrillionniumFoundation/Trillionnium-Chain/pull/839), tested/anchored at head `cc4576a5911138d724ab0f397642ea03f6b5943f`. Does not modify original runner, test, CPU/memory/PID limits, workload, resource contract or production authority.

## Full original GitHub artifact readback

| Hosted Actions run | Exact executed source head | Artifact ID | GitHub ZIP SHA-256 | Original result |
| --- | --- | --- | --- | --- |
| [42587477765](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42587477765) | `0d99924005b70b1308bf3e62c53e9300fbb4aac4` | `13659748476` | `06fdbd610d0c96982cf447fdbb30d89b028dfa2013c9a9f890bbaaa76e4962a9` | 0/3 campaigns, 0/9 phases |
| [42645192695](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42645192695) | `cc4576a5911138d724ab0f397642ea03f6b5943f` | `13691406748` | `96f920034ff4be76ec69108e23844f8dc7c1c25ec76df282986f8cc55df0e924` | 0/3 campaigns, 0/9 phases |

Both complete ZIPs were downloaded through the GitHub artifact API. Each has **1,766 archive members**. For each of the six original runs, the entire original `run-N-raw/report.json` was SHA-256 checked against the corresponding `results.json` attempt receipt before extracting any fields; its three embedded phase JSON objects were compared to the separately retained `run-N-raw/{baseline,from-zero,late-product}.json`. Report content was not replaced by a projection. No independently authenticated executor or adversarial WAN is claimed.

Exact original inputs retained in both: **three separate 30-second phases**, `0/24/24` attacker processes, four seed blocks with 1,024 genuine signed transfers, 21 business blocks, receiver/verifier **0.25 CPU and 2 GiB**, controller **4 CPUs**, fixed original policy. The release build succeeded. Host controller readiness and native phase child execution passed in all 18 phases. Local Host readiness is explicitly **not** a business-service PASS.

## Same repeated pattern across 18 original phases

* **Baseline (6 phases):** each 1/2 pressure-window confirmation rounds, 11–12 successful submissions out of 12–13 attempts, final receiver/client states unequal, original criteria false.
* **From-zero (6 phases):** 24/24 attackers ready each time; 1,321–1,350 full rejected work observations and 1,322–1,351 executor refusals per phase; 0/1 pressure-window confirmation round, `PUBLIC_REQUEST_DEADLINE` in all six, unequal final states and criteria false.
* **Late-product (6 phases):** 24/24 attackers ready; 1,210–1,236 full rejected work and 1,211–1,236 executor refusals per phase; 0/1 pressure-window confirmation round, `PUBLIC_REQUEST_DEADLINE` in four of six, unequal final states and criteria false.
* **Original paid-CPU-credit depletion:** not observed in **any** of the 18 phases. End-of-phase paid credit is between 1,988,878,278 and 1,999,968,118 ns. Rejected adversarial work does **not** imply original domain-credit depletion under replenishment and accounting.
* **State convergence:** final receiver/client state unequal in **all** 18 phases. Total original phase passes: **0/18**.

These are observed failed predicates, not a uniquely identified ultimate bottleneck. In particular, successful setup or rejected malicious requests cannot explain the missing 21-business-block/confirmation requirement away. Real CPU throttling, state apply latency, queue/grant delay, debt/refill accounting, import convergence and deadline behavior require same-source, original-resource controlled attribution. Avoid lowering thresholds or increasing phase deadlines. The latest prior [#837 qualification record](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/44330b91eb552fd20ef6f2e69bf5e6f1e8f5c0b0/evidence/pq-root-continuation-v4-20261109/qualification-record.json) remains valid for its own executed source; this comparison does not alter that record.

## Exact acceptance still blocked

Independent real operators/devices/root+anchor+writer+provider custody and recoverable backups; fresh authenticated state surviving owner **and all anchors** co-restore; native M15/FinalUse and real provider payment/API/resource/reorg-liability reconciliation; explicit versioned algorithm migration; entire lifetime key/epoch and offline/shared-oracle query scope; concrete reductions and all eight whole-chain bad-event upper bounds. No actual lifetime cryptographic bound has been established. `actual_lifetime_failure_bound=null`, `composition_coverage_proved=false`, `whole_chain_pq_qualified=false`, `production_activation=false`.

**Evidence boundary:** original uploaded ZIPs, their GitHub artifact IDs, full reports, run receipts, exact executables, and unchanged release test definitions remain the sources of truth. This evidence-only PR does not rerun or repair the campaign. Do not report CLOSED.
