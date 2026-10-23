# W1 local cost and admission security profile

This is the retained 2026-10-18 local observation of the installed W1 primitive
and original receiver CPU budget. It is not a new consensus or resource profile.
W1 bytes, signed domains, required work, fork choice and the production verifier
remain unchanged. The [report interface](W1_SAME_TARGET_BUDGET_REPORT.md) defines
the native measurement boundaries and complete JSONL record schema.

## Exact observation and read-only reproduction

The measured source is commit
`54fae446d956be1e3095537aa02035e310ad03b0`, tree
`4ebc5dd78d6f4727cc5c1c08ec06e4d758dfd69a`. The retained raw directory is
`evidence/pon-upgrade-implementation-20261018/native-rounds/chain-p0-native-54/`.
The four campaign files, host description and complete batch results have these
SHA-256 values; a later source checkout does not change this observation's source:

| File | SHA-256 |
| --- | --- |
| `w1-seed1.jsonl` | `fe49f1e01f45d27d8b1b71ebfeb3052feaebee6f61d7caa895e0cde9dda3836a` |
| `w1-seed2.jsonl` | `57f75a0f511953c9e4e8b14b32b1955d9e31dabf0824a721fbeb6a65eaa7e635` |
| `w1-exhausted.jsonl` | `9d7dc8e9cb7d3401c513e933d5e0db720290f48c54ca0b0651ad42fa1ff50d9c` |
| `w1-receiver-budget.jsonl` | `0f497ed2b74793a244eef7ee8b95c732f8bfc88e7fe7dda41f697f03a2e87600` |
| `hardware.json` | `9492cc47014b2e6909c1610b1421f6ea93808a995636cf62dff1b722636622b9` |
| `results.json` | `28d621cffb88a0c833b1e005b3ba3d0d5542f046aa56b6df525fd6a01eeb35d4` |

All four W1 commands exited zero. The same batch retained failures for
`model-evidence-native`, `unpaid-shared64-native`, `public-services-native` and
`strict-clippy`; this is not an all-pass batch. The host reported x86-64,
Intel Xeon E5-2673 v3 at 2.40 GHz, kernel `7.0.0-38-generic` and a 400% CPU quota.
Other builds on the same host were possible. There was one controlled operator;
independent-operator qualification was false. The first command's 61.556005
seconds included compilation and is not a producer proof-cost denominator.

The [reader](../../../../scripts/pon_w1_budget_reader.py) checks record framing,
public material and digest reconstruction, complete search attempts, unsupported
and exhausted arms, matched verifier outcomes, nested timing and the original
receiver account's transitions and conservation. Unknown CPU measurements remain
unknown. The [derivation tool](../../../../scripts/pon_w1_budget_derive.py) first
runs those checks on every input, then derives complete costs, distinct proof
counts, matched algorithm comparisons and actual refill recovery. Its numeric
cost comparisons require known CPU samples. These readers do not rerun native
verification or authenticate the host's statements. They do not create a service,
change raw input, acquire work, or infer independent operators from keys.

From the repository root, after the original preflight, use a fresh output path:

```sh
W1_RAW=evidence/pon-upgrade-implementation-20261018/native-rounds/chain-p0-native-54
W1_OUT=/tmp/pon-w1-readback-new
mkdir "$W1_OUT"
set -o noclobber
python3 -B scripts/pon_w1_budget_reader.py \
  "$W1_RAW/w1-seed1.jsonl" "$W1_RAW/w1-seed2.jsonl" \
  "$W1_RAW/w1-exhausted.jsonl" "$W1_RAW/w1-receiver-budget.jsonl" \
  > "$W1_OUT/consistency.json"
python3 -B scripts/pon_w1_budget_derive.py --raw-dir "$W1_RAW" \
  --expected-head 54fae446d956be1e3095537aa02035e310ad03b0 \
  --expected-tree 4ebc5dd78d6f4727cc5c1c08ec06e4d758dfd69a \
  > "$W1_OUT/costs-and-recovery.json"
python3 -B scripts/ci/test_pon_w1_budget_readers.py --raw-dir "$W1_RAW"
```

The reader exits 2 for malformed/inconsistent input, 1 for unexpected native
verification outcomes and 0 for internally consistent records. The derivation
also requires the explicitly supplied source head/tree to match `results.json`.
The [counterexample tests](../../../../scripts/ci/test_pon_w1_budget_readers.py)
alter retained rows only in memory and check that missing failed attempts,
unsupported arms, credit resets and misleading denominators are detected. They
do not generate replacement native evidence or create a new CI policy gate.

## Complete offered cohorts and distinct proofs

The two comparison campaigns used target
`7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff`, samples 3,
attempt limit 32, one receiver replay, and seeds 1 and 2 respectively. The
exhaustion campaign used the all-zero target, samples 1, attempt limit 2 and one
replay. The receiver-budget campaign used the all-`ff` target, samples 1, attempt
limit 1 and 1,024 replays. Both latter campaigns used seed 1.

| Campaign | Producer arm cases offered | Hit / unsupported / exhausted | Actual attempts | Receiver requested / started / refused | Verified / relation rejected / cancelled |
| --- | ---: | ---: | ---: | ---: | ---: |
| Seed 1 | 48 | 33 / 15 / 0 | 62 | 33 / 33 / 0 | 21 / 12 / 0 |
| Seed 2 | 48 | 33 / 15 / 0 | 67 | 33 / 33 / 0 | 21 / 12 / 0 |
| Zero target | 16 | 0 / 5 / 11 | 22 | 0 / 0 / 0 | 0 / 0 / 0 |
| Receiver budget | 16 | 11 / 5 / 0 | 11 | 11,264 / 863 / 10,401 | 549 / 314 / 0 |

The all-zero target is the diagnostic's deliberate no-hit boundary, not an
economic-difficulty or sustained capacity experiment. Its 22 failed attempts,
11 exhausted supported arms and 5 unsupported arms are all retained; there is no
winning proof or receiver cost to impute. Each comparison campaign contains 99
raw verifier diagnostics: 63 successful and 36 `Transcript` errors over the
three measured kernels.

Producer full CPU totals, including unsupported setup, were 68.572659 ms,
87.395828 ms, 26.821643 ms and 13.503105 ms in the table's order. Construction of
the shared public material was measured separately at 21.160443 ms, 16.115726 ms,
16.471662 ms and 14.390740 ms. A complete producer denominator includes its setup
and all attempted challenges. Setup/search/trial fields are nested measurements
and must not be added to full total CPU a second time. Public material is neither
silently charged once to every arm nor omitted from the retained observation.

Different legal algorithms can produce the same proof bytes. Each seed's 33
candidate arm cases contain only 24 distinct proof digests: 12 legal and 12
false. Together the seeds contain 48 distinct digests, 24 legal and 24 false.
The budget campaign's 11 candidate arm cases contain 8 distinct digests, 4 legal
and 4 false. Its 549 successful verification calls replay those same 4 legal
proofs. None of these counts is a count of unique confirmed business
transactions, newly admitted blocks, model upgrades, or business TPS.

## Paired structure-dependent producer costs

Every pair below shares its seed, material class, sample, task, target, challenge
stream, actual trial count and exact winning proof. Each row has 6 pairs. Speedup
is the sum of generic full CPU divided by the sum of alternative full CPU; saved
CPU uses the same complete-search denominator.

| Material / alternative | Generic full CPU ms | Alternative full CPU ms | Ratio of sums | Full CPU saved | Slower alternative pairs |
| --- | ---: | ---: | ---: | ---: | ---: |
| Zero / existing structured | 24.422794 | 24.014810 | 1.016988849797271 | 1.6705050208424166% | 1 / 6 |
| Zero / blocked-zero | 24.422794 | 20.713261 | 1.179089762833578 | 15.188815006178247% | 0 / 6 |
| Rank-one / structured | 19.100329 | 16.570420 | 1.1526762146040956 | 13.245368705429106% | 0 / 6 |

The corresponding per-pair speedup minimum/median/maximum values were
0.9519799797 / 1.0764156178 / 1.1338231096, 1.0966088003 / 1.2550904988 /
1.3110644836, and 1.0995791312 / 1.1711476047 / 1.2389312900. These per-pair
statistics use a different aggregation from the ratio-of-sums column.

On zero material the existing structured setup fell from a summed 2,471,761 ns
to 74,060 ns, but the full-search saving was only 1.670505%; one pair was slower.
The blocked-zero setup sum was 77,230 ns. For rank-one the corresponding setup
sums were 2,388,937 ns and 341,414 ns. Setup or operation-count improvements alone
are not full W1 producer speedups. Unsupported dense/sparse arms remain in the
offered cohort.

These are two seeds with three samples per seed and a fixed arm order on one
nonexclusive host. They do not estimate the fastest adversary, establish
statistical confidence, or demonstrate hardware-independent economic hardness.

## False-trace cost and raw verifier comparisons

All 24 false-trace comparison cases were rejected with `Transcript` by every
raw verifier and every completed cooperative verification. Their complete false
producer CPU cost ranged from 0.238378 to 0.448028 ms. Raw production verification
took 1.806293 to 3.075475 ms. The per-case ratio of raw verification CPU to full
false producer CPU ranged from 6.864470524 to 7.897722905.

| Material, 6 cases each | Raw production verify / full false producer CPU, ratio of sums | Cooperative settled CPU / full false producer CPU, ratio of sums |
| --- | ---: | ---: |
| Dense | 7.3295356331 | 9.4950371256 |
| Zero | 7.4219552100 | 10.3390725057 |
| Rank-one | 7.3270713280 | 10.5855223212 |
| Sparse | 7.6143843819 | 11.0448662680 |

Cooperative settled CPU ranged from 2.589319 to 3.179564 ms per false case. The
producer denominator retains its prefix setup and all trials; the shared public
material cost remains separate. Raw verification excludes report serialization,
socket/admission-ticket/signature/packet handling, M06 and SQLite. The budget
campaign also reuses already constructed proof bytes on subsequent requests.
The measured asymmetry is real for these cases, but is neither a full public
network amplification factor nor a lower bound on the cheapest possible attack.

Across the two seeds' 42 legal raw case records, production/limb/scalar-reference
CPU sums were 98.208494 / 88.277873 / 172.678560 ms. Across 24 false records they
were 48.633131 / 44.068985 / 84.142174 ms. Production-to-limb ratios of sums were
1.1124927534 and 1.1035682124; every recorded matched limb timing was lower. This
is a diagnostic comparison of complete primitive kernels in fixed order, with
duplicate proof bytes across some arms. It neither changes the production
kernel nor establishes a service throughput improvement or independent samples.

## Original receiver budget: exhaustion and refill

The diagnostic uses the existing standalone domain: 2,000,000,000 ns initial
credit, refill of 250,000,000 CPU ns per wall second, a 100,000,000 ns **start
reservation**, and the original worker limit of 2. The ordinary CLI instead
uses `new_process_cold`: zero initial CPU credit and zero challenge tokens. A
standalone diagnostic's warm burst is not a CLI restart entitlement.

The first 853 requests started. Request 854, round 77, case
`rank-one/0/generic`, was the first `PUBLIC_MUTATION_CPU_BUDGET` start refusal.
Its credit was 99,832,653 ns before and 99,844,895 ns after actual refill, both
below the 100 ms start reservation. **Eligibility to start was exhausted; the
account did not reach zero.** The minimum retained balance was 96,125,904 ns.

Of 11,264 offered requests, 863 started: 549 verified, 314 were `Transcript`
rejections and none was locally cancelled. The other 10,401 were start refusals.
Ten requests started after nonempty refusal streaks in the same original domain:
ordinals 885, 1,675, 3,201, 4,146, 5,252, 6,361, 7,466, 8,575, 9,539 and 10,489.
They comprised 6 legal and 4 false proofs. The preceding refusal streaks were
31, 789, 1,525, 944, 1,105, 1,108, 1,104, 1,108, 963 and 949 requests. There were
775 trailing refusals. These are actual refill recoveries of start eligibility,
not process restarts, replacement accounts or peer entitlements.

The receiver loop took 2.706193886 wall seconds, including row serialization and
its real elapsed refill opportunities. Recorded credit conserves exactly:

```text
2,000,000,000 initial credit
  + 676,148,935 actually credited refill
  - 2,576,592,196 settled CPU
  = 99,556,739 final credit

2,575,777,367 live debit + 814,829 residual settlement
  = 2,576,592,196 settled CPU
```

Discarded refill was 61,415 ns; settlement discard was zero. Final booked
reservation, live owners and unsettled known live CPU were all zero. Accounting
was available throughout. No cancellation inside an individual proof was
observed, so this experiment cannot certify that separate long-proof behavior.

## Remaining public-admission and economic limits

The [r10 shared intake implementation](PUBLIC_POOL_INTAKE_V3.md) retains 64
original shared slots and marks the oldest eligible unpaid input for cancellation
only under full-pool pressure after at least 250 ms without actual input. The
original reactor closes that socket before returning its original slot. Paid and
server-owed stages are protected. This bounds that finite silent-input case; a
passing run is required to establish the corresponding native assertions.

Slow drip within 250 ms, timely valid Hellos, fresh connection churn, paid-body
delays and host/WAN saturation can still contend for resources. The original
absolute 2-second and 30-second deadlines are not renewed by activity, but those
deadlines alone do not prove honest anonymous fairness under arbitrary floods.
The source54 batch's failed shared64 test remains a failed observation, even if
a subsequent source revision repairs the test's parent construction.

Different self-generated keys, processes, stores, proof algorithms and seeds do
not establish independent operators. These local CPU budgets and measurements
also do not prove PoN economic hardness, unique useful-task demand, training/data
custody, model improvement, or authorization for validators to replace their own
consensus rules. No automatic PoW/BFT fallback or new business authority follows
from this report.
