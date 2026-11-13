# W2-E: global batched polynomial verification, with late-forgery economics

**Research-only / HOLD_NO_GO.** Candidate child of Chain #387, source parent
'9955b2b144ee38729f60a2f28c5be04725c53c38'. This is not a new W1
protocol, signed V3 Cookie, SNARK, STARK, VerifiedWork or public activation.
No W1 wire/target/chainwork/Genesis/reorg/finality/Final-use change.

## Why another experiment after W2-D failed availability

W2-D's two-round per-tile Freivalds reduces CPU for valid proofs but costs
about 60ms to reject a falsified last tile. A prepared producer can alter its
last tile, regenerate the SHA256 transcript and pass the ordinary W1 ticket
with ~0.1–0.9ms of CPU after one genuinely expensive witness setup. This is
sound **nonacceptance** yet still a cheap-forgery/expensive-**rejection**
counterexample. Four independent fixed-input Freivalds rounds also tended
to erase the W2-D valid-proof CPU saving.

W2-E tests a different verification schedule using the SAME complete
131,072-byte, 512-tile canonical witness and the original exact SHA256
transcript digest. Define D[k,i,j] as the claimed increment at output
coordinate (i,j) for each of eight inner 8-element blocks. The required
per-step equation is

    D[k,i,j] = sum_{s=8k}^{8k+7} A'[i,s] B'[s,j]  mod q.

For each of five independently hashed rounds sample uniformly in
q=4,294,967,291 by rejecting words >=q:
- u[0..64] independent output-row variables;
- v[0..64] independent output-column variables;
- w[0..8] independent inner-block variables.

Assert a single batched identity per round:

    sum_{k,i,j} w[k] u[i] D[k,i,j] v[j]
      ==
    sum_{s=0..63} w[floor(s/8)]
       (sum_i u[i] A'[i,s]) (sum_j B'[s,j] v[j])  mod q.

An incorrect cell in ANY of the 512 tile updates yields a distinct
nonzero coefficient of the formal monomial u[i] v[j] w[k]. Hence the
difference polynomial is nonzero with **total degree at most three**,
even when adversarial errors at different tile positions might cancel at
one randomly selected numerical evaluation. The Schwartz–Zippel bound
for a *fixed false witness* is <=3/q per fresh uniform round; five
rounds are <=(3/q)^5, ~1.66e-46 (about 152 fixed-input bits).
A separate u/v scalar identity also checks C=AB without performing
full 64x64 matrix multiplication.

All sampling uses a fresh research-domain Fiat–Shamir statement hash
binding the exact challenge, task, target, complete original 49,188-byte
PNW1 proof and all 131,072 sidecar bytes. The 'left-rows', 'right-cols'
and 'inner-blocks' labels separate variables and round indices.
A sidecar's final digest must match the W1 trace claim byte-for-byte.
The vectors are deterministic once committed. The externally established
header/task/target must still be checked by real consensus; this Python
research function is no authority.

### Vital mathematical and cryptographic limitations

The ~152-bit expression is a **fixed-input statistical bound**, not
152-bit effective blockchain security. An attacker can adaptively generate
many different commitments and force many hash queries. If up to Q distinct
commitments are tried, a random-oracle union-bound approximation is
Q*(3/q)^5. For Q=2^60 this loses 60 bits and would be only about
92 bits, ignoring cryptographic implementation failures. This is not a
rigorous public-network security proof. Changing rounds, polynomial
variables or wire encoding requires an **independently versioned** domain.
There is no trusted setup and also no succinct cryptographic proof.

## Exact tests and bounded cost reproduction

    python3 formal/pon-nakamoto-v1/test_w2e_batched_polynomial.py -v
    python3 formal/pon-nakamoto-v1/test_w2e_matched_costs.py -v
    python3 formal/pon-nakamoto-v1/w2e_matched_costs.py \
       --seeds 1 2 3 4 --cap 128 --out /unique/new/w2e-cost.json

The two new Python test modules passed 7 + 2 cases on 2026-10-26,
including honest dense, sparse and zero matrices, bad first/middle/last
tile with recomputed transcript, counterfeit product, four fake traces,
noncanonical sidecar, incorrect context, a complete bounded report and
all hash misses. Existing W2-D late-fraud tests also passed 4/4 after
parameterizing the same attacker constructor to select either
independent verifier. The exact locally executed Python files have the
same Git blob identities as the remotely committed sources.

One local Python 3.13.5 process-CPU snapshot on one Linux host, not a
native Rust/GPU run, independent operators or a statistically controlled
deployment:

| Material | W1 complete verification | W2-E five-round valid verification |
| --- | ---: | ---: |
| Dense | 113.4ms | 86.0ms |
| Zero | 101.8ms | 82.9ms |
| Sparse | 120.2ms | 83.9ms |

**Invalid-work amplification is STILL present.** After one genuine
full-proof+sidecar setup, a fresh fake last-tile W1 transcript that passes
the original half-probability ticket was generated at the following
marginal search/rejection CPU costs:

| Seed | Ticket tries (misses counted) | False construction | W2-E rejection | Receiver / false producer |
| ---: | ---: | ---: | ---: | ---: |
| 1 | 1 | 0.124ms | 34.2ms | 276x |
| 2 | 1 | 0.127ms | 32.0ms | 251x |
| 3 | 5 | 0.591ms | 30.1ms | 51x |
| 4 | 1 | 0.186ms | 33.4ms | 179x |

The local reject returns BATCHED_TILE_RELATION; no VerifiedWork or
chainwork is created. These ratios compare **marginal** already-prepared
attacker cost against one receiver CPU sample and exclude one-time
proof acquisition, GPU, network, host scheduling, State/Root/M06,
signatures, bytes/retention and actual relay fanout. They are not
a permissionless upper bound or a remotely executed attack.

## Obligations and decision

- P0–P1: original exact W1 rejection and physical Host-bound ingress
  remain responsible for any untrusted validation; no W2 candidate
  may secretly remove that resource isolation.
- P2: true CPU/GPU/hash-target economic prices for false proofs and honest
  clients must be frozen and measured under the original V3 signed Cookie
  and worker budgets, including actual bandwidth for a **180,260-byte**
  combined W1+W2-E certificate versus old 49,188 bytes.
- P3–P4: rotated identities, one-use admission payment, hostile late-tile
  packet flood and A03's three modes × three runs × three honest
  confirmations remain physically unqualified.
- P5: cryptographic soundness under adaptive grinding and actual hardware;
  5-round proof generation/network/validator cost and cheapest producer
  across task structures must be independently reviewed. Fixed-input
  polynomial identity testing **does not fix rejection amplification**.
- P6: independently implemented native byte-accurate verifier,
  adversarial public threat model, external cryptographic review, exact
  versioned activation and explicit fork/rollback semantics are missing.

**Verdict: HOLD_NO_GO.** W2-E modestly improves local valid-check CPU
with a stronger fixed-input randomized check than W2-D, yet still suffers
a large cheap-invalid-producer / expensive-receiver asymmetry. A real PoN
product needs a low-cost invalid-proof admission strategy and/or a
cryptographic argument whose worst-case rejected-input verification cost
is service-affordable, separately from verified valid-work economics.
