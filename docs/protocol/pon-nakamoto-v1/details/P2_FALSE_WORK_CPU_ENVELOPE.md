# P2: W1 false-transcript multi-receiver CPU cost envelope

Status: **read-only research accountant**. Base Chain #335 source
'db0dad68f0909460e8b1cf0c248d8bab4b59c129'.
No change to W1 arithmetic, PNW1, V3 Cookie, proof difficulty, Chainwork, ledger,
M06, deployment, consensus profile, operator grants or production flags.

## Why the one-proof/many-receivers denominator matters

A fabricated false W1 transcript can be searched once and then sent to several
receivers. Every independent receiver may spend a full W1 verification unless
its local replay cache actually contains the exact statement. It would be wrong
to multiply the attacker's original hash-search cost by the number of receiver
requests. Conversely, repeated deliveries of the same proof **within** one
receiver are only counted as separate validation CPU if raw observed calls
actually show CPU spent. The arithmetic does not assume cache misses.

'scripts/pon_w1_flood_cost_envelope.py' reads a caller-supplied, externally
collected JSON file with the exact 'pon-w1-flood-cost-input-v1' schema.
It performs bounded accounting, **not** node execution, independent proof
verification or host/hardware attestation.

Required top level:

    {
      "schema": "pon-w1-flood-cost-input-v1",
      "source": {
        "head": "<40 lower-case hex>",
        "tree": "<40 lower-case hex>",
        "profile": "pon-matmul-transcript-64-v1"
      },
      "cases": [ ... ]
    }

For **this from-zero false-transcript profile**, every case also carries
header_hex (the exact canonical 318-byte PNH1 wire), a_hex and b_hex
(each exactly 16,384 canonical field bytes encoded in lowercase hex).
The reader independently parses fixed Header offsets, extracts target and
work_task, validates canonical Fq words, rederives TaskId and
challenge = H("challenge", header). It recomputes for every nonce the
precise fake trace H("public-v3-from-zero-v1", challenge, LE64(nonce))
and resulting W1 ticket H("ticket", challenge, trace), checking the
caller-provided ticket_hit on **every** attempt against the exact Header
target. Finally it constructs the canonical fake PNW1 with zero claimed C
and the winning fake trace and verifies its exact SHA256 against
proof_sha256. This prevents accidentally pairing another Header, a
different task/target, missing ticket misses or unrelated proof bytes.

It does **not** verify that the reconstructed trace is invalid by an
independent W1 relation replay, nor that the caller really spent the
reported measured CPU, nor that the destination node actually received
the claimed bytes. The special from-zero forged-C-zero material is
research-scoped, not a generic interface for all attack variants.

Each unique cases[] item binds one **SHA256 exact proof** by proof_sha256
(64 canonical lowercase hexadecimal characters), an inclusive
complete_attacker_cpu_ns, attempted_trials, the complete bounded trials[]
from zero to winning nonce and an array receivers[]. Each trial has
nonce, ticket_hit and measured cpu_ns; all failed trials before the one
winning ticket are compulsory. All positive/failed attempt CPU intervals are
nested within the inclusive total, never added to it.

Each receiver row has globally unique call_sha256, source-claimed
node_claim_sha256 (not a verifiable independent operator), outcome in
TRANSCRIPT/PRODUCT/TARGET/BUSY/CANCELLED/UNKNOWN,
whole_receiver_cpu_ns or null, and chainwork_granted=false.
The whole receiver CPU interval includes replay when it occurred; adding W1
subphase CPU again would double-charge it. BUSY, CANCELLED and UNKNOWN do
not constitute invalidity of the mathematical relation.

The reader refuses duplicate JSON keys, nonfinite/float input, excessive
bytes/cases/calls, duplicate proof digests, duplicate call IDs, nonce gaps,
multiple claimed target hits, premature target wins, missing trial count,
negative/boolean/noninteger CPU and truncated inclusive cost. Missing any
true CPU clock or a zero attacker full-CPU total yields UNKNOWN; no zero
substitution or unsupported speedup. It emits exact rational CPU ratios
plus a 6-decimal display approximation and preserves denominator metadata.

Run on one actual measured, source-pinned input:

    python3 scripts/pon_w1_flood_cost_envelope.py \
      --input /unique/actual/collected-w1.json \
      --out /unique/new/envelope.json

Output uses exclusive create: prior negative raw evidence is not overwritten.
Tests (synthetic counterexamples only) are:

    python3 scripts/ci/test_pon_w1_flood_cost_envelope.py -v

## Interpretation boundary

- CPU_ONLY_OBSERVATION means **only** that all declared CPU observations are
  present and arithmetic is internally consistent. It does not establish
  actual hardware/custody, process tree exclusivity, GPU/ASIC asymmetry, packet
  identities, W1 validity, model benefit or honest public service fairness.
- UNKNOWN means absent or nonpositive producer CPU or missing real CPU
  samples. In all circumstances public_fairness_or_security_verdict is
  UNKNOWN, p0_to_p6_closed=false and production_activation=false.
- An apparent amplifier ratio is not a lower bound on globally cheapest
  attacker cost. Different CPU microarchitectures, CPU quotas, sampling
  scopes, batched proof construction, total networking costs and higher-rate
  hash algorithms can change the economics dramatically.
- Supply the **original** signed native campaign report, source commit/tree,
  host/kernel cgroup readback, per-actor clocks, all hash attempts, packet
  hashes, full receiver CPU and honest Busy/failed request denominators for
  actual P2/P3/A03 qualification. This bounded reader does not replace
  existing 'read_original_native_campaign.py' or project A03 independent
  physical evidence.

Remaining blockers: the exact original producer hardness; price-valid
receiver-bound tickets in V3 measured on actual CPU/GPU/ASIC; unknown/censored
requests and service fairness; full original P4 A03 3×3×3 on changed source;
W2-A sampled-fraud counterexample, W2-B non-succinct full replay, W2-C
unmeasured attacker economics; independent P6 cryptographic acceptance.
SHADOW_ONLY / HOLD_NO_GO.
