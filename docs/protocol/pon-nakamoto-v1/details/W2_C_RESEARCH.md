# W2-C separated security work: executable negative/positive study

Status: **research only**. This work does not implement or activate a new
consensus protocol, fork choice, public interface, payment, model reward or
fallback. The existing PNW1 canonical verifier remains the only W1 relation.

## Exact executable scope

'formal/pon-nakamoto-v1/w2c_separated_security_pow.py' and the matching
'test_w2c_separated_security_pow.py' are bounded, independent Python studies.
Their explicit synthetic 318-byte Header and exact PNW1 bytes bind a
domain-separated 'w2c-proposal' commitment. 'w2c-security' binds that
commitment to LE64 nonce. A 256-bit SHA256 value with 8..28 required leading
zero bits is the security gate. The script measures every attempted nonce
up to a declared finite cap; it records actual Python process CPU and wall
time. This is **not** a native signed network admission cost, native Host
CPU owner or independent CPU/GPU comparison.

The observer checks the security ticket BEFORE W1, and if it passes runs
the existing Python W1 task/ticket/formal transcript/product verification.
A fake W1 trace that passes *security* remains invalid. A valid W1
transcript that passes security returns **VALID_W1_RESEARCH_ONLY**,
NEVER VerifiedWork or chainwork. A changed header, task/proof bytes, nonce
or security threshold must be handled under exact specified context.
No result writes Node State, invokes FinalUse or imports historical blocks.

Use from repo root:

    python3 formal/pon-nakamoto-v1/test_w2c_separated_security_pow.py
    python3 formal/pon-nakamoto-v1/w2c_separated_security_pow.py \
      --bits 8 12 --cap 65536 --out /absolute/new-w2c-comparison.json

The --out path is create-only. A capped failure is EXHAUSTED, not a
successful or assumed hit. Missing GPU/ASIC, real network and independent
operator observations remain null/false.

## Important limitation: it is a *different* consensus-economic objective

If security Hashcash is used to decide accumulated work, the W1 neural
arithmetic is a *separate* useful-output/reward observation. One must not
rename Hashcash mining as useful neural computation or add W1 ticket luck to
security chainwork. Full W1 verifier and State/root validation still
must succeed before an admitted block can receive any proposed security
weight. Model payout is a later separately attested non-duplicative
event; a repeated identical model output cannot mint new benefit.

For any new deployment, the anti-DoS cost must be compared separately from
security chainwork and model quality. The provider can share precomputed
SHA256 prefix states when generating many bogus proofs, and a GPU/ASIC may
hash far faster than the honest CPU verifier. Thus 2^bits expected hashes
(conditional on ideal uniform hash assumptions) is **NOT** a universal
cost or a safe default. If bits are too high, honest low-power Hepta peers
may be excluded; if too low, fake-W1 amplification remains.

## W2-A/W2-B/W2-C decision

| Prototype | What can be cheaply refused? | What remains unqualified? |
| --- | --- | --- |
| W2-A Merkle sampling | Sampled intermediate-tile errors | A one-tile unsampled forgery is accepted by the filter; full transcript proof is absent. |
| W2-B complete computation proof | In principle an invalid trace without complete replay | Must design and independently review a sound circuit/proof, range constraints, exact W1 digest/transcript and robust relation to useful-work costs. No code path is claimed valid yet. |
| W2-C separated security PoW | Work submissions with insufficient independent Hashcash before W1 | Cost ratio across hardware, Sybil and sustained honest access; GPU dominance; all actual consensus, governance/reward and migration rules. |

W2-C is the only studied approach above that is straightforward to code as a
low-cost *separate* security puzzle, but this is not evidence that it meets
the original goal that most spent energy is useful neural computation.

**Gate outcome:** P5 is OPEN; no new work profile, target, proof grammar,
genesis, DAA, cumulative-work formula or public listener is activated.
