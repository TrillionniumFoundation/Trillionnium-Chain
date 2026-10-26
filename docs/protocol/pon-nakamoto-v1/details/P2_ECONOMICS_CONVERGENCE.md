# P2: two independent admission-cost screens combined without authority

Scope: research-only exact-source composite, not W1, V3, consensus, mining,
model evaluation, public security acceptance or a new host policy.

The existing V3 Cookie cost-feasibility model in
'scripts/pon_admission_price_model.py' calculates an honest 95th-percentile
solve-time envelope from declared hashes/second and a speculative attacker
USD/hash estimate. The independent W2-C cost reader in
'formal/pon-nakamoto-v1/w2c_cost_verdict.py' compares actual declared sender
and receiver CPU-time components, optional acceleration bounds, and distinct
receiver count. Their units (USD and CPU nanoseconds) **cannot** be summed or
used as if either were an attested attacker's minimum resource cost.

This integration adds 'scripts/pon_p2_joint_triage.py'. It requires a
single claimed source commit, challenge, task, target and host-receipt digest,
runs both original readers unchanged, refuses contradictory source SHA claims,
then reports all unresolved gates. All generated verdicts are HOLD_NO_GO;
even a modeled feasible bit level and a finite sample with no observed
amplification cannot attest real hardware, source, independent operator,
physical CPU quota, GPU/ASIC upper bound or worst-case forged W1 proof cost.
No caller-supplied independent_operator=true boolean can change that.

Research inputs are JSON with keys 'schema', 'binding', 'v3_model' and
'w2c_cost'. Use schema 'trnm-pon-p2-joint-triage-v1' and the two existing
source schemas. Inputs are limited to 1 MiB; outputs are create-only when a
path is selected, never overwrite original evidence.

Independent regression:

    python3 scripts/ci/test_pon_admission_price_model.py
    python3 formal/pon-nakamoto-v1/test_w2c_cost_verdict.py
    python3 scripts/ci/test_pon_p2_joint_triage.py

The source selected for composition is frozen at Chain PR #421 commit
'dc8df72d82059915bd0c69c81eee298243bcbd68'. P2 source provenance:
PR #400 '83ecbbd361c15fb11df26d2abbc544bbf530bef7'
and PR #394 '7573e3ae83fd6090a1005a29fe716b0402b090ff'.
The composed research files do not assert that their historical tests
ran on the combined exact tree.

Still-open P0–P6: exact four original attack bytes and verified native
replay, unified real CPU owner under interleaved physical load, V3 Cookie
GPU/ASIC truthful price and honest p95, rotated legitimate and hostile
identity coexistence, original A03 three modes x three physical runs x
3/3 real client confirmations, sound efficient W2, external independent
cryptography review and activation governance. No automatic change to
the development profile, Chainwork or production flags is authorized.
