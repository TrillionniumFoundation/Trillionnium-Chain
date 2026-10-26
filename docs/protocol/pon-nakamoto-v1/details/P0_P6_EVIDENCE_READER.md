# P0–P6 fail-closed qualification-evidence reader

Status: **source-only research control; no production activation**.

Executable implementation: `scripts/pon_p0_p6_evidence_gate.py`.
Negative controls: `scripts/ci/test_pon_p0_p6_evidence_gate.py`.
Source parent `db0dad68f0909460e8b1cf0c248d8bab4b59c129`.

This standalone reader handles an external prospective JSON report with
`schema=pon-p0-p6-readiness-evidence-v1`, an exact 40-lowercase-hex
`exact_source.chain_sha`, and explicit evidence records for all P0–P6.
It is deliberately **not** a cryptographic verifier, an independent
attestation, or the real host monitoring system.

P0 requires four full W1 rejections, no VerifiedWork, unchanged state and
chainwork and native byte identity; P1 demands externally reachable path
inventory, one real host CPU owner, non-resettable restart semantics and no
unmetered route; P2 demands real signed Cookie, attacker CPU and GPU,
honest acquisition and complete receiver costs; P3 demands rotated keys,
spent-cookie replay, distinct false traces, wrong StateRoot and mixed honest
traffic. P5 requires sound W2 proof with grinding and hardware accounting;
P6 requires an independent external review and blind verification receipt.

**P4/A03:** Requires exactly **nine** run records (three specified attack
modes times three repetitions). Every run must record 3/3 timely confirmed
honest rounds, retain Busy/timeout requests in the denominator and include
a fixed-format raw receipt hash. Any missing, duplicated or changed run
is rejected. This counts declarations only, not their provenance.

Source-only smoke execution:

    python3 scripts/ci/test_pon_p0_p6_evidence_gate.py

Read an explicitly supplied report with create-only optional output:

    python3 scripts/pon_p0_p6_evidence_gate.py /verified/path/claim.json \
        --out /new/unique/output.json

**Critical:** even if a crafted JSON sets every field true and supplies
nine well-formed fake run claims, the tool always returns
`verdict=HOLD_NO_GO`, `production_activation=false`,
`independent_attestation_verified=false`. A schema checker cannot verify
CPU counters, secured source, physical independent hosting, external
cryptanalysis, work economic hardness or model efficacy. Its phase_pass
fields mean **self-reported coverage only**, not actual acceptance.

P0–P6 authority remains with independent evidence/signer/reviewer
systems and the explicit governed deployment gate. This reader adds no
ability to mint chainwork, override local FinalUse, or waive A03. Original
failures and missing fields cannot become PASS by completing a form.
