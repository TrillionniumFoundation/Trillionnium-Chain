# Declared control and research evidence readers

Status: **HOLD**. These readers preserve compatible research components from
the branch consolidation on 2026-11-13. They do not activate a network, change
consensus parameters, authenticate an operator, or grant release authority.
The [development plan](../../../development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md)
and existing native owners remain authoritative.

## Declared control and local material

[`pon_decentralization_audit.py`](../../../../scripts/pon_decentralization_audit.py)
uses the versioned
[declaration policy](../../../../config/pon/decentralization-audit-v1.json).
It computes the transitive closure of declared parent, alias and shared-key
relationships. Unknown control remains unknown. A stale relationship cannot
turn a known related author into an independent evaluator. Quorum reports
retain the full key denominator and distinguish identified keys, declared
control groups, author-related keys, and unresolved slots. Funding and hardware
reports retain their declared units, denominator, evidence window and unknown
share. The result always retains `independent_administration_verified: false`.

[`pon_decentralization_evidence.py`](../../../../scripts/pon_decentralization_evidence.py)
checks the exact bytes of an externally pinned local input and SHA-256-named
local materials. It uses bounded regular-file reads, retained directory
descriptors and before/after identity checks. Missing, changed, expired,
revoked and mismatched materials remain separate gaps. A successful byte
comparison does not authenticate signatures, custody, claim contents,
deployment context or external independence. This reader makes no network
requests and retains `status: HOLD` even when all declared bytes match.

## Explicit WAN V3 and V4 accounting

[`pon_wan_evidence.py`](../../../../scripts/pon_wan_evidence.py) retains the
original V1 and V2 schemas and their original denominators. The explicit V3
schema binds the declared control registry to the campaign's source, binary,
profile, network, genesis, parameters and observation window. Retrieval and
replica accounting consider common control, including aliases of forbidden
origins, without treating unidentified owners as independent.

V4 adds a maximum matching between declared control groups and failure domains
for complete replicas. Separate group and domain counts alone do not establish
the required number of jointly distinct replicas. The ordinary cohort floors,
source restrictions, failed attempts and missing observations remain in the
calculation. These schemas report declared arithmetic only; they do not claim
that the campaign occurred or that its operators are independent. The existing
[WAN evidence contract](WAN_EVIDENCE_ACCOUNTING_V1.md) continues to require
authenticated external observations.

## Retained diagnostic readers

[`pon_p0_p6_evidence_gate.py`](../../../../scripts/pon_p0_p6_evidence_gate.py)
checks the shape of declared P0–P6 evidence and the complete three-mode,
three-run P4 denominator. Even a maximally positive self-declaration returns
`HOLD_NO_GO`, with independent attestation and production activation false.
It does not run an adversarial campaign or authenticate a receipt.

[`pon_admission_price_model.py`](../../../../scripts/pon_admission_price_model.py)
compares declared honest and candidate cost rates under the unchanged
8–20-bit, two-second cookie research profile. A feasible arithmetic row does
not change policy or establish measured hardware performance, independent
security acceptance, or activation. Its synthetic fixtures remain synthetic.

## Provenance and validation boundary

The original components are retained in Git history at
[`058a729a27`](https://github.com/TrillionniumFoundation/Trillionnium-Chain/commit/058a729a27),
[`428d084bce`](https://github.com/TrillionniumFoundation/Trillionnium-Chain/commit/428d084bce)
and [`83ecbbd361`](https://github.com/TrillionniumFoundation/Trillionnium-Chain/commit/83ecbbd361).
Their old observations do not become observations of the consolidated source.
The six reader suites run exactly once at the beginning of the existing
`external-evidence-contract` lane. Its closed command contract also checks
omission, duplication, wrong-lane placement and swallowed failures. Original
WAN controls remain alongside the added V3/V4 controls.
