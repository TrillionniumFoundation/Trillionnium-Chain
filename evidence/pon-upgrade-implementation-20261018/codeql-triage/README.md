# CodeQL source triage

This is a new source review of the exported findings for PR #323 source
`e467124838cc8342cedaa4b2c61096dbd7eb1247`. It is not a fresh CodeQL
scan, independent audit, gate pass or runtime qualification. Historical manifests
and raw scan evidence are unchanged.

`analysis.json` binds the original artifact, source bytes, SARIF rules, spans and
data flows. Two actual diagnostics stop formatting native Result/receipt or scan
result payloads. All original state and accounting predicates remain. The other
findings retain `external_review_required`: collection mutation spans are not
rewritten to evade sink modeling; aggregate public experiment metrics remain
visible; deterministic operation-identity and challenge fixtures keep their
original semantic names, values and signed bytes. No finding is dismissed or
suppressed, and no query or security gate changes. Only a fresh unchanged-config
scan and the designated reviewer can establish the next security disposition.
