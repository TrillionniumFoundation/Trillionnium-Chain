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

These 37 original API annotations are not the whole branch's SARIF results or
a later PR gate. On source `9e705ccf75b7318dcc4bda4815956f58beb10e72`, the
subsequent API SARIF contains 223 results; the aggregate check reports 35 alerts.
The two changed diagnostic sites disappear from that SARIF. The 35 previously
external-review-required alerts retain their source spans/fingerprints there;
this is not an independent false-positive disposition. The source check's
`pull_requests` array is empty, so its PR-specific annotation association remains
unavailable. The exporter v2 preserves source-only annotations with an explicit
null PR verdict instead of inferring an association from summary text or another
Actions check suite. A complete read-only export still cannot clear the gate.
