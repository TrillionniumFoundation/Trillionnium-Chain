# External blocker evidence

This directory defines the repository intake format for external evidence
**declarations**. Submissions belong in `docs/evidence/external/submissions/`
and use `trnm-external-evidence-v1`. The source-controlled checker currently
validates structure and declared success conditions, not authenticity.

```bash
python3 scripts/ci/test_external_evidence_v1.py
python3 scripts/ci/check_external_evidence_v1.py
python3 scripts/ci/check_external_evidence_v1.py --require-all \
  --source-commit "<exact audited source commit>" \
  --source-tree "<exact audited source tree>"
```

The first command executes isolated regression fixtures. The second reports
intake declarations without accepting them. The third requires a valid source
identity and remains closed (exit 2): the trusted external-evidence verifier
and independent acceptance path have not been implemented. No local switch,
submission field or release-policy boolean can override their absence.

## Acceptance boundary

`result=accepted` is a submitter's claim. It appears only in
`declared_accepted`; the authoritative `accepted` map stays empty, all six
`open_blockers` remain open and both production flags stay false.
`verification_scope=structural-declarations-only`, `authenticity_verified=false`
and `independent_acceptance=not-assessed` are explicit report facts. A successful
ordinary exit means intake validation succeeded, not release qualification.

The optional offline authentication component is specified in [`AUTHENTICATION_PROFILE_V1.md`](AUTHENTICATION_PROFILE_V1.md). It verifies pinned-role Ed25519 signatures and content-addressed local artifact bytes, while remaining non-authoritative for independent acceptance or release.

The present format checks the shape of signature strings, matching declared
digests, producer/reviewer names and artifact references. It does not recompute
the signed envelope, authenticate keys against a trusted role registry, fetch
and hash artifact bytes, establish reviewer independence or observe a physical
campaign. Even cryptographically valid signatures alone would not establish
all those facts. Structurally plausible fabricated or mutable references may
be reported as declarations, but can never close a blocker through this checker.

A future acceptance implementation requires a reviewed canonical signed-body
profile, trusted signer enrollment/revocation and role separation, exact-source
binding, authenticated artifact content, applicable independent review and
invalidation handling. Authoring this contract or test fixtures does not
implement or provision that authority. This is a stable M17 technical boundary,
not another roadmap; development order remains in the canonical Plan v2.

Rejected campaigns and audits retain common identity/signature-declaration
structure and a rejected result, without being forced to satisfy successful
campaign thresholds. They never become acceptance. Duplicate JSON members,
non-finite JSON literals and invalid UTF-8 are rejected before report creation.
The source pair is validated in release mode even when intake is empty.

## Regression scope

The retained suite copies the exact checker into temporary directories and
runs its real CLI. Six fabricated declarations previously made `--require-all`
exit zero; the regression requires exit two and zero accepted evidence. Other
controls cover individual blockers, plausible signature shape, changed claims
and artifacts, policy-flag injection, output files, missing/stale source
bindings, duplicate identities and JSON members, malformed input, failed audit
retention and continued rejection of declared successes with open findings.
No fixture is installed under the actual submission directory. These tests
verify the intake boundary; they are not external evidence or a crypto audit.

Blocker-specific claims:

- `EXT-REVIEW-001`: exact package/interface digest, independent replay counts,
  reviewer independence, and downstream invalidation.
- `EXT-G1-CAMPAIGN-001`: real node counts 4/7/31/100, multiple physical hosts,
  operators and custody domains, signed traces, partitions, restart, sync and
  epoch/key rotation, with no conflicting finality or double-sign.
- `EXT-ANCHOR-HSM-001`: device-backed non-exportable key, external monotonic
  anchor, rotation/revocation and rollback/cloned-namespace rejection.
- `EXT-POWERLOSS-001`: physical power interruption, controller-cache loss, host
  reboot, independent recovery process and exact root readback.
- `EXT-AUDIT-001`: independent consensus, cryptography and economic audits plus
  red team, with zero open Critical or High findings.
- `EXT-SOAK-ACTIVATION-001`: completed 72-hour chaos, 7-day public-testnet and
  30-day production-candidate wall-clock runs, drills, and an authorized
  governance/activation record.
