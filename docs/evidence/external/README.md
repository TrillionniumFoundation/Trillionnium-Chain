# External blocker evidence

This directory defines the only repository-ingestible format for evidence that
cannot be created by a source-code commit alone. Accepted submissions belong in
`docs/evidence/external/submissions/` and use
`trnm-external-evidence-v1`.

The validator is:

```bash
python3 scripts/ci/check_external_evidence_v1.py
python3 scripts/ci/check_external_evidence_v1.py --require-all \
  --source-commit "$(git rev-parse HEAD)" \
  --source-tree "$(git rev-parse HEAD^{tree})"
```

The first command validates all evidence that is present and reports every open
blocker. The second is the release gate and fails unless all six external
blockers have accepted, independently signed, exact-source evidence.

Repository authors cannot satisfy independent review by signing twice. Fixtures,
single-host simulations, local file/HMAC watermarks, SIGKILL-only tests,
shortened or simulated-time soak, self-audits, queued/skipped CI, mutable URLs,
and unsigned summaries are rejected.

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
