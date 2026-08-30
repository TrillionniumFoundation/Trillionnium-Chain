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

## Integrity checks

Every submission is checked against the local Git object database. `source_commit`
must name an existing commit object and `source_tree` must be that commit's
exact tree object; a well-shaped but invented pair is rejected. `--require-all`
also checks the tuple supplied by the caller before scanning submissions.

The envelope contains `evidence_digest`, computed as:

```text
SHA-256("trnm.external-evidence.envelope.v1\0" || canonical-json(envelope-without-signatures-and-evidence_digest))
```

Each signature covers the 32 digest bytes with the domain
`trnm.external-evidence.signature.v1\0`. Signatures use raw Ed25519, lowercase
hex encoding, and an explicit `key_id` from
`SIGNER_KEY_REGISTRY_V1.json`; `signer_registry_sha256` binds the exact registry
snapshot into the signed envelope. The registry is an allow-list, not an approval
authority: an entry only proves that the bytes were signed by a registered key;
the independent-operator/reviewer and governance duties remain external.
The checked-in registry is intentionally empty until keys are provisioned and
reviewed, so it cannot accidentally turn a fixture or repository author key
into accepted external evidence.

Each artifact URI must carry the same SHA-256 as its `sha256` field. The
validator accepts a canonical `urn:trnm:artifact:sha256:<digest>`, a
`/sha256/<digest>` path, or one explicit `sha256=<digest>` parameter on an
HTTPS, IPFS, or file URI; a bare or mutable URL is rejected. An optional
`local_path` (repository-relative, with optional `bytes`) is read and hashed
again. Remote URI availability is still an external prerequisite and is never
pretended to be proven by this local check.

JSON duplicate keys and non-finite numbers are rejected before validation.
These checks protect the signed preimage from parser differentials and do not
create any evidence when `submissions/` is empty.

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

The checked-in template remains a rejected example. Do not copy it into
`submissions/`; replace every placeholder, compute the envelope digest, obtain
signatures from two distinct active registry keys, and retain the immutable
artifact bytes/URIs supplied by the external operators.
