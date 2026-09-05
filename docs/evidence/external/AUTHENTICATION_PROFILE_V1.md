# External evidence authentication profile v1

Status: candidate M17 implementation contract; independent acceptance pending.
This is an offline authentication component, not a development plan or release
authorization. Sequencing remains in the [canonical Plan v2](../../development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md).

## Authority and inputs

`authenticate_external_evidence_v1.py` verifies actual Ed25519 signatures and
content-addressed local artifact bytes. It consumes a v1 declaration, an
**independently obtained expected SHA-256 of a trusted enrollment policy**, that
policy's exact bytes, a local artifact directory, an expected source commit and
tree, and an explicit verification time. A hash copied from an untrusted
submission's companion policy is not a trust anchor. No production keys, default
trust policy, enrollment approval or acceptance override ships in this repository.

The caller is responsible for approved policy enrollment, current revocation
information, verification time, exact-source selection, trusted Python/OpenSSL,
and an isolated execution environment. Root policy enrollment, key generation
assurance, actual operator independence and signature creation time are not
established by the signatures themselves. The tool does not verify the remote
Git commit/tree relation: its expected pair must come from the source verifier.

Only immutable public inputs enter this component. It has no private-key input,
network fetch, subprocess shell, signing, chain state, HSM control or activation
capability. Outputs authenticate the supplied envelope and the bytes observed at
verification time. They do not establish that a campaign happened, an audit was
adequate, a URI will remain available, or a governance ceremony authorized release.

## Trusted enrollment policy

The JSON object has exactly these keys:

- `schema`: `trnm-external-evidence-trust-v1`;
- `valid_from`, `valid_until`: inclusive UTC whole-second timestamps;
- `keys`: 2 through 128 enrollment objects.

Each enrollment has exactly `signer`, `public_key_hex`, `role`,
`independence_domain`, `blocker_ids`, `valid_from`, `valid_until`, and `revoked`.
Signer and independence-domain IDs use ASCII `[A-Za-z0-9][A-Za-z0-9_.@-]{0,127}`.
Public keys are 32 bytes of lowercase hex. Signer IDs and public keys are unique
across the entire policy. `role` is exactly `producer` or `reviewer`;
`blocker_ids` is a nonempty unique subset of the six canonical external blocker
IDs. `revoked` is a JSON boolean. Malformed or reversed intervals reject.

Exactly one enrolled producer and one enrolled reviewer must match the envelope,
with different registered independence domains and distinct keys. Both must
have the appropriate blocker scope, be unrevoked, and have validity covering
the declared evidence end through the trusted verification time. The policy
itself must be valid at verification time. These are checks of trusted enrollment
statements, not a discovery mechanism for hidden common control.

Policy digest is over the exact file bytes, not a reserialization. Any policy
change invalidates old signatures under this profile, even if the keys remain
unchanged. Re-authorization under an approved successor policy must be explicit;
there is no historical-key or revoked-key fallback.

## Canonical signed bytes

The declaration retains the existing `trnm-external-evidence-v1` shape.
Top-level fields are exactly the existing required fields, plus optional string
`notes`. Artifact and signature objects are closed. All body fields, including
claims, source, identities, timestamps, artifacts, result and notes, are signed.
There are exactly two signature entries and no embedded public-key authority.

Remove only top-level `signatures`. Encode the remaining JSON object with
lexicographically sorted keys, no insignificant whitespace, JSON ASCII escapes,
no floating-point values, and no non-finite values. This is the explicitly
specified Python JSON ASCII profile, **not a claim to implement RFC 8785**.
Strings must contain Unicode scalar values, never lone surrogates. Integer
values are bounded to `[-2^63, 2^128-1]`. Claim counters are nonnegative integers,
not booleans. The logical body digest is:

```text
SHA256(
  ASCII("trnm.external-evidence.body.v1") || 0x00 ||
  u64_be(canonical_body_byte_length) || canonical_body_bytes
)
```

Every signature entry uses `algorithm = "ed25519-trnm-evidence-v1"`, 64 signature
bytes as lowercase hex, the common recomputed body digest in `signed_digest`,
and its exact enrolled `signer`. Ordinary Ed25519 signs this message:

```text
ASCII("trnm.external-evidence.signature.v1") || 0x00 ||
policy_sha256_bytes[32] || body_digest_bytes[32] || role_byte ||
u16_be(signer_ascii_length) || signer_ascii_bytes
```

`role_byte` is `0x00` for producer and `0x01` for reviewer. This is ordinary
Ed25519 over a domain-bound message containing a SHA-256 body commitment; it is
not Ed25519ph. A role, signer, policy, body or source substitution must fail.
There is no fallback to opaque digest-string agreement or other algorithms.
OpenSSL receives the Ed25519 SubjectPublicKeyInfo DER prefix
`302a300506032b6570032100` followed by the 32-byte enrolled public key.

## Artifacts and resource bounds

Each signed artifact has a unique `name`, unique 32-byte lowercase SHA-256,
and exact `immutable_uri = "urn:sha256:" + sha256`. Remote URLs are not fetched
or treated as immutable. An operator first supplies the approved content at
`artifact_directory/<sha256>`; the filename is derived only from validated hex.
All named artifacts must exist and hash to their signed digests.

The artifact directory is opened once with a no-follow directory descriptor.
Each child opens relative to that descriptor with no-follow and nonblocking
flags, then must be a regular file. Files are streamed and observed identity,
size, modification/change timestamps and the final content digest are checked.
Root path parents are caller-trusted; this is not a hostile-host sandbox, a
permanent URI guarantee or protection against a kernel-controlled attacker.
Later replacement does not revoke already verified bytes; consumers must retain
content-addressed copies and bind their own later reads.

Limits: 1 MiB each for policy/submission and canonical body, depth 32, 100,000
JSON nodes, strings up to 16,384 code points, 64 artifacts, 64 MiB per artifact,
256 MiB total artifact bytes, and five seconds per OpenSSL verification. All
limits are local tool bounds, not consensus parameters or performance claims.
Missing files, symlinks, special files, observed mutation, overflow, unsupported
platforms or unavailable crypto backends reject without a success report.

## Invocation and output

```bash
python3 scripts/ci/authenticate_external_evidence_v1.py \
  --submission "$SUBMISSION" \
  --trust-policy "$APPROVED_POLICY" \
  --trust-policy-sha256 "$INDEPENDENTLY_TRUSTED_POLICY_SHA256" \
  --artifact-directory "$LOCAL_CONTENT_ADDRESS_DIRECTORY" \
  --source-commit "$EXPECTED_SOURCE_COMMIT" \
  --source-tree "$EXPECTED_SOURCE_TREE" \
  --as-of "$TRUSTED_VERIFICATION_TIME"
```

Exit 0 means this component authenticated the envelope and local content under
the supplied pinned policy. JSON output binds source, body/policy digests,
verification time, signers and artifact byte counts. Exit 2 means rejected or
unavailable and emits no partial success JSON. Temporary verification files are
private and removed on normal completion/error. No report is written over a
submission or policy: output is stdout only.

`accepted` remains empty, `independent_acceptance=not-assessed`, physical claims
remain unverified, and all production/closure flags remain false. A valid
signature by a reviewer is not automatically that reviewer's authorized release
acceptance. The existing `check_external_evidence_v1.py --require-all` still
refuses release, even for these authenticated fixtures. The separate governed
acceptance/invalidation integration, real keys and authentic campaign/artifact
submissions remain open; a success JSON cannot itself serve as an acceptance
capability.

## Tests and retained negatives

```bash
python3 scripts/ci/test_external_evidence_authentication_v1.py
python3 scripts/ci/test_external_evidence_v1.py
```

The authentication suite uses deterministic, explicitly synthetic private seeds
only inside temporary test fixtures. It exercises real OpenSSL signing and
verification, RFC 8032 Ed25519 test vector 2, changed messages, roles, policy
pins, revocation, source, claims and artifacts, typed/closed input validation,
resource bounds, post-hash file mutation, and CLI no-partial-success behavior.
Backend-unavailability/timeout and reduced byte-limit cases are explicitly
injected faults; they are not real hardware experiments. No fixture is enrolled
or stored in the repository submission directory. The existing required
`external-evidence-contract` job runs both suites without relaxed limits,
permissions, runner selection or required check names.

References: RFC 8032 section 7.1; OpenSSL `openssl-pkeyutl(1)` Ed25519 verification
with `-verify -pubin -keyform DER -rawin`. Those specify the primitive; they do
not independently audit this wrapper or establish project release readiness.
