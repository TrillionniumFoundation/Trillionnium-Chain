# Bounded release PQ quorum shadow candidate

[`pq_quorum.hepta`](pq_quorum.hepta) runs the original V1 release quorum's
mathematics in one emitted HIA call. It uses the exact owned
[strict ML-DSA-65 SPKI key-ID primitive](../crypto/pq_frame.hepta) and
[actual Pure ML-DSA-65 verification kernel](../crypto/ml_dsa.hepta). There
is no provider call, caller-supplied signature result or fallback. The
canonical [V1 transcript](PQ_SIGNING.md) remains unchanged.

## Trust boundary

The caller must supply one independently trusted, immutable authority
snapshot: its provisioned root network and generation, selected role,
that role's threshold and complete sorted public key/SPKI map. It must
not source those bytes from the candidate release. This entry does not
authenticate the root, check the trusted current role against another
snapshot, authenticate a clock, or enforce cross-role and retirement
rules at root provisioning. It does not prove that the supplied root
generation is current.

The entry compares the transcript's own network, generation and role
against the independently supplied snapshot. It reconstructs exact
strict key pins from selected public SPKIs in the same immutable map; a
failed pin cannot become a math result. There is no independent retained
verifier cache, and therefore no stale verifier or externally supplied
cache-valid flag. The original Rust owner's separate cache consistency
check and current authorized state remain unchanged. The result cannot
advance a release, a checkpoint, role state, or content custody. It does
not mint the original V0 callback's same-call quorum token.

## Borrowed contract

The pinned private `f0(input, output, work)` borrows live disjoint
regions. Exact input consists of:

- A 48-byte header: key count, signature count and threshold (u16 LE);
  role (u8 1–4); one reserved zero byte; root network (32 bytes);
  and root generation (u64 LE).
- The exact 184-byte V1 signing transcript, starting at offset 48.
- One 2,006-byte row per trusted key: 32-byte key ID and exactly 1,974
  bytes of strict DER SPKI. The map has 1–16 rows in ascending unique
  unsigned byte order. Threshold is in 1 through key count.
- One 4,130-byte row per supplied signature: 32-byte key ID, u16 LE
  declared extent and 4,096-byte slot. This private shape can express
  0–32 rows so that original counts above 16 can be refused. Only
  exactly 3,309 bytes may ever reach verification. Other declared
  sizes are rejected without reading their claimed content. Slot
  padding never affects verification.

Scope, framing and the bounded trusted-map shape are private checks.
For a typed input, the original signature count is then applied.
Preflight walks supplied signatures in original input order, checking
duplicate ID, trusted role membership, strict pin and then signature
width. No signature equation runs until the complete roster passes.
Successful math checks **every** supplied signature, including those
beyond threshold, over this single exact transcript with empty FIPS
context. Each verification uses freshly cleared private scratch; no
successful equation is reused between calls.

The output region is never written. Code `0` is an observation limited
to quorum mathematics. Codes `105`–`109` follow the original precedence:
insufficient count, rejected signature or wrong width, duplicate
signer, unknown signer, invalid pin. Private framing is `100`, scratch
capacity is `102`, internal refusal is `103`, and an unmatched
snapshot/transcript scope is `110`. The first 32,896 bytes of scratch
are wiped on every return after a preflight or math invocation. Other
refusals do not touch scratch; the suffix is always unchanged.

## Exact original comparison

[`qualify_release_pq_quorum.py`](../../tests/qualify_release_pq_quorum.py)
builds the unmodified locked original Rust release/crypto crates and an
adapter appending the byte-exact, hash-checked original private quorum
functions from [`pq_release.rs`](../../../trillionnium/crates/trnm-release-bundle/src/pq_release.rs).
The original fixture bootstraps an isolated synthetic root and exercises
one original acceptance, returning only public metadata, pins, SPKIs
and signatures. Seeds originate in the test process and are not passed,
printed or stored; core dumps are disabled. The native emitter compares
the same complete quorum to Rust, including valid rosters at the bound,
a valid signer from a different role, an invalid extra signature, and
mixed preflight ordering. All cases are offline and no production or
release-owner state changes.

With pinned compiler environment, pinned Rust on `PATH` and populated
offline Cargo cache:

```sh
python3 -I -S -B hia/tests/qualify_release_pq_quorum.py \
  --output /tmp/new-release-pq-quorum
```
