# Release PQ V1 signing bytes and V0 bridge locator

These two HIA entries implement the exact message preparation and
signature-set locator from the
[original V1 release owner](../../../trillionnium/crates/trnm-release-bundle/src/pq_release.rs).
Neither one verifies a signature, selects a trusted public key, advances
a checkpoint, publishes, signs, or admits a release.

## Exact V1 metadata signing bytes

[`pq_signing_message.hepta`](pq_signing_message.hepta) has the pinned
private `f0(input, output, scratch)` ABI. Caller regions must be live and
disjoint. Input is exactly 155 bytes:

| Offset | Field |
| ---: | --- |
| 0 | Role u8 (1 NodeSoftware, 2 ProtocolConfiguration, 3 CellManifest, 4 CellActivation) |
| 1 | Network ID, 32 bytes |
| 33, 41, 49 | Root generation, role version, expiry, each a little-endian u64 |
| 57 | Expected full prior owner checkpoint, 32 bytes |
| 89 | Previous-content present Boolean |
| 90 | 32-byte previous content, zero-filled if absent |
| 122 | Content digest, 32 bytes |
| 154 | Explicit rollback-approval Boolean |

Output is exactly 184 bytes: the 29-byte domain
`TRNM/Release/PQ/ML-DSA-65/v1\0` (literal NUL at the end), followed by the
same field order, with the three u64s written big endian. This is the
message itself, not a digest, prehash, raw message representative or
FIPS context. Present all-zero previous content retains the presence bit;
it does not alias absent. Invalid role/Boolean/extent or nonzero payload
for an absent option yields framing code `100`. Short capacity yields
`102`; success yields `0` with output suffix untouched. All other
buffers are unchanged. No policy validation is implied by raw metadata
encoding.

## V1 signature-set digest for V0's locator

[`pq_signature_set.hepta`](pq_signature_set.hepta) uses the same separate
ABI. Input starts with u16 LE row count, followed by exactly that many
4,130-byte slots: 32-byte key ID, u16 LE signature size, then a fixed
4,096-byte signature slot. Only declared bytes are considered. Slot
padding is ignored, and the private shape represents 0–32 entries.

As in the original, a typed roster with zero or more than 16 entries
gives `105` (`InsufficientSignatures`). Within that bound, stable
bytewise ordering by key ID preserves the original tie order. For each
selected row a duplicate key is detected before checking that row's
signature length. A wrong length on an earlier sorted row is reported
before any later duplicate. Codes `106` and `107` map to the original
length `SignatureRejected` and `DuplicateSigner` errors. The admitted
actual size of each signature is exactly 3,309 bytes.

After that full precheck, SHA-256 hashes the raw 32-byte domain
`TRNM/Release/PQ/SignatureSet/v1\0` followed by each sorted pair
`key_id || signature`, without count or length fields. Output capacity
is at least 32 and scratch at least 1,240. Malformed private shape
(`100`), precheck errors and short capacity (`102`) leave all buffers
unchanged; `103` is an internal refusal that never publishes a digest.
Alignment-independent copies publish only the digest on `0`.

A correctly sized dummy signature can have a valid locator, so the
locator never authorizes or proves a mathematical signature. The
[V0 unsigned candidate](UNSIGNED_CANDIDATE.md) remains distinct. The Rust
V0 callback checks content, stable signer identity and this locator;
only then can the real V1 verifier use pinned role keys and verify every
signature over the exact message with Pure ML-DSA-65 and empty context.
Its same-call quorum observation is bound to root, role, message and
signature bytes, and checkpoint/time/current-state checks still run.
That authority and handoff are unchanged.

The differential compiles the exact formatter, signature-set helper,
role types and constants from the original Rust source. GNU coreutils
replaces only the external SHA-256 seam for the locator. Independent
byte fixtures, hashlib, both pinned machine-code emitters, mixed-error
ordering, bounds and canaries are checked. No private keys are used or
generated, and no successful release verification is claimed.

File custody is independent: the
[original content observer](../../../trillionnium/crates/trnm-release-bundle/src/content_v1.rs)
requires a retained Unix descriptor, matching size and zero starting
position, and compares before/after identity metadata. This still does
not prove immutable custody or an atomic snapshot of a writable file.
Neither HIA entry reads files or changes its custody/permissions.

```sh
python3 -B -m unittest -v hia.tests.test_release_pq_signing
```
