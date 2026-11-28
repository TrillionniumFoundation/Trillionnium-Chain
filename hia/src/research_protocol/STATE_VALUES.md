# Native Research state values

`state_values.hepta` implements the seven public state-object canonical encoders,
the AppliedCommandRecordV1 encoder, and the ResearchProtocolSnapshotV1 encoder
from the unchanged original `state.rs`. It also computes the original object-leaf
and snapshot hash domains using the existing native SHA-256 implementation.
Every production instruction is compiled from HIA. Original Rust is solely the
independent test oracle; Python transports buffers and observes execution.

## Canonical values and state admission

These original public value encoders do not validate the state graph. They retain
the input vector order, duplicates, zero keys, zero/full-width object versions,
invalid authority identities, unsupported snapshot versions representable by u8,
and all other well-typed values. The native codec preserves this distinction.
State construction/restoration must separately run the original authority,
journal, nonce-floor, object and graph checks. A matching byte encoding or hash
does not admit any state, issue a capability or qualify the state owner.

Match, evaluation, workload, license and resolution objects encode the original
three-element array: version 1, ObjectRefV1, original payload. Claims encode six
elements with current claimants, ClaimStatus and optional active challenge;
challenges encode five with status and optional resolution reference. The immutable
original claim payload remains separate from its current claimant allocation.

Applied records encode the original nine elements: version 1, command id,
fingerprint, primary reference, chain, signer DID, role, nonce and public key.
Snapshots encode ten elements: their actual u8 protocol version, authorities,
seven object vectors and the applied-record vector. The out-of-band state chain
binding is deliberately absent from this original snapshot format.

## Borrowed interface

The 24-byte `RSV1` header is magic, an operation byte and nineteen zero bytes.
All typed unsigned words and lengths are u64 little endian. A reference is its
kind word, raw 32-byte key and version word. Strings are byte length plus UTF-8;
options are 0, or 1 followed by the typed value. Vectors are count plus elements.

| Operation | Typed input after header | Output |
| --- | --- | --- |
| 1 | Object type 1–7, reference, original payload fields, and its extra state fields | Object canonical bytes and original leaf hash |
| 2 | Snapshot version, two authority buckets, seven object vectors and journal vector | Snapshot canonical bytes and original snapshot hash |
| 3 | Applied-record fields in original declaration order | Applied-record canonical bytes |

Payload fields use the existing payload ABI without an extra command tag. The
claim extras are current claimant shares, status 1–5 and optional challenge key.
Challenge extras are status 1–2 and optional resolution reference. Authority
identities are DID string and raw public key; this encoder does not validate them.

Output has four u64 words: canonical-byte length, object type (zero for other
operations), hash-present Boolean and zero; a 32-byte hash follows, then the exact
canonical bytes. Operation 3 writes zero hash bytes and a false hash flag. The
original hash framing and domains are:

- `TRNM_RESEARCH_PROTOCOL_HASH_V1\0 || u32_be(domain_bytes) || domain || u64_be(message_bytes) || message`.
- Objects: `trnm-research-protocol-object-leaf-v1`.
- Snapshots: `trnm-research-protocol-snapshot-v2`.

Status 64 is insufficient output/scratch or capacity arithmetic overflow; status
65 is a frame that cannot represent a well-typed original value. Output stays
unchanged on every refusal. Input remains unchanged; success preserves output
tail and scratch tail. Borrowed live extents must be exclusive and disjoint.
Required scratch is `8192 + 16 * typed_input_bytes`, checked before writes. There
is no new collection-count ceiling; the caller's actual extents bound the call.
The common test runner's 1 MiB per-buffer ceiling remains a test-interface limit.

## Observed development qualification

The first full five-method run passed 465 actual original/native pairs,
385 independently recomputed hashes and 2,844 ABI controls in 42.307 seconds.
The actual composition has 53 functions, 3,839 operations and 489 blocks under
the original compiler limits. Tests include all seven object types, all status
and optional-state variants, full-width versions/nonces, raw inconsistent
snapshots, duplicate and reversed vectors, unsupported snapshot versions, Unicode
and NUL strings, counts through 129, every representative typed truncation,
invalid discriminants and atomic short-output/scratch refusals. These finite
observations do not qualify the forthcoming complete state owner.

```sh
python3 -m unittest hia.tests.test_research_state_values -v
```
