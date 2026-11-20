# Native Research authority values

`authority.hepta` implements the public `AuthorityIdentityV1::new`,
`AuthoritySetV1::new`, `validate`, `authorizes`/`authorizes_identity`, and both
canonical encoders from the unchanged Research `state.rs`. It reuses the signed
command's native DID/public-point helpers and the shared canonical codec. The
entire composed unit is HIA; no original Rust validation callback supplies a
production decision. This value layer is consumed by the forthcoming state
owner and does not qualify that owner, generic Serde or package retirement.

## Original semantics

An identity requires a 5–192 byte `did:` visible-ASCII token and a nonzero,
well-formed, nonweak Ed25519 public point. Backslash remains allowed. Public Y
normalization follows the original dalek behavior while identity comparisons
retain the exact public-key bytes. The role is outside the identity.

Each authority bucket permits at most 128 identities. `new` sorts each bucket
by `(signer_did, public_key)` and then validates; `validate` requires the supplied
order to be strictly increasing. Duplicates are errors, including same-DID and
same-key duplicates. Both empty buckets are valid. The two role buckets remain
independent; the same identity can occur once in each.

The public struct permits construction of an unvalidated set. Therefore the
authorization operation preserves the original `binary_search_by` behavior even
for an unsorted or duplicate raw bucket; it does not silently sort or validate
it. The native binary search uses the same size/base/mid update and exact tuple
comparison. Tests invoke both original authorization methods, including a raw
unsigned command with irrelevant invalid fields, so signature validation cannot
be accidentally added to this membership method. State application must perform
its separate signed-command validation before invoking membership.

## Borrowed byte interface

The 24-byte `RSA1` header contains magic, the operation byte and nineteen zero
bytes. Identity data is a little-endian u64 UTF-8 length, the DID bytes and a raw
32-byte public key. A set is the first bucket's u64 count and identities, followed
by the second bucket's count and identities.

| Operation | Input after header | Result |
| --- | --- | --- |
| 1 | One identity | Validated identity and canonical bytes |
| 2 | Raw set | Sorted, validated set and canonical bytes |
| 3 | Raw set | Original order, after original validation |
| 4 | Raw set, role u64, query identity | Unmodified set plus original membership boolean |

Role 1 selects Nakama and role 2 Hepta. The output begins with four u64 words:
canonical length, normalized typed length, membership boolean and zero. Canonical
and typed bytes follow. For operation 4 the returned set excludes the query.
The identity canonical form is `[1, did, public_key]`; the set form is
`[1, nakama_identities, hepta_identities]`. Length heads remain shortest CBOR.

Status 301 is the original `InvalidAuthoritySet`. It clears only the fixed
32-byte result prefix. Status 64 is insufficient borrowed capacity and 65 is a
shape that cannot represent the typed public input, including invalid UTF-8,
role or framing; both leave the complete output untouched. All operations keep
the input and output tail unchanged. At least 32 output bytes and
`266752 + 16 * request_payload_length` scratch bytes are required. Arithmetic is
checked before writes. Metadata, curve workspace, backup, original flat bytes,
normalized output, pointer indexes and canonical bytes occupy disjoint regions.
The existing test runner's 1 MiB per-buffer bound remains explicit.

## Executed qualification

Five methods passed 590 actual original/native pairs and 180 ABI controls in
43.759 seconds. The unchanged formal recorder observed one actual self-hosted
build and 770 returned native calls; no methods were skipped, all source bytes
remained stable and actual build provenance passed. The composition has
50 functions, 2,882 operations and 356 blocks under the original limits.

The corpus covers every ASCII suffix byte, empty/short/maximum/oversized DIDs,
Unicode and backslash, canonical and noncanonical Y values, weak keys, all
permutations of representative duplicate-DID/key tuples, bucket sizes through
129, both role buckets, raw unordered authorization, every fixture truncation,
u64 count overflow, short output/scratch and exact bounds. It does not claim
full state, persistence, snapshot graph or Node acceptance.

Reproduce with the repository's pinned toolchain environment:

```sh
python3 -m unittest hia.tests.test_research_authority -v
```
