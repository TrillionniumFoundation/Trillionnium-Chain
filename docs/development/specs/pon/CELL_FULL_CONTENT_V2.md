# Cell complete actual-content binding v2

Status: candidate component, not production activation or whole-chain PQ128
qualification. This continuation starts from the complete-version candidate
`0dc13a92cc49e9a751a2b6cf7cc96524f1244a2a`. TCV1, TCM1, CPV3 and CAS identities
retain their original bytes and meaning. The separate CPQ1 candidate's TCM2/TCC2
namespace is not copied or silently reinterpreted here.

## Why an additional content record is needed

TCV1 already includes the complete model root, environment closure, dependency
edges, file roles and original manifests. Its SHA-512 outer commitment still
contains SHA-256 payload/chunk commitments. Merely changing the outer hash cannot
strengthen that inner binding. TCV2 records SHA-512 commitments computed from the
actual complete payload and every actual chunk, with independent framing.

SHA-256 manifest IDs remain convenient existing CAS locators. The new acceptance
path also requires the full TCV1 metadata and actual SHA-512 bytes. No lookup hit,
completion marker, transport ACK or signature is used as a substitute for the
full readback. This is byte identity, not a claim about model quality or whether
the author declared all real dependencies.

## Canonical TCV2 encoding

All integers below are unsigned, big endian. Files retain the strictly increasing
TCM1-ID order of TCV1. There is no implicit sort, duplicate repair or extra member.

| Field | Encoding |
| --- | --- |
| Magic | Four bytes `TCV2` |
| Complete metadata | u32 length followed by exact canonical TCV1 |
| File count | u16, exactly equal to the TCV1 manifest count |
| Each file | 32-byte legacy manifest locator, 64-byte full payload digest, u32 chunk count, then one 64-byte digest per ordered chunk |

The maximum complete wire is 24 MiB; TCV1 retains its own 8 MiB, 512-manifest and
per-manifest bounds. Chunk counts and sizes must agree with the full embedded
TCM1, with exact EOF. Missing, extra, zero, reordered, truncated or noncanonical
records are rejected.

For exact payload bytes `P` and chunk bytes `C`:

```text
payload = SHA512("TRNM/Cell/PayloadContent/v2\0" || u64be(len(P)) || P)
chunk   = SHA512("TRNM/Cell/ChunkContent/v2\0" || u32be(len(C)) || C)
root    = SHA512("TRNM/Cell/CompleteVersionContent/v2\0" || canonical_TCV2)
```

`capture_cached` reads the actual original manifest and ordered chunks, verifies
the original full payload, and constructs the strong records. Consumers must
receive the expected strong root from their existing owner. A cache/provider
cannot choose that expected root. `pin_for_owner` checks both original loader
contexts and the independent strong root before exposing the per-chunk checker.
This typed pinned view is metadata-only; it is distinct from a full readback.
The optional strong-content BT receive path checks the exact pinned manifest
before network admission, checks both cache hits and received chunks against
this view before CAS publication, and verifies the complete ordered payload
SHA-512 on actual readback. The original TCM1-only transport entry remains
separate. A successful per-file transfer still does not verify every file in
the complete model/environment version or grant execution permission.

`verify_cached` reconstructs all model and environment byte commitments and
compares every record. Only successful complete verification constructs
`VerifiedCellVersionContentV2`. It describes the bytes during that scan and does
not freeze future cache reads.

## CPV4 publisher authentication

The fresh signature message is
`TRNM/Cell/CompleteVersionContent/ML-DSA-65/v4\0 || header`. It uses the original
in-process ML-DSA-65 verifier with no alternate classical acceptance path.

| Header field | Bytes |
| --- | ---: |
| `CPV4`, version 4, algorithm 0x65, withdrawal bit, zero reserved byte | 8 |
| Original network and parameter locators | 32 + 32 |
| TCV2 actual-content commitment | 64 |
| Original signer key locator | 32 |
| Domain-separated SHA-512 of full canonical SPKI | 64 |
| Generation, sequence, issued-at, expires-at | 4 × 8 |
| Total unsigned header | 264 |

The full-key commitment is
`SHA512("TRNM/Cell/ContentSignerSPKI/v4\0" || u64be(len(SPKI)) || SPKI)`.
This prevents the legacy key locator alone from selecting different full key
bytes in this new path. The full signature follows the header at the original
fixed ML-DSA-65 signature length. CPV3/CPR2 signatures cannot be relabelled as CPV4.

`verify_cached_at` checks the independently supplied network, parameters, full
key pin, generation, sequence, lifetime, version/loader views and signature before
payload I/O. Withdrawn/expired/mutated claims produce no actual-byte success.
`content_at` rechecks the supplied current owner view and observation lifetime.
The owner must maintain the actual fresh monotone view; passing an old copy does
not prove current authorization. This API does not consume a production nonce,
change CURRENT or grant FinalUse.

## One cumulative original read reservation

`CellContentReadSessionV2` holds one absolute deadline, attempted-scan limit and
total payload/chunk reservation. It reserves a complete scan before cache I/O.
Corrupt or unavailable late reads retain the reservation. Reusing the same
session cannot silently renew a deadline or refund a failed attempt.

These are conservative logical scan reservations. SQLite may internally read
pages more than once; hashing and filesystem calls are cooperative. The counters
are not physical I/O, RSS, device memory, CPU accounting or economic payment.
Owner-level hard execution/resource limits remain separate.

## Join to the actual immutable loader objects

The [sealed loader](CELL_SEALED_LOADER_V1.md) rereads the final sealed kernel
object and computes the same full payload SHA-512. `verify_sealed_loader`
requires the entire declared closure structure and each post-seal digest to
match the independently pinned TCV2. It returns a borrowed observation with an
explicit `Model` or `Environment` scope. One scope does not establish the other.

`verify_sealed_version` requires both exact scopes together. Swapping the scopes
or supplying the model twice is rejected. Its borrowed result retains the same
kernel objects later exposed to the consumer. A separate mutable cache check
followed by a different path reopen is therefore not the accepted handoff.

This does not sandbox arbitrary loaders, enumerate dependencies the owner
omitted, allocate NVMe/VRAM, run an ordinary Hepta expert, or prohibit an external
loader from opening unrelated files. The real loader/Hepta execution owner must
enforce these remaining boundaries, original resources, current state and
FinalUse. Duplicated descriptors and mappings remain owned resources; dropping
a Rust bundle does not prove all kernel memory has been reclaimed.

The existing [ordinary handoff](CELL_ORDINARY_HOST_HANDOFF_V2.md) has a separate
schema boundary: its `context.runtime` pins the worker source, whereas this
complete-version path pins the environment closure ID. Its CPR2/TCR1 entry
cannot silently become CPV4/TCV2. A future ordinary integration needs a fresh
versioned entry and independent owner context, content, loader and runtime pins.
The existing [model material loader](../../../../scripts/llm_base_material.py)
already constructs tokenizer/model state from the same captured checked bytes.
A new descriptor adapter must preserve that property and its tensor/parent
checks, then meet the original host resource, Ready, FinalUse and terminal
unload boundaries. The synthetic tensor example is not that ordinary run.

## Independent controls and retained qualification gates

[The independent Python vector](../../../../scripts/cell_version_content_vector.py)
builds actual synthetic payloads, TCV2 framing, the unsigned CPV4 header and the
exact domain-separated digests without invoking Rust. Rust tests compare those
bytes and exercise real signatures, signature/record substitutions, failed scan
reservations, strict metadata coverage and actual final sealed-object reads.

Complete native regression and exact-source results are recorded in the final
evidence directory, not inferred from this specification. Public independent
custody, actual payment, elapsed availability, WAN SLA, ordinary Hepta use and
whole-chain quantum security remain separate qualification gates. In particular,
legacy network/parameter locators and every other chain primitive have not been
replaced by this new content component.
