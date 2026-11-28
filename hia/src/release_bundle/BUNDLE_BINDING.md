# ReleaseBundle V0 pure digest binding

[This HIA entry](bundle_binding.hepta) composes the native
[ExactSourceV0 predicate and digest](EXACT_SOURCE.md) with the final
[original ReleaseBundleV0 digest-binding branch](../../../trillionnium/crates/trnm-release-bundle/src/lib.rs).
It is the pure check after artifact, SBOM and provenance validation in
the original verifier, not a replacement for those validation steps or
for signatures. The function is not used by production.

The private borrowed entry `f0(input, digest, scratch)` requires disjoint
regions. The input is exact length, with no extensions or trailing bytes.
Digests are raw octets, not hexadecimal.

| Offset | Field |
| ---: | --- |
| 0 | 193-byte ExactSourceV0 candidate, in original field order, with its dirty flag |
| 193 | Protocol digest (32 bytes) |
| 225 | Externally calculated artifact-set digest (32 bytes) |
| 257 | Externally calculated SBOM digest (32 bytes) |
| 289 | Declared provenance digest (32 bytes) |
| 321 | Previous bundle digest (32 bytes; absent is projected as 32 zero bytes) |
| 353 | Signer identity digest (32 bytes; not an actual signature) |
| 385 | Provenance source-digest declaration (32 bytes) |
| 417 | Provenance artifact-set-digest declaration (32 bytes) |
| 449 | Provenance SBOM-digest declaration (32 bytes) |
| 481 | Bundle digest declaration (32 bytes) |
| 513 | Bundle-name length, little-endian u16 (0–512) |
| 515 | Release-version length, little-endian u16 (0–256) |
| 517 | Consecutive exact name and version byte strings |

The exact-source digest is computed natively from the first 193 bytes.
Source, artifact-set and SBOM declarations are compared in their original
short-circuit order. Only when all three match does HIA derive the canonical
bundle digest and compare it to the bundle declaration. The canonical
transcript uses `trnm.release.bundle.v0` (no NUL), name, version, protocol
digest, computed exact-source digest, supplied artifact-set digest, supplied
SBOM digest, declared provenance digest, previous digest and signer identity
digest. Each part, including the domain, has its own big-endian u64 byte
count. None and a present all-zero previous digest have the same original
canonical representation. Signature bytes and signature digest are not in
this transcript. Lengths are ABI bounds; name/version and required
nonzero-field admission remain earlier checks in the original Rust verifier.

The output needs at least 32 bytes and scratch at least 2,302 bytes.
Success (`0`) writes the canonical digest only, preserving any output
suffix. Malformed extent, length or dirty flag (`100`), invalid exact source
(`101`) and inadequate capacity (`102`) are checked in that order before any
scratch writes. Shared hash-helper failure (`103`) and any original
provenance-binding mismatch (`104`) publish no output, but may modify private
scratch. Each hashing attempt reinitializes the SHA-256 state, not the
whole scratch buffer. Scratch is not a caller status or an evidence receipt. Input and scratch suffix stay unchanged.

The differential compiles the unchanged original V0 declarations, fixture
builders, canonical methods and verifier with pinned Rust. SHA-256 uses
coreutils at the external `sha2` seam. The signature callback deliberately
fails and checks that the original execution reached that boundary; there
is no successful signature stub. Both machine emitters compare decisions
and digest bytes. Tests independently check the fully framed scratch
transcript with hashlib, test every canonical component and a stale
declaration, mutate the last octet of each provenance link, and cover
source-invalid, capacity, and output canary interactions.

```sh
python3 -B -m unittest -v hia.tests.test_release_bundle_binding
```

Not in scope: artifact or SBOM membership, provenance validation, raw
artifact observation, actual checkout or builder authenticity, signing,
custody, publication, production admission or legacy retirement.
