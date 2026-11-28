# ReleaseBundle V0 native unsigned prefix

[This single HIA entry](unsigned_prefix.hepta) checks the part of the
[original V0 release verifier](../../../trillionnium/crates/trnm-release-bundle/src/lib.rs)
from the outer declaration through required-package coverage. It then
computes all three candidate digests in the same emitted machine artifact.
It accepts no precomputed digest or validity flag for these three outputs.

The pinned borrowed ABI is `f0(input, output, scratch)` with disjoint
regions. The input starts with this fixed header:

| Byte offset | Field |
| ---: | --- |
| 0, 2 | Name and version lengths (little-endian u16; at most 512 and 256) |
| 4, 6, 8 | Actual artifact, package and required-key counts (little-endian u16; each at most 64) |
| 10 | Protocol digest (32 bytes) |
| 42 | Signer-identity declaration (32 bytes) |
| 74 | Signature-digest declaration (32 bytes; a nonzero-field check only) |
| 106 | 193-byte [ExactSourceV0](EXACT_SOURCE.md) candidate |
| 299 | 512-byte name slot |
| 811 | 256-byte version slot |

At byte 1,067 follow the actual 877-byte
[artifact slots](ARTIFACT_SET_DIGEST.md), then the 1,351-byte
[package slots and 772-byte required-key slots](SBOM_ADMISSION.md), in
that order. Section starts and exact frame extent are derived from the
counts. No sub-buffer loan, padded digest alias, trailing bytes or
caller-supplied section offsets are used. Unused text-slot bytes are
ignored. The private 64-row bound for each section is not a change to
original Cargo type limits or a large-roster claim.

Malformed framing or untyped Boolean returns `100` before any original
semantic checks. After framing, the original prefix decision order is:

1. `110`: invalid name/version, zero protocol/signer/signature digest,
   or empty actual artifact or package roster (`InvalidBundle`).
2. `101`: invalid `ExactSourceV0`.
3. `106` / `107`: invalid artifact / duplicate logical name.
4. `116` / `117`: invalid package / duplicate name and version.
5. `108`: absent required key.

Within each roster, validity precedes each row's duplicate lookup in
original input order. Required keys are matched byte-for-byte regardless
of the direct-production Boolean. The supplied required roster is not
independently derived here. Output capacity (`102`) is checked after
the prefix decisions. These failures preserve the entire output and
scratch.

On `0`, exactly 96 output bytes are written in source, artifact-set,
SBOM order. All cryptographic work uses shared offset-aware private cores
over the original borrowed frame; standalone entries keep their previous
ABIs. The first 5,200 bytes of private scratch are available for temporary
work; three computed digests are retained at 5,200 through 5,295 until
all are ready. The minimum scratch size is 5,296 bytes. An internal failure
(`103`) may modify private work but never publishes partial output. Input
and output/scratch suffixes stay unchanged.

The tests call both independent machine emitters, compare all three
digests with unchanged original Rust V0 and independent hashlib, and
exercise compound errors, shifting section offsets, malformed frames,
exact capacity and 64 actual rows in each section. GNU coreutils is used
only at the original external `sha2` seam. The Rust reference's signature
callback deliberately refuses when reached; it never reports acceptance.

This output is **not** an unsigned release or a release admission
result. The entry stops before provenance validation and final bundle
binding. Those stages, actual signatures, artifact custody, checkout
observation, and production integration are not part of this entry.

```sh
python3 -B -m unittest -v hia.tests.test_release_unsigned_prefix
```
