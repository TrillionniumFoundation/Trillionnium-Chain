# ReleaseBundle V0 bounded SBOM checks and digest

[This HIA entry](sbom_admission.hepta) implements the package and
required-package checks in the
[original V0 release verifier](../../../trillionnium/crates/trnm-release-bundle/src/lib.rs).
It consumes actual package rows and an explicit required roster. It shares
the native sorted hash body of the
[arithmetic-only SBOM component](SBOM_DIGEST.md), but does not accept a
supplied aggregate digest or validity flags.

The private `f0(input, digest, scratch)` uses disjoint regions. Its input
starts with the exact arithmetic-only SBOM frame (u16 little-endian package
count, followed by one 1,351-byte slot per package). Then it has a u16
little-endian required-key count and one 772-byte slot per required key:

| Offset in required key | Field |
| ---: | --- |
| 0 | Name length, little-endian u16 (0–512) |
| 2 | Version length, little-endian u16 (0–256) |
| 4 | 512-byte name slot |
| 516 | 256-byte version slot |

Both rosters are bounded to 64 in this private ABI. The original structural
limit of 100,000 SBOM packages and its separate caller-provided required
slice are unchanged. No input bytes before or after the exact frame are
permitted. Unused text slot suffixes are ignored.

Validation follows original precedence within this slice:

1. Require at least one package; then inspect each package in input order.
   Its name, version and license must be nonempty printable ASCII, and
   both source digest and package checksum must be nonzero.
2. Immediately after validating each package, reject a repeated exact
   `(name, version)` regardless of checksum, license or direct flag.
   Same-name/different-version packages remain distinct.
3. Require every supplied key, in caller order, by exact byte equality.
   Repeated requirements are allowed. A direct-production Boolean of
   false still covers a required key. The Boolean affects the package
   digest, not membership. Extra valid packages are allowed.

An empty or arbitrary-byte required key within the slot bounds is not
separately rejected: it is missing unless exactly present (valid package
rules make a matching empty/non-printable key impossible). No assertion is
made that the supplied required roster is the real production closure.

After checks, the component computes and publishes the exact V0 SBOM
digest to the first 32 output bytes. Required keys are not hashed.
Scratch needs 4,868 bytes. Status `100` rejects malformed framing before
semantic checks; `105`, `106`, `107` and `108` correspond to the
original empty-SBOM `InvalidBundle`, `InvalidSbomPackage`,
`DuplicateSbomPackage` and `IncompleteSbom` outcomes; `102` is inadequate
output or scratch capacity after those checks. These refusals preserve
all buffers. `103` is an internal hashing failure that publishes no
digest but may modify scratch. Inputs and unused output/scratch suffixes
are unchanged.

The differential compiles the unchanged Rust verifier, fixture and hash
methods. GNU coreutils is used only at the external `sha2` seam. The
Rust signature callback fails deliberately even when reached. Both
machine emitters compare expected behavior, actual aggregate bytes and
sorted member digests, including full 64-by-64 rosters and failure
precedence. Tests feed the checked SBOM digest into native
[provenance](BUILDER_PROVENANCE.md) and
[bundle binding](BUNDLE_BINDING.md) with prior native artifact and source
outputs. This is a test composition, not a unified runtime owner,
signature verification, or release authority.

```sh
python3 -B -m unittest -v hia.tests.test_release_sbom_admission
```
