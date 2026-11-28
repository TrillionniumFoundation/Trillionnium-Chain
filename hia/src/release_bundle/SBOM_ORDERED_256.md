# Original V0 ordered SBOM digest, 256-slot diagnostic

The original public `ReleaseBundleV0::sbom_digest()` sorts complete typed
package values and hashes their canonical SHA-256 member digests in order.
This independent native component takes precisely the original private
SBOM slot format, with a separate 0–256 bound, little-endian u16 count,
exact 1,351 bytes per slot and no trailing bytes. It reuses the existing
member codec, sort comparison, and SHA-256 stream. It preserves
duplicates and does not establish SBOM validity, coverage, certification
or release authority.

The earlier 64-slot selector used a single visited-bit word and repeated
scans. This entry initializes a 256-index array and performs up to eight
bottom-up merge passes into an alternate disjoint index array, with at
most 2,048 merge copies and at most that many full bounded typed
comparisons. The invariant preserves every original slot exactly once.
The largest packet is 345,858 bytes, below the common Direct/Selfhost
1-MiB borrowed ABI. Its disjoint scratch region is 16,384 bytes: private
SHA transcript and sorted member bytes end by offset 11,012; index
arrays are [12,288, 14,336) and [14,336, 16,384). The 32-byte aggregate
is published only after complete successful hashing. Status 100 is
malformed input, 102 insufficient scratch/output, 103 private hash
failure. Malformed or short calls mutate neither output nor scratch.

The unchanged old 64-slot entry and whole unsigned-candidate profile do
not allow 65 or more rows. This additional value primitive is not an
expanded verifier or replacement. Locked Cargo runs the actual public
original SBOM digest for inert fixtures, compared against both native
emitters, including 256 rows, duplicate multiplicity and an uneven last
merge. No live source, build owner, production integration, signatures,
or validation/authorization outcome is used.
