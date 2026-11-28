# Original RootRecovery V3 release intent values

This private bounded byte entry checks original canonical `ReleaseIntentV3`
values against exact borrowed, inert bundle, contract and artifact bytes. The
input is three little-endian u64 transport lengths (intent, bundle and
contract), followed by the exact original intent encoding, candidate bundle,
candidate contract, and the remaining candidate artifact. The outer transport
has neither authority nor content policy.

The native entry checks the inner original domain, original kind and
big-endian blob lengths, exact exhaustion before typed value checks, nonzero
attempt and attributed hash, and the original encoded artifact length bound
(64 MiB). Match requires exact bundle and contract equality, exact artifact
length, and SHA-512 of `BE64(domain length) || domain || BE64(artifact length) ||
artifact` using the original ActualArtifact domain. This concrete fixture
transport intentionally supports up to 64 KiB of candidate artifact bytes;
it is not a replacement for the full original 64 MiB matching interface.

Statuses: 0 match; 1 original Codec; 2 original Capacity; 3 original Intent;
4 valid intent but nonmatching inputs; 101 private backend error; 102
private transport/scratch refusal. Scratch requires 132,256 bytes. There
is no emitted payload: the ABI output slot is unused and the input is unchanged. Tests run the original
locked Rust crate using actual `ReleaseIntentV3::from_bytes`, `encode`,
`decode` and `matches_bytes` before comparing each stock backend.
No interpretation, installation, execution, signing or root authorization
is performed.
