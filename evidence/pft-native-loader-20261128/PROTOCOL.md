# Native pinned PFT JSON loader v1

Frozen before the first build. Parent source:
`6a9eb25662330cf4e8b7845f6bbf5cfc6d9f875a`.
The existing typed core and its arithmetic profile remain unchanged.

## Input contract

The public Rust API accepts bounded candidate and feature JSON byte slices plus
an independently retained typed expectation. That expectation fixes the full
candidate/feature-packet SHA-256 identities, candidate contract/head/weight
identities, model family/profile/shape and feature semantics, parent/objective,
request/source/ordered-row identities and the expanded feature binary64 digest.
Expected pins do not authenticate their provider or authorize model use.

The loader hashes complete input bytes before interpreting their contents.
It checks the exact existing `pft-online-candidate-v1`,
`pft-online-statistics-v1`, and `pft-feature-input-v1` fields and constants.
The declared original `contract_canonical_json` and
`head_material_canonical_json` strings are parsed strictly and hashed verbatim;
no floating-point JSON reserialization is used for these commitments. Their
decoded values must match the candidate contract and declared head semantics.
This verifies retained raw-string pins, not Python serializer canonicality.

Contract epoch is an integer in `0..=i64::MAX`; dimension is 1..1024, outputs
1..32 and the regularizer is positive, finite and normal. Parent/objective and
all feature semantics match retained pins. Head batches number 1..256, each ID
is unique, strictly increasing, ASCII alphanumeric/underscore/dot/hyphen and
1..128 bytes. Each payload digest is lowercase SHA-256. Revision equals the
batch count; declared sample count is between revision and revision*100000.

Weight shape is exactly d×m. Feature shape is rows×d, rows 1..256. All numeric
matrix values decode as finite binary64 zero or normal values. Dense C row-major
little-endian weight bytes must hash to both the candidate and retained weight
pin; feature bytes must hash to the independently retained expanded-feature
pin. Signed-zero byte identity is preserved. Row IDs are distinct lowercase
SHA-256 strings; the digest of their compact ASCII JSON array preserves order.
No normalization, transpose, quantization, feature execution or fitting occurs.

## Strict parser and bounds

Each outer input is at most 16 MiB. The parser rejects duplicate decoded keys,
trailing tokens, unknown schema fields, invalid JSON/UTF-8, NaN/Infinity, wrong
types and malformed number/string tokens. Maximum depth is 8, total values
300000, object fields 32, string token 131072 bytes and number token 128 bytes.
Contract text is at most 4096 bytes; head text at most 131072 bytes.
Raw input limits and structural limits precede unbounded allocations.

Object/array framing is parsed independently of serde_json's internal special
number representation. Only a lexically delimited numeric token is decoded as
`serde_json::Number`; an object using a serde private number key remains an
object and cannot masquerade as a matrix scalar. Quoted tokens decode using
serde_json's string decoder. This must hold with arbitrary_precision enabled.

## Verification and authority boundary

Use only the existing small public synthetic candidate and a frozen synthetic
feature packet. Controls cover every independent pin, duplicate/unknown fields,
contract/head/batch mismatches, shape/type/range violations, row reuse/order,
private-number object confusion, exact LE byte identity, and bounded parser
depth/token/node/byte limits. No historical candidate or XW is rerun.

The single engineering gate is an isolated offline Cargo harness with its own
target directory and a total 120-second process deadline. It pins the actual
Chain-lock sha2 0.10.9 and serde_json 1.0.149 dependency versions, enables
arbitrary_precision, and runs only the new loader controls. Missing dependencies
stop the build; no install, old-gate replay, deadline extension or budget reset.
Full native-crate graph/Clippy/source gates remain separate CI requirements.

Successful loading means byte identities and declared bounded semantics match
retained expectations and produce an owned typed handle. Provenance, signature,
training/Gram/PSD/normal equations/quality, real user B, original-owner permission,
TCV1 adoption, int257/TMT1 compatibility, FinalUse, payment, reward, production and
consensus remain unproved and unauthorized. No native dispatch entry is changed.
