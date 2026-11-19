# Native ML-DSA-65 and ML-DSA-87

The four modules implement FIPS 204 key generation, signing and verification as
HIA v8 Core compiled by the pinned self-hosted native compiler. They reuse the
unchanged [Keccak implementation](KECCAK.md) and
[canonical polynomial arithmetic](ML_DSA_POLY.md). Production operations do not
call Rust, C, Python, OpenSSL, a subprocess, or a verification fallback.

The original application surface covered here is
[`pq_candidate.rs`](../../../trillionnium/crates/trnm-crypto-primitives/src/pq_candidate.rs).
The original dependency is exactly `ml-dsa 0.1.1`, with `alloc` and `zeroize`.
`pq_auth`, TPQ1/SPKI authentication, profile/content authorization, root quorums,
revocation, attempt budgets, Node integration and automatic resource ownership
are separate integration work. These files do not retire the original crypto
crate or establish production activation.

## Original method coverage

| Original surface | Native Candidate operation |
| --- | --- |
| `CandidateAlgorithm::ALL` | 8 returns the ordered pair 65, 87 |
| `name`, `public_key_bytes`, `signature_bytes`, `nist_category` | 5 returns all four properties for a trusted parameter |
| `CandidateVerifier::from_pinned_raw` | 0 constructs a verifier from the caller's pinned raw public key |
| `CandidateVerifier::algorithm` and `public_key` | 9 and 4 read the fixed owner |
| `CandidateVerifier::verify` | 2 verifies the exact bounded message |
| `CandidateSigningKey::from_owned_seed` | 1 consumes the caller's private 32-byte seed slot |
| `CandidateSigningKey::algorithm` and `public_key` | 9 and 4 read the fixed owner |
| `CandidateSigningKey::sign` | 3 signs deterministically and immediately self-verifies |
| All seven `CandidateError` display variants | 7 formats the original error text, including full u64 lengths |
| Secret cleanup at the native ownership boundary | 6 explicitly clears the complete owner and temporary workspace |

The message limit is the original 65,536 bytes. Candidate signing and verification
use Pure ML-DSA with an empty FIPS context. Their message representative is
`SHAKE256(tr || 00 || 00 || message, 64)`. An incoming message cannot select a
different algorithm, provide a context, import a raw message representative, or
replace an existing owner's pinned public key.

| Parameter | Public key | Signature | Expanded diagnostic key | k / l | eta | tau | beta | omega | Challenge bytes |
| --- | ---: | ---: | ---: | --- | ---: | ---: | ---: | ---: | ---: |
| 65 | 1,952 | 3,309 | 4,032 | 6 / 5 | 4 | 49 | 196 | 55 | 48 |
| 87 | 2,592 | 4,627 | 4,896 | 8 / 7 | 2 | 60 | 120 | 75 | 64 |

Both parameters use n = 256, q = 8,380,417, d = 13, gamma1 = 524,288 and
gamma2 = 261,888. Sampling, bit packing, rounding, decomposition, hints, rejection
sampling and challenge reconstruction execute in the HIA modules.

## Candidate owner entry

[`ml_dsa_owner.hepta`](ml_dsa_owner.hepta) exports
`f0(request: readbuf, owner: mutbuf, work: mutbuf) -> u32` through the existing
private borrowed-byte entry. Each borrowed extent is at most 1 MiB. The owner
has at least 16,384 bytes and workspace at least 131,072 bytes. This pinned
`legacy-f0-private-buffers` entry shim does not validate overlap, null pointers,
or address arithmetic. Its caller must provide live, correctly sized, disjoint
allocations with exclusive mutable ownership. Core still checks types, internal
aliasing and loan lifetimes. Publishing a foreign raw-pointer API requires a
separate native entry gate; that gate is not implemented or qualified here.

The request is a 64-byte header followed by `public_key || message || signature`.
Integers use little-endian encoding.

| Header offset | Field |
| --- | --- |
| 0..8 | ASCII `TRNMDSO1` |
| 8 | Operation, 0 through 9 |
| 9 | Trusted parameter for constructors/metadata; error code for formatter; otherwise zero |
| 10..16 | Reserved zero bytes |
| 16 | Message length, u64 |
| 24 | Signature length, u64 |
| 32 | Public-key length, u64 |
| 40 | Formatter's expected length; otherwise zero |
| 48 | Formatter's actual length; otherwise zero |
| 56 | Reserved zero u64 |

All lengths must exactly describe the body. Only operation 0 accepts a public
key; only 2 accepts a signature; only 2 and 3 accept a message. Operations 0, 1
and 5 accept parameter 65 or 87. All other operations require parameter zero,
except 7 which accepts error code 2 through 8.

The private owner occupies `[0,8192)`. A successful constructor writes the magic
`TRNMDSK1`, kind 1 for a verifier or 2 for a signer, fixed parameter, and fixed
public/secret lengths. The public key starts at 64. A signer's private expanded
key starts at 3072 and ends at 7104 or 7968. Construction from a seed reads
`owner[3008:3040]` into private workspace **before** clearing the owner. It then
generates the key, installs the pinned public key, and clears all 131,072
temporary bytes. The consumed seed slot is zero on success. Verifiers have no
private signing key.

An uninitialized owner has a zero first u64. A live owner cannot be replaced by
another constructor. There is no signing-key clone/import/export operation in
this interface. The expanded-key diagnostic module described below is a
different entry and is not a serialization method on a Candidate owner.

The response starts at owner offset 8192. Its first 24 bytes are three u64s:
`code, expected_or_payload_length, actual`. Public-key and signature responses
append bytes at 8216. Metadata responses append four u64s (public-key length,
signature length, security category, parameter) followed by the nine ASCII bytes
`ML-DSA-65` or `ML-DSA-87`. The return value is the response length. Unused response
bytes through offset 16384 are zero after an admitted request. Bytes beyond
16384 and workspace bytes beyond 131072 remain unchanged.

| Code | Meaning |
| --- | --- |
| 0 | Success |
| 2 | Original `KeyEncoding` |
| 3 | Original public-key length mismatch; expected and actual are populated |
| 4 | Original oversized message; limit 65536 and actual length are populated |
| 5 | Original signature length mismatch; expected and actual are populated |
| 6 | Original `SignatureEncoding` |
| 7 | Original `SignatureRejected` |
| 8 | Original `SigningFailed` |
| 9 | Native owner state/lifecycle refusal, outside the original Rust error enum |

A structurally malformed request or insufficient capacity returns `0xfffffffd`
without changing any caller bytes. This includes preserving a previous response;
the caller must check the return value and must not reuse that response as a new
success. An unexpected internal cryptographic helper failure returns
`0xfffffffc` after temporary cleanup and does not produce a successful result.
The test harness records the upper return word as `abi_status`; this legacy shim
returns zero there and does not implement the general foreign ABI's refusal codes.

### Error order and cleanup

The verifier constructor checks the raw public-key length before expansion.
Verify checks message length, then signature length, then signature decoding,
then the cryptographic equation. Signature decoding checks canonical hint
encoding and the z norm before challenge reconstruction. A z coefficient at
`abs(z) >= gamma1 - beta` is an encoding rejection, not a signature-equation
rejection. Hint cuts may repeat; active index zero and repeated indices in
different polynomials are valid. Indices within one polynomial must strictly
increase, cuts cannot decrease or exceed omega, and unused padding is zero.

Signing copies private key material into workspace, produces a deterministic
signature, and invokes the native verifier against the same stored public key
before returning it. Failed signing leaves no signature response. Failed
self-verification clears the response area and all workspace. A malformed owner
header clears the owner and workspace and reports state refusal. Ordinary
message/signature length refusals keep the private owner, matching the original
borrowed methods, and leave unused workspace unchanged.

Operation 6 is idempotent. It erases every byte of the owner prefix and temporary
workspace before returning. It is an explicit destructor boundary: this C ABI
does not provide Rust's automatic `Drop`, an unforgeable opaque allocator handle,
or a proof that an arbitrary foreign caller never copied secret bytes. A native
application owner must ensure exclusive lifetime, call destruction on every
normal/error path, prevent process/core-dump leakage according to its policy,
and not expose this private arena as a serialized value. Automatic ownership
integration remains open and is not inferred from arithmetic tests.

## Mathematical diagnostic entries

These entries let official vectors exercise the full FIPS arithmetic, including
contexts and supplied randomizers. They do not widen the Candidate API.

| Source | Request | Result | Minimum workspace |
| --- | --- | --- | ---: |
| [`ml_dsa.hepta`](ml_dsa.hepta) | 64-byte `TRNMDSA1` header, key, signature, context, message | 24-byte code/expected/actual | 32,768 |
| [`ml_dsa_keygen.hepta`](ml_dsa_keygen.hepta) | `TRNMDKG1`, parameter byte, seven zeros, 32-byte seed | Header, raw public key, diagnostic expanded key | 65,536 |
| [`ml_dsa_sign.hepta`](ml_dsa_sign.hepta) | 64-byte `TRNMDSG1` header, expanded key, context, message, explicit 32-byte randomizer | Header, signature | 131,072 |

Verification header bytes 8/9/10 are operation zero, parameter and profile.
Bytes 11..16 are zero. U64 lengths at 16/24/32/40 describe key/signature/message/
context; words at 48 and 56 are zero. Profile 0 is bounded Candidate-style Pure
verification with empty context. Profiles 1/2/3 are diagnostic Pure with context,
internal formatted message, and a 64-byte raw message representative. Context is
allowed only in profile 1 and is limited to 255 bytes by FIPS 204.

Signing header bytes 8/9 are parameter and diagnostic profile 1/2/3; bytes 10..16
are zero. U64 lengths at 16/24/32/40 describe expanded key/message/context/
randomizer; words 48 and 56 are zero. Expanded-key length and eta encoding are
checked. The randomizer is always 32 bytes; all zeros select deterministic
signing. The exact borrowed envelope, including all headers, stays within 1 MiB.
No production Candidate message limit was shortened to fit a test budget.

Successful key generation reports `(0, public_key_length, expanded_key_length)`.
Successful signing reports `(0, signature_length, 0)`. Every diagnostic success
clears its full workspace prefix and preserves output/workspace tails.
Diagnostic malformed frames preserve all buffers. An admitted diagnostic
signing failure clears workspace and reports code 8 with its internal reason;
it is not an original expanded-key import API.

Signing follows the complete original nonce range rather than imposing a small
iteration budget. In original `ml-dsa 0.1.1`, ML-DSA-87's last loop value 65534
overflows `u16` while forming the third nonce in a checked build; exhausting
ML-DSA-65's loop reaches `unreachable!`. The HIA implementation explicitly refuses
to sample a nonce above 65535, never wraps or repeats it, and returns signing
failure after cleanup. This is explicit fail-closed treatment of an original
panic/unreachable boundary, not an assertion that the original returns the same
ordinary `Result`. The bounded sampler fixture executes the actual last nonce
guard without claiming to have run thousands of rejected signing attempts.

## Evidence and limits

The official fixture is selected from NIST ACVP Server commit
[`975de31eb83d87039ec88934fdc47d8c312b892d`](https://github.com/usnistgov/ACVP-Server/tree/975de31eb83d87039ec88934fdc47d8c312b892d/gen-val/json-files),
tag `v1.1.0.43`. It includes complete supported groups, not just successful
examples: 90 signature-verification cases, 50 key-generation cases, and 180
signature-generation cases. Every selected answer was also matched with the
separate official `expectedResults.json`. The fixture records all six original
file SHA256 values, selected group/case identities and the excluded ML-DSA-44 and
prehash groups. Official signatures from all 180 signing cases are reverified,
giving 500 mathematical native checks. The exact original public API exposes
150 of the 180 signing comparisons; the other 30 are hedged raw-mu cases covered
by official output bytes, not by an invented original Rust API.

The [test adapter](../../tests/rust_ml_dsa_reference.rs) links the unchanged
original crate and exact dependency. Tests require that executable and its
receipt hash; a missing original never silently skips or substitutes a Python
implementation. Retained tests additionally cover all Candidate getters,
formatters, message limits, mixed-error order, canonical decoding thresholds,
private ownership transitions, dirty-workspace cleanup, actual over-capacity
disjoint allocations and all eight pointer alignments. The full
original all-feature crate gate includes the repository's pinned OpenSSL 3.5.9
provider, Rust 1.95, all retained targets, doc tests, formatting and strict Clippy.
Original provider/download failures are retained separately from successful runs.

The qualification history also retains a failed attempt to require the general
foreign ABI's `ABI_ALIAS` from the legacy private entry. Actual disassembly and
overlapping-pointer observations showed that this shim has no such guard. Those
out-of-contract probes are not counted as supported behavior or successful
refusals. The formal scope keeps the caller's nonalias ownership precondition;
it does not silently promote the private entry to a foreign memory-safety API.

The normative arithmetic reference is
[FIPS 204](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.pdf).
The [potential-updates spreadsheet](https://csrc.nist.gov/files/pubs/fips/204/final/docs/fips-204-potential-updates.xlsx)
read for this implementation has SHA256
`5bc93ce63bc647e6d1d456cb2d3a171426c15aca4a7a0e0edd40d08b7a34c793`.
It is a list of potential corrections, not a new published FIPS version. The
implementation hashes `mu || w1`, produces high parts in 0..15, and uses canonical
residues rather than the optional Montgomery pseudocode.

This evidence is bounded functional coverage. It does not establish CAVP/FIPS
certification, a complete independent cryptographic audit, constant-time
behavior, side-channel resistance, crash-proof secret destruction, entropy
provisioning, or whole-chain quantum security. In particular, current shared
modular helpers use native division/remainder, while sampling and signing have
secret-dependent rejection and indexing. Timing qualification remains open.
The owner must still enforce current authorization, generation, revocation,
deadlines and budgets for every effect, including cached verification results.

## Reproduce the complete bounded gate

Set `HIA_TOOLCHAIN_ROOT`, `HIA_NATIVE_COMPILER` and
`HIA_NATIVE_COMPILER_SHA256` to the exact repository toolchain/compiler pins.
Use the repository's Rust 1.95 toolchain and a new output directory. Prepare
OpenSSL with the unchanged repository script, directing its environment output
to a task-owned file. For example, with `TRNM_ML_DSA_WORK` pointing to a new
directory outside the checkout:

```sh
bash scripts/project-preflight.sh
GITHUB_ENV="$TRNM_ML_DSA_WORK/provider.env" \
TRNM_CI_RECEIPT_DIR="$TRNM_ML_DSA_WORK/provider-receipts" \
RUNNER_TEMP="$TRNM_ML_DSA_WORK" CARGO_BUILD_JOBS=8 \
  bash scripts/ci/prepare_pq_provider.sh
python -B hia/tools/qualify_ml_dsa.py run \
  --output "$TRNM_ML_DSA_WORK/qualification" \
  --rust-bin "$TRNM_RUST_195_BIN" \
  --provider-environment "$TRNM_ML_DSA_WORK/provider.env" \
  --provider-receipt "$TRNM_ML_DSA_WORK/provider-receipts/pq-provider/provider.json"
python -B hia/tools/qualify_ml_dsa.py readback \
  --input "$TRNM_ML_DSA_WORK/qualification"
```

The entry performs a fresh locked original build, preserves every complete test
listing and test executable, runs all 343 retained Rust tests and both doc tests,
checks workspace/adapter formatting and strict Clippy, and links the adapter to
the exact captured Cargo artifact graph. It then runs all 16 native method
tests and all 20 integrity controls. The source roster includes the external
work-profile JSON, the cross-crate `w1_from_zero.rs` example support, and the
protocol's content-framing fixture. Inherited compiler, Cargo profile and
loader overrides or unbound Cargo configuration are rejected before the original
build. Each actual test profile is checked, and all five live provider inputs
are hashed before and after the original gate. Every method requires the live original
oracle. The reader checks actual commands, working directories, wall limits,
Rust version/host, all target/library identities, generated-fixture owner and
canonical dependencies, complete method rosters, raw observations, and explicit
scope exclusions. A failed, partial, filtered, skipped or changed record is
rejected; a compiler receipt alone does not count as execution.

Retain the entire qualification output except `original/target`, which is only
the reproducible Cargo build cache. Required original executables and adapter
libraries have independent copies under `original/retained` and
`original/dependencies`. Native images, full original/native raw streams,
provider inputs, receipts, test/control transcripts and the source map remain
in the output. A failure is a separate observation and must never be overwritten
by a later successful run. This bounded gate does not inherit a PASS when the
checkout, included source graph, test source, compiler or dependency changes.
