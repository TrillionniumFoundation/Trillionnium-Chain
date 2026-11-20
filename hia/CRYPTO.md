# Native public Ed25519 verification

The current implementation provides SHA-512, arithmetic over the Edwards25519
field/group, and strict verification of public Ed25519 signatures. All three
algorithms execute compiled HIA machine code. The Python and Rust programs under
`tests/` supply independent observations and are not runtime crypto providers.

This is a bounded public verifier. It does not implement private signing-key
ownership, zeroizing secret lifetimes, ML-DSA/PQ identity, transport installation,
or production authorization. The original crypto package remains necessary.
Variable-time arithmetic operates on public inputs; this implementation has no
constant-time secret-operation or cryptographic-module certification claim.

## Sources and algorithm

- [SHA-512 arena](src/crypto/sha512_arena.hepta) implements NIST FIPS 180-4
  SHA-512. Its [tests](tests/test_sha512.py) bind the constants and source
  provenance, compare an independent SHA implementation, and exercise actual
  pointer misalignment.
- [Field and group operations](src/crypto/ed25519_group.hepta) implement the
  equations in [RFC 8032, sections 5.1.1–5.1.4](https://www.rfc-editor.org/rfc/rfc8032.html#section-5.1.1).
  The point representation is extended homogeneous `(X,Y,Z,T)`.
- [Strict verification](src/crypto/ed25519_verify.hepta) preserves the public
  acceptance policy of the retained
  [original crypto crate](../trillionnium/crates/trnm-crypto-primitives/src/lib.rs).
  It verifies the uncofactored equality `S B = R + k A`, where `k` is the
  complete SHA-512 digest reduced modulo the group order. Canonical coordinates,
  canonical `S`, and rejection of small-order public keys and `R` are explicit.
  Nonweak mixed-order points are not rejected solely for having torsion: the
  original `verify_strict` contract does not impose that additional rule.

`components.json` includes only named, already checked helper functions from the
group and SHA modules. It does not duplicate their implementations or inject
unresolved external crypto calls. The self-hosted compiler exports only the
selected `f0` entry; arena-offset helpers are private compiled functions.

## Exact public interfaces

All entries have the locked native ABI
`f0(input:readbuf, output:mutbuf, scratch:mutbuf) -> u32`.

### Signature verifier

Input is `A[32] || R[32] || S[32] || message`, with at most 131,072 message
bytes. `A` and `R` are canonical compressed points; `S` is little-endian.
No JSON, hexadecimal normalization, implicit context, prehash variant, or
algorithm negotiation is part of this interface.

The verifier requires scratch of at least **140,800 bytes**. It leaves the
complete input and output buffers unchanged; output may be empty. Scratch bytes
at or after 140,800 remain unchanged. Length and capacity refusals occur before
any scratch write. Other refusals may leave intermediate public values in the
owned scratch region.

| Code | Meaning and precedence |
| --- | --- |
| 0 | Signature accepted by the bounded strict verifier |
| 1 | Public-key point has noncanonical `y` or negative-zero encoding |
| 2 | Canonically encoded public key is not a curve point |
| 3 | Public key has small order |
| 4 | Signature `R` has noncanonical `y` or negative-zero encoding |
| 5 | Remaining strict-signature rejection: invalid/weak `R`, `S >= L`, or equation mismatch |
| 100 | Input length is below 96 or above 131,168 |
| 101 | Insufficient scratch capacity |
| 102 | Internal SHA entry returned an unexpected status; never an acceptance |

The original public-key checks precede signature checks. Signature `R`
canonicality precedes the generic signature failure. Code 0 is a result for
the exact supplied public bytes; it does not create the original private
authenticated-frame type or provide any state-commit authority.

### Public field/group component

Input has exactly 65 bytes: `operation[1] || a[32] || b[32]`. Output must have at
least 32 bytes and scratch at least 140,800. Success returns 0 and writes only
the first 32 output bytes; every refusal preserves the complete output.

| Operation | Inputs | Canonical output |
| --- | --- | --- |
| 0 | Field elements `a,b < p` | `(a+b) mod p` |
| 1 | Field elements `a,b < p` | `(a-b) mod p` |
| 2 | Field elements `a,b < p` | `a*b mod p` |
| 3 | Nonzero field element `a < p`; `b` unused | Multiplicative inverse |
| 4 | Compressed curve point `a`; `b` unused | Decode/encode round trip |
| 5 | Compressed curve points `a,b` | Point sum |
| 6 | Compressed point `a`, arbitrary 256-bit little-endian public scalar `b` | Scalar multiple |

Scalar multiplication consumes all 256 bits. It does not silently reduce a
public scalar modulo `L`: that would alter the result on mixed-order points.
The signature challenge has its own explicit modulo-`L` reduction.

Group refusal codes are 1 for noncanonical encoding, 2 for an off-curve point,
3 for zero inversion, 100 for a length/capacity violation, and 101 for an unknown
operation. Group operations admit small-order points as algebraic values; the
signature verifier separately enforces its stricter policy.

### SHA-512 component

The internal `sha512_arena(arena, input_len)` accepts at most 131,168 message
bytes at offset 0. The digest occupies `[131168,131232)` and work occupies
`[131232,132576)`. Minimum arena capacity is 133,120. The digest is standard
big-endian SHA-512 output; success returns 64 and an extent refusal returns
`0xfffffffd` before writes.

The external `f0` accepts the raw message and writes a 64-byte output digest.
It preserves input, output tail and the unused arena tail. The Ed25519 verifier
uses the same helper over the exact bytes `R || A || message`.

## Arithmetic and memory bounds

Each field element uses sixteen nonnegative radix-2^16 limbs in little-endian
u64 slots. Canonical values have the top limb below 2^15. A multiplication
coefficient is at most `16 * 65535^2 < 2^36`. Folding high coefficients with
`2^256 = 38 mod p` gives a conservative slot bound below `2^42`. Carries and the
final `2^255 = 19 mod p` fold therefore fit u64; arithmetic uses checked integer
operations. Subtraction forms `a + 2p - b` limbwise before reduction, so each
intermediate is nonnegative. Normalization carries to a 255-bit representative
and then conditionally subtracts `p` once.

The shared arena is divided at 133,120. SHA code writes strictly below that
boundary. Ed25519 constants, points, temporaries and public scalars occupy
`[133120,140800)`. Field multiplication has its own temporary accumulator;
point addition consumes all input coordinates before writing outputs, allowing
the explicit doubling and accumulation aliases used by scalar multiplication.
The public input-length bound also ensures `R || A || message` fits the SHA
input region. Actual tests check unchanged output and scratch tails.

These private helpers are not arbitrary-offset buffer APIs. Scalar
multiplication requires its output point to differ from its input point;
field operands/results must not occupy the multiplication accumulator
`[139648,139776)`. Every call in both public entries satisfies those constraints.

## Qualification and limits

[The tests](tests/test_ed25519.py) compare field results with arbitrary-precision
integer arithmetic; cover carry extremes, inverse and encoding boundaries;
exercise torsion and all public scalar bits; reproduce RFC known answers;
verify deterministic independently generated signatures; reject mutations,
weak points, negative zero, noncanonical `S` and `S+L`; and retain a constructed
valid nonweak mixed-order signature. A distinct explicit native backend is
tested separately; it never substitutes for a rejected self-hosted build.

[Independent adversarial tests](tests/test_ed25519_adversarial.py) use affine
point arithmetic to construct nonzero low-order residuals: their cofactored
equations hold but strict equations fail. The native verifier rejects every
case. Additional raw-pointer probes exercise all residues modulo eight,
physical arena reuse across group/verifier calls, long-to-short messages,
recovery after refusal and adjacent canaries.

[The Rust test adapter](tests/rust_crypto_reference.rs) directly calls the
retained original crate for signing, public-key parsing, signature parsing and
strict verification. CI compiles the original locked crate and requires this
oracle. Local environments without Rust record the missing differential test
as an explicit skip. The common qualifier refuses any such skip in CI.

Passing these finite cases provides evidence for this implementation and ABI.
It does not prove every possible cryptographic input, satisfy the node's
original service budget, establish cross-architecture behavior, or authorize
removal of the original identity/signing stack.
