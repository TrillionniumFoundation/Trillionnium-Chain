# Legacy Ed25519 seed recovery: relation and implementation review

Status: **HOLD_NO_GO**, research only. Reviewed 2026-11-08 America/New_York,
continuing PR #723 from `12e510b211110d93d9ead07e02c07a1eecc28ae9`.
This extends the [historical-account migration contract](PQ_HISTORICAL_ACCOUNT_MIGRATION_V1.md)
and the [sole development plan](../development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md).
No recovery authority, current-account permission or activation is introduced.

## 1. Exact relationship reproduced in this repository

The new [public-fixture reproducer](../../formal/pon-nakamoto-v1/pq_seed_relation_vectors_v1.py)
checks the deterministic relationship

\[
  h=\operatorname{SHA512}(s),\qquad
  a=\operatorname{clamp}(h[0:32]),\qquad
  A=[a]B,\qquad
  h_x=\operatorname{SHA512}(m\mathbin\Vert s).
\]

Here `s` is a fixed public test seed; `a` is interpreted little-endian and `A`
uses compressed Ed25519 encoding. The message `m` comes from the existing
complete V1 public statement. Seed-to-public-key derivation and the public
vectors follow [RFC 8032 sections 5.1.5, 5.1.6 and 7.1](https://www.rfc-editor.org/rfc/rfc8032.html);
the `hx` relationship comes from the pinned PQChain circuit described below.
Three published RFC vectors and sixteen fixed label-derived synthetic vectors
are compared between an integer Edwards reference and the cryptography Ed25519
backend. The SHA-512 calculations are checked through two library APIs; this
does not assert independently implemented underlying hash providers.

The [tests](../../formal/pon-nakamoto-v1/test_pq_seed_relation_vectors_v1.py)
cover byte order, both hash halves, pruning bits, compressed-point encoding,
scalar/expanded-secret substitutions, invalid lengths and all mutable public
statement bindings. A pruning mutation that is a no-op on a fixture is counted
as a no-op, not as a failed cryptographic negative control. The backend is
mandatory: absence, refusal or disagreement cannot return a reference-only pass.

The public API accepts only names from the fixed public catalogue. The CLI has
no arguments, wallet file input or stdin-reading path. Its status is always
`PUBLIC_FIXTURE_RELATION_ONLY_NO_PROOF_OR_AUTHORITY`; its result cannot be used
as a Boolean authority verdict. The optional statement is fixture data, not an
independently authenticated observation of chain state. The arithmetic is
variable-time and must not process real wallet secrets.

These checks do not execute the upstream WASM, generate a ZK proof, verify a ZK
proof, validate the new PQ signature, measure source entropy or consume any
account operation. They provide precise interoperability vectors for that later
work. The original V1 public-statement bytes and namespaces are unchanged.

## 2. The ownership relation has 251 clamped-scalar free bits

This is an independent analysis of the concrete RFC rule, not a measured attack
and not an end-to-end security theorem. The set of allowed clamped scalars is

\[
  \mathcal A=\{2^{254}+8k:0\leq k<2^{251}\}.
\]

Let `L = 2^252 + 27742317777372353535851937790883648493`, the subgroup order.
Reduction modulo `L` is injective on this set: the difference of two such
scalars is a multiple of 8 of magnitude below `2^254`; if it were also a
nonzero multiple of the odd integer `L`, its magnitude would be at least
`8L > 2^255`, a contradiction. Thus a discrete-log result `a mod L` identifies
the unique clamped representative. The reproducer checks this arithmetic on
the public fixtures, endpoints and canonical residues. It does not recover a
seed from that scalar.

Under an idealized uniform-hash model, with the scalar already exposed, a
random 256-bit seed matches a fixed allowed clamped scalar with probability
about `2^-251`. Searching for *any* accepted seed preimage therefore has the
generic Grover query scale

\[
  Q=O(2^{251/2})=O(2^{125.5}).
\]

This is an available ideal-query search scale, not a lower bound, physical
cost, concrete attack forecast or a complete security level. For `M` distinct
target scalars, the corresponding any-account search model has scale
`O(sqrt(2^251/M))`; real oracle construction, resources and lifecycle success
probability still need separate accounting. The model has about 32 expected
preimages per independently selected scalar image. Selecting a random original
seed first changes that expectation by size bias; no exact preimage count is
asserted for a concrete wallet.

The public `hx` is chosen for the current request. Once a different valid seed
preimage has been found, its holder can compute `hx` for a new message and PQ
key. Therefore this message binding is not an additional independently fixed
ownership target. Prover-chosen randomization does not change that point. A
separately authenticated pre-compromise seed commitment could change the model,
but would add a historical trust premise; it is not supplied by Route C.

A seed proof establishes knowledge of a preimage satisfying the admitted
relation. It does not establish that this was the unique seed historically held
by the wallet. A nominal 32-byte witness must not be promoted to an unconditional
PQ128 claim. Low-entropy source distributions and known derivation paths require
their own search-cost model; byte length and KDF expansion do not create entropy.

## 3. Paper, relation and implementation must be mapped separately

Primary sources are Baldimtsi, Chalkias, Roy and Sedaghat,
[Post-Quantum Readiness in EdDSA Chains, ePrint 2025/1368](https://eprint.iacr.org/2025/1368),
the [FC 2026 program](https://fc26.ifca.ai/program.html), and its
[official conference manuscript](https://fc26.ifca.ai/preproceedings/190.pdf).
The ePrint metadata identifies a 2026-03-20 revision. The conference manuscript
was accessible; the current full-version PDF was not obtained in this review.
The latter cannot be declared fully reviewed from the abstract or metadata.

In the accessible conference manuscript, the formal construction preceding
Theorem 2 uses the randomized relation `R_rand`, with both seed and randomness
as private witnesses. Section 5 describes the implemented Equation (2),
`R_det`. The theorem's full proof is delegated to the full version. This is an
unresolved applicability mapping for the selected deterministic implementation,
not a proof that either relation is insecure. Knowledge soundness in the stated
quantum model, zero knowledge and the actual Fiat-Shamir transformation must
each cover the relation, compiler and verifier that will be deployed.

Zero knowledge of proof contents also does not remove information deliberately
placed in public inputs. Deterministic `hx`, repeated messages and low-entropy
seed candidates need an explicit privacy analysis.

## 4. Fixed upstream source has additional concrete audit obligations

The inspected upstream remains
[SoundnessLabs/pqchain at 598cdff516c3086487a173d7d9f9af2830e04a32](https://github.com/SoundnessLabs/pqchain/tree/598cdff516c3086487a173d7d9f9af2830e04a32).
Its README describes Ligetron v1.1.0, but
[VERSION](https://github.com/SoundnessLabs/pqchain/blob/598cdff516c3086487a173d7d9f9af2830e04a32/VERSION)
and [RELEASE.json](https://github.com/SoundnessLabs/pqchain/blob/598cdff516c3086487a173d7d9f9af2830e04a32/RELEASE.json)
identify v1.2.0. The existing V1 profile string is preserved as an unqualified
wire label, not used as a verified release identity. Exact source, compiler,
dependencies, circuit, shader and executable digests are required.

The Fiat-Shamir and Merkle findings below are source observations, not executed
invalid-proof acceptance. The first-block finding also has an isolated
characterization using unchanged upstream headers and public seeds. No complete
prover or verifier was built or run, and no ownership forgery is demonstrated.
These obligations must be resolved before admitting the backend for recovery:

| Boundary | Observation at the pinned source | Required qualification |
| --- | --- | --- |
| Fiat-Shamir sample seed | The [prover](https://github.com/SoundnessLabs/pqchain/blob/598cdff516c3086487a173d7d9f9af2830e04a32/src/webgpu_prover.cpp) hashes the encoded code/linear/quadratic arrays to form `stage2_seed`. The [verifier](https://github.com/SoundnessLabs/pqchain/blob/598cdff516c3086487a173d7d9f9af2830e04a32/src/webgpu_verifier.cpp) reads `sample_seed` from the proof and uses it for sampling without rederiving that equality in the reviewed native path. | Verify the canonical transcript-derived seed before sampling; execute independent positive and noncanonical-transcript controls on the exact binary. |
| Merkle query identity | The verifier derives `sample_index`, while [Merkle reconstruction](https://github.com/SoundnessLabs/pqchain/blob/598cdff516c3086487a173d7d9f9af2830e04a32/include/zkp/merkle_tree.hpp) positions sampled digests using the proof's `known_index()`. Their equality is not checked in the reviewed caller/reconstruction path. | Bind the exact ordered query indices and tree shape, with bounds and duplicate checks. A matching reconstructed root alone does not establish this equality. |
| First sampling block | The constructor in [random.hpp](https://github.com/SoundnessLabs/pqchain/blob/598cdff516c3086487a173d7d9f9af2830e04a32/include/zkp/random.hpp) stores the seed, but the first `operator()` block flushes a hash of its initial counter before absorbing that seed. | Review seed dependence, reset/discard semantics and exact bytes in the challenge sampler. |
| Prover padding entropy | The prover fills 32 bytes from `std::mt19937` initialized with one result of `random_device`, then uses those bytes as the encoding PRG seed. | Establish a cryptographic entropy source and its full seeding contract. A 32-byte output is not evidence of 256 bits of fresh entropy. |

The reviewed context and Merkle helpers do not supply the missing sample-seed
equality on behalf of the verifier. The isolated first-block component produced
identical first 32-byte outputs for two distinct public seeds and different
second blocks. It covers direct construction followed by `operator()`; it does
not run `portable_sample`, reset/discard paths or a full proof transcript.
Full impact on soundness, privacy and adversarial resource cost remains open.
This increment compiles only that unchanged-header component; it does not build
or activate the full proof backend. A successful component or honest-proof run
would not discharge the remaining transcript-consistency obligations.

## 5. Wallet compatibility and local custody

| Retained wallet material | Relation compatibility | Required action |
| --- | --- | --- |
| Original RFC8032 seed32 | A candidate witness if it reproduces the historical key | Verify exact wallet derivation, actual custody and source entropy locally. |
| Documented `seed || public_key` container | Potentially compatible through an explicit format adapter | Identify the library/version; verify the second half against the derived key. The reproducer deliberately does not truncate it automatically. |
| Expanded scalar plus nonce prefix | Not the current seed witness | Preserve this distinct format; do not reinterpret either half as the original seed. |
| Scalar only | Not the current seed witness | This is within the compromised-old-key threat model, not an ownership recovery credential. |
| Mnemonic or HD root | Undetermined until the exact derivation is fixed | Bind wallet family, path and source distribution; do not assume every Ed25519 HD wallet uses the same construction. |
| Non-exportable hardware wallet | Undetermined | Require an approved device-local proving capability or another explicitly reviewed protocol; ordinary signing support is insufficient. |

Actual proving must keep the seed in the local owner and out of command-line
arguments, logs, telemetry and remote proving services. The upstream example
configuration must not be reused with real secrets without auditing its argument
printing. Public fixture execution is the only input class used here.

## 6. Separate acceptance gates

The existing complete statement must continue to bind the destination PQ key,
network/genesis, source and migration roots, account state/generation, operation,
validity, derivation profile and exact proof artifacts. A request digest that
changes with randomized proof/signature bytes is not the one-use operation slot.
Current account eligibility must be read before expensive work and rechecked
inside the atomic owner transition. Cached immutable proof facts cannot replace
that current-state check.

The following remain open independently: authentic source scope and existing
theft accounting; prior binding for Route B; complete operational inventory for
Route A; source write retirement; unsupported application/effect preservation;
cross-activation reorganization; durable one-use/effect roots; wallet custody and
entropy; concrete ownership-relation strength; full deterministic-relation proof
review; fixed verifier/transcript qualification; real local proof generation and
verification; malicious-input resource bounds; PQ possession and native atomic
claim integration. A seed proof cannot recreate assets already stolen and settled.

Actual finite observations and original failures are in the
[execution record](../../evidence/pq-migration-qualification-20261108/README.md).
