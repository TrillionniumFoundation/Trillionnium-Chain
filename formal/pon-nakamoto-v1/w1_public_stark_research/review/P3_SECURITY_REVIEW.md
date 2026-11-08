# Plonky3 0.8.0: full W1 security review

## Status and reconstruction

This review was reconstructed and extended after local scratch loss. It describes the restored relation modules and the newly implemented fixed proof configuration. It does not reuse a historical test result as evidence that the new runner has compiled or proved anything. `source_review.json` distinguishes the historical component tests from the current source snapshot and integration results.

The qualification is **HOLD_NO_GO**. A complete concrete ROM/QROM soundness bound is unresolved. Successful execution of a real proof is an implementation milestone; it does not itself discharge that cryptographic obligation.

The final-source run-02 has now completed both full proofs, three fresh complete verifications, eleven original negative controls and four typed later-stage controls. Its security metadata is structurally identical to run-01's actual metadata, as checked from both raw prover reports. The separate source/binary identities and execution records are in `runner_review.run02.json`; this execution result does not promote the conditional model to a complete noninteractive theorem.

## 1. Exact proof configuration

The new `src/proof_config.rs` fixes the following parameters in code. An untrusted proof cannot select a weaker profile.

| Item | Fixed value |
|---|---|
| Base field | Goldilocks, P = 18446744069414584321 |
| Challenge extension | Quadratic, X² − 7 |
| Commitment/transcript permutation | Official default Goldilocks Poseidon2, width 8 |
| MMCS leaf hash | PaddingFreeSponge, width 8, rate 4, output 4 |
| Internal compression | TruncatedPermutation, two inputs, digest width 4, state width 8 |
| MMCS arity and cap height | 2 and 0 |
| FRI blowup | 4, `log_blowup = 2` |
| Final polynomial log length | 0 |
| Maximum log folding arity | 1 |
| Query count | 64 |
| All grinding sites | 0 |
| Zero knowledge | Disabled |
| Component domains | SHA = 1, arithmetic = 2 |

The challenger observes the fixed research-domain length, one canonical field element per research-domain byte, and the component identifier before the library transcript. This is application domain separation. The underlying typed P3 transcript, challenge sampling and commitment scheme still require their own soundness analysis.

The native W1 relation's SHA-256 remains fully constrained in the SHA AIR. Poseidon2 is the separate proof-system commitment/transcript primitive. A claim that this configuration uses SHA-256 for all proof cryptography would be false.

## 2. Public-statement composition

The public encoding is fixed at 377,290 bytes. The canonical factory consumes that encoding plus independently supplied expected header/artifact commitments. It produces the complete SHA table and complete arithmetic table, and the runner reconstructs both preprocessing verifier keys from those tables.

Let `E` be the independently retained expected input and let `x` be a canonical public encoding. The relation review establishes:

`PublicChecks(E,x) AND AllSHAEquations(E,x) AND AllArithmeticEquations(E,x)`

implies acceptance by the frozen complete native W1 relation, with the supplied prefix equal to the exact original noisy multiplication prefix trace.

If the two actual noninteractive component verifiers have adaptive soundness errors `epsilon_sha(A)` and `epsilon_arith(A)` under an explicitly specified adversary/oracle budget A, then an accepted false W1 statement has probability at most

`min(1, epsilon_sha(A) + epsilon_arith(A))`.

This union bound does not require the two proof attempts to be independent. Each component hypothesis must allow the other proof and shared data as auxiliary information. Fiat–Shamir compilation, challenge sampling and commitment/preprocessing binding must already be included in those component hypotheses.

There is no separate host-digest attestation substituted for the native SHA constraints. Rebuilding a preprocessing key binds the public table through the commitment mechanism; it does not eliminate that mechanism's collision/binding assumptions.

## 3. What the official estimator reports

The retained actual registry sources are the fixed 0.8.0 implementation. `StarkSecurityParams::from_air` derives constraints, degrees, quotient chunks and batching counts. The source distinguishes:

| Estimator | Interpretation |
|---|---|
| `ProvenSecurity` / `proven_security_report` | Conditional round-by-round estimate in unique-decoding and Johnson list-decoding regimes |
| `ConjecturedSecurity` | Separately labeled random-words/correlated-agreement heuristic |
| `LegacySecurity` | Historical comparison, not a deployment soundness bound |

The proven report takes the weakest named term within a regime and the better of valid regimes. This is not the same as a complete noninteractive forgery probability. The library's floating-point bit estimate must not be restated as an unconditional per-proof error `2^-bits`.

The old full-candidate FS-v2 Freivalds theorem with `mu^t` analyzed a different protocol and cannot be transferred to this STARK transcript.

Official API references: [p3-uni-stark 0.8.0](https://docs.rs/p3-uni-stark/0.8.0/p3_uni_stark/), [p3-security 0.8.0](https://docs.rs/p3-security/0.8.0/p3_security/).

## 4. Metadata derived from the actual AIR

`security_metadata` explicitly constructs an `AirLayout` with the main and preprocessed widths, the actual public-value and periodic-column counts, and no lookup/permutation columns. It passes the actual PCS natural trace domain to `StarkSecurityParams::from_air`. A future lookup/permutation change must update that layout.

For the present non-hiding, two-adic, quadratic-extension design, the full shapes observed in the first complete prover report are:

| Quantity | SHA | Arithmetic |
|---|---:|---:|
| Main width | 7728 | 516 |
| Preprocessed width | 27 | 18 |
| Trace height | 8192 | 131072 |
| Main next-row access | yes | no |
| Preprocessed next-row access | no | no |
| Degree hint | 3 | 2 |
| Actual constraint count | 8152 | 525 |
| Quotient chunks | 2 | 1 |
| `max_combo` | 2 | 1 |
| Batching powers | 15487 | 536 |

The actual `retained-native-01` metadata and component tests confirm these dimensions and batching counts. In the 0.8.0 security accounting, any main next-row access charges the whole main width twice. Restricting SHA next-row accesses to 16 state limbs does not justify charging only those limbs in that formula. Setting the batching count to one would remove a real error source.

The complete prover report returns **63.95384529640614 bits** for each component's conditional round-by-round report, with the low-degree-test term limiting the selected list-decoding regime. Its batch-combination terms are approximately 64.7666 bits for SHA and 65.6220 bits for arithmetic. The separately labeled conjectured estimate is 98 bits for each. These are actual library outputs under the declared assumptions; none is a concrete noninteractive forgery bound or a production security level. The report takes the minimum of named round-by-round terms rather than summing their probabilities. The source and report identities are recorded in `runner_review.run01.json`.

The extension has exactly P² elements, slightly fewer than 2^128. The new metadata uses the conservative integer lower bound **127 bits** and publishes the exact cardinality as a decimal string. This is a deliberate conservative rounding choice. It does not establish that the concrete duplex challenger samples independent uniform field elements.

The estimator's **128-bit hash collision input is an explicit assumption**, not an independently established strength of this Poseidon2/MMCS instantiation. The metadata labels it as such. The complete noninteractive bound and quantum bound are explicitly false/unresolved flags, never inferred from the query count.

All grinding sites are zero in both the actual configuration and the model. Query grinding cannot be credited to batching, and a larger query count cannot repair an unrelated batching or out-of-domain bottleneck.

## 5. PaddingFreeSponge: fixed-length limitation

The official Plonky3 advisory [GHSA-3g92-f9ch-qjcm](https://github.com/advisories/GHSA-3g92-f9ch-qjcm) describes collisions between inputs of different lengths for this unpadded sponge construction. It explicitly distinguishes uses whose input length is fixed in advance. The newer alternative `Pad10Sponge` provides length binding for general variable-length input. Pinning version 0.8.0 does not turn `PaddingFreeSponge` into a general length-binding hash.

This prototype's intended use is the fixed-shape MMCS case. The verifier fixes the component, heights, widths, quotient layout, query configuration and expected preprocessing table. It cannot accept an attacker-selected row width or a different plan as the same W1 statement. Internal compression has fixed arity and digest width. These restrictions address the advisory's varying-input-length precondition within a fixed commitment role.

They are not an independent 128-bit proof. A full audit must still enumerate every MMCS leaf role, multi-matrix grouping, FRI folding leaf width, cross-role transcript binding and malformed-opening check in the exact 0.8.0 implementation. The main verifier presently relies on P3's shape checks after its own byte/envelope/fixed-degree checks. Cross-role hash assumptions and the concrete permutation's security remain explicit unresolved hypotheses.

No variable-length W1 message is passed directly to this padding-free sponge. W1 messages are handled by the SHA AIR with the original SHA padding. The Fiat–Shamir challenger is a separate `DuplexChallenger`, not a call to the leaf `PaddingFreeSponge` on an arbitrary message.

The actual 0.8.0 `duplex_challenger.rs` was also inspected. On a nonempty absorb it clears unused rate cells and adds the number of absorbed elements to the first capacity cell before permuting. On an empty absorb it squeezes. This length-tagged duplex operation must not be conflated with the unpadded MMCS leaf hash. Its ordinary `CanSampleBits` path masks the low bits of a canonical Goldilocks value, while a distinct uniform-bit API performs rejection sampling. The FRI call path must select which distribution applies; `QUERY_SAMPLING_REVIEW.md` records the resulting component audit.

Relevant retrieved source identities are `2f74ff9049e96a23d3d26aa1c0dc6cffb471b5b271bfe37af8dc34ff75d6ac97` for `p3-symmetric/src/sponge.rs`, `82d7f006d285015d358e70e3c08378cc907ebb5416a1d1ad2d03d374c56f62e9` for `p3-challenger/src/duplex_challenger.rs`, and `8164c4089590055bed06739a327b4561ce4793f3bc19b730fd1c24d77dec1e4c` for `p3-merkle-tree/src/mmcs/mod.rs`. Local `round2_runtime/` identifiers refer to the audit exports used during review and are not delivery-path requirements. `AUDIT_SOURCE_LOCATORS.json` provides pinned official 0.8.0 crate/source URLs and full hashes.

## 6. Bibliographic checks

The library's comment gives ePrint **2024/1553** an incorrect title. The actual paper is **STARK-based Signatures from the RPO Permutation**, by Atapoor, Delpech de Saint Guilhem and Al Kindi. Its published Theorems 2 and 3 do provide the DEEP-ALI LDR/UDR round-by-round analysis. Its state-restoration and BCS results have further budget-dependent terms. The paper was checked directly: [metadata](https://eprint.iacr.org/2024/1553), [published PDF](https://cic.iacr.org/p/3/2/38/pdf).

The distinct **Fiat-Shamir Security of FRI and Related SNARKs**, by Block et al., is [ePrint 2023/1071](https://eprint.iacr.org/2023/1071). Its framework does not automatically validate every sampler, serializer and preprocessing feature in a concrete library configuration.

The library's Johnson-regime update cites [Dao, Kominers and Thaler, ePrint 2026/2056](https://eprint.iacr.org/2026/2056) and includes its own polynomial-curve derivation in `proximity.rs`. That source explicitly distinguishes the characteristic-free order-zero argument from a positive-order result. This review did not independently formalize that added derivation or the entire proof library.

[Diamond and Gruen, ePrint 2025/2010](https://eprint.iacr.org/2025/2010) gives counterexamples to an unrestricted capacity conjecture. The associated heuristic is therefore kept separate from the proven-regime report.

## 7. Remaining concrete obligations

- Match the exact challenger, domain observations, typed transcript, extension sampling and bit sampling to a stated ROM compilation theorem, including all adversarial oracle budgets.
- Establish the concrete MMCS binding hypothesis for its exact fixed shapes, leaf/compression roles, cap and preprocessing commitments.
- Instantiate the complete two-proof noninteractive error, including compilation and hash-binding terms. A union of unnamed library bit estimates is not that theorem.
- Analyze quantum soundness separately; the present review certifies no QROM estimate.
- Keep each delivered source matched to its own execution records. This requirement is satisfied for the frozen final source by run-02 and does not carry over automatically to later edits. Its maximum observed negative sample is not a universal latest-rejection or denial-of-service bound.
- Preserve the distinction between bounded wire input, allocator behavior, panic containment and a hard process resource limit.

The original component tests, the new small real-proof tests, the full W1 proof run and the complete security theorem are four different evidence levels. Reports must state exactly which have completed.
