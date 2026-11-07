# W1 STARK review — formula reproduction and known conjecture limits

Status: **HOLD for complete W1 and post-quantum security qualification**.
Reviewed on 2026-11-06. This is an independent arithmetic reconstruction and
source/literature review by the same project operator. It is **not external
cryptographic sign-off**. The
[sole development plan](../development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md)
owns follow-up work and admission decisions.

The review preserves the historical evidence and parameter choices. It adds a
published obstruction to optimistic capacity-based estimates while retaining
the exact upstream equations for reproducibility. It does not qualify a new
receipt, change a verifier, or assign the chain a quantum security level.

## Separate the quantities being reported

| Quantity | Meaning and boundary |
| --- | --- |
| Official native/recursive estimates, 96/99 bits | The [RISC Zero 3.0 security model](https://dev.risczero.com/api/security-model), reviewed on 2026-11-06, lists the Random Oracle Model and Toy Problem Conjecture and separately marks the STARK paths quantum safe. This table is not an instantiated QROM bound for W1. |
| Locked calculator's toy-model sum | A conjectural component expression reproduced from exact source. Correct arithmetic does not validate its conjectures. |
| Locked calculator's proven-list-decoding formula | An upstream component formula evaluated with upward rational square-root enclosure. This review does not prove its complete AIR/IOR, hash, recursion or QROM applicability. |
| Paper Table 2, 100 versus 92.5 | Query-phase model accounting at the paper's parameters; 92.5 is the displayed negative logarithm of a lower bound on an information-theoretic adversary's success. It is not a security lower guarantee. |
| Complete W1 receipt or accepted recursive family | Requires the full relation, admitted controls, claim/image binding, transcript and composition analysis. No bit count is established here. |
| Quantum security/work factor | Requires a concrete quantum adversary/query budget and applicable reduction losses. It is not obtained by relabeling, halving or subtracting from another row. |

The same official page describes the STARK-to-Groth16 translator over BN254 as
vulnerable to quantum attacks. That is a separate outer proof construction; it
does not show that a saved W1 Succinct receipt used Groth16. Any proposed outer
construction needs its own profile and security assessment.

## Exact-source arithmetic review

The reviewed source is RISC Zero commit
`8c215e2f4ccdd935f0517bf05d90f1ae032840a9`, especially
[`risc0/zkp/src/prove/soundness.rs`](https://github.com/risc0/risc0/blob/8c215e2f4ccdd935f0517bf05d90f1ae032840a9/risc0/zkp/src/prove/soundness.rs).
The project implementation is
[`w1_security_budget.py`](../../scripts/w1_security_budget.py), alongside
[`w1_profile_source_map.py`](../../scripts/w1_profile_source_map.py).

An independent review-workspace replay checks seven original source files
against their fixed SHA-256 pins and Git blob hashes. It extracts column widths
and maximum tap multiplicity directly from the original individual tap entries.
Its expected values use 160-digit Decimal arithmetic; the project evaluator
uses exact fractions and a rational square-root enclosure.

The replay covers both circuits, every `po2` from 13 through 24, and query counts
1, 2, 50, 64, 65 and 4096: **144 combinations passed**. Every toy expression
agrees, and the proven-formula components agree with the intended upward
square-root enclosure. The largest observed relative enclosure excess is about
`8.964e-54`. Another 24 checks confirm that changing the query count alone cannot
reach the 128-bit comparison budget under the retained toy formula's fixed
accumulator/field terms. These are equation checks, not successful attacks or
new cryptographic qualification. The replay does not emulate upstream `f32`
rounding and does not rerun crate archive verification or a prover.

The [dated evidence and replay commands](../../evidence/pon-w1-stark-review-20261106/README.md)
retain the independent audit script, seven-file source bundle, exact arithmetic
report and separate Table 2 diagnostic. The same evidence records the actual
saved-v2 verifier test repair; that acceptance regression does not qualify a
cryptographic security level.

| Circuit | Accumulator/code/data columns | Trace polynomials | Largest tap combination |
| --- | --- | --- | --- |
| RV32IM | 103 / 1 / 211 | 315 | 6 |
| Recursion | 12 / 23 / 128 | 163 | 6 |

For the ideal first-nonzero-of-four sampler, let `p = 2013265921` and `m = 2^b`
divide `p - 1`. Under independent uniform field draws, the single-call total
variation distance after the low-bit mask is `(m - 1) / (m * p^4)`. This confirms
the local ideal-experiment expression. It does not establish that an adaptive
Poseidon2 transcript supplies those draws or bound the full transcript distance.

The prior source-comment mismatch at `po2 = 24` and the need to avoid absolute
values of negative logarithms were already recorded locally. This review does
not present them as newly discovered defects.

## Published small-field obstruction

Giacomo Fenzi and Antonio Sanso,
[Small-field hash-based SNARGs are less sound than conjectured](https://cic.iacr.org/p/3/3/44),
IACR Communications in Cryptology, published 2026-10-26,
DOI `10.62056/akdkmpxqi`; [official full text](https://cic.iacr.org/p/3/3/44/pdf).
This review read the published version, including Corollary 4, Remark 2 and
Table 2. The earlier ePrint identifier is 2025/2197.

For Construction 1 using an extension of a base-field linear code, put
`B = |base field|`, `F = B^e`, `rho = k/n`, and let `t` be the query count.
Corollary 4 gives a lower bound on information-theoretic adversarial success:

```text
H_B(delta) = [delta ln(B-1) - delta ln(delta)
              - (1-delta) ln(1-delta)] / ln(B)
A = B^[n * (rho - 1 + H_B(delta))]
beta_toy(delta) >= A * (1-delta)^t
                   / [(F-1) * sqrt(8*n*delta*(1-delta)) + A]
```

Table 2, PDF page 14, uses `B = 2013265921`, `e = 4`, `rho = 1/4`, `t = 50`
for its RISC Zero row and fixes `n = 2^21`. Its 100-bit query-only conjectural
figure becomes 92.5 in the negative-log-success column. This tuple matches the
locked backend's field, extension, rate and query count; the paper's `n` is not
an observation of a W1 receipt's trace size. A separate numerical reconstruction
gives approximately `92.4543301564` at that `n`; it is diagnostic numerical
evaluation, not a certified optimizer or full W1 bound.

Remark 2, PDF page 12, states that the strategy is information-theoretic, with
no known polynomial-time implementation. Its Lemma 6 attack does not transfer
verbatim to the ethSTARK toy protocol. The paper's FRI connection instead invokes
BSCH+26 Lemma 8.4 together with Corollaries 2 and 3's list-size bounds. Full W1
protocol instantiation remains a separate obligation. Do not replace the local
calculator output by 92.5 or subtract 7.5 from the official 96/99 figures.

## Other conjectures and QROM obligations

[Crites and Stewart, 2025/2046](https://eprint.iacr.org/2025/2046) identify
counterexamples to the stated up-to-capacity correlated-agreement,
WHIR mutual-correlated-agreement and DEEP-FRI list-decodability conjectures.
The unrestricted statements therefore cannot be described merely as awaiting
proof. Their failure does not establish failure of every restricted parameter
choice or of proven decoding regimes. In particular, reproducing the locked
`conjectured_strict` source references would not instantiate a replacement
theorem for its chosen constants; that function is not a new qualified output
of the local calculator.

The [QROM framework, 2025/2166](https://eprint.iacr.org/2025/2166) remains an
abstract-level mapping in this project. Its full theorem hypotheses and concrete
losses have not been instantiated for the exact W1 IOR, vector commitments,
Poseidon2/SHA interfaces, adaptive transcript sampling and recursive family.
The full-text review of the separate small-field paper does not change that
status. The
[prime-field near-capacity result](https://arxiv.org/abs/2604.09724) also concerns
a specified family and is not by itself a break of this fixed backend.

The implementation retains the historical component equations and all existing
negative qualification flags. New source-map runs include the dated literature
annotation and unresolved applicability obligation; historical
`security-map.json` evidence remains unchanged. External cryptographic review,
an explicit quantum cost/error target, complete source/parameter mapping and
full composition analysis are still required before a stronger claim.

## Follow-through: source snapshots and actual-record consistency

The [source-snapshot continuation](../../evidence/pon-w1-source-snapshot-20261106/README.md)
starts from `d9fd07c473998bd236207c1b7db4233f0eafd7fe`. The original transparent
workflow has now completed successfully on both that head and its prospective
merge. Its retained head artifact contains all three named v2 Rust tests and
all 58 actual saved-v2 receipt controls. This is evidence that the earlier
always-reject coverage repair executed; it is not the same unresolved defect.

Two further evidence-boundary defects are addressed in this continuation:

- The source mapper used to hash a crate archive and then reopen its path for
  parsing. A deterministic replacement between those reads made it accept
  different source bytes under the original archive checksum. Archive hashing
  and parsing now consume the same bounded byte snapshot. Lockfile parsing,
  historical-log and manifest parsing, and selected-source size/hash records
  likewise retain the digest of the bytes actually inspected.
- The v2 CI report gate used to check the outer case result without reconciling
  contradictory nested process results or incomplete output observations.
  The continuation reconciles the report with the retained per-case process,
  input and log records, while keeping the real accepted receipt as a positive
  control and preserving the original ordered 58-case plan and deadline.

These are source and observation integrity repairs. They do not demonstrate a
forged STARK, a Node admission bypass, or a practical attack on the fixed
cryptographic profile. The original source-map byte comparison and GitHub
Actions step failures provided additional detection boundaries; a permissive
standalone report check does not by itself prove an entire CI job could turn
green. The real historical positive receipt and all negative qualification
flags remain unchanged.

An offline replay of the repaired mapper against seven actual locked crate
archives verifies 37 selected files. Its new snapshot differs from the dated
historical snapshot only in the generator digest. The original snapshots are
retained. This replay is scoped to the exact mapper, locked inputs and cache;
it does not compile a new verifier or generate another proof. All full W1,
QROM, quantum-work, ordinary-node proof admission and whole-chain PQ gates
remain HOLD.
