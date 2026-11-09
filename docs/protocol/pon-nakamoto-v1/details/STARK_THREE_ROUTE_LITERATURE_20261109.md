# Three STARK routes: literature scope, 2026-11-09

Status: **HOLD — primary-source review and scope mapping only**.

This record extends the evidence at
`e2a02f9271b49f146e70806c8a66e161b5973971`. Its machine-readable companion is
[the literature manifest](../../../../config/pon/w1-stark-literature-evidence-v1.json).
It does not transfer a security estimate between RISC Zero/Poseidon2,
Plonky3 W1, and the tagged SHA3 candidate.

## 1. Preserve the actual manuscript-review timeline

The [official CDHZ record](https://eprint.iacr.org/2025/2166) still identifies
2026-03-02 as the latest of three revisions. The
[EUROCRYPT publication](https://link.springer.com/chapter/10.1007/978-3-032-25336-1_14)
is dated 2026-05-09. Neither record certifies a particular executable.

| Evidence time | What the retained evidence establishes | Limit |
|---|---|---|
| 2026-11-07 | Selected January theorem statements and conditional composition arithmetic had already been reviewed. | This was more than abstract-only reading; the latest PDF was unavailable then. |
| 2026-11-08 | The repository records complete January/March PDF retrieval and comparisons of all 102 pages. Text/render differences occur on pages 1, 4, 100, 101, 102; formal-body pages 5–99 match. | This closes correspondence of those two pinned versions. It does not independently establish every proof or instantiate the theorem. |
| 2026-11-09, this review | Official metadata and the historical evidence were re-read. A normal retrieval of the frozen March PDF returned HTTP 403. | No new PDF bytes, hash computation, or complete proof audit is claimed. The failed fetch does not erase the earlier successful comparison. |

The records are the
[November 7 selected review](../../../../evidence/pon-w1-qrom-formal-bridge-20261107/theorem-review.json),
[PDF identities](../../../../evidence/pon-w1-qrom-proof-chain-20261108/manuscript-pdf-manifest.json),
and [page comparison](../../../../evidence/pon-w1-qrom-proof-chain-20261108/manuscript-comparison.json).
The historical March identity is
`2cfb88c76732d9f39f4b1943b4aabc0390dd3d17830d91d910c38e16e4bb5a30`
(927,435 bytes, 102 pages); this review has not recomputed that digest.

The implementation contract retains **15 obligation IDs**. The later
[proof-chain disposition](../../../../evidence/pon-w1-qrom-proof-chain-20261108/proof-chain-status.json)
also retains 15 IDs, records one closed pinned-version **sub-obligation**, and
reports 14 other historical obligations. It explicitly reports **zero fully
discharged security obligations**. These are different counts; subtracting the
version sub-obligation from the full cryptographic obligation count is invalid.

For an implementation claim, the remaining evidence must cover the actual
strict/relaxed relations, full round-by-round knowledge and state-restoration
hypotheses, quantum commitment extraction, shared oracle, compiler, recursive
composition, enlarged query domains and lifetime error budget. The existing
conservative arithmetic adapter is not an author erratum or an implementation
security theorem.

## 2. Binary additive-domain results have specific hypotheses

The [DKTZ ECCC record](https://eccc.weizmann.ac.il/report/2026/237/) has
revision 1 dated 2026-11-03. Its
[68-page PDF](https://eccc.weizmann.ac.il/report/2026/237/revision/1/download)
was readable through the document reader. This review checked the scope of
Theorems 4.1, 4.5, 4.7, 5.1 and 6.10 and Section 6.4. The revision retains the
results and theorem numbering. Full independent proof verification is not
claimed, and a separate normal byte download failed with a connection reset.

These results concern characteristic two and binary additive domains, with
further theorem-specific conditions on rate, domain size, containing field,
challenge extension and agreement. The Gold counting result additionally has
a density condition. Matching only a challenge width or a headline rate does
not match these hypotheses.

**Application rule:** once the actual field is established as odd
characteristic, these characteristic-two hypotheses do not apply. Extending
BabyBear or Goldilocks does not change its characteristic. This exclusion
provides no affirmative soundness result, and does not discharge other
Reed–Solomon or Fiat–Shamir obligations.

## 3. Small-base-field limitations remain relevant

Fenzi and Sanso's
[journal article](https://cic.iacr.org/p/3/3/44) was published on 2026-10-26.
The [18-page published PDF](https://cic.iacr.org/p/3/3/44/pdf) was readable;
Sections 1.2 and 4.3, Corollaries 3–4, and Table 2 were checked. It is kept
distinct from the April 9 ePrint revision. A normal byte download returned
HTTP 403, so no fresh full-file digest is asserted.

The relevant setting is an extension code over a smaller base field, with
evaluation points in that base field. Increasing the challenge-field degree
does not remove the inherited large-list limitation. This applies independently
of the binary-domain exclusion above.

The paper's RISC Zero example uses BabyBear, extension degree 4, rate 1/4,
50 queries and block length `2^21`. Table 2 contrasts 100 conjectured
query-phase bits with 92.5 under its information-theoretic lower bound;
grinding is omitted. **These are published example values, not a recomputed
security estimate for this repository or a quantum/lifetime guarantee.**
For FRI, the paper identifies an additional FRI-specific reduction, rather than
directly applying its toy-protocol lemma. It does not provide an efficient
practical attack on a compiled SNARG.

Therefore each route still needs the actual code/extension correspondence,
evaluation domain, list-size and distance-preservation bounds, complete FRI
mapping and sampling/grinding analysis. Counting test passes or changing the
hash profile does not satisfy those mathematical premises.

## 4. Odd characteristic is not a general exemption

The [KKH primary record](https://eprint.iacr.org/2026/782), revised 2026-04-24,
describes a different near-capacity counterexample family over prime fields
and multiplicative subgroups. This review read its official abstract and
metadata, not the complete proof. Its parameter-family hypotheses have not
been instantiated for these candidates. It is retained to prevent the invalid
inference that excluding one binary-field result establishes safety for every
odd-prime configuration.

## Required interpretation by callers

The literature manifest records evidence provenance and applicability
conditions. It is not an admission capability. A caller must retain separate
field, relation, oracle and resource identities for every route; establish the
applicable mathematical hypotheses; and obtain a complete bound before
changing any security qualification. All production/consensus qualification
flags remain false, and complete-system security bits and lifetime failure
bounds remain null.
