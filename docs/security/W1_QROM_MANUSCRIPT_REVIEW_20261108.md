# W1: CDHZ manuscript revision and interface review

Date: 2026-11-08. Status: **JANUARY–MARCH VERSION COMPARISON COMPLETE;
NAMED ONLINE ENVELOPE DERIVED; COMPLETE W1 SECURITY HOLD**.

This review retrieves the actual official PDF bytes of Alessandro Chiesa,
Zijing Di, Zihan Hu, and Yuxi Zheng, *How to Prove Post-Quantum Security for
Succinct Non-Interactive Reductions*, ePrint 2025/2166. It closes the specific
January-to-March access and version-consistency question left open by
[the 2026-11-07 formal obligations](W1_QROM_FORMAL_OBLIGATIONS_20261107.md).
It does not instantiate the paper for either accepted W1 candidate.

The mathematical pages of the two revisions are unchanged in both extracted
text and the tested page rendering. The online-error parameter-order
inconsistency observed in January is also present in the March PDF. Its
semantic query-mass dependence can be established directly from the supporting
lemmas. A separate query-accounting issue in Construction 11.11 calls for an
explicit conservative allowance; these are different findings.

## 1. Official source identities

The [official version history](https://eprint.iacr.org/archive/versions/2025/2166)
contains three PDF revisions: November 28, 2025; January 1, 2026; and March 2,
2026. It also lists a March 2 metadata-only update. The exact versions used
here are:

| Identity | January manuscript | March manuscript |
|---|---|---|
| Official revision ID | `20260101:061307` | `20260302:160701` |
| Archived metadata | [January entry](https://eprint.iacr.org/archive/2025/2166/20260101:061307) | [March entry](https://eprint.iacr.org/archive/2025/2166/20260302:160701) |
| Frozen PDF | [1767247987.pdf](https://eprint.iacr.org/archive/2025/2166/1767247987.pdf) | [1772467621.pdf](https://eprint.iacr.org/archive/2025/2166/1772467621.pdf) |
| Title-page date | January 1, 2026 | March 2, 2026 |
| Bytes | 927,381 | 927,435 |
| Pages | 102 | 102 |
| SHA-256 | `215a62b9a1b5144c89ae103aaabaf6049eab23f7ccb23130bc7d65d597c1eac9` | `2cfb88c76732d9f39f4b1943b4aabc0390dd3d17830d91d910c38e16e4bb5a30` |

The live [latest PDF](https://eprint.iacr.org/2025/2166.pdf) was downloaded
separately and is byte-for-byte identical to the frozen March PDF at this
observation. The metadata-only entry is `20260302:103747`; it must not be
counted as a fourth PDF revision. This review does not compare the November
PDF or the publisher's separately typeset proceedings chapter.

Ordinary browser navigation retrieved the official PDFs after an automatic
site verification completed. No credentials, access-control changes, or
interactive CAPTCHA solving were used. Earlier 403 and 522 observations in
the historical obligations remain accurate descriptions of that earlier
retrieval attempt; they no longer describe the available evidence in this
review.

For reproducibility, use the explicit frozen PDF links. The title hyperlink
on an archived metadata page can still point to the live latest PDF; following
that link alone does not pin the historical version. All page references below
are one-based PDF pages, matching the printed page numbers.

## 2. Whole-document and per-theorem comparison

The comparison used both `pdftotext -layout` and `pdftotext -raw` over each
complete file, followed by complete unified diffs. Independently, PyMuPDF
1.26.6 compared each page's extracted text and rendered RGB samples, at a
1.5-times scale (108 dpi), with alpha disabled. For both documents each rendered
page was 918 by 1188 pixels. No page was omitted.

The text and pixel comparisons identify the same five changed pages:

| Pages | Observed difference |
|---|---|
| 1 | Title-page date changes from January 1 to March 2. |
| 4 | The introductory references `BC24` and `BC25` become `BC25a` and `BC25b`, with line reflow. |
| 100 | LatticeFold's bibliography entry changes from ePrint 2024/257 to its ASIACRYPT 2025 publication; the LatticeFold+ key becomes `BC25b`. |
| 101–102 | Bibliography pagination and layout reflow following the preceding bibliographic update. |

The other **97 pages**, including every page from **5 through 99**, have
identical page text and identical RGB sample bytes under this rendering.
Thus the changed bibliography is not being mistaken for a change to a
hypothesis, constant, exponent, theorem interface, or proof argument.

The following inventory covers every distinct theorem statement, including
the informal introduction statements. Repeated prose references to “Theorem
8.4” inside lemmas are not additional theorem statements.

| Statement | Start page | Subject | January–March result |
|---|---:|---|---|
| Informal Theorem 1 | 5 | Post-quantum BCS reduction security | Statement unchanged. |
| Informal Theorem 2 | 5 | Round-by-round to state-restoration security | Statement unchanged. |
| Informal Theorem 3 | 6 | Merkle multi-extractability | Statement unchanged. |
| Theorem 5.4 | 31 | Generalized instability bound | Statement and proof unchanged. |
| Theorem 6.9 | 44 | Round-by-round soundness to quantum state restoration | Statement and proof unchanged. |
| Theorem 6.10 | 46 | Relaxed round-by-round knowledge to quantum state restoration | Statement, extractor construction, and proof unchanged. |
| Theorem 8.3 | 53 | Concrete Merkle commitment errors | Statement and supporting proof unchanged, including the online parameter order. |
| Theorem 8.4 | 53 | Sufficient conditions for VC multi-extractability | Statement and supporting Section 9 proofs unchanged. |
| Theorem 10.6 | 72 | Sequential composition of non-interactive reductions | Statement, enlarged query arguments, extractor order, and proof unchanged. |
| Theorem 11.3 | 78 | Knowledge security of the BCS transformation | Statement, Construction 11.7, Lemma 11.6, and subsequent proof arguments unchanged. |
| Theorem A.1 | 98 | Soundness specialization | Statement and proof unchanged. |

This is a complete revision comparison for the pinned PDFs. Equality of the
inspected text and rendering is not an independent correctness proof of the
paper, a comparison of TeX sources, or a certification of any implementation.
In particular, a discrepancy already present in January is not repaired by
establishing version equality.

### Reproduction procedure

The repository's [comparison script](../../scripts/w1_cdhz_revision_compare.py)
accepts only the two byte identities above. It analyzes captured copies of
those verified bytes, records the renderer and text-extractor versions, and
writes per-page text and pixel digests plus complete raw/layout text diffs to
a JSON manifest. It does not write the manuscript PDFs to the repository or
claim implementation security.

```bash
python3 scripts/w1_cdhz_revision_compare.py cdhz-january.pdf cdhz-march.pdf --output comparison.json
```

The underlying text comparison can also be reproduced directly. Reacquire the
two frozen PDFs, first verify the two full-file digests above, then run:

```bash
sha256sum cdhz-january.pdf cdhz-march.pdf
pdftotext -layout cdhz-january.pdf january-layout.txt
pdftotext -layout cdhz-march.pdf march-layout.txt
diff -u january-layout.txt march-layout.txt
pdftotext -raw cdhz-january.pdf january-raw.txt
pdftotext -raw cdhz-march.pdf march-raw.txt
diff -u january-raw.txt march-raw.txt
```

For the independent rendering check, open the two documents with PyMuPDF
1.26.6 and compare, for each index `i` from 0 through 101:

```python
left[i].get_text() == right[i].get_text()
left[i].get_pixmap(
    matrix=fitz.Matrix(1.5, 1.5), colorspace=fitz.csRGB, alpha=False
).samples == right[i].get_pixmap(
    matrix=fitz.Matrix(1.5, 1.5), colorspace=fitz.csRGB, alpha=False
).samples
```

Check page counts and pixel dimensions as well as sample bytes. Expected
one-based differing-page lists are `[1, 4, 100, 101, 102]` for both comparisons.
Record per-page digests before disposing of temporary renders. Renderer
versions can affect pixels, so equality is checked within the same renderer
and settings; cross-renderer pixel identity is not asserted.

## 3. Online extraction: a named semantic interface

### 3.1 The displayed positional discrepancy survives in March

The following orders are visible in both pinned PDFs:

| Source | Displayed online-error arguments after `lambda, t` |
|---|---|
| Definition 7.3, item 5, p. 51 | `w_MultiExtract, w_VC, w_Record, sigma` |
| Theorem 8.3, p. 53 | `w_VC, w_MultiExtract, w_Record, sigma` |
| Theorem 8.4, p. 54 | `w_VC, w_MultiExtract, w_Record, sigma` |
| Theorem 11.3, p. 79 | `w_MultiExtract + 1, w_VC + q_CRhat + q_CRhat_prime, w_FS + k, sigma` |

In particular, inserting the first two numerical arguments of Theorem 11.3
into Theorem 8.3 by position would substitute the extractor mass for the
ordinary VC-query mass. The March PDF does not license that operation.
This review has not obtained an author clarification or an erratum and does
not claim that the displayed interface has been formally amended.

### 3.2 Lemmas determine which query mass multiplies the error

The semantic answer can be derived without guessing a positional convention.
In [the March PDF](https://eprint.iacr.org/archive/2025/2166/1772467621.pdf),
Lemma 9.7, p. 65, bounds the **sum of total query masses on the ordinary VC
oracles** by `w_VC`. Its online-indistinguishability envelope is

\[
80\,T\,W_{\rm VC}\max I(P_{\rm online},T).
\]

For the paper's Merkle construction, Lemma 8.8, p. 56, bounds the instability
by `3T / 2^sigma`. Combining the two gives the named envelope

\[
\boxed{
\operatorname{OnlineUpper}(T,W_{\rm VC},\sigma)
=\frac{240\,W_{\rm VC}\,T^2}{2^\sigma}.
}
\]

Here `T` is the **total** oracle-query bound for the online game, including
all oracle purposes. `W_VC` is the total mass assigned specifically to the
ordinary commitment-oracle interfaces. Extractor and recording calls may
increase `T` even though their own masses do not multiply this particular
upper expression. Query mass is defined as a sum of squared selector-register
amplitudes in Definition 4.3, p. 29; it is a nonnegative real number and is not
restricted to an integer number of queries.

The proof of Lemma 9.7, pp. 69–70, supports this reading: the remaining
commutator terms are weighted by ordinary VC-query masses; the recording term
is handled by Lemma 9.13 and the purified multi-extractor commutes with the
splitting operator. Thus this named dependence follows from the proof's
explicit hypotheses, not from choosing whichever positional order gives a
smaller number.

The metric is the **square of a difference of square roots of acceptance
probabilities**. It must not be relabeled as an ordinary acceptance-probability
difference or as a norm with different squaring conventions. The constants in
the subsequent BCS expression belong to the paper's stated metric conversions.

### 3.3 Construction 11.11 has a separate budget question

Write `d = q_CRhat + q_CRhat_prime`. On p. 86, Construction 11.11 explicitly
runs VC checks at step 13. Its following query count includes up to `q_V`
queries for these checks and gives

\[
T=t+1+q_V+k+d.
\]

On p. 87, the displayed ordinary VC-mass bound is only `w_VC + d`. The same
smaller quantity appears in the online-error argument of Lemma 11.10 and
Theorem 11.3. Both full PDFs contain these displays. The local source review
has not established a justification for excluding the step-13 queries from
that mass bound. The separate commutativity term does not, by itself, prove
such an exclusion.

A conservative accounting of the displayed construction is:

| Interface purpose | Upper allowance for Construction 11.11 |
|---|---:|
| Total queries | `t + 1 + q_V + k + d` |
| Ordinary VC-query mass | `w_VC + q_V + d` |
| Purified multi-extraction mass | `w_MultiExtract + 1` |
| Recording mass | `w_FS + k` |

The added `q_V` is an upper allowance: `q_V` is the verifier's total query
complexity and therefore also bounds the portion used for its VC checks.
Each such ordinary query can contribute at most one unit of VC mass. The
allowances sum to at most `T` whenever the adversary masses sum to at most `t`.
If the implementation supplies a separately justified smaller VC-check cost,
it can be used only through an explicit documented refinement.

The conservative local substitution is therefore

\[
\operatorname{OnlineUpper}
  (t+1+q_V+k+d,\;w_{\rm VC}+q_V+d,\;\sigma).
\]

This is a derived conservative envelope for the displayed game, not a claim
that the authors stated this replacement, nor a complete repair or independent
validation of all later proof steps. A calculator must distinguish this local
accounting choice from verbatim evaluation of the printed theorem. An output
that uses the tighter printed mass remains conditional on resolving that
specific bookkeeping question.

## 4. Continuous maximum for a conditional BCS expression

The named online envelope makes it possible to define a reviewable arithmetic
expression without exchanging extractor and VC masses. This section derives
that expression; it supplies no real-protocol values for its inputs. The
[companion evaluator](../../scripts/w1_qrom_bcs_budget.py) implements this
named conservative expression with exact rational arithmetic and keeps all
implementation-security qualifications false.

Fix all protocol, instance, and proximity parameters. Assume a valid relaxed
RBR-knowledge envelope `K_RRBR(delta)` on the chosen statement set, the exact
state-restoration setting of Theorem 6.10, and the Merkle setting of Theorem
8.3. Denote this assumed nonnegative RBR envelope by `K`. In addition to `d`
and `T` above, define

\[
U=2t+1,
\qquad
Q=q_y+q_\Pi+\ell_{\max}n'_y.
\]

Theorem 6.10, p. 46, gives the state-restoration component

\[
80(t+k+1)(w_{\rm FS}+k)K+(t+k+1)k2^{-r_{\min}}.
\]

Theorem 8.3, p. 53, gives the following Merkle components, with their arguments
interpreted by purpose:

\[
\begin{aligned}
\operatorname{ComUpper}(q)&=240(q+1)2^{-\sigma},\\
\operatorname{ExtractUpper}(n)&=8n\ell_{\max}2^{-\sigma},\\
\operatorname{OfflineUpper}(q,w,Q)&=
 (160wq^2+16Q\log_2\ell_{\max})2^{-\sigma}.
\end{aligned}
\]

Multiplying these by the displayed Theorem 11.3 coefficients `4, 4, 8, 4`,
and retaining its final `2 q_V^2` commutativity term, produces an affine
objective in the adversary's masses:

\[
F(w_{\rm FS},w_{\rm VC},w_{\rm M})=C+a_{\rm FS}w_{\rm FS}+a_{\rm VC}w_{\rm VC}.
\]

For the conservative step-13 allowance in Section 3.3,

\[
\begin{aligned}
a_{\rm FS}&=320(t+k+1)K,\\
a_{\rm VC}&=(1280U^2+960T^2)2^{-\sigma},\\
C&=320(t+k+1)kK+4(t+k+1)k2^{-r_{\min}}\\
 &\quad +\bigl(32n_y\ell_{\max}+128Q\log_2\ell_{\max}
       +960(d+q_V)T^2+480q_V^2(t+k+q_V+2)\bigr)2^{-\sigma}.
\end{aligned}
\]

The coefficient of `w_M` is zero in these particular upper envelopes. It does
not follow that multi-extraction costs nothing: its calls already affect
`T`, `U`, admissibility, oracle interfaces, and the extractor's running time.
The masses satisfy

\[
w_{\rm FS},w_{\rm VC},w_{\rm M}\ge0,
\qquad w_{\rm FS}+w_{\rm VC}+w_{\rm M}\le t.
\]

Consequently, without rounding masses or assuming they are integral,

\[
\boxed{\max F=C+t\max\{a_{\rm FS},a_{\rm VC},0\}.}
\]

To verify this, each mass coefficient is at most the maximum coefficient, so
the linear part is at most that coefficient times `t`. Allocating all mass to
an interface attaining the maximum achieves the algebraic supremum over this
relaxed simplex. This is an exact maximum of the chosen upper expression; it
need not be achievable by a real malicious prover.

The printed-mass variant would replace `d + q_V` by `d` only in the constant
`960(d + q_V)T^2`. The conservative expression exceeds that variant by exactly

\[
960q_VT^2 2^{-\sigma}.
\]

Both variants retain the same total query bound `T`. They must not be merged
under one unexplained result name. A proof checker should retain the distinct
formula, its source revision, and the query-accounting assumption.

In the paper's complete binary Merkle construction, the committed lengths are
powers of two, so their maximum is also a power of two and `log_2(lmax)` can be
represented exactly as an integer. Other tree constructions need their own
mapping. All component domains must cover the enlarged query arguments,
including `2t+1` and `T`; checking an envelope only at `t` is insufficient.
Any missing RBR extractor, instance range, query cost, or VC/IOR mapping leaves
the project-level result unqualified. An upper expression above one is retained
as an upper expression, not converted into an attack estimate.

## 5. Theorem 10.6 and recursion obligations

The preceding [composition evaluator](../../scripts/w1_qrom_composition_budget.py)
can continue to cite the same expression: its source theorem has not changed
between the pinned PDFs. Theorem 10.6 begins on p. 72, with the error expression
and composed extractor on p. 73. Theorem 10.6 requires one common emulated
oracle `(Init, U1, U2)` for both reductions and matching intermediate strict
and relaxed relations. Definition 10.3, pp. 71–72, supplies the simulation,
commutativity, classical-query, and straightline-extraction properties; Remark
10.4 supplies monotonicity of the commutativity envelope.

The relevant enlarged query arguments remain

\[
\begin{aligned}
A&=t+q_{V_1}+q_{V_2}+q_{E_2},\\
B&=t+q_{V_1},\\
C_{\rm comp}&=t+2q_{V_1}+q_{V_2}+q_{E_2}
                    +q_{\widehat R_2}+q_{\widehat R_3}.
\end{aligned}
\]

The sufficient composed extraction expression, after substituting the
allowed minimum for the common commutativity error, is

\[
2\operatorname{ext}_1(A)+2\operatorname{ext}_2(B)
+2q_{E_2}^{,2}\bigl(q_{V_1}^{,2}
 +(q_{\widehat R_2}+q_{\widehat R_3})^2\bigr)
 \min\{\operatorname{com}_1(C_{\rm comp}),
       \operatorname{com}_2(C_{\rm comp})\}.
\]

The composed extractor first recomputes the first verifier's intermediate
instance, then calls the second extractor and the first extractor in that
order. These are query- and running-time costs that must be charged at each
permitted recursive composition. Merely having a recursively verified proof
or a shared hash name does not establish the common-oracle or middle-relation
premises.

## 6. What the version bridge does and does not discharge

All locations in this table refer to the pinned March PDF; the corresponding
January pages are identical.

| W1 interface | Paper evidence | Remaining concrete artifact |
|---|---|---|
| Actual semantics | IOR relations and relaxed relations in Section 3; committed relations in Definition 11.2, p. 78 | An exact relation map across Node, guest, VM, AIR, and every admitted recursion program and size. |
| Per-round knowledge | Definition 3.6, p. 26, requires a knowledge state function and deterministic polynomial-time RBR extractor; Theorem 6.10, p. 46, uses them. | The extractor and its per-round errors for the actual IOR. Degree or interactive soundness alone supplies neither. |
| Quantum state restoration | Definition 6.1 and Definition 6.4, pp. 41–42; Theorem 6.10 | Full statement set, challenge lengths, salt/transcript conventions, coherent moves, and uniform extraction cost over the accepted instance range. |
| Vector commitments | Definitions 7.1–7.3, pp. 49–51; Definition 8.2, p. 52; Theorems 8.3–8.4 | A mapping for actual encoding, salt, binary/root or cap structure, opening format, duplicate query handling, and commitment indices. The paper's distinct commitment-oracle indices are not the same thing as deduplicating repeated leaf queries. |
| Shared hashing | Separate oracle purposes in Construction 11.7, p. 81; common emulated oracle in Definition 10.3 and Theorem 10.6 | A joint model or reduction for all exposed leaf, branch, transcript, public API, and precomputation interfaces of the real primitive. Marginal uniformity does not establish this model. |
| Fiat–Shamir | Construction 11.7, p. 81, includes the explicit instance, commitment indices and roots, and salts in challenges; Theorem 11.3, pp. 78–79, supplies query amplification. | An exact encoding and sampler map, bias allowance, grinding accounting, and the enlarged query/mass budgets. The Section 3.3 bookkeeping question must remain visible. |
| Recursion | Definition 10.3 and Theorem 10.6, pp. 71–77 | Component extractors over all allowed programs and sizes, matching intermediate relations, and valid error domains at every amplified query bound. |
| Lifetime | Each displayed theorem quantifies its own query/adversary experiment. | A specified multi-instance failure event and lifetime budget, with justified aggregation across attempts and shared primitives. Single-instance expressions do not themselves establish that aggregate. |

The review therefore closes **the manuscript version-equivalence task** and
establishes **which named mass governs the online Merkle envelope**. It also
makes one additional budget question concrete. It does not turn either the
P3 conditional RBR estimate or the RISC Zero obligation list into a complete
non-interactive, quantum, recursive, or lifecycle security bound. Those
project-level bounds remain `null` until their implementation and composition
premises are supplied.
