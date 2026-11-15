# W1: evidence and proof interfaces across the P3 and RISC Zero candidates

Date: 2026-11-08. Status: **RESEARCH CONTINUATION; END-TO-END QROM HOLD**.

This continuation strengthens implementation evidence for the quantum-proof
chain. It does not supply a complete knowledge extractor, a concrete shared
hash-to-QROM reduction, or an adopted adversarial lifetime budget. The
post-quantum authorization, computation-proof, quantum-work/chainweight, and
production decisions remain separate.

## 1. Two immutable candidate identities

The integration base for this continuation is
`0c830e0be8939ce80c8443c9ad68021b87343a00`, the published head of
[PR #778](https://github.com/TrillionniumFoundation/Trillionnium-Chain/pull/778).
The P3 candidate is an explicitly external comparison at
`cc836dfc13ef0006eb0878abd8cb5eca9a76bec0`, the published head of
[PR #783](https://github.com/TrillionniumFoundation/Trillionnium-Chain/pull/783).
These are different source trees. A successful check on one is not evidence of
a successful check on their combination.

| Parameter | P3 research profile | RISC Zero frozen outer recursion profile |
|---|---|---|
| Base field | Goldilocks | BabyBear, p = 2013265921 |
| Extension degree | 2 | 4, X^4 + 11 |
| FRI inverse rate | 4 | 4 |
| Folding factor | 2 | 16 |
| Query repetitions | 64 | 50, with replacement |
| Terminal object | Constant terminal polynomial | At most 256 extension coefficients |
| Proof/recursion scope | Research W1 AIR; no RISC Zero control catalog is imported | Fixed guest/VM plus allowed recursive control catalog; the saved outer program is join.zkr |
| Existing numerical statement | Approximately 63.9538 bits for a stated conditional RBR expression | Component/recursive-interface arithmetic with unresolved implementation premises |
| Complete noninteractive quantum lifetime bound | Unknown | Unknown |

The P3 source is its
[pinned proof configuration](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/cc836dfc13ef0006eb0878abd8cb5eca9a76bec0/formal/pon-nakamoto-v1/w1_public_stark_research/src/proof_config.rs).
The RISC Zero source is the
[implementation contract](../../config/pon/w1-qrom-implementation-v1.json),
[implementation map](W1_QROM_IMPLEMENTATION_MAP_20261107.md), and the
[formal-obligation review](W1_QROM_FORMAL_OBLIGATIONS_20261107.md).

The 63.9538 quantity is a value of a conditional sufficient expression. It is
neither an end-to-end security certificate nor a discovered attack with that
work factor. No component estimate, stored digest width, or fixed receipt
measurement is converted into unconditional project security bits here.

## 2. What an executable transcript check can establish

The earlier `w1_fri_transcript_audit.py` deliberately stops at source, encoding,
geometry and RNG scheduling. Its documentation explicitly excludes permutation
evaluation, root reconstruction, challenge generation and opening checks.
That leaves a concrete, testable implementation interface between the source
map and the bytes of the historical proof.

The new replay work follows the frozen verifier's actual order: protocol and
circuit context; public outputs and raw po2; code/data commitments; accumulator
mix and commitment; constraint mix, check commitment and DEEP point; the U
coefficient commitment; FRI batching and round commitments; the terminal
polynomial commitment; then query generation and the Merkle openings. A replay
must use the actual Montgomery representation, digest byte order, cap geometry,
RNG pool state, and sampling routine. It must not replace these by an ideal
independent challenge generator.

The frozen FRI path maps a position using `quot = pos / domain` and
`group = pos % domain`, then carries `group` into the next round. Consequently,
distinct initial queries can have identical later positions. Report each
original draw and the repeated positions. The number of distinct positions is
an observation, not a license to change the protocol's 50-query theorem input.

Even a successful replay proves only the stated fixed-input transcript/opening
subclaim. It does not check the AIR constraints, DEEP equation, FRI fold
identity or final polynomial evaluation, establish a knowledge extractor,
certify every accepted recursive program, or establish production Node
admission. The saved proof's identity and historical validation stay attached
to their original source and input scope.

## 3. Eight interfaces and their actual proof deliverables

The existing fifteen obligation identities remain in force. The eight rows
below are a grouping of those obligations, not a replacement or a shorter
acceptance list.

| Interface | Required mathematical or implementation artifact | What the present evidence can support | Remaining closure condition |
|---|---|---|---|
| Actual semantics | Explicit accepted Node, guest, VM, AIR, strict and relaxed intermediate relations, with canonical encodings and a semantics-preserving map | Fixed sources, guest/image identity, relation and constraint-DAG observations | Prove the map for every accepted input, program, error path and reachable trace size; a degree bound or saved proof is insufficient |
| Round-by-round knowledge | A concrete extractor and relaxed RBR knowledge bound for the entire implemented IOR and statement class | Parameter and FRI source maps; conditional component arithmetic | Include batching, lookup/permutation constraints, DEEP events and the terminal object; degree or interactive soundness alone is insufficient |
| Quantum state restoration | The exact adversary/extractor interface, auxiliary state and challenge-adaptive restoration argument | Named theorem interface and exact enlarged-query arithmetic | Discharge the theorem's uniform quantum-state and restoration hypotheses with a proved RRBR envelope |
| Vector commitments | Quantum multi-extraction for the actual leaf/branch encoding, salt, cap, length, repeated-index and prefix behavior | Source-pinned encoding map, control-tree reconstruction and the new fixed-input replay work | Prove admissible coherent extraction for the implemented commitment, including all allowed lengths and extraction-query costs |
| Shared hash | A joint model for all permutation/hash/RNG interfaces, exposed precomputation and overlapping encodings | Concrete source aliases and finite joint-oracle countermodels are retained | Establish a compatible joint emulation/reduction, or introduce and separately qualify a new construction/profile; purpose labels alone do not create independent oracles |
| Fiat--Shamir | Complete statement/context absorption and a proof for the actual stateful challenge schedule, sampling bias and grinding | Source order, raw/Montgomery boundaries, fixed-input draw/opening replay | Map the actual transcript transformation to the selected theorem, including adaptive masses and enlarged query domains |
| Recursion | Every allowed program and size, matching middle strict/relaxed relations and one common emulated oracle | Default-27 control IDs and root are reconstructed in earlier evidence; the saved outer program is identified | Prove each recursive reduction, composition and extractor cost uniformly; catalog membership does not prove program semantics |
| Lifetime | A justified joint adversarial query envelope and total error expression for all uses and instances | Existing ledger includes failed, aborted, offline, recursive, adaptive, delegated and unclassified phases | Supply truthful budgets and uniform component guarantees over all histories; honest permutation counts and successful receipt counts are insufficient |

The declaration of a relation should contain its exact byte encoding and
compiler/profile identity, not just a human name. At every recursive edge,
compare both the strict middle relation and its relaxation. The sequential
composition interface additionally requires the same `Init/U1/U2` emulated
oracle. Matching identifiers are necessary bookkeeping checks; proofs are
required to establish their semantics.

## 4. The pinned January-to-March version bridge is now closed

The [manuscript review](W1_QROM_MANUSCRIPT_REVIEW_20261108.md) uses both
actual official archived PDFs, rather than an indexed excerpt:

| Revision | Official archive | SHA-256 |
|---|---|---|
| January 1, 2026 | [1767247987.pdf](https://eprint.iacr.org/archive/2025/2166/1767247987.pdf) | `215a62b9a1b5144c89ae103aaabaf6049eab23f7ccb23130bc7d65d597c1eac9` |
| March 2, 2026 | [1772467621.pdf](https://eprint.iacr.org/archive/2025/2166/1772467621.pdf) | `2cfb88c76732d9f39f4b1943b4aabc0390dd3d17830d91d910c38e16e4bb5a30` |

Both have 102 pages. Complete text extraction and per-page RGB comparison
identify differences only on pages 1, 4, 100, 101 and 102: the date,
introductory citation keys and bibliography changes/reflow. All 95 pages from
5 through 99, containing the formal definitions, theorems and proofs, match
in extracted text and rendered pixels. This closes the version-correspondence
sub-obligation for these two byte-pinned manuscripts. It is not an independent
proof of every theorem, and says nothing about any future revision.

The positional interface discrepancy survives in the actual March PDF:
Definition 7.3 lists the online arguments as `w_M,w_VC`, while Theorems 8.3
and 8.4 list `w_VC,w_M`; Theorem 11.3 uses the definition order. Lemma 9.7
instead identifies the quantity semantically as ordinary VC query mass.
Together with Lemma 8.8 it supplies the named expression
`240 * W_VC * T^2 / 2^sigma`. The new adapter uses that semantic argument,
not a silent positional substitution. No author's erratum is asserted.

A second bookkeeping issue is retained explicitly. Construction 11.11,
step 13, makes up to `q_V` ordinary VC checking queries, included in its total
query count on page 86. The displayed ordinary-VC mass bound on page 87 does
not include this addend. The conservative adapter charges
`W_VC = w_VC + q_V + q_R_input + q_R_output` instead. This is a documented
upper-accounting choice, not a claim that the authors' tighter bound has been
disproved; justifying its exclusion would require a separate argument.

The historical 6.10/10.6 reports and their original source-access observations
are retained unchanged. A new report records the completed correspondence,
semantic interpretation and conservative accounting separately. The larger
implementation, extraction, joint-oracle and lifetime premises remain open.

## 5. Sound budget composition

There are two distinct tasks: proving a component envelope and evaluating it.
The repository's exact-rational tools address the second. Supplying an assumed
polynomial with a matching hash does not accomplish the first.

For January Theorem 10.6, the left extraction envelope is required at
`t + q_V1 + q_V2 + q_E2`, the right envelope at `t + q_V1`, and the
commutativity envelope at
`t + 2*q_V1 + q_V2 + q_E2 + q_R2 + q_R3`. The commutator coefficient is
`2*q_E2^2*(q_V1^2 + (q_R2 + q_R3)^2)`. A bound valid only at `t` cannot be
substituted at these larger points. Squared-norm, amplitude and probability
errors must retain their own conventions.

Theorem 11.3 additionally maximizes over shared query masses. A coherent query
can distribute amplitude among uses: the masses are not necessarily integers.
An implementation must optimize over the stated continuous domain or prove a
conservative relaxation. Replacing all masses simultaneously by the full
budget is not an exact optimization; testing just integer vertices is not
valid for an arbitrary nonlinear envelope either.

A legitimate lifecycle conclusion needs an explicit real-to-model reduction
and the compiled multi-instance error at the complete enlarged query budget.
It cannot be constructed by adding eight convenient component bit counts.
A union bound across attempts needs no independence. Reusing a single-run
conditional guarantee for adaptive attempts requires a bound uniform over all
allowed prior histories and auxiliary quantum information, or a separate proof
of each required unconditional event bound. All such bounds must use the
appropriate complete query envelope. Sequential extraction losses must first
be included at the appropriate recursive interfaces.

The new [BCS expression adapter](../../scripts/w1_qrom_bcs_budget.py) combines
only explicitly hypothetical component envelopes. Put `d=q_R_input+q_R_output`,
`U=2*t+1`, and `T=t+1+q_V+k+d`. After the semantic/conservative substitutions,
the objective is affine:

`C + a_FS*w_FS + a_VC*w_VC`, where

- `a_FS = 320*(t+k+1)*kappa_RRBR`;
- `a_VC = (1280*U^2 + 960*T^2)/2^sigma`;
- `C` retains finite randomness, extraction, offline opening-set,
  fixed online VC mass and commutator contributions.

Over nonnegative real masses whose sum is at most `t`, its exact maximum is
`C + t*max(a_FS,a_VC)`. This follows from nonnegative affine coefficients and
is attained at a vertex; it is not a general vertex rule for nonlinear
security envelopes. The additional charge for the step-13 verifier checks is
exactly `960*q_V*T^2/2^sigma`. The adapter requires declared component domains
to cover both `U` and `T`; missing domains block the conditional expression.
It also requires `q_V >= k`, because the compiled verifier itself performs
the `k` Fiat--Shamir queries in Construction 11.7.
Its numerical example is invented and never assigned to either real profile.

Unknown premises remain unknown even when a numerical factor happens to be
zero. A computed upper expression larger than one is recorded as an unhelpful
sufficient expression, not clamped into a claim of an attack. A sufficient
expression that cannot meet a target is evidence about that analysis route,
not a lower bound on the protocol's actual failure probability.

## 6. The next substantive proof artifact

For each candidate independently, the next formal deliverable is a named
reduction with source/parameter identity, accepted statement class, strict and
relaxed relations, extractor, oracle interface, error envelope and query-cost
domain. Begin with a bounded admitted program/size class that can actually be
proved. Extending the class requires an explicit new coverage proof.

For P3, the source-specific shared compression/permutation construction and
full AIR-to-RRBR argument precede any claim that the conditional FRI number
certifies the complete protocol. The unrestricted collision construction does
not by itself establish reachability at legal committed nodes or a forged W1.
A retained construction needs the missing restricted-domain/joint-model proof;
a replacement construction needs a new profile and measured compatibility and
costs.

For RISC Zero, the radix-16 fold, nonconstant terminal object, full recursive
relations, padding cases and actual source/compiler boundaries require their
own mapping. A binary-folding/constant-terminal theorem cannot be imported
merely because both protocols are called FRI. The Johnson-regime sufficient
expression discussed in the prior review has a sampling term greater than
`2^-50` at inverse rate four and fifty queries. That observation neither proves
an attack nor closes the protocol mapping; it prevents that particular
expression from being advertised as a stronger certified RRBR bound.

A full computation-proof theorem would still leave quantum work/chainweight
and post-quantum authority as independent tasks. This continuation makes no
production activation or end-to-end post-quantum certification claim.
