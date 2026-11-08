# W1 proof-chain research observations, 2026-11-08

Status: **PINNED MANUSCRIPT VERSION BRIDGE CLOSED; END-TO-END QROM HOLD**.

This packet extends the exact #778 head
`0c830e0be8939ce80c8443c9ad68021b87343a00`. It compares the separate P3 #783
candidate `cc836dfc13ef0006eb0878abd8cb5eca9a76bec0` without merging its source
or transferring its numerical bound to RISC Zero. The containing Git commit
binds the new generator, test, workflow, documentation and evidence bytes.
The older head is input/profile provenance, not the revision of the new code.

## Results and their limits

1. The two official January and March ePrint PDFs were retrieved in full and
   identified by SHA-256. All 102 pages were compared using two whole-document
   Poppler text modes and per-page PyMuPDF text and RGB pixels. Differences
   occur only on pages 1, 4, 100, 101 and 102. All 95 formal-body pages 5–99
   match. This closes the **pinned version-correspondence** task; it does not
   independently prove every theorem or qualify W1.
2. The March text retains the online-interface positional discrepancy. The
   new hypothetical BCS adapter uses the named ordinary-VC mass justified by
   Lemmas 9.7/8.8 and explicitly charges the verifier's step-13 VC checks.
   It maximizes the resulting affine expression over a real shared-mass
   simplex, checks enlarged query domains and `q_V >= k`, and preserves
   unknown premises. No author erratum or real implementation instantiation
   is asserted.
3. A new source-pinned RISC Zero replay computes all 69 transcript events,
   244 base samples, seven caps, 217 cap pair hashes, 50 query draws and 350
   Merkle openings with 4,050 sibling nodes for the historical join seal.
   It consumes exactly 55,667 words. This is a hash-transcript/opening replay;
   AIR, DEEP-ALI, FRI-folding and terminal-evaluation equations are omitted.
   It is not a complete receipt verifier or a quantum extractor.
4. The separate P3 arithmetic reproduces `(2001/4000)^64` and its displayed
   negative logarithm, approximately `63.95384529640614`. Exact rational
   comparisons determine minimal query counts for explicitly hypothetical
   multipliers. The source estimator's other terms and optimization remain
   relevant. Neither this number nor insufficient proof bounds establish an
   attack or unconditional security bits.

The umbrella [proof-chain review](../../docs/security/W1_QROM_PROOF_CHAIN_20261108.md)
maps all eight interfaces. Detailed reviews cover the
[manuscript](../../docs/security/W1_QROM_MANUSCRIPT_REVIEW_20261108.md),
[RISC Zero replay](../../docs/security/W1_FRI_QUERY_REPLAY_20261108.md), and
[P3 expression](../../docs/security/W1_P3_QUERY_EXPRESSION_20261108.md).

## Evidence index

| Artifact | Scope |
|---|---|
| [proof-chain-status.json](proof-chain-status.json) | All fifteen historical obligation IDs, one closed version sub-obligation, fourteen other obligations retained, eight-interface mapping and null complete/lifetime bounds |
| [manuscript-pdf-manifest.json](manuscript-pdf-manifest.json) | Official frozen PDF URLs, byte counts and complete-file hashes |
| [manuscript-comparison.json](manuscript-comparison.json) | All 102 per-page text/pixel comparisons, renderer/extractor versions, complete text differences and theorem inventory |
| [fri-query-replay.json.gz](fri-query-replay.json.gz) | Complete fresh replay, including every challenge, query, cap and sibling path; compressed without a timestamp |
| [query-expression.json](query-expression.json) | Exact P3 expression and explicitly hypothetical query-count rows |
| [bcs-unknown.json](bcs-unknown.json) | No unstated numeric defaults; actual system bounds remain unknown |
| [bcs-example-input.json](bcs-example-input.json) / [bcs-example.json](bcs-example.json) | An invented, explicit arithmetic example; never assigned to either implementation |
| [p3-source-manifest.json](p3-source-manifest.json) / [p3-dependency-source-manifest.json](p3-dependency-source-manifest.json) | Fixed application and upstream sources, including the unverified `p3-security` archive correspondence |
| [required-tests.json](required-tests.json) / [named-controls.json](named-controls.json) | Pinned required names and actual registered, started and successful test identities |
| [validation.json](validation.json) | Commands, observed results, code/hash binding, initial limitations and validation scope |
| [artifact-manifest.json](artifact-manifest.json) | Byte counts, SHA-256 and Git-blob IDs for the final packet and new source files, excluding itself |

## Executed controls

The fresh named execution completed **69 distinct tests**, with no skips,
expected failures, missing names, duplicated names or early completion.

| Suite | Actual successful tests |
|---|---:|
| P3 exact query expression | 11 |
| Fixed RISC Zero transcript/opening replay | 13 |
| Existing exact sequential-composition evaluator | 16 |
| Existing conditional component evaluator | 13 |
| New conservative BCS expression | 11 |
| Named-control completion checks | 5 |

Separately executed existing source-integrity and project-boundary suites
passed **43 and 16** tests. These are implementation/guard observations, not
cryptographic assumptions. Counts of independent review scenarios, repeated
runs or fractional arithmetic points are not added to the 69-test total.

The [controls log](controls.log) and [separate completion result](completion.log)
retain actual output. The [execution snapshot](execution-source-before.json)
binds every materialized Python script plus the specified boundary inputs,
workflow and roster observed at execution. Its unchanged after-snapshot is
retained separately. A subsequent workflow-only completion-guard change is
explicitly recorded in `validation.json`; the Python generators and test
modules were unchanged. The final workflow has its own independent review
and syntax check bound to its final hash.

Independent review records retain their **own reviewed source hashes**:

- [Runner/query review](independent-runner-query-review.json): isolated
  negative controls and a different exact query-count algorithm; includes the
  runner's early-zero observation and its completion-gate remedy.
- [BCS numeric review](independent-bcs-numeric-review.json): numeric/schema
  rejection, unknown propagation, enlarged domains, 32 affine scenarios and
  1,152 fractional mass points on the final evaluator.
- [BCS component expansion](independent-bcs-component-review.json): 96
  independent arithmetic cases on the earlier, explicitly identified snapshot
  before the `q_V >= k` input-compatibility guard. This is not represented as
  a run of the final source.
- [Workflow review](independent-workflow-review.json): actual report and
  completion inputs, plus clearly labeled synthetic source/stage metadata
  for rejection testing. This does not claim a hosted CI run occurred locally.

The new workflow runs on both the exact PR head and the prospective merge.
It requires fresh output, full tracked-source identity before/after, named
completion, independent literal qualification checks and every stage's actual
success. An early zero exit without a completion artifact is insufficient.

Local preparation materialized all 2,475 tracked non-evidence source files
at the integration base and selected historical evidence. The working copy
does not contain every historical evidence blob and retains skip-worktree
entries. Consequently **local full tracked-worktree verification is not
claimed**. The unchanged hosted source checker remains required. Cargo and
rustc were unavailable on the local command path, so no new Rust build,
Clippy, formatting, prover performance or native regression is claimed.
Initial missing-link observations are retained. A bounded later restoration
materialized **1,594 exact historical blobs / 108,413,449 bytes** without
changing their contents or index flags. The subsequent full repository check
still exits 2 on a missing historical archive; **19 historical link targets**
remain absent from this partial checkout. The fixed Git identities are in
[the remaining-target list](historical-missing-targets.json), and the actual
[final check result](repository-final-result.json) and [raw log](repository-final.log)
retain the failure. The complete restored-file identity list is preserved in
[historical-restoration.json.gz](historical-restoration.json.gz).

All **50 local links in the five new Markdown documents**, plus the **five
added plan links**, resolve to actual files; [the scoped result](new-link-scope.json)
does not imply a full repository pass. The hosted complete checkout is the
remaining route for complete source/link verification.

## Reproduction

From a complete checkout, reserve a fresh directory and run:

```bash
bash scripts/project-preflight.sh --audit
python3 scripts/ci/w1_qrom_proof_chain_controls.py run --output /tmp/w1-proof-chain-fresh
python3 scripts/ci/w1_qrom_proof_chain_controls.py check --output /tmp/w1-proof-chain-fresh
python3 scripts/w1_fri_query_replay.py --output /tmp/w1-proof-chain-fresh/fri-query-replay.json
python3 scripts/w1_query_expression_feasibility.py
python3 scripts/w1_qrom_bcs_budget.py
python3 scripts/w1_qrom_bcs_budget.py --example
```

Use a new directory on each attempt. The hosted workflow also independently
checks completion records, sources and report qualifications. To repeat the
paper comparison, obtain both exact archived PDFs and use
`scripts/w1_cdhz_revision_compare.py` as described in the manuscript review.
That optional comparison needs PyMuPDF and Poppler; the 69 named controls use
the standard Python library.

## Remaining acceptance

The closed item concerns correspondence of two manuscript versions only.
The actual relation/compiler proof, full RRBR knowledge extractor, admissible
quantum commitment extractor, joint shared-hash model, exact FS mapping,
recursive relation/cost composition and lifetime budgets remain unresolved.
Post-quantum authorization and quantum work/chainweight also remain separate
acceptance lines. All end-to-end, production and consensus qualifications stay
false; complete project security bits and lifetime failure bounds stay null.
