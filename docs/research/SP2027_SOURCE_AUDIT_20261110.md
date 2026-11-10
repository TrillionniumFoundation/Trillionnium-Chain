# S&P 2027 public-source audit snapshot — 2026-11-10

This record supports the publication continuation in the
[authoritative development plan](../development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md).
It records observed public evidence and research boundaries. It does not certify
a new execution, production activation, manuscript readiness or submission.

## Identity and scope

- Default main: dd6e1c3cbeacbdc532b0679297835b3a0aac78f0; complete recursive tree
  1,267 entries, not truncated.
- Publication branch base: e4abb172147e941b62483652b0ceabaae4317624, the observed
  head of PR #876, which retains the current #847 integration lineage.
- Complete tracked inventory at that base: 27,884 paths, including 1,651 Rust
  files, 1,412 Python files, 31 workflows and 22,826 evidence paths. These counts
  overlap by language/location and are not maturity scores.
- Six nonempty open-PR pages yielded 546 unique PRs; two subsequent pages were
  empty. This was sequential live enumeration, not an atomic snapshot.
- All M00–M17 maturity entries, critical work/admission/confirmation paths,
  selected current contracts and primary evidence were reviewed. This is full
  inventory/module coverage with focused semantic audit, not every-line review
  or a new run of every experiment.

The [source register](sp2027-20261110/source-register.json) pins selected heads,
execution identities, evidence deliveries, scope and exclusions. The
[open-PR inventory](sp2027-20261110/open-pr-inventory.json) is an observed index;
unselected branches are not thereby integrated or accepted.

## Current observations

| Area | Evidence-backed finding | Boundary |
| --- | --- | --- |
| Native work | PreparedTask retains A×B; each fresh challenge still requires its transcript work. Full verification follows the cheap task/ticket filter. | Reuse does not imply free mining; a new ticket does not imply a new useful output. |
| Native confirmation | The legacy path checks successor depth and accumulated required work and visits ancestry to genesis. It returns finalized=false and execution_authority=false. | A six-depth observation is not a proved failure probability or permission to execute external effects. |
| Original service | aaa3c539 / run42781760995: 0/3 complete campaigns, 0/9 phases, 6/27 scheduled confirmations within the original window; 15 recorded, 12 unreached. | Archived execution, not rerun on the publication branch. All six successes are baselines. |
| Separate History diagnosis | df927b6f / run42793318645: nine terminal inner PUBLIC_REQUEST_DEADLINE outcomes; first observed boundary admission 4/9, submit_result 5/9. | Different source/run from the row above; do not pool denominators or infer a repaired causal mechanism. |
| Common restore | #878 jointly restores owner SQLite, anchor remembered head and an equally old valid recovery floor; old history is accepted. A surviving newer floor rejects before transport/mutation. Native suite 9/9. | Controlled mock anchor and native signatures; no operationally independent freshness source or general exactly-once claim. |
| Real model recovery | #879: 280,269,602 B, 30 manifests, 95 chunks, RS(6,4), 570 publications; two slots unavailable and caches removed; 380 verified shard reads and two sealed forwards in 36.047064473 s under the original 300 s clock. | Single host, six directories; no independent WAN custody, paid lifecycle, ordinary Hepta FinalUse or statistical speedup estimate. |
| DFT sharing | #871 full-receiver wall median 0.515773328 s baseline versus 0.527050337 s candidate; CPU 0.8741635 versus 0.8785715 s. | One task, retained-proof replay, zero new complete proofs; benefit not established. |
| QROM/accounting | #873 has 298 methods / 34 harnesses on a13c56ca, plus scoped locked graph/fmt/Clippy observations. | Current all-algorithm work lower bounds and whole-system security remain unknown. Counts do not establish native service or cryptographic qualification. |

All 18 module entries retain native_product_integrated=false and
independent_accepted=false. This does not prohibit a rigorously scoped security
paper. Publication requires a new defensible result and sufficient evidence
for its stated scope; it does not automatically require the whole product to
be deployed.

## Research contribution boundaries

Three separate questions can organize the evidence:

1. **Receiver availability:** identify a causal failure linking complete
   receiving/validation/storage cost to independently confirmed honest service.
   Confirmed goodput is part of this same evaluation, not an extra contribution
   merely because it has a separate report.
2. **Producer cost attribution:** determine whether a legal reusable history
   invalidates a concrete resource or credit assertion. One explicit legal
   schedule establishes an attainable upper cost, not a universal lower bound.
   Existing caching alone is not a novel attack.
3. **Authority and recovery:** identify a nontrivial composition problem across
   owner, model version, chain view, independently surviving freshness and
   external effect. Signature validity and anti-rollback are distinct; known
   indistinguishability under complete common restore is not a new theorem.

Broad whole-chain PQ, storage and throughput claims should not be separated
into manuscripts unless each has its own independent scientific result.

Recent primary work makes these boundaries necessary:
[arbitrary-MatMul PoUW](https://arxiv.org/abs/2504.09971),
[Hollow-LLM](https://arxiv.org/abs/2607.28884),
[DoSVER/DoSDET](https://doi.org/10.1145/3658644.3690329),
[commit-time authorization](https://arxiv.org/abs/2607.10487),
[The Forking Way](https://www.ndss-symposium.org/ndss-paper/the-forking-way-when-tees-meet-consensus/)
and [RIFL](https://doi.org/10.1145/2815400.2815416).
A catalogue of existing techniques is not enough to establish novelty.

## Evidence discipline for the continuation

Each reported claim must distinguish implementation source, executed binary,
evidence-delivery commit and current manuscript source. Keep operation identity,
all attempted/unreached outcomes, fixed budget, trust-domain assumptions and the
actual measured endpoint. Hash equality identifies bytes; it does not certify
execution provenance, freshness, honest operators or model usefulness.

For receiving-cost studies, collect decode/auth/full verification/admission/
persist/History/independent-confirmation/ACK spans without double-counting nested
CPU. Compare healthy no-pressure, matched transport, early and late rejection,
valid costly inputs, cold/warm/churn state and equal total sender budgets.
Separate development traces from frozen confirmation traces. Existing 4-second
Host and 30-second campaign gates keep their original definitions; new research
profiles must be explicit and cannot erase prior failures.

For recovery studies, declare exactly which state survives each fault. Test
correlated restore, clone writer, stale signed facts, revocation, reorganization,
ACK loss and possible-commit timeout with actual effect readback. Without a
suitable provider completion/idempotency/query contract, unresolved outcomes
remain Unknown.

## Immutable public evidence

- [Module maturity](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/e4abb172147e941b62483652b0ceabaae4317624/config/pon/module-maturity-v1.json)
- [Native W1](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/e4abb172147e941b62483652b0ceabaae4317624/trillionnium/crates/trnm-crypto-primitives/src/pon_work.rs)
- [Native Node](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/e4abb172147e941b62483652b0ceabaae4317624/trillionnium/crates/trnm-pon-node/src/store.rs)
- [Original service readback](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/e4abb172147e941b62483652b0ceabaae4317624/evidence/pon-open-consensus-20261110-29db/original-service-readback-summary.md)
- [Separate History diagnosis](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/bcc0d2369e81d85c001190ea4c8ee0b1778e178d/evidence/pq-root-terminal-history-boundary-20261110/README.md)
- [Scoped QROM native checks](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/617b6ee73759429781f0b6ff073072ec1a16d724/evidence/pon-four-qrom-composed-20261110/native-a13-20261110/README.md)
- [Common restore](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/391a92248f0268aa5238eb1e2763fc6849ce4016/evidence/pq-root-co-restore-contrast-20261110/README.md)
- [Model cold recovery](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/30ce6e99c5d0d86e6563a49786e8b1e41b44c6c6/evidence/cell-paged-model-release-34e09-20261110/README.md)
- [DFT negative result](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/f2ad7e1389588a9913e308df8633277ae7c22f4d/formal/pon-nakamoto-v1/w1_node_adapter_research/evidence/dft-sharing-20261110-ai395/README.md)

## This documentation delivery

Only the publication-plan section and these public-source audit records are
changed. No native source, acceptance threshold or activation flag changes.
Fresh checks cover project boundary, changed-document links, JSON consistency
and diff scope. Archived Cargo/Clippy/native outcomes remain attributed to their
original source; this documentation successor does not inherit a full test pass.
