# Native integer model evidence V3

Status: an explicit development successor with native empirical admission and
test-unit settlement. It is not public-model efficacy, independently governed
evaluation, training provenance, or a new mining-hardness primitive.

## Installed context and ownership

`--model-profile linear-factor-evidence-dev-v3` selects revision13 with
`--evaluation-policy native-public-evaluation-dev-v1`. The legacy maintenance task
profile is supported. The separately installed
`consensus-maintenance-continuity-dev-v1` task successor can compose with this model
profile; both exact policies enter parameters and the higher revision is retained.
An unknown or incompatible task/evaluation selector refuses startup.

The [installed evidence policy](../../../../config/pon/model-evidence-v3.json),
model family, factor policy, evaluation policy, and task material all enter the
native parameter or evaluation-plan commitments. The model family additionally
binds this admission profile. Network label, family, parameters, plan, complete
genesis models and state root differ from revision11. This is not a hot upgrade.
Historical profile bytes and meanings remain unchanged.

M06 [model evidence](../../../../trillionnium/crates/trnm-mvcc-fee/src/model_evidence_v3.rs)
uses the existing integer factor model/state owner and public evaluation owner.
There is no new transaction tag, Cargo package, dependency, SQL table, trainer,
authority cache, or reward ledger. Existing tag23 carries ILF2 and produces a full
ILM2 candidate as described in [factor admission V2](NATIVE_INTEGER_FACTOR_CANDIDATE_V2.md).
Existing tags14–17 and8–9 retain their owners. The new context adds their explicitly
documented gates below.

## Frozen material, not a newly discovered model improvement

The installed corpus contains one row per source file: choose the smallest task
ID in each file from the historical
[evaluation A](../../../../evidence/pon-native-node-v1/model-current/model/evaluation_a.json).
There are25 distinct source groups. Each row binds its historical task ID,
source path and content SHA256, exact257 integer features, and class label.
The source-group hash is SHA256 of the source path. Unknown dimensions, labels,
out-of-range features, repeated source groups/content identities or a changed
source-path binding refuse the installed policy. This is a fixed public,
retrospective dataset. It is available to candidate producers and can be memorized.

The four full control parameter arrays are copied exactly from `current`,
`best_single`, `mean_merge` and `pooled` in the historical
[E3 bundle](../../../../evidence/pon-native-node-v1/model-current/model/evaluation-bundle.json).
The policy retains that bundle's source commit, original control artifact IDs and
SHA256 of the source bundle and row file. Their little-endian integer coefficients
are committed in the new context and installed as full ILM2 models in ordinary
genesis State. These are historical integer routing controls, not new LoRA/full-tune
LLM runs or independent operators. The current native parent is an additional
control, including after adoption of a successor model.

## Native empirical score and reveal binding

Every admitted tag23 candidate first passes full parent loading, BA computation,
range/no-op checks and exact-update duplicate checks. Native M06 then loads the
complete candidate, actual parent and all four installed controls. It executes the
family's exact integer router and logits with lowest-index tie breaking on every
frozen row. With one row per source group, the arithmetic is exactly equal-group
accuracy. It computes

    strongest = max(current parent correct, all four control correct counts)
    score = floor(max(candidate correct - strongest, 0) * 1000000 / row count).

There are at most32 tasks,4 controls and16 admitted candidates per round. One
candidate evidence computation executes at most444096 scalar coefficient-feature
products, apart from decoding, hashing and storage. A release can recompute its
bundle and at most16 allocation contributions; these costs are bounded and are
not claimed to be cheap compared with mining. The profile is not succinct ML proof
verification, generalization assessment or the historical E3 statistical test.

The retained record binds N/P/family/plan/policy/task roots, candidate and actual
parent artifact IDs, all four control IDs and counts, candidate/parent/strongest
counts, exact score, and a fresh-domain digest. State uses one bounded
`model-evidence-v3:<candidate>` row. The contribution carries its exact evidence
digest, score and admitted source/root-work identity. No producer-supplied score,
prediction or acceptance Boolean is trusted.

Every existing tag15 reveal must match that native score and evidence digest in
addition to the original strict signature, frozen roster, height phase and prior
commitment. A self-consistent commitment to a fabricated positive score or another
evidence digest refuses `MODEL_EVIDENCE_REVEAL`. Zero-gain candidates may retain
their failed evidence and close at zero; they cannot be adopted or rewarded.
Tag8 recomputes the complete evidence again for the bundle and every allocation
contribution, compares the stored digest and accepted score, and requires positive
gain. Merkle leaves, totals and release identity continue to be independently checked.

`components_root` binds the allocation membership committed by the candidate
publisher. Native execution does not derive the bundle's parameters from those
components or prove that a component caused the bundle's gain. Each candidate is
compared with its actual parent and the four frozen historical controls; the gate
does not require the bundle to outperform every newly submitted component. Thus
valid membership and individually positive empirical scores do not establish
complementary composition, causal attribution, or a fair division of rewards.
Those properties require a separately specified composition and attribution rule.

This proves the specified empirical integer computation. Labels, source rights,
truthful provenance, independence, private held-out quality and future benefit do
not follow. Public acceptance flags remain false. Distinct model parameters can
have identical predictions, and frozen benchmark memorization can attain full
accuracy without supplying a useful new public model.

## One bounded source budget across admitted aliases

The installed development policy maps exact author public keys to source IDs before
candidate admission. Development keys0 and1 deliberately share one source in order
to exercise aliases. Keys2 and3 have separate declared sources. Unknown authors
refuse `MODEL_EVIDENCE_SOURCE`; this fixed roster is not permissionless identity or
proof that declared sources have independent controllers.

`root_work = H(domain, network, parameters, round, admitted source)` binds one source
budget across all its accounts, candidate factors, components and changing parents
within the same128-height round. `model-source-v3:<round>:<source>` stores at most4
accepted candidate intakes and at most100000 reserved test-unit payouts. A failed
candidate still consumes its successful intake; a new nonce or known alias cannot
restore that allowance. Pure rejected transactions do not partially mutate this row.

At tag8, native execution sums the actual integer payout amounts for every
allocation leaf sharing a source, adds previous reservations in that round, and
refuses a source-cap overrun. The publisher's existing account debit funds the
release only after every gate passes. The cap is reserved at publication, so claims,
aliases and a second parent within the round cannot reserve it again. Rounding
dust follows the existing ledger rule. This is a finite known-source budget bound;
it does not establish fair Shapley allocation or stop concealed common controllers.

## Finite pre-adoption review and monetary disposition

The original round freezes candidate/commit/reveal periods, closes after offset47,
and first permits adoption at offset56. A participant's valid tag17 appeal admitted
after closure and before offset56 places this candidate under
`MODEL_EVIDENCE_REVIEW_HOLD`. Tag8 refuses it for the rest of that candidate's
lifetime. There is no automatic positive resolution, timeout vote or fabricated
fraud verdict. The candidate expires under the original64-height lifetime; a new
round is a distinct attempt with new evidence and source intake. No release budget
has been debited while this pre-adoption objection is unresolved.

Appeals admitted at or after offset56 remain bounded audit records, including after
adoption. They do not change an old empirical score, recall an already paid claim,
or invent adjudication authority. Such remedies and public evaluator governance
remain explicit work. This window is vulnerable to transaction censorship and
participant veto; local development signatures do not solve either problem.

An accepted release continues to use its original20-height maturity,1000-height
claim window, single-claim proof, finite reserved balance and deterministic expiry
refund. Reorganization reverses candidate evidence, source reservations, adoption
and ledger claims with their branch. It does not rewind physical inference,
application outboxes or prior external payouts.

Source counters are removed after their round. Evidence survives with an active
candidate or its evaluation archive and is removed when both disappear. Existing
256-height closed-archive retention applies. Full control models remain retained
as installed dependencies. Ordinary model/release cleanup and the existing bounded
monetary refund mechanism retain their owners; no new mandatory insertion is added.

## Executable evidence and its limits

[Native regression tests](../../../../trillionnium/crates/trnm-pon-node/tests/model_evidence_v3.rs)
use signed PNX1, actual PNW1, full native state, SQLite reopening and real competing
branches. They exercise computed score/digest binding, malformed control material,
zero gain, pre-adoption objections, known-source aliases, funded caps, release,
mature claims and rollback. The positive candidate is explicitly a deterministic
memorization fixture built from these public test rows. A passing settlement test
does not establish positive prospective model efficacy.

The combined continuity/model regression selects both the revision12 maintenance
task and revision13 model profile. It checks their distinct native context against
each profile alone, runs signed contribution, public evidence, release and mature
claim transactions through actual maintenance blocks, and reopens the stored
chain. Continuing through closed-archive retention checks capacity reservations
at evaluation closure and cleanup of source counters, model evidence and archives.
This integration regression exercises the capacity invariant on its actual state;
the separate continuity tests cover admission at the full key-capacity boundary.

```sh
cargo test --locked --manifest-path trillionnium/Cargo.toml -p trnm-pon-node --test model_evidence_v3
```

Actual prospective datasets, independently controlled operators and evaluation,
truthful source admission, authorized training/consent, LLM execution, poisoning
and forgetting controls, complete GPU/serving/retention costs, general functional
copy handling, funded public dispute adjudication and mining hardness remain
unaccepted. This profile makes a concrete native subset enforceable without
promoting those external claims.
