# Native evaluation quorum V2

Status: an explicitly selected revision15 development protocol for the existing
fully replayed integer evidence V3 and composition V4 model profiles. The
evaluation threshold is a model-admission rule. It supplies no block weight,
consensus finality, independent-identity claim, or permission to install a Hepta
artifact.

## Problem and exact selected scope

The existing `native-public-evaluation-dev-v1` requires every frozen evaluator
to reveal. One absent key aborts that candidate. In its evidence V3/V4
composition, a participant can additionally submit a nonzero claim/evidence
hash before adoption and hold the candidate for its entire lifetime. These
historical rules remain intact under the old selector, including its regression
tests and stored bytes.

The new explicit selector is
`--evaluation-policy native-public-evaluation-quorum-dev-v2`. It can compose only
with `--model-profile linear-factor-evidence-dev-v3` or
`--model-profile linear-factor-composition-dev-v4`, and their existing supported
task profiles. Every node already loads the complete integer model, executes the
frozen tasks and controls, and checks each reveal against the exact recomputed
score and evidence digest. The new selector refuses the old attestation-only
model, factor-only profile and SmolLM profile. A smaller acceptance threshold
therefore does not replace native model computation with an attestor's opinion.

The authoritative
[registry](../../../../config/pon/public-evaluation-quorum-v2.json) explicitly
overrides only the old evidence policy's hash-only review hold in this fresh
combination. The old model/data/control contracts and empirical gain checks
continue to apply. `production_activation`, `objective_model_quality`,
`independent_governance_accepted`, `consensus_finality`, `execution_authority` and
`fresh_dataset_activation` remain false.

## Frozen roster and honest absence

Revision15 installs four **controlled development keys**, numbered0–3. Each
candidate freezes the complete installed roster excluding its author. It does
not claim that these keys have independent controllers. The native evidence
author policy also remains the existing fixed development roster; this is not a
new permissionless admission or identity-rotation protocol.

Let `n` be the size of this frozen non-author roster. Freeze
`q = ceil(2*n/3)` and retain the same denominator for the candidate's lifetime.
Previously evidenced disqualifications are recorded in
`disqualified_at_freeze`; those keys stay in the denominator and never count.
Freeze refuses when fewer than `q` non-disqualified keys remain. With the
installed four keys and an author in that roster, `n=3` and `q=2`.

Tags14 and15 keep their existing outer PNX1 transaction ownership, strict
signatures, nonces, fees and height phases. Two real, matching reveals from the
eligible keys can close the candidate even when the third key is absent. No
timeout creates a vote, score or evidence record. Reveals must match both their
prior commitment and the native empirical computation. A consistently signed
invented score still fails `MODEL_EVIDENCE_REVEAL` before counting.

At the mandatory transition after reveal offset47, count only non-disqualified
reveals. Group them by exact `(score, evidence_digest)`; one group must contain at
least the frozen `q` signers. Because `q > n/2`, at most one group can meet that
threshold in one branch state. The immutable closure records the actual matching
and eligible reveal counts, missing count, exact disqualified signers and count, score, evidence,
round, generation context and closure-record digest. It does not claim that
the same threshold establishes BFT agreement between forks: `n=3, q=2` alone
would not provide a general Byzantine finality certificate.

## Real conflicts, audit appeals and the adoption transaction

Tag16 retains the original objective evidence type: two full, strictly verified
signed PNX1 envelopes from the same evaluator, candidate, round and tag14 or15,
with different payloads. An opaque claim hash is not such evidence. The exact
conflicting identity is recorded in ordinary branch state and is excluded from
subsequent votes and current adoption counts, including other already frozen
candidates. Evidence does not replace the roster or reduce its denominator.

The original native M06 tag8 owner scans the current disqualification namespace
and rechecks both its bundle and every allocation component in the same state
transaction. That scan participates in MVCC conflict validation. A preceding
tag16 from another sender in the same block therefore invalidates a speculative
release that depended on that evaluator. A late conflict with an absent key
does not defeat the remaining sufficient real votes; a late conflict that leaves
fewer than `q` does block a new adoption.

Tag17 remains a bounded, signed participant audit record with an exact closed
result digest, nonzero claim/evidence digests and maximum16 appeals. In this
new profile it has no automatic veto, service suspension, work-weight effect,
score mutation or adjudication authority. Native invalid model relations still
fail full execution; real signed conflicts still remove the proven signer. A
general fraud-proof language and independent dispute governance are outside
this increment.

Adoption cannot rewrite the original closure. A later appeal/conflict cannot
invent reversal of a past external operation or payment. The ordinary ledger
rules govern accepted release, maturity, claims and branch rollback. Hepta's
physical operations, selector authorization, revocation and reconciliation
remain with their existing owners.

## Version, generation and storage boundaries

| Commitment | Historical selector | New explicit selector |
|---|---|---|
| Evaluation registry | public-evaluation-native-v1 | public-evaluation-quorum-v2 |
| Highest combined revision |13 for evidence V3;14 for composition V4 |15 |
| Frozen plan schema | pon-native-frozen-evaluation-v1 | pon-native-frozen-evaluation-v2 |
| Round domain | native-public-evaluation-round-v1 | native-public-evaluation-round-v2 |
| Reveal commitment domain | native-public-evaluation-reveal-v1 | native-public-evaluation-reveal-v2 |
| Closed result schema/domain suffix | v2 | v3 |
| Closure records domain suffix | v2 | v3 |
| Appeal identity domain suffix | v1 | v2 |
| Evaluation storage revision / record namespace |2 / evaluation-record-v2 |3 / evaluation-record-v3 |

The registry changes the network, parameters and evaluation-plan commitments.
Custom genesis-time startup also selects the new network label. Opening an old
SQLite store under the new selector, or a new store under the old selector,
refuses its context. There is no implicit migration, live activation or rewritten
old signature domain. The existing contribution/archive containers retain an
explicit versioned evaluation value; the new bounded subordinate records have
their own schema and namespace. Hydration refuses unknown revisions, mismatched
schemas and foreign prefixes. Each record and compact candidate remains within
the existing4096-byte limit, and record cleanup follows candidate/archive
retention.

The V2 frozen plan additionally commits the author, exact roster, frozen
disqualifications, threshold, dataset root and generation number. Here
`generation = floor(submitted_height/128)` denotes a candidate-round index. A
separate `native-public-evaluation-generation-v2` digest binds network,
parameters, family, model/evaluation plan, dataset root, actual parent release
and that index. Candidate round commitments bind the complete frozen plan.
The original ILF2 parent checks and tag8 actual-current-parent checks remain live.
Replacing a parent, replaying a previous round's commitment or downgrading the
storage marker cannot authorize the new candidate.

**This generation context is not a fresh dataset owner.** The installed25 public
historical rows remain unchanged and can be memorized. A valid24/25 parent can
be followed by a25/25 candidate, but on this same corpus no later candidate can
strictly exceed25/25. Fresh future windows, custody, lawful data access, consent,
historical exclusions, independent evaluators and activation of new evaluation
material require their own protocol and evidence. A reported window history or
ordinary accepted-task receipt must not be relabelled as revision15 approval of
an arbitrary Hepta artifact.

## Completion and no-update behavior

| Round outcome | Native result | Subsequent behavior |
|---|---|---|
| At least `q` matching eligible real reveals, positive native gain | complete-scored | May adopt from offset56 after full native relation and budget checks |
| At least `q` matching reveals, score0 | complete-scored at zero | Cannot become an individual positive release; a V4 component may enter only a bundle with verified positive omission marginal |
| Insufficient matching reveals after offset47 | aborted / evaluation-aborted | No synthetic retry or timeout approval; ordinary bounded archive and round cleanup |
| New real conflict leaves fewer than `q` before adoption | Original closure retained; tag8 refused | Candidate cannot adopt through that compromised certificate; current-parent/expiry rules still apply |
| Not enough non-disqualified installed keys at next freeze | PUBLIC_EVAL_ROSTER | No automatic key replacement or quorum reduction; another explicitly governed profile is required |
| No useful candidate | No release | Chain maintenance and existing model continue under their original owners |

An unadopted evaluated candidate expires under its existing64-height lifetime.
An aborted candidate is removed with its candidate round; the original closed
archive persists for the existing256-height retention. These are bounded
no-update outcomes, not promises that learning will always produce improvement.
Failures beyond the stated key-availability threshold remain failures and are
not disguised by a reduced quorum or an independence flag.

## Source and executable checks

The existing
[evaluation owner](../../../../trillionnium/crates/trnm-mvcc-fee/src/public_evaluation.rs)
dispatches to the explicitly versioned
[V2 count and generation implementation](../../../../trillionnium/crates/trnm-mvcc-fee/src/public_evaluation/quorum_v2.rs).
Actual candidate, commit/reveal, closure, composition and release paths use it;
the CLI selector and both durable evaluation observation APIs select the same
domains. Closure and adoption recompute the complete frozen round commitment;
adoption also checks the retained closure's candidate and quorum against the
frozen plan. A well-formed replacement roster cannot reuse an earlier round
commitment even when its generation subcontext is unchanged.

Both durable observation APIs bind the candidate to one exact transaction in
the root-checked intake packet. Historical tag6 retains its existing membership
rule under the original model selector. Factor profiles use the existing
canonical tag23 `FactorWitnessV2` decoder and recompute the contribution identity
from the installed network/parameters and actual sender. The decoded family,
parent release and artifact, candidate artifact, update identity, components
root, submission round and slot must match the retained native contribution.
A different candidate, wrong owner, duplicate membership, another transaction
tag or noncanonical ILF2 bytes cannot supply that anchor. These checks preserve
the complete ancestry, historical state roots, closure and active-generation
validation; they do not replace native model execution with payload parsing.

The independent
[Python oracle](../../../../formal/pon-nakamoto-v1/native_evaluation_quorum_oracle.py)
recomputes17 retained cases and genuine Ed25519 conflicting envelopes without
calling native code. Cases include old all-reveal/missing semantics, one or two
absences, no synthetic votes, zero score, mixed evidence, frozen and late
disqualification, other-candidate conflicts, record-only appeals and the next
generation. The
[native parity test](../../../../trillionnium/crates/trnm-mvcc-fee/tests/evaluation_quorum_v2.rs)
compares exact frozen/round/closure/digest/storage bytes and refusal outcomes.
These seeded state-machine vectors do not substitute for native model execution.

The actual
[V3 node regression](../../../../trillionnium/crates/trnm-pon-node/tests/model_evidence_v3.rs)
uses signed model/commit/reveal/appeal/conflict/release transactions,56 real PNW1
blocks, SQLite reopen and a heavier57-block branch. It also checks false native
scores, same-block conflict-before-release MVCC ordering and old-round replay.
Both views assert the exact admitted tag23 transaction, remain reusable after
reopen, and reject their prior generation after that reorg. A narrow native
observer regression admits two different factor candidates in one real packet
for each V3/V4 model profile and checks both views plus malformed, mismatched
and duplicate intake refusal cases.
The
[V4 native executor regression](../../../../trillionnium/crates/trnm-pon-node/tests/model_composition_v4.rs)
uses two actual release parents and complete empirical/composition replay,
including zero standalone component scores, a hash appeal and actual matured
claims in both generations. It executes all M06 heights1–204 consecutively,
retains the original reward-queue capacity invariant and checks every maturity
height and total issued subsidy; these are not PNW1 packet histories. The
[CLI regression](../../../../trillionnium/crates/trnm-pon-node/tests/evaluation_quorum_cli.rs)
checks real selector startup, incompatible models, new/old store separation and
reopen.

The required `protocol-contract` CI lane executes the independent oracle tests
and separately recomputes the retained vectors in read-only mode. The CI
contract checker rejects omission, duplication, relocation or replacement of
either command, including fixture regeneration through `--write`. The existing
`rust-baseline` workspace/all-targets invocation executes the native parity,
model, Node and CLI targets; their presence does not grant a hosted-CI result.

```sh
python3 -m unittest discover -s formal/pon-nakamoto-v1 -p test_native_evaluation_quorum_oracle.py -v
python3 formal/pon-nakamoto-v1/native_evaluation_quorum_oracle.py
cargo test --locked --manifest-path trillionnium/Cargo.toml -p trnm-mvcc-fee --test evaluation_quorum_v2
cargo test --locked --manifest-path trillionnium/Cargo.toml -p trnm-pon-node --lib factor_candidate_membership_is_exact_for_evidence_and_composition
cargo test --locked --manifest-path trillionnium/Cargo.toml -p trnm-pon-node --test model_evidence_v3
cargo test --locked --manifest-path trillionnium/Cargo.toml -p trnm-pon-node --test model_composition_v4
cargo test --locked --manifest-path trillionnium/Cargo.toml -p trnm-pon-node --test evaluation_quorum_cli
```

Test selectors document executable assertions. Actual execution status belongs
to exact-source native logs and receipts; a new selector or a retained reference
vector alone does not certify a test run, model efficacy or deployment readiness.
