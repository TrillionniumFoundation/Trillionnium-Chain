# PoCO economic security and operation contract v1

Status: **candidate implementation contract and bounded attack model; no economic,
consensus, testnet or production activation**. Primary semantic owner M12;
M01/M02/M03/M05/M07/M08/M10/M11/M13/M15 produce or consume the stated facts.
M17 owns the executable analysis, not the truth of external identity claims.

## Authority and unchanged protocol

The frozen authority is `docs/protocol/poco-bft-v0/05-poco-weights-bond-and-slashing.md`
together with consensus, epochs, cryptography and light-client specifications 01–07.
This supplement does not edit their bytes, signing domains, validator selection,
weighted quorum, unweighted leader schedule, or activated parameters. It specifies
missing producer/consumer obligations and implements a separate non-authorizing
analysis. A proposed controller cap or penalty is a model input, not a new v0 rule.
No local model result, administrator setting or self-authored review may leave shadow.

There are three distinct assertions:

* A strict BFT verifier authenticates the required signatures and state relations.
* An application authenticates finalized consumption, bonds, identities and cutoff
  projection according to an explicitly commissioned profile.
* An economic review assesses whether the profile's identity, independence, custody,
  incentives and attack-cost assumptions are credible in the deployment.

Success in one assertion is not success in the others. In particular, PoP proves
key control, not independent beneficial ownership; two bilateral signatures do not
prove independent demand; a hash identifies a report, not an independent witness.
The existing min(consumption capacity, slashable bond capacity, maximum power)
rule bounds declared weight by collateral but does not prove economic usefulness.

## Exact amount and concentration admission

The candidate settlement risk model keeps its existing fixture root and integer
accounting. Monetary values and products are checked unsigned u128; booleans,
floating-point values, NaN, negative values and overflows reject. Actor/task inputs
are bounded before full materialization. The model uses at most 4,096 actors and
1,024 task facts; these are analysis limits, not network consensus parameters.

Concentration admission uses the exact inequality:

```text
exposure * 10000 <= total_exposure * maximum_exposure_bps
```

Both products must fit the selected arithmetic domain. A rounded display ratio
must never decide admission. For exposure 40,001, total 100,000 and cap 4,000 bps,
`floor(exposure*10000/total)` is 4,000, but the exact fraction exceeds the cap and
must reject. Equality is admissible; overflow refuses instead of saturating.
Apply this independently to provider identity and declared controlling owner.

The current model's beneficial-owner/funding strings are caller assertions.
`identity_claims_authenticated=false` is returned even when every numerical
constraint passes. The model is not an oracle for the runtime's `independent`
relationship classification. Existing approved fixture bytes/root are unchanged.

## M10/M01 identity and relationship production

A future authoritative identity observation must bind subject and controller,
issuer identity and key generation, chain/profile, evidence digest, observation
height, validity interval, conflict classification and current revocation frontier.
The issuer and trust policy come from installed authority, not the same request.
Public self-labels, web profiles, shared IPs and graph proximity cannot independently
produce trusted ownership or authorize punishment.

The producer must resolve all parties used by a selected consumption certificate:
consumer, provider, beneficial controller, verifier and funding source. A missing,
expired, revoked, conflicting or unsupported observation remains unresolved; it
must not default to independent. Current v0 related, reciprocal and unresolved
relationships contribute zero eligible units. This contract does not invent a new
wire relationship enum or silently change frozen certificate eligibility.

Required operation sequence is:

```text
bounded request -> installed issuer/profile -> exact signature and current
revocation -> subject/role/funding binding -> committed observation -> cutoff view
```

Updates compare expected previous revision and preserve the original historical
observation used at each cutoff. Revocation stops future eligibility according to
its finalized effective boundary; it does not rewrite historical signed sets.
Lost update replies recover the exact operation and predecessor/target, not a new
identity generation. Unknown source is unavailable; malformed proof rejects;
contradictory committed identity history fences the responsible owner.

The implementation and deployment of this authenticated identity producer remain
open. In particular, declaring two different controller strings cannot certify
that two validators are independent. An unresolved identity policy prevents
non-shadow economic activation; it is not repaired by a self-signed statement.

## Consumption, wash funding and graph diagnostics

M05 authenticates the complete signed intent. M10 binds task/lease/attempt and
funding, M11 supplies the selected result/evidence authority, M12 settles the exact
bilateral sequence, and M07/M08 supply the finalized cutoff projection. The tuple
must bind consumed units, meter/version, prices, payer/provider, original funding,
result, certificate identity and finalization epoch. No caller's aggregate replaces
complete authenticated cutoff state or duplicate/nullifier checks.

The accounting audit distinguishes gross transfers from net external expenditure,
refundable principal, subsidies, provider rebates, fees and rewards. Moving funds
among controlled identities must not be treated as independent economic cost.
Bonds are committed principal, not necessarily money an attacker must irreversibly
spend. Collateral ownership, asset valuation, liquidity and rehypothecation need
separate facts; the executable model does not estimate them.

`possible_consumption_cycles` finds strongly connected components of declared
payer-to-provider flows, including self-loops and cycles of length greater than
two. It is bounded to 100 controller labels and 1,024 flows. Cycles are diagnostic:
legitimate businesses can trade cyclically, and an acyclic attacker can still
collude. The output issues no eligibility, slashing, or blacklist instruction.
Absent graph edges prove neither independence nor the absence of wash funding.

Acceptance must include duplicate certificate replay, provider identity splitting,
funds cycling through at least three actors, verifier/provider common control,
pre-cutoff revocation and incomplete cutoff enumeration. Local model labels do not
satisfy real funding provenance, privacy-preserving independence or Sybil policy.

## M12 bond and withdrawal lifecycle

A future runtime bond position uses one globally unique position identity, owner,
asset, amount, state, activation epoch, locked-until epoch, outstanding obligations,
revision, and finalized creation/transition evidence. A position cannot be pledged
twice in one selected set. Reuse across epoch roles requires a single liability
ledger covering the overlapping obligations, not duplicated balance records.

For target epoch t, frozen eligibility requires active slashable state and:

```text
t + evidence_window_epochs < locked_until_epoch
unbonding_delay_epochs >= evidence_window_epochs
unbonding_delay_epochs > light_client_trusting_period_epochs
```

Equality at locked-until is withdrawable and therefore not covered. Epoch arithmetic
is checked u64, money and weight products checked u128. A same-epoch jail does not
change the frozen quorum denominator. Policy may stop local signing while the
unchanged set remains authoritative, which can reduce liveness.

Withdrawal must compare current revision, all active and accountable epoch
obligations, challenge status and finalized height. Reserve/release, principal
movement, nullifier and resulting receipt belong in one canonical transaction.
On response loss, exact replay returns the original receipt; no second debit or
release is permitted. An unknown obligation is unavailable, not permission to
withdraw. Operator requests cannot bypass evidence and trusting horizons.

The bounded risk analyzer marks a short or prematurely unlockable declaration
uncovered and assigns it zero guaranteed slash backing. It does not claim that
valid-looking declarations are actually held or slashable. The same bond ID twice
within one analyzed set rejects. Authenticating actual escrow custody remains an
M07/M12 runtime and external-evidence obligation.

## BFT safety, liveness and leader concentration

For positive total weight W, q = floor(2W/3)+1. A blocking coalition can withhold
weight W-q+1. Two q-weight signer sets intersect in at least 2q-W weight. These are
integer bounds, not a proof that a particular malicious coalition can construct
conflicting finality. Safety still depends on protocol locks, correct persistence,
ancestry and the strict Byzantine-weight assumption 3B < W.

The model computes exact minimum declared collateral/assumed penalty over whole
controller groups with bounded 0/1 dynamic programming. There are at most 100
validators and total weight 100,000 in the analyzer. Exceeding this analysis bound
returns unavailable/reject for the model; it must not invalidate a peer block.
Per-position assumed penalties are rounded before aggregation. Blocking by itself
is not necessarily a slashable offense. The minimum collateral in a blocking
coalition is not a minimum bribery cost or a guaranteed penalty.

Frozen v0 leaders rotate by canonical validator ID count, not voting weight.
Therefore voting-weight concentration and proposal-slot concentration must both be
observed. The regression has nine weight-1 validators under one declared attacker
and four independent weight-100 honest validators. The attacker has only 9/409
weight, below one third, yet controls 9/13 proposal slots and can occupy nine
consecutive slots in the chosen canonical ordering. This is a liveness/censorship
exposure counterexample, not a finality break or a benchmark result. A deployment
needs progress and recovery tests for such distributions as well as equal-weight
fixtures. A weighted/random leader replacement would require explicit protocol
versioning, not a local optimization in this patch.

## M02/M03/M08 epoch transition and retirement

Old and new sets must satisfy their fault and trust assumptions separately.
`analyze_handoff` checks consecutive epoch policies and analyzes each declared set;
it cannot verify a joint certificate, commit a checkpoint or activate a signer.
The sum of old/new voting power is never a quorum denominator for either role.
Membership overlap does not make two role-specific signatures interchangeable.

The causal order is unchanged: execute checkpoint C, certify the two empty seals,
strictly commit C, issue a fresh pre-handoff receipt, retire old ordinary custody,
authorize the intended handoff roles, verify their separate quorums, persist and
join the new native/Safety/checkpoint/custody cut, then release the initial timer.
Do not require a joint certificate in the receipt needed to produce its signatures.
New-only commissioning verifies old finality independently; removed validators get
no new ordinary owner. Seals have no application effects.

Every crash cut must retain source/target identity and original signatures. A
post-sign lost reply is not evidence no signature escaped. Recovery joins fresh
actual owners and an independently trusted monotonic frontier before any new key
use. Neither this contract nor a local sidecar supplies that independent frontier.
Current real-owner runtime timeouts remain separate blockers; passing these pure
models is not an execution receipt for the existing V8/V9 integration tests.

## M12 economic profile operation: specified, not implemented activation

A complete proposed economic profile needs an exact protocol version, profile
identity, predecessor, effective epoch, identity/relationship policy, meter policy,
asset and collateral rules, concentration metrics, objective offense taxonomy,
slash fractions, rounding, reporter rewards, correlated-fault treatment, unbonding
and challenge horizons, and downgrade/recovery rules. Missing fields are unresolved,
not zero or convenient defaults. A future command and codec must be independently
reviewed before any such fields become consensus input.

The operation must authenticate a finalized authorization under the existing
configuration, compare the expected predecessor, validate arithmetic and horizons,
reserve storage/recovery capacity, and retain the immutable proposal before epoch
activation. An installation result can become effective only at the exact accepted
handoff. Response-loss replay preserves one proposal and one activation; conflicting
same-identity bytes reject. Unknown profile/version rejects without changing the
current set. Lack of independent audit blocks promotion, not normal shadow work.

A bare parameter commitment, true Boolean or successful model cannot replace the
accepted release, authenticated decision and implementation required by the frozen
activation boundary. This patch deliberately supplies no new activation constructor.
Mainnet slash fractions and identity/anti-collusion assumptions remain unresolved;
the analyzer's explicit hypothetical fraction is never exported as their answer.

## Objective offense processing and long-range recovery

M11/M12 may punish only an enabled objective offense with exact signed evidence,
context, offender identity and evidence-window admission. Derive the canonical
offense ID, compare any prior disposition and atomically apply the one-time
penalty/reward/nullifier. An exact retry is read-only; a conflict is not a second
reward. Network timeouts, graph cycles, an unavailable verifier or disputed service
quality alone cannot be relabeled double-signing. A challenge must retain funding,
response/maturity windows and bounded evidence, without making disagreement itself
proof of fraud.

An old valid signature can remain cryptographically valid after its collateral is
withdrawn. M13 consequently needs an independently provisioned recent trust anchor,
its age policy and authenticated configuration history, not only hashes in a peer's
self-consistent chain. Reject stale/unknown anchors for live admission. Download
and stage may proceed inertly, but no signing or authoritative root publication is
allowed before trusted installation. Complete local rollback of database and
sidecars must not manufacture a newer external checkpoint.

## Executable evidence and limits

`simulations/economics/test_economic_security_v1.py` exercises exact provider and
controller concentration, type/overflow and iterator bounds, unchanged settlement
fixture identity, weighted quorum intersection enumeration, controller aggregation,
leader-slot counterexample, strict collateral/withdrawal boundaries, duplicate
pledges, exact coalition DP against exhaustive subsets, separate handoff assumptions,
input permutation stability and multi-party cycle detection.

These are self-authored Python model regressions. They do not execute Rust Core,
verify signatures, authenticate controller identities, prove held collateral,
calibrate asset values or profits, or replace independent audits and physical
fault campaigns. The existing G2E Rust/SQLite tests and all source/merge gates remain
required. Reports always retain false identity/collateral/activation authority.

The operation supplement `docs/modules/TRNM_OPERATION_DESIGN_V2.md` states the
producer/consumer obligations. Its coverage report keeps all-operation completeness
false until the actual enabled surface has been classified and independently
reviewed; 18 headings or 102 design rows cannot authorize any of the operations.

## Primary background references

* Ethereum developer documentation, Weak subjectivity:
  https://ethereum.org/en/developers/docs/consensus-mechanisms/pos/weak-subjectivity/
  — recent independently obtained checkpoints address the PoS long-range trust
  problem; this is background, not an Ethereum implementation claim for PoCO.
* STAKESURE, arXiv:2401.05797: https://arxiv.org/abs/2401.05797
  — distinguish cost of corruption from profit from corruption. This model
  supplies neither a market valuation nor an end-to-end security guarantee.

Repository-specific rules remain the pinned frozen v0 specifications. Adopting an
external paper's design or changing those rules requires separate explicit review.
