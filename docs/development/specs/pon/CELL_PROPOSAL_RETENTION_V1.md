# Local retention of a reviewed Cell proposal V1

This contract adds one explicit local operation to the existing
[TCA1 adoption owner](NODE_LOCAL_CELL_ADOPTION_V1.md). A proposed complete
version and the version kept for use are different identities. The operation
records both without changing an existing Retain action or interpreting a
local choice as training NoUpdate.

The sole development plan remains the
[canonical plan](../../TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md).
This is a local review and persistence contract. It does not qualify an ordinary
Hepta learning iteration, independent evaluation, release settlement or FinalUse.

## Inputs and immutable local policy

`CellAdoptionOwnerV1::retain_proposal` receives:

- a nonzero 32-byte operation identity;
- the original exact expected `CellAdoptionSnapshotV1`;
- a `CellCandidateObservationV1` containing the proposed TCV1 commitment,
  its direct parent commitment and one exact evidence-reference commitment;
- the nonzero 64-byte commitment to the local owner's original review.

The caller is the existing trusted local policy owner. Public candidate bytes,
an evaluator name or a Chain/Hepta checkpoint do not acquire this authority.
In particular, a HEPLCP04 structural report marked `DENY_ALL` cannot invoke
this operation or grant permission to execute its proposal.

The snapshot policy digest binds the immutable node, policy and Cell-scope
identities, model-data/execution boundary and capacities. This operation cannot
replace those inputs, change consensus or fees, rotate Root, install software
or modify the fixed model interface.

## Atomic decision and evidence binding

The original SQLite immediate transaction, file lease, full TCA1 audit,
monotone observed recovery floor, request replay check, expected-snapshot CAS
and finite decision budget remain in force.

Inside that same transaction, the proposal must already exist in the local
catalog, differ from the selected version, and have that selected version as
its direct parent. The supplied parent must match the retained complete
metadata. The exact evidence-reference commitment must be a member of the
proposal's retained observations. An unknown proposal, substituted parent,
unobserved reference or stale expected snapshot refuses before any new event
is committed.

On a new successful operation the owner commits the original TCA1
`Retain(current)` event. Its candidate field continues to identify the selected
parent. Its revision advances once, its selected version stays unchanged, and
its review commitment binds the separate proposal as specified below.

The returned `CellProposalRetentionReceiptV1` exposes `proposal()`,
`local_review_commitment()` and `retention_receipt()`. The first two are the
original typed inputs; the third is the ordinary TCA1 retention receipt. Its
`evidence_set_commitment()` still describes the retained parent's reference
set. The proposal's selected observation is bound separately by the new review
commitment. Other observations may be appended later without changing the
identity of the original typed request.

An evidence reference is a commitment to supplied records. This operation does
not verify their signatures, evaluator independence, quality judgment, training
cost, settlement or chain inclusion. It can record a local retention decision
without declaring the proposal qualified.

## Review commitment encoding

The new commitment is SHA-512 over the following exact concatenation. There is
no JSON encoding or implicit conversion between 32-byte and 64-byte identities.

| Field | Encoding |
| --- | --- |
| Domain | ASCII `TRNM/Cell/LocalProposalRetentionReview/v1` followed by one zero byte |
| Operation identity | 32 raw bytes |
| Expected snapshot length | Unsigned 16-bit big-endian byte count |
| Expected snapshot | Exact original TAS1 encoding |
| Proposed version | 64 raw bytes of the complete TCV1 commitment |
| Proposal parent | Original optional-commitment encoding: byte `01`, then 64 raw parent bytes; None is refused |
| Proposal observation | 64 raw bytes of the exact retained evidence-reference commitment |
| Original local review | 64 raw bytes |

TAS1 contains its original magic, policy commitment, big-endian revision,
optional selected commitment and history commitment. Thus the new binding
includes the original node policy, state predecessor and retained version.
The resulting 64 bytes occupy the existing TAD1 `review` field.

TCA1 application identity, SQLite schema, TAD1/TAS1/TAP1 bytes, existing action
tags, policy digest and ordinary decision/history hash domains are unchanged.
An original reader can replay the event as Retain(parent). Raw V1 Retain still
refuses a target different from the selected version. No existing signed
domain or stored field is reinterpreted and no schema migration is performed.

## Retry, cold readback and provenance limits

The caller must retain the complete original operation identity, expected
snapshot, proposal observation and local review reference. After reopening
against a separately retained recovery floor, those exact inputs can be
submitted again. The currently retained catalog membership is checked before
the matching historical receipt is returned. The same identity with a changed
proposal, evidence observation, review or expected snapshot refuses.

An exact retry after later choices returns the original historical receipt.
It neither rewinds the current snapshot nor grants permission to consume the
retained parent's old version. Current use still requires the original fresh
snapshot, selected-byte guard, current execution pins and real effect-owner
authorization. Lost replies reconcile the original operation identity; they
do not justify creating another identity and applying a second decision.

The database stores the new review commitment, not its complete typed preimage.
The commitment cannot reconstruct the original request or external evidence.
Ordinary TCA1 `open`, `status` and parent consumption continue to verify the
ordinary Retain(parent) history only. If a proposal that no other decision
references is removed from the catalog, that original history may remain
valid; a typed retry with the original inputs must refuse the missing proposal.
An ordinary successful open is not evidence of successful typed readback.

A trusted raw `decide` caller can supply the identical constructed review
commitment. A subsequent typed retry can then return a matching wrapper after
checking the proposal's currently retained observation. This proves the
present structural binding to the stored retention event; it does not prove
that `retain_proposal` was the historical entry point, that its checks ran at
the event time, or that the proposal was already observed at that time.
The owner does not attest execution provenance. Evidence of a historical
authorized call requires its original execution owner and separate records.

Restoring the database and an old recovery floor together still provides no
freshness guarantee. The prior independent-floor custody requirement remains.

## Explicit operator CLI

`trnm-cell-adoption retain-proposal` takes the normal owner database, operator
policy, approved anchor and independent recovery-floor arguments, plus:

```text
--request-id HEX32
--expected-snapshot ORIGINAL_FLOOR_JSON
--proposal-commitment HEX64
--proposal-parent HEX64
--proposal-evidence HEX64
--local-review HEX64
```

The proposal fields come from the exact local `observe` result. The operator
must retain the original expected snapshot for retries and separately preserve
the latest observed recovery floor. These are different roles after later
decisions. All original strict operator-file and argument checks remain active.
Output separates the proposal, original local review, inner retention receipt
and current observed recovery floor. It grants no use authority.

Hepta bundle digests and complete TCV1 commitments are separate identity
systems. This CLI does not authenticate a bundle-to-TCV1 mapping, import a
Hepta decision or install ordinary Generator/Evaluator/Selector/consumer owners.

## Validation boundary

The native controls cover proposal/parent identity separation, unchanged raw
Retain semantics, exact replay after additional observations and cold reopen,
later adoption with old-receipt refusal at selected use, known alternative
proposal/reference conflicts, unknown/current/wrong-parent refusals, original
commit cuts and lost replies, journal tampering, missing-proposal typed refusal
and the raw-entry provenance limitation. CLI controls compare Adopt, Defer and
Retain across separate local owners and verify actual selected cache bytes.

These tests establish only their executed component contracts on their recorded
source. Synthetic complete-version bytes do not establish model benefit or
independent operation. A valid block may have no model contribution; training
NoUpdate remains a separate outcome. Neither the new operation nor its receipt
awards mining, model-contribution or service payment, and it does not change the
ordinary end-to-end learning or production qualification counters.

## Source owners

- [Owner transaction and typed entry point](../../../../trillionnium/crates/trnm-data-availability/src/cell/adoption/store.rs)
- [Receipt type and review encoding](../../../../trillionnium/crates/trnm-data-availability/src/cell/adoption/types.rs)
- [Native controls](../../../../trillionnium/crates/trnm-data-availability/src/cell/adoption/tests/retention.rs)
- [Operator CLI](../../../../trillionnium/crates/trnm-data-availability/src/bin/trnm-cell-adoption.rs)
- [CLI controls](../../../../trillionnium/crates/trnm-data-availability/tests/cell_adoption_cli.rs)
