# Q1 — exact source-attested task admission and output identity

Owners: M00 owns the bounded description, M01 checks strict signatures and actual matrix
material, and existing M02/M06/M07 owners admit and retain parent-relative registrations.
The [registry](../../../../config/pon/qualified-work-task-v1.json) is new development
material. It does not change existing work/devnet/ledger parameters or activate a network.
The name QualifiedWorkTask identifies a candidate description; it is **not** scientific
qualification of work hardness, useful learning, genuine demand or lawful authorization.

## Scope and the two verified facts

`trnm_protocol::qualified_work_task::QualifiedWorkTask::decode` returns only a structural
description. No Boolean, unsigned JSON, decoded manifest or self-published hash can create
`AuthenticatedTaskStatement` or `DevelopmentTaskAdmission`; their constructors are private.

`verify_development_statement(packet, context)` checks exact context, caller-pinned
source/demand/source-record/authorization/withdrawal/availability identities, signed height
bounds, retention arithmetic and the source's strict Ed25519 signature. This is an explicit
development attestation trust class. The caller must obtain its expected identities from
its independently configured owner, rather than copying them out of the received packet.
A signature authenticates the source's statement, not the truth of demand, rights, source
provenance, legal consent, current final-use permission or remote retention. A mutable
local allowlist cannot redefine otherwise valid network history.

`verify_development_admission(packet, TaskMaterial { model,input,a,b }, context)` additionally
checks actual artifact lengths and hashes, derives both matrices from the supported recipe,
compares every supplied A/B entry and recomputes the existing matrix TaskId. It returns a
private material-bound development fact. This is the business/CLI admission path; chain
registrations containing only a signed manifest remain explicitly **source-attested**.
Keeping bytes outside a transaction does not promote its declaration to a material proof.

## Canonical QWT1 and QWA1 bytes

All integer fields use little endian; hashes are raw32 bytes. Length is checked before
any allocation or signature verification. Unknown enum values, reserved bits, trailing
bytes, unknown profile/recipe, absent identities and noncanonical field values reject.
No optional fields or accepted-hardness encoding exist in this version.

| Offset | Field | Bytes |
|---:|---|---:|
| 0 | QWT1 | 4 |
| 4 | version=1 | 2 |
| 6 | purpose: maintenance=1, adapter=2, evaluation=3, inference=4 | 1 |
| 7 | cost_class=1: fixed experimental transcript64 | 1 |
| 8 | numeric_encoding=1: canonical LE32 field | 1 |
| 9 | hardness_status=0: NotAccepted | 1 |
| 10 | reuse=1: fresh header attempts, one result meter | 1 |
| 11 | reserved=0 | 1 |
| 12 | sixteen hashes in registry order | 512 |
| 524 | rows=64, inner=64, columns=64 | 6 |
| 530 | reserved=0 | 2 |
| 532 | five u64 in registry order | 40 |
| 572 | model_bytes, input_bytes, useful_output_limit | 12 |

The manifest is exactly584 bytes. Signed packet is `QWA1 || manifest || signature64`,
exactly652 bytes, below the existing2048-byte transaction-envelope budget. Its signature
message is `H("qualified-task-source-sign-v1", manifest)`. Manifest identity is
`H("qualified-task-manifest-v1", manifest)`; randomized/alternate signature bytes do not
create another manifest identity. Existing TRNM-PON1 hash framing is used unchanged.

`work_profile=H("qualified-task-profile-v1",UTF8("pon-matmul-transcript-64-v1"))`.
`recipe=H("qualified-task-recipe-v1",UTF8("canonical-field-matrix64-product-v1"))`.
The cost class fixes shape/relation, not equal hardware cost or an adversarial lower bound.
The262144 logical result multiply-add units count A×B's mathematical operation dimensions;
they are neither a miner work report nor a consensus chainwork multiplier.

## Supported model/layer/input recipe

Version1 supports one exact64×64 field-valued linear layer and a64-column input batch.
Both model and input are exactly16384 bytes containing4096 row-major LE32 values <q,
q=4294967291. `derive_matrices` directly decodes model bytes into A and input bytes into B.
No caller may supply different matrices by simply rehashing a claim and signing it.
Model hash is `H("artifact", model_bytes)`; input hash is
`H("qualified-task-input-v1", input_bytes)`. The exact full-layer identifier is
`H("qualified-task-layer-v1", model_hash,UTF8("entire-row-major-field-layer-64x64"))`.

The existing work task is `pon_work::task_id(A,B)` and its original verifier is unchanged.
This exact linear contraction is not a whole257-feature classifier, transformer, training
update, arbitrary adapter recipe or neural-circuit optimality certificate. An extended
partial-layer recipe must define extraction, padding, scales/ranges and new versioned bytes
before admission. A valid purpose label is still a source-attested intended use, not a
measured learning/inference benefit. Field-canonical zero/low-rank workloads are not
silently declared hard; the unchanged work profile's shortcut obligation remains open.

## Validity, availability, reuse and counting

Demand nonce is positive u64. `not_before <= expires`, lifetime<=1000 blocks and
`available_until>=expires`. Admission requires current height inside the signed window,
exact caller-pinned DA manifest/root and checked
`available_until >= expires + required_retention_blocks`; overflow rejects. Actual model
and input bytes are present in material admission, but signed future availability does
not prove geographically independent copies or10000-block retention. Custodian acquisition,
renewal/repair/funding and revocation remain their existing owners' responsibilities.

Output meter is `H("qualified-task-output-meter-v1",network,parameters,demand_id,model,
layer,input,recipe,matrix_task)`. It excludes demand nonce, header nonce, challenge,
proof, signature and mining producer. Changing only a demand nonce cannot mint another
output meter. Each attempt still binds and computes the full current header challenge.
Reuse can provide fresh consensus attempts while the same A×B result is counted once.

`DevelopmentTaskAdmission::bind_verified_output(&VerifiedWork)` requires the verified
matrix task, then returns exact product/challenge/meter identities with maximum output
credit1. This is an arithmetic-output fact, not marginal model value or reward. The branch
owner must atomically consume the meter and retain its product identity before counting.
Maintenance is separately classified work with maximum output credit0. Continuous
fallback/renewal is not implemented in the finite native development profile: its
bootstrap expires at height1000 and subsequent work requires a previously registered
valid successor. This pure codec cannot supply indefinite chain liveness.

## Parent admission, persistence and state transitions

The implemented fresh-context transition is `Unregistered -> StatementAdmitted` in a valid
block, then `ParentEligible` only in a later block. Actual material validation is a separate
business fact. A manifest cannot register itself in the block in which it provides work.
The existing parent state chooses eligible tasks; packet fields cannot override it.
The native persistent owner binds its admitted source roster/policy to the new context,
enforces source sequence/replay and its fixed withdrawal frontier, retains expiry and output
meter state, and includes their changes in branch delta/undo. A chain rollback never
revokes or replays an external Hepta effect. Pure admission performs no I/O or commits.

`Config::installed_with_profiles(policy,"signed-task-dev-v1")` and
`Settings::development_with_profiles(timestamp,policy,"signed-task-dev-v1")` explicitly
select native consensus revision5. The new profile hashes this entire registry into its
parameter identity, changes the network label and genesis, and cannot open an existing
historical store. Historical32-byte register_work, default genesis and golden roots remain
unchanged. Codec tag13 carries exactly652 signed payload bytes (811 including envelope);
its fixed fee is100 units. Historical executors reject tag13. Fresh signed-task executors
reject tag12, and `Node::make` rejects implicit maintenance.

Genesis pins16 demand identities `H("qualified-development-demand-v1",network,parameters,
LE64(index))`, indices0..15. Index0 is maintenance; other indices map index%3=1 to inference,
2 to evaluation and0 to adapter. These are public fixture demands, not genuine user demand.
The only source is public development account0; its seed `H("DEV-ONLY-KEY",LE64(0))` is
public, so this is an explicit reproducible attestation contract with **no exclusive source
custody or production authentication guarantee**. Source-record, authorization and DA roots
are independently derived from this fresh context and fixed demand identity; a received
manifest or mutable local allowlist cannot replace them. The withdrawal root is the fixed
context-bound genesis-zero frontier. Registration and work eligibility both check it, but
this version has no live withdrawal command or source-governance transition.

Genesis retains the full signed maintenance manifest, source nonce1 and demand0 nullifier.
At registration the envelope sender must match the fixed source; the source nonce must be
exactly previous+1, demand and matrix task must both be unused, and purpose must equal its
genesis demand record. Every eligibility check revalidates signature, signed height window,
the full stored manifest identity, demand nullifier and withdrawal frontier **before** the
work verifier. At validator entry, the fixed49188-byte `PNW1` proof is also required to
carry actual model A bytes whose `H("artifact",A_bytes)` equals the registered model and
actual input B bytes whose `H("qualified-task-input-v1",B_bytes)` equals the registered
input. The model is proof bytes4..16388 and the input16388..32772. These checks run before
the full work verifier, which then verifies canonical fields, TaskId and full transcript.
A valid signature on an unrelated model/input claim cannot pass by proving another A/B
matrix task, even when a miner bypasses `Node::make_with_task` and constructs the complete
packet/state root manually. This proves the fixed recipe's material binding at work
admission; source rights, genuine demand and future availability remain attested.
Validator rejection names are `TASK_PROOF_MATERIAL` for incompatible proof framing,
`TASK_MODEL_BINDING` for the A commitment and `TASK_INPUT_BINDING` for the B commitment.
`Node::make_with_task` additionally requires a private material admission
and rederives the actual A/B matrices; self-registration in the same block cannot grant
work eligibility. A different branch without the registration cannot mine/admit that task.

Each admitted non-maintenance block adds/checks `work-output:<meter>` in its state root,
holding product hash and `arithmetic_output_count=1`. Later fresh challenges for the same
registered task preserve count1. Maintenance creates no output meter. Source nonce,
registration, demand nullifier and meter are included in branch delta/undo and persist on
reopen. No marginal-value score, chainwork multiplier or additional reward is introduced.

`bootstrap_task_statement()` and `bootstrap_task_material()` expose the exact separately
classified genesis maintenance fixture for an explicit CLI choice. It remains valid only
through height1000, and the16 demand records are finite. This bounded testing context does
not supply a production maintenance renewal, demand-market or indefinite-liveness policy.

## Errors, tests and remaining acceptance

Structural errors are Length, Version, Purpose, Profile, Shape, CostClass,
NumericEncoding, Recipe, HardnessNotAccepted, Reuse, Identity, Layer, OutputMeter,
Limits, Validity and Reserved. Admission errors additionally distinguish Context, Source,
Demand, Authorization, Withdrawal, Signature, Height, Availability, MaterialLength, Model,
Input, MatrixTask, MatrixBinding, Numeric and WorkTask. Failure returns no private checked
type. Retry after source withdrawal or expiry requires new independently admitted owner
facts; retry cannot manufacture an accepted-hardness byte or a second output meter.

`trnm-protocol/tests/qualified_work_task.rs` checks exact lengths/all truncations,
closed flags/recipe, maintenance accounting, resource bounds and nonce-independent meter.
`trnm-crypto-primitives/tests/qualified_work_task.rs` checks real signed material, strict
signature/tampering/weak source rejection, every pinned context substitution, availability
overflow, rehashed wrong matrices, noncanonical numeric bytes and two full verified work
attempts sharing one arithmetic product meter. These cases test their named component
facts, not source honesty, independent custodians, end-to-end deployment or hardness.
`trnm-pon-node/tests/qualified_tasks.rs` covers actual registration→mine→admit, exact stored
manifest, absent parent registration, implicit maintenance rejection, same-result accounting,
source/signed-statement/nonce/demand/withdrawal rejection, tag isolation, expiry before work
verification, reopen/context isolation and heavier-fork removal of registration and meter.
It also registers genuinely signed false model/input claims and manually constructs correct
matrix transcripts, product meters and state roots while bypassing the qualified builder:
the validator rejects these claims before full work, while an equivalent material-correct
manually constructed packet is admitted as a positive control.
