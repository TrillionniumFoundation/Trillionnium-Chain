# L3 — revision3 ledger context, native commands and lifecycle

Revision3 remains the historical default described below. Explicit revision4 selects
the [complete eligible evaluation round](MODEL_EVALUATION.md); explicit revision5
`signed-task-dev-v1` additionally selects the [signed task registration contract](QUALIFIED_WORK_TASK.md).
Tag13 and its new parent-admission rules belong only to that distinct development
context. The explicit revision6 native evaluation policy adds tags14..17 for frozen
commit/reveal, signed conflict evidence and bounded archived appeals; it refuses legacy
direct-score tag7. Revision7 [renewable task leases](QUALIFIED_TASK_LIFECYCLE_V2.md)
adds18 OPEN, 19 standalone RENEW, 20 REVOKE and 21 REGISTER, and refuses historical
task tags12/13. Revision8 [V3 atomic renewal](QUALIFIED_TASK_LIFECYCLE_V3.md)
retains18/20/21, adds exact1028B atomic22 and refuses standalone19. Revision9
[V4 signed-overlap renewal](QUALIFIED_TASK_LIFECYCLE_V4.md) retains those tags and
refusal, permitting atomic22 inclusion during the source-authorized overlap instead of
V3's exact containing height. Each successor has its own committed registry/network/
parameters/genesis; none reinterprets V2/V3. The explicit [operator actor context](OPERATOR_ACTORS_V1.md)
separately binds its public descriptor and bootstrap signatures; it is not the historical
default. Payload widths and exact phase/error/state rules are specified by
[PUBLIC_EVALUATION_LIFECYCLE](PUBLIC_EVALUATION_LIFECYCLE.md) and the selected
lifecycle contract, alongside their versioned JSON registries and native tests.
[Current CLI profiles and remaining public gates](PUBLIC_READINESS.md) bind
interfaces, source ownership, resource limits and actual acceptance scope. These
extensions do not reinterpret revision3 byte commitments, golden roots or stored state.

The historical/default core registry is [`ledger-v1.json`](../../../../config/pon/ledger-v1.json),
with [`devnet-v1.json`](../../../../config/pon/devnet-v1.json), work and model-family JSONs.
The core rules below have normative scope `consensus_revision=3`, chain label
`trnm-pon-invariant-contract-devnet-3`; explicit successor profiles select the additional
contracts above through fresh parameter/genesis commitments. Historical valid parameters,
genesis and recorded results retain their original identities. Registry filenames ending
in v1 are stable identifiers, not claims that their content still specifies consensus revision1.
PNH1/PNX1 remain the wire magic; the complete parameter commitment selects semantics.

The rules below describe revision3 as a whole. The two final Revision3 sections define
signed contribution windows, resource identity, retained release discovery and strict
signatures. They replace revision2's lifetime/nullifier rules, not supplement an optional
legacy mode. Revision2 is historical context only; there is no in-place database upgrade,
old-context decoder dispatch or activation by editing these documents.
Canonical JSON used INSIDE commitments is ASCII escaped, key-sorted, compact JSON with
only strings, booleans, null, bounded integers, arrays and string-key objects. Duplicate
keys, floats, NaN and out-of-range integers reject. JSON whitespace is not wire encoding.

## L1.1 Domains and genesis

H is defined in [WORK_PROFILE.md](WORK_PROFILE.md). Network=H("network",UTF8(chain_label)).
Parameters=H("parameters",canonical(devnet),canonical(ledger),canonical(work),canonical(model)).
Any change to these contracts yields a distinct genesis context; there is no silent upgrade.

Development accounts i=0..3 each receive 10,000,000 test units. Their deliberately public
Ed25519 seeds are H("DEV-ONLY-KEY",LE64(i)); they are fixtures, never a production custody
scheme. Account 4 is an unfunded consumer. Evaluation fixture keys 0,1,2 can attest a
model, but an author cannot attest its own contribution. Two distinct allowed non-author
keys are required. This is explicitly a controlled attestation profile, not independent
operators or permissionless subjective consensus.

Genesis timestamp=1,800,000,000; initial target=pow_limit=0x7f followed by 31 0xff bytes;
spacing=10 seconds; difficulty interval=16; clamp factor=4; median window=11; local future
skew=120 seconds. Reorganizations recompute from their branch ancestry. Reward maturity
is 20 blocks; policy confirmation is depth>=6 AND work delta>=6×the included block's
required work. No such policy makes a deeper valid reorg impossible.

Subsidy at height h is 1000 >> min(floor(h/100000),64), in valueless test units. There is
no arbitrary mint transaction. Genesis issued sum is 40,000,000; subsequent issuance is
only that subsidy. Fees are transfers into immature miner rewards, not new supply.
GenesisId=H("genesis",Network,Parameters,GenesisStateRoot,LE64(genesis_timestamp)).

## L1.2 Header: exactly 318 bytes

All offsets are zero based. Hashes are raw 32 bytes; integers are unsigned little-endian.
Target bytes are the sole numeric exception: unsigned big-endian comparison, fixed32.

| Offset | Field | Size |
|---:|---|---:|
| 0 | magic PNH1 | 4 |
| 4 | version=1 | 2 |
| 6 | network | 32 |
| 38 | parameters | 32 |
| 70 | parent | 32 |
| 102 | height | 8 |
| 110 | timestamp | 8 |
| 118 | required target | 32 |
| 150 | miner payout/public identity | 32 |
| 182 | transaction sequence root | 32 |
| 214 | application state root | 32 |
| 246 | receipt sequence root | 32 |
| 278 | parent-admitted work task | 32 |
| 310 | nonce | 8 |

Consensus checks version/context/parent/height/DAA/median before expensive work. A future
time defers locally and may later become admissible; it is not permanently bad-block
proof. Missing parent/data is unavailable, not permission to trust an announced work sum.
Work(T)=floor(2^256/(T+1)); sum uses checked 512-bit storage. Credit expected target, never
the lucky actual digest. A fully verified strictly heavier branch wins; ties keep the
active branch. Headers alone cannot become executable active state.

## L1.3 Signed transaction envelope

`PNX1 || network32 || sender32 || nonceLE64 || expiryHeightLE64 || feeLimitLE64 || tagU8
|| payloadLengthLE16 || payload || signature64`.

Unsigned overhead=95; signed overhead=159; total<=2048 bytes. Sign Ed25519 over
H("tx-sign",unsigned envelope); TxId=H("tx-id",complete signed bytes). Signature is
strictly verified before any state mutation. Sender nonce must equal current+1; zero
nonce rejects. Height>expiry rejects. Unknown tags, payload lengths and trailing bytes
reject. There is no extensible arbitrary-code field and no old transaction decoder.

Each command's exact field order is in the JSON registry; this table defines semantics.
All invalid commands reject the candidate block and leave the parent state unchanged.

| Tag | Command / fixed payload bytes | Preconditions and transition |
|---:|---|---|
| 1 | transfer / 40 | positive amount; sender funds cover fee+amount; transfer to recipient; checked balances |
| 2 | reserve_task / 80 | new task, positive budget, pre-reserved expiry slot; reserve payer funds; bind provider; status reserved |
| 3 | cancel_task / 32 | only task owner, only reserved; refund remaining escrow; terminal cancelled |
| 4 | record_receipt / 64 | bound provider, reserved and before deadline, nonzero output; status receipt, no payment yet |
| 5 | accept_task / 64 | task owner, receipt and matching output before deadline; pay provider, status settled |
| 6 | contribute / 176 | current parent release, exact family, bounded artifact; id binds author+family+parent+artifact+components root+submission round; reject same parent/round/artifact duplicate; count live candidates, not zero-score history |
| 7 | evaluate / 104 | registered non-author evaluator; once per evaluator; fixed plan, nonzero evidence, integer bounded score; freeze minimum of first two valid attestations |
| 8 | publish_release / 145+40n | 1<=n<=16 sorted unique contribution IDs; bundle and allocations positively evaluated; recompute total and root; sponsor locks finite budget and reserves maturity+1000 claim deadline; adopt release |
| 9 | claim_reward / 73+32n | payee bound by allocation-root membership, maturity and deadline, exact Merkle depth/root/score; one claim per contribution; transfer floor(budget×score/total), retain dust |
| 10 | reserve_quota / 112 | payer prepays units×1024, binds consumer/provider and deadline; independent quota object |
| 11 | consume_quota / 136 | provider transaction plus consumer signature over exact quota/provider nonce/units/result; subtract units, pay provider less fee; user pays no funds |
| 12 | register_work / 32 | new nonzero task commitment; eligible only in a later block |

ContributionId=H("contribution-v3",author,family,parent,artifact,components_root,LE64(submission_round)).
ReleaseId=H("release",parent,bundle,LE64(budget),allocation_root,LE64(total_score)).
The bundle is itself an evaluated contribution binding its exact allocation root.
This prevents an otherwise valid publisher from inventing contribution scores or a
larger reward share unrelated to assessed candidates. Evaluation signatures still carry
an explicit attestation trust assumption; ledger validity does not prove model utility.

## L1.4 Fees, deadlines and deterministic mandatory work

Fee=command.base_fee_units+encoded_transaction_bytes. Exact base charges are in the
registry. fee_limit<=10,000,000 and must cover calculated fee. For tag11, prepaid quota
pays the fee; otherwise the sender pays it. Quota consumer consent binds provider nonce,
so re-signing the receipt under another attempt fails. No dynamic price API is queried.

Before transactions, retire obsolete contribution records; expire due tasks/quotas/releases sorted by (deadline,key), maximum16, and
release mature miner rewards. Admission allows at most16 outstanding expiries at one
height, at most256 pending funded task/quota/release obligations and task/quota deadline within1000 blocks; release claim deadline at publication+maturity+1000 blocks. Thus mandatory
expiry is bounded without allowing miners to starve obligations. Receipts do not extend
deadlines. A late acceptance cannot resurrect cancelled/expired escrow.

All amounts and nonces are u64; intermediates use exact checked arithmetic and reject
before overflow. The state-root encoder rejects oversize keys/values. Block<=1MiB,
transactions<=256, state keys<=65536; a protocol extension must version these limits.

## L1.5 Commitments and conservation

Transaction and receipt sequence leaves include LE64(index); internal Merkle levels
pair left/right and duplicate the last odd leaf. Empty roots have distinct tags.
Receipts contain canonical integer fee/status facts, not runtime wall-clock durations.
State keys use a 256-level sparse Merkle path H("state-key",key); present leaves are
H("state-leaf",key,value), missing leaves H("state-empty"), nodes H("state-node",L,R).
Collision of different keys at one hashed path rejects. Value-size<=4096; key-size<=160.
Rust computes top-down partitions; Python computes bottom-up integer paths.

Allocation leaves=H("allocation-leaf",contribution,payee,LE64(score)); pair hashes sort the
two children. Publication recomputes the entire bounded list, rather than trusting a
claimed denominator. Claims require exactly ceil(log2(leaf_count)) siblings, prevent
leaf replay and retain indivisible dust. No infinite lineage royalty exists.

At every accepted block:

    sum(accounts + task escrow + quota escrow + release escrow + immature rewards)
       == genesis issuance + sum(valid active-branch subsidies)

Miner reward identity uses parent, height and miner, not current proof/block id.
Chain reorg reverses these balances and entitlement; real external effects do not rewind.

## L1.6 Vectors and implementation boundary

`vectors/expected.json` holds independent-language expected hashes; it is not regenerated
by tests. Native `pon_wire` must accept all 12 tags and reproduce header, transaction and
state roots, while rejecting every malformed vector. The Python oracle separately checks
signatures and application transitions. Native M06 now executes all twelve commands and is compared to the reference at1/2/4/8 workers. See EXECUTION_PARALLEL.md. It is explicitly selectable through the existing Ledger bridge. A native application engine is not a complete native consensus/persistence or Hepta node.

## L3.7 Revision2 provenance and superseded rules

Revision2 introduced live-candidate capacity, root-bound claims and reserved refunds.
Revision3 retains those behaviors but replaces unbounded same-parent nullifier retention
with signed intake rounds and finite same-round history, as specified below. The active
schema identifier and parameter bytes come from the installed revision3 configuration;
this provenance paragraph is not a second set of applicable rules. Root-bound claims
survive candidate retirement; unclaimed release budgets still refund at their reserved
deadline, and noncurrent empty release objects can retire.

Consumer use signatures now cover H("use",Network,Parameters,quota,provider,nonce,units,result).
`result` may be the strict closed inference receipt digest binding model/request/input/
output and exact provider/quota. The consumer validates expected fields before signing.
The chain verifies the signed digest, not private plaintext or actual model usefulness.

## Revision3: finite contribution windows without replay reopening

`consensus_revision=3` and a new chain label produce a fresh parameter/genesis context.
This is NOT an in-place revision2 database or transaction upgrade. Tag6 appends one u64
`submission_round`, giving176 payload bytes. The field is signed and part of its ID.
Require submission_round=floor(candidate_height/128). Retain at most512 contribution
records and256 active candidates in that window. A64-block candidate lifetime expires
both pending and evaluated results; expired results cannot authorize publication.

On crossing the window boundary, old-window candidate and artifact duplicate records
can be removed because their original signed payloads remain invalid. A new submission
requires a new ID/signature/round and new evaluation; there is no carried-forward score.
Published release-root claims remain independently payable within their original claim
window even after candidate rows retire. A chain reorg replays these changes normally;
it does not erase the independent local execution/revocation journal.

The finite window may reject excess submissions temporarily. It does not claim Sybil
fairness or solve all historical account, task, work-registration and block-storage growth.
The parameters are experimental and require separate production resource/economic design.

## Revision3: resource identity, current model and strict signatures

TaskId=H("task-instance-v3",Network,Parameters,sender,LE64(creation_nonce),provider,
LE64(budget),LE64(deadline)). QuotaId=H("quota-instance-v3",Network,Parameters,sender,
LE64(creation_nonce),consumer,provider,LE64(units),LE64(deadline)). These are mandatory
checks on the existing tag2/tag10 payloads. Closed, remaining-zero resources can retire
after the declared deadline: old transaction nonces and old signed deadlines remain
invalid; a new nonce cannot reopen the same ID. Raw task labels are not resource IDs.

Publication preserves bundle artifact, family, components root and parent in the release
record before candidate rows are retired. Current model discovery must not depend on a
reclaimed candidate record. Reward Merkle membership remains a separate fact.

The parameter commitment now includes the explicit strict Ed25519 profile: canonical
point encodings with y<p and no negative-zero encoding; scalar S<L; reject small-order
public keys and R; then the actual signature equation verifier. Python backend defaults
were observed to accept the identity-key/identity-R zero-scalar case; relying on those
defaults disagreed with native verify_strict. Both paths now perform the specified
rejections, with an RFC8032 positive vector and small-order/canonicality parity tests.
These tests are not an independent cryptographic audit. No private scalar or signing
primitive is implemented by the Python public-point prevalidation helper.

Early admission checks envelope count and lengths before root/work replay. Identical
already verified header/body/proof retransmission reuses that stored fact; a matching
BlockId with altered certificate/body rejects and cannot poison the valid stored entry.

## Application scope and non-goals of this mainline

This PoN mainline is a dedicated AI-work/model/service ledger with twelve original closed
native commands in the base registry and explicit profile-gated successor tags13..22.
The exact selected context determines enabled commands; V3 refuses19 and task12/13. It is not a general-purpose user-deployed
contract VM. There is no arbitrary bytecode deployment, EVM opcode dispatch, Solidity ABI,
Move package installation, reentrant contract call or user-selected host function.
Model artifacts are bounded data, not executable contracts. Local Hepta actions remain
outside deterministic chain execution and under their existing authorization owners.

The current fee rule meters the registered command and encoded bytes. It is not a gas
schedule for arbitrary programs, nor a completed storage-rent policy. Native command
benchmarks establish only the stated command mix, shared-key conflicts and exact pipeline
stage; they say nothing about arbitrary smart-contract capacity.

Adding a general-purpose VM is outside the selected implementation scope, not an implicit
promise or a permanent prohibition on future research. A future explicit architecture
choice must define the VM and bytecode verifier, deterministic instruction/host-call
semantics, compute/memory/storage metering, ABI and type/resource rules, deployment and
upgrade authorization, reorg/undo behavior, tooling and wallet interfaces, and owners in
M00/M05/M06/M07/M14/M15. It requires a separately reviewed version/context and adversarial
vectors before any executable tag is admitted. No EVM or other VM is added merely to
match another chain's feature list. Until that decision, reject unknown tags and bytecode.
