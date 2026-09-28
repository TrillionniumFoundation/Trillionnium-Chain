# Documentation authority and applicability — PoN transition

Status: selected development contract, no implemented/accepted/activated PoN claim.
Primary module M17; producers/consumers M00-M17. The sole sequence is
`docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md`.

## 1. Separate design target, source truth and deployment

The selected new-development profile is `pon-nakamoto-v1`, governed by
[the PoN suite](../protocol/pon-nakamoto-v1/README.md) and
[its machine contract](../../config/pon-nakamoto-v1.json). PoCO is retired as the
development target. It is not kept as a BFT finality layer or automatic fallback.

The literal `consensus_mainline=native-poco-bft` and `protocol_target=poco-bft-v0`
fields still describe current legacy source/storage identifiers for existing tools.
They must not be used as the selected engineering direction: `development_target`
explicitly separates that choice. None of the actual old Rust APIs, binaries, stored
bytes, tests or chains became PoN by this documentation change. All production and
new work-profile/efficacy acceptance flags remain false.

Resolve `(repository, source_commit, source_tree, chain/genesis, protocol/profile,
parameter commitment, feature closure, evidence class)` before interpreting any rule.
New development contracts cannot reinterpret authenticated old history; old executable
behavior cannot override the newly selected design. Deployment requires its own accepted
release and activation context; neither chat, source merge nor passing document checks
is runtime authority. A conflict stops the affected profile, not all authorized coding.

## 2. Applicability matrix

| Profile | Applicable material | Current meaning |
|---|---|---|
| `pon-nakamoto-v1` | `docs/protocol/pon-nakamoto-v1/` and the PoN sections of M00-M17 | Selected development target; primitive, codecs, native runtime and independent acceptance remain unqualified/unimplemented |
| `bft-v0` | `docs/protocol/poco-bft-v0/` frozen specification and vectors | Retired target; retain exact legacy implementation and historical verification only |
| `pcc1` | `docs/protocol/poco-convergence-v1/` | Retired target integration contract; exact imported old byte/proof semantics, not a wire version or PoN implementation |
| `ai-v1` | `docs/protocol/poco-ai-native-v1/` | Retained legacy candidate application/source reference; business patterns may be adapted but old quorum/epoch/finality cannot authorize PoN |
| `legacy-ledger-observation` | retained old journal/function/error/test traces | Historical local-stage vocabulary, not new publication or execution authority |

The frozen directory/file fingerprints in the PoN contract bind retained bytes; this
refactor does not repin the seven PCC1 v0 imports or invent new tags. Unknown profiles
fail rather than trying decoders until one accepts. Historical QC, full PoCO finality,
work proof, model evaluation, availability and local capability remain different types.

## 3. Module and operation documentation

Every primary module file starts with PoN authority, interfaces, state machine,
persistence/reorg, resource, security, verification and migration sections. All content
below its `Retired PoCO implementation reference` heading is legacy source detail.
Planned old Vote/QC/TC/epoch work inside that retained section is retired backlog,
not a competing next-work sequence. Stable paths remain to avoid breaking exact source
selectors and historical review links. The suffix V1 in an old filename is not a new
PoN wire version. All existing module supplements and crate docs carry explicit scope.

`config/module-coverage-v1.toml` remains the actual source ownership inventory.
`config/documentation-contracts-v1.json` retains exact old implementation and regression
traces and explicitly adds the new profile/domain references. Its legacy requirement
IDs and source symbols do not prove new code exists. The PoN machine contract references
that inventory rather than owning a duplicate set of crates or domain writers.

## 4. Publication and recovery meanings

Historical PCC1 publications remain separately interpretable:

    signing: Validated -> IntentDurable -> SignatureRecorded -> VotePublished
    finality: FinalityVerified -> CommitIntentDurable -> ApplicationApplied
              -> CommitRecorded -> CheckpointConfirmed -> ReceiptPublished

Prepared and unmapped historical stages remain inert caller observations and cannot
authorize either vote or finality publication.

The old signing path does not wait for its own block's finality. These preserved source
facts are NOT the PoN publication rule. PoN mining uses exact template/work/output
publication; active-chain application uses durable reorg intent, detach/attach, root
readback and generation publication. A depth/work confirmation is probabilistic.

Chain-derived state can reorg; independent local effect/revocation/anti-rollback history
cannot. Model-release reorg never rewrites the parameters used by a completed historical
decision. Migration is fresh instance, exact liability reconciliation and explicit
proof-class dispatch; old signer or ledger state is never overwritten in place.

## 5. One integration line and evidence invalidation

Use the current canonical PR and protected main, resolving actual head/base/tree and
prospective merge from Git/GitHub. Earlier numbered stacks are history, not another
selected successor. A local preparation worktree does not create a second remote
architecture branch. Preserve concurrent changes; no force push or branch-protection
relaxation is implied by this refactor.

Each changed implementation, contract, source or evaluation input invalidates affected
acceptance evidence. Historical source hashes cannot be presented as latest passes.
Independent reviewer assignments must be actually authorized; no placeholder account
or self-approval establishes cryptographic/economic/model expertise.

## 6. Evidence axes and executable checks

Run the new PoN documentation and reference tests plus existing canonical-plan,
source-coverage, legacy byte/source and applicable package tests. All checks are
read-only except the explicit reviewable input-fingerprint refresh before committing.
`traceability integrity`, `semantic design acceptance`, `work-profile security`,
`runtime acceptance`, `model future-window efficacy` and `deployment` remain separate.

The reference model proves only tested arithmetic, selected fork/reorg examples and
accounting behavior. It is not a real miner or proof verifier. Document coverage does
not prove usefulness, consensus security, independence or scalable free service.
Preserve failures and open obligations; do not enable a work profile or weaken retained
legacy tests merely because the architecture changed.
