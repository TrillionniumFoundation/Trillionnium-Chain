# Documentation authority and applicability contract v1

Status: **candidate documentation contract; no protocol freeze, activation or independent acceptance**. Primary module: M17; producers/consumers: M00, M03, M08 and M15.

The sole engineering plan remains `docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md`. This is a resolver for technical rules, not a roadmap. Machine activation authority remains `config/consensus-mainline.json`. Its false production/release flags are not changed by this contract.

## 1. Resolve a rule before implementing it

An implementation or review selects the tuple `(repository, source_commit, source_tree, protocol_version, contract_profile, parameter_commitment, feature_closure)`. A branch name, PR number, file modification date or successful ancestor check is not this tuple. Obtain commit/tree from the actual checkout; obtain active chain/profile/parameters from authenticated commissioning or activation material, never from the proof being verified.

Read in this order: authenticated activation/governance and machine policy; the selected frozen protocol and its exact schemas/parameters/vectors; the applicable integration contract; module implementation contracts; operating instructions. A lower layer may strengthen local isolation but cannot change signing bytes, validity, quorum, locks, finality or replicated state without explicit protocol/profile change. A conflict in those meanings stops the affected profile and requires producer, consumer and specialist review. Neither newest prose nor executable code wins automatically.

## 2. Applicability matrix

| Profile ID | Applicable rule set | Status and permissible use | Not implied |
|---|---|---|---|
| `bft-v0` | `docs/protocol/poco-bft-v0/README.md`, its seven numbered specifications, parameters and vector registry | Frozen version-0 normative **implementation target**; CEV0 and the committed v0 signature/hash domains | An implemented, audited or activated network |
| `pcc1` | `docs/protocol/poco-convergence-v1/README.md` and its resource/proof-migration companions | Candidate implementation/integration contract importing the exact v0 kernel; PCC1 is a contract revision, not protocol version 1 | A new consensus algorithm, permission to alter v0 bytes, or default-node activation |
| `ai-v1` | `docs/protocol/poco-ai-native-v1/README.md` and its specification manifest | Draft version-1 design/candidate surface; independently selected CEV1 schemas, domains, parameters and activation | Automatic activation on a v0 node or acceptance of re-encoded v0 signatures |
| `legacy-ledger-observation` | Existing `Prepared` through `OutboundPublished` candidate journal vocabulary and historical implementation evidence | Local integration observation only; stages/digests may describe recorded caller facts | Proof that domain operations occurred, three-chain finality, or permission to gate consensus vote publication on finality |

`pcc1` may import `bft-v0` only at the seven blob identities already recorded in PCC1 section 1. The checker verifies those imports rather than silently repinning them. `ai-v1` has no implicit compatibility edge to either profile. Historical proof classes require the explicit dispatch and migration rules in `PROOF_MIGRATION.md`; a legacy QC cannot be relabelled as native finality. Missing or unknown profiles are unsupported, not a cue for fallback.

The AI resource proposal inside PCC1 is a proposed application-profile extension. Its complete wire registry, state codec, Rust implementation and independent vectors must be accepted before enabling it under a runtime/parameter commitment. A Python model is not its codec. A crate ending in `v1` is not, by itself, proof of protocol/profile activation.

## 3. Integration lineage is not protocol authority

The observed stack is `main <- #62 <- #85 <- #86`. PR #62 remains the sole Plan V2 integration successor into protected main. PR #85 is a bounded contract child of #62; PR #86 is its implementation continuation. This documentation change is a bounded child of #86, not another selected successor. The observed source for preparation is `1f5ebbb8dab62cfd4d56447480ad60992f61f0ba`.

The machine registry records PR/ref relationships as observations. Every review rereads the actual base, head and prospective-merge identities and verifies ancestry/content. It does not assume that a parent contains a child's changes. A branch rename, restack or new head requires a new observation and invalidates affected review evidence. This file does not close, supersede, merge or approve any PR.

The old assessed Plan V2 commit remains historical assessed provenance. It must not be displayed as the current tip. Current-source reports always derive HEAD/tree and input hashes during verification. No immutable document claims to know a continuously moving latest head.

## 4. Publication ordering: two lifecycles, not one circular wait

For PCC1, use the two lifecycles specified in its durable lifecycle contract:

```text
signing:  Validated -> IntentDurable -> SignatureRecorded -> VotePublished
finality: FinalityVerified -> CommitIntentDurable -> ApplicationApplied
          -> CommitRecorded -> CheckpointConfirmed -> ReceiptPublished
```

The signing owner verifies the exact authorized intent, durable Safety state and required independent anchor before releasing a signature. It must not wait for finality of the vote's block. A vote is not an application receipt. A receipt requires verified finality, durable application/commit records and confirmed checkpoint.

The older single `Prepared` through `OutboundPublished` sequence in local candidate journals is retained as an implementation observation, not as the orchestration rule for both message classes. For this scope it is superseded by the two PCC1 lifecycles. Do not rename stored enum tags in a documentation change. Adapter adoption requires an explicit mapping from each stored fact to its real domain operation, predecessor, owner, recovery action and publication class, followed by crash/replay qualification. Unmapped records remain inert and cannot authorize publication.

The plan's persistence section and the M08 module reference must carry this same distinction. The documentation checker rejects removal of either lifecycle or the explicit vote/finality separation. This is a consistency check, not a liveness proof.

## 5. Implementable document bundle

`config/documentation-contracts-v1.json` binds all M00-M17 modules to `TRNM_MODULE_IMPLEMENTATION_GUIDE_V1.md`, concrete normative files, implementation files, regression inputs and review domains. The ownership inventory remains `config/module-coverage-v1.toml`; the two inventories must agree exactly. No crate or auxiliary unit becomes documented merely because a directory exists.

Each module section supplies version applicability, ordered state/admission steps, authoritative inputs, mutation/publication boundaries, error/retry/recovery semantics, conformance cases and implementation/consumer tracing. Referenced frozen layouts and existing code enums remain their authoritative definitions; the guide does not invent wire error numbers. Unimplemented or unregistered operations are explicitly blocked rather than assigned guessed defaults.

Every enabled operation needs a requirement-level record containing: requirement ID; exact profile and normative clause; concrete schema/domain/limit; pre-state and authenticated input; accepted post-state/effects; each rejected/local-unavailable/uncertain outcome; concrete positive/negative vector IDs and expected bytes/errors; implementation symbol and feature; producer/consumer; source-bound replay command and result. Module-level navigation and source hashes are the starting index, not proof that every operation has such an accepted record.

## 6. Three independent status axes

- **Traceability integrity:** all declared module/profile/source/reference links and hashes resolve, with no forbidden compatibility or authority promotion.
- **Semantic design acceptance:** qualified independent specialists can implement and compare the specified operation without guessing, and attest to the requirement-level records.
- **Implementation/production acceptance:** the selected production closure and deployed artifacts pass the relevant real execution and external gates.

The automated checker may pass the first axis only. It always reports semantic and implementation acceptance as not assessed. Open requirements and vacant reviewer slots remain visible. Neither a new status label nor a zero missing-link count advances the other axes.

## 7. Replay and change invalidation

Run `python3 scripts/ci/test_documentation_contracts_v1.py` and `python3 scripts/ci/check_documentation_contracts_v1.py` in the exact checkout. The existing canonical-plan gate invokes both; its pre-existing checks remain required. The checker is read-only and uses no network or dependency installation. Its output records source/tree and SHA-256 input digests, not an attestation of expertise or release approval.

Changes to a referenced rule, implementation, test, dependency, feature, parameter, reviewer authorization or ownership invalidate that requirement and affected consumers. Changes to author/reviewer conflicts invalidate the associated signatures. Submit fresh source-bound evidence through the existing external-evidence process. Keep failed observations immutable; do not import the result of an ancestor, a fixture or a different binary.
