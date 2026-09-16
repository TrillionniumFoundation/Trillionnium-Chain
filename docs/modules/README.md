# Trillionnium Chain module specifications

Every module M00–M17 has an individual implementation design below. These are
candidate technical contracts for the next implementation, with current source,
proposed APIs, algorithms, durable data, errors, limits and concrete test cases.
They are not claims that the designed runtime is implemented or independently
accepted. CI reports structural coverage only; it cannot prove semantic completeness.

Read the [authority resolver](../architecture/TRNM_DOCUMENTATION_AUTHORITY_V1.md)
first. Frozen protocol bytes, cryptographic domains and root meaning take
precedence. The [technical reference](TRNM_MODULE_TECHNICAL_REFERENCE_V1.md)
remains the ownership/index authority; the [implementation guide](TRNM_MODULE_IMPLEMENTATION_GUIDE_V1.md)
and [trace registry](../../config/documentation-contracts-v1.json) bind current
code and representative regressions. This index adds detailed designs for all
18 boundaries, not a second development sequence.

| Module | Technical design | Specific implementation boundary |
|---|---|---|
| M00 | [M00_FOUNDATION_PROTOCOL_TECHNICAL_SPEC_V1.md](M00_FOUNDATION_PROTOCOL_TECHNICAL_SPEC_V1.md) | Exact codecs, domains, parameter/context binding and reject-before-allocation rules |
| M01 | [M01_CRYPTO_IDENTITY_TECHNICAL_SPEC_V1.md](M01_CRYPTO_IDENTITY_TECHNICAL_SPEC_V1.md) | Strict verification, verified capabilities, key roles, verification work budgets |
| M02 | [M02_CONSENSUS_CORE_TECHNICAL_SPEC_V1.md](M02_CONSENSUS_CORE_TECHNICAL_SPEC_V1.md) | Proposal/QC/TC processing, locks, pacemaker, checkpoint/seal/epoch transitions |
| M03 | [M03_SAFETY_SIGNER_TECHNICAL_SPEC_V1.md](M03_SAFETY_SIGNER_TECHNICAL_SPEC_V1.md) | Safety state, durable intents, exact retries, old/new signer roles and rollback anchors |
| M04 | [M04_P2P_TECHNICAL_SPEC_V1.md](M04_P2P_TECHNICAL_SPEC_V1.md) | Authenticated TCP/TLS candidate transport, framing, replay sequences and lane backpressure |
| M05 | [M05_TX_LIFECYCLE_TECHNICAL_SPEC_V1.md](M05_TX_LIFECYCLE_TECHNICAL_SPEC_V1.md) | Signed admission, nonce/idempotency, durable journal, proposer selection and receipt semantics |
| M06 | [M06_EXECUTION_TECHNICAL_SPEC_V1.md](M06_EXECUTION_TECHNICAL_SPEC_V1.md) | Deterministic execution, read-set validation, fee rebasing and sparse epoch-edge execution |
| M07 | [M07_STATE_STORAGE_TECHNICAL_SPEC_V1.md](M07_STATE_STORAGE_TECHNICAL_SPEC_V1.md) | Prepared/committed state, JMT carried predecessor root, incremental delta schema and pruning |
| M08 | [M08_FINALITY_RECOVERY_TECHNICAL_SPEC_V1.md](M08_FINALITY_RECOVERY_TECHNICAL_SPEC_V1.md) | Three-chain finality, Node Commit Ledger, consensus/application coordinates and recovery cuts |
| M09 | [M09_DATA_AVAILABILITY_TECHNICAL_SPEC_V1.md](M09_DATA_AVAILABILITY_TECHNICAL_SPEC_V1.md) | Chunk/manifest commitments, durable-before-attest, retention, retrieval and repair |
| M10 | [M10_AGENT_MARKET_TECHNICAL_SPEC_V1.md](M10_AGENT_MARKET_TECHNICAL_SPEC_V1.md) | Agent/capability/task/lease/escrow states, deterministic scheduling and development profile |
| M11 | [M11_VERIFICATION_CHALLENGE_TECHNICAL_SPEC_V1.md](M11_VERIFICATION_CHALLENGE_TECHNICAL_SPEC_V1.md) | Verification registry, implemented StakeQuorum scope, challenge windows and disabled backends |
| M12 | [M12_SETTLEMENT_TECHNICAL_SPEC_V1.md](M12_SETTLEMENT_TECHNICAL_SPEC_V1.md) | Fee/escrow/refund/slash accounting, economic profile validation and conservation vectors |
| M13 | [M13_STATE_SYNC_MIGRATION_TECHNICAL_SPEC_V1.md](M13_STATE_SYNC_MIGRATION_TECHNICAL_SPEC_V1.md) | Trusted checkpoint/epoch proof, chunk admission, staged import, catch-up and migration |
| M14 | [M14_CLIENT_PLATFORM_TECHNICAL_SPEC_V1.md](M14_CLIENT_PLATFORM_TECHNICAL_SPEC_V1.md) | Public API/SDK/indexer consistency, proofs, overload and transaction/block root distinction |
| M15 | [M15_NODE_RELEASE_TECHNICAL_SPEC_V1.md](M15_NODE_RELEASE_TECHNICAL_SPEC_V1.md) | Composition, startup/shutdown, runtime feature closures, release bundles and host acceptance |
| M16 | [M16_CONTROL_PLANE_TECHNICAL_SPEC_V1.md](M16_CONTROL_PLANE_TECHNICAL_SPEC_V1.md) | Observer/evaluator separation, local policy generations, action budgets and rollback |
| M17 | [M17_EVIDENCE_SECURITY_TECHNICAL_SPEC_V1.md](M17_EVIDENCE_SECURITY_TECHNICAL_SPEC_V1.md) | Evidence identity, metrics, benchmark denominators, security and independent acceptance |

## Shared decisions that consumers must implement consistently

| Contract | Producer → consumers | Decision and limitation |
|---|---|---|
| Epoch application edge | M08/M13 → M02/M03/M06/M07/M15 | Planned authenticated checkpoint C / seal C+1 / seal C+2 edge; first new application version C+3. Seals produce no application mutation, P row or receipt. |
| Carried predecessor root | M07 → M06/M08/M13 | Planned alias only for the authenticated empty-path root at C+2. Child node versions remain real historical versions; pruning and recovery retain the full reachable source root. No arbitrary path/version remapping. |
| Public transaction completion | M05/M06/M08/M13 → M14 | Journal acceptance, execution and finality are separate. Existing v0 root-equality checks stay intact; general multi-transaction proofs require the specified versioned result/inclusion contract. |
| Network authority | M04 → M02/M03/M15 | Transport authentication and delivery acknowledgement do not authorize signatures or finality. Peer identity binds chain/profile/active keys; data lanes cannot exhaust consensus reservations. |
| Economic application | M09/M10/M11/M12 → M06/M14 | Development profiles are explicit and immutable per run. Unsupported verification backends remain disabled. PoCO stays shadow; no documented profile grants permissionless identity or mainnet economics acceptance. |
| Evidence | All → M17 | Source-bound logs, reproducible vectors and independent acceptance remain distinct. Source structure and headings are navigation checks, never an acceptance certificate. |

The [foundation operation contracts](TRNM_FOUNDATION_OPERATION_CONTRACTS_V1.md)
and [operation catalog](../../config/documentation-operations-v1.json) retain
selected concrete source/function/error/test bindings. The catalog is explicitly
incomplete; extending a module design does not invent executable operation coverage.
The [native signed Vote replay contract](TRNM_NATIVE_SIGNED_VOTE_REPLAY_CONTRACT_V1.md)
grants laboratory readback only, with no new signing/recovery authority.

## Reviewing a design change

For the affected boundary, review exact input/output fields and versioning;
state transitions and forbidden edges; database keys, atomicity and replay;
work/memory/network caps; authenticated trust inputs; and a positive/negative/crash
case with an expected root, effect or error. Check the consuming module against
the same decision. If a parameter is deployment-selected, its schema, constraints,
selection authority and development fixture must be explicit before enabling it.

Do not replace these checks with word counts, repeated headings or a large
registry. Preserve anti-double-sign, persist-before-sign, cryptographic vectors,
crash recovery and deterministic concurrent roots. The
[sole development plan](../development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md#14-immediate-executable-order)
sets the implementation order and stage exits. Production and external acceptance
remain governed by machine truth and authenticated evidence.
