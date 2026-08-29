# TRNM Workspace Agent Prompt Pack v1

Status: **copy-ready starter-prompt index; subordinate to the canonical Plan**

Before using any starter prompt, put
[`AGENT_CONTROL_AND_OPERATING_CONTRACT_V1.md`](AGENT_CONTROL_AND_OPERATING_CONTRACT_V1.md)
into the Agent's persistent Instructions and restrict GitHub to the Chain
repository with write confirmation and no merge/release/secret authority.

- [`AGENT_PROMPTS_A00_A08_V1.md`](AGENT_PROMPTS_A00_A08_V1.md): Control, G0, G1 and G1.5 registry agents.
- [`AGENT_PROMPTS_A09_A17_V1.md`](AGENT_PROMPTS_A09_A17_V1.md): independent conformance, G2 and G3–G5 preparation agents.

Each section is a first-task message for one Agent. The Agent continues its
package loop across repeated runs until it reaches `MODULE_CLOSED_CANDIDATE`,
`BLOCKED_UPSTREAM`, `BASE_DRIFT`, `STOP_CONDITION` or `RESUME_REQUIRED`.

`MODULE_CLOSED_CANDIDATE` never means merged, accepted, gate-exit, release-ready
or production.

## Prompt index

- # A00 — [TRNM Control Tower](AGENT_PROMPTS_A00_A08_V1.md#a00--trnm-control-tower)
- # A01 — [G0 Truth, Provenance and Reproducibility](AGENT_PROMPTS_A00_A08_V1.md#a01--g0-truth-provenance-and-reproducibility)
- # A02 — [G1-R2 Recovery and Core Acknowledgement](AGENT_PROMPTS_A00_A08_V1.md#a02--g1-r2-recovery-and-core-acknowledgement)
- # A03 — [G1-R3 Ordinary Proposal Authority](AGENT_PROMPTS_A00_A08_V1.md#a03--g1-r3-ordinary-proposal-authority)
- # A04 — [G1-R4 Application and Ordered Finality](AGENT_PROMPTS_A00_A08_V1.md#a04--g1-r4-application-and-ordered-finality)
- # A05 — [G1-R4 Safety, Signer, Checkpoint and Anti-Rollback](AGENT_PROMPTS_A00_A08_V1.md#a05--g1-r4-safety-signer-checkpoint-and-anti-rollback)
- # A06 — [G1-R4 Fault Matrix and Independent Replay](AGENT_PROMPTS_A00_A08_V1.md#a06--g1-r4-fault-matrix-and-independent-replay)
- # A07 — [G1-R5 Native 4/7-Node Campaign](AGENT_PROMPTS_A00_A08_V1.md#a07--g1-r5-native-4-7-node-campaign)
- # A08 — [G1.5 CEV1 Registry and Normative Specification](AGENT_PROMPTS_A00_A08_V1.md#a08--g1-5-cev1-registry-and-normative-specification)
- # A09 — [Independent Parser, Vectors, Mutation and Fuzz](AGENT_PROMPTS_A09_A17_V1.md#a09--independent-parser-vectors-mutation-and-fuzz)
- # A10 — [G2.0 W0-W7 Traceability and Codegen](AGENT_PROMPTS_A09_A17_V1.md#a10--g2-0-w0-w7-traceability-and-codegen)
- # A11 — [G2A DA-FULLREP-V1](AGENT_PROMPTS_A09_A17_V1.md#a11--g2a-da-fullrep-v1)
- # A12 — [G2B Agent, Capability and Task Market](AGENT_PROMPTS_A09_A17_V1.md#a12--g2b-agent-capability-and-task-market)
- # A13 — [G2D Deterministic Execution, MVCC and Fees](AGENT_PROMPTS_A09_A17_V1.md#a13--g2d-deterministic-execution-mvcc-and-fees)
- # A14 — [G2C Verification and Challenge](AGENT_PROMPTS_A09_A17_V1.md#a14--g2c-verification-and-challenge)
- # A15 — [G2E Settlement and Economic Conservation](AGENT_PROMPTS_A09_A17_V1.md#a15--g2e-settlement-and-economic-conservation)
- # A16 — [G2F Whole-Node Authority, State Sync and Light Client](AGENT_PROMPTS_A09_A17_V1.md#a16--g2f-whole-node-authority-state-sync-and-light-client)
- # A17 — [G3-G5 Benchmark, Security, Operations and Activation Preparation](AGENT_PROMPTS_A09_A17_V1.md#a17--g3-g5-benchmark-security-operations-and-activation-preparation)
