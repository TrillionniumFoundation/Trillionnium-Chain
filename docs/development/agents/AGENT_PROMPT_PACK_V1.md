# TRNM Workspace Agent Prompt Pack v1

Status: **copy-ready starter-prompt index; subordinate to the canonical Plan**

## 1. How to configure each Workspace Agent

Follow [`GPT_WORK_AGENT_SETUP_V1.md`](GPT_WORK_AGENT_SETUP_V1.md).
Use [`AGENT_CONTROL_AND_OPERATING_CONTRACT_V1.md`](AGENT_CONTROL_AND_OPERATING_CONTRACT_V1.md)
as the persistent Agent Instructions. Restrict GitHub to
`TrillionniumFoundation/Trillionnium-Chain`, require confirmation for writes,
and grant no merge, release, secret or production-credential authority.

Then send the Agent its A00–A17 starter message from the files below. The
starter message tells it to continue the package gap loop across current and
subsequent cloud/scheduled runs until one of these honest terminal states:

```text
MODULE_CLOSED_CANDIDATE
BLOCKED_UPSTREAM
BASE_DRIFT
STOP_CONDITION
RESUME_REQUIRED
```

`MODULE_CLOSED_CANDIDATE` means only that the Agent's package-local documented
gaps and evidence obligations are closed on its isolated candidate branch. It
does not mean merged, independently accepted, Gate-exit, release-ready or
production.

## 2. Prompt files

- [`AGENT_PROMPTS_A00_A02_V1.md`](AGENT_PROMPTS_A00_A02_V1.md)
- [`AGENT_PROMPTS_A03_A05_V1.md`](AGENT_PROMPTS_A03_A05_V1.md)
- [`AGENT_PROMPTS_A06_A08_V1.md`](AGENT_PROMPTS_A06_A08_V1.md)
- [`AGENT_PROMPTS_A09_A11_V1.md`](AGENT_PROMPTS_A09_A11_V1.md)
- [`AGENT_PROMPTS_A12_A14_V1.md`](AGENT_PROMPTS_A12_A14_V1.md)
- [`AGENT_PROMPTS_A15_A17_V1.md`](AGENT_PROMPTS_A15_A17_V1.md)

## 3. Prompt index

- # A00 — TRNM Control Tower
- # A01 — G0 Truth, Provenance and Reproducibility
- # A02 — G1-R2 Recovery and Core Acknowledgement
- # A03 — G1-R3 Ordinary Proposal Authority
- # A04 — G1-R4 Application and Ordered Finality
- # A05 — G1-R4 Safety, Signer, Checkpoint and Anti-Rollback
- # A06 — G1-R4 Fault Matrix and Independent Replay
- # A07 — G1-R5 Native 4/7-Node Campaign
- # A08 — G1.5 CEV1 Registry and Normative Specification
- # A09 — Independent Parser, Vectors, Mutation and Fuzz
- # A10 — G2.0 W0-W7 Traceability and Codegen
- # A11 — G2A DA-FULLREP-V1
- # A12 — G2B Agent, Capability and Task Market
- # A13 — G2D Deterministic Execution, MVCC and Fees
- # A14 — G2C Verification and Challenge
- # A15 — G2E Settlement and Economic Conservation
- # A16 — G2F Whole-Node Authority, State Sync and Light Client
- # A17 — G3-G5 Benchmark, Security, Operations and Activation Preparation

## 4. First publication order

Publish and test A00/A01 first. Then enable A02–A06 with no more than five
concurrent core-writing packages. A07 and A16 remain prerequisite-blocked for
promotion. A08–A15 may work concurrently on candidate specifications,
independent implementations and isolated kernels, but cannot promote later
Gates. A17 may prepare harnesses/runbooks and may not create readiness or
performance claims.

A scheduled run always re-reads GitHub. Agent Memory is not a source of
commit, status or evidence truth.
