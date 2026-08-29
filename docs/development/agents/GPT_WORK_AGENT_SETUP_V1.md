# GPT Work / Workspace Agent Setup Guide v1

Status: **operator setup guide; no repository or gate authority**

## 1. Create 18 Agent drafts

Create one Agent for each `A00` through `A17` in
[`AGENT_REGISTRY_V1.yaml`](AGENT_REGISTRY_V1.yaml). Do not use one broad Agent
for all modules.

For every Agent:

1. Name it with the exact registry ID and name.
2. Connect only `TrillionniumFoundation/Trillionnium-Chain`.
3. Require confirmation for GitHub writes.
4. Do not grant merge, release, secrets, production credentials, branch
   protection or deployment authority.
5. Use the strongest approved coding/reasoning model and high reasoning effort.
6. Put
   [`AGENT_CONTROL_AND_OPERATING_CONTRACT_V1.md`](AGENT_CONTROL_AND_OPERATING_CONTRACT_V1.md)
   in persistent Instructions.
7. Attach or make available the canonical Plan, execution-package map,
   engineering evidence contract, machine truth, release truth, this registry
   and the Agent's module-specific protocol/package documents.
8. Send the Agent its copy-ready first-task block from
   [`AGENT_PROMPT_PACK_V1.md`](AGENT_PROMPT_PACK_V1.md).
9. Preview the Agent before publication. Test base-drift, forbidden-path and
   stop-condition behavior.
10. Publish A00 and A01 first. Publish code-writing Agents only after ownership
    and interface boundaries pass review.

## 2. Recommended capabilities

### Core authority Agents A02-A07 and A16

- Memory: off or advisory only.
- Web search: off unless the package explicitly requires primary standards.
- GitHub: repository-limited, write confirmation, no merge.
- Schedule: package cadence from the registry.
- Required behavior: re-read exact GitHub source, Plan and machine truth on every
  run.

### Specification/evidence Agents A00-A01, A08-A15 and A17

- Memory may retain stable conventions, never commit/status/evidence truth.
- Web search may be enabled for standards/research, using primary sources.
- GitHub remains repository-limited and confirmation-gated.

## 3. First message

For the target Agent, copy the universal first sentence and the complete module
block under its `## Axx` heading. Do not send only the Agent name or a one-line
request.

The first message gives the Agent authority to continue its package-local gap
loop, not authority to bypass dependencies, write other modules, merge, promote
truth or activate production.

## 4. Continued autonomous work

A cloud run is finite. Continued work requires one or more explicit triggers:

- a recurring schedule;
- a new run triggered after an upstream interface/PR changes;
- an operator resume after `RESUME_REQUIRED`;
- a Control Tower dispatch after ownership and dependency checks.

Every run must leave `agent-handoff-v1` state and an exact next action. The next
run resumes from repository/evidence state, not from an unverifiable private
scratchpad.

Recommended cadences are in `AGENT_REGISTRY_V1.yaml`. A scheduled writer must
first acquire a package/generation lease; a concurrent run exits without
writing.

## 5. Rollout order

```text
Wave 0: A00, A01
Wave 1: A02
Wave 2: A03
Wave 3: A04 and A05 after interface freeze
Wave 4: A06
Wave 5: A07 after accepted R4 evidence
Parallel candidate prep: A08-A15
Whole-node integration prep: A16 after predecessor interfaces
Benchmark/security/ops: A17
```

No more than five core-writing packages are active concurrently.

## 6. Expected terminal states

- `MODULE_CLOSED_CANDIDATE`: package-local gaps/evidence complete; independent
  review still required.
- `BLOCKED_UPSTREAM`: required versioned interface/evidence absent.
- `BASE_DRIFT`: pinned source moved; rebase/rerun decision required.
- `STOP_CONDITION`: a safety, root, durability, economic, profile, light-client,
  custody or truth invariant failed.
- `RESUME_REQUIRED`: run ended due finite context/tool/runtime limits, with an
  exact continuation record.

It is incorrect to promise that one uninterrupted chat will run until every
project gap is closed. The correct guarantee is a repeatable, scheduled,
repository-backed package loop that keeps working while prerequisites and tools
are available and stops honestly at governed boundaries.

## 7. Operator review checklist

Before accepting an Agent PR, verify:

- exact base SHA/tree;
- owned paths only;
- no duplicate open package work;
- interface digest/version;
- positive/negative/fault results;
- retained failed mutants;
- evidence scope/authority/classification;
- known gaps and non-claims;
- downstream invalidation;
- independent reviewer;
- no global truth promotion in the feature PR.
