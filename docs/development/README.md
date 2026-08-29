# Chain development entry point

There is one live development plan:

[`TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md`](TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md)

The plan is executed with:

- [`TRNM_AI_NATIVE_BLOCKCHAIN_ENGINEERING_EVIDENCE_CONTRACT_V1.md`](TRNM_AI_NATIVE_BLOCKCHAIN_ENGINEERING_EVIDENCE_CONTRACT_V1.md)
- [`TRNM_AI_NATIVE_BLOCKCHAIN_EXECUTION_PACKAGES_V1.md`](TRNM_AI_NATIVE_BLOCKCHAIN_EXECUTION_PACKAGES_V1.md)
- [`TRNM_DEVELOPMENT_DOCUMENTATION_UPGRADE_V1.md`](TRNM_DEVELOPMENT_DOCUMENTATION_UPGRADE_V1.md)

The current source identity is summarized, without promoting it, in
[`CURRENT_SNAPSHOT_V1.json`](CURRENT_SNAPSHOT_V1.json).

## Current candidate stack

The latest candidate source used by this documentation upgrade is
`feature/chain-g1-r4c-full-gap-closure-20260829@6e0189e351015ef3230f217ca7ff86149baedcf0`.
It is a Draft/unaccepted candidate, not a gate exit.

Current promotion-critical work spans:

- G0 truth/provenance closure;
- G1-R2 recovery/Core acknowledgement;
- G1-R3 ordinary proposal/execution/AuthorityVote;
- G1-R4 application/Safety/checkpoint/multi-block/anti-rollback;
- G1-R5 native 4/7-node evidence.

See [`packages/README.md`](packages/README.md) for the subordinate package index.

## Multi-agent execution

The 18-agent control plane, ownership map and copy-ready Workspace Agent prompts
are under [`agents/`](agents/AGENT_CONTROL_AND_OPERATING_CONTRACT_V1.md).

These files are execution contracts, not a second roadmap. Agents may close
candidate gaps and create evidence on isolated branches. They cannot change
machine truth, release status or activation merely by producing code, tests or
documents.

The machine-readable Plan authority tuple remains in
[`plan-manifest-v1.toml`](plan-manifest-v1.toml). Architecture/protocol
contracts, `config/consensus-mainline.json`, and `RELEASE_READINESS.md` remain
authorities for their respective domains.
