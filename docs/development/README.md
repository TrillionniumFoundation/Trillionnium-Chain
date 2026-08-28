# Chain development entry point

There is one live development plan:

[`TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md`](TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md)

The plan is executed with the supporting evidence contract:

[`TRNM_AI_NATIVE_BLOCKCHAIN_ENGINEERING_EVIDENCE_CONTRACT_V1.md`](TRNM_AI_NATIVE_BLOCKCHAIN_ENGINEERING_EVIDENCE_CONTRACT_V1.md)

The evidence contract is not a second plan. It defines the signed evidence
schema, canonical transaction-to-settlement trace, wire conformance rules,
benchmark manifest, launch-profile fields, and downstream-gate invalidation
rules used by the single plan.

The complete review-sized G0–G5 package decomposition is:

[`TRNM_AI_NATIVE_BLOCKCHAIN_EXECUTION_PACKAGES_V1.md`](TRNM_AI_NATIVE_BLOCKCHAIN_EXECUTION_PACKAGES_V1.md)

The active implementation package is:

[`packages/TRNM_G1_REPLAY_RECOVERY_AND_CORE_ACK_EXECUTION_PACKAGE_V1.md`](packages/TRNM_G1_REPLAY_RECOVERY_AND_CORE_ACK_EXECUTION_PACKAGE_V1.md)

Execution-package files are subordinate work contracts. They cannot override
the canonical plan, protocol, machine truth, release conclusion or evidence
requirements, and they do not create a second roadmap.

The machine-readable authority tuple is recorded in
[`plan-manifest-v1.toml`](plan-manifest-v1.toml). Its hash is provisional until
the plan and manifest are committed and signed together.

Architecture/protocol contracts, `config/consensus-mainline.json`, and
`RELEASE_READINESS.md` remain the truth authorities for their respective
domains. Dated delivery boards and superseded schedules are under
`../audits/` and are not execution instructions.

Other linked worktrees and historical branches may still contain older copies;
they are audit inputs, not parallel authorities. New work must start from the
canonical PoCO mainline and this plan, and any branch promotion must carry an
explicit evidence/manifest decision. A plan or evidence bundle that is
untracked, hash-inconsistent, or unreplayable from a clean clone is not an
authority for gate promotion.
