# Project and development boundary

This Git root is **Trillionnium Chain** (`trillionnium-chain`), lane
`chain-consensus`. Before a write, build, commit, branch, remote, or dependency
change, run:

```bash
bash scripts/project-preflight.sh
```

Stop on a repository, project ID, lane, remote, source tuple, dependency, or
protected-branch mismatch. Do not rely on person-specific absolute worktree
paths or compatibility aliases.

The only active development direction is
`docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md`. Machine truth
is `config/consensus-mainline.json`; compact module and release-train data live
beside the plan. Git history is the archive. Do not create another roadmap,
delivery board, sprint plan, agent prompt pack, package narrative, continuation
note, or active historical-document directory.

Every implementation change declares one primary module from M00-M17. Cross-
module work changes the versioned contract first and requires producer and
consumer review. Candidate, fixture, lab, research, benchmark, and legacy code
must not enter the production dependency closure.

This repository owns consensus, canonical runtime/state, transaction admission,
RPC/node interfaces, genesis/validator/operator tooling, and canonical finality
and proof semantics. It does not own World gameplay, business-service
orchestration, Nakama rooms or matches, or sibling-worktree dependencies.
