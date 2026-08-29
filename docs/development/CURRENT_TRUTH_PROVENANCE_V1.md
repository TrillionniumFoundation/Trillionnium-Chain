# Current truth and provenance observation v1

This file is explanatory. Machine-readable authority is split between
`plan-manifest-v1.toml`, `plan-evidence-manifest-v1.json`,
`CURRENT_SNAPSHOT_V1.json`, and `config/consensus-mainline.json`.

## Identity table

| Role | Ref | Commit | Tree | Authority |
|---|---|---|---|---|
| Default branch observation | `refs/heads/main` | `b2d485e5641614ea0ca34ebf80a5f7843ff1e6d9` | `ffbad926850a12159336126390271abffc1d99a6` | observation only; commit signature verified |
| G1 candidate baseline | `refs/heads/feature/chain-g1-r4c-full-gap-closure-20260829` | `6e0189e351015ef3230f217ca7ff86149baedcf0` | `efea864cb2fbc4835a59a089b3dbab8934e71231` | Draft, unaccepted |
| Agent control plane | `refs/heads/docs/agent-fleet-plan-v1-20260829` | `8bfd73f0cf1b785a29ae212f13212e51fe34231e` | `cfedd363147934f50d1352dae31b7d87d79aa8d9` | subordinate documentation candidate |
| Assessed Plan authority | `refs/heads/docs/chain-poco-bft-mainline-20260825` | `8198fea0307eb368df34ff77ffc272a6b0e655ec` | `a1be71bba1b54c428493d186fafb656d081b31a9` | provisional until committed and signed |
| Live Plan branch tip | same ref | `92449b8e101642f39d644d863db7bb60dea488f7` | `cf8f1ab4f5065cb0551a30ec0e036cd44cb31766` | observed only; not substituted for assessed authority |

## Lineage

- assessed Plan authority → live Plan tip: ahead 12, behind 0;
- candidate baseline → Agent control head: ahead 32, behind 0;
- default branch tip → candidate baseline: diverged, ahead 645, behind 1.

The last row means `main` and the candidate are not a linear release chain.
Neither side may be called the other without a reviewed integration decision.

## Workflow observation

Five PR-triggered runs were observed on the exact control head. One G1-R2 run
succeeded; three were skipped; the Agent documentation/payload-replay run
failed. No run has `G0_TRUTH_PROVENANCE_V1` scope, so the G0 eligible count is
zero.
