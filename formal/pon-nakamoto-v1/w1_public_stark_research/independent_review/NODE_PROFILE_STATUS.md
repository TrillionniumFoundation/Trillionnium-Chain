# Node profile status for the W1 P3 research

## Finding

At the two reviewed commits, the P3 and carry research profiles have no observed dispatch or qualification reference in the runtime workspace, configuration or qualification tree. The concrete Node work path examined calls the existing native PNW1 verifier. Standalone P3 proof generation and verification do not close the production Node integration and qualification gate.

Qualification remains **HOLD_NO_GO**. This record covers tracked source at fixed research commits. It does not describe the latest `main`, installed binaries, a running production Node, deployed configuration or live admission behavior. No Node process, production ingress or deployment was exercised by this reviewer, and no admission or activation logic was changed.

## Fixed scope and retained evidence

The source comparison used:

- Research publication baseline: `3bbd072e4983eceee4531d7576d329da5b0d0900`.
- Reviewed carry v2 commit: `ac4927c52266e7bd1fae547f92a1d0753f4f96d6`.
- Observed HEAD of the inspected research worktree at review time: `ac4927c52266e7bd1fae547f92a1d0753f4f96d6`.

The committed diff between those revisions contained no change under `trillionnium/`, `config/` or `qualification/`.

The integrator reports that subsequent additions for this work are confined to `formal/` and `docs/`. That is integration context, not an extension of this source audit to a new commit. This record retains its original two revision pins and makes no claim about a later `main` or production deployment.

[The original read-only evidence](readonly-review-ac4927c.json) contains the source objects, selected exact source lines, searches and observed worktree metadata:

- Schema: `trnm-readonly-carry-and-node-review-evidence-v1`.
- Size: 91,458 bytes.
- SHA-256: `c3d15b152a73dd5103c177f0c950d716b80f27f7a47ff3b5ae4232fa93b0cd33`.

The JSON is attached unchanged. It predates the later packed-source review, which is recorded separately in [the carry review](CARRY_INDEPENDENT_REVIEW.md).

## Minimal positive source evidence

All paths below are repository-relative. The four listed blob identities were unchanged between the two reviewed commits.

| Source | Observed behavior | Git blob |
|---|---|---|
| `trillionnium/crates/trnm-pon-node/src/store/growth/work_checked.rs` | `GrowthWorkCheckedPacket::verify_with_progress` encodes the packet, then calls `pon_work::verify_with_progress` with its challenge, task, target and proof bytes. The wrapper carries no activation or admission authority. | `f247b152dfdbddfb29fcf95c97fdaeb0742d25b4` |
| `trillionnium/crates/trnm-crypto-primitives/src/pon_work.rs` | The work profile is `pon-matmul-transcript-64-v1`. The default selects `VerificationKernel::FullLimb`, with fixed PNW1 grammar. No P3/carry variant is present in the inspected kernel enum. | `ce1608248d2ee67ed8f5d82a2c5f15942689139b` |
| `trillionnium/crates/trnm-pon-node/Cargo.toml` | The Node crate declares `role = "experimental-native-composition"`, `production_activation = false` and `consensus_authority = false`. Its dependency list does not include the P3 research crate. | `eb44e7bc91a36b54ae025e5c1f1629e548af204f` |
| `formal/pon-nakamoto-v1/w1_public_stark_research/Cargo.toml` | The P3 dependencies belong to the separate `w1-full-public-stark-research` crate, which declares its own `[workspace]`. | `b1471a6c56e64fb1b7b150cecea9c55806c6d560` |

The fixed PNW1 parser requires `4 + 3*4096*4 + 32 = 49,188` bytes and the four-byte prefix `PNW1`. The default verifier passes through this check. A research `W1P3...` component envelope presented directly to that path fails the length check or, if resized to the fixed native length, the version check. This conclusion follows from the inspected source; it is not a recorded live ingress test.

Two additional records agree with that boundary:

- `config/portability-inventory-v1.json` assigns `trnm-pon-node` to M15 as a native development composition, with production activation and consensus authority false. Its role text makes no publicly qualified deployment claim.
- `docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md`, in the dated complete W1 AIR/STARK research entry, explicitly records that no production Node wiring or task-admission change was added. The retained exact excerpt is in the evidence JSON.

## Complete scoped reference search

For each fixed revision, the reviewer ran a tracked, case-sensitive literal `git grep -n -I -F` search across all of `trillionnium/`, `config/` and `qualification/` for:

```text
W1P3SHA1
W1P3ARI1
W1P3ACR
w1_public_stark_research
w1-full-public-stark-research
carry_backend
Dot8CarryAir
CARRY_COMPONENT
p3-uni-stark
p3-fri
plonky3
```

Both scoped searches returned zero matches, the expected no-match exit code 1, empty stderr and `truncated = false`. The retained `node_scoped_searches` entries record the exact terms, scopes and revisions. These results complement the positive native call-chain evidence above.

The later `W1P3APC3` packed snapshot was not present in these fixed-revision Node searches and is not silently added to their scope. Its separate source review establishes a research component-4 example, not Node dispatch or qualification. The integrator's report that subsequent changes remain in `formal/` and `docs/` does not by itself become a newly executed source audit.

## Existing blockers for the fifth gate

The reviewed source does not provide a versioned Node dispatch/adaptation path for the paired P3 components and canonical public statement, including their binding to the Node's expected challenge, task and target. It does not provide a Node resource-profile selection or qualification entry for this research PCS verifier. Its native PNW1 path and experimental Node activation declarations remain in force.

Consequently, the available evidence establishes standalone research verification and separate AIR review. Production Node integration still requires an actual admitted profile and dispatch path, its Node-context and resource-policy binding, and qualification evidence on an exact integrated source/configuration. The independently open noninteractive-security, end-to-end benefit, malicious-rejection and physical-work-cost gates are not discharged by the standalone verifier or these source searches.
