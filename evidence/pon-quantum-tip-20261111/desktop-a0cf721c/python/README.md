# Exact source desktop Python observations

This directory archives an actual desktop execution of candidate `a0cf721c0a3fd5bc034e010119d2b09d148de8ec` and tree `0fee4598d69db92beea2845c6d939f059f2d14a3`. The candidate branch was not changed by this archival step. These are local process results, separate from GitHub Actions results.

The durable Python job was `1a1c86d9577-135c4-67`. It ended with `state=succeeded`, exit 0, no timeout, complete durable stdout, and no stderr. The batch began at 2026-11-11T02:26:29.296669+00:00 and finished at 2026-11-11T02:28:52.994979+00:00. The frozen driver SHA-256 is `058552b6353680ca4f9adb097cd59935ad695f84e5899cc4dc699d1006fde18f`.

## Observed results

All 10 unittest suites completed successfully. The total below is derived from their actual `Ran ... tests` and `OK` footers, and each underlying command returned exit 0.

| Suite | Actual tests passed |
| --- | ---: |
| network-tests | 58 |
| adversarial-tests | 12 |
| resource-clock-tests | 18 |
| joint-tests | 34 |
| participation-tests | 28 |
| lifetime-tests | 58 |
| w1-lifetime-tests | 19 |
| storage-evidence-tests | 19 |
| discovery-evidence-tests | 5 |
| ci-contract-tests | 180 |
| **Total** | **431** |

Project preflight, source inventory, corpus pins, the joint qualification contract, and the CI contract returned exit 0. The separate qualification request returned exactly 3 and `qualification_request=REFUSED_UNPROVED_JOINT_CONSENSUS`.

The fixed paired campaign produced 72 observations and 36 pairs. All 72 observations reached the declared horizon without a trace limit. Verification actually replayed all 72 observations and passed source binding and trace arithmetic. The panel recorded 1844 tip measurement requests.

Both full tracked-source checks verified 27930 entries and 2555806765 bytes. `source-before.json` and `source-after.json` are byte-identical, with SHA-256 `bbf4c3be432d3440eff4ee91c279c9e134d2bc1b0d4e16521926f5b12490f9bb`. The runner also requires its source and runner files to be committed at the tested HEAD.

## Archive contents and integrity

`observations.zip` contains 199 regular file members: all 193 original observation files without byte changes, the frozen driver, runtime launch and terminal receipts, durable stdout and stderr, and an archive manifest. It includes all 72 compressed raw traces, the complete paired report and manifest, every command's raw combined output, argv, cwd, real exit status, timing receipt, all source JSON, and all execution summaries and manifests.

ZIP size: 1243895 bytes. ZIP SHA-256: `299afbddd6f390d2f19c5346c746d5dfe5d4e39856d4650ffbdd8568ae494acb`.

The ZIP was reopened and every member was compared byte-for-byte with the original input. `archive-members.json` lists every member's size and SHA-256. Readable copies of the execution summary, manifest, before/after source identity, frozen driver, durable terminal receipt, and durable stdout are provided alongside the ZIP. The completed observation directory was not changed while packaging.

## Scope

This driver did not execute native Rust tests. Native test observations belong to their separate evidence records.

These results check implementation behavior under the declared simulation assumptions. They do not prove native W1 quantum realizability or an oracle lower bound, and they do not establish common prefix, chain growth, chain quality, or whole-chain quantum security. Native W1, CP/CG/CQ proof, and release qualification remain false in the report; the joint qualification request was explicitly refused.

The network uses a common propagation delay and first-seen equal-work ties. For the usual reactive same-parent race, this represents gamma = 0. The observations do not cover heterogeneous network races or prove aggressive mining ineffective. Matching random seeds are reproducibility inputs; after policy-dependent events diverge, they are not fixed-arrival counterfactuals. The finite N = 4096 cases are narrow-domain stress observations, with many empty marked domains, and do not represent the full native nonce space.
