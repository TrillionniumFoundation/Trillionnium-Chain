# Original PQ Root native campaign: terminal History failure boundaries (HOLD)

This is a **diagnostic-only** continuation stacked on [#862](https://github.com/TrillionniumFoundation/Trillionnium-Chain/pull/862), not an original workload modification or acceptance run. It adds a fail-closed *last History import* stage attribution to `scripts/ci/inspect_native_campaign_failure.py`, its unit controls, and the machine-readable [terminal-boundaries.json](terminal-boundaries.json).

## Immutable primary observations

- Source commit **`df927b6ffaecff293b9e9428e3ba516f47cd101a`**, tree `a883a05b590fb8b0113b3715f4294eee7a00275b`.
- [GitHub original native workflow 42793318645](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42793318645), original artifact **13762887011**; downloaded ZIP SHA-256 `7998dea9c8bd1e7f1b5e4f4cc795265983e6e6ac46718f19594b94b2767cecd4`.
- Original full `run-{1,2,3}-raw/report.json` SHA-256, in order: `f49934336738b3431fc30042b06f66aeebab1f0eabd6d706fd04dc796bcfea4a`, `447c4ad2d94a1adfe685de31be8332c5d3ea33783c1a1ad3744ec68dda313199`, `4c4578087502925829605eb450e323d4f895ae3805746a5b86adf671687789cf`.
- Original fixed workload: three runs, each 1,024 seed transfers, 4 seed blocks, 21 business blocks, three 30-second phases, attackers 0/24/24. All **3/3 runs failed**, all **9/9 phases failed**.

The **last** History request in each of the nine phases has `status=ok` at the outer network level but `client_import.succeeded=false` and `client_import.error=PUBLIC_REQUEST_DEADLINE`. Earliest observed failing internal packet boundary:

| Run | Baseline | From-zero | Late-product |
| --- | --- | --- | --- |
| 1 | admission | submit_result | submit_result |
| 2 | admission | submit_result | admission |
| 3 | admission | submit_result | submit_result |

Thus **4/9** first fail in the admission phase; **5/9** first fail at `submit_result`, with `commit` recorded completed and accepted for those five. The three baseline cases also record a nested `commit` deadline, but a propagated error is not two independent root causes. No claim is made about durable atomicity or actual end-to-end effects from an observation of a completed commit interval.

All nine receiver/client state-equality checks and signed-round-window checks are false. No genuine paid-budget depletion is observed. The successful outer network response cannot be counted as a successful native import. This stage attribution is not evidence that checkpoint overhead alone caused each deadline.

## Validation boundary

Independent local offline reproduction against the original unmodified downloaded ZIP performed three focused tests: original nine-stage split, missing/ambiguous evidence, and nested propagated deadline precedence (**3/3 passed**). This is separate from the original fixed Host campaign; the branch's augmented unit suite and new GitHub CI remain subject to their own execution results.

The code does not alter `public_v3_multiprocess.rs`, workload, cgroup CPU/memory/PID resource limits, original deadline, budget, policies, scoring, or `HOLD` flags. No independent custody, non-co-rollback freshness, real provider/M15/FinalUse settlement, versioned migration authority or formal PQ multi-user/query composition evidence was supplied. In particular `actual_lifetime_failure_bound=null` and `whole_chain_pq_qualified=false` remain mandatory.
