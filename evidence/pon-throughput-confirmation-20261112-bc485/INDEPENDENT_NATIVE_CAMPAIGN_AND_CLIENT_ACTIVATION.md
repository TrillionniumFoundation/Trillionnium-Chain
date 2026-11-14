# Independent current-head native confirmation and durable-state readback (2026-11-12 UTC)

**Status: HOLD_NO_GO.** This is a completed independent read-only audit of one exact-source GitHub Actions run. It does not change source code, testing denominators, original resource enforcement, consensus/finality, W1/M06/Host checks, or claim production throughput.

## Fixed provenance

- Draft [PR #890](https://github.com/TrillionniumFoundation/Trillionnium-Chain/pull/890); **actual tested head** `bc485f46beb3b6acb244a0be06197bc1a8dfd0a8`; **tested tree** `ba108a0d61767365749ba194b0852bbf8fdd8851`; stacked base `e4abb172147e941b62483652b0ceabaae4317624`. Do **not** transfer this native result to an evidence-only successor commit.
- Original [Actions run 43128060852 / job 130885076481](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/43128060852/job/130885076481), original artifact **13905756051**: ZIP size **76,585,530 bytes**, independently computed ZIP SHA-256 `d5a6e42f299a19d30d31be2dcbf184ccdf0d155d0c615e5580dce3c85975d6d2`.
- Stream-verified **1,765/1,765** manifest members, each complete byte length, SHA-256 and ZIP CRC; **587,408,756** total manifest-listed uncompressed bytes, **0** missing, mismatched, or unlisted members. A further ZIP member is the manifest itself.
- Original source-before/build/campaigns/after records agree on the tested commit/tree, tracked clean worktree. Cargo **1.95.0 locked/offline release test build succeeded**, and retained native executable SHA-256 (before/after) is `fb29efccdc75af04f3ce7938fb4d5d472d63f8b9ad401ec6cac21091aa535868`, **12,646,952 bytes**. This proves build/file identity, not business acceptance.

## Original campaign result: still failed

| Original measure | Current tested-head result |
| --- | ---: |
| Complete original campaigns | **0 / 3**; all three returned **101** |
| Qualified phases | **0 / 9** |
| In-window confirmations | **3 / 27** scheduled; **12** observed, **15** not reached |
| Timely honest Submit ACK | **84 / 84** |
| Receiver full-work accepted | **84** |
| Hostile client attempts | **16,224** (not the same unit as the following count) |
| Receiver full-work failures | **16,094** |
| History RPC and actual import attempts | **65 / 65** returned/observed |
| Page imports completed / rejected | **56 / 9** |
| Equal final receiver/client native state | **0 / 9** |
| Genuine budget depletion | **0 / 9** |

The three successful in-window confirmations again refer to the *same fixed first-round fixture block* `1bbddf43d04bb6512e9f4fd84e394ca9a2f9c9ff5d1ef5ea54e525a2098c19ee`, repeated across three campaigns. They do not constitute three distinct independently settled business effects. ACK, native inclusion, chain depth, execution authority and finality are separately qualified.

## New exact-source durable-state finding: block stored but not active

The original six baseline SQLite DBs were copied into separate scratch directories and opened **read-only/immutable**; all six `PRAGMA integrity_check` returned `ok`. The active tips were reconstructed by following each stored block's `parent` pointers from the database's `active.tip`, rather than mistaking any row in `blocks` for an active-chain ancestor.

| Baseline run | Receiver active height | Receiver active-chain depth for included block at height 12 | Independent-client active height | Client has block row at height 12 | Client active-chain ancestor |
| --- | ---: | ---: | ---: | --- | --- |
| 1 | **18** | **6** | **11** | **yes** | **no** |
| 2 | **18** | **6** | **11** | **yes** | **no** |
| 3 | **18** | **6** | **11** | **yes** | **no** |

All three copies contain the exact second-round block `cb491d5dd5071dbec06dfe4f018c7340e130051c4c701054973a035fa39be709` at height 12. Unlike the older exact-source `53e1b98a...` native artifacts (receiver heights 17/17/16), **this current exact-source artifact has receiver active height 18/18/18 and the second-round block is an ancestor at depth 6**. However, **the independent clients have already stored that block as a database row while their active chains still end at height 11**. Mere storage, RPC success and Submit ACK therefore **cannot be treated as activation, depth, confirmation or finality**.

**Timing caveat:** this is a readback of the persisted **post-phase** databases. It does *not* prove receiver height 18 was reached within the original 30-second deadline. Confirmation for round 2 remained **not achieved in-window** in all three baselines; its terminal observation was `PUBLIC_REQUEST_DEADLINE`.

All six baseline `peer_replay`, `peer_outbox`, `peer_request_audit` tables have **zero rows**. This is absence of durable peer-request receipts in these specific fixture DBs, not a proof of general production idempotency failure.

## History CPU budget attribution

Across the **65** observed imports: **597,960** Host checkpoint calls; checkpoint invoking-thread CPU **30.184655380 seconds** nested within importer invoking-thread CPU **35.297041399 seconds**, or **85.52%** of the latter. These are overlapping timing scopes and **must not be added**, extrapolated to whole-process CPU or called removable without preserving all Host validations. There were **9** import rejections; even baseline phases returned `PUBLIC_REQUEST_DEADLINE` after late page processing. Original limits (0.25 CPU, 2 GiB, zero swap, 256 PID, four-second Host) and original 3 × 30-second denominators remain unchanged.

## CI classification and next gate

The complete current-head **22 workflow-run identities and each Job/Artifact index** were read from GitHub. Original campaign is **failed**; current required-baseline repository-truth retains a **`trillionnium/Cargo.lock` frozen PQ Root source-register mismatch**. W1 QROM closure and implementation have independent required-check failures (including exact changed-source binding / fixed input bound), and CodeQL exporter reported a GitHub transport failure after polling. No security finding or source qualification is inferred from a successful unrelated lane; unfinished jobs are not counted as passes.

**Next native acceptance gate:** on one frozen binary/config/Host resource identity, log timestamps for receiver active-chain reach to height 18 **inside** the deadline, then separately measure independent-client stored block, imported page, active tip promotion and authenticated receipt. For an uncertain Submit result, restart the *actual durable client owner* in another process/session; authenticate original request/transaction/effect ID and any inclusion/work/finality, then repeat the exact intent with a negative duplicate-effect assertion. Unknown remains UNKNOWN, never presumed safe to resubmit. Do not weaken any W1/M06/Host check or omit original capacity/churn, WAN, cold-recovery or 3 × 30 s denominators.

All four metrics—independently unique confirmed business TPS, accepted useful-task throughput, complete versioned weight-delivery throughput, real model-service throughput—remain **unqualified / null**. No production admission, customer-demand or independent WAN qualification is claimed.

This file records an independently verified **negative native acceptance result**, and one **previously unseparated stored-but-inactive client state**, not a fix or a passing CI run. **Draft / HOLD_NO_GO.**
