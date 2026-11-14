# Original baseline: receiver depth and independent-client gap (2026-11-12 UTC)

**Qualification: HOLD_NO_GO. This is an independent read-only analysis of an already failed native run, not a new performance experiment or a production-finality claim.**

## Exact provenance

- Draft [PR #890](https://github.com/TrillionniumFoundation/Trillionnium-Chain/pull/890), tested head `53e1b98a7955898b9feff4778f7136c0fd0199c8`, Git tree `094ccb0afc9e7ffbbcc83f85efb6ca4ad8d54aa0`, base `e4abb172147e941b62483652b0ceabaae4317624`. Do not transfer this outcome to any evidence-only descendant.
- Original [Actions run 43104547221, artifact 13894656010](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/43104547221/artifacts/13894656010): ZIP **71,025,468 bytes**, SHA-256 `9a2c2250205c6a5fe18524451addf56115aafbf951d9a5c2fd3f6056988e437e`.
- Independently streamed every entry in `artifact-files.json`: **1,765/1,765** member byte lengths, SHA-256 and ZIP CRC agree; **522,609,424** uncompressed manifest bytes; **0** missing/mismatched/unlisted members (1,766 ZIP entries including the manifest itself).
- Three actual original native campaigns completed with exit **101** each. Existing overall result remains **0/3 campaigns, 0/9 accepted phases, 3/27 scheduled in-window confirmations**. No raw result is renamed or waived.
- The original source responsible for phase scheduling is [`public_v3_multiprocess.rs`](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/53e1b98a7955898b9feff4778f7136c0fd0199c8/trillionnium/crates/trnm-pon-node/tests/public_v3_multiprocess.rs), Git blob `ec6420becaba837f22d45c917d15554a8e653275`: requests at fixed 1/5/9 s; after each seven signed submissions the independent verifier must import the complete History and call `confirmation` under the original 30-second deadline. Source `store.rs` Git blob `a8bd7b9c8d9b02617060bea955b3bb21d905129f` defines native confirmation depth as **observed tip height minus included block height**, and requires both the configured depth and work delta; `finalized=false` and `execution_authority=false` remain separate.

## Fresh independent native SQLite readback

The six original `run-{1,2,3}-raw/baseline/{receiver,independent-client}/native.sqlite` databases were opened in SQLite read-only/immutable mode. Every `PRAGMA integrity_check` returned `ok`. The preserved second-round included block is `cb491d5dd5071dbec06dfe4f018c7340e130051c4c701054973a035fa39be709` at **height 12**, present on every receiver and absent from every independent-client database.

| Original run | Receiver active height | Client active height | Receiver depth for second-round included block (height 12) | Client knows second-round included block | Second-round in-window confirmation |
| --- | ---: | ---: | ---: | --- | --- |
| 1 | 17 | 11 | **5** | No | No |
| 2 | 17 | 11 | **5** | No | No |
| 3 | 16 | 11 | **4** | No | No |

The same first-round included block `1bbddf43d04bb6512e9f4fd84e394ca9a2f9c9ff5d1ef5ea54e525a2098c19ee` is at height 5 and has observed depth **6** at the independent client's height 11. The six-depth original rule thus cannot be met by the receiver's end-of-window height 17/17/16 for the second-round block (would require active height **18**), **even if the client could immediately import every receiver block**. Independently, the client remains at height 11 and does not know the second-round inclusion at all. These are **two distinct acceptance blockers**, not one History timeout.

Receiver `native.sqlite` SHA-256 for runs 1 and 2: `518bc13908ee91bed9d56dc47319b5f609f67a63efff1c9bc20bf501ac686dcd`; run 3: `276152274bb001b9de8712aa881cd49a0988e045321e3cd988e8005f2667a536`. All three client SQLite SHA-256: `0d82fab1b620241a938621ce47bb4d66b6799e1e243b79b751a0d2004097c515`.

In **all six baseline DBs**, `peer_replay`, `peer_outbox`, and `peer_request_audit` each contain **zero rows**. This proves only that these exact fixture-state files do not contain a durable peer request receipt; it does **not** prove that other production paths lack idempotency. The fixed baseline uses a direct public request path and does not establish a cross-session timeout-retry acceptance test.

## Minimal independent reproduction (no source changes)

After verifying the ZIP and manifest, extract **only** the six SQLite files and `run-{1,2,3}-raw/report.json` to isolated storage, open `file:<path>?mode=ro&immutable=1`, execute `PRAGMA integrity_check`, `SELECT hex(tip),generation,state_slot FROM active`, `SELECT height FROM blocks WHERE id=?` for the native active tip and second-round included block, and `SELECT count(*)` on the three peer tables. Compare the two original `confirmations` rows per baseline report to the block IDs; do not infer a business effect or finality from block membership alone.

## Required next native gates (not satisfied here)

1. Under the **unchanged 0.25 CPU / 2 GiB / zero swap / 256 PID / 4-second Host boundary** and original **3 × 30-second** conditions, distinguish receiver work growth to height 18 from independent-client complete-page import/activation. Retain original W1/M06/Host checkpoints and record nested CPU without addition.
2. After an ambiguous Submit timeout, exit the client; reopen its *original* durable owner in a **new process/session**, query the original request/transaction/effect identity from the receiver's durable state, authenticate membership, depth, chain work and execution outcome, then retry exactly the same intent under a negative duplicate-effect check. Log original and retried request IDs and effect cardinality. Unknown or missing proof must remain UNKNOWN, never success or safe-to-resubmit by default.
3. Establish native independent confirmation with original resource denominators, capacity/churn, WAN, cold recovery and production demand before any unique-business TPS, paid useful-task throughput, weight-delivery throughput, or model-service throughput is called measured.

**No new code, native execution, source pin, budget, cryptographic check, test denominator or acceptance rule is changed by this evidence file. The original client/receiver mismatch, all failed phases, and draft status remain.**
