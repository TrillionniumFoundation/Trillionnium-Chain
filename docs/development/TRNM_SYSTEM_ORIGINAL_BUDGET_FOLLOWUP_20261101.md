# Original-budget follow-up: native failure remains authoritative

Observation snapshot: 2026-11-01, after the completed `64cb26b` x64 head retry.
This is a source-bound supplement to
[the earlier audit](TRNM_SYSTEM_ORIGINAL_BUDGET_EVIDENCE_20261101.md).
The accompanying [structured evidence](TRNM_SYSTEM_ORIGINAL_BUDGET_FOLLOWUP_20261101.json)
retains the exact source identities, downloaded artifact digests, native exits,
stage counters and local-control receipts. Results below belong to their named
sources; they do not certify later commits containing this document.

## Acceptance remains HOLD

The original CPU policy, independent business confirmation and complete History
gates remain separate. ACKs, an outer metering `Ok`, successful compilation,
release-profile tests and mathematical-cache hits cannot close a failed native
or business gate. No full-chain TPS or complete PQ qualification is established.

| Gate / source | Actual result | Boundary |
| --- | --- | --- |
| Original workspace test profile, `64cb26b`, x64 head | Both original large-state tests fail with `PUBLIC_MUTATION_CPU_BUDGET` | Full original graph compiled; four named selectors actually ran |
| Default release, `64cb26b`, four source/architecture cells | Four named tests passed in each cell; ARM-head artifact creation failed | Overall run is failure; three ZIPs were actually read back |
| Original four-second business window, `b97f632` observations | Seven timely honest ACKs, independent confirmation 0/1 in each of four inspected artifacts | Four execution artifacts, not a complete architecture/source matrix or a throughput distribution |
| Original thirty-second campaign, `5606a971` | Each of three runs: baseline 1/3, from-zero 0/3, late-product 0/3 | All offered rounds remain in the denominator, including unattempted rounds |
| Original 4,105-block History, `5606a971`, four cells | Four native failures; independent active height remains 0 | Actual lifetime exits observed at the unchanged 1,800-second limit |

## The completed original-profile CPU retry

[Run 41332424883, attempt 2, job 124930286370](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/41332424883/job/124930286370)
tested head `64cb26b53ed82be14049000387040ba119f00e1e`, tree
`1eccfeefc4f68f3b82e721ba08b9a80248e2860e`. Its
[artifact 13094428721](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/41332424883/artifacts/13094428721)
was downloaded: 86,992 bytes, 49 members, verified CRC and SHA-256
`8032f55d06b6f789caa35f1ad0307664814040d27c765cf456c13a80c5f3fe1a`.

| Executed case | Paid / settled CPU | Credited refill | Final credit | Native / tee / reader |
| --- | ---: | ---: | ---: | --- |
| First selector, Legacy | 2.656805504 s | 0.626746999 s | -0.030058505 s | 101 / 0 / 1 |
| Independent supplementary Authenticated | 2.623309213 s | 0.620740593 s | -0.002568620 s | 101 / 0 / 1 |
| Lifetime-exit control | Not a CPU-policy benchmark | Not applicable | Not applicable | 0 / 0 / 0 |
| External-stop control | Not a CPU-policy benchmark | Not applicable | Not applicable | 0 / 0 / 0 |

The first selector fails during Legacy and never executes its later
Authenticated case. The supplementary selector supplies an actual independent
Authenticated failure. Each failing native summary is 0 passed / 1 failed /
0 ignored. Its reader JSON is empty and reader stderr correctly rejects the
failed test; this is not a parser failure to be waived.

Both CPU observations preserve the original 2,000,000,000 ns initial credit,
250,000,000 ns/s refill, 100,000,000 ns start reserve and two-worker limit.
Accounting is available, both workers finish with known CPU, and
`live_refused=true`. A two-second initial burst is not a constant total-CPU cap.

`original_dispatch_result: {"Ok":"ok"}` describes the outer
`Result<MeteredResult>`. The inner `result.native` remains the actual CPU-budget
error. It proves neither native success nor commit success. Both
`active_state_unchanged_on_refusal` fields are null: that readback was not executed
for these metered-wrapper results. Null is not a successful state-invariance check.

The actual command builds the locked full workspace, all targets and all features
with Rust 1.95.0 in the unchanged test profile. Cargo records 520 compiler artifacts
and 26 workspace packages, followed by successful build completion. Node is
opt-level 3; M06 is opt-level 1; both keep debug assertions and overflow checks.
Actual `serde_json` 1.0.149 is opt-level 0 with `arbitrary_precision`, `default`
and `std`. The original pinned static OpenSSL 3.5.9 provider and its positive and
negative smoke observations are retained. Provider preparation is not whole-chain
PQ acceptance.

Source-before equals source-after. The original, before and after Node ELF hash
receipts agree on
`9efe8d51fe01c4ea5d87b8efd90ab3eb612113d13cc448e85b4d4a222eb5a583`.
The archive contains binding receipts rather than the ELF body; no local
recalculation of an absent hosted ELF is claimed.

## What the stage counters support

These are actual Authenticated counter differences for the same dispatch.
Intervals are inclusive/nested and must not be added. Stage CPU measures the
current thread; it excludes scoped-worker CPU.

| Stage | Calls | CPU |
| --- | ---: | ---: |
| admission | 2 | 2.620870793 s |
| publish | 1 | 1.250197330 s |
| execute | 1 | 0.835147840 s |
| verify_state | 4 | 1.091192656 s |
| complete_commitment | 5 | 1.206653171 s |
| complete_state_root | 5 | 0.599297054 s |
| execution_parent_binding | 1 | 0.355868312 s |
| account_graph | 4 | 0.000732593 s |
| activation | 0 | No executed interval |

This large-string fixture has little account-graph cost. The measured remaining
work concerns complete current input, commitment/publication and execution.
The difference between commitment and root intervals cannot all be attributed
to serialization. Mathematical reuse is real (19,573 partition roots reused,
42 computed, no original-algorithm error fallback), but the whole native policy
still fails. A small final credit deficit does not establish the cost of any
later, unexecuted work. Authenticated-only zero counters are not a Legacy profile.

## Default release and local semantic controls are narrower evidence

[Default-release run 41332424790](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/41332424790)
binds the same head and actual merge
`2c3a3aaa29e1ff75bc919694c2817c84873d7b77`, with the same tree. Logs show all four
named tests actually passed in all four cells. Three artifact ZIPs were downloaded
and checked: 12 native/tee/reader triples are 0/0/0, 12 execution JSON records
are PASS, and source/ELF binding receipts agree. The ARM-head upload instead
returns `403 Forbidden: job is completed`; its artifact remains missing and its
job cancelled. The overall run is failure. Release uses different compiler checks
and optimization and does not override the original-profile failures above.

On exact `64cb26b` locally, the additional package-only M06 `pon_commitment` group
finished with 29 passed, 0 failed and the five original explicitly ignored
microbenchmarks. All five newly added bounded-root semantic controls ran and
passed. The actual M06 libtest uses opt-level 1 with both checks enabled and PQ
features; this package build is not the original full-workspace gate.

Seven additional Node integration controls passed using completed executables
from the interrupted full-graph local build: five `derived_commitment` tests and
two active-state cancellation/generation tests. Their actual source and ELF bytes
were checked before/after. The original overall local build still failed while
compiling the separate Node libtest; these integration passes do not rewrite it
as a complete-build pass. Earlier `8a77adb` failed with a missing independent
Node-constructor field; `64cb26b` fixes that compile error. Two later local full
build attempts received SIGKILL. Those failures remain recorded.

A later shared-disk exhaustion prevented a normal command from starting. Before
the bounded cleanup could run, the local build-cache directory was observed
absent; that cleanup stopped at its initial path assertion. Source, original
native logs and their execution-time before/after hash receipts remain, but no
successful archival of those local ELF bodies is claimed. This later availability
observation does not change the recorded test outcomes.

[The recovered `64cb26b` quality shard](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/41332424801/job/124931986054)
completed its retained formatting, dependency, documentation-test and strict
Clippy commands successfully. It does not execute the complete runtime shard.

## Complete History: actual exit branch, still failed completion

All four original tests in
[5606 priority run 41296585278](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/41296585278)
failed. Exact stored heights below come from retained confirmer databases opened
read-only and immutable, with unchanged database SHA-256 before/after inspection.
They are not the last printed 500-block milestones.

| Cell | Exact stored height / 4,105 | Independent active height | Recorded lifetime exit |
| --- | ---: | ---: | ---: |
| x64 head | 3,041 | 0 | 1,800.000815044 s |
| x64 actual merge | 3,190 | 0 | 1,800.000594233 s |
| ARM head | 2,503 | 0 | 1,800.000349999 s |
| ARM actual merge | 2,522 | 0 | 1,800.000144421 s |

All validators retain all 4,105 work packets and active height 4,105. All four
service records identify `lifetime_expired` before internal shutdown; the original
configured lifetime remains 1,800 seconds. The later cleanup stop flag does not
prove an external stop request. These observations confirm the termination branch
in these runs, not every cause of insufficient progress. Increasing the lifetime
would still not pass this original gate. Full test elapsed time includes building
the source chain and is not pure cold-sync time.

## Keep the performance paths distinct

The [original 4,105-block test](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/64cb26b53ed82be14049000387040ba119f00e1e/trillionnium/crates/trnm-pon-node/tests/ancestry_long_sync.rs)
calls `Node::open`, selecting Legacy, and keeps the
confirmer active at genesis until the complete import. Legacy snapshots occur
every 128 blocks; this chain has 32 non-genesis cadence snapshots under the
unchanged 64-row retention limit. Normal sequential import reconstructs a retained
snapshot suffix. The three located admission rebuilds are execution-time parent,
post-write parent and post-write child. This is not three identical parent calls.

AuthenticatedV1's [history verifier](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/64cb26b53ed82be14049000387040ba119f00e1e/trillionnium/crates/trnm-pon-node/src/store/native_authenticated.rs)
still walks parents toward genesis,
but that alone does not establish the hotspot of this Legacy test. The original
[four-second confirmation fixture](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/64cb26b53ed82be14049000387040ba119f00e1e/trillionnium/crates/trnm-pon-node/tests/public_v3_from_zero.rs)
also selects Legacy. The Authenticated campaign,
large-state fixture and Legacy cold sync need their own native evidence; costs
must not be transferred between them.

The following source candidates address separate work, with no native acceptance
claim in this observation snapshot:

- ASCII encoding: a bounded word-at-a-time guard selects only unescaped ASCII
  strings after original validation. It preserves the pinned serializer's bytes,
  initial Vec capacity and write sequence, including accounting-relevant spare
  capacity. Other values use the original serializer. Direct-serializer controls
  check escaping, capacities, grammar/error order and budget choices.
- Reorganization readback: reuse is confined to one existing authenticated write
  transaction, after its last real write. A strict epoch check follows the last
  callback even if no duplicate graph was consumed. The original writer is checked
  on success and error; no readback scope crosses COMMIT. Real genesis and
  non-genesis forks, every cut, cold reopen, transaction replacement and callback
  writes have explicit controls.
- SQL preparation: only prepared statements are reused for current record,
  snapshot and Legacy delta queries. All actual reads, parameters, decoding,
  intermediate roots and progress/Host checks remain. Record/snapshot helpers are
  shared by other backends, so the impact is not described as Legacy-only. Snapshot
  cadence and retained-state policy are unchanged. Current Node authorizers use
  static Allow/Deny read policies without Ignore projections; the scope does not
  certify a mutable authorization policy behind an unchanged prepare-time handler.
  Warm-cache controls install and replace denial handlers for each queried table.
  Transaction ownership remains observed at SQL execution.

Each candidate must be executed on its own final source. The updated original
test-profile workflow keeps the four original selectors first and retains their
failures, then independently runs the new semantic controls from the same complete
workspace build. Neither source review nor a successful control can replace the
original CPU, four-second confirmation, thirty-second campaign or 4,105-block
completion result.
