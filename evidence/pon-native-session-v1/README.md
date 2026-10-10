# Native session and receiver-confirmation evidence

Measured implementation: `fbe72b70f096d04290b8ef14ac95a4b32cdaf4fb`.
Measured tree: `31b4df1df65ef70d92936091271d21e1d90c1142`.
The [qualification](qualification.json) and raw logs were produced on that clean source.
This is a continuation of the same PR #204, not a new native node or parallel ledger.

## Actual behavior and responsibility

The existing twelve-command M06 engine is callable as a bounded root/sequence-bound
native compute session. Its compressed in-memory commitment updates changed paths and
matches the full root builder. The reference Ledger remains the sole durable owner.
Lost replies, wrong predecessor bytes, Boolean aliases, malformed deltas, backend changes
mandatory receipt omission/reordering, and process faults discard the cache without inventing a committed state. Pure repeated
results report zero new communication, signatures and native work and are not counted as additional executions. Empty blocks retain mandatory expiry receipts; their bounded sorted prefix is independently derived from funded predecessor objects.

The existing admission path rejects malformed proof fields/task/tickets before branch
state reconstruction. A cheaply forged passing ticket still requires full verification
and rejects; adversarial work hardness and public Sybil-safe admission remain unqualified.
The existing receiver's bounded confirmation batch validates all memberships and one
complete current-clock ancestry, retaining generation and future-spike checks.

## Reproduced failures and repair

[The retained initial candidate](failures/initial-candidate/README.md) passed its selected
matrix, but additional real probes found a height-three expiry receipt rejection and
underfunding at the maximum allowed benchmark sample count. Both failures remain in raw
logs with their original source. The current receipt comes from a complete rerun after
fixing receipt-prefix semantics and deriving funding from actual registered transfer fees.
No fee, subsidy, genesis allocation or consensus rule was weakened to make either pass.

## Exact-source execution

- 1809 native tests passed; 15 documentation tests passed.
  The default-ignored fixture helper ran separately. Strict full-workspace Clippy and formatting passed.
- 27 session/IPC/cache counterexamples passed, including actual twelve-command
  sessions at 1/2/4/8 workers and source/receiver restart/reorg behavior.
- 40 distinct client cases ran with the reference, explicit native single-shot,
  and explicit native-session backends. Repeating configurations is not more unique cases.
- 4 early-proof rejection cases passed. The same-source full ledger and invariant
  suites also ran with explicit native work and eight-worker session execution.
- Historical E3 and client packages were validated against their own original Git trees.
  Their mutation suites and current responsibility bindings ran without repinning old outcomes.

Rust, interpreter, NumPy/cryptography, exact commands, binary hashes, two compiler jobs,
one test-harness thread and ext4-backed `/tmp` are recorded in the receipt. No new external
Cargo version, consensus parameter, genesis, model training, paid provider or deployment
was introduced. A retained existing serde version is now an explicit example dependency.

## Paired application intervals, not public-chain TPS

[The paired report](comparison/report.json) contains 96 actual intervals,
including labelled warmups, across three signed workloads and four worker settings.
There are three retained samples per variant/case after one warmup. Every sample advances
nonce/root; no pure repeated-request cache hit is counted. All complete states, receipts
and roots are compared against separately coded Python execution.

The per-variant timer starts after common request construction. It includes transport,
execution and independent Python result-root checking; the session additionally performs
its exact predecessor-byte comparison. Bootstrap is separately recorded, not hidden in
steady-state claims. These are this driver's defined intervals, not total application or
network latency. Full-map copies/scans and Python full-root verification remain costs.
No p95/p99 estimate is inferred from this small sample set; slower results remain visible.

| Workload | Workers | Full-state interval ms | Session interval ms | Full root ms | Session root ms | Session/full interval |
|---|---:|---:|---:|---:|---:|---:|
| independent | 1 | 308.736 | 259.638 | 81.141 | 33.027 | 0.8410 |
| independent | 2 | 311.455 | 286.275 | 83.152 | 54.735 | 0.9192 |
| independent | 4 | 323.907 | 279.184 | 82.984 | 53.628 | 0.8619 |
| independent | 8 | 307.595 | 284.611 | 72.326 | 60.599 | 0.9253 |
| hot-recipient | 1 | 251.992 | 205.580 | 65.889 | 17.048 | 0.8158 |
| hot-recipient | 2 | 257.031 | 221.737 | 67.350 | 33.672 | 0.8627 |
| hot-recipient | 4 | 266.020 | 234.004 | 67.909 | 34.119 | 0.8796 |
| hot-recipient | 8 | 260.021 | 218.927 | 66.742 | 33.646 | 0.8420 |
| hot-sender | 1 | 252.681 | 184.444 | 66.029 | 1.368 | 0.7300 |
| hot-sender | 2 | 252.473 | 186.642 | 67.432 | 2.688 | 0.7393 |
| hot-sender | 4 | 269.419 | 207.898 | 67.384 | 2.673 | 0.7717 |
| hot-sender | 8 | 251.256 | 184.327 | 67.132 | 2.659 | 0.7336 |

## Actual work through local receiver confirmation

[The pipeline report](pipeline/report.json) records 44
real mined/work-verified block executions across two separately stored 22-block scenarios, including signed funding and confirmation-fill blocks. This count is not a claim of globally unique block IDs.
96 signed application transactions were included,
independently re-executed by the receiving ledger, and locally policy-confirmed from actual
membership/depth/chainwork. Full packets and bounded delivery pages are retained. The
publication checker replays their work, signatures, states and confirmation results;
reported remote work totals or Boolean success flags do not substitute for this replay.

This is one controller on one physical host with separate source/receiver SQLite stores
and native compute children. Transport is bounded page delivery, not public P2P. Time is
explicitly logical and block production is NOT paced to the ten-second target. Per-stage
and submission-through-confirmation durations are local implementation costs; public
confirmed TPS, hostile-peer availability and unmeasured GPU memory remain null.

## Historical applicability and remaining work

The old `pon-v1`, `pon-v3`, `pon-v4`, E3, contract-authority and client packages are unchanged.
Use the existing responsibility reporter to distinguish subject equality, whole-runtime
matching and observed selectors. This new receipt covers the changed runtime; historical
model scores, no-adoption and zero-reward outcomes are not new experiments on this source.

Still incomplete: ordinary fully native mining/consensus/persistence/P2P composition;
public work-cost/shortcut/admission qualification; persistent paged state and long-run
history economics; ordinary Hepta export/withdrawal/resource owners; independently
administered future model evaluation and funded long-term DA; target-side effects,
physical power loss and sustained WAN capacity. The cache is not a second durable store.
All production, independent-acceptance and full-native-node flags remain false.
