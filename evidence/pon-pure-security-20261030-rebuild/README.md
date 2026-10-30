# Pure PoN security continuation: rebuilt source and retained limits

This candidate continues section 3 of the pure PoN audit from integration
commit `540d72356a921da31dde1113537382e5c0f0c4fd`. The working date is
2026-10-29 in America/New_York; the evidence namespace uses 2026-10-30 UTC.
The sole development plan remains
[the canonical plan](../../docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md).

The delivered changes improve authenticated attack coverage, work-cost evidence
binding, complete-proof receiver checks, and failure retention. They do not
establish open-network honest service, a global lower bound on effective work,
practical succinct proving, quantum security, or deployment qualification.
Consensus still uses independently validated PoN and cumulative required work.
No Hashcash admission gate, stake, quality/evaluator multiplier, committee,
alternative work identity, automatic fallback, or activation is introduced.

## Recovery and evidence scope

The preceding local workspace and unpublished commit `bb358a91` were unavailable
after the execution environment changed. Their source, executable, measurements
and logs are not reconstructed as historical artifacts. This checkout was
recovered from the current integration head, including its concurrent worker,
History and recent-batch fixes. See [recovery-scope.json](recovery-scope.json).

New local commands were actually executed. Historical GitHub artifacts were
downloaded again, checked against their fixed archive digests, and clearly
labeled as readbacks. The proof receiver was rebuilt and executed against the
recovered original proof. Neither reading historical V5 output nor reading a
History database is a new native campaign.

Local native records were collected on an uncommitted candidate, so their
process records retain `source_sha: null`. Per-lane source/asset hashes and final
native-source observations bind the inspected bytes; they do not retroactively
turn those runs into clean whole-commit or reproducible-build attestations.
The publication commit identifies the delivered files. Subsequent exact-head
CI is a separate observation.

## 1. Preserve rejection correctness and expose admission coverage

The W1 production relation, scalar error ordering, ticket rule and native cache
semantics are unchanged. Three added native controls establish narrower facts:

- Eight mixed-invalid scalar/header cases preserve the reference verifier's
  error precedence before any arithmetic-cache access or progress callback.
- A correct final product with a false trace requires complete replay for each
  of three fresh challenges. Each cold rejection records 512 tiles, returns
  `Transcript`, and grants no `VerifiedWork`. Only an exact warm arithmetic fact
  avoids that same replay.
- After 65 exact challenges exceed the 64-entry cache, the evicted first
  challenge requires replay again. Eviction cannot become a rejection fact.

These controls substantiate the remaining asymmetric rejection cost. They do
not report acceptance of a forged block or claim a new arithmetic speedup.

The optional fresh-caller campaign now derives a different deterministic
Ed25519 key for every phase/actor/sequence, inside the original measured actor
work. Its observer records the caller only after actual request-signature
verification. A Hello claim, bad signature or issued key is insufficient.
The original observer remains schema v3; the explicit authenticated-caller
constructor selects v4.

The independent reader reconstructs both the key and exact request, and requires
at least 65 distinct **actually authenticated** hostile callers in each attack
phase. It conjuncts the original pressure criteria through an explicit in-memory
schema projection. It does not rewrite retained raw reports, relax the original
30-second windows, or treat identity count as a Sybil-resistance proof.

The original native gates remain. The opt-in driver adds four native gates and
four reader/environment gates. Ordinary failures of the original campaigns or
their readers do not skip the fresh-caller campaign; their failures still make
the final conjunction false. Both hosted x64 and ARM lanes use the pinned reader
environment within the original fixed-Host resource limits.

The receiver-owner failure path now preserves actual partial controller and
receiver observations when terminal output is missing or malformed, including
already-collected attacker outcomes and single-reap `wait4` costs. It continues
to fail and does not manufacture a successful receiver report.

See the [reader controls](admission-reader-controls/results.json),
[final native controls](local-validation/pressure-controls-final.stdout.log),
and [final ingress tests](local-validation/public-ingress.stdout.log).

## 2. Bind every V5 attempt to the original context

The stdlib-only reader independently reconstructs the fixed configuration's
network, parameters, maintenance task, nonzero target, canonical header and
every nonce challenge. Checks run before the hit/miss branch, so misses and
exhausted searches cannot bypass them. Winning packets must have the exact
49,508-byte length, including retained cold-readback observations.

The full seed-header digest additionally pins fields that are not independently
replayed by this reader. This is an exact fixed-fixture check, not independent
genesis or application execution. A genuinely changed native fixture must be
identified explicitly rather than silently accepted through a relaxed pin.

The recovered historical run contains 144 cohorts, 11,844 searches, 22,590
attempts, 11,772 hits and 10,818 misses. Its 25 original summary fields remain
unchanged; `context_binding` is the additional field. Seven coordinated metadata
mutations pass the old reader and fail the new reader. These are evidence-reader
defects, not seven native block-forgery exploits.

The original roster, budgets, nonce windows, search accounting, retained
exhaustion, pairing, timing and cold-recovery predicates remain. No producer is
declared globally optimal; no reader-derived total grants chainwork.

See [the V5 readback and executable red/green controls](cost-context/README.md).

## 3. Measure the complete-proof receiver without weakening W1

The standalone host rejects inconsistent header task/target and zero target
before receipt I/O. The guest, full W1 relation, image, strict verifier, bounded
decoder and original proof-production limit remain unchanged. `audit-one`
accepts exactly eight fixed cases, each preceded by actual verification of the
original real proof.

The recovered proof is a **15,862,780-byte Composite receipt**, with 62 segments.
It is distinct from the earlier 256,886-byte Succinct receipt cited in the audit.
No new proof was generated in this continuation.

| Actual case | Receiver milliseconds | Outcome |
| --- | ---: | --- |
| Valid | 1332.826232 | Verified |
| First seal tampered | 57.424247 | Rejected |
| Last seal tampered | 1187.393954 | Rejected |
| Wrong verifier parameters | 30.613254 | Rejected |
| Wrong statement miner | 26.058207 | Rejected |
| Truncated encoding | 0.014742 | Refused |
| Trailing byte | 0.016314 | Refused |
| Seal-length allocation bomb | 0.005468 | Refused |

These are single observations on a shared host, with a verifier warmed by the
mandatory positive prerequisite. The timer includes preflight, decoding, strict
verification and receipt destruction. File I/O, case construction, context
preparation, hashing, output and startup are excluded; whole-process records
are retained separately. These are not cold-start costs or worst-case bounds.

The late-seal refusal still costs about 1.19 seconds. Reusing a public receipt
and corrupting a late seal does not require repeating its original proving
work. This result does not close cheap-submission/expensive-rejection or prove
practical admission economics.

Durable, exactly checked fixture objects make the new CI independent of artifact
expiration. The independent metadata reader binds source and bytes, but does
not itself verify a STARK, authenticate timings, or independently reconstruct
SDK seal positions. See [the full proof evidence](complete-w1/README.md).

## 4. Separate the actual History failure from the N8 evidence

The original strict fixed-Host baseline at `540d723` fails without any attacker:
its first depth-six confirmation finishes at **45.067188843 seconds**, outside
the unchanged 30-second window. Seven imports consume **10.341637184 CPU
seconds** under a 25% CPU quota. Even an idealized budget conversion gives
41.366548736 wall seconds before other work and waiting.

From ready through the final snapshot, including the separate confirmation and
snapshot calls, the nested account-graph stage records 85 full traversals and
9.240268480 CPU seconds. The decode cache already hits 127,426 of 127,571
observations. This stage interval differs from the seven-import interval;
nested stage times cannot be added to process CPU. Exact retained SQLite and
source mappings support the repeated-graph diagnosis; they do not establish
that every nanosecond is kernel I/O or that a proposed cache is safe.

The existing explicit N8 resource profile has different, bounded observations.
In three retained `pure-history-raw-v1` runs, all nine phases complete all three
depth-six confirmations with full receiver/client State equality; all 27
confirmations are within 30 seconds. The latest confirmation per phase ranges
from 22.002793236 to 27.464329723 seconds. Actual typed counters preserve node
checks, a maximum eight-node resource-check window, and zero scope/import errors.

All six hostile phases nevertheless fail the original paid-credit-depletion
coverage requirement. No sampled remaining credit is below the required
100,000,000 nanoseconds with the corresponding debit and overlap predicates.
Those three campaigns remain failed. Timely service under the observed finite
load is useful evidence, but does not cover service after the required depletion.

The strict and N8 observations use distinct campaign profiles. No passing result
or speedup factor is transferred between them. No same-root cache was added:
SQL writes, triggers, persistence and per-node resource observations must still
be respected. See [the strict baseline](history-baseline/README.md) and
[the separate N8 follow-up](history-n8-followup/README.md).

## Local verification and remaining acceptance

| Newly executed check | Observed result |
| --- | --- |
| M01 release unit suite, original default features | 130 passed |
| Node consensus arithmetic suite | 6 passed |
| Public ingress suite | 183 passed |
| Pressure/receiver control suite after the final retention fix | 19 passed; 16 long/subprocess campaign entries intentionally ignored |
| Authenticated-caller rerun | 2 passed; these are already included in the 183 above |
| V5 reader and diagnostic controls | 30 passed |
| Admission reader/driver controls | 66 passed |
| Complete-proof host release suite | 17 passed |
| Main crypto/node all-target, all-feature release Clippy | Passed with `-D warnings` |
| Standalone host/relation strict Clippy | Passed |
| Source-integrity negatives / project-boundary controls | 34 / 16 passed |
| Risk model / quantum-DAA controls | 23 / 7 passed; all three native parity checks executed |
| Main locked Cargo metadata | 26 packages; no manifest or lockfile modification |
| Source inventory and Rust formatting | Passed |

Counts describe distinct suites, not an aggregate security score. Repeated
controls and earlier checkpoints are not added to inflate a total. Raw local
logs, process scopes and source observations are in
[local-validation](local-validation/README.md); each other lane has its own
manifest and reproduction instructions. The initial typo in a source-control
command and the original failed artifact download remain recorded.

This host lacks systemd, so the fixed-Host x64/ARM campaigns were not run here.
They require the actual hosted physical resource envelope. Their new exact-head
results, and any later native V5 capture, must be reported separately from these
local controls and historical readbacks.

Still open: bounded honest-service acceptance under the original attack and
resource model; effective work-share assumptions across task structure, hardware,
precomputation and demand; practical complete-proof economics; quantitative
quantum security; independent security/economics review; and production
activation. No completion percentage or qualified-security flag is inferred
from passing implementation tests.
