# M17 Observability / Benchmark / Security / Evidence technical specification v1

Status: **implementation contract; evidence tooling is not self-acceptance authority**

## Authority

M17 instruments, tests and reports M00-M16. It cannot approve its own security
claim, grant a signer capability, promote production or replace a missing real
service with a passing fixture. Evidence distinguishes source/structure checks,
behavioral conformance, multi-process integration and independent external review.
A test count or `PASS` string without an oracle is not conformance evidence.

### Source map and evidence classes

| Source | Existing use | Claim boundary |
|---|---|---|
| `trillionnium/crates/trnm-consensus-sim` | Deterministic consensus/fault simulation | Simulated scheduling, not WAN/runtime proof |
| `trillionnium/crates/trnm-bench/src/main.rs` | Benchmark entrypoint | Inspect workload and timed boundary before interpreting TPS |
| `trillionnium/crates/trnm-poco-lab-validator` | Candidate process/network/restart campaigns | Lab profiles/local keys do not prove production custody |
| `scripts/poco-fleet/run_local_fault_performance_campaign_v1.py` | Real-process loopback proxy partition/heal/restart campaign | Candidate local transport evidence; not independent multi-host or production performance acceptance |
| `trillionnium/crates/trnm-production-adapter-conformance-v0/src/lib.rs` | Adapter conformance contracts | Real adapter plus crash evidence still required |
| `formal/`, `scripts/ci/` | Models, vectors, regression and source checks | Model assumptions and checker scope must be named |
| `scripts/ci/check_documentation_contracts_v1.py` | Reference/source integrity | Does not establish semantic design acceptance |

The following network campaign, metrics envelope and measurement procedure are
implementation targets. Existing tests count only for the properties and
configuration they actually execute; this document does not mark campaigns done.

`trnm-bench` emits `determinism.input_sha256` and
`determinism.groups_sha256`, which bind the generated workload and ordered
group membership while excluding host clock data. Passing
`--determinism-repeats N` replays the exact input in-process and fails closed on
any ordered-assignment mismatch. These digests make executor scheduling
regressions mechanically comparable; they are not ingress TPS, consensus
finality or multi-host performance evidence.

### Epoch host feature isolation (M17-EPOCH-HOST-FEATURES-V2)

The recursive Cargo feature graph must reject every
`candidate-epoch-host-*` feature of the consensus Core or Safety store in the
production CLI, default node component and outgoing-only authority closures.
This applies to new version names as well as the existing explicit forbidden
feature list. Package membership alone cannot detect an authority API enabled
inside a package already used by production. Explicit epoch candidate builds
may select these features; enabling a candidate host must not activate a test
fixture or change release truth. Mutation tests cover dependency/default leaks,
a newly named future version and explicit candidate-only selection.

The required baseline separately executes the V2-only Core feature, all-feature
Core tests/documentation, journal10's actual-owner and SIGKILL target, and strict
all-target Core/Safety Clippy. The journal10 child entries are invoked only by
their process-death parents. This is an unconditional bounded execution step;
commented commands, extra test filters, skipped steps and masked failures reject.
A source check of those commands is not a substitute for their actual results.

### Observed fleet readiness and its limits

The 2026-09-16 read-only run of `scripts/poco-fleet/probe_fleet.py` and
`probe_run_readiness.py` reached all six configured physical hosts: five Linux
hosts assigned validator roles and one macOS observer. A stale observer LAN IP
was corrected only after SSH host/interface identity agreed. The repeated
readiness probe and independent `check_run_readiness_evidence.py` passed all
six hosts, including LAN reachability, declared tools and free candidate ports;
observed clock spread was three seconds. Linux resource admission also fit the
configured 7/31/100 process profiles. Capacity arithmetic is not a running
validator or throughput result.

This is one controlled LAN, not six independent operators or a WAN campaign.
These probes start no validators, induce no faults and provide no finality,
restart or goodput acceptance. Release evidence must rerun against the actual
binary/source/profile and retain the raw host facts, failures and checker result.
The probe now retains parsed facts on a failed host and identifies native
builder availability independently of subsequent LAN checks. Its regression
suite requires a network failure to remain failure, without inventing an absent
builder; a genuinely absent platform builder and oversized probe output still
reject. This repairs diagnostics without weakening the readiness gate.

### Repository-local multiprocess fault evidence

`python3 scripts/poco-fleet/run_local_fault_performance_campaign_v1.py campaign
--output <path> --messages <n>` launches three independent endpoint processes
and a separate `p2p_fault_proxy.py` process. It performs real TCP round trips
for every link, then records baseline traffic, one-link-at-a-time partition
rejection with unaffected-link progress, healing, and a clean proxy restart.
Each partition is applied while its link has an established TCP stream; the
proxy must observe EOF/reset on that existing stream before recording rejection,
so a test cannot pass merely because new connections fail while an old stream
continues to carry traffic. Healing opens a fresh stream and proves progress
under the same link identity.
The JSON artifact binds the proxy source digest, canonical link configuration
digest, exact phase counts, monotonic timing and a sidecar artifact digest. The
campaign test executes the same child-process path with one message per link.

Before the artifact is written, `validate_campaign_result` rechecks the
schema, source/config digest shape, monotonic elapsed time, exact phase order,
per-link isolation/recovery counts and latency percentile ordering. It also
fails closed if any candidate-only boundary flag is changed. The regression
suite mutates partition counts, latency ordering and the performance flag to
prove that a hand-edited result cannot be accepted by this local verifier.

This closes a reproducible repository-side transport-fault observation and
loopback latency measurement. It intentionally sets
`candidate_only=true`, `independent_multihost_evidence=false`,
`physical_power_loss_evidence=false`, `performance_acceptance=false` and
`production_activation=false`. Loopback processes share one host and one
operator, so this result cannot close P2-NET/P2-OPS independent LAN/WAN,
attestation, HSM, power-loss or production SLO gates.

## Interfaces

### Evidence and metric records

Planned `EvidenceManifestV1` binds source commit/tree, base and prospective-merge
identities, module/protocol/profile versions, toolchain/lockfile/features,
configuration and binary digests, topology, validator weights/key roles,
workload bytes/seed, fault schedule, command argv, start/end times, runner identity,
raw artifact digest/size/media type, oracle, results and invalidation scope.
Record independent reviewer identity, conflict declaration and signature in a
separate acceptance record; the producer cannot populate its own approval.

`MetricEnvelopeV1` contains schema, node/process/module, source/config identity,
monotonic sequence and interval, metric ID/type/unit, value or histogram,
sample/drop counts and privacy class. Counter restarts require a new process ID.
No tx ID/account/peer hash becomes an unbounded metric label.
M16's future telemetry interval setting affects optional diagnostic exports only;
the 1 s canary guard feed and mandatory security/fault milestones retain their
own fixed capture schedule and reserved buffers.

`TestCaseResultV1` contains case ID, setup/profile, fault cut, expected invariant,
observed outputs, actual exit status, assertions executed, artifact digest and
`pass|fail|blocked|not_run`. A process exit 0 without the expected nonzero assertion
count is `fail`. Deliberately failing mutants pass the harness only when the
specified invariant failure is detected; their evidence records remain negative.

`GateDecisionV1` enumerates applicable case IDs and their terminal results.
Missing, skipped, queued, cancelled, `action_required`, stale or different-source
results cannot close the gate. A source-only check must carry
`semantic_acceptance:"not-assessed"`, even when its result is pass.

### Core observation events

Instrument typed milestones without private transaction contents:
`client_signed`, `ingress_received`, `admission_durable`, `broadcast_prepared`,
`ordered`, `execution_complete`, `commit_durable`, `proof_verified`,
`client_finalized`, `restart_begin`, `recovery_complete`.
Each event binds run/process/tx or block identity and local monotonic time.
Use private bounded trace storage for these IDs, not Prometheus labels.
M08/M13 are the producers of durable/finality facts; the harness cannot stamp
`proof_verified` merely because a node returned a nonzero proof digest.

### Research evidence protocol package

`trillionnium/crates/trnm-research-protocol` is a metadata/commitment protocol,
not the independent reviewer, raw research store or consensus engine. Its
`canonical.rs` defines deterministic CBOR; this must not be relabelled CEV0.
`SignedResearchCommandV1` binds chain_id, command_id, signer DID/role, nonzero
nonce, public key, typed command and signature. `signing_bytes` emits the exact
nine-element array (including protocol version and canonical encoding label);
`validate` verifies the 64-byte Ed25519 signature with strict verification.
NakamaAuthority can issue match commitments; HeptaAuthority issues evaluation,
workload, claim, license, challenge and resolution commands. `AuthoritySetV1`
must independently bind allowed DID/key/role; a self-selected role is insufficient.

`ResearchProtocolState::apply` verifies that authority, then compares command ID
and signed fingerprint. Exact replay returns `Idempotent` with no changed object
refs; altered replay returns `AlteredReplay`. New commands require exact existing
object versions, legal claim/challenge status and timestamps. Missing/stale refs,
unauthorized issuer, rejected evaluation, absent accepted contribution or corrupt
snapshot graph rejects. These records describe who attested to a claim; they do
not prove its scientific truth, chain finality or review independence.

Current persistence is `export_snapshot`/`from_snapshot` plus canonical snapshot
bytes/hash; the library does not supply a durable database or global nonce
allocator. A commissioned adapter must enforce expected chain, authenticated
height/context and its transaction nonce before invoking it. Planned bounded
adapter profile RESEARCH-DEV-1 admits at most 1 MiB/envelope, 1,024 commands and
64 MiB total retained bytes per import, with zero raw media payloads. Capacity
refusal is local unavailable. Preview on an isolated copy, then atomically commit
object mutations, applied-command fingerprint and surrounding nonce in M07; on
uncertain commit, read the exact operation before retry. Direct in-memory calls
are not committed evidence. This adapter remains disabled until implemented.

Retain `tests/protocol_v1.rs`: canonical cross-implementation fixtures, strict
roundtrips, self-asserted authority rejection, altered replay, stale refs,
challenge/resolution and snapshot corruption. Add adapter crash cuts around the
atomic object/nonce/command transaction and different-chain replay before public
submission is enabled. A successful protocol test does not issue specialist or
external-evidence acceptance.

## State machine

```text
Declared -> Running -> Completed -> ArtifactSealed -> IndependentlyReplayed
 -> Accepted | Rejected | Superseded
Running -> Failed | Blocked   (retained, never overwritten)
```

### Execute and seal algorithm

1. Freeze workload, profile, binary, input source and oracle before starting.
   Validate topology/clock configuration and require every participant to report
   matching public identities. A mismatched participant blocks the run.
2. Execute one uniquely identified attempt with a finite deadline. Collect
   stdout/stderr, exit status, typed events, resource counters and fault receipts.
   Attempt IDs are never reused after a failure or source change.
3. Stop admission at the declared boundary; allow a bounded drain; independently
   verify finality and deterministic replay from retained canonical input bytes.
4. Generate the manifest from actual observations. Mark missing required raw
   traces or participants as incomplete; do not synthesize success from averages.
5. Hash artifacts, upload to immutable content-addressed storage, read them back
   and compare digest/size. Only then emit ArtifactSealed.
6. The independent verifier loads artifacts in a credential-free sandbox,
   recomputes metrics/oracles and signs its actual finding. Producer summaries
   cannot stand in for this replay.

A changed binary, dependency, feature, parameter profile, root format or workload
invalidates dependent claims. Identical unchanged inputs may reuse evidence with
an explicit dependency record; every prose edit need not rerun a physical test.
Source-to-artifact binding remains exact for all reused records.

### End-to-end goodput procedure

Use separate client machines where possible. The initial dev campaign is four
independent validator processes with equal weight and unique dev keys, then seven;
31/100 and independent operators/custody domains are larger campaign targets.
One-host results are labelled one-host and cannot establish WAN/decentralization.

A workload manifest specifies the exact executable operation, canonical payload
corpus, sender/nonce distribution, authorization scheme, access conflict pattern,
fee/compute limits and expected successful state transition. It names an existing
M06 operation or marks its workload implementation missing. Do not substitute
empty blocks, consensus votes or no-op counter increments for user transactions.

| Workload class | Required construction / reason |
|---|---|
| Disjoint state | Unique sender/state keys, identical operation cost; parallel upper case |
| Moderate contention | Seeded 20% accesses to a shared hot set; disclose exact key distribution |
| Hot state | 90% writes target one logical key/account; exposes serialization/retry cost |
| Mixed costs | Fixed 80/15/5% low/medium/high compute or proof costs with exact operation bytes |
| Invalid ingress | Separate malformed/auth/expired corpus, never counted as committed work |

For each class use 1/2/4/8 execution workers with identical canonical input and
expected final roots. Use a fixed arrival trace/open-loop sender; report actual
offered rate and client scheduling lag. A closed-loop benchmark is labelled as
such because slow replies reduce offered load and hide overload.

1. Warm up 60 s, measure 300 s, then drain at most 60 s. These are proposed
   **development** durations; an external soak uses its separately required real
   wall-clock duration. Run at least three independent seeds/repetitions.
2. Let `[T0,T1]` be the client monotonic measurement interval. Count unique
   successful user transactions submitted and independently proof-verified as
   finalized within that interval. `committed_goodput=N/(T1-T0)`.
   Also report all finalized attempts, finalized execution failures, duplicate
   submissions, rejected requests, and successes finalized only during drain.
3. Exclude warmup submissions, duplicate tx IDs, consensus votes and unsupported
   proof claims from N. Publish the exact ID-set digest so counts are reproducible.
4. Latency starts at the first send of the exact signed intent and ends at the
   first client-verified finalized receipt. Retries retain that start time.
   Internal stage latency is separate; do not subtract network/disk from E2E.
5. Report p50/p95/p99 from raw successful completion durations plus incomplete,
   rejected and failed counts. Timed-out samples are right-censored and remain
   visible; successful-only p99 must not hide a large timeout fraction.
6. Use exact nearest-rank quantiles: sorted n samples, rank `ceil(p*n)`, minimum 1.
   Report n; do not average node p99s or invent a percentile for an empty set.
   Across repetitions report each run and median/min/max goodput, not one peak.
7. Sweep offered load through approximately 25/50/75/100/125/150% of the last
   measured sustainable rate, documenting how that reference was obtained.
   Record queue growth, drops, RSS, CPU, disk bytes/fsync tails and recovery cost.
8. Verify final state and receipt roots by independent deterministic replay.
   A mismatch invalidates the run regardless of goodput. A full queue must reject
   explicitly or backpressure; unbounded memory growth is a failed capacity test.

Use one client's monotonic clock for E2E latency. Cross-host stage comparisons
need measured clock offset/error; when uncertainty exceeds the stage duration,
report intervals/unknown rather than precise microseconds. Process-signed reports
alone do not prove external wall-clock time or geographic topology.

## Persistence and recovery

Raw artifacts are immutable per attempt. Manifest entries include byte length,
SHA-256, media type and relative logical name; mutable HTTP URLs are not identity.
Derived summaries can be regenerated without the producer's database. Failed
runs remain retained with the same integrity guarantees as passing runs.

Partial uploads retain an unsealed manifest. Resume by immutable chunk identity;
conflicting bytes for an existing digest or changed manifest are rejected.
A restarted collector starts a new sequence/process identity and records the gap;
no fabricated continuity. Missing required fault or receipt events makes the
specific test inconclusive and blocks the associated claim.

## Resource bounds

Proposed local harness defaults are configuration inputs, not production limits.

| Resource | Development default / overflow behavior |
|---|---|
| Metric envelope | 16 KiB, <=64 fixed metrics, <=128-byte label values |
| Trace event | 4 KiB, no raw private payload; oversize rejected |
| Telemetry buffer | 64 MiB/process; noncritical drops counted explicitly |
| Security/fault trace reserve | 16 MiB separate; exhaustion alarms and fails campaign completeness |
| Local artifact budget | 4 GiB/attempt initially; preflight required; no silent truncation |
| Archive ingestion | <=10,000 entries, <=4 GiB expanded, <=100x ratio; no traversal/symlinks |
| Upload retries | 5 attempts, 1/2/4/8/16 s backoff; then unsealed |
| Test deadlines | Per-case manifest, finite; timeout is a failed/blocked result, never pass |

Instrumentation never blocks a consensus thread on remote upload. It can drop
explicitly non-authoritative telemetry with counters; it cannot drop the only
required durability/fault evidence and still claim complete qualification.

## Security

Candidate code runs without repository/release/acceptance credentials. The
controller/oracle used to authenticate evidence comes from a protected source
separate from a candidate's mutable success output. Publishers execute no candidate
code. Intake validates sizes and paths before extraction and parses strictly.

Exclude private keys, bearer tokens, raw user payloads and personal data by
schema. Store public test keys only in clearly marked dev artifacts. Security
scan findings include scanner version, advisory database snapshot and reachable
component scope; a clean scan is not proof of absence of protocol bugs.

## Observability and SLO

Measure queue time separately from test execution, artifact completeness,
instrumentation CPU/RSS/latency overhead and replay reproducibility.
Run paired instrumented/uninstrumented development trials with identical workload;
report measured overhead rather than assuming metrics are free.
`evidence-tooling-v1` does not assign chain readiness by averaging failed lanes.
M16 consumes sealed bounded windows; it may not alter raw measurements or remove
failed canary evidence to improve its objective.

## Verification and evidence

### Formal auxiliary unit: assumptions, runner and counterexamples

`formal/poco-convergence-v1/check.py` runs abstract Python conformance cases and
retained mutations. `formal/quint/poco-bft-v0/` and
`formal/quint/poco-ai-native-v1/` are distinct bounded model suites; sharing the
lock-pinned Quint tool binary does not share model state or proof scope.
For each model record its source digest, invariant, transition relation, initial
states, validator/weight/fault bounds, depth/seed/count, tool version and timeout.
Map modeled fields to actual protocol fields and list abstractions explicitly.
In particular, model authentication assumptions and `reopen()` are not signature
verification, disk recovery or HSM tests.

Run typecheck, legal reachability witnesses, safety predicates and corresponding
unsafe mutants. A mutant qualifies only with the expected counterexample, not a
parse error or unrelated tool failure. Preserve witness/counterexample traces and
actual explored states/steps; a timeout, missing tool or empty collection is
inconclusive/failure, never complete formal verification. For a new safety fix,
replay the minimized counterexample against both the model and the Rust boundary
when that implementation exists. A simulation witness proves only its bounded
schedule; liveness under partial synchrony needs its separate stated argument.

### Fuzz auxiliary unit: target oracles and retained corpus

`trillionnium/fuzz` has its own manifest/lockfile and three current targets:
`canonical_tx_json` validates typed transaction decode/dispatch/round-trip;
`signed_envelope_json` covers framing/hex/hash/auth rejection and nested input;
`poco_cev0_exact` requires accepted frozen CEV0 bytes to re-encode identically.
The current smoke runner is `scripts/ci/check_canonical_fuzz_smoke.sh`, using
`nightly-2026-07-27` and cargo-fuzz 0.13.2. Its 15 s/target default is only an
integration check. The script validates 1..60 s and <=2,162,688 input bytes;
the current per-input timeout is 10 s with 2048 MiB RSS bound.

Long campaigns declare a separate duration/seed/sanitizer budget and retain the
initial/final corpus hashes, executions, coverage observations and every crash,
hang or OOM. Reproduce a failure with exact tool/input, minimize without losing
the failing oracle, add the input to its target corpus and add a deterministic
regression where practical. Do not classify an input rejection as a fuzzer crash;
do not classify a build failure or zero executions as a passing campaign.
Corpus mutation occurs in an isolated run directory; persisted reproductions are
immutable evidence inputs. Resume from recorded corpus identity, never erase a
failure when restarting. Mutate canonical accepted inputs as well as random bytes
so deep validation paths are reached; report uncovered paths honestly.

### Repository-CI auxiliary unit: execution and failure propagation

`scripts/ci` produces source checks, real execution records and evidence intake
decisions with separate result classes. The canonical plan entrypoint invokes
its retained child checks once per source context with shell failure propagation.
The required baseline verifies the exact source HEAD and separately the actual
prospective merge with expected base/head parents; a source-only success cannot
replace the merge run. Pin refresh regenerates reviewable input fingerprints,
not acceptance, signatures, external evidence or production flags.

Internal helpers are reviewed at the same checkout and their actual input blobs
are recorded; formatting edits need not be authorized by duplicated hard-coded
helper hashes. Structural path/header/invocation checks remain structural and
must report semantic design acceptance as unassessed. Retain tests that mutate
real security boundaries, empty/skipped execution, source substitution and lost
failure propagation. Workflow omission, unavailable prerequisite, killed job or
missing binding artifact is a failed/blocked run. Archive the exact command,
source context, terminal status, expected/actual case inventory and artifact
digests before publishing a result; credentials used to publish cannot be made
available to arbitrary candidate execution.

### Native candidate shard execution (M17-NATIVE-SHARDS-V1)

The native candidate library test is compiled exactly once with the pinned
source, package, feature set and lockfile. `scripts/ci/run_native_candidate_shards_v1.py`
discovers the resulting libtest executable from Cargo JSON output and records
the exact source commit/tree, test inventory, shard commands, logs and exit
codes. It must reject an empty, duplicate or unmapped inventory entry before
running a shard. Admission requires a clean complete checkout and the independently
expected source SHA when supplied; completion rechecks the same commit/tree,
checkout cleanliness and executable SHA-256. Existing nonempty evidence
directories are refused without modifying their contents.

The inventory is partitioned into exactly these disjoint categories:

* `general`: every discovered test outside the named native recovery groups;
* `historical-install`, `historical-replay`, and `historical-receiver`: the
  corresponding `later_epoch_checkpoint_bridge` tests;
* `later-bridge`: remaining `later_epoch_checkpoint_bridge` tests;
* `schema7`: schema7 incremental-owner commit tests; and
* `poco-sigkill`: the native checkpoint SIGKILL boundary test.

Every category must be nonempty and every discovered name must occur exactly
once in the recorded partition. A new test name therefore enters `general`
automatically unless it matches a reviewed recovery category. Child-process
SIGKILL tests remain real process tests; ignored child entry points retain
their ignored status and are not replaced by name filtering. The only permitted
ignored tests are the three reviewed child entry points; their corresponding
active parent drivers must be present. Before each execution, the filtered
libtest listing must equal its partition. After execution, the final parent
summary must match exact passed, ignored and filtered counts; child summaries
cannot substitute for it. No test stack-size override is introduced.

Each shard has an independent finite deadline. A timeout, nonzero exit, missing
log, missing exit code, or incomplete inventory is a failed evidence result.
The default per-shard deadline is 900 seconds. Timeout terminates the process
group with bounded TERM/KILL grace and bounded output drain. Every admitted
run retains a failed or passed summary with its last phase, including build,
inventory and source-binding failures. The existing all-target strict Clippy
command runs after all shards. The shard
artifact is source-bound and retained even when a shard fails, so a hosted
runner timeout cannot be mistaken for a passing or complete native campaign.

### Required security and fault matrix

| Layer / producer | Fault injection | Oracle / expected result |
|---|---|---|
| M00 canonical parser | Every truncation, unknown tag, length overflow, trailing byte | Reject before unbounded allocation; equivalent canonical bytes agree |
| M01/M03 authorization | Wrong signer/chain/domain, stale key, duplicate signing request | No unauthorized signature/effect; exact retries preserve receipt |
| M02 consensus | Equivocation, reordered/duplicated votes, leader silence, minority partition | No two conflicting finalized decisions within protocol fault assumptions; recovery resumes when liveness assumptions hold |
| M04 transport | Wrong peer profile, same nonce altered body, ACK loss, slow bulk lane | One prepared ingress; replay floor preserved; votes/ACKs retain reserved capacity |
| M05 admission | Concurrent same-nonce replacement, fee overflow, crash before/after CAS | Old record or complete replacement pair; never one half or two nonce owners |
| M06 execution | Different worker schedules, hot-key conflicts, resource exhaustion | Same ordered outcome/gas/roots; finite retries/fallback under declared contract |
| M07/M08 storage | Disk full, failed fsync, kill at each intent/apply/commit cut, namespace replacement | Exact predecessor or committed target; uncertainty blocks publication; acknowledged data recovered |
| M09/M13 data/proofs | Withhold chunk, wrong root, stale validator set, forged checkpoint | No unsupported finality/state acceptance; explicit availability failure |
| M14 clients/index | Lost submit response, corrupt projection, stale cursor, proof substitution | Exact retry identity; local state never labelled proof-verified |
| M15 lifecycle | Duplicate owner, stale watermark, incompatible upgrade, drain timeout | Refusal/recovery without key reuse or finalized-state rollback |
| M16 guard | Forged plan, critical parameter marked local, controller death mid-canary | No authority change; observer mode never applies; safe rollback/freeze |
| M17 harness | Remove oracle, empty job, tamper artifact, substitute source, fake reviewer | Harness rejects false success and preserves actual failed evidence |

Run crash cuts both with returned I/O failures and child-process SIGKILL where
an OS adapter exists. Physical power loss, controller flush behavior, HSM custody,
independent operators and real wall-clock soak require actual external campaigns;
a simulator cannot close them. For partitions or Byzantine weight outside the
protocol assumptions, record behavior without inventing a promised liveness bound.

Every claimed regression names at least one positive and one failing mutant.
Preserve essential security tests when deduplicating CI: reuse identical-input
results, not a source-only substitute for execution. Module owners review the
oracle; affected consumers replay their boundary. Independent specialists review
security/proof claims separately from implementation authors.

## Activation boundary

M17 reports exactly which evidence class is complete and which is blocked.
Release acceptance requires the same artifact/profile identity, nonempty required
results and authenticated independent external records where required. Repository
fixtures, self-review, shortened runs or synthetic clocks cannot close those
external gates. Critical/High unresolved findings block the affected acceptance.

### Actual native client candidate campaign

`run_consensus_fleet.py --native-client-key-root` selects the native branch only
when its exact coordinator manifest contains the native application profile
and excludes both legacy workload files. The existing seven-validator/five-
Linux-host process, Ready/Start certificate, signed terminal report, runtime
journal, metrics, final-state and replay-archive requirements still apply.
Mac signs an operator funding request and bounded client Transfer requests
using isolated campaign keys in a fresh private directory, then independently
verifies every returned native payload/receipt/finality proof against the public
manifest and the exact submitted outer bytes. Keys never enter validator or
observer-public deployment material. The coordinator bridges requests to the
real node's private Unix endpoint; this does not establish a public HTTP RPC.

`check_native_client_campaign_v1.py` rechecks the exact runner artifact
inventory, all original signed fleet artifact sets and each actual native
proof through the pinned Rust verifier. It decodes the proved command to
exclude funding from business counts and rejects relabeling, duplicate native
hashes, wrong exact bytes, substituted parent headers, idempotency sequence
changes or inconsistent measurement windows. Observed goodput is unique proved
Transfer requests divided by coordinator monotonic elapsed time from the first
business submit to the last independent verification, including sequential SSH
and proof latency. It is a small candidate-path measurement, not peak execution
TPS, N/N transaction receipts, host attestation, fault-matrix completion, A-tier
completion, production readiness or the missing full M05 intent binding.
