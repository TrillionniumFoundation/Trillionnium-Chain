# Account authorization development boundary: implementation and observations

Status: **development hardening; full Rust baseline and retained Node command
FAILED; production admission remains CLOSED**. This receipt directory records the actual work for integration
candidate #847. It grants neither whole-chain PQ qualification nor production,
migration, recovery, throughput or release acceptance.

## Source and provenance

| Role | Exact source |
| --- | --- |
| Candidate before this increment | `df927b6ffaecff293b9e9428e3ba516f47cd101a` |
| Account-boundary implementation, X | `077ac4f33206de00a178553d9a0c729a20685088` |
| Current source bindings, Y | `90ee47159e32e9014410a1823bed05d84c17b858` |
| Preserved historical W1 report and separate current-source fixture, Z | `cdd984808a088e6c2e13b1e1ae6630a94d500c89` |
| Z tree | `1ed39b6ebe55cb00c238f26f6bfc9361ab93faec` |

The completed current-source observations below execute **Z**. Earlier Y
observations, including failures, are retained in their own source cohort.
Adding this evidence directory in a later commit does not retroactively turn
those observations into execution of that later commit. Full byte verification
of Z covered 27,862 tracked entries and 2,551,591,940 bytes on both the local
cloud checkout and the desktop checkout; this is stronger than a clean Git
status alone, but is not a release attestation.

The root policy is in the [sole development plan](../../docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md).
The [account authorization boundary](../../docs/security/ACCOUNT_AUTHORIZATION_DEVELOPMENT_BOUNDARY_20261110.md)
describes implementation, permitted research use, migration constraints and
recovery limits. The [whole-chain claim guard](../../docs/security/WHOLE_CHAIN_PQ_CLAIM_GUARD_20261031.md)
remains in effect.

## What changed

Ordinary `--development` execution without an explicit PQ application still
permits real Ed25519 debit, credit, nonce and fee effects in its development
ledger. PQ transport does not by itself make that application PQ. This is an
independent classical development route; this investigation did not find an
explicit PQ verification failure retried as Ed25519.

The shared `Config::check_account_profile` now requires all three existing
development fields with their exact types and values: `production_activation`
is Boolean `false`, `not_mainnet` is Boolean `true`, and `coin_atomic_unit` is
the string `test-unit-no-market-value`. Missing, null, mistyped or different
values fail with `ACCOUNT_DEVELOPMENT_SCOPE_REQUIRED`. The classical branch
also requires the absence of `account_authorization_profile` and every
`native_pq_*` key. Explicit null, unknown `native_pq_*` keys and orphan PQ declarations are
not interpreted as a classical selection.

Private PQ owners keep their existing validation and selection authority.
NPQ2-NPQ6 retain their complete configuration digest; the older QTX1 owner
retains its existing policy checks. Deleting a public selector cannot erase
an existing private PQ owner. No signed grammar, algorithm choice, network ID,
parameter identity or storage schema is changed by this increment.

The common check covers application root and envelope validation and the
existing execution/prepare/empty-block boundaries. Node opening, wrappers
that already possess Settings, warm namespace checks, recovery and activation
also apply it. Invalid owned live configuration is a local structural failure,
requiring that operation's owner to stop. This does not create a permanently
poisoned Node object: restoring legal Settings may allow a later check to pass.
Scope/profile rejection of newly supplied startup Settings keeps the ordinary
startup error classification; remote diagnostic text cannot forge a local
integrity origin. Existing progress/cancellation contracts, bounded
snapshot preparation and legitimate failed-startup accounting remain; no
blanket zero-callback, zero-temporary-file or zero-journal claim is made.

## The five admission questions

| Question | Implemented or existing boundary | Qualification still required |
| --- | --- | --- |
| Which profile is a valid production participant? | The production-qualified set is empty. Classical, QTX1/PQG1, NPQ2-NPQ6 and CPQ1 remain explicitly scoped research/development profiles. The shared check rejects attempts to alter the required scope fields. | A separately authorized deployment transition binding application, peer, governance, release, recovery and work rules. No production activation or new whole-network negotiation was added. |
| How do old accounts and authority migrate? | Existing restricted migration uses an admitted source checkpoint and a separately pinned prior PQ key registry, preserves supported balances/nonce floors/liabilities, creates a distinct PQ research network and locks imported accounts until the required PQ CLAIM. Unsupported rows refuse import. | Independent source finality, registry existence before compromise, retirement of old assets/authority and complete coverage of effect-bearing authorization domains. An admitted checkpoint may be on a retained side branch; admission is not independent finality. |
| Which classical routes remain? | Explicit classical development execution and associated test/research owners remain functional. Real positive execution is tested, not replaced by a refusal-only mock. | Production use remains unqualified. Research listeners may be explicitly non-loopback; neither a listener nor PQ TLS qualifies the account authorization. |
| Can recovery or an upgrade reopen authority? | Existing schema/parameters/genesis/PQ-owner/witness checks remain, and damaged scope/orphan PQ declarations now fail at startup and live owner boundaries. Historical signed bytes and legal development stores are not rewritten. | Independent monotonic recovery and revocation/consumption frontiers. PNQ2's external witness covers its three PNQ2 tables, not all account/reorganization state. A legal classical development snapshot can still recover as a classical research owner. |
| How are profile and algorithm versions compared? | Existing owner-selected fixed grammars, signing domains, `crypto_profile_id`, network/parameters/genesis/protocol/scope and matching PNQ2 context remain binding. An advertised ID cannot choose a weaker verifier. | Any new signed domain, algorithm or schema needs a fresh namespace and compatibility/recovery/negative tests. Agreement on a profile does not prove production or whole-chain quantum security. |

CPQ1 ML-DSA-65/87 parameter candidates remain `CandidateOnly` at
`select_current`; listing those experiments does not make them a current
activatable profile.

## Actual validation on Z

PASS denotes only the named command and source. Ignored and filtered tests do
not count as passed. Local-cloud and desktop toolchains, providers, environments
and binary measurements are retained separately in the raw context records.

| Observation | Actual result and scope |
| --- | --- |
| M06 retained package tests, local-cloud | **PASS: 18 executed suites/binaries, 272 passed, 0 failed, 9 ignored, 0 filtered.** Includes all five new account-boundary tests. |
| New Node boundary tests, desktop | **PASS: 4 passed, 0 failed, 0 ignored, 1,398 filtered** in the focused command; the same four also passed in the later retained library run. They do not change that broader command's FAIL result. |
| First Node package all-target/all-feature attempt, desktop | **INCOMPLETE:** compilation logged LLVM `No space left on device`; stdout remained empty, `result.json` was zero bytes, and no test `Running` header was observed. The supervisor reported an unknown outcome without a confirmed terminal receipt. No native test pass or exit code is inferred. |
| Node package all targets/all features, separate data-volume retry | **FAIL, rc101: 1,359 passed, 4 failed, 39 ignored, 0 filtered** in the 1,402-test parent library suite. The command took 9,327.550 seconds; the suite reported 7,809.10 seconds. Cargo stopped before the remaining integration targets. |
| PQ feature disabled, desktop | **PASS: 1 passed.** The explicit PQ-disabled refusal control actually executed. |
| Strict workspace Clippy, desktop | **PASS**, `--workspace --all-targets --all-features -- -D warnings`, original source and flags. This is a separate completed command, not the unexecuted tail of the failed full baseline. |
| Formatting and exact Cargo graphs | **PASS**, original locked workspace/all-features and fuzz dependency graphs, without changing either lockfile. |
| Full `repository-truth`, desktop | **PASS**, 1,085.246 seconds on clean Z. The original pinned `packaging==26.3` was installed in a separate environment with `--require-hashes`, selected only through the existing `TRNM_RUNTIME_RELEASE_PYTHON` entry. The prior host-dependency failure remains a separate FAIL record. |
| Current PQ corpus | **PASS: 1,085 pins and 59 integration tests, including negative controls**; its HOLD/NO-GO meaning is unchanged. |
| CI source integrity | **PASS: 43 tests, including negative controls**. |
| W1 current-source report | **PASS: 19 tests; 7 generated reports with 7 full-byte comparisons**. These are source/report consistency checks, not native W1 qualification. |
| Original full `rust-baseline`, desktop | **FAIL**, return code 101, 2,841.481 seconds. Its data-availability library suite ran 715 tests: **713 passed, 2 failed**. The workspace command stopped there. |

The new M06 controls exercise a real signed Ed25519 transfer, maturity, subsidy,
receipts and state roots with workers 1/2/4/8, plus a real empty block. They
check 35 damaged development configurations and 27 orphan/partial/null/unknown
PQ declarations without the forbidden application effects. A real ML-DSA-65
owner and empty-block positive case accompany private-owner/selector/scope
negative controls. Node tests cover fresh open, cold open, warm owner and a
real growth fixture, including recovery, activation, progress and no-op cases,
with state and SQLite mutation checks.

### Full Rust failure and unavailable scope

The original command was `bash scripts/ci/ci_job.sh rust-baseline`, with
the original recipe and standard per-run Cargo/tool directories. Formatting
and the actual supply-chain policy completed successfully. Workspace test
compilation completed in 31 minutes 51 seconds; the DA library later failed:

1. `cell::retained::tests::native_tcp_recovers_every_retained_version_with_one_shared_exact_quota`
   failed at `cell/retained/tests.rs:780` with `Unavailable`, one connection
   attempt, 16 request attempts, 100,144 response bytes, three completed
   manifests and nine downloaded chunks. The fixture's full target is 20
   frames and 165,736 response bytes, so those totals were not exhausted.
   PersistentV2 has a fixed two-second connection lifetime; a possible
   expiry/redial-budget path loses the lower-level error before `Unavailable`.
   The original log lacks phase clocks and does **not** establish that expiry
   was the actual trigger. Request attempts also need not equal wire exchanges.
2. `retained_shard_plan_initial_128_profile_accepts_complete_65_and_128_chunk_catalogs`
   failed at `version_retention/tests/shard_plan_capacity.rs:162` with
   `Invalid("RS46 provider deadline")`. The error comes from one of three
   local shard-cache deadline checks under a ten-second absolute deadline,
   fresh for each 65/128 case and shared across that entire create operation.
   It occurred before CRP1 creation or physical-provider publication.
   The original log does not identify which 65/128 case, chunk, slot or check,
   or whether CPU or I/O consumed the interval. Local cache writes may already
   have occurred. Static full-case transaction counts are not measured work
   completion.

The whole DA subtree, its relevant crypto/protocol path dependencies and the
workspace manifest/lockfile are byte-identical between the candidate base and
Z. **The base was not executed as a comparison**, so these failures are not
reported as proven historical failures. No deadline, quota, test roster,
optimization setting or acceptance threshold was changed to make them pass.
Read-only diagnoses are retained under `support/` with their original source
references and limits. No root-cause certainty or OOM attribution is inferred
from generic failure signals.

Because the original workspace command failed, the recipe's later DAA/work
schedule/joint-DAA readers, prefix/model/authenticated-state/migration/account
multiproof/obligation-range oracle consumers, four explicitly ignored release
capacity/growth/cost controls, workspace doctests and final Clippy command were
not reached. Created but empty export directories are not completed evidence.
The independent Node command and the separate successful Clippy command keep
their own scope; neither changes this baseline FAIL into PASS.

These local/desktop commands also do not constitute a hosted GitHub Actions
acceptance run. The hosted runtime and quality Rust shards must meet their
existing same-source, same-run fan-in contract. No hosted shard result or
fan-in acceptance is claimed by this directory.
The runtime shard retains workspace tests and their export/oracle consumers;
the quality shard independently retains formatting, supply-chain, doctests,
Clippy and the four explicit release controls. Failure in this desktop full
recipe does not establish the execution status of a separate hosted shard.

### Interrupted Node compilation and separate retry

The first Node package follow-up was a separate command after the failed DA
baseline. Its preflight passed, but compilation exhausted available filesystem
space. The actual four original files remain unchanged: `context.json` was
4,332 bytes, stdout was empty, stderr was 4,193 bytes, and `result.json` was
empty. The queued `node-retained-source-after` directory was never created.
The runtime reported `finalizing` / unknown outcome and no authoritative
terminal receipt. The empty result is retained as incomplete evidence, never
repaired into a fabricated result or included in terminal PASS/FAIL totals.
The frozen archive retains the original empty `result.json` path. In the
expanded delivery only, that exact file is named `result.json.empty` so the
repository's rule that every checked-in `.json` file parses as JSON is kept.
Its zero-byte contents and SHA-256 remain unchanged; the record index exposes
the original logical receipt and the projected path. Only the explicitly
bound incomplete record receives this treatment; other malformed or missing
results still block assembly.

A read-only probe found no active compiler or test process for this task and
zero user-available bytes on the original filesystem. The task's isolated
target occupied 56,243,097,600 bytes. Only one already copied and verified
43,692-byte base64 transfer temporary was deliberately removed at this stage;
all original receipt files and the frozen transfer archive were preserved.
A later probe found the entire target directory absent and approximately
56 GB available. The cause of that intervening disappearance is unknown;
neither the root agent nor the remote evidence collector removed or moved it.
This observation is not credited as a deliberate successful cache cleanup.

The repository was independently rechecked at clean Z, and a new task-owned
target was created on the separate `/data` filesystem with approximately
173 GB available. The retry retains the original compiler, provider, jobs,
features, test roster, timeouts and quotas; only the standard `CARGO_TARGET_DIR`
location changes. Its preflight, full source-before check, Node command and
full source-after check have separate IDs beginning `node-retained-data-`.
Its outcome cannot replace the interrupted attempt or the failed full Rust
baseline.

### Retained Node failure and exact observed limits

The separate DATA retry reached an authoritative failed job outcome with exit
code 1; its actual Cargo command returned 101. Its four records are three PASS
(preflight and the complete source-before/source-after guards) and one FAIL
(the retained Node command). The final source guard finished at
`2026-11-11T06:27:10.516448+00:00` and still verified clean Z, the same tree,
and all 27,862 tracked entries. No timeout or cancellation ended this job.

The only Cargo test `Running` header was the Node `src/lib.rs` executable.
The parent summary was **1,359 passed, 4 failed, 39 ignored, 0 measured,
0 filtered out**, totaling 1,402. Three additional `1 passed; 1401 filtered`
summaries came from nested child processes; they are not added to those parent
totals. Cargo then reported that the library test failed and did not execute
the remaining integration targets. All four new account-profile boundary
cases printed `ok` in this actual library run. The 39 ignored controls remain
unexecuted, including the retained capacity/release qualification scopes.

The complete 209,668-byte stdout has SHA-256
`3591e3a47da4904328b0eff2382a0d3f434c3673b7a859c2a3d6d10171f97435`.
The four actual failures are:

| Test | Actual failure and reached boundary |
| --- | --- |
| `ingress::pq_network::tls::tests::shared_tests::recovery_cases::actual_npq6_lost_ack_and_cold_resume_reuse_exact_wire_without_history_consuming_sequence` | `recovery_cases.rs:209`: the cold Resume success assertion received `IO: Resource temporarily unavailable (os error 11)`. This is the actual retained I/O error; the log does not identify its lower-level socket stage. |
| `ingress::pq_network::tls::tests::shared_tests::recovery_cases::actual_npq6_plain_parent_recovery_and_cold_membership_keep_one_original_campaign` | `recovery_cases.rs:130`: the cold Resume success assertion received `PUBLIC_CLIENT_DEADLINE`. The original ten-second campaign also covers cold reopen and Resume; no new campaign budget was granted. |
| `store::detached_admission::tests::admitted_custom_genesis_over_eight_mib_keeps_original_held_schedule_and_cpu_owner` | `store/detached_admission/tests.rs:1058`: the first, legacy-backend iteration reached `PUBLIC_MUTATION_CPU_BUDGET` with `Capacity` classification. Its captured diagnostics report `authenticated_backend=false` and unchanged active state on refusal. The later authenticated iteration in that same test was not reached. |
| `store::pq_rollback_witness::combined_tests::guarded_npq6_valid_submit_exact_replay_and_independent_process_restart` | `store/pq_rollback_witness/combined_tests.rs:586`: the first send returned `IO: Connection reset by peer (os error 104)`, classified as `Transport`. Captured cleanup reported completion and successful child exit while preserving the original error. Replay and independent restart assertions later in this positive case were not reached. |

The large-parent case records 8,625,548 complete key/canonical-value bytes and
an 8,391,103-byte held-capacity lower bound. Its original metered dispatch took
2,871,025,464 ns. Settlement recorded 2,728,308,769 ns of paid CPU against
2,000,000,000 ns initial credit and 700,213,267 ns credited refill, leaving
-28,095,502 ns. These are the original operation's observations, not a rerun
with a larger budget. Both scoped workers were accounted for; the original
capacity refusal was retained. The active-state readback remained unchanged.
The zero-valued arithmetic stage counters on this legacy backend do not prove
that no work occurred or attribute CPU to an individual guard.

The independent-witness case has a separate 250 ms cap on each witness
Current/CAS exchange inside the outer send budget. The complete captured log
contains no `TRNM_PQ_PHASE_DIAGNOSTIC` records, so the connection reset cannot
be assigned to a particular witness/ingress/commit phase from this run.
Successful cleanup does not qualify the unexecuted replay/restart assertions
or prove that the failed send had no earlier effects.

Changed Node/M06 checks are reachable on these execution paths, so unchanged
fixture files leave causality unresolved. The NPQ6 cases reach additional
complete PQ configuration-digest checks. The large-parent case uses a valid
classical development profile: its new guard checks scope and selector
fields without entering the PQ digest or canonicalizing the eight-MiB initial
State. The new Node guard is outside the witness client's own 250 ms request
implementation. Incremental guard cost has not been measured, and the base
candidate was not executed as a comparison. The observed errors do not
establish a new guard semantic refusal, but they also do not clear possible
runtime-cost effects or prove an environmental or previously existing cause.

No deadline, CPU allowance, feature, optimization setting, roster or acceptance
threshold was changed to turn these failures green. The original pre-panic
snapshots and the successor diagnosis based on the complete log remain separate
under `support/`. These observations keep full CI, release and production
qualification unavailable.

### Preserved earlier failures

The complete local Y/Z observations include the initial missing fuzz-index and
cargo-deny failures, the old-source W1 golden mismatch, an `EXDEV` hard-link
failure, a missing GNU time failure, an `ENOSPC` setup failure, and real Node
compilation `SIGKILL` failures. No tests are claimed to have executed when
compilation was killed, and `SIGKILL` alone is not diagnosed as OOM. The
desktop's first repository-truth host Python dependency failure and the initial
tool-preparation graph assertion failure also remain intact. Corrections use
real tools/dependencies and ordinary supported environment selectors; earlier
results are never rewritten.

The old W1 golden remains at its original path and hash. Z adds a separate
current-source fixture whose seven changed survey fields are restricted to
source identity/hash/size/anchor information; numerical work assumptions and
acceptance claims are unchanged. Complete report comparisons and negative
controls remain active.

## Reading and verifying this directory

`record-index.json` enumerates terminal PASS/FAIL receipts and any incomplete
contexts by host, exact source and command ID. Raw `context.json`, `result.json`,
stdout, stderr and native exports are preserved without normalization under
`hosts/<host>/sources/<commit>/`. Historical inventory snapshots are labeled as
snapshots rather than silently rewritten to include later runs. Tool setup,
transfer checks, diagnoses and the assembly program/plan live under `support/`
or the corresponding host imports.

Each imported archive is pinned to its complete SHA-256. Its manifest, member
names, file types, sizes and hashes were checked against the actual received
bytes. `binary-identities.json` indexes measured binary identities; the ELF and
Cargo target directories are not embedded. Paths identify the executable at
the recorded measurement time, not a promise that a later build cache still
contains those bytes. Post-run binary hashing is not an execution-time signed
attestation.

`manifest.json` binds every payload file and the derived indexes by relative
path, byte length and SHA-256. `manifest.sha256` binds the exact manifest bytes;
neither the manifest nor its sidecar appears in that manifest's own file list.
The assembly records always keep full CI, production and whole-chain PQ
qualification false. Evidence collection cannot grant those qualifications.
